"""Policy engine (gate): a finished run, judged against YAML rules, gives PASS, WARN or FAIL.

The gate reads what the analysis wrote (``manifest.json``, ``summary.json``, ``findings.json``) and judges two
things:

  integrity   whether the run can be trusted. The gate fails closed: a failed tool, an empty SBOM, no successful
              scan or a run without priority scores is a FAIL by default, because a scan that saw nothing would
              otherwise pass the build. Missing EPSS or KEV data, a fused-SBOM loss and unlocked manifests are
              checked too, each with its own action.
  rules       conditions on each correlated finding on installed software (score, band, KEV, EPSS, CVSS, severity,
              fix, depth, consensus, vulnerability and component patterns, ecosystem). A finding takes the most
              severe action of the rules it matches. A condition on a value that is not known does not hold.

Exceptions accept findings until a date, with a reason and an approver. They are time-boxed: one without an expiry,
or expiring more than ``max_exception_days`` after the evaluation date, makes the policy invalid; an expired one no
longer applies and is reported, as is one that matches nothing. The decision is the most severe action left, and
``verdict.json`` lists every reason with the findings behind it. Findings on entries that are not installed
software (D9) never trigger a rule. Nothing here runs a tool or asks the network.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from chainguard import __version__
from chainguard.correlate import SEVERITY_ORDER

SCHEMA = "chainguard.verdict/v1"
DECISIONS = ("PASS", "WARN", "FAIL")
ACTIONS = {"ignore": "PASS", "warn": "WARN", "fail": "FAIL"}
INTEGRITY = {
    "tool_failure": "fail",
    "empty_sbom": "fail",
    "no_scan": "fail",
    "not_prioritised": "fail",
    "missing_snapshot": "fail",
    "fused_loss": "warn",
    "unlocked_manifest": "warn",
}
CONDITIONS = (
    "band",
    "score_min",
    "kev",
    "epss_min",
    "epss_percentile_min",
    "cvss_min",
    "severity",
    "fix_available",
    "depth_max",
    "consensus_min",
    "vulnerability",
    "component",
    "type",
)
EXIT = {"PASS": 0, "WARN": 0, "FAIL": 1}


class PolicyError(ValueError):
    """The policy is not valid, or the run cannot be read."""


@dataclass(frozen=True)
class Rule:
    id: str
    action: str
    when: Mapping[str, Any]
    description: str = ""


@dataclass(frozen=True)
class Exception_:
    vulnerability: str
    component: str | None
    reason: str
    approved_by: str
    expires: date


@dataclass(frozen=True)
class Policy:
    integrity: Mapping[str, str]
    rules: tuple[Rule, ...]
    exceptions: tuple[Exception_, ...]
    max_exception_days: int
    source: str = "packaged policy.yaml"
    sha256: str = ""
    evaluated_on: date = field(default_factory=lambda: datetime.now(UTC).date())


def _list(value: Any) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]


def _check_condition(key: str, value: Any, where: str) -> None:
    numbers = {"score_min": (0, 100), "epss_min": (0, 1), "epss_percentile_min": (0, 1), "cvss_min": (0, 10)}
    if key in numbers:
        low, high = numbers[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
            raise PolicyError(f"{where}.{key}: expected a number in [{low}, {high}], not {value!r}")
    elif key in ("depth_max", "consensus_min"):
        if isinstance(value, bool) or not isinstance(value, int) or value < (1 if key == "depth_max" else 0):
            raise PolicyError(f"{where}.{key}: expected a whole number, not {value!r}")
    elif key in ("kev", "fix_available"):
        if not isinstance(value, bool):
            raise PolicyError(f"{where}.{key}: expected true or false, not {value!r}")
    elif key == "severity":
        bad = [s for s in _list(value) if s.upper() not in SEVERITY_ORDER]
        if bad:
            raise PolicyError(f"{where}.severity: unknown {', '.join(bad)}; choose from {', '.join(SEVERITY_ORDER)}")
    elif key in ("band", "vulnerability", "component", "type") and (
        not _list(value) or any(not v for v in _list(value))
    ):
        raise PolicyError(f"{where}.{key}: expected a name or a list of names")


def parse(data: Any, *, source: str = "<policy>", sha256: str = "", today: date | None = None) -> Policy:
    """A policy from its YAML data. Unknown keys, actions and conditions are refused, so a typo cannot silently
    leave a check out; so are exceptions that are not time-boxed."""
    today = today or datetime.now(UTC).date()
    if not isinstance(data, dict):
        raise PolicyError(f"{source}: expected a mapping")
    extra = set(data) - {"version", "integrity", "rules", "exceptions", "max_exception_days"}
    if extra:
        raise PolicyError(f"{source}: unknown keys {', '.join(sorted(extra))}")
    if data.get("version") != 1:
        raise PolicyError(f"{source}: version must be 1")
    given = data.get("integrity") or {}
    if not isinstance(given, dict) or set(given) - set(INTEGRITY):
        raise PolicyError(f"{source}: integrity: checks are {', '.join(INTEGRITY)}")
    integrity = {**INTEGRITY, **given}
    for check, action in integrity.items():
        if action not in ACTIONS:
            raise PolicyError(f"{source}: integrity.{check}: action must be fail, warn or ignore, not {action!r}")
    rules = []
    seen: set[str] = set()
    for i, spec in enumerate(data.get("rules") or []):
        where = f"{source}: rules[{i}]"
        if not isinstance(spec, dict) or set(spec) - {"id", "description", "when", "action"}:
            raise PolicyError(f"{where}: expected id, description, when and action")
        rule_id = str(spec.get("id") or "")
        if not rule_id or rule_id in seen:
            raise PolicyError(f"{where}: every rule needs an id of its own")
        seen.add(rule_id)
        if spec.get("action") not in ("fail", "warn"):
            raise PolicyError(f"{where} ({rule_id}): action must be fail or warn")
        when = spec.get("when")
        if not isinstance(when, dict) or not when:
            raise PolicyError(f"{where} ({rule_id}): 'when' needs at least one condition")
        for key, value in when.items():
            if key not in CONDITIONS:
                raise PolicyError(
                    f"{where} ({rule_id}): unknown condition {key!r}; conditions: {', '.join(CONDITIONS)}"
                )
            _check_condition(key, value, f"{where}.when")
        rules.append(Rule(rule_id, spec["action"], dict(when), str(spec.get("description") or "")))
    limit = data.get("max_exception_days", 90)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise PolicyError(f"{source}: max_exception_days must be a whole number of days, at least 1")
    exceptions = []
    for i, spec in enumerate(data.get("exceptions") or []):
        where = f"{source}: exceptions[{i}]"
        if not isinstance(spec, dict) or set(spec) - {"vulnerability", "component", "reason", "approved_by", "expires"}:
            raise PolicyError(f"{where}: expected vulnerability, component, reason, approved_by and expires")
        for key in ("vulnerability", "reason", "approved_by", "expires"):
            if not spec.get(key):
                raise PolicyError(f"{where}: {key} is required: an exception must be explained, approved and dated")
        expires = spec["expires"]
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError as exc:
                raise PolicyError(f"{where}: expires must be a date (YYYY-MM-DD), not {spec['expires']!r}") from exc
        if not isinstance(expires, date) or isinstance(expires, datetime):
            raise PolicyError(f"{where}: expires must be a date (YYYY-MM-DD)")
        if (expires - today).days > limit:
            raise PolicyError(
                f"{where}: expires {expires}, more than max_exception_days ({limit}) after {today}: exceptions are "
                "time-boxed"
            )
        exceptions.append(
            Exception_(
                str(spec["vulnerability"]),
                spec.get("component"),
                str(spec["reason"]),
                str(spec["approved_by"]),
                expires,
            )
        )
    return Policy(integrity, tuple(rules), tuple(exceptions), limit, source, sha256, today)


def load(path: str | Path | None = None, today: date | None = None) -> Policy:
    """The policy in ``path``, or the packaged default, as of ``today`` (default: today, UTC)."""
    if path is None:
        text = resources.files("chainguard").joinpath("policy.yaml").read_text(encoding="utf-8")
        source = "packaged policy.yaml"
    else:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"{path}: not readable ({exc.strerror or exc})") from exc
        source = str(path)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{source}: not valid YAML ({exc})") from exc
    return parse(data, source=source, sha256=hashlib.sha256(text.encode()).hexdigest(), today=today)


# --------------------------------------------------------------------------- findings


def _value(finding: Mapping[str, Any], key: str) -> Any:
    e, p = finding.get("enrichment") or {}, finding.get("priority") or {}
    return {
        "band": p.get("band"),
        "score_min": p.get("score"),
        "kev": e.get("kev"),
        "epss_min": e.get("epss"),
        "epss_percentile_min": e.get("epss_percentile"),
        "cvss_min": e.get("cvss_v3", finding.get("cvss_v3")),
        "severity": finding.get("max_severity"),
        "fix_available": e.get("fix_available"),
        "depth_max": e.get("depth"),
        "consensus_min": finding.get("consensus"),
        "vulnerability": finding.get("vulnerability"),
        "component": finding.get("component"),
        "type": str(finding.get("component") or "").split("/", 1)[0],
    }[key]


def holds(key: str, wanted: Any, finding: Mapping[str, Any]) -> bool:
    """Whether one condition holds for a finding. A value that is not known never satisfies a condition."""
    value = _value(finding, key)
    if value is None:
        return False
    if key.endswith("_min"):
        return value >= wanted
    if key == "depth_max":
        return value <= wanted
    if key in ("kev", "fix_available"):
        return bool(value) is wanted
    if key == "severity":
        return str(value).upper() in {s.upper() for s in _list(wanted)}
    if key in ("vulnerability", "component"):
        return any(fnmatch.fnmatchcase(str(value), pattern) for pattern in _list(wanted))
    return str(value) in _list(wanted)  # band, type


def matches(rule: Rule, finding: Mapping[str, Any]) -> bool:
    return all(holds(key, wanted, finding) for key, wanted in rule.when.items())


def _excepts(exception: Exception_, finding: Mapping[str, Any]) -> bool:
    if not fnmatch.fnmatchcase(str(finding.get("vulnerability")), exception.vulnerability):
        return False
    return exception.component is None or fnmatch.fnmatchcase(str(finding.get("component")), exception.component)


# --------------------------------------------------------------------------- the run


def _read(run_dir: Path, name: str) -> dict[str, Any]:
    try:
        return json.loads((run_dir / name).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PolicyError(f"{run_dir}: {name} is missing or unreadable ({exc}): not a finished run") from exc


def integrity_checks(manifest: Mapping[str, Any], summary: Mapping[str, Any], findings: Mapping[str, Any]) -> list:
    """(check, message, details) for every integrity problem the run has."""
    out = []
    failed = [s for s in manifest.get("steps") or [] if not s.get("ok")]
    if failed:
        out.append(
            (
                "tool_failure",
                f"{len(failed)} tool step(s) failed: " + ", ".join(s["name"] for s in failed),
                [{"step": s["name"], "error": s.get("error")} for s in failed],
            )
        )
    per_generator = (summary.get("components") or {}).get("per_generator") or {}
    empty = [g for g, st in per_generator.items() if not st.get("unique_components")]
    if empty:
        out.append(("empty_sbom", f"SBOM with no components: {', '.join(empty)}", empty))
    scans = [s for s in manifest.get("steps") or [] if s.get("kind") == "scan" and not s["name"].startswith("direct+")]
    if not any(s.get("ok") for s in scans) or not per_generator:
        out.append(("no_scan", "no SBOM was generated and scanned successfully", []))
    schema = str(findings.get("schema") or "")
    version = int(schema.rsplit("/v", 1)[-1]) if schema.rsplit("/v", 1)[-1].isdigit() else 0
    # Findings on entries that are not installed software (D9) are kept without a score, by design.
    installed = [c for c in findings.get("correlated") or [] if not c.get("not_installed")]
    if "priority" not in summary or version < 3 or any("priority" not in c for c in installed):
        out.append(("not_prioritised", "the run has no priority scores: reprocess it with this ChainGuard", []))
    used = (manifest.get("analysis") or {}).get("enrichment") or {}
    missing = [kind.upper() for kind in ("epss", "kev") if not used.get(kind)]
    if missing:
        out.append(
            ("missing_snapshot", f"no {' and no '.join(missing)} snapshot was used: run chainguard db update", missing)
        )
    handoff = summary.get("handoff") or {}
    if handoff.get("fused_lossless") is False:
        out.append(
            (
                "fused_loss",
                "the merged SBOM lost findings against a direct scan (handoff.json)",
                handoff.get("warnings") or [],
            )
        )
    lock = summary.get("lockfiles") or {}
    flagged = [m["path"] for m in lock.get("manifests") or [] if m.get("status") in ("pinned", "unlocked")]
    if flagged:
        out.append(("unlocked_manifest", f"dependency manifests not locked (D5): {', '.join(flagged)}", flagged))
    return out


def _brief(finding: Mapping[str, Any]) -> dict[str, Any]:
    p, e = finding.get("priority") or {}, finding.get("enrichment") or {}
    return {
        "vulnerability": finding.get("vulnerability"),
        "component": finding.get("component"),
        "score": p.get("score"),
        "band": p.get("band"),
        "rank": p.get("rank"),
        "kev": e.get("kev"),
        "fix_versions": finding.get("fix_versions") or [],
    }


def evaluate(run_dir: Path, policy: Policy) -> dict[str, Any]:
    """The verdict on a finished run. Writes nothing."""
    run_dir = Path(run_dir)
    manifest, summary = _read(run_dir, "manifest.json"), _read(run_dir, "summary.json")
    findings = _read(run_dir, "findings.json")
    reasons: list[dict[str, Any]] = []
    for check, message, details in integrity_checks(manifest, summary, findings):
        action = policy.integrity[check]
        if action != "ignore":
            reasons.append({"kind": "integrity", "id": check, "action": action, "message": message, "details": details})
    installed = [c for c in findings.get("correlated") or [] if not c.get("not_installed")]
    used = {i: 0 for i in range(len(policy.exceptions))}
    excepted: list[dict[str, Any]] = []
    by_rule: dict[str, list[dict[str, Any]]] = {r.id: [] for r in policy.rules}
    outcome: dict[tuple[str, str], str] = {}  # each finding's most severe action, so a finding counts once
    for finding in installed:
        hit = [r for r in policy.rules if matches(r, finding)]
        if not hit:
            continue
        live = [
            (i, x) for i, x in enumerate(policy.exceptions) if _excepts(x, finding) and x.expires >= policy.evaluated_on
        ]
        if live:
            i, x = live[0]
            used[i] += 1
            excepted.append(
                {
                    **_brief(finding),
                    "rules": [r.id for r in hit],
                    "exception": {"reason": x.reason, "approved_by": x.approved_by, "expires": x.expires.isoformat()},
                }
            )
            continue
        for r in hit:
            by_rule[r.id].append(_brief(finding))
        outcome[(finding["component"], finding["vulnerability"])] = max(
            (r.action for r in hit), key=lambda a: DECISIONS.index(ACTIONS[a])
        )
    for rule in policy.rules:
        if by_rule[rule.id]:
            reasons.append(
                {
                    "kind": "rule",
                    "id": rule.id,
                    "action": rule.action,
                    "message": f"{len(by_rule[rule.id])} finding(s): {rule.description or rule.id}",
                    "findings": by_rule[rule.id],
                }
            )
    notes = []
    for i, x in enumerate(policy.exceptions):
        target = f"{x.vulnerability}" + (f" on {x.component}" if x.component else "")
        if x.expires < policy.evaluated_on:
            reasons.append(
                {
                    "kind": "exception",
                    "id": "expired",
                    "action": "warn",
                    "message": f"the exception for {target} expired on {x.expires}; it no longer applies",
                    "details": {"reason": x.reason, "approved_by": x.approved_by},
                }
            )
        elif not used[i]:
            notes.append(f"the exception for {target} matches no finding of this run")
    decision = max((ACTIONS[r["action"]] for r in reasons), key=DECISIONS.index, default="PASS")
    return {
        "schema": SCHEMA,
        "chainguard": __version__,
        "evaluated_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "evaluated_on": policy.evaluated_on.isoformat(),
        "run": manifest.get("run_id") or run_dir.name,
        "target": (manifest.get("target") or {}).get("spec"),
        "policy": {"source": policy.source, "sha256": policy.sha256},
        "decision": decision,
        "counts": {
            "findings": len(installed),
            "fail": sum(1 for a in outcome.values() if a == "fail"),
            "warn": sum(1 for a in outcome.values() if a == "warn"),
            "excepted": len(excepted),
        },
        "reasons": sorted(reasons, key=lambda r: (-DECISIONS.index(ACTIONS[r["action"]]), r["kind"] != "integrity")),
        "excepted": excepted,
        "notes": notes,
    }


def write(run_dir: Path, verdict: Mapping[str, Any]) -> Path:
    path = Path(run_dir) / "verdict.json"
    path.write_text(json.dumps(verdict, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def render(verdict: Mapping[str, Any], limit: int = 5) -> str:
    """The verdict for a terminal or a CI log: the decision, then every reason with its first findings."""
    c = verdict["counts"]
    lines = [
        f"Gate: {verdict['decision']} · {c['findings']} findings on installed software · {c['fail']} failing, "
        f"{c['warn']} warning, {c['excepted']} excepted · policy {verdict['policy']['source']}"
    ]
    for r in verdict["reasons"]:
        lines.append(f"  {r['action'].upper():<5} {r['kind']} {r['id']}: {r['message']}")
        for f in (r.get("findings") or [])[:limit]:
            fix = f"; fixed in {', '.join(f['fix_versions'][:3])}" if f["fix_versions"] else ""
            lines.append(f"        {f['vulnerability']} on {f['component']} (score {f['score']}, {f['band']}{fix})")
        more = len(r.get("findings") or []) - limit
        if more > 0:
            lines.append(f"        and {more} more (verdict.json)")
    for x in verdict["excepted"][:limit]:
        e = x["exception"]
        lines.append(f"  EXCEPTED {x['vulnerability']} on {x['component']} until {e['expires']}: {e['reason']}")
    for note in verdict["notes"]:
        lines.append(f"  note: {note}")
    return "\n".join(lines)
