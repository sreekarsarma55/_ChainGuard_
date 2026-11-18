"""Reports (gate): a judged run as SARIF, a JSON report and a Markdown job summary.

Each report is written from what the run already holds: ``manifest.json``, ``findings.json`` and the gate's
``verdict.json``. Nothing is decided here; the reports present the verdict.

  report.sarif  SARIF 2.1.0 for GitHub code scanning. One rule per vulnerability, one result per (component,
                vulnerability) the policy acted on: level error for a failing finding, warning for a warning, and
                an excepted finding as a suppressed result with the exception's justification. ``include_all``
                adds every other finding on installed software at level note. Each result points at the
                dependency manifest of its ecosystem (the line naming the package where one does), carries a
                fingerprint of its identity so an alert survives a manifest edit, and each rule a security-severity
                from CVSS, as GitHub expects. Integrity problems are tool notifications.
  report.json   every finding on installed software in priority order, with its gate outcome, location, priority,
                enrichment and evidence, and the run's tools, databases, snapshots, policy and decision.
  report.md     the job summary: the decision, the findings behind it and the fix for each, the warnings, the
                integrity checks, the exceptions.

A container image has no manifest in the repository, so its results point at ``location`` (default:
``Dockerfile``), which the report says.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from chainguard import __version__

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
REPORT_SCHEMA = "chainguard.report/v1"
INFORMATION_URI = "https://github.com/sreekarsarma55/_ChainGuard_"
LEVELS = {"fail": "error", "warn": "warning", "excepted": "warning", None: "note"}
# Used where a vulnerability has no CVSS score: the middle of each GitHub severity range.
SEVERITY_SCORES = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.0, "NEGLIGIBLE": 0.5}
# PURL type -> the manifest ecosystem chainguard.lockfiles reports
ECOSYSTEMS = {"npm": "npm", "maven": "maven", "pypi": "pypi", "gem": "rubygems", "golang": "go", "cargo": "cargo"}
DEFAULT_IMAGE_LOCATION = "Dockerfile"
# GitHub code scanning rejects a SARIF file beyond these (docs: "SARIF support for code scanning")
GITHUB_LIMITS = {"runs": 20, "results": 25_000, "rules": 25_000, "locations": 1_000, "tags": 20}
GITHUB_GZIP_BYTES = 10 * 1024 * 1024


class ReportError(ValueError):
    """The run cannot be reported: it is not finished, or it has not been judged."""


def _read(run_dir: Path, name: str) -> dict[str, Any]:
    try:
        return json.loads((run_dir / name).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        hint = ": run chainguard gate first" if name == "verdict.json" else ""
        raise ReportError(f"{run_dir}: {name} is missing or unreadable{hint} ({exc})") from exc


def fingerprint(component: str, vulnerability: str) -> str:
    return hashlib.sha256(f"{component}|{vulnerability}".encode()).hexdigest()[:16]


def name_version(component: str) -> tuple[str, str]:
    """``npm/@scope/lodash@4.17.15`` -> (``@scope/lodash``, ``4.17.15``); the namespace is kept for npm scopes."""
    path, _, version = component.rpartition("@")
    parts = path.split("/")
    name = "/".join(parts[1:]) if parts[0] == "npm" else parts[-1]
    return name, version


# --------------------------------------------------------------------------- locations


class Locator:
    """Where in the repository each finding belongs: the manifest of its ecosystem, and the line naming it.

    The target is recorded as given on the command line (``target.spec``), relative to where the scan ran, which in
    CI is the repository root; ``source_root`` makes an absolute target relative again. Lines are found by reading
    the manifest (and an npm lockfile, for packages the manifest does not name); a file that cannot be read gives
    line 1. A target without a manifest in the repository, such as an image, points at ``location``.
    """

    def __init__(self, manifest: Mapping[str, Any], location: str | None = None, source_root: Path | None = None):
        target = manifest.get("target") or {}
        self.kind = target.get("kind")
        self.spec = str(target.get("spec") or "")
        self.scanned = Path(str(target.get("path") or "")) if target.get("path") else None
        self.source_root = Path(source_root or os.getcwd()).resolve()
        self.location = location
        survey = manifest.get("dependency_manifests") or {}
        self.manifests = [m for m in survey.get("manifests") or [] if m.get("path")]
        self._lines: dict[str, list[str] | None] = {}

    def _base(self) -> str | None:
        """The target directory as a path relative to the repository root, or None if it is not inside it."""
        spec = PurePosixPath(self.spec.replace("\\", "/"))
        if self.spec and not spec.is_absolute() and ".." not in spec.parts and ":" not in self.spec:
            return "" if str(spec) == "." else str(spec)
        if self.scanned:
            try:
                return self.scanned.resolve().relative_to(self.source_root).as_posix()
            except ValueError:
                return None
        return None

    def _text(self, relative: str) -> list[str] | None:
        if relative not in self._lines:
            lines = None
            for candidate in (
                (self.scanned / relative) if self.scanned else None,
                self.source_root / (self._base() or "") / relative,
            ):
                if candidate is None:
                    continue
                try:
                    lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
                    break
                except OSError:
                    continue
            self._lines[relative] = lines
        return self._lines[relative]

    def _line(self, relative: str, component: str) -> int | None:
        """The first line that declares the package, in the syntax of its file; never a comment that names it."""
        lines = self._text(relative)
        if not lines:
            return None
        pattern = declaration(component, PurePosixPath(relative).name)
        return next((i for i, text in enumerate(lines, 1) if pattern and pattern.search(text)), None)

    def locate(self, component: str) -> dict[str, Any]:
        """{uri, line, how}: the file and line a finding on this component points at, and how it was chosen."""
        base = self._base()
        ecosystem = ECOSYSTEMS.get(component.split("/", 1)[0])
        candidates = [m for m in self.manifests if m.get("ecosystem") == ecosystem] if ecosystem else []
        if self.kind == "directory" and base is not None and candidates:
            for m in candidates:  # the manifest that names the package, then its lockfile, then the first manifest
                for relative in filter(None, (m["path"], m.get("lockfile"))):
                    line = self._line(relative, component)
                    if line:
                        how = "manifest names it" if relative == m["path"] else "lockfile names it"
                        return {"uri": _join(base, relative), "line": line, "how": how}
            first = candidates[0]["path"]
            line = 1 if self._text(first) is not None else None
            return {"uri": _join(base, first), "line": line or 1, "how": "manifest of its ecosystem"}
        if self.location:
            return {"uri": self.location, "line": 1, "how": "given location"}
        if self.kind == "directory" and base is not None:
            return {"uri": _join(base, "") or ".", "line": 1, "how": "target directory"}
        return {"uri": DEFAULT_IMAGE_LOCATION, "line": 1, "how": "default for targets without a manifest"}


def declaration(component: str, file_name: str) -> re.Pattern[str] | None:
    """How a manifest of this kind declares the package: Maven's artifactId element, an npm key, a requirement
    line (names compared as PEP 503 normalises them). None for a file this does not know."""
    name, _ = name_version(component)
    kind = component.split("/", 1)[0]
    if kind == "maven" and file_name.endswith(".xml"):
        return re.compile(rf"<artifactId>\s*{re.escape(name)}\s*</artifactId>")
    if kind == "npm" and file_name.endswith(".json"):
        return re.compile(rf'"(?:node_modules/)?{re.escape(name)}"\s*:')
    if kind == "pypi":
        spelled = "[-_.]+".join(re.escape(part) for part in re.split(r"[-_.]+", name))
        if file_name.endswith(".txt") or file_name.endswith(".in"):
            return re.compile(rf"^\s*{spelled}\s*(?:\[[^]]*\])?\s*(?:[=<>!~;@]|$)", re.IGNORECASE)
        return re.compile(rf"[\"']{spelled}\s*(?:\[[^]]*\])?\s*(?:[=<>!~;@\"']|$)", re.IGNORECASE)
    return None


def _join(base: str, relative: str) -> str:
    return str(PurePosixPath(base) / relative) if base else relative


# --------------------------------------------------------------------------- the findings and their outcome


def outcomes(verdict: Mapping[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """(component, vulnerability) -> {outcome, rules, exception}: what the gate did with each finding."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for reason in verdict.get("reasons") or []:
        if reason.get("kind") != "rule":
            continue
        for f in reason.get("findings") or []:
            entry = out.setdefault((f["component"], f["vulnerability"]), {"outcome": None, "rules": []})
            entry["rules"].append(reason["id"])
            if entry["outcome"] != "fail":
                entry["outcome"] = reason["action"]
    for f in verdict.get("excepted") or []:
        out[(f["component"], f["vulnerability"])] = {
            "outcome": "excepted",
            "rules": f.get("rules") or [],
            "exception": f.get("exception"),
        }
    return out


def _findings(run_dir: Path, verdict: Mapping[str, Any], locator: Locator) -> list[dict[str, Any]]:
    data = _read(run_dir, "findings.json")
    acted = outcomes(verdict)
    out = []
    for c in data.get("correlated") or []:
        if c.get("not_installed") or not c.get("priority"):
            continue
        key = (c["component"], c["vulnerability"])
        e = c.get("enrichment") or {}
        out.append(
            {
                "rank": c["priority"].get("rank"),
                "vulnerability": c["vulnerability"],
                "component": c["component"],
                "outcome": (acted.get(key) or {}).get("outcome"),
                "rules": (acted.get(key) or {}).get("rules", []),
                "exception": (acted.get(key) or {}).get("exception"),
                "score": c["priority"]["score"],
                "band": c["priority"]["band"],
                "severity": c.get("max_severity"),
                "cvss_v3": e.get("cvss_v3", c.get("cvss_v3")),
                "epss": e.get("epss"),
                "epss_percentile": e.get("epss_percentile"),
                "kev": e.get("kev"),
                "kev_date_added": e.get("kev_date_added"),
                "fix_available": e.get("fix_available"),
                "fix_versions": c.get("fix_versions") or [],
                "depth": e.get("depth"),
                "consensus": c.get("consensus"),
                "generators": c.get("generators") or [],
                "scanners": c.get("scanners") or [],
                "raw_ids": c.get("raw_ids") or [],
                "factors": c["priority"].get("factors"),
                "location": locator.locate(c["component"]),
            }
        )
    return sorted(out, key=lambda f: (f["rank"] is None, f["rank"] or 0))


# --------------------------------------------------------------------------- SARIF


def security_severity(findings: list[dict[str, Any]]) -> str:
    """GitHub's security-severity for a vulnerability: its highest CVSS, else its scanners' severity."""
    scores = [f["cvss_v3"] for f in findings if f["cvss_v3"]]
    if not scores:
        scores = [SEVERITY_SCORES.get(str(f["severity"]), 0.0) for f in findings]
    value = max(scores, default=0.0)
    return f"{min(max(value, 0.1), 10.0):.1f}"


def _version_key(version: str) -> tuple:
    """Numbers compared as numbers: 2.3.1 before 2.12.2 before 2.15.0."""
    return tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in re.split(r"[.\-+]", version))


def _fix_text(f: Mapping[str, Any]) -> str:
    if f["fix_versions"]:
        return f"fixed in {', '.join(sorted(f['fix_versions'], key=_version_key)[:4])}"
    return "no fix known" if f["fix_available"] is False else "fix not known"


def _message(f: Mapping[str, Any]) -> str:
    """GitHub shows the first sentence as the alert's title, so it names the vulnerability, the package and why it
    matters; the rest says what the gate did and how to fix it."""
    name, version = name_version(f["component"])
    title = f"{f['vulnerability']} in {name} {version}, priority {f['score']:g} ({f['band']}" + (
        ", in CISA KEV)." if f["kev"] else ")."
    )
    gate = {"fail": "Fails the gate", "warn": "Warns", "excepted": "Excepted"}.get(f["outcome"] or "", "Reported")
    detail = f"{gate}" + (f" ({', '.join(f['rules'])})" if f["rules"] else "")
    if f["epss"] is not None:
        detail += f"; EPSS {f['epss']:.3g}"
    return f"{title} {detail}; {_fix_text(f)}."


def _help(vulnerability: str, findings: list[dict[str, Any]]) -> str:
    f = findings[0]
    lines = [
        f"**{vulnerability}**: see [OSV](https://osv.dev/vulnerability/{vulnerability})"
        + (f" and [NVD](https://nvd.nist.gov/vuln/detail/{vulnerability})" if vulnerability.startswith("CVE-") else "")
        + ".",
        "",
    ]
    if f["kev"]:
        lines.append(f"- Listed in the CISA Known Exploited Vulnerabilities catalog since {f['kev_date_added']}.")
    if f["epss"] is not None:
        lines.append(f"- EPSS {f['epss']:.3g} (percentile {f['epss_percentile']:.3g}).")
    if f["cvss_v3"] is not None:
        lines.append(f"- CVSS v3 {f['cvss_v3']:g}.")
    for x in findings:
        lines.append(f"- `{x['component']}`: {_fix_text(x)}; reported as {', '.join(x['raw_ids'])}.")
    lines += ["", "ChainGuard ranks it by EPSS, KEV, CVSS, fix availability, dependency depth and tool consensus."]
    return "\n".join(lines)


def _precision(findings: list[dict[str, Any]], most: int) -> str:
    """How sure the tools are, from the consensus (D10): every generator and scanner, at least half, or fewer."""
    share = max((f["consensus"] or 0 for f in findings), default=0) / most if most else 0
    return "very-high" if share >= 1 else "high" if share >= 0.5 else "medium"


def github_problems(log: Mapping[str, Any]) -> list[str]:
    """What GitHub code scanning would refuse or not display in this log: its limits, the gzipped size, and the
    properties it requires to be present and not empty."""
    problems = []
    runs = log.get("runs") or []
    if len(runs) > GITHUB_LIMITS["runs"]:
        problems.append(f"{len(runs)} runs, more than {GITHUB_LIMITS['runs']}")
    if log.get("version") != "2.1.0":
        problems.append("version is not 2.1.0")
    for i, run in enumerate(runs):
        rules = (run.get("tool") or {}).get("driver", {}).get("rules") or []
        results = run.get("results") or []
        if not (run.get("tool") or {}).get("driver", {}).get("name"):
            problems.append(f"run {i}: no tool.driver.name")
        for what, items in (("results", results), ("rules", rules)):
            if len(items) > GITHUB_LIMITS[what]:
                problems.append(f"run {i}: {len(items)} {what}, more than {GITHUB_LIMITS[what]}")
        for rule in rules:
            if len((rule.get("properties") or {}).get("tags") or []) > GITHUB_LIMITS["tags"]:
                problems.append(f"run {i}: rule {rule.get('id')} has more than {GITHUB_LIMITS['tags']} tags")
            severity = (rule.get("properties") or {}).get("security-severity")
            if severity is not None and not 0.0 < float(severity) <= 10.0:
                problems.append(f"run {i}: rule {rule.get('id')} security-severity {severity} is outside (0, 10]")
        ids = {rule.get("id") for rule in rules}
        for j, result in enumerate(results):
            where = f"run {i} result {j}"
            if not result.get("ruleId") or result["ruleId"] not in ids:
                problems.append(f"{where}: ruleId missing or not a rule of the run")
            if not (result.get("message") or {}).get("text"):
                problems.append(f"{where}: no message.text")
            locations = result.get("locations") or []
            if not locations or len(locations) > GITHUB_LIMITS["locations"]:
                problems.append(f"{where}: {len(locations)} locations")
            for location in locations[:1]:
                physical = location.get("physicalLocation") or {}
                if not (physical.get("artifactLocation") or {}).get("uri"):
                    problems.append(f"{where}: no artifactLocation.uri")
                if (physical.get("region") or {}).get("startLine", 1) < 1:
                    problems.append(f"{where}: startLine below 1")
    size = len(gzip.compress(json.dumps(log).encode()))
    if size > GITHUB_GZIP_BYTES:
        problems.append(f"{size} bytes gzipped, more than {GITHUB_GZIP_BYTES}")
    return problems


def sarif(
    run_dir: Path,
    *,
    include_all: bool = False,
    location: str | None = None,
    source_root: Path | None = None,
) -> dict[str, Any]:
    """The run's SARIF 2.1.0 log for GitHub code scanning."""
    run_dir = Path(run_dir)
    manifest, verdict = _read(run_dir, "manifest.json"), _read(run_dir, "verdict.json")
    summary = _read(run_dir, "summary.json")
    locator = Locator(manifest, location, source_root)
    findings = [f for f in _findings(run_dir, verdict, locator) if include_all or f["outcome"]]
    most = (summary.get("correlation") or {}).get("most_consensus") or 0
    by_vulnerability: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        by_vulnerability.setdefault(f["vulnerability"], []).append(f)
    rules, index = [], {}
    for vulnerability, group in by_vulnerability.items():
        index[vulnerability] = len(rules)
        top = group[0]
        title = f"{vulnerability} ({'in KEV; ' if top['kev'] else ''}{top['severity'].lower()} severity)"
        rules.append(
            {
                "id": vulnerability,
                "name": re.sub(r"[^A-Za-z0-9]+", "", vulnerability.title()) or vulnerability,
                "shortDescription": {"text": title[:1024]},
                "fullDescription": {"text": f"Known vulnerability {vulnerability} in a dependency."[:1024]},
                "helpUri": f"https://osv.dev/vulnerability/{vulnerability}",
                "help": {
                    "text": f"See https://osv.dev/vulnerability/{vulnerability}",
                    "markdown": _help(vulnerability, group),
                },
                "defaultConfiguration": {"level": "warning"},
                "properties": {
                    "tags": ["security", "vulnerability", "dependency", *(["kev"] if top["kev"] else [])],
                    "security-severity": security_severity(group),
                    "precision": _precision(group, most),
                },
            }
        )
    results = []
    for f in findings:
        identity = fingerprint(f["component"], f["vulnerability"])
        result: dict[str, Any] = {
            "ruleId": f["vulnerability"],
            "ruleIndex": index[f["vulnerability"]],
            "level": LEVELS.get(f["outcome"], "note"),
            "message": {"text": _message(f)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["location"]["uri"], "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": f["location"]["line"]},
                    },
                    "message": {"text": f"{f['component']} ({f['location']['how']})"},
                }
            ],
            # The identity, not the line: an alert keeps its history when the manifest is edited.
            "partialFingerprints": {"primaryLocationLineHash": f"{identity}:1", "chainguardFinding/v1": identity},
            "properties": {
                "component": f["component"],
                "priority": f["score"],
                "band": f["band"],
                "rank": f["rank"],
                "kev": f["kev"],
                "epss": f["epss"],
                "gate": f["outcome"] or "none",
                "rules": f["rules"],
            },
        }
        if f["outcome"] == "excepted":
            x = f["exception"] or {}
            why = f"{x.get('reason')} (approved by {x.get('approved_by')}, until {x.get('expires')})"
            result["suppressions"] = [{"kind": "external", "status": "accepted", "justification": why}]
        results.append(result)
    # Within GitHub's limits: the results are in priority order, so the most important are kept, and the log says so.
    dropped = max(0, len(results) - GITHUB_LIMITS["results"])
    results = results[: GITHUB_LIMITS["results"]]
    rules_kept = {r["ruleId"] for r in results}
    if dropped:
        kept = [rule for rule in rules if rule["id"] in rules_kept]
        index = {rule["id"]: n for n, rule in enumerate(kept)}
        rules[:] = kept
        for r in results:
            r["ruleIndex"] = index[r["ruleId"]]
    notifications = [
        {
            "level": "error" if r["action"] == "fail" else "warning",
            "message": {"text": f"{r['id']}: {r['message']}"},
            "descriptor": {"id": f"chainguard/integrity/{r['id']}"},
        }
        for r in verdict.get("reasons") or []
        if r["kind"] in ("integrity", "exception")
    ]
    if dropped:
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": f"{dropped} lower-priority results left out: GitHub accepts at most "
                    f"{GITHUB_LIMITS['results']} per run (report.json has every finding)"
                },
                "descriptor": {"id": "chainguard/report/results-limit"},
            }
        )
    failed_tools = any(r["kind"] == "integrity" and r["id"] in ("tool_failure", "no_scan") for r in verdict["reasons"])
    category = re.sub(r"[^A-Za-z0-9._-]+", "-", locator.spec or str(manifest.get("run_id") or "target")).strip("-")
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ChainGuard",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"chainguard/{category}/{manifest.get('run_id') or ''}"},
                "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "The repository root."}}},
                "invocations": [
                    {
                        "executionSuccessful": not failed_tools,
                        "toolExecutionNotifications": notifications,
                        "properties": {"decision": verdict["decision"], "policy": verdict["policy"]},
                    }
                ],
                "results": results,
                "properties": {"decision": verdict["decision"]},
            }
        ],
    }


# --------------------------------------------------------------------------- JSON report and job summary


def report(run_dir: Path, *, location: str | None = None, source_root: Path | None = None) -> dict[str, Any]:
    """The machine-readable report: every finding on installed software, in priority order, with the decision."""
    run_dir = Path(run_dir)
    manifest, verdict = _read(run_dir, "manifest.json"), _read(run_dir, "verdict.json")
    findings = _findings(run_dir, verdict, Locator(manifest, location, source_root))
    analysis = manifest.get("analysis") or {}
    enrichment = analysis.get("enrichment") or {}
    return {
        "schema": REPORT_SCHEMA,
        "chainguard": __version__,
        "run": manifest.get("run_id"),
        "target": manifest.get("target"),
        "scanned_utc": manifest.get("started_utc"),
        "toolchain": {n: t.get("version") for n, t in sorted((manifest.get("toolchain") or {}).items())},
        "databases": {
            n: (t.get("database") or {}).get("updated_at") or (t.get("database") or {}).get("built")
            for n, t in sorted((manifest.get("toolchain") or {}).items())
            if t.get("database")
        },
        "snapshots": {k: (enrichment.get(k) or {}).get("version") for k in ("epss", "kev")},
        "priority_config": {k: (analysis.get("priority") or {}).get(k) for k in ("source", "sha256")},
        "verdict": {k: verdict[k] for k in ("decision", "counts", "policy", "evaluated_on", "notes")},
        "reasons": [{k: r[k] for k in ("kind", "id", "action", "message")} for r in verdict["reasons"]],
        "findings": findings,
    }


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def markdown(data: Mapping[str, Any], limit: int = 10) -> str:
    """The job summary, from ``report()``'s data."""
    v = data["verdict"]
    c = v["counts"]
    target = (data.get("target") or {}).get("spec") or data["run"]
    lines = [
        f"## ChainGuard: **{v['decision']}** · `{target}`",
        "",
        f"{c['fail']} findings fail the policy, {c['warn']} warn and {c['excepted']} are excepted, of {c['findings']} "
        f"findings on installed software. Policy: {v['policy']['source']} (sha256 {v['policy']['sha256'][:12]}), "
        f"evaluated on {v['evaluated_on']}.",
    ]
    integrity = [r for r in data["reasons"] if r["kind"] in ("integrity", "exception")]
    if integrity:
        lines += ["", "**Checks on the run itself**", ""]
        lines += [f"- {r['action'].upper()} `{r['id']}`: {_cell(r['message'])}" for r in integrity]
    header = [
        "| Rank | Vulnerability | Component | Score | KEV | EPSS | Fix | Rules |",
        "|---:|---|---|---:|---|---:|---|---|",
    ]

    def rows(selected: list[dict[str, Any]]) -> list[str]:
        out = []
        for f in selected[:limit]:
            epss = "" if f["epss"] is None else f"{f['epss']:.3g}"
            out.append(
                f"| {f['rank']} | {f['vulnerability']} | `{f['component']}` | {f['score']:g} | "
                f"{'yes' if f['kev'] else ''} | {epss} | {_cell(_fix_text(f))} | {', '.join(f['rules'])} |"
            )
        if len(selected) > limit:
            out.append(f"| | and {len(selected) - limit} more | | | | | | |")
        return out

    failing = [f for f in data["findings"] if f["outcome"] == "fail"]
    warning = [f for f in data["findings"] if f["outcome"] == "warn"]
    if failing:
        lines += ["", f"### Why it fails ({len(failing)})", "", *header, *rows(failing)]
    if warning:
        lines += ["", f"### Warnings ({len(warning)})", "", *header, *rows(warning)]
    excepted = [f for f in data["findings"] if f["outcome"] == "excepted"]
    if excepted:
        lines += ["", f"### Excepted ({len(excepted)})", ""]
        for f in excepted[:limit]:
            x = f["exception"] or {}
            lines.append(
                f"- {f['vulnerability']} on `{f['component']}` until {x.get('expires')}: {_cell(x.get('reason'))} "
                f"(approved by {_cell(x.get('approved_by'))})"
            )
    for note in v.get("notes") or []:
        lines.append(f"- note: {_cell(note)}")
    tools = ", ".join(f"{n} {ver}" for n, ver in data["toolchain"].items())
    dbs = ", ".join(f"{n} {(d or '')[:10]}" for n, d in data["databases"].items())
    snaps = data["snapshots"]
    lines += [
        "",
        "<details><summary>Run</summary>",
        "",
        f"Run `{data['run']}`, scanned {data.get('scanned_utc')} with {tools or 'unknown tools'}; databases "
        f"{dbs or 'unknown'}; EPSS {snaps.get('epss') or 'none'}, KEV {snaps.get('kev') or 'none'}. Every finding, "
        "its location and the factors of its score are in `report.json`; code scanning reads `report.sarif`.",
        "",
        "</details>",
        "",
    ]
    return "\n".join(lines)


def write_all(
    run_dir: Path,
    *,
    sarif_path: Path | None = None,
    json_path: Path | None = None,
    markdown_path: Path | None = None,
    include_all: bool = False,
    location: str | None = None,
    source_root: Path | None = None,
) -> dict[str, Path]:
    """Write the three reports (by default into the run directory) and return where they went."""
    run_dir = Path(run_dir)
    data = report(run_dir, location=location, source_root=source_root)
    log = sarif(run_dir, include_all=include_all, location=location, source_root=source_root)
    paths = {
        "sarif": Path(sarif_path or run_dir / "report.sarif"),
        "json": Path(json_path or run_dir / "report.json"),
        "markdown": Path(markdown_path or run_dir / "report.md"),
    }
    paths["sarif"].write_text(json.dumps(log, indent=2) + "\n", encoding="utf-8")
    paths["json"].write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    paths["markdown"].write_text(markdown(data), encoding="utf-8")
    return paths
