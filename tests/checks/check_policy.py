#!/usr/bin/env python3
"""Check the policy engine (CI runs this; no network, no tools).

Synthetic run directories, as the analysis writes them, go through chainguard.policy and the CLI. Everything must
come out as the module defines it:

  policy       the packaged policy.yaml is valid; unknown keys, checks, actions and conditions, rules without an
               id or a condition, values of the wrong kind, and exceptions that are not explained, approved and
               time-boxed are refused
  conditions   each condition, its patterns, and a value that is not known never satisfying one
  integrity    a failed tool, an empty SBOM, no scan, no priority scores and a missing snapshot fail closed; a
               fused loss and unlocked manifests warn; every check can be set to another action, or ignored
  rules        the most severe action decides; a finding counts once; not-installed findings never trigger one
  exceptions   a live exception accepts a finding and is listed with its reason; an expired one no longer applies
               and warns; one that matches nothing is noted; --on decides what is expired
  CLI          gate exit codes 0 / 1 / 2, verdict.json, and scan refusing a bad policy before any tool runs

    python3 tests/checks/check_policy.py
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
from datetime import date
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainguard import cli, policy  # noqa: E402

TODAY = date(2026, 11, 1)
LOG4J, SPRING, LODASH = (
    "maven/org.apache.logging.log4j/log4j-core@2.14.1",
    "maven/org.springframework/spring-beans@5.3.17",
    "npm/lodash@4.17.15",
)


def expect(failures: list[str], label: str, got: object, want: object) -> None:
    if got != want:
        failures.append(f"{label}: {got!r}, expected {want!r}")


def correlated(
    component: str,
    vulnerability: str,
    score: float,
    band: str,
    *,
    kev=False,
    fix=True,
    depth=1,
    consensus=4,
    severity="HIGH",
    not_installed=None,
    epss=0.5,
    percentile=0.9,
    cvss=7.5,
) -> dict:
    return {
        "component": component,
        "vulnerability": vulnerability,
        "max_severity": severity,
        "consensus": consensus,
        "not_installed": not_installed,
        "fix_versions": ["9.9"] if fix else [],
        "enrichment": {
            "kev": kev,
            "epss": epss,
            "epss_percentile": percentile,
            "cvss_v3": cvss,
            "fix_available": fix,
            "depth": depth,
        },
    } | ({} if not_installed else {"priority": {"score": score, "band": band, "rank": 1}})  # as findings.json writes it


FINDINGS = [
    correlated(LOG4J, "CVE-2021-44228", 100.0, "critical", kev=True, severity="CRITICAL", cvss=10.0),
    correlated(SPRING, "CVE-2022-22965", 92.1, "critical", kev=True, depth=2, consensus=2, severity="CRITICAL"),
    correlated(LODASH, "CVE-2021-23337", 68.7, "high"),
    correlated(LODASH, "CVE-2020-8203", 65.0, "high", fix=False),  # high, but no fix: not warned
    correlated("npm/minimist@1.2.5", "CVE-2021-44906", 45.0, "medium"),
    correlated("generic/README@", "CVE-2021-44228", 0, "", kev=True, not_installed="file"),
]


def write_run(
    root: Path,
    name: str = "run",
    *,
    findings=None,
    failed=(),
    empty=(),
    schema="chainguard.findings/v3",
    snapshots=("epss", "kev"),
    fused_lossless=None,
    manifests=(("pom.xml", "locked"),),
    priority=True,
) -> Path:
    run = root / name
    run.mkdir(parents=True)
    names = ["syft", "cdxgen", "syft+trivy", "syft+grype", "cdxgen+trivy", "cdxgen+grype", "fused+trivy", "fused+grype"]
    steps = [
        {
            "name": n,
            "kind": "scan" if "+" in n else "generate",
            "ok": n not in failed,
            "error": "exit 1" if n in failed else None,
        }
        for n in names
    ]
    manifest = {
        "run_id": name,
        "target": {"spec": "app"},
        "steps": steps,
        "analysis": {"enrichment": {k: ({"version": "v"} if k in snapshots else None) for k in ("epss", "kev")}},
    }
    per_generator = {g: {"unique_components": 0 if g in empty else 10} for g in ("syft", "cdxgen") if g not in failed}
    summary = {
        "components": {"per_generator": per_generator},
        "handoff": {
            "fused_lossless": fused_lossless,
            "warnings": ["fused+trivy lost 1"] if fused_lossless is False else [],
        },
        "lockfiles": {"manifests": [{"path": p, "status": s} for p, s in manifests]},
    }
    if priority:
        summary["priority"] = {}
    rows = copy.deepcopy(FINDINGS if findings is None else findings)
    if not priority:
        for r in rows:
            r.pop("priority", None)
    (run / "manifest.json").write_text(json.dumps(manifest))
    (run / "summary.json").write_text(json.dumps(summary))
    (run / "findings.json").write_text(json.dumps({"schema": schema, "correlated": rows}))
    return run


def packaged() -> dict:
    return yaml.safe_load((Path(policy.__file__).parent / "policy.yaml").read_text())


def check_policy(failures: list[str]) -> None:
    p = policy.load(today=TODAY)
    expect(
        failures,
        "packaged rules",
        [r.id for r in p.rules],
        ["known-exploited", "critical-priority", "high-priority-fixable"],
    )
    expect(failures, "packaged integrity", dict(p.integrity), policy.INTEGRITY)
    expect(failures, "a sha256", len(p.sha256), 64)
    exception = {"vulnerability": "CVE-1", "reason": "r", "approved_by": "a", "expires": "2026-12-01"}
    cases = {
        "an unknown key": lambda d: d.__setitem__("rule", []),
        "an unknown integrity check": lambda d: d["integrity"].__setitem__("tool_failed", "fail"),
        "an unknown integrity action": lambda d: d["integrity"].__setitem__("tool_failure", "block"),
        "a rule action ignore": lambda d: d["rules"][0].__setitem__("action", "ignore"),
        "a rule without an id": lambda d: d["rules"][0].pop("id"),
        "two rules with one id": lambda d: d["rules"][1].__setitem__("id", "known-exploited"),
        "a rule without a condition": lambda d: d["rules"][0].__setitem__("when", {}),
        "an unknown condition": lambda d: d["rules"][0]["when"].__setitem__("exploited", True),
        "a score above 100": lambda d: d["rules"][0]["when"].__setitem__("score_min", 120),
        "a kev that is no boolean": lambda d: d["rules"][0]["when"].__setitem__("kev", "yes"),
        "an unknown severity": lambda d: d["rules"][0]["when"].__setitem__("severity", "SEVERE"),
        "a depth of 0": lambda d: d["rules"][0]["when"].__setitem__("depth_max", 0),
        "another version": lambda d: d.__setitem__("version", 2),
        "an exception without a reason": lambda d: d.__setitem__("exceptions", [{**exception, "reason": ""}]),
        "an exception without an approver": lambda d: d.__setitem__("exceptions", [{**exception, "approved_by": ""}]),
        "an exception without an expiry": lambda d: d.__setitem__("exceptions", [{**exception, "expires": None}]),
        "an exception that is no date": lambda d: d.__setitem__("exceptions", [{**exception, "expires": "soon"}]),
        "an exception beyond max_exception_days": lambda d: d.__setitem__(
            "exceptions", [{**exception, "expires": "2027-03-01"}]
        ),
        "a max_exception_days of 0": lambda d: d.__setitem__("max_exception_days", 0),
    }
    for label, change in cases.items():
        data = packaged()
        change(data)
        try:
            policy.parse(data, today=TODAY)
            failures.append(f"accepted {label}")
        except policy.PolicyError:
            pass
    data = packaged()
    data["exceptions"] = [{**exception, "expires": date(2027, 1, 30)}]  # YAML gives a date; exactly 90 days
    expect(failures, "an exception at exactly the limit", len(policy.parse(data, today=TODAY).exceptions), 1)


def check_conditions(failures: list[str]) -> None:
    f = FINDINGS[1]  # spring-beans: KEV, critical, depth 2, consensus 2
    cases = [
        ("kev", True, True),
        ("kev", False, False),
        ("band", ["high", "critical"], True),
        ("band", "high", False),
        ("score_min", 92.1, True),
        ("score_min", 92.2, False),
        ("depth_max", 2, True),
        ("depth_max", 1, False),
        ("consensus_min", 3, False),
        ("severity", "critical", True),
        ("type", ["npm", "maven"], True),
        ("component", "maven/org.springframework/*", True),
        ("component", "npm/*", False),
        ("vulnerability", "CVE-2022-*", True),
        ("fix_available", True, True),
        ("cvss_min", 7.5, True),
        ("epss_min", 0.6, False),
        ("epss_percentile_min", 0.9, True),
    ]
    for key, wanted, want in cases:
        expect(failures, f"condition {key}={wanted!r}", policy.holds(key, wanted, f), want)
    unknown = copy.deepcopy(f)
    unknown["enrichment"].update(kev=None, depth=None, fix_available=None)
    for key, wanted in (("kev", False), ("depth_max", 5), ("fix_available", False)):
        expect(failures, f"an unknown value never satisfies {key}", policy.holds(key, wanted, unknown), False)


def verdict(run: Path, data: dict | None = None, on: date = TODAY) -> dict:
    return policy.evaluate(run, policy.parse(data or packaged(), today=on))


def reasons(v: dict) -> dict[str, str]:
    return {r["id"]: r["action"] for r in v["reasons"]}


def check_integrity(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        clean = [correlated("npm/a@1", "CVE-1", 30.0, "low")]
        expect(failures, "a clean run passes", verdict(write_run(root, "clean", findings=clean))["decision"], "PASS")
        # A finding on an entry that is not installed software has no score, as findings.json writes it: that is
        # not a run without scores (a bug that once failed clean runs).
        with_file = [*clean, correlated("generic/README@", "CVE-2021-44228", 0, "", kev=True, not_installed="file")]
        v = verdict(write_run(root, "not-installed", findings=with_file))
        expect(failures, "an unscored not-installed finding is not a missing score", v["decision"], "PASS")
        faults = {
            "tool_failure": dict(failed=("cdxgen+grype",)),
            "empty_sbom": dict(empty=("cdxgen",)),
            "no_scan": dict(
                failed=(
                    "syft",
                    "cdxgen",
                    "syft+trivy",
                    "syft+grype",
                    "cdxgen+trivy",
                    "cdxgen+grype",
                    "fused+trivy",
                    "fused+grype",
                )
            ),
            "not_prioritised": dict(schema="chainguard.findings/v2", priority=False),
            "missing_snapshot": dict(snapshots=("epss",)),
            "fused_loss": dict(fused_lossless=False),
            "unlocked_manifest": dict(manifests=(("requirements.txt", "pinned"),)),
        }
        for check, kwargs in faults.items():
            v = verdict(write_run(root, check, findings=clean, **kwargs))
            want = policy.INTEGRITY[check]
            expect(failures, f"{check}: {want}s", (reasons(v).get(check), v["decision"]), (want, policy.ACTIONS[want]))
        data = packaged()
        # Each half of "not prioritised" alone: a v3 run without scores, and scores in an older schema.
        for label, kwargs in (
            ("v3-unscored", dict(priority=False)),
            ("v2-scored", dict(schema="chainguard.findings/v2")),
        ):
            v = verdict(write_run(root, label, findings=clean, **kwargs))
            expect(failures, f"not prioritised: {label}", reasons(v).get("not_prioritised"), "fail")
        data["integrity"] = {"unlocked_manifest": "fail", "tool_failure": "ignore"}
        v = verdict(root / "unlocked_manifest", data)
        expect(failures, "a check set to fail", v["decision"], "FAIL")
        expect(failures, "a check ignored", "tool_failure" in reasons(verdict(root / "tool_failure", data)), False)
        no_kev = verdict(root / "missing_snapshot")
        expect(failures, "the missing snapshot is named", [r["details"] for r in no_kev["reasons"]], [["KEV"]])
        (root / "clean" / "findings.json").unlink()
        try:
            verdict(root / "clean")
            failures.append("a run without findings.json was judged")
        except policy.PolicyError:
            pass


def check_rules(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        v = verdict(write_run(Path(tmp)))
        expect(failures, "decision", v["decision"], "FAIL")
        expect(
            failures,
            "rules triggered",
            reasons(v),
            {"known-exploited": "fail", "critical-priority": "fail", "high-priority-fixable": "warn"},
        )
        expect(
            failures,
            "each finding counts once, under its most severe action",
            v["counts"],
            {"findings": 5, "fail": 2, "warn": 1, "excepted": 0},
        )
        kev = next(r for r in v["reasons"] if r["id"] == "known-exploited")
        expect(
            failures,
            "a not-installed finding triggers nothing",
            [f["component"] for f in kev["findings"]],
            [LOG4J, SPRING],
        )
        expect(failures, "fails listed first", [r["action"] for r in v["reasons"]], ["fail", "fail", "warn"])
        only_warn = [correlated(LODASH, "CVE-2021-23337", 68.7, "high")]
        expect(
            failures,
            "a warning alone warns",
            verdict(write_run(Path(tmp), "w", findings=only_warn))["decision"],
            "WARN",
        )


def check_exceptions(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        run = write_run(Path(tmp))
        data = packaged()
        data["exceptions"] = [
            {
                "vulnerability": "CVE-2021-44228",
                "component": "maven/org.apache.logging.log4j/*",
                "reason": "not reachable",
                "approved_by": "security",
                "expires": "2026-11-30",
            },
            {
                "vulnerability": "CVE-2022-22965",
                "reason": "mitigated by WAF",
                "approved_by": "security",
                "expires": "2026-11-15",
            },
            {"vulnerability": "CVE-1999-0001", "reason": "old", "approved_by": "security", "expires": "2026-12-01"},
        ]
        v = verdict(run, data)
        expect(
            failures,
            "both KEV findings accepted: only the warning is left",
            (v["decision"], v["counts"]["excepted"]),
            ("WARN", 2),
        )
        expect(
            failures,
            "an exception is listed with its reason",
            sorted(x["exception"]["reason"] for x in v["excepted"]),
            ["mitigated by WAF", "not reachable"],
        )
        expect(failures, "an exception matching nothing is noted", len(v["notes"]), 1)
        last_day = verdict(run, data, on=date(2026, 11, 15))
        expect(failures, "an exception still applies on its expiry date", last_day["counts"]["excepted"], 2)
        later = verdict(run, data, on=date(2026, 11, 20))  # the second exception expired on the 15th
        expect(
            failures,
            "an expired exception no longer applies",
            (later["decision"], later["counts"]["excepted"]),
            ("FAIL", 1),
        )
        expect(failures, "and warns", reasons(later).get("expired"), "warn")
        wrong = copy.deepcopy(data)
        wrong["exceptions"] = [{**data["exceptions"][0], "component": "maven/other/*"}]
        expect(
            failures, "an exception for another component accepts nothing", verdict(run, wrong)["counts"]["excepted"], 0
        )


def run_cli(args: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(args)
    return code, out.getvalue() + err.getvalue()


def check_cli(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        failing = write_run(root, "failing")
        code, text = run_cli(["gate", str(failing), "--on", "2026-10-25"])
        expect(failures, "gate FAIL exits 1", code, 1)
        if "Gate: FAIL" not in text or "CVE-2021-44228 on " + LOG4J not in text:
            failures.append(f"gate output:\n{text[:500]}")
        written = json.loads((failing / "verdict.json").read_text())
        expect(
            failures,
            "verdict.json",
            (written["schema"], written["decision"], written["evaluated_on"]),
            ("chainguard.verdict/v1", "FAIL", "2026-10-25"),
        )
        warning = write_run(root, "warning", findings=[correlated(LODASH, "CVE-2021-23337", 68.7, "high")])
        expect(failures, "gate WARN exits 0", run_cli(["gate", str(warning)])[0], 0)
        bad = root / "bad.yaml"
        bad.write_text("version: 1\nrules: [{id: x, when: {kev: true}, action: block}]\n")
        expect(failures, "a bad policy exits 2", run_cli(["gate", str(warning), "--policy", str(bad)])[0], 2)
        expect(failures, "a missing run exits 2", run_cli(["gate", str(root / "none")])[0], 2)
        code, text = run_cli(["scan", str(root), "--policy", str(bad), "--out", str(root / "out")])
        expect(
            failures,
            "scan refuses a bad policy before any tool runs",
            (code, (root / "out").exists(), "error: policy:" in text, "scanning" in text),
            (2, False, True, False),
        )


def main() -> None:
    failures: list[str] = []
    for check in (check_policy, check_conditions, check_integrity, check_rules, check_exceptions, check_cli):
        check(failures)
    for failure in failures:
        print(f"FAIL  {failure}")
    print("policy: policy file, conditions, integrity (fail closed), rules, exceptions, CLI exit codes: ", end="")
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
