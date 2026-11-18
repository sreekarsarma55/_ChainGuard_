#!/usr/bin/env python3
"""Check the reports (CI runs this; no network, no tools).

A synthetic judged run, with real manifest files in a temporary repository, goes through chainguard.reports and the
CLI. Everything must come out as the module defines it:

  locations    each ecosystem's declaration found on its line (Maven artifactId, npm key, a requirement with its
               name normalised), never a comment; the lockfile for what only it names; the manifest's first line
               otherwise; an absolute target made relative to the repository; images at the given location or
               Dockerfile
  SARIF        one rule per vulnerability with GitHub's security-severity (CVSS, else the severity) and precision;
               a result per finding the policy acted on (fail error, warn warning, excepted suppressed), every
               finding with --sarif-all; stable fingerprints; integrity checks as notifications; GitHub's limits,
               keeping the highest priority
  JSON, MD     every finding in priority order with its outcome; the job summary's decision, tables and exceptions
  CLI          gate writes the reports (not with --no-reports), report needs a verdict, --sarif, --job-summary

    python3 tests/checks/check_reports.py
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainguard import cli, reports  # noqa: E402

LOG4J = "maven/org.apache.logging.log4j/log4j-core@2.14.1"
CONTEXT = "maven/org.springframework/spring-context@5.3.17"  # transitive: the pom does not name it
LODASH, BODY = "npm/lodash@4.17.15", "npm/body-parser@1.19.0"
TYPING = "pypi/typing-extensions@4.16"

POM = """<?xml version="1.0"?>
<!-- Log4Shell is here on purpose: log4j-core 2.14.1 -->
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
"""
PACKAGE = '{\n  "name": "app",\n  "description": "uses lodash",\n  "dependencies": {\n    "lodash": "4.17.15"\n  }\n}\n'
LOCK = (
    '{\n  "packages": {\n    "node_modules/lodash": {"version": "4.17.15"},\n'
    '    "node_modules/body-parser": {}\n  }\n}\n'
)
REQUIREMENTS = "# typing-extensions is pulled in by asgiref\nDjango==3.2.0\ntyping_extensions==4.16.0\n"


def expect(failures: list[str], label: str, got: object, want: object) -> None:
    if got != want:
        failures.append(f"{label}: {got!r}, expected {want!r}")


def finding(
    component,
    vulnerability,
    rank,
    score,
    band,
    *,
    kev=False,
    cvss=None,
    severity="HIGH",
    fix=("9.9",),
    consensus=4,
    not_installed=None,
) -> dict:
    return {
        "component": component,
        "vulnerability": vulnerability,
        "max_severity": severity,
        "consensus": consensus,
        "generators": ["cdxgen", "syft"],
        "scanners": ["grype", "trivy"],
        "raw_ids": [vulnerability],
        "fix_versions": list(fix),
        "not_installed": not_installed,
        "enrichment": {
            "kev": kev,
            "kev_date_added": "2021-12-10" if kev else None,
            "epss": 0.5,
            "epss_percentile": 0.9,
            "cvss_v3": cvss,
            "fix_available": bool(fix),
            "depth": 1,
        },
        "priority": None if not_installed else {"score": score, "band": band, "rank": rank, "factors": {}},
    }


FINDINGS = [
    finding(
        LOG4J,
        "CVE-2021-44228",
        1,
        100.0,
        "critical",
        kev=True,
        cvss=10.0,
        severity="CRITICAL",
        fix=("2.15.0", "2.3.1", "2.12.2"),
    ),
    finding(CONTEXT, "CVE-2022-22968", 2, 65.0, "high", cvss=None, severity="MEDIUM", consensus=2),
    finding(LODASH, "CVE-2021-23337", 3, 62.0, "high", cvss=7.2),
    finding(BODY, "CVE-2024-45590", 4, 30.0, "low", cvss=7.5),
    finding("generic/README@", "CVE-2021-44228", None, 0, "", not_installed="file"),
]
# A not-installed finding with a score anyway (a file from another tool, or an older ChainGuard): never reported.
FINDINGS[-1]["priority"] = {"score": 20.0, "band": "low", "rank": 5, "factors": {}}


def verdict_for(findings: list[dict], excepted=(), integrity=()) -> dict:
    def brief(f):
        return {
            "vulnerability": f["vulnerability"],
            "component": f["component"],
            "score": f["priority"]["score"],
            "band": f["priority"]["band"],
            "rank": f["priority"]["rank"],
            "kev": f["enrichment"]["kev"],
            "fix_versions": f["fix_versions"],
        }

    fail = [brief(f) for f in findings if f["priority"] and f["priority"]["band"] == "critical"]
    warn = [
        brief(f)
        for f in findings
        if f["priority"]
        and f["priority"]["band"] in ("critical", "high")
        and (f["component"], f["vulnerability"]) not in excepted
    ]
    reasons = [{"kind": "integrity", "id": i, "action": "fail", "message": f"{i} happened"} for i in integrity]
    reasons.append({"kind": "rule", "id": "critical-priority", "action": "fail", "message": "m", "findings": fail})
    reasons.append({"kind": "rule", "id": "high-fixable", "action": "warn", "message": "m", "findings": warn})
    return {
        "schema": "chainguard.verdict/v1",
        "decision": "FAIL",
        "evaluated_on": "2026-11-01",
        "policy": {"source": "packaged policy.yaml", "sha256": "ab" * 32},
        "counts": {"findings": 4, "fail": len(fail), "warn": len(warn) - len(fail), "excepted": len(excepted)},
        "reasons": reasons,
        "excepted": [
            {
                **brief(f),
                "rules": ["high-fixable"],
                "exception": {"reason": "not reachable | yet", "approved_by": "security", "expires": "2026-11-30"},
            }
            for f in findings
            if (f["component"], f["vulnerability"]) in excepted
        ],
        "notes": [],
    }


def write_repo(
    root: Path, *, spec: str | None = None, kind: str = "directory", excepted=(), integrity=(), findings=None
) -> tuple[Path, Path]:
    """(repository root, run directory): the target's manifests in the repository, the run beside it."""
    app = root / "repo" / "apps" / "app"
    app.mkdir(parents=True)
    (app / "pom.xml").write_text(POM)
    (app / "package.json").write_text(PACKAGE)
    (app / "package-lock.json").write_text(LOCK)
    (app / "requirements.txt").write_text(REQUIREMENTS)
    run = root / "out" / "run-1"
    run.mkdir(parents=True)
    rows = FINDINGS if findings is None else findings
    manifest = {
        "run_id": "run-1",
        "started_utc": "2026-11-01T00:00:00+00:00",
        "target": {"kind": kind, "spec": spec if spec is not None else "apps/app", "path": str(app)},
        "toolchain": {"grype": {"version": "0.119.0", "database": {"built": "2026-11-01T00:00:00Z"}}},
        "dependency_manifests": {
            "manifests": [
                {"path": "pom.xml", "ecosystem": "maven", "lockfile": None},
                {"path": "package.json", "ecosystem": "npm", "lockfile": "package-lock.json"},
                {"path": "requirements.txt", "ecosystem": "pypi", "lockfile": None},
            ]
        }
        if kind == "directory"
        else None,
        "analysis": {
            "enrichment": {"epss": {"version": "2026-10-31"}, "kev": {"version": "2026.10.30"}},
            "priority": {"source": "packaged priority.yaml", "sha256": "cd" * 32},
        },
    }
    (run / "manifest.json").write_text(json.dumps(manifest))
    (run / "summary.json").write_text(json.dumps({"correlation": {"most_consensus": 4}}))
    (run / "findings.json").write_text(json.dumps({"schema": "chainguard.findings/v3", "correlated": rows}))
    (run / "verdict.json").write_text(json.dumps(verdict_for(rows, excepted, integrity)))
    return root / "repo", run


def check_locations(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo, run = write_repo(Path(tmp))
        locate = reports.Locator(json.loads((run / "manifest.json").read_text()), source_root=repo).locate
        expect(
            failures,
            "Maven: the artifactId line, not the comment",
            locate(LOG4J),
            {"uri": "apps/app/pom.xml", "line": 7, "how": "manifest names it"},
        )
        expect(
            failures,
            "Maven: a transitive dependency",
            locate(CONTEXT),
            {"uri": "apps/app/pom.xml", "line": 1, "how": "manifest of its ecosystem"},
        )
        expect(
            failures,
            "npm: the manifest's key, not its description",
            locate(LODASH),
            {"uri": "apps/app/package.json", "line": 5, "how": "manifest names it"},
        )
        expect(
            failures,
            "npm: only the lockfile names it",
            locate(BODY),
            {"uri": "apps/app/package-lock.json", "line": 4, "how": "lockfile names it"},
        )
        expect(
            failures,
            "PyPI: names normalised, comments skipped",
            locate(TYPING),
            {"uri": "apps/app/requirements.txt", "line": 3, "how": "manifest names it"},
        )
        expect(failures, "PyPI: case", locate("pypi/django@3.2")["line"], 2)
        expect(failures, "no manifest of its ecosystem", locate("deb/debian/libc6@2.36")["how"], "target directory")
        # An absolute target is made relative to the repository; one outside it cannot be.
        _, run2 = write_repo(Path(tmp) / "abs", spec=str(Path(tmp) / "abs" / "repo" / "apps" / "app"))
        m = json.loads((run2 / "manifest.json").read_text())
        expect(
            failures,
            "an absolute target",
            reports.Locator(m, source_root=Path(tmp) / "abs" / "repo").locate(LOG4J)["uri"],
            "apps/app/pom.xml",
        )
        expect(
            failures,
            "a target outside the repository",
            reports.Locator(m, source_root=Path(tmp) / "elsewhere").locate(LOG4J)["how"],
            "default for targets without a manifest",
        )
        _, image = write_repo(Path(tmp) / "img", spec="image.tar", kind="image-archive")
        m = json.loads((image / "manifest.json").read_text())
        expect(failures, "an image: Dockerfile", reports.Locator(m).locate(LOG4J)["uri"], "Dockerfile")
        expect(
            failures,
            "an image: the location given",
            reports.Locator(m, "docker/app.Dockerfile").locate(LOG4J),
            {"uri": "docker/app.Dockerfile", "line": 1, "how": "given location"},
        )


def results_by(log: dict) -> dict[tuple[str, str], dict]:
    return {(r["properties"]["component"], r["ruleId"]): r for r in log["runs"][0]["results"]}


def check_sarif(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo, run = write_repo(Path(tmp), excepted={(LODASH, "CVE-2021-23337")})
        log = reports.sarif(run, source_root=repo)
        expect(failures, "GitHub would accept it", reports.github_problems(log), [])
        got = results_by(log)
        expect(
            failures,
            "results: what the policy acted on",
            sorted(got),
            sorted([(LOG4J, "CVE-2021-44228"), (CONTEXT, "CVE-2022-22968"), (LODASH, "CVE-2021-23337")]),
        )
        expect(
            failures,
            "levels",
            {k[1]: r["level"] for k, r in got.items()},
            {"CVE-2021-44228": "error", "CVE-2022-22968": "warning", "CVE-2021-23337": "warning"},
        )
        lodash = got[(LODASH, "CVE-2021-23337")]
        expect(
            failures,
            "an excepted finding is suppressed, with its justification",
            (
                lodash["suppressions"][0]["status"],
                "approved by security, until 2026-11-30" in lodash["suppressions"][0]["justification"],
            ),
            ("accepted", True),
        )
        log4j = got[(LOG4J, "CVE-2021-44228")]
        expect(
            failures,
            "the title sentence",
            log4j["message"]["text"].split(". ")[0],
            "CVE-2021-44228 in log4j-core 2.14.1, priority 100 (critical, in CISA KEV)",
        )
        if "fixed in 2.3.1, 2.12.2, 2.15.0" not in log4j["message"]["text"]:
            failures.append(f"fixed versions in version order: {log4j['message']['text']}")
        rules = {r["id"]: r for r in log["runs"][0]["tool"]["driver"]["rules"]}
        expect(
            failures, "security-severity from CVSS", rules["CVE-2021-44228"]["properties"]["security-severity"], "10.0"
        )
        expect(
            failures,
            "security-severity from the severity without CVSS",
            rules["CVE-2022-22968"]["properties"]["security-severity"],
            "5.5",
        )
        expect(
            failures,
            "precision from consensus",
            (rules["CVE-2021-44228"]["properties"]["precision"], rules["CVE-2022-22968"]["properties"]["precision"]),
            ("very-high", "high"),
        )
        expect(failures, "a security rule", "security" in rules["CVE-2021-44228"]["properties"]["tags"], True)
        expect(
            failures,
            "rule indexes",
            all(log["runs"][0]["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"] for r in got.values()),
            True,
        )
        expect(
            failures,
            "the fingerprint is the identity, not the line",
            log4j["partialFingerprints"]["primaryLocationLineHash"],
            reports.fingerprint(LOG4J, "CVE-2021-44228") + ":1",
        )
        everything = reports.sarif(run, include_all=True, source_root=repo)
        expect(
            failures,
            "--sarif-all adds the rest as notes, never the not-installed",
            {k[1]: r["level"] for k, r in results_by(everything).items() if r["level"] == "note"},
            {"CVE-2024-45590": "note"},
        )
        _, broken = write_repo(Path(tmp) / "broken", integrity=("tool_failure",))
        inv = reports.sarif(broken)["runs"][0]["invocations"][0]
        expect(
            failures,
            "an integrity failure",
            (inv["executionSuccessful"], inv["toolExecutionNotifications"][0]["level"]),
            (False, "error"),
        )
        # GitHub's limit: the highest-priority results are kept, the rest said to be left out.
        saved = dict(reports.GITHUB_LIMITS)
        try:
            reports.GITHUB_LIMITS["results"] = 2
            small = reports.sarif(run, include_all=True, source_root=repo)
        finally:
            reports.GITHUB_LIMITS.clear()
            reports.GITHUB_LIMITS.update(saved)
        kept = [r["properties"]["rank"] for r in small["runs"][0]["results"]]
        expect(failures, "over the limit: the highest priority kept", kept, [1, 2])
        expect(failures, "and the rules with them", len(small["runs"][0]["tool"]["driver"]["rules"]), 2)
        notes = [n["descriptor"]["id"] for n in small["runs"][0]["invocations"][0]["toolExecutionNotifications"]]
        expect(failures, "and the log says so", "chainguard/report/results-limit" in notes, True)
        bad = json.loads(json.dumps(log))
        bad["runs"][0]["results"][0]["locations"] = []
        bad["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = "0.0"
        expect(failures, "github_problems sees what GitHub would not display", len(reports.github_problems(bad)), 2)


def check_json_and_markdown(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo, run = write_repo(Path(tmp), excepted={(LODASH, "CVE-2021-23337")})
        data = reports.report(run, source_root=repo)
        expect(
            failures,
            "report.json: installed findings in priority order",
            [(f["rank"], f["outcome"]) for f in data["findings"]],
            [(1, "fail"), (2, "warn"), (3, "excepted"), (4, None)],
        )
        expect(
            failures,
            "report.json: the run",
            (data["snapshots"], data["verdict"]["decision"]),
            ({"epss": "2026-10-31", "kev": "2026.10.30"}, "FAIL"),
        )
        expect(failures, "report.json: a finding's location", data["findings"][0]["location"]["line"], 7)
        text = reports.markdown(data)
        for want in (
            "## ChainGuard: **FAIL** · `apps/app`",
            "### Why it fails (1)",
            "### Warnings (1)",
            "### Excepted (1)",
            "not reachable \\| yet",
            "fixed in 2.3.1, 2.12.2, 2.15.0",
        ):
            if want not in text:
                failures.append(f"report.md lacks {want!r}:\n{text}")
        _, broken = write_repo(Path(tmp) / "broken", integrity=("empty_sbom",))
        if "FAIL `empty_sbom`" not in reports.markdown(reports.report(broken)):
            failures.append("report.md lacks the integrity check")


def run_cli(args: list[str], env: dict | None = None) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    old = dict(os.environ)
    os.environ.update(env or {})
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(args)
    finally:
        os.environ.clear()
        os.environ.update(old)
    return code, out.getvalue() + err.getvalue()


def check_cli(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo, run = write_repo(Path(tmp))
        summary = Path(tmp) / "step-summary.md"
        summary.write_text("earlier step\n")
        os.chdir(repo)
        code, text = run_cli(["report", str(run), "--job-summary"], {"GITHUB_STEP_SUMMARY": str(summary)})
        expect(failures, "report exits 0", code, 0)
        expect(
            failures,
            "report writes all three",
            sorted(p.name for p in run.glob("report.*")),
            ["report.json", "report.md", "report.sarif"],
        )
        written = summary.read_text()
        expect(
            failures,
            "--job-summary appends",
            (written.startswith("earlier step\n"), "## ChainGuard: **FAIL**" in written),
            (True, True),
        )
        code, text = run_cli(["report", str(run), "--job-summary"], {"GITHUB_STEP_SUMMARY": ""})
        expect(failures, "--job-summary outside Actions warns", "GITHUB_STEP_SUMMARY is not set" in text, True)
        elsewhere = Path(tmp) / "x.sarif"
        run_cli(["report", str(run), "--sarif", str(elsewhere)])
        expect(failures, "--sarif", json.loads(elsewhere.read_text())["version"], "2.1.0")
        (run / "verdict.json").unlink()
        expect(failures, "report without a verdict exits 2", run_cli(["report", str(run)])[0], 2)
        for p in run.glob("report.*"):
            p.unlink()
        # gate on a run without a summary's priority fails closed, and still writes its reports
        (run / "summary.json").write_text(
            json.dumps(
                {
                    "correlation": {"most_consensus": 4},
                    "priority": {},
                    "components": {"per_generator": {"syft": {"unique_components": 1}}},
                }
            )
        )
        manifest = json.loads((run / "manifest.json").read_text())
        manifest["steps"] = [
            {"name": "syft", "kind": "generate", "ok": True},
            {"name": "syft+grype", "kind": "scan", "ok": True},
        ]
        (run / "manifest.json").write_text(json.dumps(manifest))
        code, _ = run_cli(["gate", str(run), "--on", "2026-11-01"])
        expect(
            failures,
            "gate writes the reports",
            (code, sorted(p.name for p in run.glob("report.*"))),
            (1, ["report.json", "report.md", "report.sarif"]),
        )
        for p in run.glob("report.*"):
            p.unlink()
        run_cli(["gate", str(run), "--no-reports"])
        expect(failures, "--no-reports", list(run.glob("report.*")), [])


def main() -> None:
    failures: list[str] = []
    cwd = os.getcwd()
    try:
        for check in (check_locations, check_sarif, check_json_and_markdown, check_cli):
            check(failures)
    finally:
        os.chdir(cwd)
    for failure in failures:
        print(f"FAIL  {failure}")
    print("reports: locations, SARIF for code scanning, GitHub limits, JSON, job summary, CLI: ", end="")
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
