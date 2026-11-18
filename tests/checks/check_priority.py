#!/usr/bin/env python3
"""Check the priority score (CI runs this; no network, no tools).

Synthetic correlated findings with known enrichment go through chainguard.priority, and a synthetic run directory
through reprocess. Everything must come out as the module defines it:

  config     the packaged priority.yaml is valid and complete; a configuration with a missing factor, an unknown
             key, a negative weight, an unknown value outside [0, 1], no weight at all, or bands that leave a
             score without one is refused; ablation and single-factor baselines
  values     each factor's value: EPSS percentile or score, KEV, CVSS v3 or else the scanner's severity, fix,
             1 / depth, consensus over its maximum; a factor not known takes the configured value and says so
  score      the weighted mean times 100, rescaled when a factor is removed; points add up to the score; bands
  ranking    highest first, deterministic ties; ranks; not-installed findings get no score
  tau        Kendall's tau-b, with ties
  run        findings.json in priority order with each finding's priority, the configuration in the manifest,
             summary.md and the console, a custom configuration, a bad one refused before anything is rewritten

    python3 tests/checks/check_priority.py
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainguard import pipeline, priority, report  # noqa: E402
from chainguard.correlate import CorrelatedFinding, ScannerClaim  # noqa: E402
from chainguard.runner import Step  # noqa: E402


def expect(failures: list[str], label: str, got: object, want: object) -> None:
    if got != want:
        failures.append(f"{label}: {got!r}, expected {want!r}")


def refused(failures: list[str], label: str, call) -> None:
    try:
        call()
        failures.append(f"accepted {label}")
    except priority.ConfigError:
        pass


def packaged() -> dict:
    return yaml.safe_load((Path(priority.__file__).parent / "priority.yaml").read_text())


def check_config(failures: list[str]) -> None:
    config = priority.load()
    expect(failures, "packaged factors", list(config.factors), list(priority.FACTORS))
    expect(failures, "packaged weights sum to 1", round(sum(f.weight for f in config.factors.values()), 6), 1.0)
    expect(failures, "packaged bands", [b for b, _ in config.bands], ["critical", "high", "medium", "low"])
    expect(failures, "a sha256 is recorded", len(config.sha256), 64)
    expect(
        failures,
        "bands",
        [config.band(s) for s in (100, 80, 79.99, 60, 40, 39.9, 0)],
        ["critical", "critical", "high", "high", "medium", "low", "low"],
    )
    base = packaged()
    cases = {
        "a missing factor": lambda d: d["factors"].pop("depth"),
        "an unknown factor": lambda d: d["factors"].__setitem__("reachability", {"weight": 1, "unknown": 0}),
        "an unknown key": lambda d: d.__setitem__("weights", {}),
        "an unknown key in a factor": lambda d: d["factors"]["kev"].__setitem__("wieght", 1),
        "a negative weight": lambda d: d["factors"]["kev"].__setitem__("weight", -0.1),
        "a weight that is no number": lambda d: d["factors"]["kev"].__setitem__("weight", "high"),
        "a boolean weight": lambda d: d["factors"]["kev"].__setitem__("weight", True),
        "an unknown value above 1": lambda d: d["factors"]["epss"].__setitem__("unknown", 1.5),
        "no weight above 0": lambda d: [f.__setitem__("weight", 0) for f in d["factors"].values()],
        "an EPSS use that is neither": lambda d: d["factors"]["epss"].__setitem__("use", "probability"),
        "use on another factor": lambda d: d["factors"]["cvss"].__setitem__("use", "score"),
        "bands that leave low scores without one": lambda d: d["bands"].pop("low"),
        "two bands at one minimum": lambda d: d["bands"].__setitem__("medium", 60),
        "a band above 100": lambda d: d["bands"].__setitem__("critical", 120),
        "an unknown severity": lambda d: d["severity_values"].__setitem__("SEVERE", 0.9),
        "another version": lambda d: d.__setitem__("version", 2),
    }
    for label, change in cases.items():
        data = copy.deepcopy(base)
        change(data)
        refused(failures, label, lambda data=data: priority.parse(data))
    refused(failures, "an ablation of an unknown factor", lambda: config.without("reachability"))
    one = config.only("cvss")
    refused(failures, "an ablation that leaves nothing", lambda: one.without("cvss"))
    expect(failures, "cvss only", {n: f.weight for n, f in one.factors.items() if f.weight}, {"cvss": 1.0})
    expect(failures, "an ablation keeps the others", config.without("kev").factors["epss"].weight, 0.3)
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "bad.yaml"
        bad.write_text("factors: [")
        refused(failures, "invalid YAML", lambda: priority.load(bad))
        refused(failures, "a missing file", lambda: priority.load(Path(tmp) / "none.yaml"))


def finding(
    component: str = "npm/a@1",
    vulnerability: str = "CVE-1",
    *,
    consensus=(2, 2),
    severity="HIGH",
    not_installed=None,
    **enrichment,
) -> CorrelatedFinding:
    generators, scanners = consensus
    claims = {s: ScannerClaim(severities={severity}) for s in ("trivy", "grype")[:scanners]}
    c = CorrelatedFinding(
        vulnerability,
        component,
        claims=claims,
        generators={"syft", "cdxgen"} if generators == 2 else {"cdxgen"} if generators == 1 else set(),
        not_installed=not_installed,
    )
    c.enrichment = {
        "epss": None,
        "epss_percentile": None,
        "kev": None,
        "cvss_v3": None,
        "fix_available": None,
        "depth": None,
        **enrichment,
    }
    return c


def check_values(failures: list[str]) -> None:
    config = priority.load()
    full = finding(epss=0.9, epss_percentile=0.99, kev=True, cvss_v3=9.8, fix_available=True, depth=1)
    s = priority.score(full, config, 4)
    expect(
        failures,
        "values",
        {n: x["value"] for n, x in s["factors"].items()},
        {"epss": 0.99, "kev": 1.0, "cvss": 0.98, "fix": 1.0, "depth": 1.0, "consensus": 1.0},
    )
    expect(failures, "the score", s["score"], round(100 * (0.3 * 0.99 + 0.25 + 0.2 * 0.98 + 0.1 + 0.1 + 0.05), 2))
    expect(
        failures,
        "points add up to the score",
        round(sum(x["points"] for x in s["factors"].values()), 1),
        round(s["score"], 1),
    )
    expect(failures, "band", s["band"], "critical")
    score = finding(epss=0.9, epss_percentile=0.99)
    data = packaged()
    data["factors"]["epss"]["use"] = "score"
    expect(
        failures,
        "EPSS score instead of percentile",
        priority.score(score, priority.parse(data), 4)["factors"]["epss"]["value"],
        0.9,
    )
    bare = priority.score(finding(severity="CRITICAL", consensus=(1, 1)), config, 4)
    f = bare["factors"]
    expect(
        failures,
        "unknown values are the configured ones, and marked",
        {n: (x["known"], x["value"]) for n, x in f.items()},
        {
            "epss": (False, 0.5),
            "kev": (False, 0.0),
            "cvss": (True, 0.95),
            "fix": (False, 0.5),
            "depth": (False, 0.5),
            "consensus": (True, 0.25),
        },
    )
    expect(failures, "CVSS falls back to the scanner's severity", f["cvss"]["from"], "scanner severity")
    unknown_severity = priority.score(finding(severity="UNKNOWN"), config, 4)["factors"]["cvss"]
    expect(
        failures, "an unknown severity is unknown", (unknown_severity["known"], unknown_severity["value"]), (False, 0.5)
    )
    expect(failures, "no fix", priority.score(finding(fix_available=False), config, 4)["factors"]["fix"]["value"], 0.0)
    expect(failures, "not in KEV", priority.score(finding(kev=False), config, 4)["factors"]["kev"]["known"], True)
    expect(failures, "depth 3", priority.score(finding(depth=3), config, 4)["factors"]["depth"]["value"], 0.33333)
    expect(
        failures, "no consensus possible", priority.score(finding(), config, 0)["factors"]["consensus"]["known"], False
    )
    expect(failures, "not installed: no score", priority.score(finding(not_installed="file"), config, 4), None)
    # Not enriched: CVSS and fix from the claims, the rest unknown.
    plain = finding()
    plain.enrichment = None
    plain.claims["trivy"].cvss_v3, plain.claims["grype"].cvss_v3 = 7.5, 9.1
    plain.claims["trivy"].fix_states = {"fixed"}
    f = priority.score(plain, config, 4)["factors"]
    expect(
        failures,
        "not enriched",
        {n: (x["known"], x["value"]) for n, x in f.items() if n in ("cvss", "fix", "epss")},
        {"cvss": (True, 0.91), "fix": (True, 1.0), "epss": (False, 0.5)},
    )
    # An ablation rescales: with KEV removed, a finding with every other factor at 1 still scores 100.
    top = finding(epss_percentile=1.0, kev=False, cvss_v3=10.0, fix_available=True, depth=1)
    expect(failures, "with KEV, a top finding not in KEV", priority.score(top, config, 4)["score"], 75.0)
    expect(failures, "without KEV, rescaled", priority.score(top, config.without("kev"), 4)["score"], 100.0)
    expect(
        failures,
        "a removed factor gives no points",
        priority.score(full, config.without("kev"), 4)["factors"]["kev"]["points"],
        0.0,
    )


def check_ranking(failures: list[str]) -> None:
    config = priority.load()
    found = [
        finding("npm/low@1", "CVE-3", epss_percentile=0.1, cvss_v3=3.0, fix_available=False, depth=3),
        # a tie: the vulnerability decides before the component (b's CVE-0 before a's CVE-2)
        finding("npm/b@1", "CVE-0", epss_percentile=0.9, cvss_v3=9.0, fix_available=True, depth=1),
        finding("npm/a@1", "CVE-2", epss_percentile=0.9, cvss_v3=9.0, fix_available=True, depth=1),
        finding("npm/top@1", "CVE-1", epss_percentile=1.0, kev=True, cvss_v3=10.0, fix_available=True, depth=1),
        finding("generic/README@", "CVE-1", not_installed="file"),
    ]
    ranked, summary = priority.prioritize(found, config, 4)
    expect(
        failures,
        "ranked, highest first, ties by vulnerability then component",
        [c.component for c in ranked],
        ["npm/top@1", "npm/b@1", "npm/a@1", "npm/low@1", "generic/README@"],
    )
    expect(failures, "ranks", [(c.priority or {}).get("rank") for c in ranked], [1, 2, 3, 4, None])
    expect(
        failures,
        "summary",
        (summary["scored"], summary["bands"]),
        (4, {"critical": 1, "high": 2, "medium": 0, "low": 1}),
    )
    expect(failures, "unknown factors counted", summary["unknown_factors"]["kev"], 3)
    expect(
        failures,
        "the top finding's reason",
        summary["top"][0]["why"].split(", ")[:2],
        ["epss 1 (+30)", "kev true (+25)"],
    )
    expect(failures, "the dict carries the priority", ranked[0].as_dict()["priority"]["band"], "critical")


def check_tau(failures: list[str]) -> None:
    a = {"x": 3.0, "y": 2.0, "z": 1.0}
    expect(failures, "tau, same order", priority.kendall_tau(a, a), 1.0)
    expect(failures, "tau, reversed", priority.kendall_tau(a, {"x": 1.0, "y": 2.0, "z": 3.0}), -1.0)
    expect(failures, "tau-b with a tie", priority.kendall_tau(a, {"x": 2.0, "y": 2.0, "z": 1.0}), 0.8165)
    expect(failures, "tau, one item", priority.kendall_tau({"x": 1.0}, {"x": 1.0}), None)
    expect(failures, "tau, only common items", priority.kendall_tau(a, {"x": 1.0, "y": 2.0, "w": 9.0}), -1.0)


def write_run(root: Path) -> Path:
    run_dir = root / "20261101T000000Z-app"
    (run_dir / "raw").mkdir(parents=True)
    app, log4j, lodash = "pkg:npm/app@1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:npm/lodash@1"
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "application", "name": "app", "bom-ref": app}},
        "components": [
            {"type": "library", "name": n, "bom-ref": p, "purl": p}
            for n, p in (("log4j-core", log4j), ("lodash", lodash))
        ],
        "dependencies": [{"ref": app, "dependsOn": [log4j, lodash]}],
    }
    (run_dir / "raw" / "cdxgen.cdx.json").write_text(json.dumps(doc))
    trivy = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-44228",
                        "PkgIdentifier": {"PURL": log4j},
                        "Severity": "HIGH",  # outranks lodash's CRITICAL on CVSS and fix: not severity order
                        "Status": "fixed",
                        "FixedVersion": "2.15.0",
                        "CVSS": {"nvd": {"V3Score": 10.0}},
                    },
                    {"VulnerabilityID": "CVE-2020-0001", "PkgIdentifier": {"PURL": lodash}, "Severity": "CRITICAL"},
                ]
            }
        ]
    }
    (run_dir / "raw" / "cdxgen.trivy.json").write_text(json.dumps(trivy))
    steps = [
        Step("cdxgen", "generate", ["cdxgen"], log="raw/c.log", output="raw/cdxgen.cdx.json", returncode=0).as_dict(),
        Step("cdxgen+trivy", "scan", ["t"], log="raw/t.log", output="raw/cdxgen.trivy.json", returncode=0).as_dict(),
    ]
    manifest = {
        "chainguard": "0.1.0",
        "run_id": run_dir.name,
        "target": {"kind": "directory", "spec": "app"},
        "options": {"sbom_format": "cyclonedx"},
        "toolchain": {},
        "steps": steps,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    return run_dir


def check_run_directory(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        run_dir = write_run(Path(tmp))
        options = pipeline.AnalysisOptions(aliases="scanner", enrichment_dir=Path(tmp) / "empty")
        result = pipeline.reprocess(run_dir, options)
        data = json.loads((run_dir / "findings.json").read_text())
        expect(
            failures,
            "findings.json in priority order",
            [(c["vulnerability"], c["priority"]["rank"]) for c in data["correlated"]],
            [("CVE-2021-44228", 1), ("CVE-2020-0001", 2)],
        )
        record = json.loads((run_dir / "manifest.json").read_text())["analysis"]["priority"]
        expect(
            failures,
            "the manifest records the configuration",
            (record["source"], len(record["sha256"])),
            ("packaged priority.yaml", 64),
        )
        text = (run_dir / "summary.md").read_text()
        if "## Priority" not in text or "| 1 | " not in text:
            failures.append(f"summary.md lacks the priority section:\n{text[:400]}")
        if "Priority: critical" not in report.render_console(result.summary):
            failures.append("the console lacks the priority line")
        # A custom configuration: CVSS only. Recorded, and the scores follow it.
        custom = packaged()
        for name, factor in custom["factors"].items():
            factor["weight"] = 1.0 if name == "cvss" else 0.0
        path = Path(tmp) / "cvss.yaml"
        path.write_text(yaml.safe_dump(custom))
        pipeline.reprocess(run_dir, pipeline.AnalysisOptions(aliases="scanner", enrichment=False, priority_config=path))
        data = json.loads((run_dir / "findings.json").read_text())
        expect(
            failures,
            "a custom configuration's scores",
            [c["priority"]["score"] for c in data["correlated"]],
            [100.0, 95.0],
        )
        expect(
            failures,
            "and its record",
            json.loads((run_dir / "manifest.json").read_text())["analysis"]["priority"]["source"],
            str(path),
        )
        before = (run_dir / "findings.json").read_text()
        path.write_text("version: 1\nfactors: {}\n")
        try:
            pipeline.reprocess(run_dir, pipeline.AnalysisOptions(aliases="scanner", priority_config=path))
            failures.append("reprocess accepted a bad configuration")
        except priority.ConfigError:
            pass
        expect(
            failures, "a bad configuration rewrites nothing", (run_dir / "findings.json").read_text() == before, True
        )
        try:
            pipeline.scan(
                str(run_dir),
                Path(tmp) / "out",
                pipeline.ScanOptions(),
                analysis=pipeline.AnalysisOptions(priority_config=path),
            )
            failures.append("scan accepted a bad configuration")
        except priority.ConfigError:
            pass
        except Exception as exc:  # it went on towards running tools
            failures.append(f"scan did not refuse a bad configuration first ({type(exc).__name__})")


def main() -> None:
    failures: list[str] = []
    for check in (check_config, check_values, check_ranking, check_tau, check_run_directory):
        check(failures)
    for failure in failures:
        print(f"FAIL  {failure}")
    print("priority: configuration, values, unknowns, score, ablation, ranking, tau, run directory: ", end="")
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
