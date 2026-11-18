#!/usr/bin/env python3
"""Check correlator v1 (CI runs this; no network, no tools, no images).

Synthetic findings on a Debian image, shaped like a real image: Trivy loses a pair on Syft's SBOM
and on cdxgen's but reports it on the merged SBOM, cdxgen lists a source package as if installed, and
scanners report one vulnerability under different IDs. Correlator v1 must count evidence, not pipelines:

  consensus     generators listing the component x scanners reporting it through any SBOM pipeline, fused
                included; the pipelines that reported it are kept apart as pipelines_reporting
  references    a direct scan is never evidence
  not installed a finding on a source package listed as installed stays on its key, scores 0 and supports
                nothing installed
  claims        one claim per scanner, keeping its own IDs; several advisories merged into one CVE keep the
                highest severity and CVSS, every fix version, the most actionable fix state, and say so
  merged view   highest severity and CVSS, every fix state and version, EPSS max, KEV any
  run directory analyze() credits the generators of the merged inventory; findings.json is v2; summary.md
                shows both counts

    python3 tests/checks/check_correlator.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainguard import aliases, correlate, pipeline, report, sbom  # noqa: E402
from chainguard import purl as purls  # noqa: E402
from chainguard.runner import Step  # noqa: E402
from chainguard.scanners import Finding  # noqa: E402

LIBC6 = "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12"
ZLIB = "pkg:deb/debian/zlib1g@1.2.13-1?arch=amd64&distro=debian-12"
GLIBC = "pkg:deb/debian/glibc@2.36-9?distro=debian-12"  # cdxgen's source package, listed as if installed
DJANGO = "pkg:pypi/django@3.2"
KEY = {p: purls.key(p) for p in (LIBC6, ZLIB, GLIBC, DJANGO)}


def cyclonedx(*entries: str) -> dict:
    components = [{"type": "operating-system", "name": "debian", "version": "12"}]
    for p in entries:
        parsed = purls.parse(p)
        components.append({"type": "library", "name": parsed.name, "version": parsed.version, "purl": p})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}


# Syft states the source package of each binary, which is what lets cdxgen's glibc entry be recognised (D9).
SYFT = cyclonedx(LIBC6 + "&upstream=glibc", ZLIB, DJANGO)
CDXGEN = cyclonedx(LIBC6, ZLIB, GLIBC)  # no Django


def finding(pipeline_name: str, purl: str, canonical: str, raw: str | None = None, **values) -> Finding:
    f = Finding(
        pipeline=pipeline_name,
        scanner=pipeline_name.split("+", 1)[1],
        raw_id=raw or canonical,
        related=(),
        component=purls.key(purl) or "",
        purl=purl,
        severity=values.get("severity", "HIGH"),
        cvss_v3=values.get("cvss_v3"),
        fix_state=values.get("fix_state", "unknown"),
        fix_versions=tuple(values.get("fix_versions", ())),
        epss=values.get("epss"),
        kev=values.get("kev"),
    )
    f.vulnerability, f.vulnerabilities = canonical, (canonical,)  # as alias resolution leaves them
    return f


def inventory():
    sboms = {"syft": sbom.parse(SYFT), "cdxgen": sbom.parse(CDXGEN)}
    entries, suppressed = correlate.canonical_inventory(sboms)
    return sboms, entries, correlate.non_components(sboms, entries, suppressed)


FINDINGS = [
    # CVE-1 on libc6: both generators list it. Trivy loses it on both generators' SBOMs (F2, F3) and reports it
    # on the merged one; Grype reports it on Syft's SBOM as a GHSA, and on cdxgen's against the source package.
    finding("fused+trivy", LIBC6, "CVE-1", severity="MEDIUM", cvss_v3=5.5, fix_state="not_fixed"),
    finding("fused-spdx+trivy", LIBC6, "CVE-1", severity="MEDIUM", cvss_v3=5.5, fix_state="not_fixed"),
    finding(
        "syft+grype",
        LIBC6,
        "CVE-1",
        "GHSA-0001",
        severity="HIGH",
        cvss_v3=7.5,
        fix_state="fixed",
        fix_versions=("2.36-9+deb12u1",),
        epss=0.2,
        kev=False,
    ),
    finding(
        "fused+grype",
        LIBC6,
        "CVE-1",
        "GHSA-0001",
        severity="HIGH",
        cvss_v3=7.5,
        fix_state="fixed",
        fix_versions=("2.36-9+deb12u1",),
        epss=0.2,
        kev=False,
    ),
    finding("cdxgen+grype", GLIBC, "CVE-1", "GHSA-0001", severity="HIGH"),
    # CVE-2 on Django: only Syft lists it; Grype merges two advisories into one CVE (D1), one HIGH, one LOW.
    finding("syft+grype", DJANGO, "CVE-2", "GHSA-0002", severity="HIGH", cvss_v3=7.5, fix_state="not_fixed"),
    finding(
        "syft+grype",
        DJANGO,
        "CVE-2",
        "GHSA-0003",
        severity="LOW",
        cvss_v3=3.1,
        fix_state="fixed",
        fix_versions=("3.2.19",),
        kev=True,
    ),
    # CVE-3 on zlib1g: only a direct scan reports it, which is a reference and never evidence.
    finding("direct+trivy", ZLIB, "CVE-3"),
    # CVE-4 on a component no generator lists (a scanner finding without a PURL)
    finding("syft+trivy", "pkg:generic/mystery@1", "CVE-4"),
]


def entries(found: list[correlate.CorrelatedFinding]) -> dict[tuple[str, str], correlate.CorrelatedFinding]:
    return {(c.component, c.vulnerability): c for c in found}


def check_consensus(failures: list[str]) -> None:
    _, inv, not_installed = inventory()
    got = entries(correlate.correlate(FINDINGS, not_installed, inv))
    libc = got.get((KEY[LIBC6], "CVE-1"))
    if libc is None:
        failures.append("libc6 CVE-1 is missing from the correlated view")
        return
    if (libc.consensus, libc.pipelines_reporting, libc.scanners) != (4, 1, ["grype", "trivy"]):
        failures.append(
            f"libc6 CVE-1: consensus {libc.consensus}, pipelines_reporting {libc.pipelines_reporting}, scanners "
            f"{libc.scanners}; expected 4 (2 generators x 2 scanners), 1 (only syft+grype among single pipelines)"
        )
    django = got.get((KEY[DJANGO], "CVE-2"))
    if django is None or (django.consensus, django.pipelines_reporting) != (1, 1):
        failures.append(f"Django CVE-2: expected consensus 1 (Syft x Grype), got {django and django.consensus}")
    if (KEY[ZLIB], "CVE-3") in got:
        failures.append("a pair only a direct scan reports was counted: a direct scan is a reference, not evidence")
    glibc = got.get((KEY[GLIBC], "CVE-1"))
    if glibc is None or glibc.not_installed != "source-package" or glibc.consensus != 0:
        failures.append(
            f"a finding on a source package listed as installed must stay on its key, marked, with consensus 0: "
            f"{glibc and (glibc.not_installed, glibc.consensus)}"
        )
    if "cdxgen+grype" in libc.reported_by:
        failures.append("the finding on the source package was moved onto libc6")
    mystery = got.get(("generic/mystery@1", "CVE-4"))
    if mystery is None or mystery.generators or mystery.consensus != 0:
        failures.append(f"a component no generator lists must have consensus 0: {mystery and mystery.consensus}")
    if any(c.consensus for c in correlate.correlate(FINDINGS, not_installed)):
        failures.append("without an inventory no generator is credited, so every consensus must be 0")


def check_claims(failures: list[str]) -> None:
    _, inv, not_installed = inventory()
    got = entries(correlate.correlate(FINDINGS, not_installed, inv))
    if (KEY[LIBC6], "CVE-1") not in got or (KEY[DJANGO], "CVE-2") not in got:
        failures.append("claims: libc6 CVE-1 or Django CVE-2 is missing from the correlated view")
        return
    libc = got[(KEY[LIBC6], "CVE-1")].as_dict()
    grype, trivy = libc["claims"].get("grype", {}), libc["claims"].get("trivy", {})
    if grype.get("pipelines") != ["fused+grype", "syft+grype"] or trivy.get("pipelines") != [
        "fused+trivy",
        "fused-spdx+trivy",
    ]:
        failures.append(f"one claim per scanner, with every pipeline that fed it: {libc['claims']}")
    if grype.get("ids") != ["GHSA-0001"] or trivy.get("ids") != ["CVE-1"]:
        failures.append(f"each claim must keep the scanner's own IDs: {grype.get('ids')}, {trivy.get('ids')}")
    merged = {k: libc[k] for k in ("max_severity", "cvss_v3", "fix_states", "fix_versions")}
    want = {
        "max_severity": "HIGH",
        "cvss_v3": 7.5,
        "fix_states": ["fixed", "not_fixed"],
        "fix_versions": ["2.36-9+deb12u1"],
    }
    if merged != want:
        failures.append(f"merged across scanners: {merged}, expected {want}")
    # EPSS and KEV come from dated snapshots, never merged from Grype's claim.
    if "epss" in libc or "kev" in libc or (grype.get("epss"), grype.get("kev")) != (0.2, False):
        failures.append(f"Grype's EPSS and KEV belong in its claim only: {libc}")
    django = got[(KEY[DJANGO], "CVE-2")].as_dict()["claims"].get("grype", {})
    want = {
        "severity": "HIGH",
        "cvss_v3": 7.5,
        "fix_state": "fixed",
        "fix_versions": ["3.2.19"],
        "kev": True,
        "severities_reported": ["HIGH", "LOW"],
        "fix_states_reported": ["fixed", "not_fixed"],
        "ids": ["GHSA-0002", "GHSA-0003"],
    }
    if {k: django.get(k) for k in want} != want:
        failures.append(f"two advisories merged into one CVE: claim {django}, expected {want}")
    if "severities_reported" in trivy:
        failures.append("a unanimous claim must not list merged values")


def check_summary(failures: list[str]) -> None:
    _, inv, not_installed = inventory()
    found = correlate.correlate(FINDINGS, not_installed, inv)
    pipelines = ["syft+trivy", "syft+grype", "cdxgen+trivy", "cdxgen+grype", "fused+trivy", "fused+grype"]
    summary = report.correlation_summary(found, 2, pipelines)
    want = {
        "pairs": 3,
        "most_consensus": 4,
        "consensus": {"4": 1, "1": 1, "0": 1},
        "pipelines_reporting": {"1": 3},
        "on_unlisted_components": 1,
        "on_not_installed": 1,
        "reported_by_several_scanners": 1,
        "scanners_disagree": {"severity": 1, "fix_state": 1, "fix_versions": 1},
    }
    if summary != want:
        failures.append(f"correlation summary {summary}, expected {want}")
    # A scanner whose every scan failed gives no evidence, so it does not raise the most consensus there can be.
    sboms, _, _ = inventory()
    steps = [Step(p, "scan", [], log="", returncode=1 if p.endswith("+grype") else 0) for p in pipelines]
    full = report.summarize(sboms, inv, FINDINGS, found, aliases.resolve(FINDINGS, None), steps)
    if full["correlation"]["most_consensus"] != 2:
        failures.append(
            f"most consensus with Grype's scans failed: {full['correlation']['most_consensus']}, expected 2"
        )
    text = "\n".join(report.correlation_lines(summary))
    for needle in (
        "| Consensus: generators listing the component × scanners reporting it | 1 | 0 | 0 | 1 | 1 |",
        "| Single pipelines that reported it | 0 | 0 | 0 | 3 | 0 |",
        "1 pairs on entries that are not installed software",
        "1 on components no generator lists",
    ):
        if needle not in text:
            failures.append(f"summary.md section lacks {needle!r}:\n{text}")


def trivy_report(rows: list[tuple[str, str]]) -> dict:
    vulnerabilities = []
    for purl, vulnerability in rows:
        parsed = purls.parse(purl)
        vulnerabilities.append(
            {
                "VulnerabilityID": vulnerability,
                "PkgName": parsed.name,
                "InstalledVersion": parsed.version,
                "PkgIdentifier": {"PURL": purl},
                "Severity": "HIGH",
            }
        )
    return {"Results": [{"Target": "image", "Type": "debian", "Vulnerabilities": vulnerabilities}]}


def check_run_directory(failures: list[str]) -> None:
    """analyze() must credit the merged inventory's generators: Trivy loses CVE-1 on cdxgen's SBOM and reports it
    on Syft's and the merged one, so the evidence is 2 generators x 1 scanner."""
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp) / "20261017T000000Z-image.tar"
        (run / "raw").mkdir(parents=True)
        files = {
            "raw/syft.cdx.json": SYFT,
            "raw/cdxgen.cdx.json": CDXGEN,
            "fused.cdx.json": cyclonedx(LIBC6, ZLIB, DJANGO),
            "raw/syft.trivy.json": trivy_report([(LIBC6, "CVE-1")]),
            "raw/cdxgen.trivy.json": trivy_report([]),
            "raw/fused.trivy.json": trivy_report([(LIBC6, "CVE-1"), (ZLIB, "CVE-3")]),
        }
        for name, content in files.items():
            (run / name).write_text(json.dumps(content))

        def step(name: str, kind: str, output: str) -> dict:
            return Step(name, kind, [name], log=f"raw/{name}.log", output=output, returncode=0).as_dict()

        manifest = {
            "chainguard": "0.1.0",
            "run_id": run.name,
            "target": {"kind": "image-archive", "spec": "image.tar"},
            "options": {"sbom_format": "cyclonedx"},
            "toolchain": {},
            "steps": [
                step("syft", "generate", "raw/syft.cdx.json"),
                step("cdxgen", "generate", "raw/cdxgen.cdx.json"),
                step("syft+trivy", "scan", "raw/syft.trivy.json"),
                step("cdxgen+trivy", "scan", "raw/cdxgen.trivy.json"),
                step("fused+trivy", "scan", "raw/fused.trivy.json"),
            ],
            "fused": {"sboms": {"fused": "fused.cdx.json"}},
        }
        (run / "manifest.json").write_text(json.dumps(manifest))
        pipeline.reprocess(run, pipeline.AnalysisOptions(aliases="scanner"))
        data = json.loads((run / "findings.json").read_text())
        if data.get("schema") != "chainguard.findings/v3":  # v3: v2 plus each pair's enrichment
            failures.append(f"run directory: findings.json schema {data.get('schema')}, expected v3")
        got = {(c["component"], c["vulnerability"]): c for c in data["correlated"]}
        libc = got.get((KEY[LIBC6], "CVE-1"), {})
        zlib = got.get((KEY[ZLIB], "CVE-3"), {})
        if (libc.get("consensus"), libc.get("pipelines_reporting"), libc.get("generators")) != (
            2,
            1,
            ["cdxgen", "syft"],
        ):
            failures.append(f"run directory: libc6 CVE-1 {libc}")
        if (zlib.get("consensus"), zlib.get("pipelines_reporting")) != (2, 0):
            failures.append(f"run directory: a pair only the merged SBOM reports: {zlib}")
        text = (run / "summary.md").read_text()
        if "## Correlated findings" not in text:
            failures.append("run directory: summary.md has no correlated-findings section")
        summary = json.loads((run / "summary.json").read_text())["correlation"]
        if (summary["most_consensus"], summary["consensus"]) != (2, {"2": 2}):
            failures.append(f"run directory: summary.json correlation {summary}")


def main() -> None:
    failures: list[str] = []
    for check in (check_consensus, check_claims, check_summary, check_run_directory):
        check(failures)
    for failure in failures:
        print(f"FAIL  {failure}")
    print(
        "correlator v1: consensus as evidence, references, not installed, claims, merged view, run directory: ", end=""
    )
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
