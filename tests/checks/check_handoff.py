#!/usr/bin/env python3
"""Check the hand-off check (CI runs this; no network, no tools, no images).

Synthetic findings on a Debian image, shaped like a real image: a Syft SBOM that lists every
package, a cdxgen SBOM with a source package listed as installed (``glibc``), a package at another version and
one missing, and the merged SBOM. Every class must come out where it belongs, in the documented order, and a
missing reference must never read as lossless:

  classes         misattributed, handoff, other_version, not_listed; misattributed is tested first
  per scanner     each pipeline is compared with its own scanner's direct scan, on canonical IDs
  listed          judged against the SBOM the pipeline's scanner read, not any other
  not checked     no direct scan, a failed direct scan, a failed pipeline scan, a missing SBOM
  warnings        raised for losses in fused pipelines only
  run directory   load_run finds the merged SBOM (also in older runs), reprocess writes
                  handoff.json and replaces, not repeats, the analysis's warnings
  options         direct scans by default for images only; --direct and --no-direct

    python3 tests/checks/check_handoff.py
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainguard import handoff, pipeline, report, sbom  # noqa: E402
from chainguard import purl as purls  # noqa: E402
from chainguard.cli import build_parser  # noqa: E402
from chainguard.runner import Step  # noqa: E402
from chainguard.scanners import Finding  # noqa: E402
from chainguard.target import Target  # noqa: E402

LIBC6 = "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12"
OPENSSL = "pkg:deb/debian/openssl@3.0.9-1?arch=amd64&distro=debian-12"
OPENSSL_OLD = "pkg:deb/debian/openssl@3.0.8-1?arch=amd64&distro=debian-12"
ZLIB = "pkg:deb/debian/zlib1g@1.2.13-1?arch=amd64&distro=debian-12"
GLIBC = "pkg:deb/debian/glibc@2.36-9?distro=debian-12"  # cdxgen: the source package, listed as if installed
DJANGO = "pkg:pypi/django@3.2"
KEY = {p: purls.key(p) for p in (LIBC6, OPENSSL, OPENSSL_OLD, ZLIB, GLIBC, DJANGO)}
NOT_INSTALLED = {KEY[GLIBC]: "source-package"}


def cyclonedx(*entries: str) -> dict:
    components = [{"type": "operating-system", "name": "debian", "version": "12"}]
    for p in entries:
        parsed = purls.parse(p)
        components.append({"type": "library", "name": parsed.name, "version": parsed.version, "purl": p})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}


SYFT = cyclonedx(LIBC6, OPENSSL, ZLIB, DJANGO)
CDXGEN = cyclonedx(LIBC6, OPENSSL_OLD, GLIBC)  # no zlib1g, no Django
FUSED = cyclonedx(LIBC6, OPENSSL, ZLIB, DJANGO)
FUSED_WITHOUT_DJANGO = cyclonedx(LIBC6, OPENSSL, ZLIB)


def finding(pipeline_name: str, purl: str, canonical: str, raw: str | None = None) -> Finding:
    f = Finding(
        pipeline=pipeline_name,
        scanner=pipeline_name.split("+", 1)[1],
        raw_id=raw or canonical,
        related=(),
        component=KEY[purl],
        purl=purl,
        severity="HIGH",
        cvss_v3=None,
        fix_state="unknown",
        fix_versions=(),
    )
    f.vulnerability, f.vulnerabilities = canonical, (canonical,)  # as alias resolution leaves them
    return f


# What the direct scan by Trivy reports. CVE-4 and CVE-5 arrive under other IDs and resolve to CVEs (D1).
DIRECT = [
    ("direct+trivy", LIBC6, "CVE-1", None),
    ("direct+trivy", OPENSSL, "CVE-2", None),
    ("direct+trivy", ZLIB, "CVE-3", None),
    ("direct+trivy", LIBC6, "CVE-4", "DLA-0004-1"),
    ("direct+trivy", DJANGO, "CVE-5", "GHSA-0005"),
    ("direct+grype", LIBC6, "CVE-1", None),
]
REPORTED = {
    # loses CVE-3 on zlib1g and CVE-4 on libc6, both listed in Syft's SBOM; reports Django's under another ID
    "syft+trivy": [(LIBC6, "CVE-1", None), (OPENSSL, "CVE-2", None), (DJANGO, "CVE-5", "PYSEC-0005")],
    "syft+grype": [(LIBC6, "CVE-1", None)],
    # reports CVE-1 on the source package instead of libc6, and nothing else
    "cdxgen+trivy": [(GLIBC, "CVE-1", None)],
    "cdxgen+grype": [(LIBC6, "CVE-1", None)],
    # everything the direct scan reports, and one pair more
    "fused+trivy": [(p, v, None) for _, p, v, _ in DIRECT[:5]] + [(OPENSSL, "CVE-9", None)],
    "fused+grype": [(LIBC6, "CVE-1", None)],
}


def findings(reported: dict) -> list[Finding]:
    out = [finding(p, purl, v, raw) for p, purl, v, raw in DIRECT]
    for p, rows in reported.items():
        out += [finding(p, purl, v, raw) for purl, v, raw in rows]
    return out


def steps(names, failed=()) -> list[Step]:
    return [Step(n, "scan", [], log="", returncode=1 if n in failed else 0) for n in names]


def scanned(**overrides) -> dict:
    docs = {"syft": SYFT, "cdxgen": CDXGEN, "fused": FUSED, **overrides}
    return {head: sbom.parse(doc) for head, doc in docs.items() if doc is not None}


def classes(detail: dict, p: str) -> dict:
    return {(r["component"], r["vulnerability"]): r["class"] for r in detail[p]["lost"]}


def check_classes(failures: list[str]) -> None:
    all_steps = steps([*REPORTED, "direct+trivy", "direct+grype"])
    summary, detail = handoff.check(findings(REPORTED), scanned(), all_steps, NOT_INSTALLED)
    expected = {
        "syft+trivy": {(KEY[ZLIB], "CVE-3"): "handoff", (KEY[LIBC6], "CVE-4"): "handoff"},
        "cdxgen+trivy": {
            (KEY[LIBC6], "CVE-1"): "misattributed",  # libc6 is listed too: misattributed is tested first
            (KEY[OPENSSL], "CVE-2"): "other_version",
            (KEY[ZLIB], "CVE-3"): "not_listed",
            (KEY[LIBC6], "CVE-4"): "handoff",
            (KEY[DJANGO], "CVE-5"): "not_listed",
        },
        "fused+trivy": {},
        # compared with direct+grype, which reports only CVE-1: comparing with Trivy's would lose four
        "syft+grype": {},
        "cdxgen+grype": {},
        "fused+grype": {},
    }
    for p, want in expected.items():
        got = classes(detail, p) if p in detail else None
        if got != want:
            failures.append(f"{p}: lost pairs classed {got}, expected {want}")
    cdxgen = summary["pipelines"]["cdxgen+trivy"]
    want = {
        "lost": 5,
        "lost_vulnerabilities": 4,  # CVE-1 is still reported, on the wrong component
        "misattributed_to_not_installed": 1,
        "beyond": 1,
        "beyond_not_installed": 1,
        "lossless": False,
    }
    if {k: cdxgen.get(k) for k in want} != want:
        failures.append(f"cdxgen+trivy summary {cdxgen}, expected {want}")
    if detail["cdxgen+trivy"]["lost"][0].get("reported_on") != [KEY[GLIBC]]:
        failures.append(f"a misattributed pair does not say where it went: {detail['cdxgen+trivy']['lost'][0]}")
    fused = summary["pipelines"]["fused+trivy"]
    if (fused["lossless"], fused["beyond"], fused["beyond_not_installed"]) != (True, 1, 0):
        failures.append(f"fused+trivy should be lossless with 1 pair beyond: {fused}")
    if summary["warnings"]:
        failures.append(f"losses in single pipelines raised warnings: {summary['warnings']}")
    if summary["fused_lossless"] is not True:
        failures.append(f"fused_lossless is {summary['fused_lossless']}, expected True")
    if summary["scanners"]["trivy"] != {
        "reference": "direct+trivy",
        "status": "checked",
        "pairs": 5,
        "vulnerabilities": 5,
    }:
        failures.append(f"trivy reference summary wrong: {summary['scanners']['trivy']}")


def check_listed_and_warnings(failures: list[str]) -> None:
    """The merged SBOM leaves Django out and the fused pipeline loses its finding: not listed there, though
    Syft's SBOM lists it, and a warning, because a fused loss is a ChainGuard defect."""
    reported = {
        "syft+trivy": REPORTED["syft+trivy"][:2],
        "fused+trivy": [(p, v, None) for _, p, v, _ in DIRECT[:4]],
    }
    summary, detail = handoff.check(
        findings(reported),
        scanned(fused=FUSED_WITHOUT_DJANGO),
        steps([*reported, "direct+trivy"]),
        NOT_INSTALLED,
    )
    if classes(detail, "fused+trivy") != {(KEY[DJANGO], "CVE-5"): "not_listed"}:
        failures.append(f"fused pipeline not judged against the SBOM it read: {classes(detail, 'fused+trivy')}")
    if classes(detail, "syft+trivy").get((KEY[DJANGO], "CVE-5")) != "handoff":
        failures.append(f"syft pipeline not judged against Syft's SBOM: {classes(detail, 'syft+trivy')}")
    if len(summary["warnings"]) != 1 or "fused+trivy lost 1 of the 5" not in summary["warnings"][0]:
        failures.append(f"a fused loss must raise exactly one warning: {summary['warnings']}")
    if summary["fused_lossless"] is not False:
        failures.append(f"fused_lossless is {summary['fused_lossless']} after a fused loss")


def check_not_checked(failures: list[str]) -> None:
    every = [*REPORTED, "direct+trivy", "direct+grype"]
    cases = {
        "no direct scan": (steps([p for p in every if not p.startswith("direct")]), scanned()),
        "direct scan failed": (steps(every, failed=("direct+trivy", "direct+grype")), scanned()),
    }
    for reason, (run_steps, docs) in cases.items():
        summary, detail = handoff.check(findings(REPORTED), docs, run_steps, NOT_INSTALLED)
        statuses = {s: v["status"] for s, v in summary["scanners"].items()}
        if statuses != {"trivy": f"not checked: {reason}", "grype": f"not checked: {reason}"}:
            failures.append(f"{reason}: scanners {statuses}")
        if summary["pipelines"] or detail:
            failures.append(f"{reason}: pipelines were checked anyway: {sorted(summary['pipelines'])}")
        if summary["fused_lossless"] is not None:
            failures.append(f"{reason}: fused_lossless is {summary['fused_lossless']}, must be None")
        warned = bool(summary["warnings"])
        if warned != (reason == "direct scan failed"):
            failures.append(f"{reason}: warnings {summary['warnings']}")
        text = "\n".join(report.handoff_lines(summary))
        if f"not run: {reason}" not in text or "lossless" in text:
            failures.append(f"{reason}: the report says {text!r}")

    fused_only = ["fused+trivy", "direct+trivy"]
    summary, _ = handoff.check(findings(REPORTED), scanned(), steps(fused_only, failed=("fused+trivy",)))
    if summary["pipelines"]["fused+trivy"]["status"] != "not checked: its scan failed":
        failures.append(f"a failed pipeline scan: {summary['pipelines']['fused+trivy']}")
    if summary["fused_lossless"] is not None:
        failures.append(f"a failed fused scan left fused_lossless {summary['fused_lossless']}")
    summary, _ = handoff.check(findings(REPORTED), scanned(fused=None), steps(fused_only))
    if summary["pipelines"]["fused+trivy"]["status"] != "not checked: the SBOM it read is not available":
        failures.append(f"a missing merged SBOM: {summary['pipelines']['fused+trivy']}")
    if summary["fused_lossless"] is not None or len(summary["warnings"]) != 1:
        failures.append(f"a missing merged SBOM: fused_lossless {summary['fused_lossless']}, {summary['warnings']}")


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
    """A run as the tool writes it, but with the manifest of an older run (no fused.sboms)."""
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp) / "20261017T000000Z-image.tar"
        (run / "raw").mkdir(parents=True)
        files = {
            "raw/syft.cdx.json": SYFT,
            "fused.cdx.json": FUSED,
            "raw/syft.trivy.json": trivy_report([(LIBC6, "CVE-1")]),
            "raw/fused.trivy.json": trivy_report([(LIBC6, "CVE-1")]),  # loses CVE-3 on zlib1g
            "raw/direct.trivy.json": trivy_report([(LIBC6, "CVE-1"), (ZLIB, "CVE-3")]),
        }
        for name, content in files.items():
            (run / name).write_text(json.dumps(content))

        def step(name: str, kind: str, output: str) -> dict:
            return Step(name, kind, [name], log=f"raw/{name}.log", output=output, returncode=0).as_dict()

        manifest = {
            "schema": "chainguard.manifest/v1",
            "chainguard": "0.1.0",
            "run_id": run.name,
            "target": {"kind": "image-archive", "spec": "image.tar"},
            "options": {"sbom_format": "cyclonedx"},
            "toolchain": {},
            "warnings": ["a warning the scan raised"],
            "steps": [
                step("syft", "generate", "raw/syft.cdx.json"),
                step("syft+trivy", "scan", "raw/syft.trivy.json"),
                step("fused+trivy", "scan", "raw/fused.trivy.json"),
                step("direct+trivy", "scan", "raw/direct.trivy.json"),
            ],
            "fused": {"formats": {"cyclonedx": "fused.cdx.json"}},
        }
        (run / "manifest.json").write_text(json.dumps(manifest))
        # No network, and no snapshot store: the enrichment check covers enrichment, and its warnings are not this
        # check's
        options = pipeline.AnalysisOptions(aliases="scanner", enrichment=False)
        if set(pipeline.load_run(run).fused) != {"fused"}:
            failures.append(f"load_run did not find the merged SBOM: {set(pipeline.load_run(run).fused)}")
        first = pipeline.reprocess(run, options)
        second = pipeline.reprocess(run, options)
        check = json.loads((run / "handoff.json").read_text())
        lost = check["pipelines"].get("fused+trivy", {}).get("lost")
        if lost != [{"component": KEY[ZLIB], "vulnerability": "CVE-3", "class": "handoff"}]:
            failures.append(f"run directory: handoff.json has fused+trivy lost {lost}")
        written = json.loads((run / "manifest.json").read_text())
        analysis_warnings = written["analysis"]["warnings"]
        if len(analysis_warnings) != 1 or "fused+trivy lost 1" not in analysis_warnings[0]:
            failures.append(f"run directory: analysis warnings {analysis_warnings}")
        if written["warnings"] != ["a warning the scan raised"]:
            failures.append(f"run directory: the scan's warnings changed to {written['warnings']}")
        if first.warnings != second.warnings or len(second.warnings) != 2:
            failures.append(f"run directory: reprocessing repeats warnings: {first.warnings} / {second.warnings}")
        text = (run / "summary.md").read_text()
        if "## Hand-off check" not in text or "fused+trivy lost 1" not in text:
            failures.append("run directory: summary.md has no hand-off table or no warning")

    shapes = {
        "recorded heads": ({"fused": {"sboms": {"fused": "a.json"}}}, {"fused": "a.json"}),
        "before 2.5, SPDX requested": (
            {"options": {"sbom_format": "spdx"}, "fused": {"formats": {"cyclonedx": "c.json", "spdx": "s.json"}}},
            {"fused-cyclonedx": "c.json", "fused": "s.json"},
        ),
        "no fused pipeline": ({}, {}),
    }
    for name, (manifest, want) in shapes.items():
        if pipeline.fused_documents(manifest) != want:
            failures.append(f"fused_documents, {name}: {pipeline.fused_documents(manifest)}, expected {want}")


def check_options(failures: list[str]) -> None:
    kinds = {
        kind: pipeline.ScanOptions().direct_for(Target(kind, "t")) for kind in ("image", "image-archive", "directory")
    }
    if kinds != {"image": True, "image-archive": True, "directory": False}:
        failures.append(f"direct scans by default: {kinds}")
    if not pipeline.ScanOptions(direct=True).direct_for(Target("directory", "t")):
        failures.append("--direct does not scan a directory directly")
    if pipeline.ScanOptions(direct=False).direct_for(Target("image", "t")):
        failures.append("--no-direct still scans an image directly")
    try:
        pipeline.ScanOptions(direct="yes").direct_for(Target("image", "t"))
        failures.append("direct='yes' was accepted")
    except ValueError:
        pass
    parser = build_parser()
    flags = {args: parser.parse_args(["scan", "t", *args]).direct for args in ((), ("--direct",), ("--no-direct",))}
    if flags != {(): "auto", ("--direct",): True, ("--no-direct",): False}:
        failures.append(f"CLI --direct / --no-direct: {flags}")
    with contextlib.redirect_stderr(io.StringIO()), contextlib.suppress(SystemExit):
        parser.parse_args(["scan", "t", "--direct", "--no-direct"])
        failures.append("--direct and --no-direct together were accepted")


def main() -> None:
    failures: list[str] = []
    for check in (check_classes, check_listed_and_warnings, check_not_checked, check_run_directory, check_options):
        check(failures)
    for failure in failures:
        print(f"FAIL  {failure}")
    print(
        "hand-off check: classes, order, per scanner, listed, not checked, warnings, run directory, options: ", end=""
    )
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
