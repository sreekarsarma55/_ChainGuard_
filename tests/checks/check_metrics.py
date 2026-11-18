#!/usr/bin/env python3
"""Check the metrics module (CI runs this; no network, no tools).

Synthetic Syft and cdxgen SBOMs of a Debian image with a Django application, in the shapes real images have: Syft
states libc6's source package (glibc), cdxgen lists glibc as if installed and a file entry with a PURL, the two spell
Django's version differently (3.2.0 and 3.2), Grype names Django's advisory by its GHSA, an advisory only Trivy's data
has is lost by both of Trivy's single pipelines (F2, F3) and recovered by the merged SBOM, and a Grype finding lands
on cdxgen's glibc. Every level, configuration and reference must come out as chainguard.metrics defines them:

  levels         as reported: keys as written, every entry, IDs as reported; aliases resolved; normalised: D4, D9,
                 findings on what is not installed left out and counted
  evidence       a single pipeline normalised with its own generator's evidence, the unions with every generator's;
                 a finding on a jar's merged-away key counts for the component it became (D11)
  fused          only normalised; the formats' agreement (D7), true and false
  references     ground truth (precision, recall, shipped recall), anchors (under their own CVE as reported, KEV),
                 direct scans (own scanner for a single pipeline, all for a union; none if one failed)
  agreement      generators, scanners per SBOM, the naive union against the fused pipeline, pipelines reporting
  failures       a failed scan is not an empty one; nothing to measure is said
  across runs    sums, micro averages, median and pooled Jaccard, the best single pipeline
  run directory  replaying a recorded alias resolution; summary.json, summary.md and the console

    python3 tests/checks/check_metrics.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainguard import aliases, correlate, merge, metrics, pipeline, report, sbom  # noqa: E402
from chainguard import purl as purls  # noqa: E402
from chainguard.runner import Step  # noqa: E402
from chainguard.scanners import Finding  # noqa: E402

LIBC6 = "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12"
ZLIB = "pkg:deb/debian/zlib1g@1.2.13-1?arch=amd64&distro=debian-12"
GLIBC = "pkg:deb/debian/glibc@2.36-9?distro=debian-12"  # cdxgen: the source package, listed as if installed
DJANGO_300 = "pkg:pypi/django@3.2.0"  # Syft's spelling
DJANGO = "pkg:pypi/django@3.2"  # cdxgen's spelling
FILE = "pkg:generic/README?path=/app/README"  # cdxgen's file entry, with a PURL
GHSA, CVE_D = "GHSA-0001-0001-0001", "CVE-2021-0001"


def cyclonedx(*entries: tuple[str, str]) -> dict:
    components = [{"type": "operating-system", "name": "debian", "version": "12"}]
    for purl, kind in entries:
        parsed = purls.parse(purl)
        components.append({"type": kind, "name": parsed.name, "version": parsed.version, "purl": purl})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}


SYFT = cyclonedx((LIBC6 + "&upstream=glibc", "library"), (ZLIB, "library"), (DJANGO_300, "library"))
CDXGEN = cyclonedx((LIBC6, "library"), (ZLIB, "library"), (GLIBC, "library"), (DJANGO, "library"), (FILE, "file"))

# One jar under two Maven groups (D11): Syft writes the artifact ID as the group, cdxgen looked the jar up by SHA-1.
JAR = "thymeleaf-3.1.2.RELEASE.jar"
THYMELEAF_SYFT = "pkg:maven/thymeleaf/thymeleaf@3.1.2.RELEASE"
THYMELEAF = "pkg:maven/org.thymeleaf/thymeleaf@3.1.2.RELEASE"


def with_jar(document: dict, purl: str, syft: bool) -> dict:
    entry: dict = {"type": "library", "name": "thymeleaf", "version": "3.1.2.RELEASE", "purl": purl}
    if syft:
        entry["properties"] = [{"name": "syft:metadata:virtualPath", "value": f"/app.jar:BOOT-INF/lib/{JAR}"}]
    else:
        entry["properties"] = [{"name": "SrcFile", "value": f"BOOT-INF/lib/{JAR}"}]
        methods = [{"technique": "hash-comparison", "value": JAR}]
        entry["evidence"] = {"identity": [{"field": "purl", "methods": methods}]}
    return {**document, "components": [*document["components"], entry]}


FINDINGS = [
    # CVE-B is in Trivy's data only: lost on Syft's SBOM and cdxgen's, reported on the merged one.
    ("syft+trivy", LIBC6, "CVE-A"),
    ("syft+trivy", DJANGO_300, CVE_D),
    ("syft+grype", LIBC6, "CVE-A"),
    ("syft+grype", DJANGO_300, GHSA),
    ("cdxgen+trivy", DJANGO, CVE_D),
    ("cdxgen+grype", GLIBC, "CVE-A"),  # on the source package cdxgen lists as installed
    ("cdxgen+grype", DJANGO, GHSA),
    *(
        row
        for head in ("fused", "fused-spdx", "direct")
        for row in (
            (f"{head}+trivy", LIBC6, "CVE-A"),
            (f"{head}+trivy", LIBC6, "CVE-B"),
            (f"{head}+trivy", DJANGO, CVE_D),
            (f"{head}+grype", LIBC6, "CVE-A"),
            (f"{head}+grype", DJANGO, GHSA),
        )
    ),
]
PIPELINES = tuple(dict.fromkeys(row[0] for row in FINDINGS))
TRUTH = [
    {"purl": "pkg:deb/debian/libc6@2.36-9", "scope": None},
    {"purl": "pkg:deb/debian/zlib1g@1.2.13-1", "scope": None},
    {"purl": "pkg:pypi/django@3.2", "scope": "runtime"},
    {"purl": "pkg:pypi/pytest@8.0", "scope": "dev"},  # listed by nobody: lowers recall, not shipped recall
]
ANCHORS = [
    {"purl": "pkg:deb/debian/libc6@2.36-9", "cve": "CVE-B", "kev_date_added": "2024-01-01"},
    {"purl": "pkg:pypi/django@3.2", "cve": CVE_D},
]


def finding(pipeline_name: str, purl: str, raw: str) -> Finding:
    scanner = pipeline_name.split("+", 1)[1]
    return Finding(pipeline_name, scanner, raw, (), purls.key(purl) or "", purl, "HIGH", None, "fixed", ())


def run(
    failed: tuple[str, ...] = (),
    drop: tuple[tuple[str, str], ...] = (),
    docs: tuple[dict, dict] = (SYFT, CDXGEN),
    merged: dict[str, str] | None = None,
    extra: tuple[tuple[str, str, str], ...] = (),
    **kw,
) -> dict:
    """The fixture measured. ``failed`` scans fail, ``drop`` removes (pipeline, raw ID) findings, ``docs`` replaces
    the two SBOMs, and ``merged`` merges CVEs, as alias resolution does when OSV links them."""
    sboms = {"syft": sbom.parse(docs[0]), "cdxgen": sbom.parse(docs[1])}
    inventory, suppressed = correlate.canonical_inventory(sboms)
    not_installed = correlate.non_components(sboms, inventory, suppressed)
    fused = {"fused": sbom.parse(merge.cyclonedx(inventory, [{"name": "debian", "version": "12"}], target="t"))}
    rows = [*FINDINGS, *extra]  # ``extra``: findings added to the fixture's
    found = [finding(*row) for row in rows if row[0] not in failed and (row[0], row[2]) not in drop]
    steps = [Step(p, "scan", [], log="", returncode=1 if p in failed else 0) for p in PIPELINES]
    ids = {GHSA: {"status": "osv", "canonical": [CVE_D]}}
    resolution = aliases.Resolution.from_dict({"ids": ids, "merged_cves": merged or {}})
    resolution.apply(found)
    return metrics.measure(sboms, fused, found, steps, inventory, not_installed, resolution, **kw)


def at(record: dict, path: tuple) -> object:
    value: object = record
    for step in path:
        if not isinstance(value, dict) or step not in value:
            return f"<no {step}>"
        value = value[step]
    return value


def expect_all(failures: list[str], record: dict, expectations: list[tuple[str, tuple, object]]) -> None:
    for label, path, want in expectations:
        got = at(record, path)
        if got != want:
            failures.append(f"{label}: {got!r}, expected {want!r}")


def C(level: str, configuration: str, *path: str) -> tuple:  # a path into a record
    return ("levels", level, "configurations", configuration, *path)


def A(level: str, *path: str) -> tuple:
    return ("levels", level, "agreement", *path)


def U(level: str, *path: str) -> tuple:
    return ("levels", level, "unique", *path)


def check_levels(failures: list[str]) -> None:
    r = run(truth=TRUTH, anchors=ANCHORS)
    expect_all(
        failures,
        r,
        [
            ("configurations", ("configurations",), [*PIPELINES[:4], "naive union", "fused"]),
            # As reported: every entry with a PURL, keys as written, IDs as reported.
            ("cdxgen as reported (file, source package)", C("reported", "cdxgen+grype", "components"), 5),
            ("naive union as reported (3.2.0 and 3.2 apart)", C("reported", "naive union", "components"), 6),
            ("naive union vulnerabilities as reported", C("reported", "naive union", "vulnerabilities"), 3),
            ("naive union vulnerabilities, aliases", C("aliases", "naive union", "vulnerabilities"), 2),
            ("naive union pairs, aliases", C("aliases", "naive union", "pairs"), 4),
            # Normalised: D4 merges Django; D9 leaves out the file and, on Syft's evidence, glibc and its finding.
            ("naive union normalised", C("normalised", "naive union", "components"), 3),
            ("naive union pairs normalised", C("normalised", "naive union", "pairs"), 2),
            (
                "naive union left out as not installed",
                C("normalised", "naive union", "not_installed"),
                {"pairs": 1, "vulnerabilities_only_there": 0},
            ),
            # A single pipeline has only its own generator's evidence: cdxgen alone cannot tell glibc is a source.
            ("cdxgen+grype normalised, own evidence", C("normalised", "cdxgen+grype", "components"), 4),
            ("cdxgen+grype pairs, own evidence", C("normalised", "cdxgen+grype", "pairs"), 2),
            ("fused as reported", C("reported", "fused"), "<no fused>"),
            ("fused with aliases only", C("aliases", "fused"), "<no fused>"),
            ("fused pairs", C("normalised", "fused", "pairs"), 3),
            ("fused pipelines", C("normalised", "fused", "pipelines"), ["fused+trivy", "fused+grype"]),
            ("formats agree", ("formats_agree",), True),
        ],
    )


def check_references(failures: list[str]) -> None:
    r = run(truth=TRUTH, anchors=ANCHORS)
    expect_all(
        failures,
        r,
        [
            ("fused truth found", C("normalised", "fused", "truth", "found"), 3),
            ("fused precision", C("normalised", "fused", "truth", "precision"), 1.0),
            ("fused recall (pytest listed by nobody)", C("normalised", "fused", "truth", "recall"), 0.75),
            ("fused shipped recall (pytest is dev)", C("normalised", "fused", "truth", "shipped_recall"), 1.0),
            ("fused not in the truth", C("normalised", "fused", "truth", "not_in_truth_keys"), []),
            ("syft as reported against the truth", C("reported", "syft+trivy", "truth", "found"), 2),
            ("syft normalised against the truth", C("normalised", "syft+trivy", "truth", "found"), 3),
            ("naive union precision as reported", C("reported", "naive union", "truth", "precision"), 0.5),
            # Anchors count under their own CVE as reported, so Grype's GHSA does not; 3.2.0 is not 3.2 until D4.
            ("syft+grype anchors as reported", C("reported", "syft+grype", "anchors", "found"), 0),
            ("syft+grype anchors, aliases", C("aliases", "syft+grype", "anchors", "found"), 0),
            ("syft+grype anchors normalised", C("normalised", "syft+grype", "anchors", "found"), 1),
            ("cdxgen+grype anchors, aliases", C("aliases", "cdxgen+grype", "anchors", "found"), 1),
            (
                "syft+trivy misses CVE-B",
                C("normalised", "syft+trivy", "anchors", "missed"),
                ["CVE-B on deb/debian/libc6@2.36-9"],
            ),
            ("fused anchors found", C("normalised", "fused", "anchors", "found"), 2),
            ("fused KEV anchors", C("normalised", "fused", "anchors", "kev_found"), 1),
            # Direct scans: a single pipeline against its own scanner's, a union against all of them.
            (
                "syft+trivy against direct+trivy",
                C("normalised", "syft+trivy", "direct"),
                {"reference": ["direct+trivy"], "pairs": 3, "reported": 2, "beyond": 0},
            ),
            (
                "naive union's reference",
                C("normalised", "naive union", "direct", "reference"),
                ["direct+trivy", "direct+grype"],
            ),
            ("naive union against both direct scans", C("normalised", "naive union", "direct", "reported"), 2),
            ("fused against both direct scans", C("normalised", "fused", "direct", "reported"), 3),
        ],
    )
    # An anchor whose CVE OSV links to an older one: as reported it counts under its own ID, otherwise under the
    # CVE its class is counted under.
    libc6_a = [{"purl": "pkg:deb/debian/libc6@2.36-9", "cve": "CVE-A"}]
    expect_all(
        failures,
        run(anchors=libc6_a, merged={"CVE-A": "CVE-0000-0001"}),
        [
            ("merged anchor as reported", C("reported", "syft+trivy", "anchors", "found"), 1),
            ("merged anchor, aliases", C("aliases", "syft+trivy", "anchors", "found"), 1),
            ("merged anchor normalised", C("normalised", "syft+trivy", "anchors", "found"), 1),
        ],
    )
    # A pair only Grype's direct scan has: a single pipeline is held to its own scanner's direct scan alone.
    expect_all(
        failures,
        run(extra=(("direct+grype", ZLIB, "CVE-Z"),)),
        [
            ("syft+trivy against direct+trivy alone", C("normalised", "syft+trivy", "direct", "pairs"), 3),
            ("syft+grype against direct+grype alone", C("normalised", "syft+grype", "direct", "pairs"), 3),
            ("the naive union against both", C("normalised", "naive union", "direct", "pairs"), 4),
        ],
    )
    expect_all(
        failures,
        run(failed=("direct+grype",)),
        [
            ("fused with a failed direct scan", C("normalised", "fused", "direct"), "<no direct>"),
            ("syft+grype with its direct scan failed", C("normalised", "syft+grype", "direct"), "<no direct>"),
            ("syft+trivy keeps its reference", C("normalised", "syft+trivy", "direct", "pairs"), 3),
        ],
    )


def check_agreement(failures: list[str]) -> None:
    r = run(truth=TRUTH, anchors=ANCHORS)
    pairs = ("trivy|grype", "pairs", "jaccard")
    expect_all(
        failures,
        r,
        [
            ("generators as reported", A("reported", "generators", "syft|cdxgen", "jaccard"), 0.333),
            ("generators normalised", A("normalised", "generators", "syft|cdxgen", "jaccard"), 1.0),
            ("scanners on syft's SBOM as reported", A("reported", "scanners", "syft", *pairs), 0.333),
            ("scanners on syft's SBOM, aliases", A("aliases", "scanners", "syft", *pairs), 1.0),
            ("scanners on the fused SBOM normalised", A("normalised", "scanners", "fused", *pairs), 0.667),
            # cdxgen's SBOM alone cannot show glibc to be a source package, so Grype's finding on it stays.
            ("scanners on cdxgen's SBOM, its own evidence", A("normalised", "scanners", "cdxgen", *pairs), 0.5),
            ("naive union and fused as reported", A("reported", "naive_union_fused"), "<no naive_union_fused>"),
            ("naive union and fused normalised", A("normalised", "naive_union_fused", "jaccard"), 0.667),
            (
                "what the merged SBOM adds (CVE-B is in no single pipeline)",
                A("normalised", "naive_union_fused", "only_fused_vulnerability"),
                {"nowhere": 1},
            ),
            ("pipelines reporting, normalised", A("normalised", "pipelines_reporting"), {"4": 1, "2": 1}),
            ("truth one generator lists", U("normalised", "truth_components"), {"syft": 0, "cdxgen": 0}),
            (
                "anchors one single pipeline finds",
                U("normalised", "anchors"),
                {"syft+trivy": 0, "syft+grype": 0, "cdxgen+trivy": 0, "cdxgen+grype": 0},
            ),
            ("anchors only the fused pipeline finds", U("normalised", "anchors_only_fused"), 1),
            ("truth no configuration lists", U("normalised", "truth_missed_by_every_configuration"), ["pypi/pytest@8"]),
        ],
    )


def check_adds(failures: list[str]) -> None:
    """A pair only the fused pipeline reports: its vulnerability is on another installed component in the naive union
    (CVE-Z, on zlib1g), only on an entry that is not installed (CVE-G, on cdxgen's glibc), or nowhere (CVE-B)."""
    extra = (
        ("syft+grype", ZLIB, "CVE-Z"),
        ("fused+grype", LIBC6, "CVE-Z"),
        ("cdxgen+grype", GLIBC, "CVE-G"),
        ("fused+grype", LIBC6, "CVE-G"),
    )
    expect_all(
        failures,
        run(extra=extra),
        [
            (
                "what the merged SBOM adds, by where the naive union has it",
                A("normalised", "naive_union_fused", "only_fused_vulnerability"),
                {"nowhere": 1, "on another installed component": 1, "only on entries not installed": 1},
            ),
            (
                "the vulnerability only on what is not installed",
                C("normalised", "naive union", "not_installed", "vulnerabilities_only_there"),
                1,
            ),
        ],
    )


def check_coordinates(failures: list[str]) -> None:
    """A finding on the key Syft gave a jar counts, normalised, for the one component the jar became (D11). A single
    pipeline cannot merge it: with one generator there is nothing to merge."""
    docs = (with_jar(SYFT, THYMELEAF_SYFT, syft=True), with_jar(CDXGEN, THYMELEAF, syft=False))
    extra = (("syft+grype", THYMELEAF_SYFT, "CVE-T"), ("fused+grype", THYMELEAF, "CVE-T"))
    expect_all(
        failures,
        run(docs=docs, extra=extra),
        [
            ("the jar's two keys as reported", C("reported", "naive union", "components"), 8),
            ("the jar once, normalised", C("normalised", "naive union", "components"), 4),
            ("generators normalised, the jar merged", A("normalised", "generators", "syft|cdxgen", "jaccard"), 1.0),
            ("syft+grype keeps its own key", C("normalised", "syft+grype", "components"), 4),
            ("the naive union's pairs", C("normalised", "naive union", "pairs"), 3),
            ("the union's finding is on the kept key", A("normalised", "naive_union_fused", "both"), 3),
            (
                "the merged SBOM still adds only CVE-B",
                A("normalised", "naive_union_fused", "only_fused_vulnerability"),
                {"nowhere": 1},
            ),
        ],
    )


def check_failures(failures: list[str]) -> None:
    expect_all(
        failures,
        run(failed=("syft+trivy",)),
        [
            ("a failed scan is no pipeline", C("normalised", "syft+trivy"), "<no syft+trivy>"),
            (
                "the naive union without it",
                C("normalised", "naive union", "pipelines"),
                ["syft+grype", "cdxgen+trivy", "cdxgen+grype"],
            ),
        ],
    )
    disagree = run(drop=(("fused-spdx+trivy", "CVE-B"),))
    expect_all(failures, disagree, [("formats agree when SPDX loses a pair", ("formats_agree",), False)])
    nothing = run(failed=PIPELINES)
    expect_all(
        failures, nothing, [("nothing to measure", ("status",), "not measured: no SBOM pipeline's scan succeeded")]
    )


def check_summarize(failures: list[str]) -> None:
    """Two different runs (the second's generators agree completely), so that medians, pooled values and per-run
    averages all differ; and one run with nothing to measure, which is left out. A different single pipeline finds
    the most anchors in each run, so the best per run beats the best over both."""
    anchors = [*ANCHORS, {"purl": "pkg:deb/debian/libc6@2.36-9", "cve": "CVE-A"}]
    one = run(truth=TRUTH, anchors=anchors, extra=(("cdxgen+grype", LIBC6, "CVE-A"),))
    two = run(truth=TRUTH, anchors=anchors, docs=(SYFT, SYFT), extra=(("syft+trivy", DJANGO, CVE_D),))
    s = metrics.summarize({"a": one, "b": two, "c": run(failed=PIPELINES)})
    expect_all(
        failures,
        s,
        [
            ("runs measured", ("runs",), 2),
            ("pooled fused truth", C("normalised", "fused", "truth", "components"), 8),
            ("pooled fused found", C("normalised", "fused", "truth", "found"), 6),
            ("pooled fused precision", C("normalised", "fused", "truth", "precision"), 1.0),
            ("pooled fused recall", C("normalised", "fused", "truth", "recall"), 0.75),
            ("pooled fused anchors", C("normalised", "fused", "anchors", "found"), 6),
            ("pooled naive union precision as reported", C("reported", "naive union", "truth", "precision"), 0.556),
            (
                "median and pooled Jaccard",
                A("reported", "generators", "syft|cdxgen"),
                {"runs": 2, "median": 0.667, "pooled": 0.556, "both": 5, "union": 9, "only": {"syft": 1, "cdxgen": 3}},
            ),
            # cdxgen+grype and syft+trivy both find 3; a tie goes to the first name in order
            ("best single pipeline, never a union", U("aliases", "best_single", "pipeline"), "cdxgen+grype"),
            ("its anchors", U("aliases", "best_single", "anchors_found"), 3),
            ("the best per run", U("aliases", "best_single", "per_run_best_anchors_found"), 4),
            (
                "what the merged SBOM adds, summed",
                A("normalised", "naive_union_fused", "only_fused_vulnerability"),
                {"nowhere": 2},
            ),
            ("no fused configuration as reported", C("reported", "fused"), "<no fused>"),
        ],
    )


def write_run(root: Path) -> Path:
    """A run directory whose findings.json recorded a resolution OSV would not give today."""
    run_dir = root / "20261018T000000Z-app"
    (run_dir / "raw").mkdir(parents=True)
    (run_dir / "raw" / "syft.cdx.json").write_text(json.dumps(SYFT))
    vulnerability = {"VulnerabilityID": "CVE-A", "PkgName": "libc6", "InstalledVersion": "2.36-9"}
    trivy = {"Results": [{"Vulnerabilities": [{**vulnerability, "PkgIdentifier": {"PURL": LIBC6}}]}]}
    (run_dir / "raw" / "syft.trivy.json").write_text(json.dumps(trivy))
    artifact = {"name": "django", "version": "3.2.0", "type": "python", "purl": DJANGO_300}
    grype = {
        "matches": [{"vulnerability": {"id": GHSA, "fix": {}}, "relatedVulnerabilities": [], "artifact": artifact}]
    }
    (run_dir / "raw" / "syft.grype.json").write_text(json.dumps(grype))
    steps = [
        Step("syft", "generate", ["syft"], log="raw/s.log", output="raw/syft.cdx.json", returncode=0).as_dict(),
        Step("syft+trivy", "scan", ["t"], log="raw/t.log", output="raw/syft.trivy.json", returncode=0).as_dict(),
        Step("syft+grype", "scan", ["g"], log="raw/g.log", output="raw/syft.grype.json", returncode=0).as_dict(),
    ]
    dates = {"oldest_record_utc": "2026-10-17T00:00:00+00:00", "newest_record_utc": "2026-10-17T00:00:00+00:00"}
    manifest = {
        "chainguard": "0.1.0",
        "run_id": run_dir.name,
        "target": {"kind": "directory", "spec": "app"},
        "options": {"sbom_format": "cyclonedx"},
        "toolchain": {},
        "steps": steps,
        "analysis": {"aliases": {"method": "osv", "source": "OSV.dev", **dates}},
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    ids = {GHSA: {"status": "osv", "canonical": [CVE_D]}}
    (run_dir / "findings.json").write_text(
        json.dumps({"aliases": {"ids": ids, "merged_cves": {"CVE-A": "CVE-0000-0001"}}})
    )
    return run_dir


def check_run_directory(failures: list[str]) -> None:
    replay = pipeline.AnalysisOptions(aliases="recorded")
    with tempfile.TemporaryDirectory() as tmp:
        run_dir = write_run(Path(tmp))
        pipeline.reprocess(run_dir, replay)
        found = {
            f["raw_id"]: f["vulnerabilities"] for f in json.loads((run_dir / "findings.json").read_text())["findings"]
        }
        if found != {GHSA: [CVE_D], "CVE-A": ["CVE-0000-0001"]}:
            failures.append(f"a replayed resolution: {found}")
        recorded = json.loads((run_dir / "manifest.json").read_text())["analysis"]["aliases"]
        got = (recorded["method"], (recorded.get("recorded_from") or {}).get("source"), recorded.get("not_in_record"))
        if got != ("recorded", "OSV.dev", 0):
            failures.append(f"replayed from: {got}")
        again = pipeline.reprocess(run_dir, replay)
        twice = json.loads((run_dir / "manifest.json").read_text())["analysis"]["aliases"].get("recorded_from") or {}
        if twice.get("source") != "OSV.dev":
            failures.append(f"replaying a replay must keep the origin: {twice}")
        summary = json.loads((run_dir / "summary.json").read_text())["metrics"]
        expect_all(
            failures,
            summary,
            [
                ("summary.json metrics", ("configurations",), ["syft+trivy", "syft+grype", "naive union"]),
                ("no reference, no coverage", C("normalised", "naive union", "truth"), "<no truth>"),
            ],
        )
        text = (run_dir / "summary.md").read_text()
        if "## The configurations, as reported and normalised" not in text or "| naive union | 3 → 3 |" not in text:
            failures.append(f"summary.md lacks the configurations section:\n{text[:600]}")
        if "Agreement as reported → normalised" not in report.render_console(again.summary):
            failures.append("the console lacks the agreement line")
        try:
            pipeline.scan(str(run_dir), Path(tmp) / "out", pipeline.ScanOptions(), analysis=replay)
            failures.append("scan accepted aliases='recorded', which only reprocess can replay")
        except ValueError as exc:
            if "recorded" not in str(exc):
                failures.append(f"scan with aliases='recorded' failed for another reason: {exc!r}")
        except Exception as exc:  # it went on towards running tools: the replay was not refused
            failures.append(f"scan accepted aliases='recorded' and went on ({type(exc).__name__})")


def check_adjudication(failures: list[str]) -> None:
    """An adjudication changes the comparison the same way for every configuration at every level."""
    zlib, pytest = purls.key(ZLIB), purls.key("pkg:pypi/pytest@8.0")
    aside = metrics.Adjudication({}, frozenset({zlib}))
    expect_all(
        failures,
        run(truth=TRUTH, anchors=ANCHORS, adjudication=aside),
        [
            ("set aside: out of the ground truth", C("normalised", "fused", "truth", "components"), 3),
            ("set aside: out of what the fused pipeline lists", C("normalised", "fused", "truth", "listed"), 2),
            ("set aside: recall without it", C("normalised", "fused", "truth", "recall"), 0.667),
            ("set aside: precision", C("normalised", "fused", "truth", "precision"), 1.0),
            ("set aside: counted", C("normalised", "fused", "truth", "adjudicated", "set_aside"), 1),
            ("set aside as reported too", C("reported", "syft+trivy", "truth", "components"), 3),
            (
                "set aside as reported: Syft lists it",
                C("reported", "syft+trivy", "truth", "adjudicated", "set_aside"),
                1,
            ),
        ],
    )
    # zlib1g counted as pytest: pytest is found instead, and zlib1g, which nothing else lists, is missed
    same = metrics.Adjudication({zlib: pytest}, frozenset())
    expect_all(
        failures,
        run(truth=TRUTH, anchors=ANCHORS, adjudication=same),
        [
            ("same-as: counts as the other", C("normalised", "fused", "truth", "found"), 3),
            ("same-as: counted", C("normalised", "fused", "truth", "adjudicated", "counted_as_another"), 1),
            ("same-as as reported, on its key as written", C("reported", "syft+trivy", "truth", "found"), 2),
            ("same-as: zlib1g is now missed", U("normalised", "truth_missed_by_every_configuration"), [zlib]),
            (
                "same-as: as reported too",
                U("reported", "truth_missed_by_every_configuration"),
                ["deb/debian/zlib1g@1.2.13-1"],
            ),
        ],
    )
    chained = metrics.Adjudication({zlib: pytest}, frozenset({pytest}))
    expect_all(
        failures,
        run(truth=TRUTH, anchors=ANCHORS, adjudication=chained),
        [
            ("same-as a set-aside key is set aside", C("normalised", "fused", "truth", "adjudicated", "set_aside"), 1),
            ("and the key it was the same as leaves the truth", C("normalised", "fused", "truth", "components"), 3),
        ],
    )
    expect_all(
        failures,
        run(truth=TRUTH, anchors=ANCHORS),
        [("no adjudication: nothing counted", C("normalised", "fused", "truth", "adjudicated"), "<no adjudicated>")],
    )


def main() -> None:
    failures: list[str] = []
    for check in (
        check_levels,
        check_references,
        check_adjudication,
        check_agreement,
        check_adds,
        check_coordinates,
        check_failures,
        check_summarize,
        check_run_directory,
    ):
        check(failures)
    for failure in failures:
        print(f"FAIL  {failure}")
    print("metrics: levels, own evidence, fused, references, agreement, failures, across runs, run directory: ", end="")
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
