#!/usr/bin/env python3
"""Check enrichment (CI runs this; no network, no tools).

Synthetic EPSS scores files and KEV catalogs go into a temporary snapshot store, and synthetic SBOMs and findings
through the correlator. Everything must come out as chainguard.enrich and the dependency graph define it:

  store        snapshots kept under their own date or catalog version, never overwritten, chosen newest or by
               version; downloads (file:// URLs here) fail per kind; anything that is not a snapshot, or has
               changed since it was stored, is refused
  values       EPSS and KEV of the canonical CVE and of the CVEs merged into it (D1); none without a CVE; none
               without a snapshot, whatever Grype says; CVSS; fix available yes, no, unknown
  depth        CycloneDX dependencies and SPDX relationships, from the document's subject only: the shortest
               distance, cycles, CONTAINS ignored, graphs that never leave the subject; one depth per component
               after D4 and D11
  summary      what is covered, the findings in KEV, Grype's values compared with the snapshots'
  run          findings.json v3, the manifest's snapshots, reprocess keeping them, warnings, summary.md, console

    python3 tests/checks/check_enrichment.py
"""

from __future__ import annotations

import gzip
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainguard import aliases, correlate, enrich, pipeline, report, sbom  # noqa: E402
from chainguard import purl as purls  # noqa: E402
from chainguard.runner import Step  # noqa: E402
from chainguard.scanners import Finding  # noqa: E402


def epss_file(date: str, rows: dict[str, tuple[float, float]], model: str = "v2026.06.15") -> bytes:
    lines = [f"#model_version:{model},score_date:{date}T12:00:00Z", "cve,epss,percentile"]
    lines += [f"{cve},{score:.5f},{percentile:.5f}" for cve, (score, percentile) in rows.items()]
    return gzip.compress(("\n".join(lines) + "\n").encode())


def kev_file(version: str, cves: dict[str, str]) -> bytes:
    entries = [
        {
            "cveID": cve,
            "dateAdded": added,
            "dueDate": "2025-01-01",
            "knownRansomwareCampaignUse": "Known" if cve == "CVE-2021-44228" else "Unknown",
        }
        for cve, added in cves.items()
    ]
    released = f"{version.replace('.', '-')}T17:00:00.000Z"
    return json.dumps(
        {"catalogVersion": version, "dateReleased": released, "count": len(entries), "vulnerabilities": entries}
    ).encode()


SCORES = {
    "CVE-2021-44228": (0.94400, 0.99990),  # log4j-core
    "CVE-2021-0001": (0.10000, 0.80000),  # lodash's canonical CVE
    "CVE-2026-0002": (0.30000, 0.90000),  # merged into CVE-2021-0001 by alias resolution: the class takes 0.3
    "CVE-2022-0003": (0.00100, 0.20000),  # transitive
}
KEV = {"CVE-2021-44228": "2021-12-10", "CVE-2026-0002": "2026-03-01"}


def expect(failures: list[str], label: str, got: object, want: object) -> None:
    if got != want:
        failures.append(f"{label}: {got!r}, expected {want!r}")


def check_store(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp)
        first, new = enrich.store_epss(epss_file("2026-10-30", SCORES), store)
        expect(failures, "EPSS stored under the date of its scores", (first.version, new), ("2026-10-30", True))
        expect(failures, "EPSS count", first.count, 4)
        expect(failures, "EPSS model", first.model, "v2026.06.15")
        again, new = enrich.store_epss(epss_file("2026-10-30", {"CVE-1": (0.5, 0.5)}), store)
        expect(failures, "the same date is never overwritten", (again.sha256, new), (first.sha256, False))
        enrich.store_epss(epss_file("2026-10-31", SCORES), store)
        expect(failures, "newest EPSS", (enrich.select("epss", store) or first).version, "2026-10-31")
        expect(failures, "EPSS by date", (enrich.select("epss", store, "2026-10-30") or first).sha256, first.sha256)
        expect(failures, "an EPSS date not stored", enrich.select("epss", store, "2026-01-01"), None)
        # A catalog version has dots: the file name must keep all of it, or two versions share one file.
        a, _ = enrich.store_kev(kev_file("2026.10.29", KEV), store)
        b, new = enrich.store_kev(kev_file("2026.10.30", {}), store)
        expect(
            failures,
            "KEV file names keep the whole version",
            (a.file.name, b.file.name, new),
            (
                "kev-2026.10.29.json",
                "kev-2026.10.30.json",
                True,
            ),
        )
        expect(
            failures,
            "KEV versions in the store",
            [s.version for s in enrich.snapshots("kev", store)],
            [
                "2026.10.29",
                "2026.10.30",
            ],
        )
        expect(failures, "KEV entries", enrich.load_kev(a)["CVE-2021-44228"]["date_added"], "2021-12-10")
        for label, call in (
            ("not gzip", lambda: enrich.store_epss(b"cve,epss\n", store)),
            ("no header line", lambda: enrich.store_epss(gzip.compress(b"cve,epss,percentile\n"), store)),
            ("not a KEV catalog", lambda: enrich.store_kev(b'{"title": "x"}', store)),
            ("a version that is not a date", lambda: enrich.select("epss", store, "../x") and None),
        ):
            try:
                call()
                if label != "a version that is not a date":
                    failures.append(f"accepted {label}")
            except enrich.SnapshotError:
                pass
        first.file.write_bytes(epss_file("2026-10-30", {"CVE-2021-44228": (0.0, 0.0)}))
        try:
            enrich.load_epss(first, ["CVE-2021-44228"])
            failures.append("a snapshot changed after it was stored was read")
        except enrich.SnapshotError:
            pass
        # Downloads: one kind failing does not stop the other.
        source = store / "feeds"
        source.mkdir()
        (source / "epss.csv.gz").write_bytes(epss_file("2026-11-01", SCORES))
        (source / "kev.json").write_bytes(kev_file("2026.11.01", KEV))
        got = enrich.update(store, epss_url=(source / "epss.csv.gz").as_uri(), kev_url=(source / "kev.json").as_uri())
        expect(
            failures,
            "update stores both",
            {k: (v[0].version, v[1]) if isinstance(v, tuple) else v for k, v in got.items()},
            {"epss": ("2026-11-01", True), "kev": ("2026.11.01", True)},
        )
        got = enrich.update(store, epss_url=(source / "missing.gz").as_uri(), kev_url=(source / "kev.json").as_uri())
        expect(
            failures,
            "a failed download is reported, per kind",
            (isinstance(got["epss"], str), got["kev"][1]),
            (
                True,
                False,
            ),
        )


# --------------------------------------------------------------------------- SBOMs and depth

APP = "pkg:npm/app@1.0.0"
LODASH, EXPRESS, BODY = "pkg:npm/lodash@4.17.15", "pkg:npm/express@4.17.1", "pkg:npm/body-parser@1.19.0"
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
DJANGO, DJANGO_300 = "pkg:pypi/django@3.2", "pkg:pypi/django@3.2.0"


def cyclonedx(components: list[str], dependencies: dict[str, list[str]], root: str | None = APP) -> dict:
    doc: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [{"type": "library", "name": purls.parse(p).name, "bom-ref": p, "purl": p} for p in components],
        "dependencies": [{"ref": ref, "dependsOn": on} for ref, on in dependencies.items()],
    }
    doc["components"].append({"type": "file", "name": "README", "bom-ref": "file", "purl": "pkg:generic/README"})
    if root:
        doc["metadata"] = {"component": {"type": "application", "name": "app", "bom-ref": root}}
    return doc


def spdx(packages: list[str], relationships: list[tuple[str, str, str]]) -> dict:
    ids = {p: f"SPDXRef-{i}" for i, p in enumerate(packages)}
    ids["root"] = "SPDXRef-root"
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [{"SPDXID": "SPDXRef-root", "name": "app"}]
        + [
            {
                "SPDXID": ids[p],
                "name": purls.parse(p).name,
                "externalRefs": [{"referenceType": "purl", "referenceLocator": p}],
            }
            for p in packages
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root"}
        ]
        + [
            {"spdxElementId": ids[a], "relationshipType": kind, "relatedSpdxElement": ids[b]}
            for a, kind, b in relationships
        ],
    }


def check_depth(failures: list[str]) -> None:
    # Two paths to body-parser (via express, and from the app directly through a cycle): the shortest counts.
    rooted = sbom.parse(
        cyclonedx(
            [LODASH, EXPRESS, BODY],
            {APP: [LODASH, EXPRESS, "file"], EXPRESS: [BODY], BODY: [EXPRESS], LODASH: []},  # "file" is no software
        )
    )
    expect(
        failures,
        "rooted CycloneDX graph",
        (rooted.graph, rooted.depths),
        (
            "rooted",
            {"npm/lodash@4.17.15": 1, "npm/express@4.17.1": 1, "npm/body-parser@1.19.0": 2},
        ),
    )
    unrooted = sbom.parse(cyclonedx([LODASH, EXPRESS, BODY], {EXPRESS: [BODY]}))
    expect(
        failures,
        "dependencies that never leave the subject",
        (unrooted.graph, unrooted.depths),
        (
            "unrooted",
            {},
        ),
    )
    expect(failures, "no dependencies", sbom.parse(cyclonedx([LODASH], {})).graph, "none")
    expect(failures, "no subject", sbom.parse(cyclonedx([LODASH], {APP: [LODASH]}, root=None)).graph, "unrooted")
    # SPDX: DEPENDS_ON and DEPENDENCY_OF are the same edge read from either end; CONTAINS is none at all.
    both = sbom.parse(
        spdx(
            [EXPRESS, BODY, LODASH],
            [("root", "DEPENDS_ON", EXPRESS), (BODY, "DEPENDENCY_OF", EXPRESS), (LODASH, "DEV_DEPENDENCY_OF", "root")],
        )
    )
    expect(
        failures,
        "SPDX graph",
        both.depths,
        {
            "npm/express@4.17.1": 1,
            "npm/body-parser@1.19.0": 2,
            "npm/lodash@4.17.15": 1,
        },
    )
    contains = sbom.parse(spdx([EXPRESS, BODY], [("root", "CONTAINS", EXPRESS), (BODY, "DEPENDENCY_OF", EXPRESS)]))
    expect(failures, "CONTAINS is no dependency (Syft)", (contains.graph, contains.depths), ("unrooted", {}))
    manifest = sbom.parse(spdx([EXPRESS], [(EXPRESS, "DEPENDENCY_MANIFEST_OF", "root")]))
    expect(failures, "a manifest is no dependency", manifest.graph, "none")
    expect(
        failures,
        "graph in the stats",
        (rooted.stats()["dependency_graph"], rooted.stats()["depth_known"]),
        (
            "rooted",
            3,
        ),
    )
    # One component after D4: Django as 3.2 at depth 2 in one place and 3.2.0 at depth 1 in another.
    spellings = sbom.parse(cyclonedx([DJANGO, DJANGO_300, LODASH], {APP: [DJANGO_300, LODASH], LODASH: [DJANGO]}))
    expect(failures, "one depth per component after D4", spellings.depths.get("pypi/django@3.2"), 1)
    # Two generators: the shorter distance counts; one without a graph from the target adds none.
    deeper = sbom.parse(cyclonedx([EXPRESS, LODASH], {APP: [EXPRESS], EXPRESS: [LODASH]}))
    inventory, _ = correlate.canonical_inventory({"cdxgen": spellings, "syft": deeper, "other": unrooted})
    lodash = inventory["npm/lodash@4.17.15"]
    expect(
        failures,
        "the shortest distance any generator gives",
        (lodash.depth, lodash.depths),
        (
            1,
            {
                "cdxgen": 1,
                "syft": 2,
            },
        ),
    )
    expect(failures, "inventory.json carries the depth", lodash.as_dict().get("depth"), 1)
    expect(failures, "unknown depth", inventory["npm/body-parser@1.19.0"].depth, None)


def check_coordinates(failures: list[str]) -> None:
    """D11: the depth of a jar's merged-away key is the depth of the component it became."""
    jar = "thymeleaf-3.1.2.RELEASE.jar"
    syft_key, kept = "pkg:maven/thymeleaf/thymeleaf@3.1.2.RELEASE", "pkg:maven/org.thymeleaf/thymeleaf@3.1.2.RELEASE"
    syft_doc = cyclonedx([syft_key], {APP: [syft_key]})
    syft_doc["components"][0]["properties"] = [
        {"name": "syft:metadata:virtualPath", "value": f"/app.jar:BOOT-INF/lib/{jar}"}
    ]
    cdx_doc = cyclonedx([kept], {})
    cdx_doc["components"][0]["properties"] = [{"name": "SrcFile", "value": f"BOOT-INF/lib/{jar}"}]
    methods = [{"technique": "hash-comparison", "value": jar}]
    cdx_doc["components"][0]["evidence"] = {"identity": [{"field": "purl", "methods": methods}]}
    inventory, _ = correlate.canonical_inventory({"syft": sbom.parse(syft_doc), "cdxgen": sbom.parse(cdx_doc)})
    entry = inventory.get("maven/org.thymeleaf/thymeleaf@3.1.2.RELEASE")
    expect(failures, "a merged-away key's depth goes to the kept one", entry.depths if entry else None, {"syft": 1})


# --------------------------------------------------------------------------- findings


def finding(pipeline_name: str, purl: str, raw: str, *, fix: str = "unknown", **values) -> Finding:
    scanner = pipeline_name.split("+", 1)[1]
    return Finding(
        pipeline_name,
        scanner,
        raw,
        (),
        purls.key(purl) or "",
        purl,
        "HIGH",
        values.get("cvss"),
        fix,
        ("9.9",) if fix == "fixed" else (),
        epss=values.get("epss"),
        kev=values.get("kev"),
        epss_date=values.get("epss_date"),
    )


def fixture(store: Path | None):
    """SBOMs, findings, inventory and resolution for: log4j-core (direct, in KEV, a fix), lodash (a class of two
    CVEs, the newer one in KEV and scored higher), body-parser (transitive, no fix), a GHSA without a CVE, and
    a finding on a file entry."""
    doc = cyclonedx([LOG4J, LODASH, EXPRESS, BODY], {APP: [LOG4J, LODASH, EXPRESS], EXPRESS: [BODY]})
    sboms = {"cdxgen": sbom.parse(doc)}
    inventory, suppressed = correlate.canonical_inventory(sboms)
    not_installed = correlate.non_components(sboms, inventory, suppressed)
    found = [
        finding("cdxgen+trivy", LOG4J, "CVE-2021-44228", fix="fixed", cvss=10.0),
        finding(
            "cdxgen+grype", LOG4J, "CVE-2021-44228", fix="fixed", cvss=9.8, epss=0.944, kev=True, epss_date="2026-10-30"
        ),
        finding("cdxgen+trivy", LODASH, "CVE-2021-0001"),
        finding("cdxgen+trivy", LODASH, "CVE-2026-0002"),
        finding("cdxgen+grype", LODASH, "GHSA-aaaa", epss=0.2, epss_date="2026-10-30"),  # Grype's value differs
        finding("cdxgen+trivy", BODY, "CVE-2022-0003", fix="not_fixed"),
        finding("cdxgen+grype", BODY, "CVE-2022-0003", fix="wont_fix", epss=0.001, kev=True),  # KEV: Grype only
        finding("cdxgen+grype", EXPRESS, "GHSA-bbbb"),  # no CVE anywhere
        finding("cdxgen+grype", "pkg:generic/README", "CVE-2021-44228"),  # on a file entry: not installed
    ]
    resolution = aliases.Resolution.from_dict(
        {
            "ids": {
                "GHSA-aaaa": {"status": "osv", "canonical": ["CVE-2021-0001"]},
                "GHSA-bbbb": {"status": "no_cve", "canonical": ["GHSA-bbbb"]},
            },
            "merged_cves": {"CVE-2026-0002": "CVE-2021-0001"},
        }
    )
    resolution.apply(found)
    correlated = correlate.correlate(found, not_installed, inventory)
    return correlated, inventory, resolution


def by_pair(correlated) -> dict[tuple[str, str], dict]:
    return {(c.component, c.vulnerability): c.enrichment or {} for c in correlated}


def check_values(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp)
        epss, _ = enrich.store_epss(epss_file("2026-10-31", SCORES), store)
        kev, _ = enrich.store_kev(kev_file("2026.10.30", KEV), store)
        correlated, inventory, resolution = fixture(store)
        summary = enrich.enrich(correlated, inventory, resolution, epss=epss, kev=kev)
        got = by_pair(correlated)
        log4j = got[("maven/org.apache.logging.log4j/log4j-core@2.14.1", "CVE-2021-44228")]
        expect(
            failures,
            "log4j-core",
            {k: log4j[k] for k in ("epss", "kev", "kev_ransomware", "cvss_v3", "fix_available", "depth")},
            {"epss": 0.944, "kev": True, "kev_ransomware": "Known", "cvss_v3": 10.0, "fix_available": True, "depth": 1},
        )
        lodash = got[("npm/lodash@4.17.15", "CVE-2021-0001")]
        expect(
            failures,
            "a class of two CVEs: the highest EPSS, KEV if either is",
            {k: lodash[k] for k in ("cves", "epss", "epss_cve", "kev", "kev_cve", "fix_available")},
            {
                "cves": ["CVE-2021-0001", "CVE-2026-0002"],
                "epss": 0.3,
                "epss_cve": "CVE-2026-0002",
                "kev": True,
                "kev_cve": "CVE-2026-0002",
                "fix_available": None,
            },
        )
        body = got[("npm/body-parser@1.19.0", "CVE-2022-0003")]
        expect(
            failures,
            "body-parser: no fix, transitive, not in KEV whatever Grype says",
            (body["fix_available"], body["depth"], body["kev"]),
            (False, 2, False),
        )
        ghsa = got[("npm/express@4.17.1", "GHSA-bbbb")]
        expect(failures, "no CVE: no EPSS, no KEV", (ghsa["cves"], ghsa["epss"], ghsa["kev"]), ([], None, None))
        expect(
            failures,
            "the summary",
            {
                k: summary[k]
                for k in ("pairs", "with_cve", "epss_scored", "kev_listed", "cvss_v3", "fix_available", "depth")
            },
            {
                "pairs": 4,
                "with_cve": 3,
                "epss_scored": 3,
                "kev_listed": 2,
                "cvss_v3": 1,
                "fix_available": {"yes": 1, "no": 1, "unknown": 2},
                "depth": {"1": 3, "2": 1},
            },
        )
        expect(
            failures,
            "the findings in KEV",
            [x["component"] for x in summary["in_kev"]],
            ["npm/lodash@4.17.15", "maven/org.apache.logging.log4j/log4j-core@2.14.1"],  # the correlated order
        )
        expect(
            failures,
            "Grype compared with the snapshots",
            summary["grype"],
            {
                "pairs": 4,
                "epss_compared": 3,
                "epss_same": 2,
                "epss_largest_difference": 0.1,
                "epss_dates": ["2026-10-30"],
                # log4j-core agrees; Grype alone lists body-parser's CVE; only the snapshot lists lodash's class,
                # through the CVE alias resolution merged into it; GHSA-bbbb has no CVE and is not compared
                "kev_compared": 3,
                "kev_agree": 1,
                "kev_only_grype": 1,
                "kev_only_snapshot": 1,
            },
        )
        expect(
            failures,
            "a finding on a file entry is enriched but not counted",
            got[("generic/README@", "CVE-2021-44228")].get("kev"),
            True,
        )
        # Without snapshots nothing is known, and Grype's values are not used instead.
        correlated, inventory, resolution = fixture(store)
        bare = enrich.enrich(correlated, inventory, resolution)
        log4j = by_pair(correlated)[("maven/org.apache.logging.log4j/log4j-core@2.14.1", "CVE-2021-44228")]
        expect(failures, "no snapshots: Grype's EPSS and KEV are not used", (log4j["epss"], log4j["kev"]), (None, None))
        expect(
            failures,
            "no snapshots in the summary",
            (bare["epss_snapshot"], bare["epss_scored"], bare["kev_listed"]),
            (None, 0, 0),
        )
        entry = next(c for c in correlated if c.component.startswith("maven/log4j") or "log4j-core" in c.component)
        entry = entry.as_dict()
        expect(failures, "no EPSS or KEV merged from the claims", ("epss" in entry, "kev" in entry), (False, False))
        expect(
            failures,
            "Grype's values stay in its claim",
            (entry["claims"]["grype"]["epss"], entry["claims"]["grype"]["epss_date"]),
            (0.944, "2026-10-30"),
        )


# --------------------------------------------------------------------------- run directory


def write_run(root: Path) -> Path:
    run_dir = root / "20261101T000000Z-app"
    (run_dir / "raw").mkdir(parents=True)
    (run_dir / "raw" / "cdxgen.cdx.json").write_text(
        json.dumps(cyclonedx([LOG4J, EXPRESS, BODY], {APP: [LOG4J, EXPRESS], EXPRESS: [BODY]}))
    )
    trivy = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-44228",
                        "PkgIdentifier": {"PURL": LOG4J},
                        "Status": "fixed",
                        "FixedVersion": "2.15.0",
                        "Severity": "CRITICAL",
                    },
                    {"VulnerabilityID": "CVE-2022-0003", "PkgIdentifier": {"PURL": BODY}, "Status": "affected"},
                ]
            }
        ]
    }
    (run_dir / "raw" / "cdxgen.trivy.json").write_text(json.dumps(trivy))
    grype = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2021-44228",
                    "severity": "Critical",
                    "fix": {"state": "fixed", "versions": ["2.15.0"]},
                    "epss": [{"cve": "CVE-2021-44228", "epss": 0.944, "percentile": 0.9999, "date": "2026-10-30"}],
                    "knownExploited": [{"cve": "CVE-2021-44228"}],
                },
                "relatedVulnerabilities": [],
                "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive", "purl": LOG4J},
            }
        ]
    }
    (run_dir / "raw" / "cdxgen.grype.json").write_text(json.dumps(grype))
    steps = [
        Step("cdxgen", "generate", ["cdxgen"], log="raw/c.log", output="raw/cdxgen.cdx.json", returncode=0).as_dict(),
        Step("cdxgen+trivy", "scan", ["t"], log="raw/t.log", output="raw/cdxgen.trivy.json", returncode=0).as_dict(),
        Step("cdxgen+grype", "scan", ["g"], log="raw/g.log", output="raw/cdxgen.grype.json", returncode=0).as_dict(),
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
        store = Path(tmp) / "store"
        enrich.store_epss(epss_file("2026-10-30", SCORES), store)
        enrich.store_kev(kev_file("2026.10.30", KEV), store)
        run_dir = write_run(Path(tmp))
        options = pipeline.AnalysisOptions(aliases="scanner", enrichment_dir=store)
        result = pipeline.reprocess(run_dir, options)
        findings = json.loads((run_dir / "findings.json").read_text())
        expect(failures, "findings.json schema", findings["schema"], "chainguard.findings/v3")
        log4j = next(c for c in findings["correlated"] if c["vulnerability"] == "CVE-2021-44228")
        expect(
            failures,
            "the correlated entry's enrichment",
            {k: log4j["enrichment"][k] for k in ("epss", "kev", "fix_available", "depth")},
            {"epss": 0.944, "kev": True, "fix_available": True, "depth": 1},
        )
        used = json.loads((run_dir / "manifest.json").read_text())["analysis"]["enrichment"]
        expect(
            failures,
            "the manifest records the snapshots",
            (used["epss"]["version"], used["kev"]["version"]),
            ("2026-10-30", "2026.10.30"),
        )
        inventory = json.loads((run_dir / "inventory.json").read_text())
        expect(
            failures,
            "the generator's graph in inventory.json",
            inventory["generators"]["cdxgen"]["dependency_graph"],
            "rooted",
        )
        text = (run_dir / "summary.md").read_text()
        if "## Enrichment" not in text or "EPSS scores of 2026-10-30" not in text or "**In KEV:**" not in text:
            failures.append(f"summary.md lacks the enrichment section:\n{text[:400]}")
        if "Enrichment: EPSS 2026-10-30 · KEV 2026.10.30" not in report.render_console(result.summary):
            failures.append("the console lacks the enrichment line")
        # A newer snapshot arrives: reprocess keeps the run's own; a scan, or an explicit request, takes the new one.
        enrich.store_epss(epss_file("2026-10-31", {"CVE-2021-44228": (0.5, 0.9)}), store)
        pipeline.reprocess(run_dir, options)
        again = json.loads((run_dir / "manifest.json").read_text())["analysis"]
        expect(failures, "reprocess keeps the run's snapshot", again["enrichment"]["epss"]["version"], "2026-10-30")
        pipeline.reprocess(
            run_dir, pipeline.AnalysisOptions(aliases="scanner", enrichment_dir=store, epss="2026-10-31")
        )
        newer = json.loads((run_dir / "findings.json").read_text())["correlated"]
        expect(
            failures,
            "an explicit snapshot is used",
            next(c for c in newer if c["vulnerability"] == "CVE-2021-44228")["enrichment"]["epss"],
            0.5,
        )
        # The snapshot the run used is gone: the newest is used, and the run says so.
        (store / "epss" / "epss_scores-2026-10-31.json").unlink()
        result = pipeline.reprocess(run_dir, options)
        record = json.loads((run_dir / "manifest.json").read_text())["analysis"]
        expect(failures, "fallback to the newest", record["enrichment"]["epss"]["version"], "2026-10-30")
        if not any("2026-10-31" in w and "not in" in w for w in record["warnings"]):
            failures.append(f"a missing snapshot is not reported: {record['warnings']}")
        # No store at all: enriched with nothing, and warned.
        result = pipeline.reprocess(
            run_dir, pipeline.AnalysisOptions(aliases="scanner", enrichment_dir=Path(tmp) / "empty")
        )
        if sum("findings carry no" in w for w in result.warnings) != 2:
            failures.append(f"an empty store must be warned about, per kind: {result.warnings}")
        result = pipeline.reprocess(
            run_dir, pipeline.AnalysisOptions(aliases="scanner", enrichment_dir=store, enrichment=False)
        )
        if (
            "enrichment" in result.summary
            or "enrichment" in json.loads((run_dir / "findings.json").read_text())["correlated"][0]
        ):
            failures.append("--no-enrichment still enriched")


def main() -> None:
    failures: list[str] = []
    for check in (check_store, check_depth, check_coordinates, check_values, check_run_directory):
        check(failures)
    for failure in failures:
        print(f"FAIL  {failure}")
    print("enrichment: store, values, depth, D4 and D11, summary, Grype cross-check, run directory: ", end="")
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
