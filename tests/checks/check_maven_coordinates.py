#!/usr/bin/env python3
"""Check design rule D11 (CI runs this; no network, no tools).

Synthetic Syft and cdxgen SBOMs of a Spring Boot jar, with each generator's own fields, in the shapes seen on
a real image:

  merge         a group-less Syft key (thymeleaf) and a guessed Syft group (ASM) each become cdxgen's SHA-1 group;
                Syft's stated group wins over cdxgen's group-less one (micrometer)
  tie           two stated groups (hibernate-core) stay apart, and both say so
  apart         different jars, different versions, one generator listing both keys, a jar no generator names,
                and a jar ranked under two groups by two archives are never merged
  evidence      jar names from Syft's virtualPath and location, cdxgen's SrcFile and identity evidence, SPDX's
                sourceInfo; the group's evidence (a SHA-1 lookup, stated, none)
  downstream    a finding on a merged-away key lands on the kept one, with both generators as its evidence; the
                hand-off check counts a document listing the old key as listing the component; the merged SBOM
                lists the jar once; the switch keeps every key, as before

    python3 tests/checks/check_maven_coordinates.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from chainguard import correlate, handoff, merge, pipeline, sbom  # noqa: E402
from chainguard.runner import Step  # noqa: E402
from chainguard.scanners import Finding  # noqa: E402

FAT = "/home/app/app.jar:BOOT-INF/lib"


def syft(name: str, version: str, group: str, jar: str | None = None, *, archive: str = FAT) -> dict:
    props = [{"name": "syft:package:foundBy", "value": "java-archive-cataloger"}]
    if jar:
        props += [
            {"name": "syft:metadata:virtualPath", "value": f"{archive}/{jar}"},
            {"name": "syft:location:0:path", "value": archive.split(":", 1)[0]},
        ]
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:maven/{group}/{name}@{version}",
        "properties": props,
    }


def cdxgen(
    name: str,
    version: str,
    group: str,
    jar: str | None = None,
    technique: str = "hash-comparison",
    *,
    evidence: bool = True,
) -> dict:
    entry = {
        "type": "library",
        "name": name,
        "version": version,
        "group": group,
        "purl": f"pkg:maven/{group}/{name}@{version}?type=jar",
    }
    if jar:
        entry["properties"] = [{"name": "SrcFile", "value": f"jar-deps-x/BOOT-INF/lib/{jar}"}]
        entry["evidence"] = {
            "identity": [
                {
                    "field": "purl",
                    "confidence": 0.5,
                    "methods": [{"technique": technique, "confidence": 0.5, "value": jar if evidence else "pom.xml"}],
                }
            ]
        }
    return entry


def document(*components: dict) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": list(components)}


SYFT = document(
    syft("thymeleaf", "3.1.2.RELEASE", "thymeleaf", "thymeleaf-3.1.2.RELEASE.jar"),
    syft("asm", "9.7.1", "org.objectweb.asm", "asm-9.7.1.jar"),
    syft("micrometer-commons", "1.14.4", "io.micrometer", "micrometer-commons-1.14.4.jar"),
    syft("hibernate-core", "6.6.8.Final", "org.hibernate", "hibernate-core-6.6.8.Final.jar"),
    syft("guava", "33.0", "guava", "guava-33.0.jar"),  # cdxgen has another version: never merged
    syft("verlib", "1.0", "verlib", "verlib.jar"),
    syft("commons-io", "2.16", "commons-io", "commons-io-2.16.jar"),  # cdxgen's is from another jar file
    syft("dup", "1.0", "a.dup", "dup-1.0.jar"),  # Syft lists both keys: to it they are two components
    syft("dup", "1.0", "b.dup", "dup-1.0.jar"),
    syft("nojar", "1.0", "nojar"),  # no jar named anywhere
    syft("two", "1.0", "two", "two-1.0.jar"),  # in two archives, each ranking another group above it
    syft("two", "1.0", "two", "two-1.0.jar", archive="/opt/other.jar:lib"),
)
CDXGEN = document(
    cdxgen("thymeleaf", "3.1.2.RELEASE", "org.thymeleaf", "thymeleaf-3.1.2.RELEASE.jar"),
    cdxgen("asm", "9.7.1", "org.ow2.asm", "asm-9.7.1.jar"),
    # names its jar in SrcFile only, as cdxgen does where its identity evidence is a manifest
    cdxgen(
        "micrometer-commons",
        "1.14.4",
        "micrometer-commons",
        "micrometer-commons-1.14.4.jar",
        "manifest-analysis",
        evidence=False,
    ),
    cdxgen("verlib", "2.0", "org.ver", "verlib.jar"),  # same jar file name as Syft's, another version: apart
    cdxgen(
        "hibernate-core", "6.6.8.Final", "org.hibernate.orm.core", "hibernate-core-6.6.8.Final.jar", "manifest-analysis"
    ),
    cdxgen("guava", "33.1", "com.google.guava", "guava-33.1.jar"),
    cdxgen("commons-io", "2.16", "org.apache.commons", "commons-io-2.16-shaded.jar"),
    cdxgen("dup", "1.0", "c.dup", "dup-1.0.jar"),
    cdxgen("nojar", "1.0", "org.nojar"),
    cdxgen("two", "1.0", "org.one", "two-1.0.jar"),
)
# One Syft key in two jar files; each of two other generators ranks a different group above it, in one jar each.
CONFLICT = {
    "syft": document(syft("x", "1.0", "x", "x-1.0.jar"), syft("x", "1.0", "x", "x-1.0-all.jar")),
    "b": document(cdxgen("x", "1.0", "org.b", "x-1.0.jar")),
    "c": document(cdxgen("x", "1.0", "org.c", "x-1.0-all.jar")),
}

MERGES = {
    "maven/thymeleaf/thymeleaf@3.1.2.RELEASE": "maven/org.thymeleaf/thymeleaf@3.1.2.RELEASE",
    "maven/org.objectweb.asm/asm@9.7.1": "maven/org.ow2.asm/asm@9.7.1",
    "maven/micrometer-commons/micrometer-commons@1.14.4": "maven/io.micrometer/micrometer-commons@1.14.4",
    # The same jar file under two archives counts once for Syft: one key, so it merges like any other.
    "maven/two/two@1.0": "maven/org.one/two@1.0",
}
APART = {
    "maven/org.hibernate/hibernate-core@6.6.8.Final",
    "maven/org.hibernate.orm.core/hibernate-core@6.6.8.Final",
    "maven/guava/guava@33.0",
    "maven/com.google.guava/guava@33.1",
    "maven/commons-io/commons-io@2.16",
    "maven/org.apache.commons/commons-io@2.16",
    "maven/a.dup/dup@1.0",
    "maven/b.dup/dup@1.0",
    "maven/c.dup/dup@1.0",
    "maven/nojar/nojar@1.0",
    "maven/org.nojar/nojar@1.0",
    "maven/verlib/verlib@1.0",
    "maven/org.ver/verlib@2.0",
}


def parsed() -> dict[str, sbom.ParsedSbom]:
    return {"syft": sbom.parse(SYFT), "cdxgen": sbom.parse(CDXGEN)}


def check_evidence(failures: list[str]) -> None:
    sboms = parsed()
    s, c = sboms["syft"], sboms["cdxgen"]
    want = {
        ("syft", "maven/thymeleaf/thymeleaf@3.1.2.RELEASE"): ({"thymeleaf-3.1.2.RELEASE.jar"}, "none"),
        ("syft", "maven/org.objectweb.asm/asm@9.7.1"): ({"asm-9.7.1.jar"}, "stated"),
        ("cdxgen", "maven/org.thymeleaf/thymeleaf@3.1.2.RELEASE"): (
            {"thymeleaf-3.1.2.RELEASE.jar"},
            "maven-central-sha1",
        ),
        ("cdxgen", "maven/micrometer-commons/micrometer-commons@1.14.4"): ({"micrometer-commons-1.14.4.jar"}, "none"),
        ("cdxgen", "maven/org.hibernate.orm.core/hibernate-core@6.6.8.Final"): (
            {"hibernate-core-6.6.8.Final.jar"},
            "stated",
        ),
    }
    for (generator, key), (jars, evidence) in want.items():
        doc = s if generator == "syft" else c
        got = (doc.archives.get(key), doc.group_evidence.get(key))
        if got != (jars, evidence):
            failures.append(f"{generator} {key}: jars and group evidence {got}, expected {(jars, evidence)}")
    if s.archives.get("maven/two/two@1.0") != {"two-1.0.jar"}:
        failures.append(f"a jar in two archives: {s.archives.get('maven/two/two@1.0')}")
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [
            {
                "SPDXID": "SPDXRef-p",
                "name": "asm",
                "versionInfo": "9.7.1",
                "sourceInfo": "acquired package info from installed java archive: /app.jar:BOOT-INF/lib/asm-9.7.1.jar",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:maven/org.objectweb.asm/asm@9.7.1"}
                ],
            }
        ],
    }
    if sbom.parse(spdx).archives.get("maven/org.objectweb.asm/asm@9.7.1") != {"asm-9.7.1.jar"}:
        failures.append("SPDX sourceInfo is not read for the jar")
    for value, want_jar in (
        ("/home/a.jar:BOOT-INF/lib/b-1.jar", "b-1.jar"),
        ("C:\\libs\\c.war", "c.war"),
        ("/usr/lib/x.so", None),
        ("jar-deps-x/BOOT-INF/lib/d.jar!/META-INF", None),
    ):
        if sbom.archive_name(value) != want_jar:
            failures.append(f"archive_name({value!r}) = {sbom.archive_name(value)!r}, expected {want_jar!r}")


def check_merges(failures: list[str]) -> dict:
    sboms = parsed()
    variants, undecided = correlate.coordinate_variants(sboms)
    if variants != MERGES:
        failures.append(f"merged {variants}, expected {MERGES}")
    ties = [sorted(u["keys"]) for u in undecided]
    if ties != [sorted(k for k in APART if "hibernate" in k)]:
        failures.append(f"undecided {ties}, expected only hibernate-core")
    inventory, _ = correlate.canonical_inventory(sboms)
    for key in APART:
        if key not in inventory:
            failures.append(f"{key}: missing; the rule must leave it apart")
    for old, new in MERGES.items():
        entry = inventory.get(new)
        if old in inventory or entry is None or entry.found_by != {"syft", "cdxgen"}:
            failures.append(f"{old} -> {new}: inventory {old in inventory}, kept entry {entry and entry.found_by}")
        elif old not in entry.merged_keys:
            failures.append(f"{new} does not record what was merged into it: {entry.merged_keys}")
    tie = inventory.get("maven/org.hibernate/hibernate-core@6.6.8.Final")
    if tie is None or tie.undecided_with != {"maven/org.hibernate.orm.core/hibernate-core@6.6.8.Final"}:
        failures.append(f"a tie must be recorded on both keys: {tie and tie.undecided_with}")
    record = inventory["maven/org.thymeleaf/thymeleaf@3.1.2.RELEASE"].as_dict()
    if record.get("merged_keys") != {"maven/thymeleaf/thymeleaf@3.1.2.RELEASE": ["syft"]} or record.get(
        "group_evidence"
    ) != {"cdxgen": "maven-central-sha1", "syft": "none"}:
        failures.append(f"inventory.json record of a merged jar: {record}")
    conflict, _ = correlate.coordinate_variants({g: sbom.parse(d) for g, d in CONFLICT.items()})
    if conflict:
        failures.append(f"a key two jars rank under different groups was merged: {conflict}")
    before, _ = correlate.canonical_inventory(sboms, maven_coordinates=False)
    if not set(MERGES) <= set(before) or any(e.merged_keys for e in before.values()):
        failures.append("maven_coordinates=False must keep every key")
    if len(before) - len(inventory) != len(MERGES):
        failures.append(f"components {len(before)} -> {len(inventory)}, expected {len(MERGES)} fewer")
    return inventory


def finding(pipeline_name: str, key: str, vulnerability: str) -> Finding:
    f = Finding(
        pipeline_name, pipeline_name.split("+")[1], vulnerability, (), key, "pkg:" + key, "HIGH", 7.5, "fixed", ("9",)
    )
    f.vulnerability, f.vulnerabilities = vulnerability, (vulnerability,)
    return f


def check_downstream(failures: list[str], inventory: dict) -> None:
    sboms = parsed()
    old, new = "maven/thymeleaf/thymeleaf@3.1.2.RELEASE", "maven/org.thymeleaf/thymeleaf@3.1.2.RELEASE"
    findings = [
        finding("syft+grype", old, "CVE-1"),
        finding("cdxgen+grype", new, "CVE-1"),
        finding("direct+grype", old, "CVE-1"),
        finding("fused+grype", new, "CVE-1"),
    ]
    steps = [
        Step(p, "scan", [], log="", returncode=0) for p in ("syft+grype", "cdxgen+grype", "direct+grype", "fused+grype")
    ]
    result = pipeline.analyze(sboms, findings, steps, pipeline.AnalysisOptions(aliases="scanner"))
    pairs = {(c.component, c.vulnerability): c for c in result.correlated}
    entry = pairs.get((new, "CVE-1"))
    if (old, "CVE-1") in pairs or entry is None or (entry.consensus, entry.pipelines_reporting) != (2, 2):
        failures.append(f"a finding on a merged key must land on the kept one with both generators: {pairs.keys()}")
    summary = result.summary["components"]
    if (summary["union"], summary["coordinates_merged"], summary["coordinates_undecided"]) != (
        len(inventory),
        len(MERGES),
        1,
    ):
        failures.append(
            f"summary: {summary['union']} components, merged {summary['coordinates_merged']}, "
            f"undecided {summary['coordinates_undecided']}"
        )
    if summary["per_generator"]["syft"]["accepted_components"] != len(sboms["syft"].components):
        failures.append(f"syft's accepted components {summary['per_generator']['syft']['accepted_components']}")
    check = result.summary["handoff"]
    if check["pipelines"].get("syft+grype", {}).get("lost") != 0:
        failures.append(
            f"hand-off: syft+grype lost a pair it reported on its own key: {check['pipelines'].get('syft+grype')}"
        )
    summary_check, _ = handoff.check(
        [finding("direct+grype", new, "CVE-2"), finding("syft+grype", "maven/org.ow2.asm/asm@9.7.1", "CVE-3")],
        {"syft": sboms["syft"]},
        [Step(p, "scan", [], log="", returncode=0) for p in ("direct+grype", "syft+grype")],
        {},
        correlate.key_aliases(inventory),
    )
    if summary_check["pipelines"]["syft+grype"]["lost_by_class"]["handoff"] != 1:
        failures.append(
            f"a document listing a merged-away key lists the component: {summary_check['pipelines']['syft+grype']}"
        )
    document = merge.cyclonedx(inventory, [], target="t")
    purls = [c.get("purl", "") for c in document["components"]]
    thymeleaf = [p for p in purls if "/thymeleaf@" in p]
    if [p.split("?", 1)[0] for p in thymeleaf] != ["pkg:maven/org.thymeleaf/thymeleaf@3.1.2.RELEASE"]:
        failures.append(f"the merged SBOM must list the jar once, under the kept group: {thymeleaf}")


def main() -> None:
    failures: list[str] = []
    check_evidence(failures)
    inventory = check_merges(failures)
    check_downstream(failures, inventory)
    for failure in failures:
        print(f"FAIL  {failure}")
    print("Maven coordinates: evidence, merges, ties, apart, downstream, switch: ", end="")
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
