#!/usr/bin/env python3
"""Check the merged SBOM keeps everything a scanner needs (CI runs this; no network, no images, no tools).

Each case below is a loss that was measured on real images before it was fixed, so a regression shows up here
instead of as a quietly smaller result.

    python3 tests/checks/check_fusion.py
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainguard import correlate, merge, ospackage, sbom  # noqa: E402

# One CycloneDX SBOM per generator, in the shapes the real tools produce for the same image.
SYFT = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "version": 1,
    "components": [
        {"type": "operating-system", "name": "debian", "version": "12.0"},
        {
            "type": "library",
            "name": "libc6",
            "version": "2.36-9",
            "purl": "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12.0&upstream=glibc",
            "cpe": "cpe:2.3:a:libc6:libc6:2.36-9:*:*:*:*:*:*:*",
            "properties": [{"name": "syft:cpe23", "value": "cpe:2.3:a:gnu:glibc:2.36-9:*:*:*:*:*:*:*"}],
        },
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.4",
            "purl": "pkg:npm/%40scope/lodash@4.17.4",
        },
    ],
}
CDXGEN = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [
        {  # cdxgen states no source package and no OS component
            "type": "library",
            "group": "debian",
            "name": "libc6",
            "version": "2.36-9",
            "purl": "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12&distro_name=bookworm",
        },
        {  # only cdxgen reports this one, so fusion must keep it
            "type": "library",
            "name": "spring-core",
            "version": "5.3.13",
            "purl": "pkg:maven/org.springframework/spring-core@5.3.13",
        },
    ],
}


def build():
    parsed = {"syft": sbom.parse(copy.deepcopy(SYFT)), "cdxgen": sbom.parse(copy.deepcopy(CDXGEN))}
    inventory = correlate.merge_inventory(parsed)
    operating_systems = [o for p in parsed.values() for o in p.operating_systems]
    return (
        inventory,
        merge.cyclonedx(inventory, operating_systems, target="t", generators=sorted(parsed)),
        merge.spdx(inventory, operating_systems, target="t", generators=sorted(parsed)),
    )


def check() -> list[str]:
    inventory, cdx, spdx = build()
    failures = []
    libc = next(c for c in cdx["components"] if c.get("purl", "").startswith("pkg:deb"))

    # Every generator's components survive the merge.
    keys = set(inventory)
    if "maven/org.springframework/spring-core@5.3.13" not in keys:
        failures.append("a component only one generator reported is missing from the merged inventory")
    if len(keys) != 3:
        failures.append(f"expected 3 merged components, got {len(keys)}: {sorted(keys)}")

    # D3 and D7: both formats carry the operating system, or a scanner cannot pick a vulnerability source.
    if not any(c.get("type") == "operating-system" for c in cdx["components"]):
        failures.append("the CycloneDX output has no operating-system component (D3)")
    if not any(p.get("primaryPackagePurpose") == "OPERATING-SYSTEM" for p in spdx["packages"]):
        failures.append("the SPDX output has no OPERATING-SYSTEM package (D7)")

    # An OS package's name must not carry its distribution: Trivy prepends `group` and matches nothing.
    if libc.get("name") != "libc6" or "group" in libc:
        failures.append(f"an OS component's name or group is wrong: {libc.get('group')}/{libc.get('name')}")
    spdx_libc = next(p for p in spdx["packages"] if p["name"].endswith("libc6"))
    if spdx_libc["name"] != "libc6":
        failures.append(f"the SPDX name of an OS package is wrong: {spdx_libc['name']}")

    # A path-like namespace is part of the real name; a Maven one is a separate coordinate.
    npm = next(c for c in cdx["components"] if c.get("purl", "").startswith("pkg:npm"))
    maven = next(c for c in cdx["components"] if c.get("purl", "").startswith("pkg:maven"))
    if npm["name"] != "@scope/lodash":
        failures.append(f"an npm scope was not kept in the name: {npm['name']}")
    if (maven.get("group"), maven["name"]) != ("org.springframework", "spring-core"):
        failures.append(f"Maven coordinates are wrong: {maven.get('group')}:{maven['name']}")

    # D2: the source package one generator stated reaches the merged document, in every carrier.
    parsed = sbom.parse(copy.deepcopy(cdx))
    source = parsed.sources.get("deb/debian/libc6@2.36-9")
    if not source or source.name != "glibc":
        failures.append(f"the source package did not survive into CycloneDX: {source}")
    spdx_source = ospackage.from_spdx(spdx_libc, type("P", (), {"version": "2.36-9"})())
    if not spdx_source or spdx_source.name != "glibc":
        failures.append(f"the source package did not survive into SPDX: {spdx_source}")

    # CPEs, primary and alternate, stated against the input rather than against our own parse, so that a
    # parser which stops reading alternates still fails here. Dropping them cost real findings: NVD indexes
    # some CVEs under a vendor the primary CPE does not name.
    expected_cpes = {SYFT["components"][1]["cpe"], SYFT["components"][1]["properties"][0]["value"]}
    if inventory["deb/debian/libc6@2.36-9"].cpes != expected_cpes:
        failures.append(f"the inventory lost CPEs from the input: {sorted(inventory['deb/debian/libc6@2.36-9'].cpes)}")
    carried = {libc.get("cpe")} | {p["value"] for p in libc.get("properties", []) if p["name"] == merge.ALTERNATE_CPE}
    if carried != expected_cpes:
        failures.append(f"CycloneDX lost CPEs: kept {sorted(c for c in carried if c)}")
    spdx_cpes = {r["referenceLocator"] for r in spdx_libc["externalRefs"] if r["referenceType"] == "cpe23Type"}
    if spdx_cpes != expected_cpes:
        failures.append(f"SPDX lost CPEs: kept {sorted(spdx_cpes)}")

    # The PURL qualifiers a scanner matches on, and provenance for every component.
    qualifiers = libc["purl"].split("?", 1)[1] if "?" in libc["purl"] else ""
    for needed in ("arch=", "distro=", "upstream="):
        if needed not in qualifiers:
            failures.append(f"the merged PURL dropped {needed.rstrip('=')}: {libc['purl']}")
    provenance = [p["value"] for p in libc["properties"] if p["name"] == merge.FOUND_BY]
    if not any("cdxgen" in v and "syft" in v for v in provenance):
        failures.append(f"a component found by both generators records {provenance}")

    # Both formats must describe the same components (D7).
    if {c["purl"] for c in cdx["components"] if c.get("purl")} != {
        r["referenceLocator"]
        for p in spdx["packages"]
        for r in p.get("externalRefs", [])
        if r["referenceType"] == "purl"
    }:
        failures.append("the two output formats describe different components")

    # Writing twice must produce the same document.
    _, again, _ = build()
    if {c["bom-ref"] for c in again["components"] if "bom-ref" in c} != {
        c["bom-ref"] for c in cdx["components"] if "bom-ref" in c
    }:
        failures.append("merging the same inputs twice gave different components")
    return failures


def main() -> None:
    failures = check()
    for failure in failures:
        print(f"FAIL  {failure}")
    print("merged SBOM: components, OS component, naming, source package, CPEs, qualifiers, both formats: ", end="")
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
