#!/usr/bin/env python3
"""Check the component filter keeps installed software and only that (CI runs this; no network, no tools).

The entries below are the shapes seen on real images: cdxgen's file and APT-repository entries, its source
packages listed beside the binary packages built from them, and installed packages that cdxgen marks with
identity confidence 0, which a confidence-based rule would wrongly drop.

    python3 tests/checks/check_component_filter.py
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainguard import correlate, merge, sbom  # noqa: E402
from chainguard.scanners import Finding  # noqa: E402


def zero_confidence(value: str) -> dict:
    return {
        "identity": [
            {"field": "purl", "confidence": 0, "methods": [{"technique": "filename", "confidence": 0, "value": value}]}
        ]
    }


SYFT = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "version": 1,
    "components": [
        {"type": "operating-system", "name": "debian", "version": "10"},
        {
            "type": "library",
            "name": "linux-libc-dev",
            "version": "4.19.235-1",
            "purl": "pkg:deb/debian/linux-libc-dev@4.19.235-1?arch=amd64&distro=debian-10&upstream=linux",
        },
        {
            "type": "library",
            "name": "libc6",
            "version": "2.28-10",
            "purl": "pkg:deb/debian/libc6@2.28-10?arch=amd64&distro=debian-10&upstream=glibc",
        },
        {
            "type": "library",
            "name": "openssl",
            "version": "1.1.1n-0+deb10u3",
            "purl": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb10u3?arch=amd64&distro=debian-10",
        },
    ],
}
CDXGEN = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [
        # installed binary packages
        {
            "type": "library",
            "name": "linux-libc-dev",
            "version": "4.19.235-1",
            "purl": "pkg:deb/debian/linux-libc-dev@4.19.235-1?arch=amd64&distro=debian-10",
        },
        {
            "type": "library",
            "name": "libc6",
            "version": "2.28-10",
            "purl": "pkg:deb/debian/libc6@2.28-10?arch=amd64&distro=debian-10",
        },
        # installed, but cdxgen gives it confidence 0: must be kept
        {
            "type": "library",
            "name": "openssl",
            "version": "1.1.1n-0+deb10u3",
            "purl": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb10u3?arch=amd64&distro=debian-10",
            "evidence": zero_confidence("openssl"),
        },
        # source packages listed as if installed: must be suppressed
        {
            "type": "library",
            "name": "linux",
            "version": "4.19.235-1",
            "purl": "pkg:deb/debian/linux@4.19.235-1?arch=amd64&distro=debian-10",
            "evidence": zero_confidence("linux-libc-dev"),
        },
        {
            "type": "library",
            "name": "glibc",
            "version": "2.28-10",
            "purl": "pkg:deb/debian/glibc@2.28-10?arch=amd64&distro=debian-10",
            "evidence": zero_confidence("libc6"),
        },
        # not software at all
        {
            "type": "file",
            "name": "alpine",
            "purl": "pkg:generic/alpine?path=%2Fetc%2Fsecfixes.d%2Falpine",
            "evidence": zero_confidence("../etc/secfixes.d/alpine"),
        },
        {
            "type": "data",
            "name": "deb.debian.org/debian",
            "version": "buster",
            "purl": "pkg:generic/os-repository/deb.debian.org/debian@buster",
        },
        # a language package only cdxgen found: must be kept
        {"type": "library", "name": "django", "version": "4.1.7", "purl": "pkg:pypi/django@4.1.7"},
    ],
}
INSTALLED = {
    "deb/debian/linux-libc-dev@4.19.235-1",
    "deb/debian/libc6@2.28-10",
    "deb/debian/openssl@1.1.1n-0+deb10u3",
    "pypi/django@4.1.7",
}


def finding(pipeline: str, component: str, vid: str) -> Finding:
    return Finding(pipeline, pipeline.split("+")[1], vid, (), component, None, "HIGH", None, "fixed", ())


def check() -> list[str]:
    failures = []
    parsed = {"syft": sbom.parse(copy.deepcopy(SYFT)), "cdxgen": sbom.parse(copy.deepcopy(CDXGEN))}
    inventory, suppressed = correlate.canonical_inventory(parsed)

    if set(inventory) != INSTALLED:
        missing, extra = sorted(INSTALLED - set(inventory)), sorted(set(inventory) - INSTALLED)
        failures.append(f"inventory is wrong: missing {missing}, extra {extra}")
    # Each generator's own contribution, not only the union: another generator listing a package must not hide
    # that this one lost it. cdxgen marks the installed openssl with identity confidence 0.
    cdxgen_installed = set(parsed["cdxgen"].components) & INSTALLED
    if cdxgen_installed != INSTALLED:
        failures.append(f"cdxgen's installed packages were dropped: {sorted(INSTALLED - cdxgen_installed)}")
    if set(suppressed) != {"deb/debian/linux@4.19.235-1", "deb/debian/glibc@2.28-10"}:
        failures.append(f"suppressed the wrong source packages: {sorted(suppressed)}")
    linux = suppressed.get("deb/debian/linux@4.19.235-1", {})
    if linux.get("source_of") != ["deb/debian/linux-libc-dev@4.19.235-1"] or linux.get("stated_by") != ["syft"]:
        failures.append(f"a suppression does not record its evidence: {linux}")
    if parsed["cdxgen"].not_software != {"data": 1, "file": 1}:
        failures.append(f"not-software entries were not counted by kind: {dict(parsed['cdxgen'].not_software)}")

    # cdxgen alone states no source packages, so nothing can be shown to be one: nothing is suppressed.
    alone, alone_suppressed = correlate.canonical_inventory({"cdxgen": sbom.parse(copy.deepcopy(CDXGEN))})
    if alone_suppressed or "deb/debian/linux@4.19.235-1" not in alone:
        failures.append("with a single generator, a component was suppressed without evidence")

    # Findings on what is not installed are kept and marked; findings on installed software are not marked.
    not_installed = correlate.non_components(parsed, inventory, suppressed)
    correlated = correlate.correlate(
        [
            finding("cdxgen+grype", "deb/debian/linux@4.19.235-1", "CVE-2024-1086"),
            finding("cdxgen+grype", "generic/alpine@", "CVE-2020-14929"),
            finding("syft+grype", "deb/debian/libc6@2.28-10", "CVE-2023-4911"),
        ],
        not_installed,
    )
    marks = {c.component: c.not_installed for c in correlated}
    if marks != {
        "deb/debian/linux@4.19.235-1": "source-package",
        "generic/alpine@": "file",
        "deb/debian/libc6@2.28-10": None,
    }:
        failures.append(f"findings were marked wrongly: {marks}")

    # The fused SBOM is written from the filtered inventory, so a scanner never sees the phantoms.
    document = merge.cyclonedx(inventory, [{"name": "debian", "version": "10"}], target="t")
    purls_out = {c.get("purl", "") for c in document["components"]}
    leaked = [p for p in purls_out if p.startswith(("pkg:deb/debian/linux@", "pkg:deb/debian/glibc@", "pkg:generic"))]
    if leaked:
        failures.append(f"the fused SBOM still lists what is not installed: {leaked}")

    # The off switch restores the old behaviour, for comparisons.
    raw = {
        "syft": sbom.parse(copy.deepcopy(SYFT), filter_kinds=False),
        "cdxgen": sbom.parse(copy.deepcopy(CDXGEN), filter_kinds=False),
    }
    everything, none = correlate.canonical_inventory(raw, suppress_source_packages=False)
    if none or len(everything) != 8:
        failures.append(f"--keep-all-entries does not keep everything: {len(everything)} components, {len(none)} out")
    return failures


def main() -> None:
    failures = check()
    for failure in failures:
        print(f"FAIL  {failure}")
    print("component filter: kinds, source packages, confidence-0 installs, findings, fused SBOM, off switch: ", end="")
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
