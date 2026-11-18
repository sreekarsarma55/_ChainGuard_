#!/usr/bin/env python3
"""Check source-package identity against each tool's real encodings (CI runs this; no network, no images).

The fragments below are copied from the output of Syft 1.52, Trivy 0.74 and cdxgen 12.8 on debian:12.0 and
alpine:3.22.0, including the cases that are easy to get wrong: a source version that differs from the binary
version, an epoch, Trivy's split version fields, and Syft's SPDX ``sourceInfo``, which describes which files
were read and must not be mistaken for a source package.

    python3 tests/checks/check_source_identity.py
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainguard import ospackage, purl  # noqa: E402
from chainguard.repair import repair  # noqa: E402
from chainguard.sbom import parse  # noqa: E402

TRIVY = ospackage.TRIVY_PREFIX


def props(**fields: str) -> list[dict[str, str]]:
    return [{"name": f"{TRIVY}{k}", "value": v} for k, v in fields.items()]


# (what it checks, component, spdx?, expected source name and version, expected evidence)
CASES = [
    (
        "Syft: upstream qualifier with only a name means the source shares the binary version",
        {"purl": "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12.0&upstream=glibc"},
        False,
        ("glibc", "2.36-9"),
        "purl-upstream",
    ),
    (
        "Syft: upstream qualifier with its own version (the binary was rebuilt)",
        {"purl": "pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bb1?upstream=util-linux%402.38.1-5"},
        False,
        ("util-linux", "2.38.1-5"),
        "purl-upstream",
    ),
    (
        "Trivy CycloneDX: the version is split across SrcVersion and SrcRelease",
        {
            "purl": "pkg:deb/debian/libc6@2.36-9",
            "properties": props(SrcName="glibc", SrcVersion="2.36", SrcRelease="9"),
        },
        False,
        ("glibc", "2.36-9"),
        "trivy-properties",
    ),
    (
        "Trivy CycloneDX: SrcEpoch belongs in front of the version",
        {
            "purl": "pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1%2Bb1",
            "properties": props(SrcName="shadow", SrcVersion="4.13+dfsg1", SrcRelease="1", SrcEpoch="1"),
        },
        False,
        ("shadow", "1:4.13+dfsg1-1"),
        "trivy-properties",
    ),
    (
        "Trivy SPDX: the 'built package from' string",
        {
            "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:deb/debian/libc6@2.36-9"}],
            "sourceInfo": "built package from: glibc 2.36-9",
        },
        True,
        ("glibc", "2.36-9"),
        "spdx-source-info",
    ),
    (
        "Syft SPDX: sourceInfo names the files that were read, which is not a source package",
        {
            "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:deb/debian/zlib1g@1%3A1.2.13.dfsg-1"}],
            "sourceInfo": "acquired package info from DPKG DB: /var/lib/dpkg/status",
        },
        True,
        ("zlib1g", "1:1.2.13.dfsg-1"),
        "binary-package",
    ),
    (
        "cdxgen: nothing stated, so the package is its own source",
        {"purl": "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12&distro_name=bookworm"},
        False,
        ("libc6", "2.36-9"),
        "binary-package",
    ),
    (
        "Alpine: the apk origin arrives in the same qualifier",
        {"purl": "pkg:apk/alpine/libcrypto3@3.5.0-r0?arch=x86_64&distro=3.22.0&upstream=openssl"},
        False,
        ("openssl", "3.5.0-r0"),
        "purl-upstream",
    ),
]


def resolve(entry: dict, spdx: bool):
    raw = entry.get("purl")
    if spdx:
        raw = next(r["referenceLocator"] for r in entry["externalRefs"] if r["referenceType"] == "purl")
    parsed = purl.parse(raw)
    return parsed, ospackage.resolve(parsed, entry, spdx=spdx)


def check_cases() -> list[str]:
    failures = []
    for title, entry, spdx, expected, evidence in CASES:
        _, source = resolve(copy.deepcopy(entry), spdx)
        if (source.name, source.version) != expected:
            failures.append(f"{title}: got {(source.name, source.version)}, expected {expected}")
        if source.evidence != evidence:
            failures.append(f"{title}: evidence {source.evidence}, expected {evidence}")
    return failures


def check_round_trip() -> list[str]:
    """Writing then reading must give the same answer, and must survive a second pass unchanged."""
    failures = []
    for title, entry, spdx, expected, _ in CASES:
        written = copy.deepcopy(entry)
        parsed, source = resolve(written, spdx)
        attach = ospackage.attach_spdx if spdx else ospackage.attach_cyclonedx
        attach(written, source)
        _, after = resolve(written, spdx)
        if (after.name, after.version) != expected:
            failures.append(f"{title}: after writing, read back {(after.name, after.version)}, expected {expected}")
        once = copy.deepcopy(written)
        if attach(written, after):
            failures.append(f"{title}: writing twice changed the document again (not idempotent)")
        if once != written:
            failures.append(f"{title}: second write altered the document")
    return failures


def check_stale_split_fields() -> list[str]:
    """Regression: a whole SrcVersion left beside Trivy's SrcRelease reads as '2.36-9-9' and matches nothing."""
    component = {
        "purl": "pkg:deb/debian/libc6@2.36-9",
        "properties": props(SrcName="glibc", SrcVersion="2.36", SrcRelease="9"),
    }
    ospackage.attach_cyclonedx(component, ospackage.SourcePackage("glibc", "2.36-9", "purl-upstream"))
    names = [p["name"].removeprefix(TRIVY) for p in component["properties"]]
    leftovers = [n for n in names if n in ("SrcRelease", "SrcEpoch")]
    if leftovers:
        return [f"stale {', '.join(leftovers)} left beside a complete SrcVersion"]
    _, source = resolve(component, False)
    return [] if (source.name, source.version) == ("glibc", "2.36-9") else [f"reads back as {source.version}"]


def check_document() -> list[str]:
    """A whole SBOM: OS components gain identity, everything else is left alone."""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "operating-system", "name": "debian", "version": "12.0"},
            {
                "type": "library",
                "name": "libc6",
                "version": "2.36-9",
                "purl": "pkg:deb/debian/libc6@2.36-9?upstream=glibc",
            },
            {"type": "library", "name": "flask", "version": "1.1.2", "purl": "pkg:pypi/flask@1.1.2"},
            {"type": "file", "name": "hosts", "purl": "pkg:generic/hosts?path=%2Fetc%2Fhosts"},
        ],
    }
    before = parse(copy.deepcopy(document))
    repaired, counts = repair(document)
    after = parse(copy.deepcopy(repaired))
    failures = []
    if counts["os_components"] != 1 or counts["source_stated"] != 1:
        failures.append(f"expected one stated OS component, got {counts}")
    if set(before.components) != set(after.components):
        failures.append("the repair changed which components the SBOM lists")
    if json.dumps(repaired["components"][2], sort_keys=True) != json.dumps(document["components"][2], sort_keys=True):
        failures.append("a PyPI component was modified")
    if repaired["components"][3] != document["components"][3]:
        failures.append("a file entry was modified")
    if after.sources["deb/debian/libc6@2.36-9"].name != "glibc":
        failures.append("libc6 lost its source package")
    return failures


def main() -> None:
    failures = check_cases() + check_round_trip() + check_stale_split_fields() + check_document()
    for failure in failures:
        print(f"FAIL  {failure}")
    print(f"{len(CASES)} encodings, round trip, split-field regression, whole document: ", end="")
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
