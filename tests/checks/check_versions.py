#!/usr/bin/env python3
"""Check version canonicalisation and that every stored identity key is current (no network, no tools).

Identity keys decide whether two tools' entries are one component, so the rules must stay stable.

    python3 tests/checks/check_versions.py
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from chainguard import correlate, merge, sbom, versions  # noqa: E402
from chainguard import purl as purls  # noqa: E402

# (type, version, canonical, why)
RULES = [
    ("pypi", "3.2.0", "3.2", "PEP 440 compares 3.2 and 3.2.0 as equal"),
    ("pypi", "3.2", "3.2", "already canonical"),
    ("pypi", "1.0-RC.1", "1rc1", "PEP 440 normalises pre-release spellings"),
    ("pypi", "1.0.post0", "1.post0", "a post-release is a different version, so it is kept"),
    ("pypi", "1!2.0", "1!2", "an epoch is kept"),
    ("pypi", "1.0+ubuntu1", "1+ubuntu1", "a local version label is kept"),
    ("pypi", "2.0.0-SNAPSHOT", "2.0.0-SNAPSHOT", "not PEP 440: left exactly as written"),
    ("deb", "0:1.2-3", "1.2-3", "epoch 0 is the same as no epoch (Debian Policy 5.6.12)"),
    ("deb", "1:2.38.1-5+b1", "1:2.38.1-5+b1", "any other epoch changes ordering, so it is kept"),
    ("deb", "10:1.0", "10:1.0", "epoch 10 is not epoch 0"),
    ("deb", "1.0-rc-0", "1.0-rc-0", "a -0 revision is not stripped: it would move the upstream/revision split"),
    ("rpm", "0:1.2-3.el9", "1.2-3.el9", "epoch 0, as for Debian"),
    ("maven", "1.0", "1.0", "a Maven version is a coordinate"),
    ("maven", "1.0.0", "1.0.0", "Maven orders 1.0 and 1.0.0 as equal, but they are different artifacts"),
    ("maven", "3.0.5.RELEASE", "3.0.5.RELEASE", "qualifiers are part of the coordinate"),
    ("npm", "v1.2.3", "v1.2.3", "no rule for npm: lockfiles carry the registry's canonical versions"),
]


def check_rules() -> list[str]:
    return [
        f"{ptype} {version!r}: got {versions.canonical(ptype, version)!r}, expected {want!r} ({why})"
        for ptype, version, want, why in RULES
        if versions.canonical(ptype, version) != want
    ]


def check_keys_and_output() -> list[str]:
    failures = []
    if (
        purls.key("pkg:pypi/Django@3.2.0") != purls.key("pkg:pypi/django@3.2")
        or purls.key("pkg:pypi/django@3.2") != "pypi/django@3.2"
    ):
        failures.append("Django 3.2 and 3.2.0 do not share one key")
    if purls.parse("pkg:pypi/requests@2.25.0").version != "2.25.0":
        failures.append("a parsed PURL lost the version its tool reported")
    if purls.key("pkg:maven/org.example/x@1.0") == purls.key("pkg:maven/org.example/x@1.0.0"):
        failures.append("two Maven coordinates were merged")

    def bom(*components: dict) -> dict:
        return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": list(components)}

    syft = bom(
        {"type": "library", "name": "django", "version": "3.2.0", "purl": "pkg:pypi/django@3.2.0"},
        {"type": "library", "name": "requests", "version": "2.25.0", "purl": "pkg:pypi/requests@2.25.0"},
    )
    cdxgen = bom(
        {"type": "library", "name": "django", "version": "3.2", "purl": "pkg:pypi/django@3.2"},
        {"type": "library", "name": "django", "version": "3.2.0", "purl": "pkg:pypi/django@3.2.0"},
    )
    parsed = {"syft": sbom.parse(copy.deepcopy(syft)), "cdxgen": sbom.parse(copy.deepcopy(cdxgen))}
    inventory, _ = correlate.canonical_inventory(parsed)
    if sorted(inventory) != ["pypi/django@3.2", "pypi/requests@2.25"]:
        failures.append(f"the merged inventory is wrong: {sorted(inventory)}")
    django = inventory.get("pypi/django@3.2")
    if not django or django.reported_versions != {"3.2", "3.2.0"}:
        failures.append(f"the merged spellings are not recorded: {django and django.reported_versions}")
    # Output keeps a spelling a tool used: requests is written 2.25.0, never the canonical 2.25.
    written = {c["purl"] for c in merge.cyclonedx(inventory, [], target="t")["components"] if c.get("purl")}
    if "pkg:pypi/requests@2.25.0" not in written:
        failures.append(f"the merged SBOM rewrote a version into a spelling no tool used: {sorted(written)}")
    return failures


def main() -> None:
    failures = check_rules() + check_keys_and_output()
    for failure in failures:
        print(f"FAIL  {failure}")
    print(f"{len(RULES)} version rules, keys and output: ", end="")
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
