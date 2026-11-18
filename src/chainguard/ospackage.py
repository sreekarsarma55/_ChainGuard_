"""Source-package identity for operating-system packages (design rule D2).

Linux distributions publish advisories against the **source** package, while an SBOM lists the **binary**
packages installed. On a Debian 12.0 image, 62 of 88 binary packages are built from a source package with a
different name, so a scanner that cannot see the source package can match almost nothing.

Each tool records that identity somewhere different, and no two agree:

================  ===========  ====================================================================
Tool              Format       Carrier
================  ===========  ====================================================================
Syft              CycloneDX    PURL qualifier ``upstream=glibc`` or ``upstream=bash@5.2.15-2``
Syft              SPDX         nothing: ``sourceInfo`` describes which files were read, not the
                               source package, so the identity is lost in this format
Trivy             CycloneDX    properties ``SrcName``, ``SrcVersion``, ``SrcRelease``, ``SrcEpoch``,
                               with the version split into its parts
Trivy             SPDX         ``sourceInfo: "built package from: glibc 2.36-9"``
cdxgen            CycloneDX    nothing usable: it emits the source package as a *separate* component
                               instead, which inflates the inventory
================  ===========  ====================================================================

This module reads every carrier into one ``SourcePackage``, and writes one back into every carrier, so that
what any generator recorded is available to any scanner. Where no carrier says otherwise, a package is its
own source, which is the correct default: most packages are.

Identity itself stays keyed on the binary package, because that is what is installed and what the ground
truth lists. The source package is an attribute of it, used for advisory matching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from chainguard import purl as purls

OS_TYPES = frozenset({"deb", "rpm", "apk"})
TRIVY_PREFIX = "aquasecurity:trivy:"
SPDX_SOURCE_PREFIX = "built package from: "  # Trivy's magic string (aquasecurity/trivy#2934)
_SPDX_SOURCE = re.compile(rf"^{re.escape(SPDX_SOURCE_PREFIX)}(?P<name>\S+)(?:\s+(?P<version>\S+))?\s*$")


@dataclass(frozen=True)
class SourcePackage:
    """The source package a binary package was built from, and where that was recorded."""

    name: str
    version: str
    evidence: str  # "purl-upstream" | "trivy-properties" | "spdx-source-info" | "binary-package"

    @property
    def implicit(self) -> bool:
        """True when no carrier stated a source package, so the binary package is its own source."""
        return self.evidence == "binary-package"

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version, "evidence": self.evidence}


def _properties(component: dict[str, Any]) -> dict[str, str]:
    return {
        str(p.get("name", "")).removeprefix(TRIVY_PREFIX): str(p.get("value", ""))
        for p in component.get("properties") or []
        if isinstance(p, dict)
    }


def _join(epoch: str, version: str, release: str) -> str:
    """Trivy splits a Debian source version into epoch, upstream version and revision; put it back together."""
    joined = f"{version}-{release}" if release else version
    return f"{epoch}:{joined}" if epoch and ":" not in joined else joined


def from_purl(parsed: purls.Purl) -> SourcePackage | None:
    """Syft's ``upstream`` qualifier: a name, optionally with its own version."""
    upstream = (parsed.qualifiers or {}).get("upstream", "").strip()
    if not upstream:
        return None
    name, _, version = upstream.partition("@")
    if not name:
        return None
    return SourcePackage(name, version or parsed.version, "purl-upstream")


def from_cyclonedx(component: dict[str, Any], parsed: purls.Purl) -> SourcePackage | None:
    """Trivy's CycloneDX properties, where the source version is split into its parts."""
    props = _properties(component)
    name = props.get("SrcName", "").strip()
    if not name:
        return None
    parts = (props.get(f"Src{field}", "").strip() for field in ("Epoch", "Version", "Release"))
    version = _join(*parts)
    return SourcePackage(name, version or parsed.version, "trivy-properties")


def from_spdx(package: dict[str, Any], parsed: purls.Purl) -> SourcePackage | None:
    """Trivy's SPDX ``sourceInfo`` string. Syft writes file provenance there, which this must not match.

    ``sourceInfo`` is free text and may hold both, one per line, since a repair keeps the provenance it found.
    """
    for line in str(package.get("sourceInfo") or "").splitlines():
        match = _SPDX_SOURCE.match(line.strip())
        if match:
            return SourcePackage(match.group("name"), match.group("version") or parsed.version, "spdx-source-info")
    return None


def resolve(parsed: purls.Purl, entry: dict[str, Any] | None = None, *, spdx: bool = False) -> SourcePackage | None:
    """The source package of an OS component, from whichever carrier holds it. None for non-OS types.

    Carriers are tried in order of specificity: an explicit version beats an implied one. The fallback is the
    binary package itself, marked ``binary-package`` so a report can tell stated identity from assumed.
    """
    if parsed.type not in OS_TYPES:
        return None
    entry = entry or {}
    candidates = [from_purl(parsed)]
    candidates.append(from_spdx(entry, parsed) if spdx else from_cyclonedx(entry, parsed))
    for candidate in candidates:
        if candidate:
            return candidate
    return SourcePackage(parsed.name, parsed.version, "binary-package")


def attach_cyclonedx(component: dict[str, Any], source: SourcePackage) -> bool:
    """Write the source package into both CycloneDX carriers. Returns whether anything changed.

    ``SrcVersion`` is written whole. Trivy also writes the version split across ``SrcVersion``,
    ``SrcRelease`` and ``SrcEpoch`` and rejoins them when reading, so the whole group is replaced together:
    leaving a stale ``SrcRelease`` beside a complete ``SrcVersion`` yields nonsense such as ``2.36-9-9``,
    which matches nothing.
    """
    wanted = [
        {"name": f"{TRIVY_PREFIX}SrcName", "value": source.name},
        {"name": f"{TRIVY_PREFIX}SrcVersion", "value": source.version},
    ]
    group = {f"{TRIVY_PREFIX}Src{field}" for field in ("Name", "Version", "Release", "Epoch")}
    kept = [p for p in component.get("properties") or [] if str(p.get("name", "")) not in group]
    existing = [p for p in component.get("properties") or [] if str(p.get("name", "")) in group]
    changed = existing != wanted
    if changed:
        component["properties"] = kept + wanted
    raw = component.get("purl")
    if isinstance(raw, str) and raw:
        upstream = source.name if source.version == _version_of(raw) else f"{source.name}@{source.version}"
        updated = purls.with_qualifier(raw, "upstream", upstream)
        if updated != raw:
            component["purl"] = updated
            if component.get("bom-ref") == raw:  # keep the reference pointing at this component
                component["bom-ref"] = updated
            changed = True
    return changed


def attach_spdx(package: dict[str, Any], source: SourcePackage) -> bool:
    """Write the source package into SPDX ``sourceInfo``, in the form Trivy reads.

    Syft uses the same field for file provenance, which is the only record of where the package was found, so
    any line that is not a source-package statement is kept. The statement is rebuilt rather than prepended,
    so repairing an already repaired document changes nothing.
    """
    wanted = f"{SPDX_SOURCE_PREFIX}{source.name} {source.version}".rstrip()
    existing = str(package.get("sourceInfo") or "")
    kept = [line for line in existing.splitlines() if line.strip() and not _SPDX_SOURCE.match(line.strip())]
    updated = "\n".join([wanted, *kept])
    if updated == existing:
        return False
    package["sourceInfo"] = updated
    return True


def _version_of(raw_purl: str) -> str:
    parsed = purls.parse(raw_purl)
    return parsed.version if parsed else ""
