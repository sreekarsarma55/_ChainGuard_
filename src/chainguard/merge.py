"""Write the canonical inventory back out as one SBOM a scanner can read (design rules D3 and D7).

Running several generators leaves several partial, mutually unreadable SBOMs. This module writes their
merged inventory as a single document, in CycloneDX and in SPDX, carrying everything a scanner needs:

* an operating-system component, in both formats, because without it Trivy cannot choose a vulnerability
  source and reports nothing for OS packages at all;
* the source package of every OS component, in every field each scanner reads (``chainguard.ospackage``),
  because advisories are keyed on it;
* the ``distro`` and ``arch`` qualifiers the generators recorded, since a scanner needs them to match;
* which generators found each component, as a property, so a finding stays traceable to its source.

Two things are left out on purpose. The CycloneDX ``group`` field is never set on OS packages: Trivy
prepends it to the package name, turning ``libtasn1-6`` into ``debian/libtasn1-6``, which matches nothing.
And no dependency graph is emitted, because the generators do not agree on one; depth comes in Phase 3 from
a single generator's graph.

The merged document describes what the tools found, so it is not a provenance claim about the build. Its
metadata names ChainGuard as the tool and lists the generators whose output it merges.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from chainguard import __version__, ospackage
from chainguard.correlate import InventoryEntry

CYCLONEDX_VERSION = "1.6"
SPDX_VERSION = "SPDX-2.3"
FOUND_BY = "chainguard:found-by"
# The property both Syft and Grype use for CPEs beyond the one `cpe` field CycloneDX allows. Writing our own
# name here would be tidier and would lose matches, so the interoperable name wins.
ALTERNATE_CPE = "syft:cpe23"
_UNSAFE_SPDX = re.compile(r"[^0-9a-zA-Z.-]+")
# What a PURL namespace means depends on the type, so a component's name cannot be built from it blindly.
# For these the namespace is part of the package's real name (``@scope/pkg``, ``github.com/owner/repo``).
_PATH_LIKE = frozenset({"npm", "golang", "composer", "swift", "github", "gitlab", "bitbucket"})
# For these it is a separate coordinate, which CycloneDX keeps in ``group``.
_GROUPED = frozenset({"maven"})
# For OS types it names the distribution, not the package. Folding it into the name gives
# ``debian/coreutils``, which matches no advisory, and that is a bug we reported in a scanner.


def component_name(entry: InventoryEntry) -> tuple[str, str | None]:
    """The component's ``name`` and CycloneDX ``group``, per the meaning of its PURL namespace."""
    if not entry.namespace:
        return entry.name, None
    if entry.type in _PATH_LIKE:
        return f"{entry.namespace}/{entry.name}", None
    if entry.type in _GROUPED:
        return entry.name, entry.namespace
    return entry.name, None


def _purl(entry: InventoryEntry) -> str:
    """The component's canonical PURL, with the qualifiers a scanner needs and the source package."""
    from packageurl import PackageURL

    qualifiers = dict(entry.qualifiers)
    if entry.source and not entry.source.implicit:
        upstream = entry.source.name
        if entry.source.version != entry.version:
            upstream = f"{entry.source.name}@{entry.source.version}"
        qualifiers["upstream"] = upstream
    return PackageURL(
        type=entry.type,
        namespace=entry.namespace or None,
        name=entry.name,
        version=entry.version or None,
        qualifiers=qualifiers,
    ).to_string()


def _spdx_id(key: str) -> str:
    """A unique, valid SPDXID. Keys contain characters SPDX forbids, so a short digest keeps them distinct."""
    digest = hashlib.sha256(key.encode()).hexdigest()[:12]
    return f"SPDXRef-{_UNSAFE_SPDX.sub('-', key).strip('-')[:60]}-{digest}"


def _primary_cpe(entry: InventoryEntry) -> str | None:
    """The CPE to put in the single field each format offers: prefer one whose product is the package name."""
    if not entry.cpes:
        return None
    ordered = sorted(entry.cpes)
    name = entry.name.lower()
    return next((c for c in ordered if c.lower().split(":")[4:5] == [name]), ordered[0])


def _os_names(operating_systems: list[dict[str, str]]) -> dict[str, str] | None:
    for entry in operating_systems:
        if entry.get("name"):
            return {"name": entry["name"], "version": entry.get("version") or ""}
    return None


def cyclonedx(
    inventory: dict[str, InventoryEntry],
    operating_systems: list[dict[str, str]],
    *,
    target: str = "",
    generators: list[str] | None = None,
    serial: str | None = None,
) -> dict[str, Any]:
    """The merged inventory as a CycloneDX 1.6 document."""
    components: list[dict[str, Any]] = []
    operating_system = _os_names(operating_systems)
    if operating_system:
        components.append(
            {"type": "operating-system", "name": operating_system["name"], "version": operating_system["version"]}
        )
    for entry in inventory.values():
        raw = _purl(entry)
        name, group = component_name(entry)
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": raw,
            "name": name,
            "version": entry.version,
            "purl": raw,
            "properties": [{"name": FOUND_BY, "value": ",".join(sorted(entry.found_by))}],
        }
        if group:
            component["group"] = group
        cpe = _primary_cpe(entry)
        if cpe:
            # CycloneDX holds a single `cpe`, so the alternates go in the property name scanners read. They
            # carry real matches: dropping them loses findings, because NVD indexes some
            # CVEs under a vendor the primary CPE does not name.
            component["cpe"] = cpe
            component["properties"] += [{"name": ALTERNATE_CPE, "value": c} for c in sorted(entry.cpes - {cpe})]
        if entry.source:
            ospackage.attach_cyclonedx(component, entry.source)
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "serialNumber": serial or f"urn:uuid:{_uuid(inventory, target)}",
        "version": 1,
        "metadata": _metadata(target, generators),
        "components": components,
    }


def spdx(
    inventory: dict[str, InventoryEntry],
    operating_systems: list[dict[str, str]],
    *,
    target: str = "",
    generators: list[str] | None = None,
) -> dict[str, Any]:
    """The merged inventory as an SPDX 2.3 document, with the operating system as a package (D7)."""
    root = "SPDXRef-DOCUMENT"
    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    operating_system = _os_names(operating_systems)
    if operating_system:
        packages.append(
            {
                "SPDXID": "SPDXRef-OperatingSystem",
                "name": operating_system["name"],
                "versionInfo": operating_system["version"],
                "primaryPackagePurpose": "OPERATING-SYSTEM",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
            }
        )
        relationships.append(
            {"spdxElementId": root, "relatedSpdxElement": "SPDXRef-OperatingSystem", "relationshipType": "DESCRIBES"}
        )
    for key, entry in inventory.items():
        identifier = _spdx_id(key)
        name, group = component_name(entry)
        package: dict[str, Any] = {
            "SPDXID": identifier,
            "name": f"{group}:{name}" if group else name,  # SPDX has no group field; Maven coordinates join
            "versionInfo": entry.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": _purl(entry),
                },
                *(
                    {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": cpe}
                    for cpe in sorted(entry.cpes)
                ),
            ],
            "annotations": [
                {
                    "annotationType": "OTHER",
                    "annotator": f"Tool: chainguard-{__version__}",
                    "annotationDate": _now(),
                    "comment": f"{FOUND_BY}={','.join(sorted(entry.found_by))}",
                }
            ],
        }
        if entry.source:
            ospackage.attach_spdx(package, entry.source)
        packages.append(package)
        relationships.append({"spdxElementId": root, "relatedSpdxElement": identifier, "relationshipType": "DESCRIBES"})
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": root,
        "name": f"chainguard-merged-{target or 'target'}",
        "documentNamespace": f"https://github.com/sreekarsarma55/_ChainGuard_/spdx/{_uuid(inventory, target)}",
        "creationInfo": {
            "created": _now(),
            "creators": [f"Tool: chainguard-{__version__}", *(f"Tool: {g}" for g in sorted(generators or []))],
        },
        "packages": packages,
        "relationships": relationships,
    }


def _metadata(target: str, generators: list[str] | None) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "timestamp": _now(),
        "tools": {
            "components": [
                {"type": "application", "name": "chainguard", "version": __version__},
                *({"type": "application", "name": g} for g in sorted(generators or [])),
            ]
        },
    }
    if target:
        metadata["component"] = {"type": "container", "name": target, "bom-ref": f"chainguard:target:{target}"}
    return metadata


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _uuid(inventory: dict[str, InventoryEntry], target: str) -> str:
    """A stable identifier: the same inventory for the same target always gets the same one."""
    digest = hashlib.sha256((target + "\n" + "\n".join(sorted(inventory))).encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def merge_documents(documents: list[dict[str, Any]], *, target: str = "") -> tuple[dict[str, Any], dict[str, Any]]:
    """Merge already-parsed SBOM documents into (CycloneDX, SPDX). Used by ``chainguard sbom merge``."""
    from chainguard import correlate, sbom

    parsed = {}
    for index, document in enumerate(documents):
        parsed[f"sbom{index + 1}"] = sbom.parse(document)
    inventory, _ = correlate.canonical_inventory(parsed)  # what is not installed software is left out (D9)
    operating_systems = [os_ for p in parsed.values() for os_ in p.operating_systems]
    generators = sorted(parsed)
    return (
        cyclonedx(inventory, operating_systems, target=target, generators=generators),
        spdx(inventory, operating_systems, target=target, generators=generators),
    )


def stats(inventory: dict[str, InventoryEntry], operating_systems: list[dict[str, str]]) -> dict[str, Any]:
    """What went into the merged SBOM, for the run manifest."""
    with_source = [e for e in inventory.values() if e.source and not e.source.implicit]
    return {
        "components": len(inventory),
        "operating_system": _os_names(operating_systems),
        "os_components_with_source": len(with_source),
        "components_with_cpe": sum(1 for e in inventory.values() if e.cpes),
        "found_by_several_generators": sum(1 for e in inventory.values() if len(e.found_by) > 1),
        "purl_qualifiers_carried": sorted({q for e in inventory.values() for q in e.qualifiers}),
    }
