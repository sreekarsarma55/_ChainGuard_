"""Read CycloneDX and SPDX SBOMs (JSON) into ChainGuard's canonical component inventory.

Only entries that describe installed software become components (design rule D9). Generators also list
things that are not software, give them package URLs, and so make them indistinguishable from components
downstream: cdxgen emits one ``type: "file"`` entry per file it walks (none of
them an installed package) and the APT repositories it found as ``type: "data"``. Such entries are left out
of the inventory and counted by reason, so a report can say how many there were, and their keys are kept so
that a finding a scanner reports against one of them can be recognised as being about no software at all.

A rule that was planned and rejected on evidence: dropping entries whose identity evidence has confidence 0.
cdxgen gives that confidence to 38 packages that the images' own package databases list as installed
(util-linux, openssl, busybox, musl, openjdk8 among them), so it is not a signal of non-software.
"""

from __future__ import annotations

import json
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chainguard import ospackage
from chainguard import purl as purls

# Entry kinds that describe something other than installed software, mapped to the reason recorded for them.
# CycloneDX `type`s; SPDX packages carry the equivalent in `primaryPackagePurpose`. Other kinds are kept:
# no generator in the toolchain emits them, and keeping an entry is the conservative default.
NOT_SOFTWARE_CYCLONEDX = {"file": "file", "data": "data", "cryptographic-asset": "cryptographic-asset"}
NOT_SOFTWARE_SPDX = {"FILE": "file"}


def not_software(entry: dict[str, Any] | None, *, spdx: bool) -> str | None:
    """Why an SBOM entry is not an installed software component, or None if it is one."""
    if not entry:
        return None
    if spdx:
        return NOT_SOFTWARE_SPDX.get(str(entry.get("primaryPackagePurpose") or ""))
    return NOT_SOFTWARE_CYCLONEDX.get(str(entry.get("type") or ""))


def spdx_purl(package: dict[str, Any]) -> str | None:
    """The PURL of an SPDX package, which keeps it among its external references."""
    for ref in package.get("externalRefs") or []:
        if isinstance(ref, dict) and ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


class SbomError(ValueError):
    """The file is not an SBOM ChainGuard can read."""


@dataclass
class ParsedSbom:
    """What one generator reported, keyed on canonical component identity."""

    format: str  # "CycloneDX" | "SPDX"
    spec_version: str
    entries: int = 0  # component / package entries in the document
    no_purl: int = 0  # entries without any PURL
    invalid_purl: int = 0  # entries whose PURL could not be parsed
    components: dict[str, purls.Purl] = field(default_factory=dict)  # canonical key -> parsed PURL
    raw_purls: dict[str, set[str]] = field(default_factory=dict)  # canonical key -> PURLs as emitted
    operating_systems: list[dict[str, str]] = field(default_factory=list)
    sources: dict[str, ospackage.SourcePackage] = field(default_factory=dict)  # OS components -> source package
    cpes: dict[str, set[str]] = field(default_factory=dict)  # canonical key -> CPEs the generator stated
    filter_kinds: bool = True  # leave entries that are not software out of the components (D9)
    not_software: Counter[str] = field(default_factory=Counter)  # reason -> entries left out (with a PURL)
    not_software_keys: dict[str, str] = field(default_factory=dict)  # canonical key -> reason
    # Every entry with a valid PURL, kind filter or not: its key as written (before D4) -> its canonical key.
    # This is what the document lists before any of ChainGuard's identity rules (chainguard.metrics).
    reported: dict[str, str] = field(default_factory=dict)
    archives: dict[str, set[str]] = field(default_factory=dict)  # Maven key -> the jar files it was found in (D11)
    group_evidence: dict[str, str] = field(default_factory=dict)  # Maven key -> what its group rests on (D11)
    # The dependency graph: each component's shortest distance from the document's subject along the
    # dependencies the generator recorded, 1 for a direct dependency. Only a graph that starts at the subject gives
    # depths, so ``graph`` says which kind the document has: "rooted", "unrooted" (dependencies between packages,
    # none from the subject, as Syft writes them) or "none".
    depths: dict[str, int] = field(default_factory=dict)
    graph: str = "none"

    def non_component_keys(self) -> dict[str, str]:
        """Keys this SBOM gave only to entries that are not software. A key also used by a real component
        (in this document) is a component, so it is not listed."""
        return {k: r for k, r in self.not_software_keys.items() if k not in self.components}

    def source_stats(self) -> dict[str, Any]:
        """How many OS components state a source package, and in which carrier (design rule D2)."""
        stated = [s for s in self.sources.values() if not s.implicit]
        return {
            "os_components": len(self.sources),
            "source_stated": len(stated),
            "source_differs_from_binary": sum(
                1 for k, s in self.sources.items() if not s.implicit and s.name != self.components[k].name
            ),
            "by_evidence": dict(sorted(Counter(s.evidence for s in self.sources.values()).items())),
        }

    @property
    def duplicate_entries(self) -> int:
        """Entries that collapsed onto an already-seen canonical key."""
        left_out = sum(self.not_software.values())
        return self.entries - self.no_purl - self.invalid_purl - left_out - len(self.components)

    def by_type(self) -> dict[str, int]:
        return dict(sorted(Counter(p.type for p in self.components.values()).items()))

    def stats(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "spec_version": self.spec_version,
            "entries": self.entries,
            "no_purl": self.no_purl,
            "invalid_purl": self.invalid_purl,
            "duplicate_entries": self.duplicate_entries,
            "unique_components": len(self.components),
            "by_type": self.by_type(),
            "operating_systems": self.operating_systems,
            "source_packages": self.source_stats(),
            "kind_filter": self.filter_kinds,
            "not_software": dict(sorted(self.not_software.items())),
            "dependency_graph": self.graph,
            "depth_known": len(self.depths),
        }

    def _set_depths(self, edges: dict[str, set[str]], roots: set[str], keys: dict[str, str]) -> None:
        """Depths from the document's own graph: ``edges`` from an element to those it depends on, ``roots`` the
        elements that are the document's subject, ``keys`` element -> canonical key of a software component."""
        if not any(edges.values()):
            return
        if not any(edges.get(root) for root in roots):
            self.graph = "unrooted"
            return
        self.graph = "rooted"
        distance = dict.fromkeys(roots, 0)
        queue = deque(roots)
        while queue:
            node = queue.popleft()
            for target in sorted(edges.get(node, ())):
                if target not in distance:
                    distance[target] = distance[node] + 1
                    queue.append(target)
        for element, d in distance.items():
            key = keys.get(element)
            if key in self.components and d > 0:
                self.depths[key] = min(d, self.depths.get(key, d))

    def _add_cpes(self, key: str, entry: dict[str, Any], spdx: bool) -> None:
        """Keep the CPEs a generator stated. A scanner falls back to them where its ecosystem feed has no
        data, so dropping them loses real findings: on an end-of-life Alpine base, Grype matches most OS
        packages by CPE against NVD, not through the Alpine database."""
        found = set()
        if spdx:
            found = {
                str(ref.get("referenceLocator"))
                for ref in entry.get("externalRefs") or []
                if isinstance(ref, dict) and ref.get("referenceType") == "cpe23Type" and ref.get("referenceLocator")
            }
        else:
            if isinstance(entry.get("cpe"), str) and entry["cpe"]:
                found.add(entry["cpe"])
            # CycloneDX allows one `cpe` per component, so a generator's alternate CPEs travel in properties
            # (Syft uses `syft:cpe23`), and scanners read them from there. They are not decoration: NVD
            # indexes CVE-2021-46848 under `gnu:libtasn1`, which is an alternate, not the primary CPE.
            found |= {
                str(p.get("value"))
                for p in entry.get("properties") or []
                if isinstance(p, dict) and str(p.get("name", "")).endswith("cpe23") and p.get("value")
            }
        if found:
            self.cpes.setdefault(key, set()).update(found)

    def _add(self, raw: str | None, entry: dict[str, Any] | None = None, *, spdx: bool = False) -> None:
        self.entries += 1
        if not raw:
            self.no_purl += 1
            return
        parsed = purls.parse(raw)
        if parsed is None:
            self.invalid_purl += 1
            return
        self.reported.setdefault(parsed.reported_key, parsed.key)
        reason = not_software(entry, spdx=spdx) if self.filter_kinds else None
        if reason:
            self.not_software[reason] += 1
            self.not_software_keys.setdefault(parsed.key, reason)
            return
        self.components.setdefault(parsed.key, parsed)
        self.raw_purls.setdefault(parsed.key, set()).add(raw)
        source = ospackage.resolve(parsed, entry, spdx=spdx)
        if source and (parsed.key not in self.sources or self.sources[parsed.key].implicit):
            self.sources[parsed.key] = source  # a stated source beats the binary-package fallback
        if entry:
            self._add_cpes(parsed.key, entry, spdx)
            if parsed.type == "maven":
                self._add_maven_evidence(parsed, entry, spdx)

    def _add_maven_evidence(self, parsed: purls.Purl, entry: dict[str, Any], spdx: bool) -> None:
        """Which jar a Maven component was found in, and what its group rests on (design rule D11).

        Two generators can give one jar different groups, so the jar file is what says they mean one component.
        Syft states its locations in ``syft:metadata:virtualPath`` (the nested path, inside a Spring Boot jar) and
        ``syft:location:0:path``, or in SPDX ``sourceInfo``; cdxgen in ``SrcFile`` and its identity evidence. The
        group's evidence: ``maven-central-sha1`` when the generator looked the jar's SHA-1 up in Maven Central
        (cdxgen's ``hash-comparison``); ``none`` when the group is the artifact ID, which is what Syft writes when
        it finds no group (a real group can look the same, such as ``junit:junit``); otherwise ``stated``. Neither
        generator says when a group came from the jar's own pom.properties.
        """
        values: list[str] = []
        techniques: set[str] = set()
        if spdx:
            values.append(str(entry.get("sourceInfo") or ""))
        else:
            props = {
                str(p.get("name")): str(p.get("value") or "")
                for p in entry.get("properties") or []
                if isinstance(p, dict) and p.get("name")
            }
            values.append(props.get("syft:metadata:virtualPath") or props.get("syft:location:0:path") or "")
            values.append(props.get("SrcFile", ""))
            evidence = entry.get("evidence") or {}
            values += [str(o.get("location") or "") for o in evidence.get("occurrences") or [] if isinstance(o, dict)]
            for identity in evidence.get("identity") or []:
                if not isinstance(identity, dict):
                    continue
                for method in identity.get("methods") or []:
                    if isinstance(method, dict):
                        techniques.add(str(method.get("technique") or ""))
                        values.append(str(method.get("value") or ""))
        jars = {jar for jar in (archive_name(v) for value in values for v in value.split()) if jar}
        if jars:
            self.archives.setdefault(parsed.key, set()).update(jars)
        if "hash-comparison" in techniques:
            kind = "maven-central-sha1"
        elif parsed.namespace == parsed.name or not parsed.namespace:
            kind = "none"
        else:
            kind = "stated"
        if GROUP_EVIDENCE_RANK[kind] >= GROUP_EVIDENCE_RANK.get(self.group_evidence.get(parsed.key, "none"), 0):
            self.group_evidence[parsed.key] = kind


# What a Maven group rests on, strongest first (design rule D11)
GROUP_EVIDENCE_RANK = {"maven-central-sha1": 2, "stated": 1, "none": 0}
ARCHIVES = (".jar", ".war", ".ear")


def archive_name(value: str) -> str | None:
    """The file name of the innermost archive a location names (``a.jar:BOOT-INF/lib/b.jar`` -> ``b.jar``)."""
    tail = value.strip().strip(",;").replace("!", "/").replace(":", "/").replace("\\", "/").rstrip("/")
    name = tail.rsplit("/", 1)[-1]
    return name if name.lower().endswith(ARCHIVES) else None


def load(path: str | Path, *, filter_kinds: bool = True) -> ParsedSbom:
    path = Path(path)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SbomError(f"{path}: not readable as JSON ({exc})") from exc
    return parse(doc, source=str(path), filter_kinds=filter_kinds)


def parse(doc: Any, source: str = "<sbom>", *, filter_kinds: bool = True) -> ParsedSbom:
    """Parse an SBOM document. ``filter_kinds=False`` keeps entries that are not software, as before D9."""
    if not isinstance(doc, dict):
        raise SbomError(f"{source}: expected a JSON object")
    if doc.get("bomFormat") == "CycloneDX":
        return _parse_cyclonedx(doc, filter_kinds)
    if str(doc.get("spdxVersion", "")).startswith("SPDX-2"):
        return _parse_spdx2(doc, filter_kinds)
    if "@context" in doc and "spdx" in json.dumps(doc.get("@context")).lower():
        raise SbomError(f"{source}: SPDX 3.0 (JSON-LD) is not supported yet; use SPDX 2.3 JSON or CycloneDX JSON")
    raise SbomError(f"{source}: neither CycloneDX JSON nor SPDX 2.x JSON")


def _walk(nodes: Any):
    for node in nodes or []:
        if isinstance(node, dict):
            yield node
            yield from _walk(node.get("components"))


def _parse_cyclonedx(doc: dict, filter_kinds: bool = True) -> ParsedSbom:
    sbom = ParsedSbom(format="CycloneDX", spec_version=str(doc.get("specVersion", "")), filter_kinds=filter_kinds)
    keys: dict[str, str] = {}  # bom-ref -> canonical key
    for component in _walk(doc.get("components")):
        sbom._add(component.get("purl"), component)
        if component.get("type") == "operating-system":
            sbom.operating_systems.append({"name": component.get("name", ""), "version": component.get("version", "")})
        parsed = purls.parse(component.get("purl"))
        if parsed and component.get("bom-ref"):
            keys[str(component["bom-ref"])] = parsed.key
    edges: dict[str, set[str]] = {}
    for dependency in doc.get("dependencies") or []:
        if isinstance(dependency, dict) and dependency.get("ref"):
            edges.setdefault(str(dependency["ref"]), set()).update(str(d) for d in dependency.get("dependsOn") or [])
    root = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    sbom._set_depths(edges, {str(root)} if root else set(), keys)
    return sbom


def _spdx_roots(doc: dict) -> set[str]:
    """SPDX IDs of the packages the document describes: the scanned artifact, not one of its components.

    CycloneDX keeps this in ``metadata.component``; SPDX lists it as an ordinary package, so it must be
    excluded explicitly or the target itself (e.g. an ``oci`` image PURL) is counted as a component.
    """
    roots = set(doc.get("documentDescribes") or [])
    for rel in doc.get("relationships") or []:
        kind = rel.get("relationshipType")
        if kind == "DESCRIBES" and rel.get("spdxElementId") == doc.get("SPDXID", "SPDXRef-DOCUMENT"):
            roots.add(rel.get("relatedSpdxElement"))
        elif kind == "DESCRIBED_BY":
            roots.add(rel.get("spdxElementId"))
    return roots


def _spdx_dependencies(doc: dict) -> dict[str, set[str]]:
    """SPDX element -> the elements it depends on. ``A DEPENDS_ON B`` and ``B DEPENDENCY_OF A`` (and its build,
    dev, test, runtime, optional and provided forms) say the same thing. ``CONTAINS`` says nothing about
    dependencies (Syft links the document's subject to every package with it), and ``DEPENDENCY_MANIFEST_OF``
    names a manifest file, so neither is an edge."""
    edges: dict[str, set[str]] = {}
    for rel in doc.get("relationships") or []:
        kind, a, b = rel.get("relationshipType", ""), rel.get("spdxElementId"), rel.get("relatedSpdxElement")
        if not a or not b:
            continue
        if kind == "DEPENDS_ON":
            edges.setdefault(a, set()).add(b)
        elif kind.endswith("DEPENDENCY_OF"):  # not DEPENDENCY_MANIFEST_OF, which ends otherwise
            edges.setdefault(b, set()).add(a)
    return edges


def _parse_spdx2(doc: dict, filter_kinds: bool = True) -> ParsedSbom:
    spec = str(doc.get("spdxVersion", "")).removeprefix("SPDX-")
    sbom = ParsedSbom(format="SPDX", spec_version=spec, filter_kinds=filter_kinds)
    roots = _spdx_roots(doc)
    keys: dict[str, str] = {}  # SPDXID -> canonical key
    for package in doc.get("packages") or []:
        if package.get("SPDXID") in roots:
            continue
        sbom._add(spdx_purl(package), package, spdx=True)
        if package.get("primaryPackagePurpose") == "OPERATING-SYSTEM":
            sbom.operating_systems.append({"name": package.get("name", ""), "version": package.get("versionInfo", "")})
        parsed = purls.parse(spdx_purl(package))
        if parsed and package.get("SPDXID"):
            keys[str(package["SPDXID"])] = parsed.key
    sbom._set_depths(_spdx_dependencies(doc), {r for r in roots if r}, keys)
    return sbom
