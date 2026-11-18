"""Merge what the tools reported: component inventory across generators, findings across pipelines.

Design rule D1: vulnerability aliases are resolved to canonical IDs *before* any merge or count. That is
done by ``chainguard.aliases`` (OSV.dev plus scanner metadata); this module only consumes the result,
crediting a finding to each of its canonical IDs.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from chainguard import ospackage, versions
from chainguard import purl as purls
from chainguard.sbom import GROUP_EVIDENCE_RANK, ParsedSbom
from chainguard.scanners import Finding

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN")


def pipeline_class(pipeline: str) -> str:
    """Which configuration a pipeline belongs to: one generator and one scanner, the merged SBOM, or neither.

    The three must never be mixed in a statistic. The union of the ``single`` pipelines is the naive-union
    baseline that fusion is measured against, and ``direct`` is a reference, not a pipeline under test.
    """
    head = pipeline.split("+", 1)[0]
    if head == "direct":
        return "direct"
    return "fused" if head.startswith("fused") else "single"


# --------------------------------------------------------------------------- components


@dataclass
class InventoryEntry:
    key: str
    type: str
    namespace: str
    name: str
    version: str
    found_by: set[str] = field(default_factory=set)
    purls: dict[str, set[str]] = field(default_factory=dict)  # generator -> PURLs as emitted
    source: ospackage.SourcePackage | None = None  # OS packages: the source package advisories are keyed on
    qualifiers: dict[str, str] = field(default_factory=dict)  # merged PURL qualifiers, e.g. arch and distro
    cpes: set[str] = field(default_factory=set)  # CPEs any generator stated; scanners fall back to them
    reported_versions: set[str] = field(default_factory=set)  # every spelling a tool used for this version (D4)
    group_evidence: dict[str, str] = field(default_factory=dict)  # Maven: generator -> what its group rests on
    merged_keys: dict[str, set[str]] = field(default_factory=dict)  # D11: a key merged into this one -> who used it
    undecided_with: set[str] = field(default_factory=set)  # D11: keys for the same jar the evidence cannot rank
    depths: dict[str, int] = field(default_factory=dict)  # generator -> distance from the target in its graph

    @property
    def depth(self) -> int | None:
        """The shortest distance from the target in any generator's dependency graph: 1 is a direct dependency.
        None where no graph that starts at the target reaches the component."""
        return min(self.depths.values(), default=None)

    def as_dict(self) -> dict[str, Any]:
        entry = {
            "key": self.key,
            "type": self.type,
            "namespace": self.namespace,
            "name": self.name,
            "version": self.version,
            "found_by": sorted(self.found_by),
            "purls": {g: sorted(p) for g, p in sorted(self.purls.items())},
        }
        if self.source:
            entry["source_name"] = self.source.name
            entry["source_version"] = self.source.version
            entry["source_evidence"] = self.source.evidence
        if len(self.reported_versions) > 1:  # one version, several spellings, merged by D4
            entry["versions_reported"] = sorted(self.reported_versions)
        if self.group_evidence:
            entry["group_evidence"] = dict(sorted(self.group_evidence.items()))
        if self.merged_keys:  # one jar under several Maven groups, merged by D11
            entry["merged_keys"] = {k: sorted(g) for k, g in sorted(self.merged_keys.items())}
        if self.undecided_with:
            entry["group_undecided_with"] = sorted(self.undecided_with)
        if self.depths:
            entry["depth"] = self.depth
            entry["depth_by_generator"] = dict(sorted(self.depths.items()))
        return entry


def coordinate_variants(sboms: dict[str, ParsedSbom]) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Maven keys that generators gave one jar, mapped to the key with the best-evidenced group (design rule D11),
    and the cases the evidence leaves undecided.

    Generators do not always agree on a jar's Maven group. Syft writes the artifact ID as the group when it finds
    none (``maven/thymeleaf/thymeleaf``) and otherwise guesses one from the jar (``org.objectweb.asm`` for ASM,
    which Maven Central publishes as ``org.ow2.asm``), while cdxgen looks most such jars up in Maven Central by
    SHA-1. Keyed on the group, one jar becomes two components, each with half the evidence.

    Keys are one component when generators list the same artifact ID and version, found in a jar of the same
    file name, and no generator lists more than one of them. The key whose group has the strongest evidence
    (``sbom.GROUP_EVIDENCE_RANK``: a SHA-1 lookup in Maven Central, then a stated group, then none) is kept. When
    the strongest evidence is shared by different groups, nothing decides between them, so the keys stay apart.
    """
    claims: dict[tuple[str, str, str], list[tuple[str, str, int]]] = {}
    for generator, parsed in sboms.items():
        for key, purl in parsed.components.items():
            if purl.type != "maven":
                continue
            rank = GROUP_EVIDENCE_RANK.get(parsed.group_evidence.get(key, "none"), 0)
            for jar in parsed.archives.get(key, ()):
                claims.setdefault((purl.name, purl.canonical_version or purl.version, jar), []).append(
                    (generator, key, rank)
                )
    aliases: dict[str, str] = {}
    undecided: list[dict[str, Any]] = []
    conflicted: set[str] = set()
    for (name, version, jar), found in sorted(claims.items()):
        keys = {key for _, key, _ in found}
        if len(keys) < 2:
            continue
        used: dict[str, set[str]] = {}
        for generator, key, _ in found:
            used.setdefault(generator, set()).add(key)
        if any(len(k) > 1 for k in used.values()):
            continue  # one generator lists two of them: to it they are two components
        best = max(rank for *_, rank in found)
        top = sorted({key for _, key, rank in found if rank == best})
        if len(top) > 1:
            undecided.append(
                {
                    "name": name,
                    "version": version,
                    "jar": jar,
                    "keys": sorted(keys),
                    "by": {g: sorted(k) for g, k in used.items()},
                }
            )
            continue
        for key in keys - {top[0]}:
            if aliases.get(key, top[0]) != top[0]:
                conflicted.add(key)  # two jars rank it under different groups: leave it alone
            aliases[key] = top[0]
    for key in conflicted:
        aliases.pop(key, None)
    # A key kept in one case and merged away in another would chain; neither is applied.
    return {k: v for k, v in aliases.items() if v not in aliases}, undecided


def key_aliases(inventory: dict[str, InventoryEntry]) -> dict[str, str]:
    """Every key merged into another component of the inventory (D11), mapped to the key it was merged into."""
    return {merged: entry.key for entry in inventory.values() for merged in entry.merged_keys}


def canonical_inventory(
    sboms: dict[str, ParsedSbom], *, suppress_source_packages: bool = True, maven_coordinates: bool = True
) -> tuple[dict[str, InventoryEntry], dict[str, dict[str, Any]]]:
    """The merged inventory without source packages listed as if installed, and those suppressed (D9).

    cdxgen lists Debian and Alpine *source* packages as components alongside the binary packages built from
    them: ``glibc`` next to ``libc6``, ``linux`` on an image that installs only kernel headers. A scanner
    then reports every advisory of the source package against software that is not there; on
    ``image-pygoat`` that is 1268 Linux kernel CVEs from the one ``linux`` entry.

    No single SBOM lets this be corrected, because cdxgen's entries carry no reliable mark of being a source
    package. Fusion does: a generator that states the source package of each binary (Syft) says which source
    packages exist and that they are attributes, not installed components. So an OS component is suppressed
    when another component's stated source package is exactly it (type, namespace, name, version) and no
    generator that states source packages reports it as installed. On a Debian image cdxgen lists hundreds
    of these, none of which the image's package database lists as installed. With a single generator
    nothing is suppressed.
    """
    inventory = merge_inventory(sboms, maven_coordinates=maven_coordinates)
    if not suppress_source_packages:
        return inventory, {}
    stating = {g for g, parsed in sboms.items() if any(not s.implicit for s in parsed.sources.values())}
    built_from: dict[tuple[str, str, str, str], list[str]] = {}
    for key, entry in inventory.items():
        source = entry.source
        if not source or source.implicit:
            continue
        version = versions.canonical(entry.type, source.version)  # compare versions as the ecosystem does (D4)
        if (source.name, version) != (entry.name, versions.canonical(entry.type, entry.version)):
            built_from.setdefault((entry.type, entry.namespace, source.name, version), []).append(key)
    suppressed: dict[str, dict[str, Any]] = {}
    for key, entry in list(inventory.items()):
        if entry.type not in ospackage.OS_TYPES or entry.found_by & stating:
            continue
        binaries = built_from.get(
            (entry.type, entry.namespace, entry.name, versions.canonical(entry.type, entry.version))
        )
        if binaries:
            suppressed[key] = {
                "reason": "source-package",
                "found_by": sorted(entry.found_by),
                "source_of": sorted(binaries),
                "stated_by": sorted(stating & {g for b in binaries for g in inventory[b].found_by}),
            }
            del inventory[key]
    return inventory, suppressed


def non_components(
    sboms: dict[str, ParsedSbom],
    inventory: dict[str, InventoryEntry],
    suppressed: dict[str, dict[str, Any]],
) -> dict[str, str]:
    """Canonical key -> reason, for every key a generator gave to something that is not installed software.

    A scanner reading a generator's own SBOM can report findings against these, so they are needed to
    recognise such findings. A key that is a component in the merged inventory is never listed.
    """
    keys = {key: info["reason"] for key, info in suppressed.items()}
    for parsed in sboms.values():
        for key, reason in parsed.non_component_keys().items():
            keys.setdefault(key, reason)
    return {k: r for k, r in sorted(keys.items()) if k not in inventory}


def merge_inventory(sboms: dict[str, ParsedSbom], *, maven_coordinates: bool = True) -> dict[str, InventoryEntry]:
    """Union of all generators' components, keyed on canonical identity, with provenance.

    Identity stays keyed on the binary package. For OS packages the source package is carried alongside it
    (design rule D2), taken from whichever generator stated one: a stated source beats the assumption that a
    package is its own source, so one generator recording it is enough for the merged inventory to have it.
    A jar that generators list under different Maven groups is one component, keyed on the best-evidenced group
    (D11, ``coordinate_variants``); ``maven_coordinates=False`` keeps every key apart.
    """
    variants, undecided = coordinate_variants(sboms) if maven_coordinates else ({}, [])
    listed = {key: purl for parsed in sboms.values() for key, purl in parsed.components.items()}
    inventory: dict[str, InventoryEntry] = {}
    for generator, sbom in sboms.items():
        for key, parsed in sbom.components.items():
            canonical = variants.get(key, key)
            kept = listed[canonical]
            entry = inventory.setdefault(
                canonical, InventoryEntry(canonical, kept.type, kept.namespace, kept.name, kept.version)
            )
            entry.found_by.add(generator)
            if canonical != key:
                entry.merged_keys.setdefault(key, set()).add(generator)
            if key in sbom.depths:  # one key per generator: D4 merged spellings at parsing, D11 never merges two
                entry.depths[generator] = sbom.depths[key]  # keys of one generator
            if key in sbom.group_evidence:
                entry.group_evidence[generator] = sbom.group_evidence[key]
            entry.purls.setdefault(generator, set()).update(sbom.raw_purls.get(key, ()))
            for qualifier, value in (parsed.qualifiers or {}).items():
                entry.qualifiers.setdefault(qualifier, value)  # a scanner needs distro and arch to match
            entry.cpes.update(sbom.cpes.get(key, ()))
            for raw in sbom.raw_purls.get(key, ()):
                reported = purls.parse(raw)
                if reported:
                    entry.reported_versions.add(reported.version)
            source = sbom.sources.get(key)
            if source and (entry.source is None or (entry.source.implicit and not source.implicit)):
                entry.source = source
    for case in undecided:
        for key in case["keys"]:
            if key in inventory:
                inventory[key].undecided_with.update(k for k in case["keys"] if k != key)
    return dict(sorted(inventory.items()))


# --------------------------------------------------------------------------- vulnerabilities


def alias_map(findings: Iterable[Finding]) -> dict[str, str]:
    """First-CVE rule, kept for comparison: non-CVE ID -> the first CVE scanners relate it to.

    Superseded by ``chainguard.aliases.resolve``, which asks OSV and keeps every CVE an advisory covers.
    """
    aliases: dict[str, str] = {}
    for finding in findings:
        group = (finding.raw_id, *finding.related)
        cves = sorted(i for i in group if i.startswith("CVE-"))
        if cves:
            for other in group:
                if not other.startswith("CVE-"):
                    aliases.setdefault(other, cves[0])
    return dict(sorted(aliases.items()))


def resolve_aliases(findings: list[Finding], aliases: dict[str, str]) -> None:
    """v0 rule (see ``alias_map``): one canonical ID per finding."""
    for finding in findings:
        finding.vulnerability = (
            finding.raw_id if finding.raw_id.startswith("CVE-") else aliases.get(finding.raw_id, finding.raw_id)
        )
        finding.vulnerabilities = (finding.vulnerability,)


FIX_PRECEDENCE = ("fixed", "not_fixed", "wont_fix", "unknown")  # a claim that a fix exists is the actionable one


def _highest(severities: Iterable[str]) -> str:
    return min(severities, key=SEVERITY_ORDER.index, default="UNKNOWN")


@dataclass
class ScannerClaim:
    """What one scanner said about one (component, vulnerability) pair, through every pipeline that fed it.

    Every pipeline of a scanner reports the same advisories for a pair, with the same severity, CVSS and fix
    data, so one claim per scanner loses nothing. A claim can still hold several values:
    a scanner may report two advisories that alias resolution (D1) merged into one CVE, such as a HIGH and a
    LOW advisory for npm-user-validate's CVE-2020-7754. The claim then keeps the highest severity and CVSS, every
    fix version and the most actionable fix state, and lists what it merged; findings.json keeps each finding.
    """

    pipelines: set[str] = field(default_factory=set)
    ids: set[str] = field(default_factory=set)  # as the scanner reported them, before alias resolution
    severities: set[str] = field(default_factory=set)
    cvss_v3: float | None = None
    fix_states: set[str] = field(default_factory=set)
    fix_versions: set[str] = field(default_factory=set)
    # The scanner's own EPSS and KEV data (Grype ships them). For cross-checking only: the values that count come
    # from the dated snapshots (chainguard.enrich).
    epss: float | None = None
    epss_date: str | None = None
    kev: bool | None = None

    def add(self, f: Finding) -> None:
        self.pipelines.add(f.pipeline)
        self.ids.add(f.raw_id)
        self.severities.add(f.severity)
        self.fix_states.add(f.fix_state)
        self.fix_versions.update(f.fix_versions)
        if f.cvss_v3 is not None:
            self.cvss_v3 = max(self.cvss_v3 or 0.0, f.cvss_v3)
        if f.epss is not None and (self.epss is None or f.epss > self.epss):
            self.epss, self.epss_date = f.epss, f.epss_date
        if f.kev is not None:
            self.kev = bool(self.kev) or f.kev

    @property
    def severity(self) -> str:
        return _highest(self.severities)

    @property
    def fix_state(self) -> str:
        return min(self.fix_states, key=FIX_PRECEDENCE.index, default="unknown")

    def as_dict(self) -> dict[str, Any]:
        claim = {
            "pipelines": sorted(self.pipelines),
            "ids": sorted(self.ids),
            "severity": self.severity,
            "cvss_v3": self.cvss_v3,
            "fix_state": self.fix_state,
            "fix_versions": sorted(self.fix_versions),
            "epss": self.epss,
            "kev": self.kev,
        }
        if self.epss_date:
            claim["epss_date"] = self.epss_date
        # Several advisories (or pipelines) gave different values: say so, rather than let the merged one pass
        # for unanimous.
        if len(self.severities) > 1:
            claim["severities_reported"] = sorted(self.severities, key=SEVERITY_ORDER.index)
        if len(self.fix_states) > 1:
            claim["fix_states_reported"] = sorted(self.fix_states, key=FIX_PRECEDENCE.index)
        return claim


@dataclass
class CorrelatedFinding:
    """Every claim about one (canonical component, canonical vulnerability) pair, with the evidence behind it.

    ``consensus`` counts independent evidence, not pipelines (design rule D10): the generators that list the
    component as installed software, times the scanners that report the vulnerability on it through any SBOM
    pipeline. Counting the pipelines that reported a pair measures their hand-offs as much as the evidence: one
    pipeline's gap makes a well-supported finding look weak. That count is kept as ``pipelines_reporting``,
    for comparisons before and after normalisation.
    """

    vulnerability: str
    component: str
    claims: dict[str, ScannerClaim] = field(default_factory=dict)  # scanner -> what it said
    generators: set[str] = field(default_factory=set)  # generators listing the component as installed software
    not_installed: str | None = None  # why the component is not installed software (D9), if it is not
    enrichment: dict[str, Any] | None = None  # EPSS, KEV, CVSS, fix and depth (chainguard.enrich), once enriched
    priority: dict[str, Any] | None = None  # score, band, rank and per-factor explanation (chainguard.priority)

    @property
    def reported_by(self) -> set[str]:
        return {p for claim in self.claims.values() for p in claim.pipelines}

    @property
    def scanners(self) -> list[str]:
        return sorted(self.claims)

    @property
    def consensus(self) -> int:
        """Generators x scanners. Zero for what is not installed: no generator lists it as installed software."""
        return len(self.generators) * len(self.claims)

    @property
    def pipelines_reporting(self) -> int:
        """How many single pipelines reported it, hand-offs as they are. The fused pipeline reads the others'
        output, so it is not counted as another voice."""
        return sum(1 for p in self.reported_by if pipeline_class(p) == "single")

    @property
    def raw_ids(self) -> set[str]:
        return {i for claim in self.claims.values() for i in claim.ids}

    @property
    def max_severity(self) -> str:
        return _highest(claim.severity for claim in self.claims.values())

    def as_dict(self) -> dict[str, Any]:
        claims = self.claims.values()
        cvss = [c.cvss_v3 for c in claims if c.cvss_v3 is not None]
        entry = {
            "vulnerability": self.vulnerability,
            "component": self.component,
            "consensus": self.consensus,
            "generators": sorted(self.generators),
            "scanners": self.scanners,
            "pipelines_reporting": self.pipelines_reporting,
            "reported_by": sorted(self.reported_by),
            "raw_ids": sorted(self.raw_ids),
            # Merged across scanners: the highest severity and CVSS, every fix version, every fix state. EPSS and
            # KEV are not merged from the claims: they come from the dated snapshots, in ``enrichment``.
            "max_severity": self.max_severity,
            "cvss_v3": max(cvss, default=None),
            "fix_states": sorted({s for c in claims for s in c.fix_states}),
            "fix_versions": sorted({v for c in claims for v in c.fix_versions}),
            "not_installed": self.not_installed,
            "claims": {scanner: claim.as_dict() for scanner, claim in sorted(self.claims.items())},
        }
        if self.enrichment is not None:
            entry["enrichment"] = self.enrichment
        if self.priority is not None:
            entry["priority"] = self.priority
        return entry


def correlate(
    findings: Iterable[Finding],
    not_installed: dict[str, str] | None = None,
    inventory: dict[str, InventoryEntry] | None = None,
) -> list[CorrelatedFinding]:
    """One entry per (component, canonical ID). A finding whose advisory covers several CVEs supports each.

    ``inventory`` is the merged inventory, whose ``found_by`` gives each entry its generator evidence; without
    it no generator is credited and every consensus is 0. Direct scans are references, never evidence, so their
    findings are ignored.

    ``not_installed`` maps the keys of entries that are not installed software to the reason (``non_components``).
    A finding on one of them is kept, because a pipeline did report it, and marked, so that no later stage
    mistakes it for a vulnerability in software that is there. It stays on the key it was reported on and
    supports nothing installed. Moving it onto the binary packages built from a source package would mean
    second-guessing each scanner's matching rules: it would put every kernel advisory on the kernel headers,
    which Grype deliberately does not match. The fused pipeline lets the scanner match the binaries itself.
    """
    not_installed, inventory = not_installed or {}, inventory or {}
    merged: dict[tuple[str, str], CorrelatedFinding] = {}
    for f in findings:
        if pipeline_class(f.pipeline) == "direct":
            continue
        for vulnerability in f.canonical_ids:
            entry = merged.get((f.component, vulnerability))
            if entry is None:
                listed = inventory.get(f.component)
                entry = merged[(f.component, vulnerability)] = CorrelatedFinding(
                    vulnerability,
                    f.component,
                    generators=set(listed.found_by) if listed else set(),
                    not_installed=not_installed.get(f.component),
                )
            entry.claims.setdefault(f.scanner, ScannerClaim()).add(f)
    return sorted(merged.values(), key=lambda c: (SEVERITY_ORDER.index(c.max_severity), c.vulnerability, c.component))


def jaccard(a: set, b: set) -> float | None:
    union = a | b
    return round(len(a & b) / len(union), 3) if union else None
