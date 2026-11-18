"""Metrics: the pipeline configurations, as the tools report them and as ChainGuard normalises them.

The configurations: every single pipeline (one generator with one
scanner, four by default), their naive union, and the fused pipeline (the generators' merged SBOM in the requested
format, scanned by every scanner). The tools' own configurations are measured at three levels:

  reported     what the tools wrote. A component is keyed on its PURL's type, namespace, name and version as the
               tool wrote them, compared as the PURL specification normalises them, qualifiers ignored. Every entry
               with a valid PURL counts. Vulnerability IDs are taken exactly as each scanner reported them
  aliases      the same, with vulnerability IDs resolved to canonical CVEs (D1). This is the level at which the
               naive union is defined: aliases resolved, identity as the tools wrote it
  normalised   ChainGuard's identity rules as well: canonical versions (D4), installed software only (D9) and one
               component per jar (D11). Findings on entries that are not installed software are left out

The fused pipeline reads an SBOM that ChainGuard wrote from the normalised inventory, so it exists only normalised;
its counterpart as the tools report it is the naive union. (The scanners' agreement on that SBOM is still measured
at every level: both read the same document, so as reported it isolates how they name vulnerabilities.)

At the normalised level everything is normalised with the evidence of the generators that feed it. A single
pipeline, and the scanners' agreement on one generator's SBOM, use that generator's evidence alone, which is all a
single pipeline has. The naive union, the fused pipeline and the generators' agreement use every generator's,
merged into one inventory. Only there can a second generator's stated source packages show cdxgen's to be source
packages (D9), and a jar's two keys become one (D11).

Coverage needs a reference and is measured against the ones given: a component ground truth and verified anchor
vulnerabilities, and the direct scans when the run made them. Each single pipeline is checked against the
direct scan by the same scanner, and a configuration that combines scanners against all of their
direct scans. Agreement needs no reference:
between the generators on components, between the scanners on each SBOM, and between the naive union and the
fused pipeline. Nothing here runs a tool or asks OSV: the inputs are a run's parsed output and its analysis.

An adjudication (a reviewer's decisions) changes the component comparison the same way for every configuration
at every level, matched on each listed component's canonical key: a component set aside (unmanaged, the target
itself, undecidable) counts for no configuration and against none, and one labelled the same as another counts as
that one. Components the adjudication adds to or removes from the ground truth are already in or out of the list
of ground-truth components given.
"""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations
from typing import Any

from chainguard import correlate
from chainguard import purl as purls
from chainguard.aliases import Resolution
from chainguard.correlate import InventoryEntry, jaccard, pipeline_class
from chainguard.runner import Step
from chainguard.sbom import ParsedSbom
from chainguard.scanners import Finding

SCHEMA = "chainguard.metrics/v1"
LEVELS = ("reported", "aliases", "normalised")
NAIVE_UNION, FUSED = "naive union", "fused"
DEV_SCOPES = frozenset({"dev", "test"})  # ground-truth scopes a build does not ship (GROUND_TRUTH.md §1.1)

Pair = tuple[str, str]  # (component key, vulnerability ID)


@dataclass(frozen=True)
class Adjudication:
    """What adjudication decided beyond the ground-truth list itself, on canonical component keys."""

    same_as: Mapping[str, str]  # a listed key -> the key it is counted as
    set_aside: frozenset[str]  # keys that count for no configuration and against none


def ratio(part: int, whole: int) -> float | None:
    return round(part / whole, 3) if whole else None


def overlap(a: set, b: set, names: tuple[str, str]) -> dict[str, Any]:
    """How two sets agree: their Jaccard index, and what both and each alone hold."""
    return {
        "jaccard": jaccard(a, b),
        "both": len(a & b),
        "union": len(a | b),
        "only": {names[0]: len(a - b), names[1]: len(b - a)},
    }


@dataclass(frozen=True)
class _Identity:
    """Normalised identity with some generators' evidence: the inventory's keys, the keys merged into another
    component (D11), and the keys of entries that are not installed software (D9)."""

    keys: frozenset[str]
    merged: Mapping[str, str]
    not_installed: Mapping[str, str]

    def of(self, key: str) -> str:
        return self.merged.get(key, key)


@dataclass
class _Configuration:
    pipelines: list[str]  # the pipelines whose findings it holds
    scanners: list[str]
    components: set[str]
    pairs: frozenset[Pair]
    identity: _Identity  # what its direct-scan reference is normalised with


class _Run:
    """One run's output, keyed at each level on demand; every PURL is parsed and every pair set built once."""

    def __init__(
        self,
        sboms: Mapping[str, ParsedSbom],
        fused: Mapping[str, ParsedSbom],
        findings: Iterable[Finding],
        steps: Iterable[Step],
        inventory: Mapping[str, InventoryEntry],
        not_installed: Mapping[str, str],
        resolution: Resolution,
        suppress: bool,
        coordinates: bool,
    ):
        self.sboms, self.fused, self.resolution = sboms, fused, resolution
        self.suppress, self.coordinates = suppress, coordinates
        ok = [s.name for s in steps if s.kind == "scan" and s.ok]
        self.findings: dict[str, list[Finding]] = {p: [] for p in ok}
        for f in findings:
            if f.pipeline in self.findings:
                self.findings[f.pipeline].append(f)
        self.singles = [p for p in ok if pipeline_class(p) == "single" and p.split("+", 1)[0] in sboms]
        self.fused_pipelines = [p for p in ok if p.split("+", 1)[0] == FUSED]
        self.other_formats = [p for p in ok if pipeline_class(p) == "fused" and p not in self.fused_pipelines]
        self.direct = {p.split("+", 1)[1]: p for p in ok if pipeline_class(p) == "direct"}
        self.scanner_order = list(dict.fromkeys(p.split("+", 1)[1] for p in ok))
        self.merged = _Identity(frozenset(inventory), correlate.key_aliases(dict(inventory)), not_installed)
        # a reported key's canonical key, from every generator's SBOM: what an adjudication is matched on
        self.canonical_of = {r: k for parsed in sboms.values() for r, k in parsed.reported.items()}
        self._own: dict[str, _Identity] = {}
        self._keys: dict[str, tuple[str, str] | None] = {}
        self._pairs: dict[tuple[str, str, int], frozenset[Pair]] = {}
        self._left_out: dict[tuple[str, str, int], frozenset[Pair]] = {}  # normalised: on what is not installed

    def generators(self) -> list[str]:
        """The generators that feed a single pipeline, in the run's order."""
        heads = {p.split("+", 1)[0] for p in self.singles}
        return [g for g in self.sboms if g in heads]

    def own(self, generator: str) -> _Identity:
        """Normalised identity with this generator's evidence alone: what a single pipeline can know."""
        if len(self.sboms) == 1:
            return self.merged
        if generator not in self._own:
            one = {generator: self.sboms[generator]}
            inventory, suppressed = correlate.canonical_inventory(
                one, suppress_source_packages=self.suppress, maven_coordinates=self.coordinates
            )
            self._own[generator] = _Identity(
                frozenset(inventory),
                correlate.key_aliases(inventory),
                correlate.non_components(one, inventory, suppressed),
            )
        return self._own[generator]

    def keys(self, raw: str | None) -> tuple[str, str] | None:
        """(key as written, canonical key) of a raw PURL, or None if there is none or it is invalid."""
        if not raw:
            return None
        if raw not in self._keys:
            parsed = purls.parse(raw)
            self._keys[raw] = (parsed.reported_key, parsed.key) if parsed else None
        return self._keys[raw]

    def pairs(self, pipeline: str, level: str, identity: _Identity) -> frozenset[Pair]:
        memo = (pipeline, level, id(identity) if level == "normalised" else 0)
        if memo not in self._pairs:
            out: set[Pair] = set()
            left_out: set[Pair] = set()
            for f in self.findings.get(pipeline, ()):
                keys = self.keys(f.purl)
                if level == "normalised":
                    base = keys[1] if keys else f.component  # a scanner gave no usable PURL: its fallback key
                    if base in identity.not_installed:
                        left_out.update((base, v) for v in f.canonical_ids)
                        continue
                    component, ids = identity.of(base), f.canonical_ids
                else:
                    component = keys[0] if keys else f.component
                    ids = f.canonical_ids if level == "aliases" else (f.raw_id,)
                out.update((component, v) for v in ids)
            self._pairs[memo] = frozenset(out)
            self._left_out[memo] = frozenset(left_out)
        return self._pairs[memo]

    def left_out(self, pipelines: Iterable[str], identity: _Identity) -> set[Pair]:
        """Normalised pairs the pipelines reported on entries that are not installed software, left out (D9)."""
        out: set[Pair] = set()
        for p in pipelines:
            self.pairs(p, "normalised", identity)
            out |= self._left_out[(p, "normalised", id(identity))]
        return out

    def generator_components(self, generator: str, level: str, identity: _Identity) -> set[str]:
        parsed = self.sboms[generator]
        if level != "normalised":
            return set(parsed.reported)
        return {identity.of(k) for k in parsed.components} & identity.keys

    def fused_components(self) -> set[str] | None:
        """The merged SBOM's components, normalised: the document the fused pipeline's scanners read."""
        parsed = self.fused.get(FUSED)
        return None if parsed is None else {self.merged.of(k) for k in parsed.components}

    def configurations(self, level: str) -> dict[str, _Configuration]:
        out: dict[str, _Configuration] = {}
        for p in self.singles:
            generator, scanner = p.split("+", 1)
            identity = self.own(generator)
            components = self.generator_components(generator, level, identity)
            out[p] = _Configuration([p], [scanner], components, self.pairs(p, level, identity), identity)
        if len(self.singles) > 1:
            scanners = sorted({p.split("+", 1)[1] for p in self.singles}, key=self.scanner_order.index)
            components = set().union(*(self.generator_components(g, level, self.merged) for g in self.generators()))
            pairs = frozenset().union(*(self.pairs(p, level, self.merged) for p in self.singles))
            out[NAIVE_UNION] = _Configuration(list(self.singles), scanners, components, pairs, self.merged)
        components = self.fused_components() if level == "normalised" else None
        if self.fused_pipelines and components is not None:
            scanners = sorted({p.split("+", 1)[1] for p in self.fused_pipelines}, key=self.scanner_order.index)
            pairs = frozenset().union(*(self.pairs(p, level, self.merged) for p in self.fused_pipelines))
            out[FUSED] = _Configuration(list(self.fused_pipelines), scanners, components, pairs, self.merged)
        return out

    def direct_reference(self, scanners: list[str], level: str, identity: _Identity) -> frozenset[Pair] | None:
        """The direct scans of the configuration's scanners, or None unless every one of them succeeded."""
        if not scanners or any(s not in self.direct for s in scanners):
            return None
        return frozenset().union(*(self.pairs(self.direct[s], level, identity) for s in scanners))

    def formats_agree(self) -> bool | None:
        """Whether the merged SBOM in every other format gave each scanner the same pairs (D7)."""
        compared = []
        for p in self.other_formats:
            counterpart = f"{FUSED}+{p.split('+', 1)[1]}"
            if counterpart in self.fused_pipelines:
                compared.append(
                    self.pairs(p, "normalised", self.merged) == self.pairs(counterpart, "normalised", self.merged)
                )
        return all(compared) if compared else None


def _truth_keys(
    run: _Run, truth: Sequence[Mapping[str, Any]], level: str, adjudication: Adjudication | None = None
) -> tuple[set[str], set[str], dict[str, str]]:
    """The ground truth's keys at this level, those a build ships (every scope but dev and test), and each one's
    key at this level by its canonical key. Keys an adjudication set aside are left out."""
    scopes: dict[str, set[str]] = {}
    at_level: dict[str, str] = {}
    aside = adjudication.set_aside if adjudication else frozenset()
    for component in truth:
        keys = run.keys(component.get("purl"))
        if keys is None or keys[1] in aside:
            continue
        key = keys[1] if level == "normalised" else keys[0]
        scopes.setdefault(key, set()).add(component.get("scope") or "")
        at_level.setdefault(keys[1], key)
    return set(scopes), {k for k, s in scopes.items() if s - DEV_SCOPES}, at_level


def _adjudicated(
    run: _Run, components: Iterable[str], level: str, adjudication: Adjudication | None, at_level: Mapping[str, str]
) -> tuple[set[str], int, int]:
    """A configuration's components as the adjudication counts them, with how many were set aside and how many
    counted as another component."""
    if adjudication is None:
        return set(components), 0, 0
    out: set[str] = set()
    aside = mapped = 0
    for key in components:
        canonical = key if level == "normalised" else run.canonical_of.get(key, key)
        target = adjudication.same_as.get(canonical)
        if canonical in adjudication.set_aside or (target is not None and target in adjudication.set_aside):
            aside += 1
        elif target is not None:
            mapped += 1
            out.add(at_level.get(target, target))
        else:
            out.add(key)
    return out, aside, mapped


def _anchor_pairs(run: _Run, anchors: Sequence[Mapping[str, Any]], level: str) -> list[tuple[Pair, bool, str]]:
    """(pair at this level, in KEV, label) per anchor. As reported, an anchor counts only under its own CVE ID."""
    out = []
    for anchor in anchors:
        keys = run.keys(anchor.get("purl"))
        if keys is None:
            continue
        cve = str(anchor["cve"])
        vulnerability = cve if level == "reported" else run.resolution.canonical(cve)[0]
        pair = (keys[1] if level == "normalised" else keys[0], vulnerability)
        out.append((pair, bool(anchor.get("kev") or anchor.get("kev_date_added")), f"{cve} on {keys[1]}"))
    return out


def _level(
    run: _Run,
    level: str,
    truth: Sequence[Mapping[str, Any]] | None,
    anchors: Sequence[Mapping[str, Any]] | None,
    adjudication: Adjudication | None = None,
) -> dict[str, Any]:
    configurations = run.configurations(level)
    truth_keys = _truth_keys(run, truth, level, adjudication) if truth is not None else None
    anchor_pairs = _anchor_pairs(run, anchors, level) if anchors is not None else None
    out: dict[str, Any] = {}
    for name, c in configurations.items():
        entry: dict[str, Any] = {
            "pipelines": c.pipelines,
            "scanners": c.scanners,
            "components": len(c.components),
            "pairs": len(c.pairs),
            "vulnerabilities": len({v for _, v in c.pairs}),
        }
        if level == "normalised":
            left_out = run.left_out(c.pipelines, c.identity)
            entry["not_installed"] = {
                "pairs": len(left_out),
                # vulnerabilities this configuration reports only on entries that are not installed software
                "vulnerabilities_only_there": len({v for _, v in left_out} - {v for _, v in c.pairs}),
            }
        reference = run.direct_reference(c.scanners, level, c.identity)
        if reference is not None:
            entry["direct"] = {
                "reference": [run.direct[s] for s in c.scanners],
                "pairs": len(reference),
                "reported": len(reference & c.pairs),
                "beyond": len(c.pairs - reference),
            }
        if truth_keys is not None:
            every, shipped, at_level = truth_keys
            listed, aside, mapped = _adjudicated(run, c.components, level, adjudication, at_level)
            found = listed & every
            extra = listed - every
            entry["truth"] = {
                "components": len(every),
                "listed": len(listed),
                "found": len(found),
                "precision": ratio(len(found), len(listed)),
                "recall": ratio(len(found), len(every)),
                "shipped": len(shipped),
                "shipped_found": len(listed & shipped),
                "shipped_recall": ratio(len(listed & shipped), len(shipped)),
                # what it lists that the ground truth does not: by PURL type, and how many have no version at all
                "not_in_truth": len(extra),
                "not_in_truth_by_type": dict(sorted(Counter(k.split("/", 1)[0] for k in extra).items())),
                "not_in_truth_versionless": sum(1 for k in extra if k.endswith("@")),
            }
            if adjudication is not None:
                entry["truth"]["adjudicated"] = {"set_aside": aside, "counted_as_another": mapped}
            if name == FUSED:  # what ChainGuard lists and the ground truth lacks: what a reviewer should look at
                entry["truth"]["not_in_truth_keys"] = sorted(extra)
        if anchor_pairs is not None:
            hit = [pair in c.pairs for pair, _, _ in anchor_pairs]
            entry["anchors"] = {
                "count": len(anchor_pairs),
                "found": sum(hit),
                "kev": sum(kev for _, kev, _ in anchor_pairs),
                "kev_found": sum(h and kev for h, (_, kev, _) in zip(hit, anchor_pairs, strict=True)),
                "missed": sorted(label for h, (_, _, label) in zip(hit, anchor_pairs, strict=True) if not h),
            }
        out[name] = entry
    result: dict[str, Any] = {"configurations": out, "agreement": _agreement(run, level, configurations)}
    if truth_keys is not None or anchor_pairs is not None:
        result["unique"] = _unique(run, level, configurations, truth_keys, anchor_pairs, adjudication)
    return result


def _agreement(run: _Run, level: str, configurations: dict[str, _Configuration]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    generators = run.generators()
    if len(generators) > 1:
        listed = {g: run.generator_components(g, level, run.merged) for g in generators}
        out["generators"] = {f"{a}|{b}": overlap(listed[a], listed[b], (a, b)) for a, b in combinations(generators, 2)}
    heads = {g: [p for p in run.singles if p.split("+", 1)[0] == g] for g in generators}
    if run.fused_pipelines:
        heads[FUSED] = run.fused_pipelines
    scanners: dict[str, Any] = {}
    for head, pipelines in heads.items():
        identity = run.merged if head == FUSED else run.own(head)
        by = {p.split("+", 1)[1]: run.pairs(p, level, identity) for p in pipelines}
        if len(by) > 1:
            scanners[head] = {
                f"{a}|{b}": {
                    "pairs": overlap(set(by[a]), set(by[b]), (a, b)),
                    "vulnerabilities": overlap({v for _, v in by[a]}, {v for _, v in by[b]}, (a, b)),
                }
                for a, b in combinations(by, 2)
            }
    if scanners:
        out["scanners"] = scanners
    if NAIVE_UNION in configurations and FUSED in configurations:
        union, fused = configurations[NAIVE_UNION], configurations[FUSED]
        out["naive_union_fused"] = overlap(set(union.pairs), set(fused.pairs), (NAIVE_UNION, FUSED))
        # What the merged SBOM adds: a pair only the fused pipeline reports has a vulnerability the naive union
        # reports on another installed component, only on entries that are not installed, or nowhere at all.
        installed = {v for _, v in union.pairs}
        elsewhere = {v for _, v in run.left_out(union.pipelines, union.identity)}
        kinds: Counter[str] = Counter()
        for _, v in fused.pairs - union.pairs:
            kinds[
                "on another installed component"
                if v in installed
                else "only on entries not installed"
                if v in elsewhere
                else "nowhere"
            ] += 1
        out["naive_union_fused"]["only_fused_vulnerability"] = dict(kinds)
    if NAIVE_UNION in configurations:
        each = [run.pairs(p, level, run.merged) for p in run.singles]
        reporting = Counter(sum(pair in pairs for pairs in each) for pair in configurations[NAIVE_UNION].pairs)
        out["pipelines_reporting"] = {str(k): n for k, n in sorted(reporting.items(), reverse=True)}
    return out


def _unique(
    run: _Run,
    level: str,
    configurations: dict[str, _Configuration],
    truth_keys: tuple[set[str], set[str], dict[str, str]] | None,
    anchor_pairs: list[tuple[Pair, bool, str]] | None,
    adjudication: Adjudication | None = None,
) -> dict[str, Any]:
    """What one tool contributes alone: ground-truth components one generator lists, anchors one pipeline finds."""
    out: dict[str, Any] = {}
    generators = run.generators()

    def counted(components: Iterable[str]) -> set[str]:
        return _adjudicated(run, components, level, adjudication, truth_keys[2] if truth_keys else {})[0]

    if truth_keys is not None and len(generators) > 1:
        listed = {g: counted(run.generator_components(g, level, run.merged)) & truth_keys[0] for g in generators}
        out["truth_components"] = {
            g: len(listed[g] - set().union(*(listed[o] for o in generators if o != g))) for g in generators
        }
    if truth_keys is not None:
        every = set().union(*(counted(c.components) for c in configurations.values()))
        out["truth_missed_by_every_configuration"] = sorted(truth_keys[0] - every)
    if anchor_pairs is not None:
        singles = [p for p in run.singles if p in configurations]
        found = {p: {pair for pair, _, _ in anchor_pairs if pair in configurations[p].pairs} for p in singles}
        out["anchors"] = {p: len(found[p] - set().union(*(found[o] for o in singles if o != p))) for p in singles}
        by_any_single = set().union(*found.values())
        if FUSED in configurations:
            out["anchors_only_fused"] = sum(
                1 for pair, _, _ in anchor_pairs if pair in configurations[FUSED].pairs and pair not in by_any_single
            )
        reported = set().union(*(c.pairs for c in configurations.values()))
        out["anchors_missed_by_every_configuration"] = sorted(
            label for pair, _, label in anchor_pairs if pair not in reported
        )
    return out


def measure(
    sboms: Mapping[str, ParsedSbom],
    fused: Mapping[str, ParsedSbom],
    findings: Iterable[Finding],
    steps: Iterable[Step],
    inventory: Mapping[str, InventoryEntry],
    not_installed: Mapping[str, str],
    resolution: Resolution,
    *,
    suppress_source_packages: bool = True,
    maven_coordinates: bool = True,
    truth: Sequence[Mapping[str, Any]] | None = None,
    anchors: Sequence[Mapping[str, Any]] | None = None,
    adjudication: Adjudication | None = None,
) -> dict[str, Any]:
    """Every configuration of one run at every level, with coverage against the references given.

    ``findings`` must carry canonical IDs (``aliases.resolve``) and ``inventory`` be the run's merged inventory,
    as ``pipeline.analyze`` leaves them. ``truth`` lists ground-truth components (``purl``, optional ``scope``),
    ``anchors`` verified vulnerabilities (``purl``, ``cve``, and ``kev`` or the corpus's ``kev_date_added``).
    """
    steps = list(steps)
    run = _Run(
        sboms,
        fused,
        findings,
        steps,
        inventory,
        not_installed,
        resolution,
        suppress_source_packages,
        maven_coordinates,
    )
    if not run.singles and not run.fused_pipelines:
        return {"schema": SCHEMA, "status": "not measured: no SBOM pipeline's scan succeeded"}
    levels = {level: _level(run, level, truth, anchors, adjudication) for level in LEVELS}
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "measured",
        "configurations": list(levels["normalised"]["configurations"]),
        "generators": run.generators(),
        "direct": sorted(run.direct.values()),
        "levels": levels,
        "formats_agree": run.formats_agree(),
    }
    if truth is not None or anchors is not None:
        record["references"] = {
            "truth": len(truth) if truth is not None else None,
            "anchors": len(anchors) if anchors is not None else None,
        }
    return record


# --------------------------------------------------------------------------- across runs


def _overlaps(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Per-run overlaps summarised: the median of the per-run Jaccard indexes and the pooled index. The median is
    taken over each run's exact index (both / union), not over the rounded ones the runs report."""
    measured = [i["both"] / i["union"] for i in items if i["union"]]
    both, union = sum(i["both"] for i in items), sum(i["union"] for i in items)
    only: Counter[str] = Counter()
    for i in items:
        only.update(i["only"])
    return {
        "runs": len(measured),
        "median": round(statistics.median(measured), 3) if measured else None,
        "pooled": ratio(both, union),
        "both": both,
        "union": union,
        "only": dict(only),
    }


def _collect(records: Iterable[Mapping[str, Any]], path: tuple[str, ...]) -> list[Mapping[str, Any]]:
    out = []
    for record in records:
        value: Any = record
        for step in path:
            value = value.get(step) if isinstance(value, Mapping) else None
        if value is not None:
            out.append(value)
    return out


def _best_single(measured: Mapping[str, Mapping[str, Any]], level: str) -> dict[str, Any]:
    """The single pipeline that finds the most anchors over every run, and what the best one per run finds: the
    most a user could get from one pipeline if they knew in advance which to pick for each target."""
    per_run: dict[str, dict[str, int]] = {}
    for target, record in measured.items():
        rows = record["levels"][level]["configurations"]
        found = {p: x["anchors"]["found"] for p, x in rows.items() if x.get("pipelines") == [p] and "anchors" in x}
        if found:
            per_run[target] = found
    if not per_run:
        return {}
    totals: Counter[str] = Counter()
    for found in per_run.values():
        totals.update(found)
    pipeline, found = max(sorted(totals.items()), key=lambda kv: kv[1])
    return {
        "pipeline": pipeline,
        "anchors_found": found,
        "per_run_best_anchors_found": sum(max(f.values()) for f in per_run.values()),
        "per_run_best": {t: sorted(p for p, n in f.items() if n == max(f.values())) for t, f in per_run.items()},
    }


def summarize(records: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Runs' metrics added up: counts summed, recall and precision over the pooled counts (micro averages),
    agreement as the median of the per-run Jaccard indexes and as the pooled index."""
    measured = {t: r for t, r in records.items() if r.get("status") == "measured"}
    order = list(dict.fromkeys(c for r in measured.values() for c in r["configurations"]))
    out: dict[str, Any] = {"runs": len(measured), "configurations": order, "levels": {}}
    for level in LEVELS:
        per = [r["levels"][level] for r in measured.values()]
        configurations: dict[str, Any] = {}
        for name in order:
            rows = _collect(per, ("configurations", name))
            if not rows:
                continue  # the fused pipeline exists only normalised
            entry: dict[str, Any] = {
                "runs": len(rows),
                **{k: sum(x[k] for x in rows) for k in ("components", "pairs", "vulnerabilities")},
            }
            direct = [x["direct"] for x in rows if "direct" in x]
            if direct:
                entry["direct"] = {
                    "runs": len(direct),
                    **{k: sum(d[k] for d in direct) for k in ("pairs", "reported", "beyond")},
                }
                entry["direct"]["recall"] = ratio(entry["direct"]["reported"], entry["direct"]["pairs"])
            left = [x["not_installed"] for x in rows if "not_installed" in x]
            if left:
                entry["not_installed"] = {k: sum(x[k] for x in left) for k in ("pairs", "vulnerabilities_only_there")}
            truths = [x for x in rows if "truth" in x]
            if truths:
                t = {
                    k: sum(x["truth"][k] for x in truths)
                    for k in (
                        "components",
                        "found",
                        "shipped",
                        "shipped_found",
                        "not_in_truth",
                        "not_in_truth_versionless",
                    )
                }
                by_type: Counter[str] = Counter()
                for x in truths:
                    by_type.update(x["truth"]["not_in_truth_by_type"])
                listed = sum(x["truth"].get("listed", x["components"]) for x in truths)
                entry["truth"] = {
                    "runs": len(truths),
                    **t,
                    "listed": listed,
                    "precision": ratio(t["found"], listed),
                    "recall": ratio(t["found"], t["components"]),
                    "shipped_recall": ratio(t["shipped_found"], t["shipped"]),
                    "not_in_truth_by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
                }
            anchored = [
                (t, r["levels"][level]["configurations"][name])
                for t, r in measured.items()
                if "anchors" in r["levels"][level]["configurations"].get(name, {})
            ]
            if anchored:
                entry["anchors"] = {
                    "runs": len(anchored),
                    **{k: sum(x["anchors"][k] for _, x in anchored) for k in ("count", "found", "kev", "kev_found")},
                    "missed": [f"{t}: {m}" for t, x in anchored for m in x["anchors"]["missed"]],
                }
            configurations[name] = entry
        agreement: dict[str, Any] = {}
        pairs_of = sorted({k for g in _collect(per, ("agreement", "generators")) for k in g})
        if pairs_of:
            agreement["generators"] = {k: _overlaps(_collect(per, ("agreement", "generators", k))) for k in pairs_of}
        heads = list(dict.fromkeys(h for s in _collect(per, ("agreement", "scanners")) for h in s))
        if heads:
            agreement["scanners"] = {}
            for head in heads:
                keys = sorted({k for s in _collect(per, ("agreement", "scanners", head)) for k in s})
                agreement["scanners"][head] = {
                    k: {
                        unit: _overlaps(_collect(per, ("agreement", "scanners", head, k, unit)))
                        for unit in ("pairs", "vulnerabilities")
                    }
                    for k in keys
                }
        union_fused = _collect(per, ("agreement", "naive_union_fused"))
        if union_fused:
            agreement["naive_union_fused"] = _overlaps(union_fused)
            kinds: Counter[str] = Counter()
            for item in union_fused:
                kinds.update(item.get("only_fused_vulnerability") or {})
            agreement["naive_union_fused"]["only_fused_vulnerability"] = dict(kinds)
        reporting: Counter[str] = Counter()
        for counts in _collect(per, ("agreement", "pipelines_reporting")):
            reporting.update(counts)
        if reporting:
            agreement["pipelines_reporting"] = dict(sorted(reporting.items(), key=lambda kv: -int(kv[0])))
        unique: dict[str, Any] = {}
        for key in ("truth_components", "anchors"):
            totals: Counter[str] = Counter()
            for counts in _collect(per, ("unique", key)):
                totals.update(counts)
            if totals:
                unique[key] = dict(totals)
        only_fused = _collect(per, ("unique", "anchors_only_fused"))
        if only_fused:
            unique["anchors_only_fused"] = sum(only_fused)
        if any("unique" in p for p in per):
            for key in ("anchors_missed_by_every_configuration", "truth_missed_by_every_configuration"):
                unique[key] = [
                    f"{t}: {m}"
                    for t, r in measured.items()
                    for m in (r["levels"][level].get("unique") or {}).get(key, [])
                ]
        best = _best_single(measured, level)
        if best:
            unique["best_single"] = best
        out["levels"][level] = {"configurations": configurations, "agreement": agreement, "unique": unique}
    formats = [r["formats_agree"] for r in measured.values() if r.get("formats_agree") is not None]
    out["formats_agree"] = {"runs": len(formats), "agree": sum(formats)}
    return out
