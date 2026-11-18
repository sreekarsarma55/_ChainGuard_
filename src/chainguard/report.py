"""Summarise a scan run: coverage per generator, findings per pipeline, and scanner agreement."""

from __future__ import annotations

from collections import Counter
from itertools import combinations
from typing import Any

from chainguard.aliases import Resolution
from chainguard.correlate import SEVERITY_ORDER, CorrelatedFinding, InventoryEntry, jaccard, pipeline_class
from chainguard.correlate import key_aliases as correlate_key_aliases
from chainguard.runner import Step
from chainguard.sbom import ParsedSbom
from chainguard.scanners import Finding


def summarize(
    sboms: dict[str, ParsedSbom],
    inventory: dict[str, InventoryEntry],
    findings: list[Finding],
    correlated: list[CorrelatedFinding],
    resolution: Resolution,
    steps: list[Step],
    suppressed: dict[str, dict[str, Any]] | None = None,
    not_installed: dict[str, str] | None = None,
) -> dict[str, Any]:
    suppressed, not_installed = suppressed or {}, not_installed or {}
    # Each generator's contribution to the canonical inventory: what it listed, less what is not installed, with a
    # key merged into another component counted as that component (D11).
    merged = correlate_key_aliases(inventory)
    keys = {g: {merged.get(k, k) for k in s.components} & set(inventory) for g, s in sboms.items()}
    per_generator = {}
    for g, s in sboms.items():
        per_generator[g] = s.stats() | {
            "accepted_components": len(keys[g]),
            "source_packages_suppressed": sum(1 for k in s.components if k in suppressed),
        }
    components: dict[str, Any] = {
        "per_generator": per_generator,
        "union": len(inventory),
        "found_by_all": sum(1 for e in inventory.values() if len(e.found_by) == len(sboms)) if sboms else 0,
        "only_in": {g: len(k - set().union(*(o for n, o in keys.items() if n != g))) for g, k in keys.items()},
        "jaccard": {f"{a}|{b}": jaccard(keys[a], keys[b]) for a, b in combinations(sorted(keys), 2)},
        # Components that tools spelled differently and that are one version by their ecosystem's rules (D4)
        "version_spellings_merged": sum(1 for e in inventory.values() if len(e.reported_versions) > 1),
        # One jar that generators gave different Maven groups (D11): merged on evidence, or left apart on a tie
        "coordinates_merged": sum(len(e.merged_keys) for e in inventory.values()),
        "coordinates_undecided": len(
            {frozenset({e.key, *e.undecided_with}) for e in inventory.values() if e.undecided_with}
        ),
        "not_installed": {
            "not_software_entries": {g: dict(sorted(s.not_software.items())) for g, s in sboms.items()},
            "source_packages_suppressed": len(suppressed),
        },
    }

    pipelines = sorted({f.pipeline for f in findings} | {s.name for s in steps if s.kind == "scan"})
    vulns = {p: {v for f in findings if f.pipeline == p for v in f.canonical_ids} for p in pipelines}
    raw_ids = {p: {f.raw_id for f in findings if f.pipeline == p} for p in pipelines}
    # The naive union is the union of the single pipelines; the fused pipeline is measured against it, never
    # folded into it (correlate.pipeline_class).
    sbom_pipelines = [p for p in pipelines if pipeline_class(p) == "single"]
    fused_pipelines = [p for p in pipelines if pipeline_class(p) == "fused"]
    union = set().union(*(vulns[p] for p in sbom_pipelines)) if sbom_pipelines else set()
    reported_by = {v: [p for p in sbom_pipelines if v in vulns[p]] for v in union}
    worst: dict[str, str] = {}  # vulnerability -> highest severity any SBOM pipeline gave it
    for c in correlated:
        current = worst.get(c.vulnerability)
        if current is None or SEVERITY_ORDER.index(c.max_severity) < SEVERITY_ORDER.index(current):
            worst[c.vulnerability] = c.max_severity

    vulnerabilities: dict[str, Any] = {
        "per_pipeline": {
            p: {
                "findings": sum(1 for f in findings if f.pipeline == p),
                "distinct": len(vulns[p]),
                "class": pipeline_class(p),
            }
            for p in pipelines
        },
        "union": len(union),
        "reported_by_one_pipeline": sum(1 for ps in reported_by.values() if len(ps) == 1),
        "reported_by_all_pipelines": sum(1 for ps in reported_by.values() if len(ps) == len(sbom_pipelines)),
        "missed_by_best_single_pipeline": len(union) - max((len(vulns[p]) for p in sbom_pipelines), default=0),
        "by_severity": {s: sum(1 for v in union if worst.get(v) == s) for s in SEVERITY_ORDER},
        "correlated_findings": len(correlated),
        # Findings a pipeline reported against something that is not installed software (D9): files, or a
        # source package listed as if installed. They are kept, since the pipeline did report them, and counted.
        "on_not_installed": {
            p: n
            for p in pipelines
            if (n := sum(1 for f in findings if f.pipeline == p and f.component in not_installed))
        },
    }

    agreement: dict[str, Any] = {}
    succeeded = {s.name for s in steps if s.kind == "scan" and s.ok}  # a failed scan is not "zero agreement"
    for generator in sboms:
        scanners = sorted(
            p.split("+", 1)[1] for p in sbom_pipelines if p.split("+", 1)[0] == generator and p in succeeded
        )
        for a, b in combinations(scanners, 2):
            pa, pb = f"{generator}+{a}", f"{generator}+{b}"
            agreement[f"{pa}|{pb}"] = {
                "jaccard_raw_ids": jaccard(raw_ids[pa], raw_ids[pb]),
                "jaccard_aliases_resolved": jaccard(vulns[pa], vulns[pb]),
            }

    summary = {
        "components": components,
        "vulnerabilities": vulnerabilities,
        # the most consensus there can be: generators whose SBOM was read x scanners that scanned one
        "correlation": correlation_summary(
            correlated, len(sboms), [p for p in sbom_pipelines + fused_pipelines if p in succeeded]
        ),
        "scanner_agreement": agreement,
        "aliases": resolution.stats(),
        "failed_steps": [{"name": s.name, "error": s.error} for s in steps if not s.ok],
    }
    if fused_pipelines:
        fused_union = set().union(*(vulns[p] for p in fused_pipelines))
        summary["fusion"] = {
            "per_pipeline": {p: len(vulns[p]) for p in fused_pipelines},
            "union": len(fused_union),
            "naive_union": len(union),
            "only_in_fused": sorted(fused_union - union),
            "only_in_naive_union": sorted(union - fused_union),
            "jaccard": jaccard(fused_union, union),
            "by_format": {
                fmt: len(set().union(*(vulns[p] for p in group)))
                for fmt, group in (
                    ("requested", [p for p in fused_pipelines if p.split("+", 1)[0] == "fused"]),
                    ("other", [p for p in fused_pipelines if p.split("+", 1)[0] != "fused"]),
                )
                if group
            },
        }
        direct = [p for p in pipelines if pipeline_class(p) == "direct"]
        if direct:
            direct_union = set().union(*(vulns[p] for p in direct))
            summary["fusion"]["versus_direct"] = {
                "direct_union": len(direct_union),
                "missed_by_fused": len(direct_union - fused_union),
                "missed_by_naive_union": len(direct_union - union),
            }
    return summary


def correlation_summary(correlated: list[CorrelatedFinding], generators: int, pipelines: list[str]) -> dict[str, Any]:
    """The correlated view on installed software: consensus as evidence (D10) beside the pipelines that reported
    each pair, and where scanners that both report a pair disagree about it."""
    installed = [c for c in correlated if not c.not_installed]
    both = [c for c in installed if len(c.claims) > 1]
    scanners = len({p.split("+", 1)[1] for p in pipelines})
    return {
        "pairs": len(installed),
        "most_consensus": generators * scanners,
        "consensus": {str(k): n for k, n in sorted(Counter(c.consensus for c in installed).items(), reverse=True)},
        "pipelines_reporting": {
            str(k): n for k, n in sorted(Counter(c.pipelines_reporting for c in installed).items(), reverse=True)
        },
        "on_unlisted_components": sum(1 for c in installed if not c.generators),
        "on_not_installed": len(correlated) - len(installed),
        "reported_by_several_scanners": len(both),
        "scanners_disagree": {
            "severity": sum(1 for c in both if len({claim.severity for claim in c.claims.values()}) > 1),
            "fix_state": sum(1 for c in both if len({claim.fix_state for claim in c.claims.values()}) > 1),
            "fix_versions": sum(
                1 for c in both if len({tuple(sorted(claim.fix_versions)) for claim in c.claims.values()}) > 1
            ),
        },
    }


def correlation_lines(correlation: dict[str, Any]) -> list[str]:
    """The correlated-findings section: consensus counts evidence, not pipelines (D10)."""
    if not correlation or not correlation.get("pairs"):
        return []
    most = correlation["most_consensus"]
    columns = [str(k) for k in range(max(most, 1), -1, -1)]
    consensus, reporting = correlation["consensus"], correlation["pipelines_reporting"]
    disagree = correlation["scanners_disagree"]
    lines = [
        "",
        "## Correlated findings ((component, CVE) pairs on installed software)",
        "",
        "| | " + " | ".join(columns) + " |",
        "|---|" + "---:|" * len(columns),
        "| Consensus: generators listing the component × scanners reporting it | "
        + " | ".join(str(consensus.get(k, 0)) for k in columns)
        + " |",
        "| Single pipelines that reported it | " + " | ".join(str(reporting.get(k, 0)) for k in columns) + " |",
        "",
        f"**{correlation['pairs']}** pairs. Consensus counts independent evidence, up to {most} here (design rule "
        "D10); the second row counts the pipelines that reported each pair, so it also measures their hand-offs. "
        f"Of the {correlation['reported_by_several_scanners']} pairs both scanners report, they disagree on "
        f"severity for {disagree['severity']}, on fix state for {disagree['fix_state']} and on fix versions for "
        f"{disagree['fix_versions']}; each scanner's claim is in `findings.json`.",
    ]
    extra = []
    if correlation.get("on_not_installed"):
        extra.append(
            f"{correlation['on_not_installed']} pairs on entries that are not installed software (kept and "
            "marked; they support nothing installed)"
        )
    if correlation.get("on_unlisted_components"):
        extra.append(f"{correlation['on_unlisted_components']} on components no generator lists")
    if extra:
        lines += ["", "Not counted above: " + " · ".join(extra) + "."]
    return lines


ENRICHMENT_LEGEND = (
    "EPSS and KEV come from the dated snapshots named above (`chainguard db update`); Grype's own values, from "
    "whenever its database was built, are kept in its claims and only compared with them. A vulnerability without a "
    "CVE has neither. *Fix available*: a scanner names a fixed version. *Depth*: the shortest distance from the "
    "target in a generator's dependency graph, 1 for a direct dependency; unknown where no graph that starts at the "
    "target reaches the component."
)


def enrichment_lines(enrichment: dict[str, Any], record: dict[str, Any] | None = None) -> list[str]:
    """The enrichment section: which snapshots, what they and the other facts cover, and Grype's cross-check."""
    if not enrichment or not enrichment.get("pairs"):
        return []
    record = record or {}
    epss, kev = record.get("epss") or {}, record.get("kev") or {}
    sources = [
        f"EPSS scores of {epss['version']} (FIRST, model {epss.get('model') or '?'}, {epss['count']} CVEs)"
        if epss
        else "**no EPSS snapshot**",
        f"CISA KEV catalog {kev['version']} ({kev['count']} entries)" if kev else "**no KEV snapshot**",
    ]
    e, fix, depth = enrichment, enrichment["fix_available"], dict(enrichment["depth"])
    unknown = depth.pop("unknown", 0)
    direct = depth.pop("1", 0)
    lines = [
        "",
        "## Enrichment (EPSS, KEV, CVSS, fix, dependency depth)",
        "",
        " · ".join(sources),
        "",
        "| Pairs on installed software | With a CVE | EPSS scored | In KEV | CVSS v3 | Fix available (yes / no / "
        "unknown) | Direct dependency | Transitive | Depth unknown |",
        "|---:|---:|---:|---:|---:|---|---:|---:|---:|",
        f"| {e['pairs']} | {e['with_cve']} | {e['epss_scored']} | {e['kev_listed']} | {e['cvss_v3']} | "
        f"{fix['yes']} / {fix['no']} / {fix['unknown']} | {direct} | {sum(depth.values())} | {unknown} |",
    ]
    listed = enrichment.get("in_kev") or []
    if listed:
        shown = [
            f"{x['vulnerability']} on `{x['component']}` (added {x['date_added']}"
            + (", known ransomware use" if x.get("ransomware") == "Known" else "")
            + ")"
            for x in listed[:10]
        ]
        more = f" · and {len(listed) - 10} more" if len(listed) > 10 else ""
        lines += ["", "**In KEV:** " + " · ".join(shown) + more]
    g = enrichment.get("grype") or {}
    checks = []
    if g.get("epss_compared"):
        dates = ", ".join(g.get("epss_dates") or []) or "undated"
        checks.append(
            f"its EPSS scores ({dates}) equal the snapshot's on {g['epss_same']} of {g['epss_compared']} pairs "
            f"(largest difference {g['epss_largest_difference']})"
        )
    if g.get("kev_compared"):
        checks.append(
            f"its KEV flags agree with the snapshot's on {g['kev_agree']} of {g['kev_compared']} (listed only by "
            f"Grype {g['kev_only_grype']}, only by the snapshot {g['kev_only_snapshot']})"
        )
    if checks:
        lines += ["", "Grype's own values, for comparison only: " + "; ".join(checks) + "."]
    return [*lines, "", ENRICHMENT_LEGEND]


PRIORITY_LEGEND = (
    "Score: 100 × the weighted mean of the factors' values in [0, 1] (EPSS percentile, KEV, CVSS v3 / 10 or the "
    "scanner's severity, fix available, 1 / dependency depth, consensus over its maximum). A factor that is not "
    "known takes the configuration's value for unknown, and says so. Every finding's factors, weights and points "
    "are in `findings.json`; findings on entries that are not installed software get no score."
)


def priority_lines(summary: dict[str, Any], record: dict[str, Any] | None = None) -> list[str]:
    """The priority section: the bands, the configuration, and the ten highest findings with their reasons."""
    if not summary or not summary.get("scored"):
        return []
    record = record or {}
    weights = " · ".join(f"{n} {f['weight']:g}" for n, f in (record.get("factors") or {}).items())
    bands = " · ".join(f"{name} {n}" for name, n in summary["bands"].items())
    unknown = " · ".join(f"{n} {k}" for n, k in summary["unknown_factors"].items() if k)
    lines = [
        "",
        "## Priority (score 0–100, highest first)",
        "",
        f"{summary['scored']} findings on installed software · {bands}. Configuration: "
        f"{summary['config']['source']} (sha256 {summary['config']['sha256'][:12]}) · weights {weights or '?'}.",
    ]
    if unknown:
        lines.append(f"Factors not known, and taken at the configuration's value: {unknown}.")
    lines += ["", "| Rank | Score | Band | Vulnerability | Component | Why |", "|---:|---:|---|---|---|---|"]
    for t in summary["top"]:
        lines.append(
            f"| {t['rank']} | {t['score']} | {t['band']} | {t['vulnerability']} | `{t['component']}` | {t['why']} |"
        )
    return [*lines, "", PRIORITY_LEGEND]


def _pct(part: int, whole: int) -> str:
    return f"{part / whole:.0%}" if whole else "n/a"


def alias_lines(stats: dict[str, Any], provenance: dict[str, Any]) -> list[str]:
    """The alias-resolution paragraph: what was resolved, how, and what is left (design rule D1)."""
    if not stats.get("non_cve_ids"):
        return ["**Aliases:** every reported ID is a CVE."]
    s = stats["by_status"]
    left = stats["non_cve_ids"] - stats["resolved_to_cve"]
    text = (
        f"**Aliases:** {stats['non_cve_ids']} non-CVE IDs; {stats['resolved_to_cve']} resolved to CVEs "
        f"(OSV.dev {s['osv']}, scanner metadata {s['scanner']}); {stats['covering_several_cves']} advisories "
        f"cover several CVEs; {stats['cves_merged_as_aliases']} CVEs merged as aliases of another. "
        f"Left as reported: {left}"
    )
    labels = {"no_cve": "no CVE in OSV", "unknown_to_osv": "unknown to OSV", "not_looked_up": "not looked up"}
    reasons = [f"{label} {s[key]}" for key, label in labels.items() if s.get(key)]
    if reasons:
        text += f" ({', '.join(reasons)}; by namespace: "
        text += ", ".join(f"{p} {n}" for p, n in stats["unresolved_by_prefix"].items()) + ")"
    text += "."
    lines = [text]
    if provenance.get("source"):
        lookups = provenance.get("lookups") or {}
        dates = provenance.get("oldest_record_utc"), provenance.get("newest_record_utc")
        when = f", records fetched {dates[0][:10]} to {dates[1][:10]}" if all(dates) else ""
        mode = " (offline)" if provenance.get("offline") else ""
        lines += [
            "",
            f"Alias data: {provenance['source']}{mode}, {lookups.get('from_cache', 0)} from cache, "
            f"{lookups.get('fetched', 0)} fetched{when}.",
        ]
        if lookups.get("not_cached") or lookups.get("failed"):
            lines[-1] += f" Not available: {lookups.get('not_cached', 0) + lookups.get('failed', 0)}."
    elif provenance.get("method") == "scanner":
        lines += ["", "Alias data: scanner metadata only (`--aliases scanner`)."]
    elif provenance.get("method") == "recorded":
        origin = provenance.get("recorded_from") or {}
        dates = origin.get("oldest_record_utc"), origin.get("newest_record_utc")
        when = f", records fetched {dates[0][:10]} to {dates[1][:10]}" if all(dates) else ""
        source = origin.get("source") or origin.get("method") or "an earlier analysis"
        lines += ["", f"Alias data: the resolution this run recorded, replayed (`--aliases recorded`): {source}{when}."]
    return lines


LOCKFILE_LEGEND = (
    "*Locked*: a lockfile fixes every version, or the file is one (a requirements file whose requirements are all "
    "hashed, or that pip-compile or uv wrote). *Pinned*: every declared version is exact, but the transitive tree is "
    "resolved when the SBOM is generated, so only generators that run the build tool list it, and pip and npm can "
    "pick other versions next time. *Unlocked*: some declared versions are ranges, branches or missing. Lock the "
    "project, or scan the built artifact."
)


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|")


def lockfile_lines(check: dict[str, Any]) -> list[str]:
    """The dependency-manifests section (D5): what the target fixes, and what is resolved when its SBOM is made."""
    if not check:
        return []
    if check.get("status") != "checked":
        return ["", f"**Dependency manifests (D5):** {check['status']}."]
    manifests = check.get("manifests") or []
    if not manifests:
        return ["", "**Dependency manifests (D5):** none found in the target."]
    lines = [
        "",
        "## Dependency manifests (design rule D5)",
        "",
        "| Manifest | Ecosystem | Status | Lockfile | Declared | Not pinned to one version | Note |",
        "|---|---|---|---|---:|---|---|",
    ]
    for m in manifests:
        loose = m.get("not_exact") or []
        shown = ", ".join(loose[:3]) + (f", and {len(loose) - 3} more" if len(loose) > 3 else "")
        status = f"**{m['status']}**" if m["status"] in ("pinned", "unlocked") else m["status"]
        declared = m["declared"] if m.get("declared") is not None else "–"
        lines.append(
            f"| `{_cell(m['path'])}` | {m['ecosystem']} | {status} | {_cell(m.get('lockfile') or '–')} | {declared} "
            f"| {_cell(shown or '–')} | {_cell(m.get('note') or '')} |"
        )
    parts = []
    for purl_type, counts in (check.get("components") or {}).items():
        alone = [f"{g} alone {n}" for g, n in counts["by_one_generator"].items() if n]
        parts.append(f"{purl_type} {counts['components']}" + (f" ({', '.join(alone)})" if alone else ""))
    if parts:
        lines += ["", "Components of these ecosystems, and how many one generator alone lists: " + " · ".join(parts)]
    return [*lines, "", LOCKFILE_LEGEND]


METRICS_LEGEND = (
    "*As reported*: components keyed on each PURL as the tool wrote it, every entry with a PURL, vulnerability IDs "
    "as each scanner reported them. *Normalised*: aliases resolved (D1), canonical versions (D4), installed software "
    "only (D9), one component per jar (D11); a single pipeline with its own generator's evidence, the naive union "
    "and the fused pipeline with every generator's. The fused pipeline reads the SBOM ChainGuard wrote from the "
    "normalised inventory, so it exists only normalised: its counterpart as reported is the naive union. "
    "Direct-scan pairs: normalised, against the direct scans of the configuration's scanners. `summary.json` has "
    "every level, aliases resolved but identity as written in between; `chainguard.metrics` defines them."
)


def _jaccards(levels: dict[str, Any], path: tuple[str, ...], names: tuple[str, ...]) -> str:
    values = []
    for level in names:
        value: Any = levels.get(level, {}).get("agreement", {})
        for step in path:
            value = value.get(step) if isinstance(value, dict) else None
        values.append("–" if value is None else str(value))
    return " → ".join(values)


def metrics_lines(record: dict[str, Any]) -> list[str]:
    """The configurations as reported and normalised, and how much the tools agree at each level."""
    if not record or record.get("status") != "measured":
        return []
    levels = record["levels"]
    reported, normalised = levels["reported"]["configurations"], levels["normalised"]["configurations"]
    lines = [
        "",
        "## The configurations, as reported and normalised",
        "",
        "| Configuration | Components | Vulnerabilities | (Component, vulnerability) pairs "
        "| Direct-scan pairs reported |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, n in normalised.items():
        r = reported.get(name) or {}
        direct = n.get("direct")
        cells = " | ".join(f"{r.get(k, '–')} → {n[k]}" for k in ("components", "vulnerabilities", "pairs"))
        shown = f"**{name}**" if name == "fused" else name
        reach = f"{direct['reported']} of {direct['pairs']}" if direct else "–"
        lines.append(f"| {shown} | {cells} | {reach} |")
    agreement = []
    for key in (levels["normalised"].get("agreement") or {}).get("generators") or {}:
        a, b = key.split("|")
        jaccards = _jaccards(levels, ("generators", key, "jaccard"), ("reported", "normalised"))
        agreement.append(f"{a} and {b} on components {jaccards}")
    for head, pairs in ((levels["normalised"].get("agreement") or {}).get("scanners") or {}).items():
        for key in pairs:
            a, b = key.split("|")
            where = "the fused SBOM" if head == "fused" else f"{head}'s SBOM"
            agreement.append(
                f"{a} and {b} on {where} {_jaccards(levels, ('scanners', head, key, 'pairs', 'jaccard'), LEVEL_NAMES)}"
            )
    if agreement:
        lines += [
            "",
            "**Agreement**, Jaccard index (components; (component, vulnerability) pairs as reported → aliases resolved "
            "→ normalised): " + " · ".join(agreement),
        ]
    if record.get("formats_agree") is not None:
        lines.append(
            "The merged SBOM gives each scanner the same pairs in every format (D7): "
            + ("yes" if record["formats_agree"] else "**no**")
        )
    return [*lines, "", METRICS_LEGEND]


LEVEL_NAMES = ("reported", "aliases", "normalised")


HANDOFF_COLUMNS = {
    "misattributed": "Misattributed",
    "handoff": "Hand-off",
    "other_version": "Other version",
    "not_listed": "Not listed",
}


def handoff_lines(check: dict[str, Any]) -> list[str]:
    """The hand-off check section (D3): every SBOM pipeline against the same scanner's direct scan."""
    scanners, pipelines = check.get("scanners") or {}, check.get("pipelines") or {}
    if not scanners:
        return []
    checked = {p: v for p, v in pipelines.items() if v.get("status") == "checked"}
    if not checked:
        statuses = [v["status"] for v in (*scanners.values(), *pipelines.values()) if v["status"] != "checked"]
        reasons = sorted({s.removeprefix("not checked: ") for s in statuses})
        text = "not run: " + "; ".join(reasons)
        if "no direct scan" in reasons:
            text += ". Images get one by default; `--direct` adds one for a source project"
        return ["", f"**Hand-off check:** {text}."]
    lines = [
        "",
        "## Hand-off check (each SBOM pipeline against the same scanner's direct scan)",
        "",
        "| Pipeline | Reference pairs | Lost | " + " | ".join(HANDOFF_COLUMNS.values()) + " | Vulnerabilities lost "
        "| Beyond the reference |",
        "|---|---:|---:|" + "---:|" * len(HANDOFF_COLUMNS) + "---:|---:|",
    ]
    for p, v in checked.items():
        by = v["lost_by_class"]
        lost = f"**{v['lost']}**" if v["class"] == "fused" else str(v["lost"])
        beyond = str(v["beyond"]) + (
            f" ({v['beyond_not_installed']} not installed)" if v["beyond_not_installed"] else ""
        )
        lines.append(
            f"| {p} | {v['reference_pairs']} | {lost} | "
            + " | ".join(str(by.get(c, 0)) for c in HANDOFF_COLUMNS)
            + f" | {v['lost_vulnerabilities']} | {beyond} |"
        )
    skipped = [f"{s} ({v['status']})" for s, v in scanners.items() if v["status"] != "checked"]
    skipped += [f"{p} ({v['status']})" for p, v in pipelines.items() if v.get("status") != "checked"]
    lines += [
        "",
        "Pairs are (component, canonical vulnerability). A pair the direct scan reports and the pipeline does not "
        "is *misattributed* if the pipeline reports that vulnerability only on other components; a *hand-off* "
        "loss if the component is in the SBOM the scanner read, which design rule D3 makes zero; otherwise the "
        "SBOM lists the package at *another version*, or *not at all* (generator coverage). Every lost pair is "
        "in `handoff.json`.",
    ]
    if skipped:
        lines += ["", "Not checked: " + " · ".join(skipped)]
    if check.get("fused_lossless") is True:
        references = sorted({scanners[v["scanner"]]["reference"] for v in checked.values() if v["class"] == "fused"})
        lines += ["", f"**The fused SBOM is a lossless hand-off:** it loses nothing against {', '.join(references)}."]
    elif check.get("fused_lossless") is False:
        lines += ["", "**The fused SBOM lost findings a direct scan reports**; see the warnings."]
    return lines


def render_markdown(summary: dict[str, Any], manifest: dict[str, Any]) -> str:
    target, tools = manifest["target"], manifest["toolchain"]
    comp, vul = summary["components"], summary["vulnerabilities"]

    def tool_text(name: str, t: dict[str, Any]) -> str:
        pin_note = "" if t.get("matches_pin", True) else f" (pinned {t['pinned']})"
        return f"{name} {t.get('version') or 'missing'}{pin_note}"

    lines = [
        f"# ChainGuard scan — `{target['spec']}`",
        "",
        f"**Run** `{manifest['run_id']}` · target kind: {target['kind']} · ChainGuard {manifest['chainguard']}",
        "",
        "**Toolchain:** " + " · ".join(tool_text(name, t) for name, t in tools.items()),
    ]
    dbs = [
        f"{n} DB {t['database'].get('updated_at') or t['database'].get('built')}"
        for n, t in tools.items()
        if t.get("database")
    ]
    if dbs:
        lines += ["", "**Vulnerability databases:** " + " · ".join(dbs)]

    lines += [
        "",
        "## Components (unique canonical PURL keys)",
        "",
        "| Generator | Format | Entries | Components | Not software | Duplicate entries | No / invalid PURL "
        "| By type |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for gen, st in comp["per_generator"].items():
        by_type = ", ".join(f"{t} {n}" for t, n in st["by_type"].items())
        accepted = st.get("accepted_components", st["unique_components"])
        note = f" ({st['source_packages_suppressed']} source pkgs out)" if st.get("source_packages_suppressed") else ""
        lines.append(
            f"| {gen} | {st['format']} {st['spec_version']} | {st['entries']} | {accepted}{note} | "
            f"{sum((st.get('not_software') or {}).values())} | {st['duplicate_entries']} | "
            f"{st['no_purl']} / {st['invalid_purl']} | {by_type} |"
        )
    only = " · ".join(f"only {g}: {n}" for g, n in comp["only_in"].items())
    jac = " · ".join(f"Jaccard {pair.replace('|', ' vs ')}: {v}" for pair, v in comp["jaccard"].items())
    lines += [
        "",
        f"Union: **{comp['union']}** · found by every generator: {comp['found_by_all']} · {only}"
        + (f" · {jac}" if jac else ""),
    ]
    if comp.get("coordinates_merged") or comp.get("coordinates_undecided"):
        lines.append(
            f"One jar under two Maven groups (D11): {comp.get('coordinates_merged', 0)} key(s) merged into the "
            f"better-evidenced group; {comp.get('coordinates_undecided', 0)} left apart, where the evidence ties "
            "(`merged_keys` and `group_undecided_with` in inventory.json)"
        )
    if comp.get("version_spellings_merged"):
        lines.append(
            f"One version spelled two ways and merged (D4): {comp['version_spellings_merged']} component(s); "
            "`versions_reported` in inventory.json lists the spellings"
        )
    excluded = comp.get("not_installed") or {}
    entries = {g: sum(r.values()) for g, r in (excluded.get("not_software_entries") or {}).items()}
    if any(entries.values()) or excluded.get("source_packages_suppressed"):
        detail = " · ".join(
            f"{g} {n} ({', '.join(f'{k} {v}' for k, v in excluded['not_software_entries'][g].items())})"
            for g, n in entries.items()
            if n
        )
        lines += [
            "",
            "**Not installed software, left out of the inventory (D9):** entries that are not software: "
            + (detail or "none")
            + f" · source packages listed as installed: {excluded.get('source_packages_suppressed', 0)}",
        ]
        on = vul.get("on_not_installed") or {}
        if on:
            lines.append(
                "Findings that pipelines reported against them (kept, and marked `not_installed`): "
                + " · ".join(f"{p} {n}" for p, n in on.items())
            )

    lines += lockfile_lines(summary.get("lockfiles") or {})

    lines += [
        "",
        "## Vulnerabilities per pipeline (aliases resolved to CVE)",
        "",
        "| Pipeline | Findings | Distinct vulnerabilities | Share of union |",
        "|---|---:|---:|---:|",
    ]
    for p, st in vul["per_pipeline"].items():
        notes = {"direct": "reference", "fused": "fused"}
        share = notes.get(st.get("class", "single")) or _pct(st["distinct"], vul["union"])
        lines.append(f"| {p} | {st['findings']} | {st['distinct']} | {share} |")
    sev = " · ".join(f"{s.lower()} {n}" for s, n in vul["by_severity"].items() if n)
    lines += [
        "",
        f"Union of SBOM pipelines: **{vul['union']}** distinct vulnerabilities ({sev or 'none'}) · "
        f"reported by only one pipeline: {vul['reported_by_one_pipeline']} · by all: "
        f"{vul['reported_by_all_pipelines']} · missed by the best single pipeline: "
        f"{vul['missed_by_best_single_pipeline']}",
    ]

    lines += correlation_lines(summary.get("correlation") or {})
    lines += enrichment_lines(summary.get("enrichment") or {}, (manifest.get("analysis") or {}).get("enrichment"))
    lines += priority_lines(summary.get("priority") or {}, (manifest.get("analysis") or {}).get("priority"))

    fusion = summary.get("fusion")
    if fusion:
        fused = manifest.get("fused") or {}
        operating_system = fused.get("operating_system") or {}
        lines += [
            "",
            "## Fused SBOM (every generator merged into one document, then scanned)",
            "",
            f"{fused.get('components', '?')} components · operating system: "
            + (f"{operating_system.get('name')} {operating_system.get('version')}" if operating_system else "none")
            + f" · {fused.get('os_components_with_source', 0)} OS components carry their source package "
            f"· found by more than one generator: {fused.get('found_by_several_generators', 0)}",
            "",
            "| Pipeline | Distinct vulnerabilities |",
            "|---|---:|",
        ]
        for p, n in fusion["per_pipeline"].items():
            lines.append(f"| {p} | {n} |")
        lines += [
            "",
            f"Fused union: **{fusion['union']}** · naive union of the single pipelines: {fusion['naive_union']} · "
            f"only the fused SBOM reports {len(fusion['only_in_fused'])} · only the naive union reports "
            f"{len(fusion['only_in_naive_union'])} · Jaccard {fusion['jaccard']}",
        ]
        if len(fusion.get("by_format", {})) > 1:
            formats = " · ".join(f"{k} {v}" for k, v in fusion["by_format"].items())
            lines.append(f"Same inventory in each output format: {formats} (design rule D7: these must agree)")
        versus = fusion.get("versus_direct")
        if versus:
            lines.append(
                f"Against a direct scan ({versus['direct_union']} vulnerabilities): the fused SBOM misses "
                f"{versus['missed_by_fused']}, the naive union misses {versus['missed_by_naive_union']}"
            )

    lines += handoff_lines(summary.get("handoff") or {})

    # Supersedes the scanner-agreement table (raw IDs against aliases resolved), which summary.json keeps.
    lines += metrics_lines(summary.get("metrics") or {})
    lines += ["", *alias_lines(summary.get("aliases") or {}, (manifest.get("analysis") or {}).get("aliases") or {})]

    lines += ["", "## Steps", "", "| Step | Seconds | Result |", "|---|---:|---|"]
    for step in manifest["steps"]:
        lines.append(f"| {step['name']} | {step['seconds']} | {'ok' if step['ok'] else step['error']} |")
    # The scan's warnings, then the analysis's own (a reprocessed run replaces only the latter).
    warnings = [*(manifest.get("warnings") or []), *((manifest.get("analysis") or {}).get("warnings") or [])]
    if warnings:
        lines += ["", "**Warnings:** " + " · ".join(warnings)]
    lines += ["", "> No gate decision yet.", ""]
    return "\n".join(lines)


def render_console(summary: dict[str, Any]) -> str:
    comp, vul = summary["components"], summary["vulnerabilities"]
    per_gen = " · ".join(
        f"{g} {st.get('accepted_components', st['unique_components'])}" for g, st in comp["per_generator"].items()
    )
    lines = [
        f"Components     {per_gen} · union {comp['union']}",
        "",
        f"{'Pipeline':<18}{'Findings':>9}{'Distinct':>10}",
    ]
    for p, st in vul["per_pipeline"].items():
        lines.append(f"{p:<18}{st['findings']:>9}{st['distinct']:>10}")
    lines += [
        "",
        f"Union of SBOM pipelines: {vul['union']} distinct vulnerabilities · "
        f"{vul['reported_by_one_pipeline']} reported by only one pipeline",
    ]
    fusion = summary.get("fusion")
    if fusion:
        lines.append(
            f"Fused SBOM: {fusion['union']} distinct · {len(fusion['only_in_fused'])} that no single "
            f"pipeline reports · {len(fusion['only_in_naive_union'])} that it alone misses"
        )
    record = summary.get("metrics") or {}
    if record.get("status") == "measured":
        levels, parts = record["levels"], []
        for key in levels["normalised"]["agreement"].get("generators") or {}:
            parts.append(
                "generators on components "
                + _jaccards(levels, ("generators", key, "jaccard"), ("reported", "normalised"))
            )
        for head, pairs in (levels["normalised"]["agreement"].get("scanners") or {}).items():
            for key in pairs:
                parts.append(
                    f"scanners on {head} "
                    + _jaccards(levels, ("scanners", head, key, "pairs", "jaccard"), ("reported", "normalised"))
                )
        if parts:
            lines.append("Agreement as reported → normalised (Jaccard): " + " · ".join(parts))
    lockfiles = summary.get("lockfiles") or {}
    if lockfiles.get("status") == "checked" and lockfiles.get("manifests"):
        flagged = [m["path"] for m in lockfiles["manifests"] if m["status"] in ("pinned", "unlocked")]
        line = "Dependency manifests (D5): " + " · ".join(f"{n} {s}" for s, n in lockfiles["by_status"].items() if n)
        if flagged:
            more = f" and {len(flagged) - 4} more" if len(flagged) > 4 else ""
            line += " · not locked: " + ", ".join(flagged[:4]) + more
        lines.append(line)
    correlation = summary.get("correlation") or {}
    if correlation.get("pairs"):

        def spread(counts: dict[str, int]) -> str:
            return " · ".join(f"{k}: {n}" for k, n in counts.items())

        lines.append(
            f"Correlated: {correlation['pairs']} pairs on installed software · consensus, generators × scanners "
            f"(of {correlation['most_consensus']}): {spread(correlation['consensus'])} · single pipelines "
            f"reporting: {spread(correlation['pipelines_reporting'])}"
        )
    enrichment = summary.get("enrichment") or {}
    if enrichment.get("pairs"):
        known = sum(n for k, n in enrichment["depth"].items() if k != "unknown")
        lines.append(
            f"Enrichment: EPSS {enrichment['epss_snapshot'] or 'none'} · KEV {enrichment['kev_snapshot'] or 'none'} "
            f"· {enrichment['epss_scored']} of {enrichment['pairs']} pairs scored · {enrichment['kev_listed']} in KEV "
            f"· fix available for {enrichment['fix_available']['yes']} · depth known for {known}"
        )
    ranked = summary.get("priority") or {}
    if ranked.get("scored"):
        bands = " · ".join(f"{name} {n}" for name, n in ranked["bands"].items())
        top = ranked["top"][0]
        lines.append(
            f"Priority: {bands} · highest {top['vulnerability']} on {top['component']} ({top['score']}: {top['why']})"
        )
    on = vul.get("on_not_installed") or {}
    if on:
        lines.append(
            f"Findings on software that is not installed (files, source packages): {sum(on.values())} "
            f"across {len(on)} pipelines, marked in findings.json"
        )
    check = summary.get("handoff") or {}
    checked = {p: v for p, v in (check.get("pipelines") or {}).items() if v.get("status") == "checked"}
    if checked:
        verdict = {True: "; the fused SBOM loses nothing", False: "; THE FUSED SBOM LOST FINDINGS"}
        lines.append(
            "Hand-off check, pairs lost against the same scanner's direct scan"
            + verdict.get(check.get("fused_lossless"), "")
            + ":"
        )
        for scanner, ref in check["scanners"].items():
            mine = {p.split("+", 1)[0]: v["lost"] for p, v in checked.items() if v["scanner"] == scanner}
            if mine:
                text = " · ".join(f"{head} {n}" for head, n in mine.items())
                lines.append(f"  {ref['reference']:<14} ({ref['pairs']} pairs): {text}")
    elif check.get("scanners"):
        reasons = sorted({v["status"].removeprefix("not checked: ") for v in check["scanners"].values()})
        hint = "; images get one by default, or use --direct" if "no direct scan" in reasons else ""
        lines.append(f"Hand-off check: not run ({', '.join(reasons)}{hint})")
    stats = summary.get("aliases") or {}
    if stats.get("non_cve_ids"):
        unresolved = stats["non_cve_ids"] - stats["resolved_to_cve"]
        lines.append(
            f"Aliases: {stats['resolved_to_cve']} of {stats['non_cve_ids']} non-CVE IDs resolved to CVEs, "
            f"{unresolved} left as reported"
        )
    for item in summary["failed_steps"]:
        lines.append(f"FAILED  {item['name']}: {item['error']}")
    return "\n".join(lines)
