"""Orchestrate one scan run: every generator on the target, every scanner on every SBOM.

A run has two halves. ``scan`` executes the tools and keeps their output untouched in ``raw/``; the
analysis then derives everything else from those raw files. ``reprocess`` repeats only the analysis on an
existing run, so a change to normalisation can be measured on the same tool output, with nothing re-run.

Run directory layout::

    <out>/<run-id>/
        manifest.json   target, toolchain versions, DB snapshots, options, every step (command, time, result),
                        the target's dependency manifests and lockfiles (D5), and how the derived files were
                        produced (analysis, with its history)
        inventory.json  canonical components, with which generator found each one
        findings.json   normalised findings per pipeline, alias resolution, correlated (component, CVE) view
                        with each pair's enrichment (EPSS, KEV, CVSS, fix, depth) and priority, highest first
        handoff.json    every (component, vulnerability) pair each SBOM pipeline lost against the same
                        scanner's direct scan, with its class (chainguard.handoff)
        summary.json    the numbers in summary.md
        summary.md      human-readable report
        fused.*.json    the merged SBOM, in each format the fused pipeline was scanned in
        raw/            each tool's own output and log, untouched
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import platform
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chainguard import (
    __version__,
    aliases,
    correlate,
    enrich,
    handoff,
    lockfiles,
    merge,
    metrics,
    ospackage,
    priority,
    report,
    runner,
    sbom,
    toolchain,
)
from chainguard import target as targets
from chainguard.generators import EXTENSIONS, GENERATORS
from chainguard.runner import Step
from chainguard.scanners import SCANNERS, Finding

# "recorded" replays the resolution a run recorded in its findings.json: reprocess only, and the way to re-derive a
# run exactly as analysed, without OSV or a cache, since OSV's records change.
ALIAS_METHODS = ("osv", "scanner", "recorded")
# Target kinds a direct scan is run for by default: where the scanner reads the package database the image
# installed, which is cheap, offline, and settles what is installed.
DIRECT_BY_DEFAULT = ("image", "image-archive")


class ToolchainError(RuntimeError):
    """Required tools or vulnerability databases are missing, or pins are violated in strict mode."""


@dataclass
class ScanOptions:
    generators: tuple[str, ...] = ("syft", "cdxgen")
    scanners: tuple[str, ...] = ("trivy", "grype")
    sbom_format: str = "cyclonedx"
    # Also scan the target directly with each scanner: the reference the hand-off check compares every SBOM
    # pipeline with (chainguard.handoff). "auto" does so for container images only. A direct scan of a source
    # project is no reference for a hand-off: the scanner resolves the dependency tree itself, over the network
    # (Trivy fetches Maven POMs and is rate-limited by Maven Central), so it measures the scanner's resolver.
    direct: bool | str = "auto"
    fuse: bool = True  # merge every generator's output into one SBOM and scan that too (the fused pipeline)
    fuse_formats: tuple[str, ...] = ("cyclonedx", "spdx")  # write and scan the merged SBOM in these formats
    cdxgen_type: str | None = None  # cdxgen -t; None lets cdxgen auto-detect
    timeout: int = 1800  # seconds per tool invocation
    strict_pins: bool = False  # refuse to run if a tool version differs from toolchain.env

    def direct_for(self, target: targets.Target) -> bool:
        """Whether this run scans ``target`` directly as well."""
        if self.direct == "auto":
            return target.kind in DIRECT_BY_DEFAULT
        if isinstance(self.direct, bool):
            return self.direct
        raise ValueError(f"direct must be 'auto', True or False, not {self.direct!r}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "generators": list(self.generators),
            "scanners": list(self.scanners),
            "sbom_format": self.sbom_format,
            "direct": self.direct,
            "fuse": self.fuse,
            "fuse_formats": list(self.fuse_formats),
            "cdxgen_type": self.cdxgen_type,
            "timeout": self.timeout,
            "strict_pins": self.strict_pins,
        }


@dataclass
class AnalysisOptions:
    """How raw tool output becomes findings. Changing these never requires re-running a tool."""

    # "osv": OSV.dev + scanner metadata (D1); "scanner": scanner metadata only (v0 rule); "recorded": the run's own
    # recorded resolution, replayed (reprocess only)
    aliases: str = "osv"
    alias_cache: Path | None = None  # default: aliases.default_cache_dir()
    alias_offline: bool = False  # never query OSV; IDs missing from the cache stay unresolved, and are counted
    alias_refresh: bool = False  # query OSV again even for cached IDs
    # Leave out of the inventory what is not installed software: entries of non-software kinds, and source
    # packages listed as if installed (D9). False keeps every entry, for comparison.
    component_filter: bool = True
    # One component for a jar that generators list under different Maven groups (D11). False keeps every key.
    maven_coordinates: bool = True
    # EPSS and KEV from dated snapshots in the store, written by `chainguard db update`, plus CVSS, fix availability
    # and dependency depth (chainguard.enrich). A version of None means the newest snapshot; reprocess keeps the ones
    # the run used while the store has them.
    enrichment: bool = True
    enrichment_dir: Path | None = None  # default: enrich.default_dir()
    epss: str | None = None  # the date of the EPSS scores (YYYY-MM-DD)
    kev: str | None = None  # the KEV catalog version (YYYY.MM.DD)
    # Weights and bands of the priority score (chainguard.priority); None: the packaged priority.yaml
    priority_config: Path | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "aliases": self.aliases,
            "component_filter": self.component_filter,
            "maven_coordinates": self.maven_coordinates,
            "enrichment": self.enrichment,
            "enrichment_dir": str(self.enrichment_dir) if self.enrichment_dir else None,
            "epss": self.epss,
            "kev": self.kev,
            "priority_config": str(self.priority_config) if self.priority_config else None,
            "alias_cache": str(self.alias_cache) if self.alias_cache else None,
            "alias_offline": self.alias_offline,
            "alias_refresh": self.alias_refresh,
        }


@dataclass
class ScanResult:
    run_dir: Path
    ok: bool
    summary: dict[str, Any]
    warnings: list[str] = field(default_factory=list)


def check_toolchain(options: ScanOptions, needs_docker: bool) -> tuple[dict[str, toolchain.ToolStatus], list[str]]:
    """Detect every tool the run needs. Raises ToolchainError on blocking problems; returns warnings."""
    tools = {name: toolchain.detect(name) for name in (*options.generators, *options.scanners)}
    problems = [f"{name}: {status.error}" for name, status in tools.items() if status.error]
    warnings = [
        f"{name} {status.version} differs from pinned {status.pinned}"
        for name, status in tools.items()
        if status.installed and not status.matches_pin
    ]
    if needs_docker and shutil.which("docker") is None:
        problems.append("docker: not found on PATH (needed to save image:<ref> targets)")
    if options.strict_pins and warnings:
        problems += [f"{w} (--strict-pins)" for w in warnings]
    if problems:
        raise ToolchainError("\n".join(problems))
    return tools, warnings


def _run_dir(out_root: Path, started: datetime, target: targets.Target) -> Path:
    label = target.image or (target.path.name if target.path else "target")
    label = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-")[:60] or "target"
    base = out_root / f"{started:%Y%m%dT%H%M%SZ}-{label}"
    run_dir, n = base, 1
    while run_dir.exists():
        n += 1
        run_dir = base.with_name(f"{base.name}-{n}")
    (run_dir / "raw").mkdir(parents=True)
    return run_dir


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_sbom(run_dir: Path, step: Step, filter_kinds: bool = True) -> sbom.ParsedSbom | None:
    """The SBOM a successful generate step wrote, or None (and the step marked failed) if it is unreadable."""
    try:
        return sbom.load(run_dir / (step.output or ""), filter_kinds=filter_kinds)
    except sbom.SbomError as exc:
        step.error = str(exc)
        return None


def _load_findings(run_dir: Path, step: Step) -> list[Finding]:
    """The findings a successful scan step wrote; an unreadable report marks the step failed."""
    scanner = step.name.split("+", 1)[1]
    try:
        return list(SCANNERS[scanner].parse(json.loads((run_dir / (step.output or "")).read_text()), step.name))
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        step.error = f"unreadable report: {exc}"
        return []


@dataclass
class Analysis:
    """Everything derived from a run's raw outputs. Producing one writes nothing to disk."""

    sboms: dict[str, sbom.ParsedSbom]
    findings: list[Finding]
    inventory: dict[str, correlate.InventoryEntry]
    correlated: list[correlate.CorrelatedFinding]
    resolution: aliases.Resolution
    summary: dict[str, Any]
    record: dict[str, Any]  # for the manifest: version, options, alias provenance and statistics, warnings
    suppressed: dict[str, dict[str, Any]] = field(default_factory=dict)  # source packages listed as installed
    not_installed: dict[str, str] = field(default_factory=dict)  # every key that is not installed software
    handoff: dict[str, Any] = field(default_factory=dict)  # per pipeline: every pair lost against direct, classed


@dataclass
class RunData:
    """A finished run as read back from disk: its manifest, steps, parsed SBOMs and parsed findings."""

    run_dir: Path
    manifest: dict[str, Any]
    steps: list[Step]
    sboms: dict[str, sbom.ParsedSbom]  # each generator's own SBOM
    findings: list[Finding]
    # The merged SBOMs ChainGuard wrote and scanned, by pipeline head ("fused", "fused-spdx"). Kept apart from
    # ``sboms``: they are derived from the generators' output, so counting them again would double every entry.
    fused: dict[str, sbom.ParsedSbom] = field(default_factory=dict)


def fused_documents(manifest: dict[str, Any]) -> dict[str, str]:
    """Pipeline head -> the merged SBOM (relative to the run directory) that the pipeline's scanners read."""
    fused = manifest.get("fused") or {}
    if fused.get("sboms"):
        return dict(fused["sboms"])
    # Runs from before the heads were recorded: the head follows the format, as scan() names it.
    requested = (manifest.get("options") or {}).get("sbom_format", "cyclonedx")
    return {"fused" if fmt == requested else f"fused-{fmt}": path for fmt, path in (fused.get("formats") or {}).items()}


def load_run(run_dir: Path, *, filter_kinds: bool = True) -> RunData:
    """Read a run directory's raw outputs back, exactly as the scan parsed them. Executes nothing."""
    run_dir = run_dir.resolve()
    try:
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise targets.TargetError(f"{run_dir}: not a ChainGuard run directory ({exc})") from exc
    steps = [Step.from_dict(s) for s in manifest.get("steps") or []]
    sboms: dict[str, sbom.ParsedSbom] = {}
    findings: list[Finding] = []
    for step in steps:
        if not step.ok or not step.output:
            continue
        if step.kind == "generate":
            parsed = _load_sbom(run_dir, step, filter_kinds)
            if parsed is not None:
                sboms[step.name] = parsed
        elif step.kind == "scan":
            findings.extend(_load_findings(run_dir, step))
    fused: dict[str, sbom.ParsedSbom] = {}
    for head, path in fused_documents(manifest).items():
        # If it is unreadable, the hand-off check reports the pipelines that read it as not checked.
        with contextlib.suppress(sbom.SbomError):
            fused[head] = sbom.load(run_dir / path, filter_kinds=filter_kinds)
    return RunData(run_dir, manifest, steps, sboms, findings, fused)


def analyze(
    sboms: dict[str, sbom.ParsedSbom],
    findings: list[Finding],
    steps: list[Step],
    options: AnalysisOptions,
    fused: dict[str, sbom.ParsedSbom] | None = None,
    survey: dict[str, Any] | None = None,
    recorded: aliases.Resolution | None = None,
) -> Analysis:
    """Resolve aliases, merge, correlate, and check every hand-off and lockfile. Sets canonical IDs on ``findings``
    in place; writes nothing. ``fused`` holds the merged SBOMs the fused pipelines read (``RunData.fused``), and
    ``survey`` the target's dependency manifests as the scan found them (``lockfiles.survey``). With
    ``aliases="recorded"``, ``recorded`` is the resolution the run recorded, applied instead of resolving again."""
    if options.aliases not in ALIAS_METHODS:
        raise ValueError(f"unknown alias method {options.aliases!r}; choose from {', '.join(ALIAS_METHODS)}")
    osv = None
    if options.aliases == "recorded":
        if recorded is None:
            raise ValueError("aliases='recorded' replays a run's recorded resolution, which only reprocess has")
        resolution = recorded
        resolution.apply(findings)
    else:
        if options.aliases == "osv":
            osv = aliases.OsvCache(options.alias_cache, offline=options.alias_offline, refresh=options.alias_refresh)
        resolution = aliases.resolve(findings, osv)
    inventory, suppressed = correlate.canonical_inventory(
        sboms, suppress_source_packages=options.component_filter, maven_coordinates=options.maven_coordinates
    )
    # A finding on a key merged into another component is a finding on that component (D11).
    merged = correlate.key_aliases(inventory)
    for f in findings:
        f.component = merged.get(f.component, f.component)
    not_installed = correlate.non_components(sboms, inventory, suppressed)
    correlated = correlate.correlate(findings, not_installed, inventory)  # direct scans are references only
    summary = report.summarize(sboms, inventory, findings, correlated, resolution, steps, suppressed, not_installed)
    enrichment, enrichment_warnings = None, []
    if options.enrichment:
        store = options.enrichment_dir or enrich.default_dir()
        epss, kev = enrich.select("epss", store, options.epss), enrich.select("kev", store, options.kev)
        summary["enrichment"] = enrich.enrich(correlated, inventory, resolution, epss=epss, kev=kev)
        enrichment = enrich.provenance(epss, kev, {"epss": options.epss, "kev": options.kev})
        for kind, snapshot, name in (("epss", epss, "EPSS"), ("kev", kev, "KEV")):
            if snapshot is None:
                asked = getattr(options, kind)
                what = f"the {name} snapshot {asked} is not" if asked else f"no {name} snapshot is"
                enrichment_warnings.append(
                    f"{what} in {store}: findings carry no {name} data (run: chainguard db update)"
                )
    # The priority score: every correlated finding on installed software, ranked; findings.json keeps that order.
    config = priority.load(options.priority_config)
    correlated, summary["priority"] = priority.prioritize(correlated, config, summary["correlation"]["most_consensus"])
    # Each pipeline is judged against the document its scanner read: a generator's SBOM, or the merged one.
    summary["handoff"], lost = handoff.check(findings, {**sboms, **(fused or {})}, steps, not_installed, merged)
    summary["lockfiles"] = lockfiles.summarize(survey, inventory)
    # The configurations as the tools reported them and as normalised: no reference here, so no coverage.
    summary["metrics"] = metrics.measure(
        sboms,
        fused or {},
        findings,
        steps,
        inventory,
        not_installed,
        resolution,
        suppress_source_packages=options.component_filter,
        maven_coordinates=options.maven_coordinates,
    )
    record = {
        "chainguard": __version__,
        "analysed_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "options": options.as_dict(),
        "aliases": {"method": options.aliases, **(osv.provenance() if osv else {}), **resolution.stats()},
    }
    if options.aliases == "recorded":
        # IDs the record does not cover stay as reported: on a run's own raw output there are none.
        missing = sorted({f.raw_id for f in findings if not aliases.is_cve(f.raw_id)} - set(resolution.detail))
        record["aliases"]["not_in_record"] = len(missing)
    if enrichment is not None:
        record["enrichment"] = enrichment
    record["priority"] = config.as_record()
    # Warnings the analysis raised. Kept apart from the scan's own, so a reprocessed run replaces them.
    warnings = []
    if record["aliases"].get("cache_write_error"):
        warnings.append(f"alias cache not written: {record['aliases']['cache_write_error']}")
    record["warnings"] = (
        warnings + enrichment_warnings + summary["handoff"]["warnings"] + lockfiles.warnings(summary["lockfiles"])
    )
    return Analysis(
        sboms, findings, inventory, correlated, resolution, summary, record, suppressed, not_installed, lost
    )


def _write_analysis(run_dir: Path, result: Analysis) -> None:
    _write_json(
        run_dir / "inventory.json",
        {
            "schema": "chainguard.inventory/v1",
            "generators": {g: s.stats() for g, s in result.sboms.items()},
            "components": [entry.as_dict() for entry in result.inventory.values()],
            # OS entries left out because they are another component's source package (D9), with the evidence
            "suppressed": [{"key": k, **v} for k, v in sorted(result.suppressed.items())],
        },
    )
    _write_json(
        run_dir / "findings.json",
        {
            # v2: correlated entries carry per-scanner claims, and consensus counts evidence (D10). v3: they carry
            # their enrichment, and no longer a top-level EPSS and KEV merged from the scanners' claims
            "schema": "chainguard.findings/v3",
            "aliases": result.resolution.as_dict(),
            "findings": sorted(
                (f.as_dict() for f in result.findings),
                key=lambda d: (d["pipeline"], d["vulnerability"], d["component"]),
            ),
            "correlated": [c.as_dict() for c in result.correlated],
        },
    )
    _write_json(
        run_dir / "handoff.json",
        {
            "schema": "chainguard.handoff/v1",
            "classes": list(handoff.CLASSES),
            "summary": result.summary.get("handoff") or {},
            "pipelines": result.handoff,
        },
    )
    _write_json(run_dir / "summary.json", result.summary)


def _keep_snapshots(manifest: dict[str, Any], options: AnalysisOptions) -> tuple[AnalysisOptions, list[str]]:
    """Options that enrich with the snapshots the run's last analysis used, where none is asked for and the store
    still has them, so that reprocessing a run does not silently change its EPSS and KEV values."""
    if not options.enrichment:
        return options, []
    used = ((manifest.get("analysis") or {}).get("enrichment")) or {}
    store = options.enrichment_dir or enrich.default_dir()
    keep, notes = {}, []
    for kind in enrich.KINDS:
        version = (used.get(kind) or {}).get("version")
        if getattr(options, kind) is not None or not version:
            continue
        if enrich.select(kind, store, version):
            keep[kind] = version
        else:
            notes.append(f"the {kind.upper()} snapshot this run used ({version}) is not in {store}: the newest is used")
    return dataclasses.replace(options, **keep), notes


def reprocess(run_dir: Path, options: AnalysisOptions | None = None) -> ScanResult:
    """Derive a finished run's inventory, findings, hand-off check and summary again from its raw outputs.
    Runs no tool.

    The manifest keeps every earlier analysis in ``analysis_history``, so it stays visible that the derived
    files were rewritten, by which ChainGuard version and with which options.
    """
    options = options or AnalysisOptions()
    run = load_run(run_dir, filter_kinds=options.component_filter)
    recorded = None
    if options.aliases == "recorded":
        try:
            recorded = aliases.Resolution.from_dict(
                json.loads((run.run_dir / "findings.json").read_text(encoding="utf-8"))["aliases"]
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise targets.TargetError(f"{run.run_dir}: no recorded alias resolution to replay ({exc})") from exc
    # The survey is part of the scan's record: the target may have changed since, so it is never taken again.
    survey = run.manifest.get("dependency_manifests")
    if survey is None and (run.manifest.get("target") or {}).get("kind") not in (None, "directory"):
        survey = lockfiles.not_applicable()
    options, notes = _keep_snapshots(run.manifest, options)
    result = analyze(run.sboms, run.findings, run.steps, options, run.fused, survey, recorded)
    result.record["warnings"] = notes + result.record["warnings"]
    manifest = run.manifest
    if recorded is not None:  # say where the replayed resolution came from, through any earlier replays
        before = (manifest.get("analysis") or {}).get("aliases") or {}
        origin = before.get("recorded_from") or {
            k: before.get(k) for k in ("method", "source", "oldest_record_utc", "newest_record_utc")
        }
        result.record["aliases"]["recorded_from"] = origin
    _write_analysis(run.run_dir, result)
    previous = manifest.get("analysis") or {"chainguard": manifest.get("chainguard"), "options": None}
    manifest.setdefault("analysis_history", []).append(previous)  # options None: written before analyses were recorded
    manifest["schema"] = "chainguard.manifest/v1"
    manifest["analysis"] = result.record
    manifest["steps"] = [s.as_dict() for s in run.steps]
    _write_json(run.run_dir / "manifest.json", manifest)
    (run.run_dir / "summary.md").write_text(report.render_markdown(result.summary, manifest), encoding="utf-8")
    ok = all(s.ok for s in run.steps)
    warnings = [*(manifest.get("warnings") or []), *result.record["warnings"]]
    return ScanResult(run_dir=run.run_dir, ok=ok, summary=result.summary, warnings=warnings)


def scan(
    target_spec: str,
    out_root: Path,
    options: ScanOptions,
    progress: Callable[[Step], None] | None = None,
    analysis: AnalysisOptions | None = None,
) -> ScanResult:
    started = datetime.now(UTC)
    analysis = analysis or AnalysisOptions()  # also decides how SBOMs are parsed, so it is settled first
    if analysis.aliases == "recorded":
        raise ValueError("aliases='recorded' replays an earlier analysis: use it with reprocess, not scan")
    priority.load(analysis.priority_config)  # a bad configuration fails before any tool runs
    target = targets.resolve(target_spec)
    # Before any tool runs: generators run build tools, which write into the target (D5).
    survey = lockfiles.survey(target.path) if target.is_directory and target.path else lockfiles.not_applicable()
    tools, warnings = check_toolchain(options, needs_docker=target.kind == "image")
    environment = toolchain.environment()
    generator_env: dict[str, dict[str, str]] = {}
    if (
        "cdxgen" in options.generators
        and target.is_directory
        and target.path
        and toolchain.has_python_manifest(target.path)
    ):
        generator_env["cdxgen"], note = toolchain.cdxgen_python_env(environment)
        if note:
            warnings.append(note)
    run_dir = _run_dir(out_root.resolve(), started, target)
    steps: list[Step] = []

    def execute(step: Step) -> Step:
        runner.run(step, run_dir, timeout=options.timeout)
        steps.append(step)
        if progress:
            progress(step)
        return step

    sboms: dict[str, sbom.ParsedSbom] = {}
    findings: list[Finding] = []
    ready = True
    if target.kind == "image":
        archive = run_dir / "raw" / "image.tar"
        save = execute(
            Step(
                "save-image",
                "prepare",
                ["docker", "save", "-o", str(archive), target.image or ""],
                log="raw/save-image.log",
                output="raw/image.tar",
            )
        )
        ready = save.ok
        if ready:
            target.path = archive
            target.info.update({"image_id": targets.image_id(target.image or ""), "sha256": targets.sha256(archive)})

    sbom_paths: dict[str, Path] = {}
    for name in options.generators if ready else ():
        generator = GENERATORS[name]
        fmt = generator.output_format(options.sbom_format)
        if fmt != options.sbom_format:
            warnings.append(f"{name} cannot emit {options.sbom_format}; it emitted {fmt}")
        output = run_dir / "raw" / f"{name}.{EXTENSIONS[fmt]}"
        step = execute(
            Step(
                name,
                "generate",
                generator.command(target, output, fmt, options.cdxgen_type),
                log=f"raw/{name}.log",
                output=str(output.relative_to(run_dir)),
                env=generator_env.get(name, {}),
            )
        )
        if step.ok:
            parsed = _load_sbom(run_dir, step, analysis.component_filter)
            if parsed is not None:
                sboms[name] = parsed
                sbom_paths[name] = output
                if not parsed.components:
                    # An empty SBOM scans clean, so a gate would silently pass the build. Never stay quiet.
                    warnings.append(f"{name} exited 0 but its SBOM lists no components; check {step.log}")

    jobs = [
        (f"{g}+{s}", s, SCANNERS[s].sbom_command(path, run_dir / "raw" / f"{g}.{s}.json"), f"raw/{g}.{s}.json")
        for g, path in sbom_paths.items()
        for s in options.scanners
    ]
    # The fused pipeline: one SBOM merged from every generator's output, scanned by every scanner (D3, D7).
    fused_stats: dict[str, Any] = {}
    fused: dict[str, sbom.ParsedSbom] = {}  # pipeline head -> the merged document its scanners read
    if options.fuse and sboms:
        inventory, suppressed = correlate.canonical_inventory(
            sboms, suppress_source_packages=analysis.component_filter, maven_coordinates=analysis.maven_coordinates
        )
        operating_systems = [os_ for parsed in sboms.values() for os_ in parsed.operating_systems]
        label = target.image or (target.path.name if target.path else "target")
        fused_stats = merge.stats(inventory, operating_systems)
        fused_stats["source_packages_suppressed"] = len(suppressed)
        fused_stats["formats"], fused_stats["sboms"] = {}, {}
        for fmt in options.fuse_formats:
            writer = merge.cyclonedx if fmt == "cyclonedx" else merge.spdx
            document = writer(inventory, operating_systems, target=label, generators=sorted(sboms))
            path = run_dir / f"fused.{EXTENSIONS[fmt]}"
            _write_json(path, document)
            name = "fused" if fmt == options.sbom_format else f"fused-{fmt}"
            fused_stats["formats"][fmt] = fused_stats["sboms"][name] = str(path.relative_to(run_dir))
            fused[name] = sbom.parse(document, source=str(path), filter_kinds=analysis.component_filter)
            for scanner in options.scanners:
                output = f"raw/{name}.{scanner}.json"
                command = SCANNERS[scanner].sbom_command(path, run_dir / output)
                jobs.append((f"{name}+{scanner}", scanner, command, output))
        if not fused_stats["operating_system"] and any(p.type in ospackage.OS_TYPES for p in inventory.values()):
            # Without it a scanner cannot pick a vulnerability source, so never let it pass unnoticed.
            warnings.append("the merged SBOM has OS packages but no operating-system component could be determined")
    if options.direct_for(target) and ready:
        jobs += [
            (
                f"direct+{s}",
                s,
                SCANNERS[s].direct_command(target, run_dir / "raw" / f"direct.{s}.json"),
                f"raw/direct.{s}.json",
            )
            for s in options.scanners
        ]
    for pipeline, _scanner, command, output in jobs:
        step = execute(
            Step(pipeline, "scan", command, log=f"raw/{pipeline}.log", output=output, env=dict(toolchain.SCAN_ENV))
        )
        if step.ok:
            findings.extend(_load_findings(run_dir, step))

    result = analyze(sboms, findings, steps, analysis, fused, survey)
    _write_analysis(run_dir, result)
    summary, record = result.summary, result.record
    manifest = {
        "schema": "chainguard.manifest/v1",
        "chainguard": __version__,
        "run_id": run_dir.name,
        "started_utc": started.isoformat(timespec="seconds"),
        "finished_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "target": target.as_dict(),
        "options": options.as_dict(),
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "toolchain": {name: status.as_dict() for name, status in tools.items()},
        "environment": environment,
        "warnings": warnings,
        "steps": [s.as_dict() for s in steps],
        "dependency_manifests": survey,
        "fused": fused_stats,
        "analysis": record,
    }
    _write_json(run_dir / "manifest.json", manifest)
    (run_dir / "summary.md").write_text(report.render_markdown(summary, manifest), encoding="utf-8")
    ok = all(s.ok for s in steps)
    return ScanResult(run_dir=run_dir, ok=ok, summary=summary, warnings=[*warnings, *record["warnings"]])
