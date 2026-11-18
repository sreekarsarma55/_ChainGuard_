"""Command-line interface: ``chainguard scan | reprocess | gate | report | tools | db update | sbom … | version``.

Exit codes: 0 success (a gate that passes or warns), 1 failure (a failed tool step, or a gate that fails),
2 usage (bad arguments, a target or policy that cannot be read, a toolchain that is not ready)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from chainguard import __version__, enrich, policy, priority, reports, sbom, toolchain
from chainguard.generators import GENERATORS
from chainguard.merge import merge_documents
from chainguard.pipeline import ALIAS_METHODS, AnalysisOptions, ScanOptions, ToolchainError, reprocess, scan
from chainguard.repair import repair
from chainguard.runner import Step
from chainguard.scanners import SCANNERS
from chainguard.target import TargetError

EXIT_OK, EXIT_FAILED, EXIT_USAGE = 0, 1, 2


def _names(value: str, known: dict, what: str) -> tuple[str, ...]:
    names = tuple(n.strip() for n in value.split(",") if n.strip())
    unknown = [n for n in names if n not in known]
    if unknown or not names:
        raise argparse.ArgumentTypeError(
            f"unknown {what}: {', '.join(unknown) or '(none)'}; choose from {', '.join(known)}"
        )
    return names


def _progress(step: Step) -> None:
    mark = "ok  " if step.ok else "FAIL"
    detail = step.output if step.ok else step.error
    print(f"  [{mark}] {step.name:<16} {step.seconds:>7.1f} s  {detail}", file=sys.stderr)


def _analysis(args: argparse.Namespace) -> AnalysisOptions:
    return AnalysisOptions(
        aliases=args.aliases,
        alias_cache=Path(args.alias_cache) if args.alias_cache else None,
        alias_offline=args.offline,
        alias_refresh=args.refresh_aliases,
        component_filter=args.component_filter,
        enrichment=args.enrichment,
        epss=args.epss,
        kev=args.kev,
        priority_config=Path(args.priority_config) if args.priority_config else None,
    )


def cmd_scan(args: argparse.Namespace) -> int:
    options = ScanOptions(
        generators=args.generators,
        scanners=args.scanners,
        sbom_format=args.sbom_format,
        direct=args.direct,
        fuse=args.fuse,
        cdxgen_type=args.cdxgen_type,
        timeout=args.timeout,
        strict_pins=args.strict_pins,
    )
    if args.aliases == "recorded":
        print("error: --aliases recorded replays an earlier analysis; use it with reprocess", file=sys.stderr)
        return EXIT_USAGE
    rules = None
    if args.gate or args.policy:
        try:  # before any tool runs: a policy that cannot be read fails the job now, not after the scan
            rules = policy.load(args.policy, _on(args))
        except (policy.PolicyError, ValueError) as exc:
            print(f"error: policy: {exc}", file=sys.stderr)
            return EXIT_USAGE
    print(f"ChainGuard {__version__}: scanning {args.target}", file=sys.stderr)
    try:
        result = scan(args.target, Path(args.out), options, progress=_progress, analysis=_analysis(args))
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ToolchainError as exc:
        print("error: toolchain not ready:\n  " + str(exc).replace("\n", "\n  "), file=sys.stderr)
        return EXIT_USAGE
    except priority.ConfigError as exc:
        print(f"error: priority configuration: {exc}", file=sys.stderr)
        return EXIT_USAGE
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    from chainguard.report import render_console

    print()
    print(render_console(result.summary))
    print(f"\nResults: {result.run_dir}  (summary.md, manifest.json, inventory.json, findings.json, handoff.json)")
    if rules is not None:  # the gate decides; a failed tool step is one of its integrity checks
        return _gate(result.run_dir, rules, args)
    return EXIT_OK if result.ok else EXIT_FAILED


def _on(args: argparse.Namespace) -> date | None:
    return date.fromisoformat(args.on) if getattr(args, "on", None) else None


def _gate(run_dir: Path, rules: policy.Policy, args: argparse.Namespace) -> int:
    try:
        verdict = policy.evaluate(run_dir, rules)
    except policy.PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    path = policy.write(run_dir, verdict)
    print()
    print(policy.render(verdict))
    print(f"Verdict: {path}")
    if args.reports and _reports(run_dir, args) != EXIT_OK:
        return EXIT_USAGE
    return policy.EXIT[verdict["decision"]]


def _reports(run_dir: Path, args: argparse.Namespace) -> int:
    """Write report.sarif, report.json and report.md (into the run, unless told otherwise); with --job-summary,
    append report.md to the file GitHub Actions names in $GITHUB_STEP_SUMMARY."""
    try:
        paths = reports.write_all(
            run_dir,
            sarif_path=Path(args.sarif) if args.sarif else None,
            include_all=args.sarif_all,
            location=args.location,
        )
    except reports.ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(f"Reports: {paths['sarif']} · {paths['json']} · {paths['markdown']}")
    if args.job_summary:
        target = os.environ.get("GITHUB_STEP_SUMMARY")
        if not target:
            print(
                "warning: --job-summary: $GITHUB_STEP_SUMMARY is not set; report.md was not appended", file=sys.stderr
            )
        else:
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(paths["markdown"].read_text(encoding="utf-8") + "\n")
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    return _reports(Path(args.run), args)


def cmd_gate(args: argparse.Namespace) -> int:
    try:
        rules = policy.load(args.policy, _on(args))
    except (policy.PolicyError, ValueError) as exc:
        print(f"error: policy: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return _gate(Path(args.run), rules, args)


def cmd_reprocess(args: argparse.Namespace) -> int:
    from chainguard.report import render_console

    status = EXIT_OK
    for run in args.runs:
        try:
            result = reprocess(Path(run), _analysis(args))
        except priority.ConfigError as exc:
            print(f"error: priority configuration: {exc}", file=sys.stderr)
            return EXIT_USAGE
        except TargetError as exc:
            print(f"error: {exc}", file=sys.stderr)
            status = EXIT_USAGE
            continue
        print(f"\n{result.run_dir}")
        print(render_console(result.summary))
    return status


def _add_analysis_arguments(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("alias resolution (design rule D1)")
    g.add_argument(
        "--aliases",
        choices=ALIAS_METHODS,
        default="osv",
        help="resolve non-CVE IDs through OSV.dev plus scanner metadata, or scanner metadata only; reprocess can "
        "replay the resolution the run recorded (recorded), without OSV or a cache (default: %(default)s)",
    )
    g.add_argument("--alias-cache", help="OSV cache directory (default: $CHAINGUARD_CACHE or ~/.cache/chainguard)")
    g.add_argument(
        "--offline", action="store_true", help="never query OSV: use the cache, and count IDs it does not have"
    )
    g.add_argument("--refresh-aliases", action="store_true", help="query OSV again even for cached IDs")
    g = p.add_argument_group("component identity (design rule D9)")
    g.add_argument(
        "--keep-all-entries",
        dest="component_filter",
        action="store_false",
        help="keep entries that are not installed software (file and data entries, source packages listed as "
        "installed) in the inventory",
    )
    g = p.add_argument_group("enrichment (EPSS and KEV snapshots from 'chainguard db update')")
    g.add_argument("--epss", metavar="DATE", help="EPSS snapshot to use, by the date of its scores (default: newest)")
    g.add_argument("--kev", metavar="VERSION", help="KEV catalog version to use, e.g. 2026.10.30 (default: newest)")
    g.add_argument("--no-enrichment", dest="enrichment", action="store_false", help="do not enrich the findings")
    g = p.add_argument_group("priority score")
    g.add_argument(
        "--priority-config", metavar="YAML", help="weights and bands of the priority score (default: priority.yaml)"
    )


def _add_gate_arguments(p: argparse.ArgumentParser, *, with_switch: bool) -> None:
    g = p.add_argument_group("gate (policy engine)")
    if with_switch:
        g.add_argument(
            "--gate",
            action="store_true",
            help="judge the run against the policy and exit with the gate's code (implied by --policy)",
        )
    g.add_argument("--policy", metavar="YAML", help="the policy (default: the packaged policy.yaml)")
    g.add_argument("--on", metavar="DATE", help="evaluate exceptions as of this date (default: today, UTC)")
    g.add_argument("--no-reports", dest="reports", action="store_false", help="write only verdict.json")
    _add_report_arguments(p)


def _add_report_arguments(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("reports (SARIF, JSON, job summary)")
    g.add_argument("--sarif", metavar="PATH", help="where to write the SARIF log (default: <run>/report.sarif)")
    g.add_argument(
        "--sarif-all", action="store_true", help="every finding in the SARIF log, not only those the policy acts on"
    )
    g.add_argument(
        "--location",
        metavar="FILE",
        help="the repository file results point at when the target has no manifest, e.g. an image's Dockerfile",
    )
    g.add_argument(
        "--job-summary", action="store_true", help="append report.md to $GITHUB_STEP_SUMMARY (GitHub Actions)"
    )


def cmd_tools(_: argparse.Namespace) -> int:
    ok = True
    print(f"{'Tool':<8}{'Installed':<12}{'Pinned':<10}{'Status':<10}Vulnerability DB")
    for name in (*toolchain.GENERATOR_TOOLS, *toolchain.SCANNER_TOOLS):
        status = toolchain.detect(name)
        state = "missing" if not status.installed else ("ok" if status.matches_pin else "MISMATCH")
        db = status.database
        db_text = (db.get("updated_at") or db.get("built") or "-") if db.get("valid") else ("missing" if db else "")
        if name == "trivy" and db.get("valid"):
            db_text += f" · Java DB {db.get('java_db_updated_at') or 'missing'}"
        print(f"{name:<8}{status.version or '-':<12}{status.pinned or '-':<10}{state:<10}{db_text}")
        if status.error:
            print(f"        {status.error}")
        ok = ok and status.installed and status.matches_pin and not status.error
    for kind, name in (("epss", "EPSS"), ("kev", "KEV")):
        newest = enrich.select(kind)
        found = len(enrich.snapshots(kind))
        text = (
            f"{newest.version} ({found} in {enrich.default_dir()})" if newest else "missing; run: chainguard db update"
        )
        print(f"{name:<8}{'snapshot':<12}{'-':<10}{'ok' if newest else 'missing':<10}{text}")
        ok = ok and newest is not None
    return EXIT_OK if ok else EXIT_FAILED


def cmd_db_update(args: argparse.Namespace) -> int:
    errors = toolchain.update_databases()
    for name, error in errors.items():
        print(f"{name:<6} {'updated' if error is None else 'FAILED: ' + error}")
    for name in toolchain.SCANNER_TOOLS:
        db = toolchain.detect(name).database
        if db.get("valid"):
            print(f"{name:<6} database {db.get('updated_at') or db.get('built')}")
    ok = all(e is None for e in errors.values())
    if args.enrichment:
        try:
            stored = enrich.update(epss_date=args.epss_date)
        except enrich.SnapshotError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
        for kind, outcome in stored.items():
            if isinstance(outcome, str):
                print(f"{kind:<6} FAILED: {outcome}")
                ok = False
                continue
            snapshot, new = outcome
            state = "stored" if new else "already stored"
            print(f"{kind:<6} snapshot {snapshot.version} {state} ({snapshot.count} entries) in {snapshot.file.parent}")
    return EXIT_OK if ok else EXIT_FAILED


def cmd_sbom_normalize(args: argparse.Namespace) -> int:
    try:
        parsed = sbom.load(args.file)
    except sbom.SbomError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.json:
        print(json.dumps({"stats": parsed.stats(), "components": sorted(parsed.components)}, indent=2))
        return EXIT_OK
    stats = parsed.stats()
    print(f"{args.file}: {stats['format']} {stats['spec_version']}")
    print(
        f"  entries {stats['entries']} · unique components {stats['unique_components']} · duplicate entries "
        f"{stats['duplicate_entries']} · no PURL {stats['no_purl']} · invalid PURL {stats['invalid_purl']}"
    )
    print("  by type: " + (", ".join(f"{t} {n}" for t, n in stats["by_type"].items()) or "-"))
    for os_ in stats["operating_systems"]:
        print(f"  operating system: {os_['name']} {os_['version']}")
    return EXIT_OK


def cmd_sbom_repair(args: argparse.Namespace) -> int:
    source = Path(args.file)
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
        repaired, counts = repair(document)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {source}: not readable as JSON ({exc})", file=sys.stderr)
        return EXIT_USAGE
    except sbom.SbomError as exc:
        print(f"error: {source}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    target = Path(args.out) if args.out else source.with_suffix(".repaired.json")
    target.write_text(json.dumps(repaired, indent=2) + "\n", encoding="utf-8")
    print(
        f"{source}: {counts['format']} · {counts['os_components']} OS components "
        f"({counts['source_stated']} state a source package, {counts['source_assumed']} assumed to be their own) "
        f"· {counts['changed']} rewritten"
    )
    print(f"Wrote {target}")
    return EXIT_OK


def cmd_sbom_merge(args: argparse.Namespace) -> int:
    documents = []
    for name in args.files:
        try:
            documents.append(json.loads(Path(name).read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {name}: not readable as JSON ({exc})", file=sys.stderr)
            return EXIT_USAGE
    try:
        cyclonedx, spdx_doc = merge_documents(documents, target=args.target)
    except sbom.SbomError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    out = Path(args.out)
    fmt = args.format or ("spdx" if "spdx" in out.name.lower() else "cyclonedx")
    document = spdx_doc if fmt == "spdx" else cyclonedx
    out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    entries = document["packages" if fmt == "spdx" else "components"]
    print(f"Merged {len(args.files)} SBOMs into {out} ({fmt}, {len(entries)} entries)")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chainguard", description=__doc__.split(":")[0] + ".")
    parser.add_argument("--version", action="version", version=f"chainguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser(
        "scan",
        help="run every generator and scanner on a target and record the results",
        description="Run each SBOM generator on the target, scan every SBOM with every scanner, "
        "and write the raw outputs plus normalised inventory, findings and a summary.",
    )
    p.add_argument("target", help="project directory, image archive (.tar from 'docker save'), or image:<ref>")
    p.add_argument("--out", default="chainguard-out", help="directory for run results (default: %(default)s)")
    p.add_argument(
        "--generators",
        default="syft,cdxgen",
        type=lambda v: _names(v, GENERATORS, "generator"),
        help="default: %(default)s",
    )
    p.add_argument(
        "--scanners", default="trivy,grype", type=lambda v: _names(v, SCANNERS, "scanner"), help="default: %(default)s"
    )
    p.add_argument(
        "--sbom-format",
        choices=("cyclonedx", "spdx"),
        default="cyclonedx",
        help="SBOM format to request from generators that support it (default: %(default)s)",
    )
    direct = p.add_mutually_exclusive_group()
    direct.add_argument(
        "--direct",
        dest="direct",
        action="store_const",
        const=True,
        default="auto",
        help="also scan the target directly with each scanner, the reference the hand-off check compares every "
        "SBOM pipeline with (default: images only)",
    )
    direct.add_argument(
        "--no-direct", dest="direct", action="store_const", const=False, help="never scan the target directly"
    )
    p.add_argument(
        "--no-fuse",
        dest="fuse",
        action="store_false",
        help="do not merge the generators' output into one SBOM and scan it (the fused pipeline)",
    )
    p.add_argument("--cdxgen-type", help="cdxgen project type, e.g. java, python, js (default: auto-detect)")
    p.add_argument("--timeout", type=int, default=1800, help="seconds per tool invocation (default: %(default)s)")
    p.add_argument("--strict-pins", action="store_true", help="fail if a tool version differs from the pins")
    _add_analysis_arguments(p)
    _add_gate_arguments(p, with_switch=True)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser(
        "gate",
        help="judge a finished run against a policy: PASS, WARN or FAIL",
        description="Read a run directory's analysis and judge it against a YAML policy: integrity checks that "
        "fail closed, rules on each finding, and time-boxed exceptions. Writes verdict.json into the run. "
        "Exit code 0 for PASS or WARN, 1 for FAIL, 2 if the policy or the run cannot be read.",
    )
    p.add_argument("run", help="a run directory (chainguard-out/<run-id>)")
    _add_gate_arguments(p, with_switch=False)
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser(
        "report",
        help="write a judged run's SARIF, JSON and Markdown reports",
        description="Write report.sarif (for GitHub code scanning), report.json and report.md (a job summary) from "
        "a run the gate has judged. gate and scan --gate write them too.",
    )
    p.add_argument("run", help="a run directory with a verdict.json")
    _add_report_arguments(p)
    p.set_defaults(func=cmd_report, reports=True)

    p = sub.add_parser(
        "reprocess",
        help="derive a finished run's inventory, findings and summary again from its raw outputs",
        description="Re-run only the analysis (normalisation, alias resolution, correlation, summary) of "
        "existing run directories. No tool is executed; raw/ is never modified. The manifest records the "
        "new analysis and keeps the earlier ones in analysis_history.",
    )
    p.add_argument("runs", nargs="+", help="run directories (chainguard-out/<run-id>)")
    _add_analysis_arguments(p)
    p.set_defaults(func=cmd_reprocess)

    p = sub.add_parser("tools", help="show installed tool versions against the pins, and database status")
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("db", help="manage the scanners' vulnerability databases")
    db_sub = p.add_subparsers(dest="db_command", required=True)
    q = db_sub.add_parser(
        "update",
        help="download fresh Trivy and Grype databases, and the EPSS and KEV snapshots",
        description="Download the scanners' vulnerability databases, today's FIRST EPSS scores and the current "
        "CISA KEV catalog. Snapshots are stored under the date of their scores or their catalog version and never "
        "overwritten; scans and reprocess use the newest unless told otherwise.",
    )
    q.add_argument("--epss-date", metavar="DATE", help="download the EPSS scores of this date (YYYY-MM-DD) instead")
    q.add_argument("--no-enrichment", dest="enrichment", action="store_false", help="only the scanners' databases")
    q.set_defaults(func=cmd_db_update)

    p = sub.add_parser("sbom", help="inspect SBOM files")
    sbom_sub = p.add_subparsers(dest="sbom_command", required=True)
    q = sbom_sub.add_parser("normalize", help="read a CycloneDX or SPDX JSON SBOM into canonical components")
    q.add_argument("file")
    q.add_argument("--json", action="store_true", help="print canonical component keys as JSON")
    q.set_defaults(func=cmd_sbom_normalize)

    q = sbom_sub.add_parser(
        "repair",
        help="write the source package of each OS component into every field scanners read",
        description="Resolve each operating-system component's source package from whichever field holds it "
        "and write it to all of them, so a scanner reading this SBOM can match distribution advisories "
        "(design rule D2). Identity is unchanged and nothing is invented.",
    )
    q.add_argument("file")
    q.add_argument("-o", "--out", help="write the repaired SBOM here (default: alongside, with .repaired.json)")
    q.set_defaults(func=cmd_sbom_repair)

    q = sbom_sub.add_parser(
        "merge",
        help="merge several SBOMs into one scanner-ready document",
        description="Normalise every input into the canonical inventory and write it as one SBOM, with an "
        "operating-system component and the source package of each OS component in every field scanners "
        "read (design rules D3 and D7).",
    )
    q.add_argument("files", nargs="+", help="CycloneDX or SPDX 2.x JSON SBOMs of the same target")
    q.add_argument("-o", "--out", required=True, help="output path; the format follows its extension")
    q.add_argument(
        "--format",
        choices=("cyclonedx", "spdx"),
        help="output format (default: inferred from --out, else cyclonedx)",
    )
    q.add_argument("--target", default="", help="name to record as the merged document's subject")
    q.set_defaults(func=cmd_sbom_merge)

    p = sub.add_parser("version", help="print the ChainGuard version")
    p.set_defaults(func=lambda _: print(f"chainguard {__version__}") or EXIT_OK)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
