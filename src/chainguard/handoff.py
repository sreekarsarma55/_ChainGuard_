"""Hand-off check (design rules D3 and D7): what does handing a scanner an SBOM cost it?

A direct scan lets a scanner read the target itself; every SBOM pipeline hands the same scanner an SBOM of that
target instead. Whatever the direct scan reports and the SBOM pipeline does not was lost on the way. Each SBOM
pipeline is compared with the direct scan by the same scanner, on (component, vulnerability) pairs, with
canonical component keys (D4) and canonical vulnerability IDs (D1). Comparing distinct vulnerability IDs alone
would hide a loss on one component behind the same advisory on another. Every pair the direct scan reports and
the pipeline does not is put in exactly one class, tested in this order:

  misattributed   the pipeline reports the vulnerability, but only on components the direct scan does not
                  attribute it to. A typical case is cdxgen's source packages listed as if installed:
                  Grype reports a glibc advisory on cdxgen's `glibc` entry rather than on the installed
                  `libc6`. The vulnerability is found; the component is wrong.
  handoff         the component is in the SBOM the scanner read, yet the scanner did not report the
                  vulnerability: the SBOM did not carry what the scanner needs to match it (a source package,
                  an operating-system component, a CPE). Design rule D3 exists to make this zero.
  other_version   the component is not in that SBOM, but the same package is, at another version
  not_listed      the package is not in that SBOM at all: the generator did not find it (coverage)

"In the SBOM the scanner read" means listed as a component of the document the pipeline's scanner was given:
a generator's own SBOM for a single pipeline, the merged document for a fused one. Entries that are not
installed software (D9) do not count as listed.

Pairs the pipeline reports and the direct scan does not are counted as ``beyond``, those on entries that are not
installed software separately. A scanner whose direct scan failed or was not run is not checked, and neither is
a pipeline whose own scan failed or whose SBOM is not available: a missing reference must never read as a
lossless hand-off. Losses are expected in single pipelines and are only reported; a loss in a fused pipeline is
a ChainGuard defect, so it is also raised as a warning.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from chainguard.correlate import pipeline_class
from chainguard.runner import Step
from chainguard.sbom import ParsedSbom
from chainguard.scanners import Finding

CLASSES = ("misattributed", "handoff", "other_version", "not_listed")


def _pairs(findings: Iterable[Finding]) -> dict[str, set[tuple[str, str]]]:
    pairs: dict[str, set[tuple[str, str]]] = {}
    for f in findings:
        for vulnerability in f.canonical_ids:
            pairs.setdefault(f.pipeline, set()).add((f.component, vulnerability))
    return pairs


def _by_vulnerability(pairs: set[tuple[str, str]]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for component, vulnerability in pairs:
        out.setdefault(vulnerability, set()).add(component)
    return out


def _name(key: str) -> str:
    return key.rsplit("@", 1)[0]


def classify(reference: set[tuple[str, str]], reported: set[tuple[str, str]], listed: set[str]) -> list[dict[str, Any]]:
    """Every pair of ``reference`` missing from ``reported``, with its class (see the module docstring).

    ``listed`` holds the component keys of the SBOM the pipeline's scanner read.
    """
    names = {_name(k) for k in listed}
    reference_on, reported_on = _by_vulnerability(reference), _by_vulnerability(reported)
    rows = []
    for component, vulnerability in sorted(reference - reported):
        elsewhere = reported_on.get(vulnerability, set()) - reference_on.get(vulnerability, set())
        if elsewhere:
            kind = "misattributed"
        elif component in listed:
            kind = "handoff"
        elif _name(component) in names:
            kind = "other_version"
        else:
            kind = "not_listed"
        row: dict[str, Any] = {"component": component, "vulnerability": vulnerability, "class": kind}
        if elsewhere:
            row["reported_on"] = sorted(elsewhere)
        rows.append(row)
    return rows


def check(
    findings: list[Finding],
    scanned: dict[str, ParsedSbom],
    steps: list[Step],
    not_installed: dict[str, str] | None = None,
    merged: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """(summary, detail): per-pipeline losses against the same scanner's direct scan, and every lost pair.

    ``scanned`` maps a pipeline's head (``syft``, ``cdxgen``, ``fused``, ``fused-spdx``) to the parsed document
    its scanner actually read, so that "listed" means listed in what the scanner was given. ``findings`` must
    carry canonical IDs already (``aliases.resolve``), and components merged into another under D11 already moved
    to it; ``merged`` maps those keys, so a document listing one counts as listing the component it became.
    """
    not_installed, merged = not_installed or {}, merged or {}
    ran = {s.name for s in steps if s.kind == "scan"}
    ok = {s.name for s in steps if s.kind == "scan" and s.ok}
    pairs = _pairs(findings)
    summary: dict[str, Any] = {"scanners": {}, "pipelines": {}, "warnings": []}
    detail: dict[str, Any] = {}
    sbom_pipelines = sorted(p for p in ran if pipeline_class(p) in ("single", "fused"))
    for scanner in sorted({p.split("+", 1)[1] for p in sbom_pipelines}):
        reference = f"direct+{scanner}"
        if reference not in ran:
            summary["scanners"][scanner] = {"reference": reference, "status": "not checked: no direct scan"}
            continue
        if reference not in ok:
            summary["scanners"][scanner] = {"reference": reference, "status": "not checked: direct scan failed"}
            summary["warnings"].append(f"hand-off check for {scanner} skipped: its direct scan failed")
            continue
        ref = pairs.get(reference, set())
        summary["scanners"][scanner] = {
            "reference": reference,
            "status": "checked",
            "pairs": len(ref),
            "vulnerabilities": len({v for _, v in ref}),
        }
        for pipeline in (p for p in sbom_pipelines if p.split("+", 1)[1] == scanner):
            head, kind = pipeline.split("+", 1)[0], pipeline_class(pipeline)
            entry: dict[str, Any] = {"scanner": scanner, "class": kind}
            summary["pipelines"][pipeline] = entry
            if pipeline not in ok:
                entry["status"] = "not checked: its scan failed"
                continue
            document = scanned.get(head)
            if document is None:
                entry["status"] = "not checked: the SBOM it read is not available"
                if kind == "fused":
                    summary["warnings"].append(f"hand-off check for {pipeline} skipped: the SBOM it read is missing")
                continue
            got = pairs.get(pipeline, set())
            lost = classify(ref, got, {merged.get(k, k) for k in document.components})
            counts = dict.fromkeys(CLASSES, 0)
            for row in lost:
                counts[row["class"]] += 1
                if "reported_on" in row:
                    row["only_on_not_installed"] = all(c in not_installed for c in row["reported_on"])
            beyond = sorted(got - ref)
            lost_vulnerabilities = sorted({v for _, v in ref} - {v for _, v in got})
            entry.update(
                {
                    "status": "checked",
                    "reference_pairs": len(ref),
                    "pairs": len(got),
                    "lost": len(lost),
                    "lost_by_class": counts,
                    "misattributed_to_not_installed": sum(1 for r in lost if r.get("only_on_not_installed")),
                    "lost_vulnerabilities": len(lost_vulnerabilities),
                    "beyond": len(beyond),
                    "beyond_not_installed": sum(1 for c, _ in beyond if c in not_installed),
                    "lossless": not lost,
                }
            )
            detail[pipeline] = {
                "reference": reference,
                "lost": lost,
                "lost_vulnerabilities": lost_vulnerabilities,
                "beyond": [
                    {"component": c, "vulnerability": v, "not_installed": not_installed.get(c)} for c, v in beyond
                ],
            }
            if kind == "fused" and lost:
                by = ", ".join(f"{k} {n}" for k, n in counts.items() if n)
                summary["warnings"].append(
                    f"hand-off check: {pipeline} lost {len(lost)} of the {len(ref)} findings of {reference} ({by}); "
                    "every lost pair is in handoff.json"
                )
    fused = [v for v in summary["pipelines"].values() if v["class"] == "fused" and "lossless" in v]
    summary["fused_lossless"] = all(v["lossless"] for v in fused) if fused else None
    return summary, detail
