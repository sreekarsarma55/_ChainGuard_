#!/usr/bin/env python3
"""Check alias resolution against real OSV records with known answers (CI runs this; network required).

Each case is a vulnerability with a known answer, so a change in behaviour shows up as a failure here
rather than as a silent shift in the results. The second pass runs offline from the cache the first pass
wrote, and must give the identical answer.

    python3 tests/checks/check_aliases.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainguard.aliases import OsvCache, resolve  # noqa: E402
from chainguard.scanners import Finding  # noqa: E402


def finding(pipeline: str, raw_id: str, related: tuple[str, ...] = ()) -> Finding:
    return Finding(pipeline, pipeline.split("+")[1], raw_id, related, "npm/x@1", None, "HIGH", None, "fixed", ())


# (what it shows, findings, expected canonical IDs per raw ID, expected merged CVEs)
CASES = [
    (
        "GHSA resolves to its CVE",
        [finding("syft+grype", "GHSA-w5hq-g745-h8pq", ("CVE-2026-41907",)), finding("syft+trivy", "CVE-2026-41907")],
        {"GHSA-w5hq-g745-h8pq": ["CVE-2026-41907"], "CVE-2026-41907": ["CVE-2026-41907"]},
        {"CVE-2026-41988": "CVE-2026-41907"},
    ),
    # Until 17 Oct 2026 this case was lodash's CVE-2021-23337 and CVE-2026-4800. OSV then gave CVE-2026-4800 an
    # advisory of its own (GHSA-r5fr-rjxr-66jc), so the two are no longer aliases. A CVE its numbering authority
    # rejected as a duplicate cannot be separated again like that.
    (
        "two CVEs that are aliases of each other are counted once (libwebp; CVE-2023-5129 is a rejected duplicate)",
        [
            finding("syft+grype", "GHSA-j7hp-h8jx-5ppr", ("CVE-2023-4863",)),
            finding("syft+trivy", "CVE-2023-4863"),
            finding("syft+trivy", "CVE-2023-5129"),
        ],
        {"GHSA-j7hp-h8jx-5ppr": ["CVE-2023-4863"], "CVE-2023-5129": ["CVE-2023-4863"]},
        {"CVE-2023-5129": "CVE-2023-4863"},
    ),
    (
        "a distribution advisory covers every CVE it fixes (DSA-5611-1: glibc)",
        [finding("syft+trivy", "DSA-5611-1")],
        {"DSA-5611-1": ["CVE-2023-6246", "CVE-2023-6779", "CVE-2023-6780"]},
        {},
    ),
    (
        "an ID unknown to OSV stays as reported",
        [finding("syft+trivy", "NSWG-ECO-101")],
        {"NSWG-ECO-101": ["NSWG-ECO-101"]},
        {},
    ),
]


def run(cache: Path, offline: bool) -> list[str]:
    failures = []
    for title, findings, expected, merged in CASES:
        osv = OsvCache(cache, offline=offline)
        resolution = resolve(findings, osv)
        got = {f.raw_id: list(f.canonical_ids) for f in findings}
        for raw_id, want in expected.items():
            if got.get(raw_id) != want:
                failures.append(f"{title}: {raw_id} -> {got.get(raw_id)}, expected {want}")
        for cve, into in merged.items():
            if resolution.merged_cves.get(cve, into) != into:
                failures.append(f"{title}: {cve} merged into {resolution.merged_cves.get(cve)}, expected {into}")
        if offline and osv.counts.get("not_cached"):
            failures.append(f"{title}: offline pass missed the cache for {osv.counts['not_cached']} IDs")
    return failures


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        failures = run(Path(tmp), offline=False) + run(Path(tmp), offline=True)
    for failure in failures:
        print(f"FAIL  {failure}")
    print(f"{len(CASES)} cases, online then offline: {'ok' if not failures else f'{len(failures)} failures'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
