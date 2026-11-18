"""Vulnerability scanner adapters (vulnerability layer): invoke Trivy and Grype, parse their reports.

Both report formats are reduced to one ``Finding`` shape so that later stages (alias resolution,
correlation, prioritisation, policy) never see scanner-specific JSON.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from chainguard import purl as purls
from chainguard.target import Target

FIX_STATES = ("fixed", "not_fixed", "wont_fix", "unknown")


@dataclass
class Finding:
    """One scanner's claim that a component is affected by a vulnerability."""

    pipeline: str  # "<generator>+<scanner>", or "direct+<scanner>" for a scan without an SBOM hand-off
    scanner: str
    raw_id: str  # the ID exactly as the scanner reported it
    related: tuple[str, ...]  # IDs the scanner says describe the same vulnerability
    component: str  # canonical component key (purl.key); '?'-prefixed when the scanner gave no PURL
    purl: str | None
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | NEGLIGIBLE | UNKNOWN
    cvss_v3: float | None  # highest CVSS v3.x base score the scanner reported
    fix_state: str  # one of FIX_STATES
    fix_versions: tuple[str, ...]
    # The scanner's own EPSS and KEV data, if it ships them (Grype does), from whenever its database was built:
    # kept for cross-checking the dated snapshots that enrichment uses (chainguard.enrich), never instead of them
    epss: float | None = None  # exploit probability
    kev: bool | None = None  # listed in CISA KEV
    epss_date: str | None = None  # the date of the EPSS score
    vulnerability: str = ""  # first canonical ID, assigned during alias resolution (aliases.resolve)
    vulnerabilities: tuple[str, ...] = ()  # every canonical ID: an advisory can cover several CVEs

    @property
    def canonical_ids(self) -> tuple[str, ...]:
        return self.vulnerabilities or ((self.vulnerability or self.raw_id),)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self) | {
            "related": list(self.related),
            "fix_versions": list(self.fix_versions),
            "vulnerabilities": list(self.canonical_ids),
        }


def _severity(value: Any) -> str:
    text = str(value or "").strip().upper()
    return text if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"} else "UNKNOWN"


def _max(values: Any) -> float | None:
    numbers = [float(v) for v in values if isinstance(v, (int, float))]
    return max(numbers) if numbers else None


class Scanner:
    name: str

    def sbom_command(self, sbom: Path, output: Path) -> list[str]:
        raise NotImplementedError

    def direct_command(self, target: Target, output: Path) -> list[str]:
        raise NotImplementedError

    def parse(self, report: dict[str, Any], pipeline: str) -> Iterator[Finding]:
        raise NotImplementedError


class Trivy(Scanner):
    name = "trivy"
    # Neither database changes during a scan: both come from `chainguard db update` (D6), the Java index included
    _flags = ["--skip-db-update", "--skip-java-db-update", "--format", "json"]
    _status = {
        "fixed": "fixed",
        "affected": "not_fixed",
        "fix_deferred": "not_fixed",
        "will_not_fix": "wont_fix",
        "end_of_life": "wont_fix",
    }

    def sbom_command(self, sbom: Path, output: Path) -> list[str]:
        return ["trivy", "sbom", "-q", *self._flags, "-o", str(output), str(sbom)]

    def direct_command(self, target: Target, output: Path) -> list[str]:
        flags = [*self._flags, "--scanners", "vuln", "-o", str(output)]
        if target.is_directory:
            return ["trivy", "fs", "-q", *flags, str(target.path)]
        return ["trivy", "image", "-q", *flags, "--input", str(target.path)]

    def parse(self, report: dict[str, Any], pipeline: str) -> Iterator[Finding]:
        for result in report.get("Results") or []:
            for vuln in result.get("Vulnerabilities") or []:
                raw_purl = (vuln.get("PkgIdentifier") or {}).get("PURL")
                fixed = tuple(v.strip() for v in str(vuln.get("FixedVersion") or "").split(",") if v.strip())
                status = str(vuln.get("Status") or "").lower()
                state = self._status.get(status, "fixed" if fixed else "unknown")
                yield Finding(
                    pipeline=pipeline,
                    scanner=self.name,
                    raw_id=vuln["VulnerabilityID"],
                    related=(),
                    component=purls.key(raw_purl)
                    or purls.fallback_key(result.get("Type"), vuln.get("PkgName"), vuln.get("InstalledVersion")),
                    purl=raw_purl,
                    severity=_severity(vuln.get("Severity")),
                    cvss_v3=_max(source.get("V3Score") for source in (vuln.get("CVSS") or {}).values()),
                    fix_state=state,
                    fix_versions=fixed,
                )


class Grype(Scanner):
    name = "grype"
    _state = {"fixed": "fixed", "not-fixed": "not_fixed", "wont-fix": "wont_fix"}

    def sbom_command(self, sbom: Path, output: Path) -> list[str]:
        return ["grype", "-q", f"sbom:{sbom}", "-o", "json", "--file", str(output)]

    def direct_command(self, target: Target, output: Path) -> list[str]:
        source = f"dir:{target.path}" if target.is_directory else f"docker-archive:{target.path}"
        return ["grype", "-q", source, "-o", "json", "--file", str(output)]

    def parse(self, report: dict[str, Any], pipeline: str) -> Iterator[Finding]:
        for match in report.get("matches") or []:
            vuln, artifact = match["vulnerability"], match["artifact"]
            related = match.get("relatedVulnerabilities") or []
            cvss_entries = [*(vuln.get("cvss") or []), *(c for r in related for c in r.get("cvss") or [])]
            fix = vuln.get("fix") or {}
            raw_purl = artifact.get("purl")
            scored = [e for e in vuln.get("epss") or [] if isinstance(e.get("epss"), (int, float))]
            top = max(scored, key=lambda e: e["epss"], default={})
            yield Finding(
                pipeline=pipeline,
                scanner=self.name,
                raw_id=vuln["id"],
                related=tuple(r["id"] for r in related if r.get("id")),
                component=purls.key(raw_purl)
                or purls.fallback_key(artifact.get("type"), artifact.get("name"), artifact.get("version")),
                purl=raw_purl,
                severity=_severity(vuln.get("severity")),
                cvss_v3=_max(
                    (c.get("metrics") or {}).get("baseScore")
                    for c in cvss_entries
                    if str(c.get("version", "")).startswith("3")
                ),
                fix_state=self._state.get(str(fix.get("state") or ""), "unknown"),
                fix_versions=tuple(fix.get("versions") or ()),
                epss=float(top["epss"]) if top else None,
                kev=bool(vuln.get("knownExploited")) if "knownExploited" in vuln else None,
                epss_date=(str(top.get("date") or "")[:10] or None) if top else None,
            )


SCANNERS: dict[str, Scanner] = {s.name: s for s in (Trivy(), Grype())}
