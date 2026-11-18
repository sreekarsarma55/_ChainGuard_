"""Vulnerability alias resolution (design rule D1): every advisory ID mapped to canonical IDs before any count.

Scanners name one vulnerability differently. Grype reports GitHub advisories (``GHSA-…``) for language
packages, Trivy mostly CVEs, and both report distribution or ecosystem IDs (``DLA-…``, ``TEMP-…``,
``NSWG-…``). Comparing pipelines on raw IDs therefore measures naming, not detection.

OSV.dev records relate IDs in two different ways, and the difference decides how findings are counted:

  aliases    the *same* vulnerability under another ID. All IDs connected by aliases form one class, and
             the class is counted once, under its lowest CVE (or its lowest ID if it has no CVE). This also
             merges duplicate CVEs: GHSA-35jh-r3h4-6jhm (lodash) lists CVE-2021-23337 and CVE-2026-4800, and
             CVE-2026-4800's own record lists CVE-2021-23337 as its alias. Trivy reports both CVEs, while
             Grype reports the GHSA once; counted as written, that is a disagreement between scanners that
             agree.
  upstream   the vulnerabilities an advisory is *derived from*. A bundle such as DSA-5611-1 (glibc: three
             CVEs) covers each of them, so a finding reported under it counts for every one.

Only non-CVE IDs are looked up; the classes they form also map the CVEs they name. Two CVEs are therefore
merged only when an advisory reported in the same run links them, and every merge is counted. Where OSV has
no record, or none with a CVE, the CVEs the scanner itself reported as related (Grype) are used as aliases.
Whatever stays unresolved is reported as is, and counted by reason.

OSV records are cached on disk, one file per ID, and never expire, so a run is reproducible offline.
``refresh`` queries OSV again; ``offline`` never queries.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chainguard import __version__
from chainguard.scanners import Finding

OSV_VULN_API = "https://api.osv.dev/v1/vulns/"
STATUSES = ("osv", "scanner", "no_cve", "unknown_to_osv", "not_looked_up")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,99}$")  # also a safe file name
_CVE = re.compile(r"^CVE-(\d{4})-(\d+)$")
_RETRY_CODES = {429, 500, 502, 503, 504}


def is_cve(vid: str) -> bool:
    return vid.startswith("CVE-")


def prefix(vid: str) -> str:
    """The ID's namespace, e.g. GHSA for GHSA-xxxx-xxxx-xxxx and DLA for DLA-3112-1."""
    match = re.match(r"[A-Za-z]+", vid)
    return match.group(0).upper() if match else "?"


def _order(vid: str) -> tuple:
    """Canonical choice within a class: CVEs first, oldest first (numerically, so CVE-2021-9999 < CVE-2021-10000)."""
    match = _CVE.match(vid)
    return (0, int(match.group(1)), int(match.group(2)), "") if match else (1, 0, 0, vid)


def default_cache_dir() -> Path:
    """$CHAINGUARD_CACHE, else $XDG_CACHE_HOME/chainguard, else ~/.cache/chainguard (the container: /cache)."""
    if os.environ.get("CHAINGUARD_CACHE"):
        return Path(os.environ["CHAINGUARD_CACHE"])
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "chainguard"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class OsvRecord:
    """What OSV.dev says about one advisory ID: whether it knows it, its aliases, and what it derives from."""

    id: str
    found: bool
    aliases: tuple[str, ...] = ()
    upstream: tuple[str, ...] = ()
    withdrawn: str | None = None
    modified: str | None = None
    fetched_utc: str = ""

    @classmethod
    def from_osv(cls, vid: str, data: dict[str, Any]) -> OsvRecord:
        def ids(key: str) -> tuple[str, ...]:
            return tuple(sorted({i for i in data.get(key) or [] if isinstance(i, str) and i and i != vid}))

        return cls(
            id=vid,
            found=True,
            aliases=ids("aliases"),
            upstream=ids("upstream"),
            withdrawn=data.get("withdrawn"),
            modified=data.get("modified"),
            fetched_utc=_now(),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "found": self.found,
            "aliases": list(self.aliases),
            "upstream": list(self.upstream),
            "withdrawn": self.withdrawn,
            "modified": self.modified,
            "fetched_utc": self.fetched_utc,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OsvRecord:
        return cls(
            id=data["id"],
            found=bool(data["found"]),
            aliases=tuple(data["aliases"]),
            upstream=tuple(data["upstream"]),
            withdrawn=data.get("withdrawn"),
            modified=data.get("modified"),
            fetched_utc=data.get("fetched_utc") or "",
        )


class OsvCache:
    """OSV.dev records by advisory ID, cached as one small JSON file per ID under ``<directory>/osv/vulns``."""

    def __init__(
        self,
        directory: Path | None = None,
        *,
        offline: bool = False,
        refresh: bool = False,
        timeout: float = 30.0,
        workers: int = 8,
    ):
        self.directory = Path(directory or default_cache_dir()) / "osv" / "vulns"
        self.offline, self.refresh, self.timeout, self.workers = offline, refresh, timeout, workers
        self.counts: Counter[str] = Counter()  # from_cache, fetched, not_cached, failed, skipped
        self.write_error: str | None = None
        self._dates: set[str] = set()

    def _path(self, vid: str) -> Path:
        return self.directory / f"{vid}.json"

    def _read(self, vid: str) -> OsvRecord | None:
        try:
            return OsvRecord.from_dict(json.loads(self._path(vid).read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError, TypeError):
            return None  # absent, or written by an incompatible version: fetch again

    def _write(self, record: OsvRecord) -> None:
        if self.write_error:
            return
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.directory, prefix=".tmp-", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(record.as_dict(), fh, sort_keys=True)
            os.replace(tmp, self._path(record.id))
        except OSError as exc:  # e.g. a read-only cache: resolution still works, it just is not cached
            self.write_error = f"{self.directory}: {exc.strerror or exc}"

    def _fetch(self, vid: str) -> OsvRecord | None:
        """The record from the API, a not-found record on HTTP 404, or None if OSV could not be asked."""
        request = urllib.request.Request(
            OSV_VULN_API + urllib.parse.quote(vid, safe=""),
            headers={"User-Agent": f"chainguard/{__version__}", "Accept": "application/json"},
        )
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return OsvRecord.from_osv(vid, json.load(response))
            except urllib.error.HTTPError as err:
                if err.code == 404:
                    return OsvRecord(vid, found=False, fetched_utc=_now())
                if err.code not in _RETRY_CODES:
                    return None
            except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                pass
            time.sleep(1.5 * (attempt + 1))
        return None

    def get_many(self, ids: Iterable[str]) -> dict[str, OsvRecord | None]:
        """Records for the given IDs; None where an ID was not looked up (offline and not cached, or failed)."""
        out: dict[str, OsvRecord | None] = {}
        pending = []
        for vid in sorted(set(ids)):
            if not _SAFE_ID.match(vid):
                out[vid] = None
                self.counts["skipped"] += 1
                continue
            cached = None if self.refresh else self._read(vid)
            if cached is not None:
                out[vid] = cached
                self.counts["from_cache"] += 1
            elif self.offline:
                out[vid] = None
                self.counts["not_cached"] += 1
            else:
                pending.append(vid)
        if pending:
            with ThreadPoolExecutor(self.workers) as pool:
                for vid, record in zip(pending, pool.map(self._fetch, pending), strict=True):
                    out[vid] = record
                    if record is None:
                        self.counts["failed"] += 1
                    else:
                        self.counts["fetched"] += 1
                        self._write(record)
        self._dates.update(r.fetched_utc for r in out.values() if r and r.fetched_utc)
        return out

    def provenance(self) -> dict[str, Any]:
        """For the run manifest: where alias data came from, and how fresh it is."""
        return {
            "source": "OSV.dev",
            "api": OSV_VULN_API,
            "cache_dir": str(self.directory),
            "offline": self.offline,
            "refresh": self.refresh,
            "lookups": {k: self.counts.get(k, 0) for k in ("from_cache", "fetched", "not_cached", "failed", "skipped")},
            "oldest_record_utc": min(self._dates, default=None),
            "newest_record_utc": max(self._dates, default=None),
            "cache_write_error": self.write_error,
        }


class _Classes:
    """Union-find over IDs that name the same vulnerability."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, vid: str) -> str:
        root = self.parent.setdefault(vid, vid)
        while root != self.parent[root]:
            root = self.parent[root]
        while vid != root:  # path compression
            self.parent[vid], vid = root, self.parent[vid]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            keep, drop = sorted((ra, rb), key=_order)
            self.parent[drop] = keep  # the root is always the class's canonical ID


@dataclass
class Resolution:
    """How the IDs of one run were resolved. CVE IDs map to themselves unless an alias class merges them."""

    detail: dict[str, dict[str, Any]] = field(default_factory=dict)  # non-CVE ID -> status, canonical IDs, notes
    merged_cves: dict[str, str] = field(default_factory=dict)  # CVE -> the CVE its class is counted under
    _canonical: dict[str, tuple[str, ...]] = field(default_factory=dict, repr=False)

    def canonical(self, raw_id: str) -> tuple[str, ...]:
        return self._canonical.get(raw_id, (raw_id,))

    def apply(self, findings: Iterable[Finding]) -> None:
        """Set every finding's canonical IDs from this resolution, in place."""
        for f in findings:
            f.vulnerabilities = self.canonical(f.raw_id)
            f.vulnerability = f.vulnerabilities[0]

    def as_dict(self) -> dict[str, Any]:
        return {"ids": self.detail, "merged_cves": self.merged_cves}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Resolution:
        """A resolution as a run recorded it in findings.json (``as_dict``), to apply again without asking OSV:
        the same IDs then get the same canonical CVEs, whatever OSV says today."""
        resolution = cls(detail=dict(data.get("ids") or {}), merged_cves=dict(data.get("merged_cves") or {}))
        for vid, entry in resolution.detail.items():
            resolution._canonical[vid] = tuple(entry["canonical"])
        for cve, into in resolution.merged_cves.items():
            resolution._canonical[cve] = (into,)
        return resolution

    def stats(self) -> dict[str, Any]:
        by_status = Counter(d["status"] for d in self.detail.values())
        unresolved = [v for v, d in self.detail.items() if d["status"] not in ("osv", "scanner")]
        return {
            "non_cve_ids": len(self.detail),
            "resolved_to_cve": by_status["osv"] + by_status["scanner"],
            "by_status": {s: by_status.get(s, 0) for s in STATUSES},
            "covering_several_cves": sum(1 for d in self.detail.values() if len(d["canonical"]) > 1),
            "cves_merged_as_aliases": len(self.merged_cves),
            "scanner_metadata_differs": sum(1 for d in self.detail.values() if "scanner_related_cves" in d),
            "by_prefix": dict(sorted(Counter(prefix(v) for v in self.detail).items())),
            "unresolved_by_prefix": dict(sorted(Counter(prefix(v) for v in unresolved).items())),
        }


def resolve(findings: list[Finding], osv: OsvCache | None) -> Resolution:
    """Set ``vulnerabilities`` (and ``vulnerability``, the first of them) on every finding, in place.

    ``osv=None`` resolves from scanner metadata alone, the v0 behaviour, kept for comparison.
    """
    related: dict[str, set[str]] = {}
    for f in findings:
        if not is_cve(f.raw_id):
            related.setdefault(f.raw_id, set()).update(r for r in f.related if is_cve(r))
    records = osv.get_many(related) if osv else {}

    classes = _Classes()
    status: dict[str, str] = {}
    for vid in sorted(related):
        record = records.get(vid)
        classes.find(vid)
        if record is not None and record.found:
            for alias in record.aliases:
                classes.union(vid, alias)
        if record is not None and record.found and any(is_cve(i) for i in (*record.aliases, *record.upstream)):
            status[vid] = "osv"
        elif related[vid]:  # OSV has no CVE for it, does not know it, or was not asked
            for cve in related[vid]:
                classes.union(vid, cve)
            status[vid] = "scanner"
        elif record is not None:
            status[vid] = "no_cve" if record.found else "unknown_to_osv"
        else:
            status[vid] = "not_looked_up"

    def canonical(vid: str) -> tuple[str, ...]:
        root = classes.find(vid)
        if is_cve(root):
            return (root,)
        record = records.get(vid)
        upstream = sorted({classes.find(u) for u in (record.upstream if record else ()) if is_cve(u)}, key=_order)
        return tuple(upstream) or (root,)

    resolution = Resolution()
    for vid in sorted(related):
        cves = canonical(vid)
        entry: dict[str, Any] = {"status": status[vid], "canonical": list(cves)}
        if any(classes.find(c) not in cves for c in related[vid]):  # the scanner relates a CVE that OSV does not
            entry["scanner_related_cves"] = sorted(related[vid], key=_order)
        record = records.get(vid)
        if record is not None and record.withdrawn:
            entry["osv_withdrawn"] = record.withdrawn
        resolution.detail[vid] = entry
        resolution._canonical[vid] = cves
    for cve in sorted({f.raw_id for f in findings if is_cve(f.raw_id)} | set(classes.parent), key=_order):
        if is_cve(cve) and classes.find(cve) != cve:
            resolution.merged_cves[cve] = classes.find(cve)
            resolution._canonical[cve] = (classes.find(cve),)
    resolution.apply(findings)
    return resolution
