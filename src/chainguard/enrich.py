"""Enrichment (vulnerability layer): EPSS and KEV from dated snapshots, and what a ranking needs to know.

Every correlated finding, one (component, canonical vulnerability) pair, gets:

  epss           the FIRST EPSS score and percentile of its CVE, from a dated snapshot of the daily scores
  kev            whether the CISA Known Exploited Vulnerabilities catalog lists it, with the date added, the due
                 date and known ransomware use, from a dated snapshot of the catalog
  cvss_v3        the highest CVSS v3 base score any scanner gave it
  fix_available  true if a scanner names a fix; false if the scanners say there is none; unknown otherwise
  depth          how far the component is from the target in the generators' dependency graphs: 1 for a direct
                 dependency, more for a transitive one, unknown where no graph reaches it (``sbom.ParsedSbom``)

The snapshots give the values that count. Grype ships EPSS and KEV values of its own, from whenever its database
was built: they stay in Grype's claim and are compared with the snapshots, never used in their place. A
vulnerability whose class holds several CVEs, because alias resolution merged them (D1), takes the highest EPSS
of its CVEs and is in KEV if any of them is. EPSS and KEV know CVEs only, so a vulnerability that stayed under
another ID has neither, and is counted.

Snapshots change only through ``chainguard db update`` (D6). Each is stored under the date of its scores or the
version of its catalog and never overwritten, so a run records the snapshots it used and ``reprocess`` can use
the same ones again.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chainguard import __version__
from chainguard.aliases import Resolution, default_cache_dir, is_cve
from chainguard.correlate import CorrelatedFinding, InventoryEntry

# FIRST publishes the daily scores through Empirical Security (https://www.first.org/epss/data).
EPSS_CURRENT = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_DATED = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KINDS = ("epss", "kev")
_VERSION = {"epss": re.compile(r"^\d{4}-\d{2}-\d{2}$"), "kev": re.compile(r"^\d{4}\.\d{2}\.\d{2}$")}
_SAME = 5e-6  # EPSS is published with five decimals: values closer than this are the same score


class SnapshotError(ValueError):
    """A download or a file is not the snapshot it claims to be."""


def default_dir() -> Path:
    """The snapshot store: ``enrichment/`` in ChainGuard's cache (``aliases.default_cache_dir``)."""
    return default_cache_dir() / "enrichment"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Snapshot:
    """One stored snapshot: an EPSS scores file of one date, or one version of the KEV catalog."""

    kind: str  # "epss" | "kev"
    version: str  # EPSS: the date of the scores (YYYY-MM-DD); KEV: the catalog version (YYYY.MM.DD)
    file: Path
    sha256: str
    source: str  # where it was downloaded from
    retrieved_utc: str
    released: str  # EPSS: the score date and time; KEV: when the catalog was released
    count: int  # CVEs scored, or catalog entries
    model: str | None = None  # EPSS model version

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "version": self.version,
            "file": str(self.file),
            "sha256": self.sha256,
            "source": self.source,
            "retrieved_utc": self.retrieved_utc,
            "released": self.released,
            "count": self.count,
            "model": self.model,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], file: Path) -> Snapshot:
        return cls(
            kind=data["kind"],
            version=data["version"],
            file=file,
            sha256=data["sha256"],
            source=data["source"],
            retrieved_utc=data["retrieved_utc"],
            released=data["released"],
            count=int(data["count"]),
            model=data.get("model"),
        )


def _paths(kind: str, version: str, directory: Path) -> tuple[Path, Path]:
    """(data file, metadata file) of a snapshot in the store."""
    if not _VERSION[kind].match(version):
        raise SnapshotError(f"not a valid {kind} snapshot version: {version!r}")
    # Names are built whole: a catalog version such as 2026.10.30 would otherwise lose ".30" as a file suffix.
    if kind == "epss":
        return directory / "epss" / f"epss_scores-{version}.csv.gz", directory / "epss" / f"epss_scores-{version}.json"
    return directory / "kev" / f"kev-{version}.json", directory / "kev" / f"kev-{version}.meta.json"


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, 0o644)  # readable by every user that shares the cache, as in the container
    os.replace(tmp, path)


def _epss_rows(data: bytes) -> tuple[dict[str, str], Iterable[list[str]]]:
    """The header of an EPSS scores file (``#model_version:…,score_date:…``) and its rows, CVE first."""
    try:
        text = gzip.decompress(data).decode("utf-8")
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        raise SnapshotError(f"not a gzipped EPSS scores file ({exc})") from exc
    lines = io.StringIO(text)
    first = lines.readline().strip()
    if not first.startswith("#"):
        raise SnapshotError("not an EPSS scores file: no '#model_version:…,score_date:…' line")
    header = dict(part.split(":", 1) for part in first[1:].split(",") if ":" in part)
    if "score_date" not in header or lines.readline().strip() != "cve,epss,percentile":
        raise SnapshotError(f"not an EPSS scores file: {first[:80]!r}")
    return header, csv.reader(lines)


def store_epss(data: bytes, directory: Path | None = None, *, source: str = EPSS_CURRENT) -> tuple[Snapshot, bool]:
    """Keep an EPSS scores file in the store under the date of its scores. Returns (snapshot, newly stored);
    a date already in the store is kept as it is."""
    directory = Path(directory or default_dir())
    header, rows = _epss_rows(data)
    version = header["score_date"][:10]
    file, meta = _paths("epss", version, directory)
    if meta.exists():
        return Snapshot.from_dict(json.loads(meta.read_text(encoding="utf-8")), file), False
    snapshot = Snapshot(
        "epss",
        version,
        file,
        hashlib.sha256(data).hexdigest(),
        source,
        _now(),
        header["score_date"],
        sum(1 for row in rows if row),
        header.get("model_version"),
    )
    _write_atomic(file, data)
    _write_atomic(meta, json.dumps(snapshot.as_dict(), indent=2).encode())
    return snapshot, True


def store_kev(data: bytes, directory: Path | None = None, *, source: str = KEV_FEED) -> tuple[Snapshot, bool]:
    """Keep a KEV catalog in the store under its catalog version. Returns (snapshot, newly stored)."""
    directory = Path(directory or default_dir())
    try:
        catalog = json.loads(data)
        version, released = str(catalog["catalogVersion"]), str(catalog["dateReleased"])
        entries = catalog["vulnerabilities"]
    except (ValueError, KeyError, TypeError) as exc:
        raise SnapshotError(f"not a KEV catalog ({exc})") from exc
    file, meta = _paths("kev", version, directory)
    if meta.exists():
        return Snapshot.from_dict(json.loads(meta.read_text(encoding="utf-8")), file), False
    snapshot = Snapshot("kev", version, file, hashlib.sha256(data).hexdigest(), source, _now(), released, len(entries))
    _write_atomic(file, data)
    _write_atomic(meta, json.dumps(snapshot.as_dict(), indent=2).encode())
    return snapshot, True


def _download(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": f"chainguard/{__version__}"})
    error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504):
                raise SnapshotError(f"{url}: HTTP {exc.code}") from exc
            error = exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            error = exc
        time.sleep(2 * (attempt + 1))
    raise SnapshotError(f"{url}: {error}")


def update(
    directory: Path | None = None,
    *,
    epss_date: str | None = None,
    epss_url: str | None = None,
    kev_url: str = KEV_FEED,
    timeout: float = 120,
) -> dict[str, tuple[Snapshot, bool] | str]:
    """Download the EPSS scores (today's, or those of ``epss_date``) and the current KEV catalog into the store.

    Returns, per kind, (snapshot, newly stored) or the error that kept it from being stored.
    """
    if epss_date and not _VERSION["epss"].match(epss_date):
        raise SnapshotError(f"not a date (YYYY-MM-DD): {epss_date!r}")
    url = epss_url or (EPSS_DATED.format(date=epss_date) if epss_date else EPSS_CURRENT)
    out: dict[str, tuple[Snapshot, bool] | str] = {}
    for kind, source, store in (("epss", url, store_epss), ("kev", kev_url, store_kev)):
        try:
            out[kind] = store(_download(source, timeout), directory, source=source)
        except (SnapshotError, OSError) as exc:
            out[kind] = str(exc)
    return out


def snapshots(kind: str, directory: Path | None = None) -> list[Snapshot]:
    """The snapshots of one kind in the store, oldest first."""
    directory = Path(directory or default_dir())
    pattern = "epss/epss_scores-*.json" if kind == "epss" else "kev/kev-*.meta.json"
    found = []
    for meta in directory.glob(pattern):
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
            file, _ = _paths(kind, data["version"], directory)
            if file.exists():
                found.append(Snapshot.from_dict(data, file))
        except (OSError, ValueError, KeyError, TypeError):
            continue  # an unreadable or partial entry is no snapshot
    return sorted(found, key=lambda s: (s.released, s.version))


def select(kind: str, directory: Path | None = None, version: str | None = None) -> Snapshot | None:
    """The snapshot of that version, or the newest one; None if the store has no such snapshot."""
    found = snapshots(kind, directory)
    if version is not None:
        found = [s for s in found if s.version == version]
    return found[-1] if found else None


def _verified(snapshot: Snapshot) -> bytes:
    data = snapshot.file.read_bytes()
    if hashlib.sha256(data).hexdigest() != snapshot.sha256:
        raise SnapshotError(f"{snapshot.file}: content changed since it was stored (sha256 mismatch)")
    return data


def load_epss(snapshot: Snapshot, cves: Iterable[str]) -> dict[str, tuple[float, float]]:
    """CVE -> (EPSS score, percentile) for the given CVEs that the snapshot scores."""
    wanted = set(cves)
    _, rows = _epss_rows(_verified(snapshot))
    out: dict[str, tuple[float, float]] = {}
    for row in rows:
        if len(row) >= 3 and row[0] in wanted:
            out[row[0]] = (float(row[1]), float(row[2]))
    return out


def load_kev(snapshot: Snapshot) -> dict[str, dict[str, Any]]:
    """CVE -> its catalog entry: date added, due date, known ransomware campaign use."""
    catalog = json.loads(_verified(snapshot))
    return {
        str(e["cveID"]): {
            "date_added": e.get("dateAdded"),
            "due_date": e.get("dueDate"),
            "ransomware": e.get("knownRansomwareCampaignUse"),
        }
        for e in catalog["vulnerabilities"]
        if e.get("cveID")
    }


# --------------------------------------------------------------------------- findings


def class_cves(resolution: Resolution) -> dict[str, list[str]]:
    """Canonical CVE -> every CVE of its class, itself first: the CVEs alias resolution merged into it (D1)."""
    members: dict[str, set[str]] = {}
    for cve, into in resolution.merged_cves.items():
        members.setdefault(into, set()).add(cve)
    return {into: [into, *sorted(m - {into})] for into, m in members.items()}


def fix_available(finding: CorrelatedFinding) -> bool | None:
    """True if any scanner names a fix, false if the scanners say there is none, None if none of them knows."""
    states = {s for claim in finding.claims.values() for s in claim.fix_states}
    if "fixed" in states:
        return True
    return False if states & {"not_fixed", "wont_fix"} else None


def enrich(
    correlated: list[CorrelatedFinding],
    inventory: Mapping[str, InventoryEntry],
    resolution: Resolution,
    *,
    epss: Snapshot | None = None,
    kev: Snapshot | None = None,
) -> dict[str, Any]:
    """Set every correlated finding's ``enrichment``, in place, and summarise the findings on installed software.

    Without a snapshot, EPSS (or KEV) is unknown for every finding (None), never Grype's value.
    """
    classes = class_cves(resolution)
    cves_of = {
        c.vulnerability: classes.get(c.vulnerability, [c.vulnerability]) if is_cve(c.vulnerability) else []
        for c in correlated
    }
    scores = load_epss(epss, {cve for cves in cves_of.values() for cve in cves}) if epss else None
    listed = load_kev(kev) if kev else None
    for c in correlated:
        cves = cves_of[c.vulnerability]
        entry = inventory.get(c.component)
        cvss = [claim.cvss_v3 for claim in c.claims.values() if claim.cvss_v3 is not None]
        values: dict[str, Any] = {
            "cves": cves,
            "epss": None,
            "epss_percentile": None,
            "epss_cve": None,
            "kev": None,
            "cvss_v3": max(cvss, default=None),
            "fix_available": fix_available(c),
            "depth": entry.depth if entry else None,
        }
        if scores is not None and cves:
            scored = [(scores[cve], cve) for cve in cves if cve in scores]
            if scored:
                (score, percentile), cve = max(scored)
                values.update(epss=score, epss_percentile=percentile, epss_cve=cve)
        if listed is not None and cves:
            hit = next((cve for cve in cves if cve in listed), None)
            values["kev"] = hit is not None
            if hit:
                values.update({f"kev_{k}": v for k, v in listed[hit].items()}, kev_cve=hit)
        c.enrichment = values
    return summarize(correlated, epss, kev)


def summarize(correlated: list[CorrelatedFinding], epss: Snapshot | None, kev: Snapshot | None) -> dict[str, Any]:
    """What the snapshots and the other facts cover, over the findings on installed software, and how Grype's own
    EPSS and KEV values compare with the snapshots."""
    installed = [c for c in correlated if not c.not_installed and c.enrichment is not None]
    e = [c.enrichment or {} for c in installed]
    depth = Counter("unknown" if x["depth"] is None else str(x["depth"]) for x in e)
    out: dict[str, Any] = {
        "epss_snapshot": epss.version if epss else None,
        "kev_snapshot": kev.version if kev else None,
        "pairs": len(installed),
        "with_cve": sum(1 for x in e if x["cves"]),
        "epss_scored": sum(1 for x in e if x["epss"] is not None),
        "kev_listed": sum(1 for x in e if x["kev"]),
        "cvss_v3": sum(1 for x in e if x["cvss_v3"] is not None),
        "fix_available": {
            "yes": sum(1 for x in e if x["fix_available"] is True),
            "no": sum(1 for x in e if x["fix_available"] is False),
            "unknown": sum(1 for x in e if x["fix_available"] is None),
        },
        "depth": dict(sorted(depth.items(), key=lambda kv: (kv[0] == "unknown", int(kv[0]) if kv[0].isdigit() else 0))),
        "in_kev": [
            {
                "vulnerability": c.vulnerability,
                "component": c.component,
                "date_added": (c.enrichment or {}).get("kev_date_added"),
                "ransomware": (c.enrichment or {}).get("kev_ransomware"),
            }
            for c in installed
            if (c.enrichment or {}).get("kev")
        ],
    }
    # Cross-check only: Grype's values beside the snapshots', on the pairs Grype reports.
    grype = [(c.claims["grype"], c.enrichment or {}) for c in installed if "grype" in c.claims]
    epss_pairs = [(claim.epss, x["epss"]) for claim, x in grype if claim.epss is not None and x["epss"] is not None]
    differences = [abs(a - b) for a, b in epss_pairs]
    kev_pairs = [(bool(claim.kev), x["kev"]) for claim, x in grype if x["kev"] is not None]
    out["grype"] = {
        "pairs": len(grype),
        "epss_compared": len(epss_pairs),
        "epss_same": sum(1 for d in differences if d < _SAME),
        "epss_largest_difference": round(max(differences), 5) if differences else None,
        "epss_dates": sorted({claim.epss_date for claim, _ in grype if claim.epss_date}),
        "kev_compared": len(kev_pairs),
        "kev_agree": sum(1 for a, b in kev_pairs if a == b),
        "kev_only_grype": sum(1 for a, b in kev_pairs if a and not b),
        "kev_only_snapshot": sum(1 for a, b in kev_pairs if b and not a),
    }
    return out


def provenance(epss: Snapshot | None, kev: Snapshot | None, requested: Mapping[str, str | None]) -> dict[str, Any]:
    """For the run manifest: the snapshots used, and any version asked for that the store did not have."""
    record: dict[str, Any] = {"epss": epss.as_dict() if epss else None, "kev": kev.as_dict() if kev else None}
    missing = {
        kind: version
        for kind, version in requested.items()
        if version and (record.get(kind) or {}).get("version") != version
    }
    if missing:
        record["not_in_store"] = missing
    return record
