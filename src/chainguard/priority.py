"""Priority score (vulnerability layer): one score per correlated finding, with an explanation.

The score combines the facts enrichment gave every correlated pair (chainguard.enrich) with the consensus the
correlator counted (D10). Each factor is turned into a value in [0, 1], and the score is the weighted mean of the
values, times 100::

    score = 100 * sum(w_f * v_f) / sum(w_f)      over the factors f with w_f > 0

so removing a factor (weight 0) rescales the others instead of lowering every score, which is what an ablation
needs. The weights, each factor's value for "not known" and the bands live in a YAML file: by default the packaged
``priority.yaml``, otherwise the file given (``--priority-config``). Every finding records, per factor, what
was observed, the value used in its place if it was not known, the weight and its share of the score, so a
ranking can always be explained, and the run records the configuration's sha256.

Findings on entries that are not installed software (D9) get no score: they are kept and marked, and support
nothing installed, so nothing must act on them.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from chainguard.correlate import SEVERITY_ORDER, CorrelatedFinding
from chainguard.enrich import fix_available

FACTORS = ("epss", "kev", "cvss", "fix", "depth", "consensus")
EPSS_USES = ("percentile", "score")


class ConfigError(ValueError):
    """The priority configuration is not valid."""


@dataclass(frozen=True)
class Factor:
    weight: float
    unknown: float
    use: str | None = None  # EPSS only: "percentile" or "score"


@dataclass(frozen=True)
class Config:
    factors: Mapping[str, Factor]
    severity_values: Mapping[str, float]
    bands: tuple[tuple[str, float], ...]  # highest minimum first
    source: str = "packaged priority.yaml"
    sha256: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)

    def without(self, factor: str) -> Config:
        """The same configuration with one factor's weight at 0: an ablation."""
        if factor not in self.factors:
            raise ConfigError(f"unknown factor {factor!r}; factors: {', '.join(FACTORS)}")
        factors = {**self.factors, factor: replace(self.factors[factor], weight=0.0)}
        if not any(f.weight > 0 for f in factors.values()):
            raise ConfigError("removing it leaves no factor with a weight above 0")
        return replace(self, factors=factors, source=f"{self.source} without {factor}")

    def only(self, factor: str) -> Config:
        """Only one factor, weighted: a single-signal baseline (CVSS alone, EPSS alone, ...)."""
        if factor not in self.factors:
            raise ConfigError(f"unknown factor {factor!r}; factors: {', '.join(FACTORS)}")
        factors = {name: replace(f, weight=1.0 if name == factor else 0.0) for name, f in self.factors.items()}
        return replace(self, factors=factors, source=f"{factor} only")

    def band(self, score: float) -> str:
        for name, minimum in self.bands:
            if score >= minimum:
                return name
        return self.bands[-1][0]

    def as_record(self) -> dict[str, Any]:
        """For the run manifest: where the configuration came from, its sha256, and the values used."""
        return {
            "source": self.source,
            "sha256": self.sha256,
            "factors": {
                n: {"weight": f.weight, "unknown": f.unknown, **({"use": f.use} if f.use else {})}
                for n, f in self.factors.items()
            },
            "severity_values": dict(self.severity_values),
            "bands": dict(self.bands),
        }


def _number(value: Any, where: str, low: float | None = 0.0, high: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where}: expected a number, not {value!r}")
    if (low is not None and value < low) or (high is not None and value > high):
        raise ConfigError(f"{where}: {value} is outside [{low}, {high if high is not None else '∞'}]")
    return float(value)


def parse(data: Any, *, source: str = "<config>", sha256: str = "") -> Config:
    """A configuration from its YAML data. Every factor must be given; unknown keys are refused, so a typo cannot
    silently leave a default in place."""
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a mapping")
    extra = set(data) - {"version", "factors", "severity_values", "bands"}
    if extra:
        raise ConfigError(f"{source}: unknown keys {', '.join(sorted(extra))}")
    if data.get("version") != 1:
        raise ConfigError(f"{source}: version must be 1")
    given = data.get("factors") or {}
    if not isinstance(given, dict) or set(given) != set(FACTORS):
        names = sorted(given) if isinstance(given, dict) else given
        raise ConfigError(f"{source}: factors must be exactly {', '.join(FACTORS)}; got {names}")
    factors: dict[str, Factor] = {}
    for name in FACTORS:
        spec = given[name]
        if not isinstance(spec, dict) or set(spec) - {"weight", "unknown", "use"}:
            raise ConfigError(f"{source}: factors.{name}: expected weight, unknown (and, for epss, use)")
        use = spec.get("use")
        if name == "epss":
            use = use or "percentile"
            if use not in EPSS_USES:
                raise ConfigError(f"{source}: factors.epss.use must be one of {', '.join(EPSS_USES)}")
        elif use is not None:
            raise ConfigError(f"{source}: factors.{name}: only epss has 'use'")
        factors[name] = Factor(
            _number(spec.get("weight"), f"{source}: factors.{name}.weight"),
            _number(spec.get("unknown"), f"{source}: factors.{name}.unknown", 0.0, 1.0),
            use,
        )
    if not any(f.weight > 0 for f in factors.values()):
        raise ConfigError(f"{source}: at least one factor needs a weight above 0")
    severities = data.get("severity_values") or {}
    if not isinstance(severities, dict) or set(severities) - set(SEVERITY_ORDER):
        raise ConfigError(f"{source}: severity_values: keys must be among {', '.join(SEVERITY_ORDER)}")
    severity_values = {s: _number(v, f"{source}: severity_values.{s}", 0.0, 1.0) for s, v in severities.items()}
    bands_given = data.get("bands") or {}
    if not isinstance(bands_given, dict) or not bands_given:
        raise ConfigError(f"{source}: bands: expected a mapping of name to minimum score")
    bands = tuple(
        sorted(
            ((str(n), _number(m, f"{source}: bands.{n}", 0.0, 100.0)) for n, m in bands_given.items()),
            key=lambda b: -b[1],
        )
    )
    if bands[-1][1] != 0:
        raise ConfigError(f"{source}: bands: the lowest band must start at 0, so every score has a band")
    if len({m for _, m in bands}) != len(bands):
        raise ConfigError(f"{source}: bands: two bands have the same minimum")
    return Config(factors, severity_values, bands, source, sha256, data)


def load(path: str | Path | None = None) -> Config:
    """The configuration in ``path``, or the packaged default."""
    if path is None:
        text = resources.files("chainguard").joinpath("priority.yaml").read_text(encoding="utf-8")
        source = "packaged priority.yaml"
    else:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"{path}: not readable ({exc.strerror or exc})") from exc
        source = str(path)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{source}: not valid YAML ({exc})") from exc
    return parse(data, source=source, sha256=hashlib.sha256(text.encode()).hexdigest())


# --------------------------------------------------------------------------- scoring


def values(finding: CorrelatedFinding, config: Config, most_consensus: int) -> dict[str, dict[str, Any]]:
    """Each factor's raw value and the value in [0, 1] it gives, or None where it is not known. CVSS and fix come
    from the scanners' claims when the finding was not enriched (``--no-enrichment``); EPSS, KEV and depth then
    stay unknown."""
    e = finding.enrichment
    if e is None:
        cvss = [claim.cvss_v3 for claim in finding.claims.values() if claim.cvss_v3 is not None]
        e = {"cvss_v3": max(cvss, default=None), "fix_available": fix_available(finding)}
    out: dict[str, dict[str, Any]] = {}
    use = config.factors["epss"].use or "percentile"
    epss = e.get("epss_percentile" if use == "percentile" else "epss")
    out["epss"] = {"raw": epss, "value": epss, "from": f"EPSS {use}"}
    kev = e.get("kev")
    out["kev"] = {"raw": kev, "value": None if kev is None else float(bool(kev)), "from": "KEV snapshot"}
    cvss = e.get("cvss_v3")
    if cvss is not None:
        out["cvss"] = {"raw": cvss, "value": min(max(cvss / 10, 0.0), 1.0), "from": "CVSS v3"}
    else:
        severity = finding.max_severity
        out["cvss"] = {"raw": severity, "value": config.severity_values.get(severity), "from": "scanner severity"}
    fix = e.get("fix_available")
    out["fix"] = {"raw": fix, "value": None if fix is None else float(bool(fix)), "from": "fix available"}
    depth = e.get("depth")
    out["depth"] = {"raw": depth, "value": 1 / depth if depth else None, "from": "dependency depth"}
    out["consensus"] = {
        "raw": f"{finding.consensus} of {most_consensus}",
        "value": finding.consensus / most_consensus if most_consensus else None,
        "from": "generators x scanners",
    }
    return out


def score(finding: CorrelatedFinding, config: Config, most_consensus: int) -> dict[str, Any] | None:
    """The finding's score, band and per-factor explanation; None for what is not installed software."""
    if finding.not_installed:
        return None
    total = sum(f.weight for f in config.factors.values() if f.weight > 0)
    explanation: dict[str, dict[str, Any]] = {}
    points = 0.0
    for name, v in values(finding, config, most_consensus).items():
        factor = config.factors[name]
        known = v["value"] is not None
        used = v["value"] if known else factor.unknown
        share = 100 * factor.weight * used / total  # a removed factor (weight 0) gives 0
        points += share
        explanation[name] = {
            "raw": v["raw"],
            "from": v["from"],
            "known": known,
            "value": round(used, 5),
            "weight": factor.weight,
            "points": round(share, 2),
        }
    value = round(points, 2)
    return {"score": value, "band": config.band(value), "factors": explanation}


def _order(finding: CorrelatedFinding) -> tuple:
    p = finding.priority or {}
    return (-p.get("score", -1.0), SEVERITY_ORDER.index(finding.max_severity), finding.vulnerability, finding.component)


def prioritize(
    correlated: list[CorrelatedFinding], config: Config, most_consensus: int
) -> tuple[list[CorrelatedFinding], dict[str, Any]]:
    """Score every correlated finding in place; return them ranked (highest score first, then severity, ID and
    component, so the order is deterministic), with a summary."""
    for c in correlated:
        c.priority = score(c, config, most_consensus)
    ranked = sorted(correlated, key=_order)
    scored = [c for c in ranked if c.priority]
    for rank, c in enumerate(scored, 1):
        (c.priority or {})["rank"] = rank
    return ranked, summarize(scored, config)


def summarize(scored: Iterable[CorrelatedFinding], config: Config) -> dict[str, Any]:
    scored = list(scored)
    bands = Counter((c.priority or {})["band"] for c in scored)
    unknown = Counter(n for c in scored for n, x in (c.priority or {})["factors"].items() if not x["known"])
    return {
        "config": {"source": config.source, "sha256": config.sha256},
        "scored": len(scored),
        "bands": {name: bands.get(name, 0) for name, _ in config.bands},
        "unknown_factors": {n: unknown.get(n, 0) for n in FACTORS},
        "top": [
            {
                "rank": (c.priority or {})["rank"],
                "score": (c.priority or {})["score"],
                "band": (c.priority or {})["band"],
                "vulnerability": c.vulnerability,
                "component": c.component,
                "why": explain(c),
            }
            for c in scored[:10]
        ],
    }


def explain(finding: CorrelatedFinding) -> str:
    """One line: the factors that gave the most points, with their raw values."""
    p = finding.priority or {}
    parts = []
    for name, x in sorted(p.get("factors", {}).items(), key=lambda kv: -kv[1]["points"]):
        if x["weight"] <= 0:
            continue
        raw = x["raw"]
        shown = f"{raw:.3g}" if isinstance(raw, float) else str(raw).lower() if isinstance(raw, bool) else raw
        parts.append(f"{name} {shown if x['known'] else 'unknown'} (+{x['points']:g})")
    return ", ".join(parts)


# --------------------------------------------------------------------------- comparing rankings


def kendall_tau(a: Mapping[Any, float], b: Mapping[Any, float]) -> float | None:
    """Kendall's tau-b between two scorings of the same items (ties allowed); None with fewer than two items."""
    items = sorted(set(a) & set(b), key=json.dumps)
    concordant = discordant = ties_a = ties_b = 0
    for i, x in enumerate(items):
        for y in items[i + 1 :]:
            da, db = a[x] - a[y], b[x] - b[y]
            if da == 0 and db == 0:
                continue
            if da == 0:
                ties_a += 1
            elif db == 0:
                ties_b += 1
            elif (da > 0) == (db > 0):
                concordant += 1
            else:
                discordant += 1
    denominator = ((concordant + discordant + ties_a) * (concordant + discordant + ties_b)) ** 0.5
    return round((concordant - discordant) / denominator, 4) if denominator else None
