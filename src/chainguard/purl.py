"""Package URL handling: turn tool-emitted PURLs into ChainGuard's canonical component key.

Key format: ``type/namespace/name@version``, qualifiers and subpath dropped, where ``version`` is the
ecosystem's canonical spelling (design rule D4, ``chainguard.versions``): ``pypi/django@3.2`` whether a tool
wrote ``3.2`` or ``3.2.0``. Names follow PEP 503 for PyPI and are lower-cased for npm/deb/rpm/apk/golang, and
an ``epoch`` qualifier is folded into the version.

A parsed ``Purl`` keeps the version exactly as its tool reported it (``version``) next to the canonical one
(``canonical_version``). Identity uses the canonical form; output keeps a spelling some tool actually used.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from packageurl import PackageURL

from chainguard import versions

_LOWERCASE_TYPES = frozenset({"npm", "deb", "rpm", "apk", "golang"})


@dataclass(frozen=True)
class Purl:
    """A parsed, normalised PURL. ``key`` is the component identity used everywhere in ChainGuard."""

    type: str
    namespace: str
    name: str
    version: str  # as the tool reported it, with an epoch qualifier folded in
    qualifiers: dict[str, str] = field(default_factory=dict, compare=False, hash=False)
    canonical_version: str = field(default="", compare=False, hash=False)  # D4; "" means the same as version

    @property
    def key(self) -> str:
        namespace = f"{self.namespace}/" if self.namespace else ""
        return f"{self.type}/{namespace}{self.name}@{self.canonical_version or self.version}"

    @property
    def reported_key(self) -> str:
        """The key with the version as the tool wrote it, before D4: what comparing raw tool output uses
        (``chainguard.metrics``)."""
        namespace = f"{self.namespace}/" if self.namespace else ""
        return f"{self.type}/{namespace}{self.name}@{self.version}"


def parse(purl: str | None) -> Purl | None:
    """Parse and normalise a PURL string. Returns None if it is absent or malformed."""
    if not purl or not purl.startswith("pkg:"):
        return None
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError:
        return None

    ptype = parsed.type.lower()
    namespace, name, version = parsed.namespace or "", parsed.name or "", parsed.version or ""
    qualifiers = parsed.qualifiers if isinstance(parsed.qualifiers, dict) else {}
    if not name:
        return None
    if ptype == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif ptype in _LOWERCASE_TYPES:
        name, namespace = name.lower(), namespace.lower()
    epoch = qualifiers.get("epoch")
    if epoch and ":" not in version:
        version = f"{epoch}:{version}"
    return Purl(ptype, namespace, name, version, dict(qualifiers), versions.canonical(ptype, version))


def key(purl: str | None) -> str | None:
    """Canonical component key for a PURL string, or None."""
    parsed = parse(purl)
    return parsed.key if parsed else None


def with_qualifier(purl: str, name: str, value: str) -> str:
    """``purl`` with qualifier ``name`` set to ``value``, re-encoded. Returns it unchanged if unparseable.

    Qualifiers are rebuilt by packageurl, so keys are sorted and values percent-encoded as the spec requires.
    """
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError:
        return purl
    qualifiers = dict(parsed.qualifiers) if isinstance(parsed.qualifiers, dict) else {}
    if qualifiers.get(name) == value:
        return purl
    qualifiers[name] = value
    return PackageURL(
        type=parsed.type,
        namespace=parsed.namespace,
        name=parsed.name,
        version=parsed.version,
        qualifiers=qualifiers,
        subpath=parsed.subpath,
    ).to_string()


def fallback_key(ecosystem: str | None, name: str | None, version: str | None) -> str:
    """Key for a scanner finding that carries no usable PURL. Marked with a leading '?'."""
    return f"?{(ecosystem or 'unknown').lower()}/{(name or '').lower()}@{version or ''}"
