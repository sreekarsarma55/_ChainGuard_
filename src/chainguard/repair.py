"""Write what an SBOM already knows into the fields a scanner actually reads (design rule D2).

Generators and scanners record the same fact in different places, so a hand-off loses it even though the
SBOM contains it. For operating-system packages, Syft records the source package in the PURL ``upstream``
qualifier, and Trivy reads only its own properties or the SPDX ``sourceInfo`` string, so Trivy matched 42 of
196 Debian CVEs on an SBOM that already named every source package.

``repair`` changes no identity and invents nothing. For each OS component it resolves the source package
from whichever carrier holds it (``chainguard.ospackage``) and writes it to every carrier of that format.
A component whose source package is not stated anywhere keeps the binary package as its source, which is
what every tool assumes by default; those are counted separately so a report can say how many were assumed.
"""

from __future__ import annotations

import copy
from typing import Any

from chainguard import ospackage
from chainguard import purl as purls
from chainguard.sbom import SbomError, _walk, spdx_purl


def repair(doc: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """A copy of ``doc`` with source-package identity in every carrier, plus what was changed."""
    if doc.get("bomFormat") == "CycloneDX":
        return _repair(copy.deepcopy(doc), spdx=False)
    if str(doc.get("spdxVersion", "")).startswith("SPDX-2"):
        return _repair(copy.deepcopy(doc), spdx=True)
    raise SbomError("neither CycloneDX JSON nor SPDX 2.x JSON")


def _repair(doc: dict[str, Any], *, spdx: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    entries = doc.get("packages") or [] if spdx else list(_walk(doc.get("components")))
    counts = {"os_components": 0, "source_stated": 0, "source_assumed": 0, "changed": 0}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        parsed = purls.parse(spdx_purl(entry) if spdx else entry.get("purl"))
        if parsed is None or parsed.type not in ospackage.OS_TYPES:
            continue
        source = ospackage.resolve(parsed, entry, spdx=spdx)
        if source is None:
            continue
        counts["os_components"] += 1
        counts["source_assumed" if source.implicit else "source_stated"] += 1
        attach = ospackage.attach_spdx if spdx else ospackage.attach_cyclonedx
        counts["changed"] += bool(attach(entry, source))
    counts["format"] = "SPDX" if spdx else "CycloneDX"
    return doc, counts
