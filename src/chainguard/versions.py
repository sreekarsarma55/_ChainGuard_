"""Version canonicalisation per ecosystem (design rule D4).

Two tools can spell one version differently: Django is ``3.2`` in its installed metadata and ``3.2.0`` in the
``requirements.txt`` that pinned it, and cdxgen lists both for the same project. Keyed on the
string, that is two components, so every count, merge and correlation splits in two. The canonical version
used in a component's identity key therefore follows each ecosystem's own definition of version equality:

=======  ==================================================================================================
Type     Rule
=======  ==================================================================================================
pypi     PEP 440 equality, canonicalised as pip does (``packaging.utils.canonicalize_version``): spellings are
         normalised (``1.0-RC.1`` -> ``1rc1``) and trailing zero release segments dropped (``3.2.0`` ->
         ``3.2``), because PEP 440 compares ``3.2`` and ``3.2.0`` as equal. A string that is not a PEP 440
         version is left exactly as written.
deb      Epoch 0 is the same as no epoch (Debian Policy 5.6.12): ``0:1.2-3`` -> ``1.2-3``. Any other epoch
rpm      is kept, because it changes how versions order. An absent Debian revision also equals ``-0``, but
         stripping ``-0`` changes where the remaining string splits into upstream version and revision
         (``1.0-rc-0`` would become ``1.0-rc``), so that rule is not applied.
maven    None, deliberately. A Maven version is a coordinate: Maven *orders* ``1.0`` and ``1.0.0`` as equal,
         yet they name different artifacts in a repository, and only one of them exists.
other    None. npm lockfiles and Go modules already carry their registries' canonical versions.
=======  ==================================================================================================

Only identity uses the canonical form. Every component keeps the version its tool reported, and that is
what ChainGuard writes into the SBOMs it produces, so nothing is presented with a spelling no tool used.
"""

from __future__ import annotations

import re

from packaging.utils import canonicalize_version
from packaging.version import InvalidVersion, Version

_ZERO_EPOCH = re.compile(r"^0+:")


def canonical(ptype: str, version: str) -> str:
    """The canonical spelling of ``version`` for components of PURL type ``ptype``."""
    if not version:
        return version
    if ptype == "pypi":
        try:
            Version(version)
        except InvalidVersion:
            return version
        return canonicalize_version(version, strip_trailing_zero=True)
    if ptype in ("deb", "rpm"):
        return _ZERO_EPOCH.sub("", version, count=1)
    return version


def same(ptype: str, a: str, b: str) -> bool:
    """Whether two version strings of one ecosystem denote the same version."""
    return canonical(ptype, a) == canonical(ptype, b)
