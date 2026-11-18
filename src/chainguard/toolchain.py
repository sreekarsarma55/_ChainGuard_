"""The external toolchain: pinned versions, installed versions, and vulnerability-database snapshots.

Every result must record the exact tool versions and the
vulnerability-database snapshot it was produced with, and scanners never update their databases
in the middle of a run. Databases change only through ``chainguard db update``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

GENERATOR_TOOLS = ("syft", "cdxgen")
SCANNER_TOOLS = ("trivy", "grype")

# Applied to every scanner invocation: no database or application update checks during a run.
SCAN_ENV = {
    "GRYPE_DB_AUTO_UPDATE": "false",
    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    "TRIVY_SKIP_VERSION_CHECK": "true",
    "TRIVY_DISABLE_TELEMETRY": "true",
}

INSTALL_HINT = "install the pinned toolchain with scripts/install-tools.sh"


def pinned_versions() -> dict[str, str]:
    """Tool -> pinned version, read from the packaged toolchain.env."""
    text = resources.files("chainguard").joinpath("toolchain.env").read_text(encoding="utf-8")
    pins: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        if name.endswith("_VERSION"):
            pins[name.removesuffix("_VERSION").lower()] = value.strip()
    return pins


@dataclass
class ToolStatus:
    name: str
    path: str | None = None
    version: str | None = None
    pinned: str | None = None
    database: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def installed(self) -> bool:
        return self.path is not None and self.version is not None

    @property
    def matches_pin(self) -> bool:
        return self.pinned is None or self.version == self.pinned

    def as_dict(self) -> dict[str, Any]:
        return asdict(self) | {"installed": self.installed, "matches_pin": self.matches_pin}


def _output(cmd: list[str], timeout: int = 120) -> str:
    env = os.environ | SCAN_ENV
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True, env=env).stdout


def _detect_syft(status: ToolStatus) -> None:
    status.version = json.loads(_output(["syft", "version", "-o", "json"]))["version"]


def _detect_grype(status: ToolStatus) -> None:
    status.version = json.loads(_output(["grype", "version", "-o", "json"]))["version"]
    try:
        db = json.loads(_output(["grype", "db", "status", "-o", "json"]))
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        status.database = {"valid": False}
        return
    status.database = {"schema": db.get("schemaVersion"), "built": db.get("built"), "valid": bool(db.get("valid"))}


def _detect_trivy(status: ToolStatus) -> None:
    info = json.loads(_output(["trivy", "version", "--format", "json"]))
    status.version = info["Version"]
    db = info.get("VulnerabilityDB")
    status.database = (
        {"updated_at": db.get("UpdatedAt"), "downloaded_at": db.get("DownloadedAt"), "valid": True}
        if db
        else {"valid": False}
    )
    # The Java index Trivy identifies jars with (by SHA-1) in direct scans. Frozen like the vulnerability database:
    # downloaded by `db update`, never during a scan (--skip-java-db-update), and recorded with every run.
    java = info.get("JavaDB")
    if db:
        status.database["java_db_updated_at"] = java.get("UpdatedAt") if java else None


def _detect_cdxgen(status: ToolStatus) -> None:
    text = re.sub(r"\x1b\[[0-9;]*m", "", _output(["cdxgen", "--version"]))
    match = re.search(r"Generator\s+(\d+\.\d+\.\d+)", text) or re.search(r"(\d+\.\d+\.\d+)", text)
    if not match:
        raise ValueError(f"unrecognised version output: {text.strip()[:80]!r}")
    status.version = match.group(1)


_DETECTORS = {"syft": _detect_syft, "grype": _detect_grype, "trivy": _detect_trivy, "cdxgen": _detect_cdxgen}


def detect(name: str) -> ToolStatus:
    """Locate a tool on PATH and record its version (and database state, for scanners)."""
    status = ToolStatus(name=name, pinned=pinned_versions().get(name), path=shutil.which(name))
    if status.path is None:
        status.error = f"not found on PATH ({INSTALL_HINT})"
        return status
    try:
        _DETECTORS[name](status)
    except (subprocess.SubprocessError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        status.error = f"could not read version: {exc}"
        status.version = None
    if status.installed and name in SCANNER_TOOLS and not status.database.get("valid"):
        status.error = "vulnerability database missing; run: chainguard db update"
    return status


_ENVIRONMENT_PROBES = {
    "python": ["python", "--version"],
    "python3": ["python3", "--version"],
    "pip": ["python3", "-m", "pip", "--version"],
    "node": ["node", "--version"],
    "npm": ["npm", "--version"],
    "java": ["java", "-version"],
    "mvn": ["mvn", "--version"],
    "docker": ["docker", "--version"],
}


def environment() -> dict[str, str | None]:
    """Versions of the interpreters and build tools the generators shell out to, as found on PATH.

    Generator output depends on them: cdxgen resolves a Python project's dependency tree through the
    ``python`` command, and silently lists only the declared requirements when no ``python`` exists
    Python's version also matters, through environment markers.
    """
    found: dict[str, str | None] = {}
    for name, cmd in _ENVIRONMENT_PROBES.items():
        if shutil.which(cmd[0]) is None:
            found[name] = None
            continue
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        except (OSError, subprocess.SubprocessError):
            found[name] = None
            continue
        text = (proc.stdout or proc.stderr).strip().splitlines()
        found[name] = re.sub(r"\x1b\[[0-9;]*m", "", text[0]).strip() if text and proc.returncode == 0 else None
    found["python_path"] = shutil.which("python")
    found["python3_path"] = shutil.which("python3")
    return found


_PYTHON_MANIFESTS = frozenset(
    {"requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock"}
)


def has_python_manifest(root: Path, max_depth: int = 3) -> bool:
    """True if a Python dependency manifest exists within ``max_depth`` directory levels of ``root``."""
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        if _PYTHON_MANIFESTS.intersection(filenames):
            return True
        if len(Path(dirpath).parts) - root_depth >= max_depth:
            dirnames.clear()
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in {"node_modules", "target"}]
    return False


def cdxgen_python_env(environment: dict[str, str | None]) -> tuple[dict[str, str], str | None]:
    """Environment overrides, and a note for the report, for running cdxgen on a Python project.

    cdxgen resolves a Python project's dependency tree with the command named by ``PYTHON_CMD``,
    which defaults to ``python``. When that command does not exist, cdxgen silently lists only the
    declared requirements. Ubuntu, macOS and WSL ship only ``python3``, so use it explicitly.
    """
    chosen = os.environ.get("PYTHON_CMD")
    if chosen:
        if shutil.which(chosen) is None:
            return {}, (
                f"PYTHON_CMD={chosen} is not on PATH: cdxgen will list only declared Python requirements, "
                "without transitive dependencies"
            )
        return {}, None
    if environment.get("python"):
        return {}, None
    if environment.get("python3"):
        return {"PYTHON_CMD": "python3"}, (
            f"no 'python' command on PATH; ran cdxgen with PYTHON_CMD=python3 ({environment['python3']})"
        )
    return {}, (
        "no Python interpreter on PATH: cdxgen will list only declared Python requirements, "
        "without transitive dependencies"
    )


def update_databases() -> dict[str, str | None]:
    """Download fresh vulnerability databases for Trivy and Grype. Returns tool -> error (None = ok)."""
    commands = {
        "trivy": ["trivy", "image", "--download-db-only", "-q"],
        "trivy-java": ["trivy", "image", "--download-java-db-only", "-q"],
        "grype": ["grype", "db", "update"],
    }
    errors: dict[str, str | None] = {}
    for name, cmd in commands.items():
        if shutil.which(cmd[0]) is None:
            errors[name] = f"not found on PATH ({INSTALL_HINT})"
            continue
        env = os.environ | {"GRYPE_CHECK_FOR_APP_UPDATE": "false", "TRIVY_SKIP_VERSION_CHECK": "true"}
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
        errors[name] = None if proc.returncode == 0 else (proc.stderr or proc.stdout).strip()[-400:]
    return errors
