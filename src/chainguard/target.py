"""What gets scanned: a project directory, a container-image archive, or a container image reference."""

from __future__ import annotations

import hashlib
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class TargetError(ValueError):
    """The target cannot be scanned."""


@dataclass
class Target:
    kind: str  # "directory" | "image-archive" | "image"
    spec: str  # as given on the command line
    path: Path | None = None  # the directory or archive the tools read (images: saved into the run)
    image: str | None = None  # image reference, for kind == "image"
    info: dict[str, Any] = field(default_factory=dict)

    @property
    def is_directory(self) -> bool:
        return self.kind == "directory"

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "spec": self.spec,
            "path": str(self.path) if self.path else None,
            "image": self.image,
            "info": self.info,
        }


def resolve(spec: str) -> Target:
    """Interpret a target argument: ``image:<ref>``, a directory, or a ``docker save`` archive."""
    if spec.startswith("image:"):
        ref = spec.removeprefix("image:").strip()
        if not ref:
            raise TargetError("image: needs a reference, e.g. image:python:3.12-slim")
        return Target(kind="image", spec=spec, image=ref)
    path = Path(spec).expanduser()
    if path.is_dir():
        target = Target(kind="directory", spec=spec, path=path.resolve())
        target.info.update(_git_info(target.path))
        return target
    if path.is_file():
        if not tarfile.is_tarfile(path):
            raise TargetError(f"{spec}: not a directory or an image archive (a .tar from 'docker save')")
        target = Target(kind="image-archive", spec=spec, path=path.resolve())
        target.info["sha256"] = sha256(path)
        return target
    raise TargetError(f"{spec}: no such file or directory (use image:<ref> for a container image)")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def image_id(ref: str) -> str | None:
    proc = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", ref], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _git_info(path: Path) -> dict[str, Any]:
    """Commit and dirty state, if the directory is inside a git work tree."""

    def git(*args: str) -> str | None:
        try:
            proc = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True, check=False)
        except OSError:
            return None
        return proc.stdout.strip() if proc.returncode == 0 else None

    commit = git("rev-parse", "HEAD")
    if not commit:
        return {}
    return {"git_commit": commit, "git_dirty": bool(git("status", "--porcelain", "--", "."))}
