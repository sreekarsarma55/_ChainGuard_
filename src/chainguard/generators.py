"""SBOM generator adapters (SBOM layer): how to invoke each generator on a target."""

from __future__ import annotations

from pathlib import Path

from chainguard.target import Target

EXTENSIONS = {"cyclonedx": "cdx.json", "spdx": "spdx.json"}


class Generator:
    name: str
    formats: tuple[str, ...]

    def output_format(self, requested: str) -> str:
        """The format this generator will actually emit for a requested format."""
        return requested if requested in self.formats else self.formats[0]

    def command(self, target: Target, output: Path, fmt: str, cdxgen_type: str | None = None) -> list[str]:
        raise NotImplementedError


class Syft(Generator):
    name = "syft"
    formats = ("cyclonedx", "spdx")
    _syft_formats = {"cyclonedx": "cyclonedx-json", "spdx": "spdx-json"}

    def command(self, target: Target, output: Path, fmt: str, cdxgen_type: str | None = None) -> list[str]:
        source = f"dir:{target.path}" if target.is_directory else f"docker-archive:{target.path}"
        return ["syft", "scan", source, "-q", "-o", f"{self._syft_formats[fmt]}={output}"]


class Cdxgen(Generator):
    name = "cdxgen"
    formats = ("cyclonedx",)

    def command(self, target: Target, output: Path, fmt: str, cdxgen_type: str | None = None) -> list[str]:
        project_type = "docker" if not target.is_directory else cdxgen_type
        cmd = ["cdxgen", "-o", str(output)]
        if project_type:
            cmd += ["-t", project_type]
        return [*cmd, str(target.path)]


GENERATORS: dict[str, Generator] = {g.name: g for g in (Syft(), Cdxgen())}
