"""Run one external tool as a recorded step: command, environment overrides, exit code, wall time, log, output."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Step:
    name: str  # e.g. "syft", "syft+trivy", "direct+grype"
    kind: str  # "prepare" | "generate" | "scan"
    command: list[str]
    log: str  # path relative to the run directory
    output: str | None = None  # path relative to the run directory
    env: dict[str, str] = field(default_factory=dict)  # variables ChainGuard set for this step (recorded)
    returncode: int | None = None
    seconds: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "command": self.command,
            "env": self.env,
            "log": self.log,
            "output": self.output,
            "returncode": self.returncode,
            "seconds": self.seconds,
            "ok": self.ok,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Step:
        """A step as recorded in a run manifest (for reprocessing a run without executing anything)."""
        return cls(
            name=data["name"],
            kind=data["kind"],
            command=list(data.get("command") or []),
            log=data.get("log") or "",
            output=data.get("output"),
            env=dict(data.get("env") or {}),
            returncode=data.get("returncode"),
            seconds=data.get("seconds") or 0.0,
            error=data.get("error"),
        )


def run(step: Step, run_dir: Path, *, timeout: int = 1800) -> Step:
    """Execute ``step`` with stdout and stderr captured to its log. Never raises for tool failures."""
    log_path = run_dir / step.log
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        with log_path.open("w", encoding="utf-8") as log:
            proc = subprocess.run(
                step.command,
                stdout=log,
                stderr=subprocess.STDOUT,
                env=os.environ | step.env,
                timeout=timeout,
                check=False,
            )
        step.returncode = proc.returncode
        if proc.returncode != 0:
            step.error = f"exit code {proc.returncode} (see {step.log})"
    except subprocess.TimeoutExpired:
        step.error = f"timed out after {timeout} s"
    except OSError as exc:
        step.error = f"could not start {step.command[0]}: {exc.strerror or exc}"
    step.seconds = round(time.monotonic() - started, 2)
    if step.error is None and step.output:
        out = run_dir / step.output
        if not out.is_file() or out.stat().st_size == 0:
            step.error = f"exited 0 but wrote no {step.output}"
    return step
