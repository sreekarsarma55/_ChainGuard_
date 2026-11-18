"""Run each check script under tests/checks/ as one test.

The scripts are plain programs (python3 tests/checks/check_policy.py) that build small synthetic SBOMs, scans and runs,
and exit 1 with the failing cases printed. Running them through pytest gives one result per script. Most need no network
and no scanner. check_aliases.py asks OSV.dev for a few advisories and is skipped with --offline.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

CHECKS = Path(__file__).resolve().parent / "checks"
SCRIPTS = sorted(CHECKS.glob("check_*.py"))
NEEDS_NETWORK = {"check_aliases.py"}


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "script" in metafunc.fixturenames:
        metafunc.parametrize("script", SCRIPTS, ids=[p.stem for p in SCRIPTS])


def test_check(script: Path, request: pytest.FixtureRequest) -> None:
    if script.name in NEEDS_NETWORK and request.config.getoption("--offline", default=False):
        pytest.skip("needs network access (OSV.dev)")
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, f"{script.name} failed:\n{result.stdout}\n{result.stderr}"
