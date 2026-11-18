from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--offline", action="store_true", default=False, help="skip the checks that need network access")
