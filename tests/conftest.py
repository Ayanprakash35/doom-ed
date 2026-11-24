# SPDX-License-Identifier: GPL-3.0-or-later
"""Pytest configuration ensuring isolated test storage and auth defaults."""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest

_TEMP_DATA_DIR: Path | None = None


def _cleanup_temp_dir() -> None:
    if _TEMP_DATA_DIR is not None:
        shutil.rmtree(_TEMP_DATA_DIR, ignore_errors=True)


def pytest_addoption(parser: Any) -> None:
    """Register --tracing when pytest-playwright is not installed."""
    try:
        parser.addoption(
            "--tracing",
            action="store",
            default="off",
            choices=("off", "on", "retain-on-failure"),
            help="Playwright tracing mode when pytest-playwright is absent.",
        )
    except ValueError:
        pass


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: Any, call: Any) -> Any:
    """Record setup/call test reports on items for Playwright trace retention."""
    outcome = yield
    report = outcome.get_result()
    setattr(item, f"rep_{report.when}", report)


def pytest_configure(config: Any) -> None:
    """Allocate isolated temp data dir and safe defaults before test collection."""
    global _TEMP_DATA_DIR
    if _TEMP_DATA_DIR is None:
        _TEMP_DATA_DIR = Path(tempfile.mkdtemp(prefix="doomed-test-"))
        atexit.register(_cleanup_temp_dir)

    if not os.environ.get("DOOMED_DATA_DIR"):
        os.environ["DOOMED_DATA_DIR"] = str(_TEMP_DATA_DIR)
    os.environ.setdefault(
        "INDUSLMS_TOKEN_FILE",
        str(_TEMP_DATA_DIR / "no_induslms_token.json"),
    )
    os.environ.setdefault("DOOMED_AUTO_BOOTSTRAP_TOKEN", "0")
