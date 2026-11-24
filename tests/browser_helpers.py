# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared helpers for Playwright E2E tests (server lifecycle, browser launch, tracing)."""

from __future__ import annotations

import os
import re
import socket
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest
import uvicorn

try:  # Playwright is a dev dependency; keep collection friendly without it.
    from playwright.sync_api import sync_playwright

    PLAYWRIGHT_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only in minimal environments
    sync_playwright = None
    PLAYWRIGHT_AVAILABLE = False

_MISSING_BROWSER_MARKERS = (
    "Executable doesn't exist",
    "download new browsers",
    "Chromium distribution",
)


def find_free_port() -> int:
    """Bind an ephemeral localhost TCP port and return its port number."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def start_uvicorn_server(app: Any, timeout: float = 10.0) -> Iterator[str]:
    """Run an ASGI app on a free localhost port and yield its base URL."""
    port = find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                time.sleep(0.1)
        else:  # pragma: no cover - server failed to boot
            pytest.fail("The test server did not start.")
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def _is_missing_browser_error(exc: Exception) -> bool:
    message = str(exc)
    return any(marker in message for marker in _MISSING_BROWSER_MARKERS)


def launch_chromium_or_skip(playwright: Any) -> Any:
    """Launch bundled Chromium (or DOOMED_PLAYWRIGHT_CHANNEL), skipping if absent."""
    if playwright is None:
        pytest.skip("playwright is not installed")
    channel = os.environ.get("DOOMED_PLAYWRIGHT_CHANNEL", "").strip() or None
    launch_kwargs: dict[str, Any] = {"headless": True}
    if channel:
        launch_kwargs["channel"] = channel
    try:
        return playwright.chromium.launch(**launch_kwargs)
    except Exception as exc:  # pragma: no cover - depends on the host
        if _is_missing_browser_error(exc):
            pytest.skip(f"Playwright browser binary is not available: {exc}")
        raise


def _sanitize_nodeid(nodeid: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", nodeid).strip("-") or "trace"


@contextmanager
def managed_browser_context(
    browser: Any,
    request: pytest.FixtureRequest | None = None,
    *,
    trace_dir: Path | str | None = None,
    **context_kwargs: Any,
) -> Iterator[Any]:
    """Create a browser context with --tracing support and guaranteed cleanup."""
    tracing_mode = (
        request.config.getoption("--tracing", default="off")
        if request is not None
        else "off"
    )
    context = browser.new_context(**context_kwargs)
    tracing_started = tracing_mode in ("on", "retain-on-failure")
    if tracing_started:
        context.tracing.start(screenshots=True, snapshots=True)

    failed = False
    try:
        yield context
    except BaseException:
        failed = True
        raise
    finally:
        if request is not None:
            rep_setup = getattr(request.node, "rep_setup", None)
            rep_call = getattr(request.node, "rep_call", None)
            if getattr(rep_setup, "failed", False) or getattr(rep_call, "failed", False):
                failed = True
        try:
            if tracing_started:
                should_save = tracing_mode == "on" or (
                    tracing_mode == "retain-on-failure" and failed
                )
                if should_save:
                    out_dir = Path(trace_dir) if trace_dir is not None else Path("test-results")
                    out_dir.mkdir(parents=True, exist_ok=True)
                    nodeid = request.node.nodeid if request is not None else "trace"
                    trace_path = out_dir / f"{_sanitize_nodeid(nodeid)}.zip"
                    context.tracing.stop(path=str(trace_path))
                else:
                    context.tracing.stop()
        finally:
            context.close()
