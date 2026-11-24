# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for shared Playwright helpers and --tracing retention."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tests.browser_helpers import launch_chromium_or_skip, managed_browser_context


def _fake_request(nodeid: str, tracing_mode: str, *, rep_setup=None, rep_call=None):
    config = MagicMock()
    config.getoption.return_value = tracing_mode
    node = SimpleNamespace(nodeid=nodeid, rep_setup=rep_setup, rep_call=rep_call)
    return SimpleNamespace(config=config, node=node)


def _fake_browser():
    context = MagicMock()
    browser = MagicMock()
    browser.new_context.return_value = context
    return browser, context


def test_managed_browser_context_tracing_off_skips_tracing(tmp_path):
    browser, context = _fake_browser()
    req = _fake_request("tests/test_x.py::test_ok", "off")

    with managed_browser_context(browser, req, trace_dir=tmp_path, viewport={"width": 800, "height": 600}) as ctx:
        assert ctx is context

    browser.new_context.assert_called_once_with(viewport={"width": 800, "height": 600})
    context.tracing.start.assert_not_called()
    context.tracing.stop.assert_not_called()
    context.close.assert_called_once()
    assert list(tmp_path.iterdir()) == []


def test_managed_browser_context_retain_on_failure_discards_on_pass(tmp_path):
    browser, context = _fake_browser()
    req = _fake_request("tests/test_x.py::test_pass", "retain-on-failure")

    with managed_browser_context(browser, req, trace_dir=tmp_path):
        pass

    context.tracing.start.assert_called_once_with(screenshots=True, snapshots=True)
    context.tracing.stop.assert_called_once_with()
    context.close.assert_called_once()
    assert list(tmp_path.iterdir()) == []


def test_managed_browser_context_retain_on_failure_saves_on_exception(tmp_path):
    browser, context = _fake_browser()
    req = _fake_request("tests/test_x.py::test_fail", "retain-on-failure")

    with pytest.raises(AssertionError):
        with managed_browser_context(browser, req, trace_dir=tmp_path):
            raise AssertionError("boom")

    expected_path = str(tmp_path / "tests-test_x.py-test_fail.zip")
    context.tracing.start.assert_called_once_with(screenshots=True, snapshots=True)
    context.tracing.stop.assert_called_once_with(path=expected_path)
    context.close.assert_called_once()


def test_managed_browser_context_tracing_on_always_saves(tmp_path):
    browser, context = _fake_browser()
    req = _fake_request("tests/test_x.py::test_always", "on")

    with managed_browser_context(browser, req, trace_dir=tmp_path):
        pass

    expected_path = str(tmp_path / "tests-test_x.py-test_always.zip")
    context.tracing.stop.assert_called_once_with(path=expected_path)
    context.close.assert_called_once()


def test_launch_chromium_or_skip_uses_bundled_default_and_channel_override(monkeypatch):
    pw = MagicMock()
    monkeypatch.delenv("DOOMED_PLAYWRIGHT_CHANNEL", raising=False)
    launch_chromium_or_skip(pw)
    pw.chromium.launch.assert_called_once_with(headless=True)

    pw.reset_mock()
    monkeypatch.setenv("DOOMED_PLAYWRIGHT_CHANNEL", "chrome")
    launch_chromium_or_skip(pw)
    pw.chromium.launch.assert_called_once_with(headless=True, channel="chrome")


def test_launch_chromium_or_skip_skips_only_on_missing_binary(monkeypatch):
    monkeypatch.delenv("DOOMED_PLAYWRIGHT_CHANNEL", raising=False)
    pw = MagicMock()
    pw.chromium.launch.side_effect = RuntimeError("Executable doesn't exist at /tmp/chromium")
    with pytest.raises(pytest.skip.Exception):
        launch_chromium_or_skip(pw)

    pw.chromium.launch.side_effect = RuntimeError("Unexpected permission failure")
    with pytest.raises(RuntimeError, match="Unexpected permission failure"):
        launch_chromium_or_skip(pw)
