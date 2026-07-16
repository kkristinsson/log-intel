"""Regression tests for medium-severity bugfixes."""

from __future__ import annotations

import queue as qmod
import threading
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from log_intel.alerts.engine import AlertEngine
from log_intel.hub_state import HubState
from log_intel.models import StreamEvent
from log_intel.parsers.palo_alto import _parse_ts_from_palo
from log_intel.syslogb.app.alert_engine import AlertEngine as FileAlertEngine
from log_intel.syslogb.app.journal_source import JournalSpec
from log_intel.syslogb.app.journal_tailer import JournalTailer
from log_intel.syslogb.app.security import post_json_webhook, resolve_webhook_connect_ip


def test_palo_event_ts_is_utc() -> None:
    row = ["x"] * 10
    row[5] = "2026/04/12 10:15:01"
    ts = _parse_ts_from_palo(row, time_col=5)
    expected = datetime(2026, 4, 12, 10, 15, 1, tzinfo=timezone.utc).timestamp()
    assert ts == expected


def test_alert_log_dir_does_not_match_prefix_sibling(tmp_path: Path) -> None:
    log_dir = tmp_path / "var" / "log"
    log_dir.mkdir(parents=True)
    evil = tmp_path / "var" / "log-evil"
    evil.mkdir()
    good = log_dir / "app.log"
    bad = evil / "app.log"
    good.write_text("x\n")
    bad.write_text("x\n")

    rule = {"log_dir": str(log_dir), "file_glob": "*.log"}
    engine = AlertEngine.__new__(AlertEngine)
    assert engine._rule_matches_path(rule, good) is True
    assert engine._rule_matches_path(rule, bad) is False

    file_engine = FileAlertEngine.__new__(FileAlertEngine)
    assert file_engine._rule_matches_path(rule, good) is True
    assert file_engine._rule_matches_path(rule, bad) is False


def test_hub_sse_subscriber_add_remove_is_thread_safe() -> None:
    hub = HubState(
        store=MagicMock(),
        alert_engine=MagicMock(),
        analysis_worker=MagicMock(),
        loggy=MagicMock(),
        netsyslog=MagicMock(),
    )
    qs = [qmod.Queue(maxsize=10) for _ in range(20)]
    errors: list[BaseException] = []

    def add_all() -> None:
        try:
            for q in qs:
                hub.add_sync_subscriber(q)
        except BaseException as e:
            errors.append(e)

    def remove_all() -> None:
        try:
            for q in qs:
                hub.remove_sync_subscriber(q)
        except BaseException as e:
            errors.append(e)

    def broadcast() -> None:
        try:
            for i in range(50):
                hub.broadcast_sync(
                    StreamEvent(
                        id=i,
                        received_at=0.0,
                        source_type="generic",
                        message=f"m{i}",
                        remote_ip="1.1.1.1",
                        importance="info",
                    )
                )
        except BaseException as e:
            errors.append(e)

    threads = [
        threading.Thread(target=add_all),
        threading.Thread(target=broadcast),
        threading.Thread(target=remove_all),
        threading.Thread(target=broadcast),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert not errors


def test_journal_tailer_stop_from_run_does_not_join_self() -> None:
    spec = JournalSpec(uri="journal://system", boot_only=False)
    tailer = JournalTailer(spec, on_failure_line=lambda *a: None)
    # Simulate being inside the worker thread.
    tailer._thread = threading.current_thread()
    tailer._proc = None
    # Must not raise RuntimeError: cannot join current thread
    tailer.stop()


def test_resolve_webhook_connect_ip_blocks_private(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOG_INTEL_WEBHOOK_ALLOW_PRIVATE", raising=False)
    ok, err, ip = resolve_webhook_connect_ip("http://127.0.0.1/hook")
    assert not ok
    assert ip is None
    assert "private" in err.lower() or "internal" in err.lower()


def test_post_json_webhook_pins_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOG_INTEL_WEBHOOK_ALLOW_PRIVATE", raising=False)

    class _Resp:
        status = 204

        def read(self) -> bytes:
            return b""

    class _Conn:
        def __init__(self, *a, **k) -> None:
            self.sock = None

        def request(self, method, path, body=None, headers=None) -> None:
            assert method == "POST"
            assert path == "/hook"
            assert headers is not None
            assert headers.get("Host") == "example.com"

        def getresponse(self) -> _Resp:
            return _Resp()

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        "log_intel.syslogb.app.security.resolve_webhook_connect_ip",
        lambda url: (True, "", "203.0.113.10"),
    )
    monkeypatch.setattr(
        "log_intel.syslogb.app.security.validate_outbound_webhook_url",
        lambda url: (True, ""),
    )
    monkeypatch.setattr("log_intel.syslogb.app.security.http.client.HTTPConnection", _Conn)
    post_json_webhook("http://example.com/hook", {"ok": True})
