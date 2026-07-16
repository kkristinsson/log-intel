"""Regression tests for critical/high bugfixes."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from log_intel.config import Settings
from log_intel.ingest.classifier import classify_and_parse
from log_intel.ingest.mist_poller import mist_event_to_log
from log_intel.ingest.syslog_server import _read_octet_frame, handle_tcp_client
from log_intel.models import LogEvent
from log_intel.parsers.generic import parse_generic_syslog
from log_intel.parsers.palo_alto import _rfc5424_message, parse_palo_alto_syslog
from log_intel.store import EventStore
from log_intel.syslogb.app.tailer import FileTailer


def test_mist_dedup_survives_event_prune(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "log_intel.config.get_settings",
        lambda: Settings(reserve_events_mist=0, reserve_events_palo=0),
    )
    event = {
        "id": "evt-prune-1",
        "type": "AP_DISCONNECTED",
        "message": "down",
        "timestamp": 1_700_000_000,
    }
    ev = mist_event_to_log(event, raw_truncate=4096)

    with tempfile.TemporaryDirectory() as td:
        store = EventStore(str(Path(td) / "events.sqlite"), max_events=2)
        assert not store.has_parser(ev.parser)
        store.insert(ev)
        assert store.has_parser(ev.parser)

        for i in range(5):
            store.insert(
                LogEvent(
                    received_at=1000.0 + i,
                    source_type="generic",
                    remote_ip="1.1.1.1",
                    transport="udp",
                    raw=f"n{i}",
                    message=f"noise {i}",
                    parser="generic",
                )
            )

        assert store.count_events() <= 2
        assert store.count_events_by_source_type("mist") == 0
        assert store.has_parser(ev.parser)
        store.close()


def test_rfc5424_windows_pusher_three_nil_marker() -> None:
    raw = (
        "<14>1 2026-07-16T10:00:00.000Z WINHOST WindowsEvents - - - "
        "Failed password for user from 203.0.113.50 port 22"
    )
    body = _rfc5424_message(raw)
    assert body.startswith("Failed password")
    assert "WINHOST" not in body
    assert "WindowsEvents" not in body

    ev = parse_generic_syslog(raw, "10.0.0.2", "tcp", 1000.0, 4096, source_type="windows")
    assert ev is not None
    assert ev.message.startswith("Failed password")
    assert ev.src_ip == "203.0.113.50"

    classified = classify_and_parse(raw, "10.0.0.2", "tcp", 4096)
    assert classified is not None
    assert classified.message.startswith("Failed password")


def test_rfc5424_palo_four_nil_still_works() -> None:
    fixture = Path(__file__).parent / "fixtures" / "pan_sample.syslog"
    if not fixture.is_file():
        pytest.skip("fixture missing")
    raw = fixture.read_text().splitlines()[0].strip()
    ev = parse_palo_alto_syslog(raw, "10.0.0.1", "udp", 1000.0, 2048)
    assert ev is not None
    assert ev.log_type == "TRAFFIC"


def test_prune_enforces_max_events_despite_floors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "log_intel.config.get_settings",
        lambda: Settings(reserve_events_mist=1000, reserve_events_palo=1000),
    )

    with tempfile.TemporaryDirectory() as td:
        store = EventStore(str(Path(td) / "events.sqlite"), max_events=5)
        for i in range(20):
            store.insert(
                LogEvent(
                    received_at=1000.0 + i,
                    source_type="mist" if i % 2 == 0 else "palo_alto",
                    remote_ip="1.1.1.1",
                    transport="udp",
                    raw=f"r{i}",
                    message=f"m{i}",
                    parser=f"mist:id-{i}" if i % 2 == 0 else f"palo:{i}",
                )
            )
        assert store.count_events() == 5
        store.close()


def test_file_tailer_reopens_at_start_after_truncate() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "app.log"
        path.write_text("old line that is longer\n")

        tailer = FileTailer(path, on_failure_line=lambda *a: None)
        assert tailer._open_at_end()
        tailer._offset = path.stat().st_size

        # Shrink in place (classic truncate); must reopen at offset 0, not EOF.
        path.write_text("err\n")
        assert path.stat().st_size < tailer._offset
        assert tailer._maybe_reopen()
        assert tailer._offset == 0
        tailer._close()


def test_file_tailer_reopens_at_start_after_rotation() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "app.log"
        path.write_text("old\n")

        tailer = FileTailer(path, on_failure_line=lambda *a: None)
        assert tailer._open_at_end()
        old_inode = tailer._inode

        path.rename(path.with_suffix(".log.1"))
        path.write_text("error failed login\n")
        assert path.stat().st_ino != old_inode
        assert tailer._maybe_reopen()
        assert tailer._offset == 0
        tailer._close()


def test_octet_framing_reads_length_prefixed_message() -> None:
    msg = b"<14>1 2026-07-16T10:00:00Z host app - - - hello"
    frame = f"{len(msg)} ".encode("ascii") + msg

    class _Reader:
        def __init__(self, data: bytes) -> None:
            self._data = data
            self._i = 0

        async def read(self, n: int) -> bytes:
            if self._i >= len(self._data):
                return b""
            chunk = self._data[self._i : self._i + n]
            self._i += len(chunk)
            return chunk

        async def readexactly(self, n: int) -> bytes:
            chunk = self._data[self._i : self._i + n]
            if len(chunk) < n:
                raise asyncio.IncompleteReadError(chunk, n)
            self._i += n
            return chunk

    got = asyncio.run(_read_octet_frame(_Reader(frame)))  # type: ignore[arg-type]
    assert got == msg


def test_handle_tcp_octet_enqueues_frame() -> None:
    msg = b"hello-syslog"
    payload = f"{len(msg)} ".encode("ascii") + msg

    class _Reader:
        def __init__(self) -> None:
            self._data = payload
            self._i = 0

        async def read(self, n: int) -> bytes:
            if self._i >= len(self._data):
                return b""
            chunk = self._data[self._i : self._i + n]
            self._i += len(chunk)
            return chunk

        async def readexactly(self, n: int) -> bytes:
            chunk = self._data[self._i : self._i + n]
            if len(chunk) < n:
                raise asyncio.IncompleteReadError(chunk, n)
            self._i += n
            return chunk

    class _Writer:
        def get_extra_info(self, name: str):
            return ("9.9.9.9", 1234)

        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def _run() -> bytes:
        q: asyncio.Queue = asyncio.Queue()
        await handle_tcp_client(_Reader(), _Writer(), q, "octet")  # type: ignore[arg-type]
        item = q.get_nowait()
        return item[0]

    assert asyncio.run(_run()) == msg
