"""Tests for Juniper Mist ingest helpers."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from log_intel.ingest.mist_poller import mist_event_parser_key, mist_event_to_log, parse_mist_timestamp
from log_intel.store import EventStore


def test_parse_mist_timestamp_seconds_and_ms() -> None:
    assert parse_mist_timestamp({"timestamp": 1_700_000_000}) == 1_700_000_000.0
    assert parse_mist_timestamp({"timestamp": 1_700_000_000_000}) == 1_700_000_000.0


def test_mist_event_to_log_and_dedup() -> None:
    event = {
        "id": "evt-123",
        "type": "AP_DISCONNECTED",
        "message": "Client lost association",
        "timestamp": int(time.time()),
        "site_name": "HQ",
    }
    ev = mist_event_to_log(event, raw_truncate=4096)
    assert ev.source_type == "mist"
    assert ev.transport == "mist_api"
    assert "AP_DISCONNECTED" in ev.message
    assert ev.parser == "mist:evt-123"

    with tempfile.TemporaryDirectory() as td:
        store = EventStore(str(Path(td) / "events.sqlite"))
        assert not store.has_parser(ev.parser)
        eid = store.insert(ev)
        assert eid > 0
        assert store.has_parser(ev.parser)
        store.close()


def test_mist_event_parser_key_hash_fallback() -> None:
    key = mist_event_parser_key({"type": "alarm", "message": "link down"})
    assert key.startswith("mist:hash:")
