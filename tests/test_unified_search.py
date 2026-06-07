"""Tests for unified cross-source search."""

from __future__ import annotations

import time

from log_intel.adapters.loggy_reader import LoggyReader
from log_intel.models import LogEvent
from log_intel.store import EventStore
from log_intel.unified_search import unified_search


def test_unified_search_hub_only(tmp_path):
    db = tmp_path / "events.sqlite"
    store = EventStore(str(db))
    store.insert(
        LogEvent(
            received_at=time.time(),
            source_type="palo_alto",
            remote_ip="1.2.3.4",
            transport="udp",
            raw="deny traffic",
            message="deny traffic from test",
            parser="test",
        )
    )
    result = unified_search(
        store,
        LoggyReader(db_path=""),
        "deny",
        include_hub=True,
        include_syslogb=False,
        hours=9999,
    )
    assert result.count >= 1
    assert result.counts_by_origin.get("hub", 0) >= 1
    assert result.results[0]["origin"] == "hub"
