"""SQLite store tests."""

from __future__ import annotations

import tempfile
from pathlib import Path

from log_intel.models import LogEvent
from log_intel.store import EventStore


def test_insert_and_search() -> None:
    with tempfile.TemporaryDirectory() as td:
        db = str(Path(td) / "test.sqlite")
        store = EventStore(db, max_events=1000)
        ev = LogEvent(
            received_at=1000.0,
            source_type="generic",
            remote_ip="1.2.3.4",
            transport="udp",
            raw="test",
            message="error connection failed from 1.2.3.4",
            parser="generic",
        )
        eid = store.insert(ev)
        assert eid == 1
        hits = store.search("error", since=0)
        assert len(hits) == 1
        assert hits[0].message.startswith("error")
        store.close()
