"""Tests for loggy_ported analysis_service + EventStore v2."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from log_intel.models import LogEvent
from log_intel.store import EventStore


def _insert_event(store: EventStore, msg: str, ts: float = 1000.0) -> int:
    return store.insert(
        LogEvent(
            received_at=ts,
            source_type="generic",
            remote_ip="1.2.3.4",
            transport="udp",
            raw=msg,
            message=msg,
            parser="generic",
        )
    )


def test_insert_analysis_marks_events() -> None:
    with tempfile.TemporaryDirectory() as td:
        store = EventStore(str(Path(td) / "t.sqlite"))
        eid = _insert_event(store, "error connection reset")
        aid = store.insert_analysis(
            [eid],
            model="test",
            raw_response="{}",
            severity="high",
            summary="bad",
            anomalies=[],
            error=None,
        )
        assert aid == 1
        batch = store.fetch_unanalyzed_batch(10)
        assert batch == []
        recent = store.recent_analyses(limit=5)
        assert recent[0]["severity"] == "high"
        store.close()


def test_drain_skips_blocked_when_enabled(monkeypatch) -> None:
    from log_intel.loggy_ported import analysis_service

    with tempfile.TemporaryDirectory() as td:
        store = EventStore(str(Path(td) / "t.sqlite"))
        blocked = _insert_event(store, "action=deny src=1.1.1.1")
        _insert_event(store, "error ssh failed")
        with patch.object(analysis_service, "process_one_batch", wraps=analysis_service.process_one_batch) as proc:
            with patch("log_intel.analysis.ollama_client.analyze_batch") as mock_llm:
                mock_llm.return_value = ({"severity": "low", "summary": "ok", "anomalies": []}, "{}")
                result = analysis_service.drain_unanalyzed(store, max_batches=2)
        assert result.batches_done >= 1
        assert store.count_unanalyzed_in_range(0, None) == 0
        store.close()
