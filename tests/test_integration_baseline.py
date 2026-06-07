"""Baseline integration smoke tests for unified log-intel."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from log_intel.main import init_hub_services
from log_intel.store import EventStore, LogStore


def test_event_store_is_logstore() -> None:
    with tempfile.TemporaryDirectory() as td:
        db = str(Path(td) / "events.sqlite")
        store = EventStore(db)
        assert isinstance(store, LogStore)
        batch = store.fetch_unanalyzed_batch(5)
        assert batch == []
        store.close()


def test_hub_services_init(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as td:
        monkeypatch.setenv("LOG_INTEL_DATA_DIR", td)
        monkeypatch.setenv("LOG_INTEL_SQLITE_PATH", str(Path(td) / "events.sqlite"))
        monkeypatch.setenv("LOG_INTEL_LLM_ENABLED", "0")
        from log_intel.config import get_settings

        get_settings.cache_clear()
        from log_intel import main as main_mod

        main_mod._hub = None
        main_mod._scheduled_drain = None
        main_mod._meta_worker = None
        main_mod._mist_poller = None
        hub = init_hub_services()
        assert hub.store.count_events() == 0
        snap = hub.health_snapshot()
        assert "events_stored" in snap
        from log_intel.hub_ingest import stop_hub_ingest

        stop_hub_ingest()
        hub.store.close()
