"""Tests for setup checklist and store improvements."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from log_intel.models import LogEvent
from log_intel.setup_checklist import compute_setup_checklist
from log_intel.store import EventStore


def test_setup_checklist_includes_core_items(monkeypatch) -> None:
    monkeypatch.setenv("LOG_INTEL_LLM_ENABLED", "0")
    from log_intel.config import get_settings

    get_settings.cache_clear()
    items = compute_setup_checklist(None)
    ids = {i["id"] for i in items}
    assert "log_dirs" in ids
    assert "mist" in ids
    assert "webhook_secret" in ids


def test_bootstrap_keeps_fresh_install_in_setup(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from log_intel import settings_bridge

    settings_bridge._store = None
    store = settings_bridge.bootstrap_settings_store()

    assert store.get("DATA_DIR") == str(tmp_path)
    assert store.get("SETUP_COMPLETE") is None

    settings_bridge._store = None


def test_bootstrap_marks_legacy_settings_complete(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from log_intel import settings_bridge
    from log_intel.syslogb.app.store import AppStore

    legacy_store = AppStore(db_path=tmp_path / "analyses.db")
    legacy_store.set_many({"DATA_DIR": str(tmp_path)})

    settings_bridge._store = None
    store = settings_bridge.bootstrap_settings_store()

    assert store.get("SETUP_COMPLETE") == "1"

    settings_bridge._store = None


def test_related_events_by_ip() -> None:
    with tempfile.TemporaryDirectory() as td:
        store = EventStore(str(Path(td) / "t.sqlite"), max_events=100)
        base = LogEvent(
            received_at=1000.0,
            source_type="mist",
            remote_ip="10.1.1.1",
            transport="mist_api",
            raw="{}",
            message="client aa:bb:cc:dd:ee:ff joined",
            parser="mist:1",
        )
        eid = store.insert(base)
        store.insert(
            LogEvent(
                received_at=1001.0,
                source_type="mist",
                remote_ip="10.1.1.1",
                transport="mist_api",
                raw="{}",
                message="same client aa:bb:cc:dd:ee:ff left",
                parser="mist:2",
            )
        )
        related = store.related_events(eid, limit=10)
        assert len(related) >= 1
        store.close()


def test_prune_respects_mist_floor(monkeypatch) -> None:
    monkeypatch.setenv("LOG_INTEL_MAX_EVENTS", "3")
    monkeypatch.setenv("LOG_INTEL_RESERVE_EVENTS_MIST", "2")
    from log_intel.config import get_settings

    get_settings.cache_clear()

    with tempfile.TemporaryDirectory() as td:
        store = EventStore(str(Path(td) / "t.sqlite"), max_events=3)
        for i in range(3):
            store.insert(
                LogEvent(
                    received_at=float(i),
                    source_type="palo_alto" if i < 2 else "mist",
                    remote_ip="1.2.3.4",
                    transport="udp",
                    raw="x",
                    message="traffic",
                    parser=f"p{i}",
                )
            )
        assert store.count_events_by_source_type("mist") >= 1
        store.close()
