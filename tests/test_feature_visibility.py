"""Tests for product UI feature visibility."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from log_intel.feature_visibility import compute_ui_features
from log_intel.hub_state import HubState
from log_intel.models import LogEvent
from log_intel.store import EventStore


def _hub_with_store(db_path: str) -> HubState:
    store = EventStore(db_path, max_events=1000)
    loggy = MagicMock()
    loggy.health.return_value = {"ok": False}
    netsyslog = MagicMock()
    netsyslog.health.return_value = {"ok": False}
    return HubState(
        store=store,
        alert_engine=MagicMock(),
        analysis_worker=MagicMock(),
        loggy=loggy,
        netsyslog=netsyslog,
    )


def test_empty_hub_hides_network_surfaces(monkeypatch) -> None:
    monkeypatch.setenv("LOG_INTEL_LLM_ENABLED", "0")
    monkeypatch.setenv("MIST_ENABLED", "0")
    from log_intel.config import get_settings

    get_settings.cache_clear()

    with tempfile.TemporaryDirectory() as td:
        hub = _hub_with_store(str(Path(td) / "events.sqlite"))
        ui = compute_ui_features(hub)
        assert ui["hub"] is False
        assert ui["hub_firewall"] is False
        assert ui["hub_geo"] is False
        assert ui["hub_analysis"] is False
        assert ui["hub_loggy_search"] is False


def test_palo_events_show_firewall(monkeypatch) -> None:
    monkeypatch.setenv("LOG_INTEL_LLM_ENABLED", "0")
    from log_intel.config import get_settings

    get_settings.cache_clear()

    with tempfile.TemporaryDirectory() as td:
        hub = _hub_with_store(str(Path(td) / "events.sqlite"))
        hub.store.insert(
            LogEvent(
                received_at=1000.0,
                source_type="palo_alto",
                remote_ip="10.0.0.1",
                transport="udp",
                raw="TRAFFIC,allow",
                message="TRAFFIC,allow",
                parser="palo",
                log_type="TRAFFIC",
            )
        )
        ui = compute_ui_features(hub)
        assert ui["hub_firewall"] is True
        assert ui["hub"] is True
        hub.store.close()


def test_loggy_configured_shows_search_and_hub(monkeypatch) -> None:
    monkeypatch.setenv("LOG_INTEL_LLM_ENABLED", "0")
    from log_intel.config import get_settings

    get_settings.cache_clear()

    with tempfile.TemporaryDirectory() as td:
        hub = _hub_with_store(str(Path(td) / "events.sqlite"))
        hub.loggy.health.return_value = {"ok": True, "raw_log_count": 10}
        ui = compute_ui_features(hub)
        assert ui["hub_loggy_search"] is True
        assert ui["hub_health_loggy"] is True
        assert ui["hub"] is True
        hub.store.close()
