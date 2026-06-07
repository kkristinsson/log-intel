"""Unified alert engine tests."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from log_intel.alerts.engine import AlertEngine
from log_intel.models import LogEvent
from log_intel.store import EventStore


def test_hub_evaluate_fires_webhook() -> None:
    with tempfile.TemporaryDirectory() as td:
        store = EventStore(str(Path(td) / "t.sqlite"))
        store.upsert_alert_rule(
            {
                "name": "deny",
                "query": "deny",
                "mode": "text",
                "enabled": True,
                "webhook_url": "http://127.0.0.1:9/hook",
            }
        )
        engine = AlertEngine(store)
        with patch("log_intel.alerts.engine.deliver_webhook", return_value=True):
            engine.evaluate(
                LogEvent(
                    received_at=1.0,
                    source_type="palo_alto",
                    remote_ip="10.0.0.1",
                    transport="udp",
                    raw="traffic deny",
                    message="traffic deny from 10.0.0.1",
                    parser="palo",
                )
            )
        events = store.list_alert_events(limit=5)
        assert len(events) >= 1
        engine.shutdown()
        store.close()


def test_on_line_respects_cooldown() -> None:
    with tempfile.TemporaryDirectory() as td:
        store = EventStore(str(Path(td) / "t.sqlite"))
        store.upsert_alert_rule(
            {
                "name": "err",
                "query": "error",
                "mode": "text",
                "enabled": True,
                "cooldown_sec": 3600,
                "webhook_url": "http://127.0.0.1:9/hook",
            }
        )
        engine = AlertEngine(store)
        with patch("log_intel.alerts.engine.deliver_webhook", return_value=True):
            engine.on_line("/var/log/syslog", "error line one", 1.0, 1.0)
            engine.on_line("/var/log/syslog", "error line two", 2.0, 2.0)
        events = store.list_alert_events(limit=10)
        assert len(events) == 2
        delivered = [e["delivered"] for e in events]
        assert delivered.count(True) == 1
        engine.shutdown()
        store.close()
