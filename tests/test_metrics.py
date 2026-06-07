"""Tests for Prometheus metrics wiring."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from log_intel.alerts.engine import AlertEngine
from log_intel.metrics import ALERTS_FIRED, PARSE_DROP, generate_latest
from log_intel.models import LogEvent
from log_intel.store import EventStore


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "events.sqlite"
    s = EventStore(str(db), max_events=1000)
    s.upsert_alert_rule(
        {
            "name": "test",
            "query": "deny",
            "mode": "text",
            "enabled": True,
            "source_type": "palo_alto",
            "webhook_url": "",
        }
    )
    return s


def test_alerts_fired_counter(store, monkeypatch):
    monkeypatch.setattr(
        "log_intel.alerts.engine.deliver_webhook",
        lambda url, payload: True,
    )
    rule = store.list_alert_rules()[0]
    store.upsert_alert_rule({**rule, "webhook_url": "http://127.0.0.1:1/hook"})
    engine = AlertEngine(store)
    before = ALERTS_FIRED.labels(origin="hub")._value.get()  # noqa: SLF001
    ev = LogEvent(
        received_at=time.time(),
        source_type="palo_alto",
        remote_ip="10.0.0.1",
        transport="udp",
        raw="TRAFFIC deny something",
        message="TRAFFIC deny something",
        parser="test",
    )
    engine.evaluate(ev)
    engine.shutdown()
    after = ALERTS_FIRED.labels(origin="hub")._value.get()  # noqa: SLF001
    assert after >= before + 1


def test_queue_full_metric():
    PARSE_DROP.labels(reason="queue_full").inc()
    body = generate_latest().decode("utf-8")
    assert "log_intel_parse_drop_total" in body
    assert 'reason="queue_full"' in body
