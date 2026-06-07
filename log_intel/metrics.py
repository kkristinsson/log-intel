"""Prometheus metrics for log-intel."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, generate_latest

INGEST_TOTAL = Counter(
    "log_intel_ingest_total",
    "Syslog messages received",
    ["transport"],
)
PARSE_OK = Counter(
    "log_intel_parse_ok_total",
    "Messages successfully parsed and stored",
    ["source_type"],
)
PARSE_DROP = Counter(
    "log_intel_parse_drop_total",
    "Messages dropped (queue full or parse failure)",
    ["reason"],
)
EVENTS_STORED = Gauge("log_intel_events_stored", "Current event count in SQLite")
QUEUE_DEPTH = Gauge("log_intel_queue_depth", "Syslog processing queue depth")
ALERTS_FIRED = Counter("log_intel_alerts_fired_total", "Alerts fired", ["origin"])


def metrics_bytes() -> bytes:
    return generate_latest()
