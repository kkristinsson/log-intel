"""Application state shared across routes and background tasks."""

from __future__ import annotations

import queue as qmod
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from log_intel.adapters.loggy_reader import LoggyReader
from log_intel.adapters.netsyslog_reader import NetsyslogReader
from log_intel.alerts.engine import AlertEngine
from log_intel.analysis.worker import AnalysisWorker
from log_intel.models import StreamEvent
from log_intel.store import EventStore


@dataclass
class HubState:
    store: EventStore
    alert_engine: AlertEngine
    analysis_worker: AnalysisWorker
    loggy: LoggyReader
    netsyslog: NetsyslogReader
    sync_stream_subscribers: list[qmod.Queue[StreamEvent | None]] = field(default_factory=list)
    recent_stream: deque[StreamEvent] = field(default_factory=lambda: deque(maxlen=500))
    ingest_stats: dict[str, Any] = field(default_factory=lambda: {"queue_drops": 0, "parse_drops": 0})

    def broadcast_sync(self, ev: StreamEvent) -> None:
        self.recent_stream.appendleft(ev)
        dead: list[qmod.Queue[StreamEvent | None]] = []
        for q in self.sync_stream_subscribers:
            try:
                q.put_nowait(ev)
            except qmod.Full:
                dead.append(q)
        for q in dead:
            if q in self.sync_stream_subscribers:
                self.sync_stream_subscribers.remove(q)

    def health_snapshot(self) -> dict[str, Any]:
        return {
            "events_stored": self.store.count_events(),
            "syslogb": {"ok": True, "integrated": True, "message": "vendored in log-intel"},
            "loggy": self.loggy.health(),
            "netsyslog": self.netsyslog.health(),
            "ingest": dict(self.ingest_stats),
        }
