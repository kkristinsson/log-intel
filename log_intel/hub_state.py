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
from log_intel.sources_registry import SourceDef, load_sources, sources_health
from log_intel.store import EventStore


@dataclass
class HubState:
    store: EventStore
    alert_engine: AlertEngine
    analysis_worker: AnalysisWorker
    loggy: LoggyReader
    netsyslog: NetsyslogReader
    sources: tuple[SourceDef, ...] = field(default_factory=tuple)
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
        journal_ok = False
        journal_msg = ""
        try:
            from log_intel.syslogb.bootstrap import get_runtime

            runtime = get_runtime()
            if runtime and runtime.tail_service:
                js = runtime.tail_service.journal_status
                journal_ok = bool(js.get("ok"))
                journal_msg = str(js.get("message", ""))
        except Exception:
            pass
        return {
            "events_stored": self.store.count_events(),
            "sources": sources_health(),
            "syslogb": {"ok": True, "integrated": True, "message": "file logs integrated"},
            "loggy": self.loggy.health(),
            "netsyslog": self.netsyslog.health(),
            "mist": self.mist_health(),
            "ingest": {**dict(self.ingest_stats), "journal_ok": journal_ok, "journal_msg": journal_msg},
        }

    def mist_health(self) -> dict[str, Any]:
        try:
            from log_intel.main import get_mist_poller

            poller = get_mist_poller()
            if poller is not None:
                return poller.health()
        except Exception:
            pass
        settings = None
        try:
            from log_intel.config import get_settings

            settings = get_settings()
        except Exception:
            pass
        if settings is None:
            return {"ok": False, "enabled": False, "configured": False, "last_error": "unavailable"}
        configured = bool(settings.mist_enabled and settings.mist_api_key.strip())
        return {
            "ok": configured,
            "enabled": settings.mist_enabled,
            "configured": configured,
            "last_poll_at": 0.0,
            "last_inserted": 0,
            "last_error": "",
            "org_id": settings.mist_org_id,
            "base_url": settings.mist_base_url,
        }
