"""On-demand LLM analysis worker (automatic batches use ScheduledAnalysisDrain)."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

from log_intel.analysis import ollama_client
from log_intel.config import get_settings

if TYPE_CHECKING:
    from log_intel.store import EventStore

log = logging.getLogger(__name__)


class AnalysisWorker:
    def __init__(self, store: EventStore) -> None:
        self._store = store

    def start(self) -> None:
        # Automatic batch analysis is owned by ScheduledAnalysisDrain.
        # This worker only serves hub on-demand analyze requests.
        log.debug("AnalysisWorker ready (on-demand only)")

    def stop(self) -> None:
        return None

    def run_on_demand(self, event_ids: list[int]) -> str:
        settings = get_settings()
        events = [self._store.get_event(eid) for eid in event_ids]
        events = [e for e in events if e is not None]
        if not events:
            job_id = self._store.create_analysis_job("on_demand", {"event_ids": []})
            self._store.update_analysis_job(
                job_id, status="failed", error="No events found"
            )
            return job_id
        ids = [e.id for e in events if e.id is not None]
        job_id = self._store.create_analysis_job("on_demand", {"event_ids": ids})
        self._store.update_analysis_job(job_id, status="running")

        def _work() -> None:
            try:
                result, raw = ollama_client.analyze_batch([e.message for e in events])
                anomalies = result.get("anomalies")
                if not isinstance(anomalies, list):
                    anomalies = []
                aid = self._store.insert_analysis(
                    ids,
                    model=settings.ollama_model,
                    raw_response=raw if isinstance(raw, str) else str(raw or "{}"),
                    severity=str(result.get("severity", "info")),
                    summary=str(result.get("summary", "")),
                    anomalies=[a for a in anomalies if isinstance(a, dict)],
                    error=None,
                )
                self._store.update_analysis_job(
                    job_id,
                    status="done",
                    result={**result, "analysis_id": aid},
                )
            except Exception as e:
                self._store.update_analysis_job(job_id, status="failed", error=str(e))

        threading.Thread(target=_work, name=f"analyze-{job_id}", daemon=True).start()
        return job_id
