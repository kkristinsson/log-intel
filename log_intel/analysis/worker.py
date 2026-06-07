"""Background LLM analysis worker."""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

from log_intel.analysis import ollama_client
from log_intel.config import get_settings

if TYPE_CHECKING:
    from log_intel.store import EventStore

log = logging.getLogger(__name__)


class AnalysisWorker:
    def __init__(self, store: EventStore) -> None:
        self._store = store
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="analysis-worker", daemon=True)
        self._thread.start()
        log.info("Analysis worker started")

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        settings = get_settings()
        while not self._stop.is_set():
            if not settings.llm_enabled:
                self._stop.wait(settings.analysis_interval_sec)
                continue
            try:
                self._run_batch()
            except Exception:
                log.exception("analysis worker error")
            self._stop.wait(settings.analysis_interval_sec)

    def _run_batch(self) -> None:
        settings = get_settings()
        events = self._store.unanalyzed_events(limit=settings.analysis_batch_size)
        if not events:
            return
        lines = [e.message for e in events]
        ids = [e.id for e in events if e.id is not None]
        job_id = self._store.create_analysis_job("batch", {"event_ids": ids})
        self._store.update_analysis_job(job_id, status="running")
        try:
            result, _raw = ollama_client.analyze_batch(lines)
            self._store.update_analysis_job(job_id, status="done", result=result)
            self._store.mark_analyzed(
                ids,
                analysis_id=0,
                severity=str(result.get("severity", "info")),
                summary=str(result.get("summary", "")),
            )
            log.info("Analyzed batch of %s events (job %s)", len(ids), job_id)
        except Exception as e:
            self._store.update_analysis_job(job_id, status="failed", error=str(e))
            log.warning("Batch analysis failed: %s", e)

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
        job_id = self._store.create_analysis_job("on_demand", {"event_ids": event_ids})
        self._store.update_analysis_job(job_id, status="running")

        def _work() -> None:
            try:
                result, _ = ollama_client.analyze_batch([e.message for e in events])
                self._store.update_analysis_job(job_id, status="done", result=result)
                self._store.mark_analyzed(
                    event_ids,
                    analysis_id=0,
                    severity=str(result.get("severity", "info")),
                    summary=str(result.get("summary", "")),
                )
            except Exception as e:
                self._store.update_analysis_job(job_id, status="failed", error=str(e))

        threading.Thread(target=_work, name=f"analyze-{job_id}", daemon=True).start()
        return job_id
