from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from pathlib import Path

from log_intel.syslogb.app.job_cancel import JobCancelled
from log_intel.syslogb.app.store import AnalysisStore
from log_intel.syslogb.rag.pipeline import analyze_file

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AnalyzeJobOpts:
    window: str | None = None


class AnalyzeWorker:
    def __init__(self, store: AnalysisStore) -> None:
        self._store = store
        self._q: queue.Queue[tuple[str, Path, AnalyzeJobOpts]] = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="analyze-worker", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._q.put(("", Path("."), AnalyzeJobOpts()))  # unblock
        self._thread.join(timeout=5)

    def enqueue(self, job_id: str, path: Path, *, window: str | None = None) -> None:
        self._q.put((job_id, path, AnalyzeJobOpts(window=window)))

    def _cancelled(self, job_id: str) -> bool:
        job = self._store.get_job(job_id)
        return bool(job and job.get("status") == "cancelled")

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                job_id, path, opts = self._q.get(timeout=1)
            except queue.Empty:
                continue
            if self._stop.is_set() or not job_id:
                break
            if self._cancelled(job_id):
                continue
            self._store.update_job(job_id, status="running")
            stage = (
                "Queued — starting time-range analysis"
                if opts.window is not None
                else "Queued — starting full-file analysis"
            )
            self._store.update_job_progress(job_id, 2, stage)

            def on_progress(pct: int, stage: str) -> None:
                if self._cancelled(job_id):
                    raise JobCancelled()
                self._store.update_job_progress(job_id, pct, stage)

            try:
                parsed, raw, mode = analyze_file(
                    path,
                    on_progress=on_progress,
                    should_cancel=lambda: self._cancelled(job_id),
                    window=opts.window,
                )
                if self._cancelled(job_id):
                    continue
                self._store.update_job_progress(job_id, 100, "Complete")
                self._store.update_job(
                    job_id,
                    status="done",
                    result=parsed,
                    raw=raw,
                )
                logger.info("Analysis job %s done (%s)", job_id, mode)
            except JobCancelled:
                logger.info("Analysis job %s cancelled", job_id)
            except Exception as e:
                if self._cancelled(job_id):
                    logger.info("Analysis job %s cancelled during error", job_id)
                    continue
                logger.exception("Analysis job %s failed", job_id)
                self._store.update_job_progress(job_id, 100, "Failed")
                self._store.update_job(job_id, status="error", error=str(e))
