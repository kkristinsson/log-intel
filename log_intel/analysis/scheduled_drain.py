"""Background periodic drain of unanalyzed hub events via loggy_ported analysis_service."""

from __future__ import annotations

import logging
import threading

from log_intel import hub_config as config
from log_intel.loggy_ported import analysis_service

log = logging.getLogger(__name__)


class ScheduledAnalysisDrain(threading.Thread):
    def __init__(self, store) -> None:
        super().__init__(name="scheduled-analysis-drain", daemon=True)
        self._store = store
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        log.info(
            "Scheduled analysis drain started (batch=%s interval=%ss)",
            config.ANALYSIS_BATCH_SIZE,
            config.ANALYSIS_INTERVAL_SEC,
        )
        while not self._stop.is_set():
            if config.LLM_ENABLED and config.ANALYSIS_AUTO:
                try:
                    result = analysis_service.drain_unanalyzed(
                        self._store,
                        inter_batch_sleep=config.ANALYSIS_INTER_BATCH_SLEEP_SEC,
                        stop_event=self._stop,
                    )
                    if result.batches_done:
                        log.info(
                            "Analysis drain: %s batches ok=%s fail=%s reason=%s",
                            result.batches_done,
                            result.batches_ok,
                            result.batches_fail,
                            result.stopped_reason,
                        )
                except Exception:
                    log.exception("Scheduled analysis drain error")
            if self._stop.wait(timeout=float(config.ANALYSIS_INTERVAL_SEC)):
                break
