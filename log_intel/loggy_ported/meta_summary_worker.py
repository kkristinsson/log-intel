import logging
import threading
import time
from typing import TYPE_CHECKING

from log_intel import hub_config as config
from log_intel.analysis import ollama_client
from log_intel.loggy_ported import meta_context

if TYPE_CHECKING:
    from log_intel.store import LogStore

logger = logging.getLogger(__name__)


def _period_label(granularity: str, start: float, end: float) -> str:
    a = time.strftime("%Y-%m-%d", time.gmtime(start))
    b = time.strftime("%Y-%m-%d", time.gmtime(end))
    return f"{granularity}:{a}_to_{b}"


class MetaSummaryWorker(threading.Thread):
    """Scheduled LLM passes over bulk stored analyses (daily + weekly windows)."""

    def __init__(self, store: "LogStore") -> None:
        super().__init__(name="meta-summary-worker", daemon=True)
        self._store = store
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def _maybe_daily(self) -> None:
        now = time.time()
        last_ok, last_any = self._store.meta_attempt_timestamps("daily")
        if last_any is not None and (now - last_any) < float(config.META_MIN_RETRY_SEC):
            return
        if last_ok is not None and (now - last_ok) < float(config.META_DAILY_INTERVAL_SEC):
            return
        end = now
        start = end - float(config.META_DAILY_INTERVAL_SEC)
        n = self._store.count_analyses_between(start, end)
        if n < int(config.META_MIN_ANALYSES_DAILY):
            logger.info("Meta daily: skip (only %s analyses in window; need ≥%s)", n, config.META_MIN_ANALYSES_DAILY)
            return
        label = _period_label("daily", start, end)
        ctx = meta_context.build_daily_meta_context(self._store, start, end)
        logger.info("Meta daily: calling Ollama (%s analyses, %s chars context)", n, len(ctx))
        try:
            out, raw = ollama_client.meta_summarize("daily", ctx)
            self._store.insert_meta_summary(
                granularity="daily",
                period_label=label,
                window_start=start,
                window_end=end,
                model=config.OLLAMA_MODEL,
                raw_response=raw,
                headline=out["headline"],
                summary=out["summary"],
                findings=out["findings"],
                confidence=out["confidence"],
                error=None,
            )
            logger.info("Meta daily: stored OK (%s)", label)
        except Exception as e:
            logger.exception("Meta daily failed")
            self._store.insert_meta_summary(
                granularity="daily",
                period_label=label,
                window_start=start,
                window_end=end,
                model=config.OLLAMA_MODEL,
                raw_response="",
                headline="Meta analysis failed",
                summary="",
                findings=[],
                confidence="low",
                error=str(e),
            )

    def _maybe_weekly(self) -> None:
        now = time.time()
        last_ok, last_any = self._store.meta_attempt_timestamps("weekly")
        if last_any is not None and (now - last_any) < float(config.META_MIN_RETRY_SEC):
            return
        if last_ok is not None and (now - last_ok) < float(config.META_WEEKLY_INTERVAL_SEC):
            return
        end = now
        start = end - float(config.META_WEEKLY_INTERVAL_SEC)
        n = self._store.count_analyses_between(start, end)
        if n < int(config.META_MIN_ANALYSES_WEEKLY):
            logger.info("Meta weekly: skip (only %s analyses in window; need ≥%s)", n, config.META_MIN_ANALYSES_WEEKLY)
            return
        label = _period_label("weekly", start, end)
        ctx = meta_context.build_weekly_meta_context(self._store, start, end)
        logger.info("Meta weekly: calling Ollama (%s analyses, %s chars context)", n, len(ctx))
        try:
            out, raw = ollama_client.meta_summarize("weekly", ctx)
            self._store.insert_meta_summary(
                granularity="weekly",
                period_label=label,
                window_start=start,
                window_end=end,
                model=config.OLLAMA_MODEL,
                raw_response=raw,
                headline=out["headline"],
                summary=out["summary"],
                findings=out["findings"],
                confidence=out["confidence"],
                error=None,
            )
            logger.info("Meta weekly: stored OK (%s)", label)
        except Exception as e:
            logger.exception("Meta weekly failed")
            self._store.insert_meta_summary(
                granularity="weekly",
                period_label=label,
                window_start=start,
                window_end=end,
                model=config.OLLAMA_MODEL,
                raw_response="",
                headline="Meta analysis failed",
                summary="",
                findings=[],
                confidence="low",
                error=str(e),
            )

    def run(self) -> None:
        logger.info(
            "Meta summary worker started (enabled=%s; weekly_meta=%s; daily %ss; weekly %ss; poll %ss)",
            config.META_SUMMARY_ENABLED,
            config.META_WEEKLY_ENABLED,
            config.META_DAILY_INTERVAL_SEC,
            config.META_WEEKLY_INTERVAL_SEC,
            config.META_WORKER_POLL_SEC,
        )
        while not self._stop.is_set():
            if config.META_SUMMARY_ENABLED:
                try:
                    self._maybe_daily()
                    time.sleep(2)
                    if config.META_WEEKLY_ENABLED:
                        self._maybe_weekly()
                except Exception:
                    logger.exception("Meta summary worker tick error")
            if self._stop.wait(timeout=float(config.META_WORKER_POLL_SEC)):
                break
