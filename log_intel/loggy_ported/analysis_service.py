"""Shared syslog→Ollama batch draining; on-demand runs use a time window."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Literal

from log_intel import hub_config as config
from log_intel.analysis import ollama_client
from log_intel.loggy_ported.pan_log import AUTO_SKIP_MODEL, is_already_blocked

if TYPE_CHECKING:
    from log_intel.store import LogStore

logger = logging.getLogger(__name__)

BatchOutcome = Literal["ok", "fail", "skipped_only", "empty"]


@dataclass
class DrainResult:
    batches_ok: int = 0
    batches_fail: int = 0
    batches_done: int = 0
    auto_skipped: int = 0
    logs_processed: int = 0
    stopped_reason: str = ""


@dataclass
class OnDemandStatus:
    state: Literal["idle", "running", "done", "error", "cancelled"] = "idle"
    message: str = ""
    since_ts: float | None = None
    until_ts: float | None = None
    pending_total: int = 0
    logs_processed: int = 0
    batches_total: int = 0
    batches_done: int = 0
    batches_ok: int = 0
    batches_fail: int = 0
    auto_skipped: int = 0
    thinking_enabled: bool = True
    started_at: float | None = None
    finished_at: float | None = None


_status = OnDemandStatus()
_status_lock = threading.Lock()
_run_thread: threading.Thread | None = None
_cancel_event = threading.Event()


def _progress_pct(logs_processed: int, pending_total: int) -> int:
    if pending_total <= 0:
        return 0
    return min(100, int(100 * logs_processed / pending_total))


def reset_terminal_status() -> None:
    """Clear finished run banner so a fresh page load is not stuck showing it."""
    with _status_lock:
        if _status.state in ("done", "error", "cancelled"):
            _status.state = "idle"
            _status.message = ""


def get_on_demand_status() -> dict:
    with _status_lock:
        s = _status
        return {
            "state": s.state,
            "message": s.message,
            "since_ts": s.since_ts,
            "until_ts": s.until_ts,
            "pending_total": s.pending_total,
            "logs_processed": s.logs_processed,
            "batches_total": s.batches_total,
            "batches_done": s.batches_done,
            "progress_pct": _progress_pct(s.logs_processed, s.pending_total),
            "batches_ok": s.batches_ok,
            "batches_fail": s.batches_fail,
            "auto_skipped": s.auto_skipped,
            "thinking_enabled": s.thinking_enabled,
            "started_at": s.started_at,
            "finished_at": s.finished_at,
        }


def _set_status(**kwargs: object) -> None:
    with _status_lock:
        for k, v in kwargs.items():
            setattr(_status, k, v)


def process_one_batch(
    store: LogStore, batch: list, *, think: bool | str | None = None
) -> BatchOutcome:
    """Run Ollama (or auto-skip) on one batch of RawLogRow objects."""
    if config.ANALYSIS_SKIP_BLOCKED_TRAFFIC:
        skipped = [r for r in batch if is_already_blocked(r.message)]
        actionable = [r for r in batch if not is_already_blocked(r.message)]
    else:
        skipped = []
        actionable = batch

    if skipped:
        n = len(skipped)
        summary = (
            f"Auto-skipped {n} blocked/denied log"
            if n == 1
            else f"Auto-skipped {n} blocked/denied logs"
        )
        store.insert_analysis(
            log_ids=[r.id for r in skipped],
            model=AUTO_SKIP_MODEL,
            raw_response="",
            severity="info",
            summary=summary,
            anomalies=[],
            error=None,
        )

    if not actionable:
        return "skipped_only" if skipped else "empty"

    ids = [r.id for r in actionable]
    lines = [r.message for r in actionable]
    try:
        parsed, raw = ollama_client.analyze_batch(lines, think=think)
        store.insert_analysis(
            log_ids=ids,
            model=config.OLLAMA_MODEL,
            raw_response=raw,
            severity=parsed["severity"],
            summary=parsed["summary"],
            anomalies=parsed["anomalies"],
            error=None,
        )
        return "ok"
    except Exception as e:
        logger.exception("Ollama analysis failed")
        store.insert_analysis(
            log_ids=ids,
            model=config.OLLAMA_MODEL,
            raw_response="",
            severity="low",
            summary="",
            anomalies=[],
            error=str(e),
        )
        return "fail"


def drain_unanalyzed(
    store: LogStore,
    *,
    since_ts: float | None = None,
    until_ts: float | None = None,
    max_batches: int = 0,
    max_wall_sec: float = 0,
    inter_batch_sleep: float = 0,
    stop_event: threading.Event | None = None,
    think: bool | str | None = None,
    on_batch_done: Callable[[DrainResult, int], None] | None = None,
) -> DrainResult:
    """Drain pending logs in batches. No time filter when since_ts is None."""
    result = DrainResult()
    cap = max_batches if max_batches > 0 else 0
    max_wall = float(max_wall_sec) if max_wall_sec > 0 else 0.0
    wake_t0 = time.time()
    batches_started = 0

    while True:
        if stop_event is not None and stop_event.is_set():
            result.stopped_reason = "stopped"
            break
        if max_wall > 0 and (time.time() - wake_t0) >= max_wall:
            result.stopped_reason = "wall_limit"
            break
        if cap > 0 and batches_started >= cap:
            result.stopped_reason = "batch_cap"
            break

        if since_ts is not None:
            batch = store.fetch_unanalyzed_in_range(
                since_ts, until_ts, config.ANALYSIS_BATCH_SIZE
            )
        else:
            batch = store.fetch_unanalyzed_batch(config.ANALYSIS_BATCH_SIZE)

        if not batch:
            result.stopped_reason = "empty"
            break

        batches_started += 1
        outcome = process_one_batch(store, batch, think=think)
        result.logs_processed += len(batch)
        result.batches_done += 1
        if on_batch_done is not None:
            on_batch_done(result, len(batch))

        if outcome == "ok":
            result.batches_ok += 1
            gap = float(inter_batch_sleep)
            if gap > 0:
                if stop_event is not None and stop_event.wait(timeout=gap):
                    result.stopped_reason = "stopped"
                    break
                elif stop_event is None:
                    time.sleep(gap)
        elif outcome == "fail":
            result.batches_fail += 1
            result.stopped_reason = "ollama_error"
            break
        elif outcome == "skipped_only":
            result.auto_skipped += len(batch)

    return result


def _on_batch_progress(result: DrainResult, _batch_len: int) -> None:
    with _status_lock:
        pending = _status.pending_total
        batches_total = _status.batches_total
    _set_status(
        logs_processed=result.logs_processed,
        batches_done=result.batches_done,
        batches_ok=result.batches_ok,
        batches_fail=result.batches_fail,
        auto_skipped=result.auto_skipped,
        message=(
            f"Processed {result.logs_processed} of {pending} log(s) "
            f"· batch {result.batches_done} of {batches_total}…"
        ),
    )


def _on_demand_thread(
    store: LogStore, since_ts: float, until_ts: float, think: bool | str | None
) -> None:
    try:
        pending = store.count_unanalyzed_in_range(since_ts, until_ts)
        if pending == 0:
            _set_status(
                state="done",
                message="No unanalyzed logs in the selected window.",
                pending_total=0,
                finished_at=time.time(),
            )
            return

        batch_size = max(1, config.ANALYSIS_BATCH_SIZE)
        batches_total = (pending + batch_size - 1) // batch_size
        mode = "with thinking" if think is not False else "without thinking"
        _set_status(
            pending_total=pending,
            logs_processed=0,
            batches_total=batches_total,
            batches_done=0,
            message=f"Analyzing {pending} log(s) in ~{batches_total} batch(es) ({mode})…",
        )
        result = drain_unanalyzed(
            store,
            since_ts=since_ts,
            until_ts=until_ts,
            max_batches=config.ON_DEMAND_MAX_BATCHES,
            max_wall_sec=config.ON_DEMAND_MAX_WALL_SEC,
            inter_batch_sleep=config.ANALYSIS_INTER_BATCH_SLEEP_SEC,
            stop_event=_cancel_event,
            think=think,
            on_batch_done=_on_batch_progress,
        )
        msg_parts = [
            f"{result.batches_ok} batch(es) OK",
        ]
        if result.batches_fail:
            msg_parts.append(f"{result.batches_fail} failed")
        if result.auto_skipped:
            msg_parts.append(f"{result.auto_skipped} log(s) auto-skipped")
        if result.stopped_reason == "stopped":
            msg_parts.append("stopped — run again to continue")
            final_state: Literal["done", "error", "cancelled"] = "cancelled"
        elif result.stopped_reason == "batch_cap":
            msg_parts.append("stopped at batch cap — run again for remainder")
            final_state = "done" if not result.batches_fail else "error"
        elif result.stopped_reason == "wall_limit":
            msg_parts.append("stopped at time limit — run again for remainder")
            final_state = "done" if not result.batches_fail else "error"
        else:
            final_state = "error" if result.batches_fail else "done"

        _set_status(
            state=final_state,
            message="; ".join(msg_parts),
            logs_processed=result.logs_processed,
            batches_done=result.batches_done,
            batches_ok=result.batches_ok,
            batches_fail=result.batches_fail,
            auto_skipped=result.auto_skipped,
            finished_at=time.time(),
        )
    except Exception as e:
        logger.exception("On-demand analysis failed")
        _set_status(state="error", message=str(e), finished_at=time.time())


def start_on_demand_analysis(
    store: LogStore,
    since_ts: float,
    until_ts: float | None = None,
    *,
    thinking_enabled: bool = True,
) -> tuple[bool, str]:
    """Start background analysis for logs in [since_ts, until_ts]. until_ts defaults to now."""
    global _run_thread
    end = until_ts if until_ts is not None else time.time()
    if end < since_ts:
        return False, "Invalid time range."

    think = config.OLLAMA_THINK if thinking_enabled else False
    _cancel_event.clear()

    with _status_lock:
        if _status.state == "running":
            return False, "Analysis already running."
        _status.state = "running"
        _status.message = "Starting…"
        _status.since_ts = since_ts
        _status.until_ts = end
        _status.pending_total = 0
        _status.logs_processed = 0
        _status.batches_total = 0
        _status.batches_done = 0
        _status.batches_ok = 0
        _status.batches_fail = 0
        _status.auto_skipped = 0
        _status.thinking_enabled = thinking_enabled
        _status.started_at = time.time()
        _status.finished_at = None

    t = threading.Thread(
        target=_on_demand_thread,
        args=(store, since_ts, end, think),
        name="on-demand-analysis",
        daemon=True,
    )
    _run_thread = t
    t.start()
    return True, "Analysis started."


def cancel_on_demand_analysis() -> tuple[bool, str]:
    """Request stop after the current batch finishes."""
    with _status_lock:
        if _status.state != "running":
            return False, "No analysis is running."
    _cancel_event.set()
    _set_status(message="Stop requested — finishing current batch…")
    return True, "Stop requested."
