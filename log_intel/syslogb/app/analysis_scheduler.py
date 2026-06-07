"""Run scheduled LLM log analyses and alert when findings exceed thresholds."""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from log_intel.syslogb.app import config
from log_intel.syslogb.app.analyze_worker import AnalyzeWorker
from log_intel.syslogb.app.llm_client import llm_enabled
from log_intel.syslogb.app.notify import send_email, send_webhook
from log_intel.syslogb.app.scanner import is_readable_file
from log_intel.syslogb.app.severity import IMPORTANCE_MIN_CHOICES, importance_min_rank, importance_rank
from log_intel.syslogb.app.store import AppStore

logger = logging.getLogger(__name__)

def compute_next_run(interval_days: int, run_at_hour: int, *, after: float | None = None) -> float:
    """Next run time (unix) at local run_at_hour, at least interval_days after `after`."""
    interval_days = max(1, int(interval_days))
    run_at_hour = max(0, min(23, int(run_at_hour)))
    after_ts = after or time.time()
    base = datetime.fromtimestamp(after_ts) + timedelta(days=interval_days)
    candidate = base.replace(hour=run_at_hour, minute=0, second=0, microsecond=0)
    if candidate.timestamp() <= after_ts:
        candidate += timedelta(days=1)
    return candidate.timestamp()


def public_app_url() -> str:
    if config.APP_PUBLIC_URL:
        return config.APP_PUBLIC_URL.rstrip("/")
    return f"http://127.0.0.1:{config.FLASK_PORT}"


def analysis_should_alert(result: dict[str, Any], schedule: dict[str, Any]) -> bool:
    if not result:
        return False
    anomalies = result.get("anomalies") or []
    if schedule.get("alert_on_anomalies") and anomalies:
        return True
    min_level = (schedule.get("min_severity") or "warning").lower()
    if min_level in ("medium", "low"):
        min_level = "warning"
    if min_level not in IMPORTANCE_MIN_CHOICES:
        min_level = "warning"
    sev = str(result.get("severity", "info")).lower()
    line = f"severity-{sev} event"
    return importance_rank(line) >= importance_min_rank(min_level)


def format_analysis_alert_body(
    schedule: dict[str, Any],
    job: dict[str, Any],
    *,
    analysis_url: str,
) -> str:
    result = job.get("result") or {}
    lines = [
        f"Scheduled analysis: {schedule.get('file_path')}",
        f"Severity: {result.get('severity', 'unknown')}",
        f"Summary: {result.get('summary', '')}",
        f"Anomalies: {len(result.get('anomalies') or [])}",
        f"View full report: {analysis_url}",
    ]
    for item in (result.get("anomalies") or [])[:5]:
        if isinstance(item, dict):
            lines.append(f"  - {item.get('title', '')}: {item.get('detail', '')}")
    return "\n".join(lines)


class AnalysisScheduler:
    def __init__(self, store: AppStore, worker: AnalyzeWorker) -> None:
        self._store = store
        self._worker = worker
        self._stop = threading.Event()
        self._pending: dict[str, str] = {}  # job_id -> schedule_id
        self._lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._run, name="analysis-scheduler", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=8)

    def reload(self) -> None:
        """No-op hook after schedule CRUD (schedules read from DB each tick)."""
        return

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                logger.exception("Analysis scheduler tick failed")
            self._stop.wait(45)

    def _tick(self) -> None:
        if not llm_enabled():
            return
        self._poll_pending_jobs()
        if self._pending:
            return
        now = time.time()
        for sched in self._store.list_due_analysis_schedules(now):
            if self._stop.is_set():
                break
            self._start_schedule(sched, now)

    def _start_schedule(self, sched: dict[str, Any], now: float) -> None:
        path = Path(sched["file_path"])
        if not path.is_file() or not is_readable_file(path):
            logger.warning("Scheduled analysis skipped, file missing: %s", path)
            nxt = compute_next_run(
                sched["interval_days"], sched["run_at_hour"], after=now
            )
            self._store.update_analysis_schedule_run(
                sched["id"],
                last_run_at=now,
                last_status="skipped",
                last_error="file not found or not readable",
                next_run_at=nxt,
            )
            return
        scope = sched.get("scope") or "full"
        window = sched.get("window") or ""
        job_mode = f"window:{window}" if scope == "window" else "full"
        job_id = self._store.create_job(str(path.resolve()), mode=f"schedule:{job_mode}")
        nxt = compute_next_run(sched["interval_days"], sched["run_at_hour"], after=now)
        self._store.update_analysis_schedule_run(
            sched["id"],
            last_run_at=now,
            last_job_id=job_id,
            last_status="running",
            last_error="",
            next_run_at=nxt,
        )
        with self._lock:
            self._pending[job_id] = sched["id"]
        win = window if scope == "window" else None
        self._worker.enqueue(job_id, path.resolve(), window=win)
        logger.info(
            "Scheduled analysis started: %s job=%s next=%s",
            path.name,
            job_id,
            datetime.fromtimestamp(nxt).isoformat(),
        )

    def _poll_pending_jobs(self) -> None:
        with self._lock:
            pending = dict(self._pending)
        for job_id, schedule_id in list(pending.items()):
            job = self._store.get_job(job_id)
            if not job:
                with self._lock:
                    self._pending.pop(job_id, None)
                continue
            status = job.get("status")
            if status in ("pending", "running"):
                continue
            with self._lock:
                self._pending.pop(job_id, None)
            sched = self._store.get_analysis_schedule(schedule_id)
            if not sched:
                continue
            self._finish_schedule(sched, job)

    def _finish_schedule(self, sched: dict[str, Any], job: dict[str, Any]) -> None:
        status = job.get("status")
        now = time.time()
        if status == "done":
            self._store.update_analysis_schedule_run(
                sched["id"], last_status="done", last_error=""
            )
            result = job.get("result")
            if result and analysis_should_alert(result, sched):
                self._send_alerts(sched, job)
            return
        if status == "error":
            err = job.get("error") or "analysis failed"
            self._store.update_analysis_schedule_run(
                sched["id"], last_status="error", last_error=err
            )
            if sched.get("webhook_url") or sched.get("email_to"):
                self._send_failure_alerts(sched, job, err)
            return
        if status == "cancelled":
            self._store.update_analysis_schedule_run(
                sched["id"], last_status="cancelled", last_error="cancelled"
            )

    def _send_alerts(self, sched: dict[str, Any], job: dict[str, Any]) -> None:
        result = job.get("result") or {}
        url = f"{public_app_url()}/analysis/{job['id']}"
        payload = {
            "app": config.APP_NAME,
            "type": "scheduled_analysis",
            "schedule_id": sched["id"],
            "file": sched["file_path"],
            "severity": result.get("severity"),
            "summary": result.get("summary"),
            "anomaly_count": len(result.get("anomalies") or []),
            "analysis_url": url,
            "job_id": job["id"],
        }
        subject = (
            f"[{config.APP_NAME}] Log analysis alert: "
            f"{Path(sched['file_path']).name} ({result.get('severity', '?')})"
        )
        body = format_analysis_alert_body(sched, job, analysis_url=url)
        if sched.get("webhook_url"):
            ok, msg = send_webhook(sched["webhook_url"], payload)
            logger.info("Schedule webhook %s: %s", sched["file_path"], msg if ok else msg)
        if sched.get("email_to"):
            ok, msg = send_email(sched["email_to"], subject, body)
            logger.info("Schedule email %s: %s", sched["file_path"], msg if ok else msg)

    def _send_failure_alerts(
        self, sched: dict[str, Any], job: dict[str, Any], err: str
    ) -> None:
        payload = {
            "app": config.APP_NAME,
            "type": "scheduled_analysis_failed",
            "file": sched["file_path"],
            "error": err,
            "job_id": job.get("id"),
        }
        subject = f"[{config.APP_NAME}] Scheduled analysis failed: {Path(sched['file_path']).name}"
        body = f"Scheduled LLM analysis failed for {sched['file_path']}.\n\n{err}\n"
        if sched.get("webhook_url"):
            send_webhook(sched["webhook_url"], payload)
        if sched.get("email_to"):
            send_email(sched["email_to"], subject, body)
