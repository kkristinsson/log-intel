from __future__ import annotations

import logging
import re
import smtplib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Optional

from log_intel.syslogb.app import config
from log_intel.syslogb.app.fail_filter import is_failure_line
from log_intel.syslogb.app.notify import send_webhook
from log_intel.syslogb.app.search import _compile_pattern, _line_matches
from log_intel.syslogb.app.store import AppStore

logger = logging.getLogger(__name__)


class AlertEngine:
    def __init__(self, store: AppStore) -> None:
        self._store = store
        self._lock = threading.Lock()
        self._rules: list[dict[str, Any]] = []
        self._last_fired: dict[tuple[str, str], float] = {}
        self._minute_window: list[float] = []
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="alert")
        self.reload_rules()

    def reload_rules(self) -> None:
        with self._lock:
            self._rules = [r for r in self._store.list_alert_rules() if r.get("enabled")]

    def on_line(
        self,
        source: str,
        line: str,
        ts: Optional[float],
        received_at: float,
    ) -> None:
        rules = self._rules
        if not rules:
            return
        path = Path(source)
        for rule in rules:
            if not self._rule_matches_path(rule, path):
                continue
            scope = rule.get("scope", "all")
            if scope == "failures_only" and not is_failure_line(line):
                continue
            try:
                pattern = _compile_pattern(rule["query"], rule.get("mode", "text"))
            except ValueError:
                continue
            if not _line_matches(line, pattern, rule.get("mode", "text")):
                continue
            key = (rule["id"], source)
            now = time.time()
            with self._lock:
                last = self._last_fired.get(key, 0)
                if now - last < rule.get("cooldown_sec", 300):
                    self._store.record_alert_event(
                        rule["id"], source, line, ts, "suppressed", "suppressed", "cooldown"
                    )
                    continue
                if not self._under_global_cap(now):
                    self._store.record_alert_event(
                        rule["id"], source, line, ts, "suppressed", "suppressed", "rate_limit"
                    )
                    continue
                self._last_fired[key] = now
            self._pool.submit(self._deliver, rule, source, line, ts)

    def _under_global_cap(self, now: float) -> bool:
        self._minute_window = [t for t in self._minute_window if now - t < 60]
        cap = config.ALERT_MAX_PER_MINUTE
        if len(self._minute_window) >= cap:
            return False
        self._minute_window.append(now)
        return True

    def _rule_matches_path(self, rule: dict[str, Any], path: Path) -> bool:
        log_dir = rule.get("log_dir")
        if log_dir:
            try:
                base = Path(log_dir).resolve()
                if not str(path.resolve()).startswith(str(base)):
                    return False
            except OSError:
                return False
        fglob = rule.get("file_glob")
        if fglob and not fnmatch(path.name, fglob):
            return False
        return True

    def _deliver(
        self,
        rule: dict[str, Any],
        source: str,
        line: str,
        ts: Optional[float],
    ) -> None:
        payload = {
            "app": config.APP_NAME,
            "rule": rule["name"],
            "rule_id": rule["id"],
            "source": source,
            "line": line,
            "ts": ts,
        }
        if rule.get("webhook_url"):
            self._send_webhook(rule, payload, source, line, ts)
        if rule.get("email_to"):
            self._send_email(rule, source, line, ts)

    def _send_webhook(
        self,
        rule: dict[str, Any],
        payload: dict[str, Any],
        source: str,
        line: str,
        ts: Optional[float],
    ) -> None:
        url = rule.get("webhook_url", "")
        ok, msg = send_webhook(url, payload)
        if ok:
            self._store.record_alert_event(rule["id"], source, line, ts, "webhook", "sent")
            try:
                from log_intel.metrics import ALERTS_FIRED
                ALERTS_FIRED.labels(origin="files").inc()
            except ImportError:
                pass
        else:
            logger.warning("Webhook alert failed: %s", msg)
            self._store.record_alert_event(
                rule["id"], source, line, ts, "webhook", "failed", msg
            )

    def _send_email(
        self,
        rule: dict[str, Any],
        source: str,
        line: str,
        ts: Optional[float],
    ) -> None:
        host = config.SMTP_HOST
        if not host:
            self._store.record_alert_event(
                rule["id"], source, line, ts, "email", "failed", "SMTP_HOST not configured"
            )
            return
        recipients = [x.strip() for x in (rule.get("email_to") or "").split(",") if x.strip()]
        if not recipients:
            return
        msg = EmailMessage()
        msg["Subject"] = f"[{config.APP_NAME}] Alert: {rule['name']}"
        msg["From"] = config.SMTP_FROM or config.SMTP_USER or "log-intel@localhost"
        msg["To"] = ", ".join(recipients)
        body = f"Rule: {rule['name']}\nSource: {source}\nTime: {ts}\n\n{line}\n"
        msg.set_content(body)
        try:
            with smtplib.SMTP(host, config.SMTP_PORT, timeout=20) as smtp:
                if config.SMTP_TLS:
                    smtp.starttls()
                if config.SMTP_USER and config.SMTP_PASSWORD:
                    smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
                smtp.send_message(msg)
            self._store.record_alert_event(rule["id"], source, line, ts, "email", "sent")
            try:
                from log_intel.metrics import ALERTS_FIRED
                ALERTS_FIRED.labels(origin="files").inc()
            except ImportError:
                pass
        except Exception as e:
            logger.warning("Email alert failed: %s", e)
            self._store.record_alert_event(
                rule["id"], source, line, ts, "email", "failed", str(e)
            )

    def send_test(self, rule_id: str) -> dict[str, str]:
        rules = {r["id"]: r for r in self._store.list_alert_rules()}
        rule = rules.get(rule_id)
        if not rule:
            raise ValueError("rule not found")
        self._deliver(rule, "/test/syslog", "log-intel test alert line", time.time())
        return {"status": "ok"}

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False)
