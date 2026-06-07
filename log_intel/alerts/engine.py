"""Live alert rule matching engine (hub syslog + file/journal tail)."""

from __future__ import annotations

import logging
import re
import smtplib
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING, Any

from log_intel.alerts.notify import build_alert_payload, deliver_webhook
from log_intel.config import get_settings
from log_intel.metrics import ALERTS_FIRED
from log_intel.models import LogEvent
from log_intel.syslogb.app.fail_filter import is_failure_line
from log_intel.syslogb.app.search import _compile_pattern, _line_matches

if TYPE_CHECKING:
    from log_intel.store import EventStore

log = logging.getLogger(__name__)


class AlertEngine:
    def __init__(self, store: EventStore) -> None:
        self._store = store
        self._lock = threading.Lock()
        self._cooldowns: dict[tuple[str, str], float] = {}
        self._recent: deque[float] = deque()
        self._rules: list[dict[str, Any]] = []
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="hub-alert")
        self.reload_rules()

    def reload_rules(self) -> list[dict]:
        self._rules = [r for r in self._store.list_alert_rules() if r.get("enabled")]
        return self._rules

    def evaluate(self, ev: LogEvent) -> None:
        settings = get_settings()
        line = ev.message or ev.raw or ""
        source = f"{ev.source_type}:{ev.remote_ip}"
        for rule in self._rules:
            if rule.get("source_type") and rule["source_type"] != ev.source_type:
                continue
            if rule.get("log_dir") or rule.get("file_glob"):
                continue
            if not self._matches(rule, line):
                continue
            self._fire(rule, source, line, ev.received_at, origin="hub", settings=settings)

    def on_line(
        self,
        source: str,
        line: str,
        ts: float | None,
        received_at: float,
    ) -> None:
        settings = get_settings()
        path = Path(source)
        for rule in self._rules:
            if not self._rule_matches_path(rule, path):
                continue
            scope = rule.get("scope", "all")
            if scope == "failures_only" and not is_failure_line(line):
                continue
            if not self._matches(rule, line):
                continue
            self._fire(rule, source, line, float(ts or received_at), origin="syslogb", settings=settings)

    def _fire(
        self,
        rule: dict[str, Any],
        source: str,
        line: str,
        ts: float,
        *,
        origin: str,
        settings,
    ) -> None:
        key = (rule["id"], source)
        now = time.time()
        with self._lock:
            if now - self._cooldowns.get(key, 0) < rule.get("cooldown_sec", settings.alert_cooldown_sec):
                self._store.insert_alert_event(
                    rule_id=rule["id"],
                    source=source,
                    line=line[:2000],
                    ts=now,
                    delivered=False,
                    payload={"reason": "cooldown"},
                    origin=origin,
                    channel="suppressed",
                    status="suppressed",
                    error="cooldown",
                )
                return
            if not self._rate_ok(now, settings.alert_max_per_minute):
                self._store.insert_alert_event(
                    rule_id=rule["id"],
                    source=source,
                    line=line[:2000],
                    ts=now,
                    delivered=False,
                    payload={"reason": "rate_limit"},
                    origin=origin,
                    channel="suppressed",
                    status="suppressed",
                    error="rate_limit",
                )
                return
            self._cooldowns[key] = now
            self._recent.append(now)
        self._pool.submit(self._deliver, rule, source, line, ts, origin)

    def _deliver(
        self,
        rule: dict[str, Any],
        source: str,
        line: str,
        ts: float,
        origin: str,
    ) -> None:
        payload = build_alert_payload(
            rule_name=rule["name"],
            rule_id=rule["id"],
            source=source,
            line=line,
            ts=ts,
            origin=origin,
        )
        if rule.get("webhook_url"):
            ok = deliver_webhook(rule["webhook_url"], payload)
            self._store.insert_alert_event(
                rule_id=rule["id"],
                source=source,
                line=line[:2000],
                ts=time.time(),
                delivered=ok,
                payload=payload,
                origin=origin,
                channel="webhook",
                status="sent" if ok else "failed",
                error="" if ok else "webhook delivery failed",
            )
            if ok:
                ALERTS_FIRED.labels(origin=origin).inc()
        if rule.get("email_to"):
            self._send_email(rule, source, line, ts, origin, payload)

    def _send_email(
        self,
        rule: dict[str, Any],
        source: str,
        line: str,
        ts: float,
        origin: str,
        payload: dict[str, Any],
    ) -> None:
        from log_intel.syslogb.app import config as sb_config

        host = sb_config.SMTP_HOST
        if not host:
            self._store.insert_alert_event(
                rule_id=rule["id"],
                source=source,
                line=line[:2000],
                ts=time.time(),
                delivered=False,
                payload=payload,
                origin=origin,
                channel="email",
                status="failed",
                error="SMTP_HOST not configured",
            )
            return
        recipients = [x.strip() for x in (rule.get("email_to") or "").split(",") if x.strip()]
        if not recipients:
            return
        msg = EmailMessage()
        msg["Subject"] = f"[log-intel] Alert: {rule['name']}"
        msg["From"] = sb_config.SMTP_FROM or sb_config.SMTP_USER or "log-intel@localhost"
        msg["To"] = ", ".join(recipients)
        msg.set_content(f"Rule: {rule['name']}\nSource: {source}\nTime: {ts}\n\n{line}\n")
        try:
            with smtplib.SMTP(host, sb_config.SMTP_PORT, timeout=20) as smtp:
                if sb_config.SMTP_TLS:
                    smtp.starttls()
                if sb_config.SMTP_USER and sb_config.SMTP_PASSWORD:
                    smtp.login(sb_config.SMTP_USER, sb_config.SMTP_PASSWORD)
                smtp.send_message(msg)
            self._store.insert_alert_event(
                rule_id=rule["id"],
                source=source,
                line=line[:2000],
                ts=time.time(),
                delivered=True,
                payload=payload,
                origin=origin,
                channel="email",
                status="sent",
            )
            ALERTS_FIRED.labels(origin=origin).inc()
        except Exception as e:
            log.warning("Email alert failed: %s", e)
            self._store.insert_alert_event(
                rule_id=rule["id"],
                source=source,
                line=line[:2000],
                ts=time.time(),
                delivered=False,
                payload=payload,
                origin=origin,
                channel="email",
                status="failed",
                error=str(e),
            )

    def _matches(self, rule: dict, line: str) -> bool:
        query = rule.get("query") or ""
        mode = rule.get("mode", "text")
        if mode == "regex":
            try:
                return bool(re.search(query, line, re.IGNORECASE))
            except re.error:
                return False
        try:
            pattern = _compile_pattern(query, mode)
            return _line_matches(line, pattern, mode)
        except ValueError:
            q = query.lower()
            if not q:
                return False
            ll = line.lower()
            return all(term in ll for term in q.split())

    def _rule_matches_path(self, rule: dict[str, Any], path: Path) -> bool:
        path_str = str(path)
        log_dir = rule.get("log_dir")
        if log_dir:
            try:
                base = str(Path(log_dir).resolve())
                if not path_str.startswith(base) and not path_str.startswith(log_dir):
                    return False
            except OSError:
                return False
        fglob = rule.get("file_glob")
        if fglob and not fnmatch(path.name, fglob):
            return False
        return True

    def _rate_ok(self, now: float, max_per_minute: int) -> bool:
        if max_per_minute <= 0:
            return True
        cutoff = now - 60
        while self._recent and self._recent[0] < cutoff:
            self._recent.popleft()
        return len(self._recent) < max_per_minute

    def ingest_syslogb_webhook(self, body: dict) -> None:
        self._store.insert_alert_event(
            rule_id=body.get("rule_id"),
            source=str(body.get("source", "syslogb")),
            line=str(body.get("line", ""))[:2000],
            ts=float(body.get("ts") or time.time()),
            delivered=True,
            payload=body,
            origin="syslogb",
            channel="webhook",
            status="sent",
        )
        ALERTS_FIRED.labels(origin="syslogb").inc()

    def send_test(self, rule_id: str) -> dict[str, str]:
        rules = {r["id"]: r for r in self._store.list_alert_rules()}
        rule = rules.get(rule_id)
        if not rule:
            raise ValueError("rule not found")
        self._deliver(rule, "/test/source", "log-intel test alert line", time.time(), "hub")
        return {"status": "ok"}

    def shutdown(self) -> None:
        self._pool.shutdown(wait=True)
