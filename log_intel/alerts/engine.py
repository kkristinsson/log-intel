"""Live alert rule matching engine."""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from typing import TYPE_CHECKING

from log_intel.alerts.notify import build_alert_payload, deliver_webhook
from log_intel.config import get_settings
from log_intel.models import LogEvent

if TYPE_CHECKING:
    from log_intel.store import EventStore

log = logging.getLogger(__name__)


class AlertEngine:
    def __init__(self, store: EventStore) -> None:
        self._store = store
        self._lock = threading.Lock()
        self._cooldowns: dict[tuple[str, str], float] = {}
        self._recent: deque[float] = deque()

    def reload_rules(self) -> list[dict]:
        return self._store.list_alert_rules()

    def evaluate(self, ev: LogEvent) -> None:
        settings = get_settings()
        rules = self._store.list_alert_rules()
        line = ev.message or ev.raw or ""
        source = f"{ev.source_type}:{ev.remote_ip}"

        for rule in rules:
            if not rule.get("enabled"):
                continue
            if rule.get("source_type") and rule["source_type"] != ev.source_type:
                continue
            if not self._matches(rule, line):
                continue
            key = (rule["id"], source)
            now = time.time()
            with self._lock:
                if now - self._cooldowns.get(key, 0) < rule.get("cooldown_sec", settings.alert_cooldown_sec):
                    continue
                if not self._rate_ok(now, settings.alert_max_per_minute):
                    continue
                self._cooldowns[key] = now
                self._recent.append(now)

            payload = build_alert_payload(
                rule_name=rule["name"],
                rule_id=rule["id"],
                source=source,
                line=line,
                ts=ev.received_at,
            )
            delivered = False
            webhook = rule.get("webhook_url")
            if webhook:
                delivered = deliver_webhook(webhook, payload)
            self._store.insert_alert_event(
                rule_id=rule["id"],
                source=source,
                line=line[:2000],
                ts=now,
                delivered=delivered,
                payload=payload,
                origin="hub",
            )
            log.info("Alert fired rule=%s source=%s", rule["name"], source)

    def _matches(self, rule: dict, line: str) -> bool:
        query = rule.get("query") or ""
        mode = rule.get("mode", "text")
        if mode == "regex":
            try:
                return bool(re.search(query, line, re.IGNORECASE))
            except re.error:
                return False
        q = query.lower()
        if not q:
            return False
        ll = line.lower()
        return all(term in ll for term in q.split())

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
        )
