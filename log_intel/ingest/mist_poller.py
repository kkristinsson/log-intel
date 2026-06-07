"""Background poller for Juniper Mist cloud events."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from typing import TYPE_CHECKING, Any

from log_intel.adapters.mist_client import MistClient
from log_intel.config import get_settings
from log_intel.metrics import EVENTS_STORED, INGEST_TOTAL, PARSE_OK
from log_intel.models import LogEvent
from log_intel.store import to_stream_event

if TYPE_CHECKING:
    from log_intel.hub_state import HubState

log = logging.getLogger(__name__)


def _first_str(event: dict[str, Any], *keys: str) -> str:
    for key in keys:
        val = event.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def parse_mist_timestamp(event: dict[str, Any]) -> float | None:
    for key in ("timestamp", "created_time", "time", "ts", "last_seen", "start"):
        val = event.get(key)
        if val is None:
            continue
        try:
            ts = float(val)
            if ts > 1e12:
                ts /= 1000.0
            return ts
        except (TypeError, ValueError):
            continue
    return None


def mist_event_parser_key(event: dict[str, Any]) -> str:
    for key in ("id", "event_id", "_id", "uuid"):
        val = event.get(key)
        if val is not None and str(val).strip():
            return f"mist:{val}"
    digest = hashlib.sha256(
        json.dumps(event, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()[:32]
    return f"mist:hash:{digest}"


def mist_event_to_log(event: dict[str, Any], *, raw_truncate: int) -> LogEvent:
    title = _first_str(event, "type", "event", "name", "reason", "category", "action", "event_type")
    body = _first_str(
        event,
        "message",
        "text",
        "description",
        "detail",
        "note",
        "device_name",
        "client_mac",
        "ap",
    )
    if title and body:
        message = f"{title}: {body}"
    else:
        message = title or body or json.dumps(event, ensure_ascii=False)[:500]

    raw = json.dumps(event, ensure_ascii=False)
    if len(raw) > raw_truncate:
        raw = raw[:raw_truncate]

    event_ts = parse_mist_timestamp(event)
    return LogEvent(
        received_at=time.time(),
        source_type="mist",
        source_id="mist",
        remote_ip="mist.cloud",
        transport="mist_api",
        syslog_host=_first_str(event, "site_name", "site_id", "ap_name", "device_name"),
        raw=raw,
        message=message,
        parser=mist_event_parser_key(event),
        log_type=title or _first_str(event, "category"),
        action=_first_str(event, "action", "severity"),
        event_ts=event_ts,
    )


class MistPoller(threading.Thread):
    def __init__(self, hub: HubState) -> None:
        super().__init__(name="mist-poller", daemon=True)
        self._hub = hub
        self._stop = threading.Event()
        self._last_poll_at = 0.0
        self._last_inserted = 0
        self._last_error = ""

    def stop(self) -> None:
        self._stop.set()

    def health(self) -> dict[str, Any]:
        settings = get_settings()
        configured = bool(settings.mist_enabled and settings.mist_api_key.strip())
        return {
            "ok": configured and not self._last_error,
            "enabled": settings.mist_enabled,
            "configured": configured,
            "last_poll_at": self._last_poll_at,
            "last_inserted": self._last_inserted,
            "last_error": self._last_error,
            "org_id": settings.mist_org_id,
            "base_url": settings.mist_base_url,
        }

    def poll_once(self) -> int:
        settings = get_settings()
        if not settings.mist_enabled or not settings.mist_api_key.strip():
            return 0

        client = MistClient(settings.mist_api_key, base_url=settings.mist_base_url)
        org_id = settings.mist_org_id.strip() or client.get_org_id()
        events = client.fetch_events(
            org_id,
            lookback_hours=settings.mist_lookback_hours,
            limit=settings.mist_poll_limit,
        )

        inserted = 0
        for raw_event in events:
            ev = mist_event_to_log(raw_event, raw_truncate=settings.raw_truncate)
            if self._hub.store.has_parser(ev.parser):
                continue
            ev.id = self._hub.store.insert(ev)
            inserted += 1
            INGEST_TOTAL.labels(transport="mist_api").inc()
            PARSE_OK.labels(source_type="mist").inc()
            self._hub.broadcast_sync(to_stream_event(ev))
            self._hub.alert_engine.evaluate(ev)

        self._last_poll_at = time.time()
        self._last_inserted = inserted
        self._last_error = ""
        if inserted:
            EVENTS_STORED.set(self._hub.store.count_events())
            log.info("Mist poll ingested %s new event(s)", inserted)
        return inserted

    def run(self) -> None:
        log.info("Mist poller started")
        while not self._stop.is_set():
            settings = get_settings()
            if settings.mist_enabled and settings.mist_api_key.strip():
                try:
                    self.poll_once()
                except Exception as e:
                    self._last_error = str(e)
                    log.warning("Mist poll failed: %s", e)
            wait_sec = max(60, int(settings.mist_poll_interval_sec))
            if self._stop.wait(wait_sec):
                break
        log.info("Mist poller stopped")
