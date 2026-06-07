"""Background asyncio syslog ingest (runs in a daemon thread)."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import TYPE_CHECKING

from log_intel.config import get_settings
from log_intel.geo.geoip import GeoLookup, enrich_event
from log_intel.ingest.classifier import classify_and_parse
from log_intel.ingest.syslog_server import QueueItem, serve_tcp, serve_udp
from log_intel.metrics import (
    EVENTS_STORED,
    INGEST_TOTAL,
    PARSE_DROP,
    PARSE_OK,
    QUEUE_DEPTH,
)
from log_intel.store import importance_for_event, to_stream_event

if TYPE_CHECKING:
    from log_intel.hub_state import HubState

log = logging.getLogger(__name__)

_thread: threading.Thread | None = None
_loop: asyncio.AbstractEventLoop | None = None


def _record_queue_drop(hub: HubState, host: str, transport: str, queue: asyncio.Queue[QueueItem]) -> None:
    PARSE_DROP.labels(reason="queue_full").inc()
    hub.ingest_stats["queue_drops"] = hub.ingest_stats.get("queue_drops", 0) + 1
    QUEUE_DEPTH.set(queue.qsize())
    log.debug("queue drop from %s (%s)", host, transport)


async def _process_queue(
    queue: asyncio.Queue[QueueItem],
    hub: HubState,
    geo: GeoLookup,
) -> None:
    settings = get_settings()
    loop = asyncio.get_running_loop()
    while True:
        data, host, transport = await queue.get()
        QUEUE_DEPTH.set(queue.qsize())
        INGEST_TOTAL.labels(transport=transport).inc()
        try:
            text = data.decode("utf-8", errors="replace")
            ev = classify_and_parse(text, host, transport, settings.raw_truncate)
            if ev is None:
                PARSE_DROP.labels(reason="unparseable").inc()
                hub.ingest_stats["parse_drops"] = hub.ingest_stats.get("parse_drops", 0) + 1
                continue
            enrich_event(ev, geo)
            eid = await loop.run_in_executor(None, hub.store.insert, ev)
            ev.id = eid
            PARSE_OK.labels(source_type=ev.source_type).inc()
            EVENTS_STORED.set(hub.store.count_events())
            hub.broadcast_sync(to_stream_event(ev))
            await loop.run_in_executor(None, hub.alert_engine.evaluate, ev)
        except Exception:
            log.exception("failed to process syslog from %s", host)
            PARSE_DROP.labels(reason="exception").inc()


async def _retention_loop(hub: HubState) -> None:
    while True:
        await asyncio.sleep(3600)
        settings = get_settings()
        if settings.retention_hours and settings.retention_hours > 0:
            n = hub.store.delete_older_than(time.time() - settings.retention_hours * 3600)
            if n:
                log.info("retention removed %s events", n)
            EVENTS_STORED.set(hub.store.count_events())


async def _ingest_main(hub: HubState, geo: GeoLookup) -> None:
    settings = get_settings()
    queue: asyncio.Queue[QueueItem] = asyncio.Queue(maxsize=settings.queue_maxsize)
    on_drop = lambda host, transport: _record_queue_drop(hub, host, transport, queue)
    worker = asyncio.create_task(_process_queue(queue, hub, geo))
    ret = (
        asyncio.create_task(_retention_loop(hub))
        if settings.retention_hours > 0
        else None
    )
    try:
        udp = await serve_udp(queue, settings, on_drop)
        tcp_srv = await serve_tcp(queue, settings, on_drop)
    except OSError as e:
        worker.cancel()
        if ret:
            ret.cancel()
        log.warning(
            "Hub syslog bind failed on port %s (%s) — HTTP/syslogb still available",
            settings.syslog_udp_port,
            e,
        )
        return
    log.info(
        "Hub syslog ingest UDP/TCP on %s:%s",
        settings.syslog_udp_host,
        settings.syslog_udp_port,
    )
    try:
        await asyncio.Event().wait()
    finally:
        worker.cancel()
        try:
            await worker
        except asyncio.CancelledError:
            pass
        if ret:
            ret.cancel()
            try:
                await ret
            except asyncio.CancelledError:
                pass
        udp.close()
        tcp_srv.close()
        await tcp_srv.wait_closed()


def _thread_target(hub: HubState, geo: GeoLookup) -> None:
    global _loop
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    try:
        _loop.run_until_complete(_ingest_main(hub, geo))
    except Exception:
        log.exception("hub ingest thread failed")


def start_hub_ingest(hub: HubState, geo: GeoLookup) -> None:
    global _thread
    if _thread and _thread.is_alive():
        return
    _thread = threading.Thread(
        target=_thread_target,
        name="hub-ingest",
        args=(hub, geo),
        daemon=True,
    )
    _thread.start()
    log.info("Hub ingest thread started")


def stop_hub_ingest() -> None:
    global _loop, _thread
    if _loop and _loop.is_running():
        _loop.call_soon_threadsafe(_loop.stop)
    _thread = None
    _loop = None
