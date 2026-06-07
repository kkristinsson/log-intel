"""log-intel entry point — syslogb Flask UI + background hub syslog ingest."""

from __future__ import annotations

import logging
import os

from flask import Flask

from log_intel.adapters.loggy_reader import LoggyReader
from log_intel.adapters.netsyslog_reader import NetsyslogReader
from log_intel.alerts.engine import AlertEngine
from log_intel.analysis.scheduled_drain import ScheduledAnalysisDrain
from log_intel.analysis.worker import AnalysisWorker
from log_intel.config import get_settings
from log_intel.geo.geoip import GeoLookup
from log_intel.hub_flask import init_hub
from log_intel.hub_ingest import start_hub_ingest, stop_hub_ingest
from log_intel.ingest.mist_poller import MistPoller
from log_intel.hub_state import HubState
from log_intel.loggy_ported.meta_summary_worker import MetaSummaryWorker
from log_intel.sources_registry import load_sources
from log_intel.store import EventStore
from log_intel.syslogb.bootstrap import init_syslogb, shutdown_syslogb

log = logging.getLogger(__name__)

_hub: HubState | None = None
_geo: GeoLookup | None = None
_meta_worker: MetaSummaryWorker | None = None
_scheduled_drain: ScheduledAnalysisDrain | None = None
_mist_poller: MistPoller | None = None


def get_hub() -> HubState | None:
    return _hub


def get_mist_poller() -> MistPoller | None:
    return _mist_poller


def _init_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _align_syslogb_env(settings) -> None:
    """Use one data directory for syslogb analyses.db and hub events.sqlite."""
    data = settings.data_dir
    os.environ.setdefault("DATA_DIR", data)
    os.environ.setdefault("APP_NAME", "log-intel")
    os.environ.setdefault("BRAND_TAGLINE", "Unified log intelligence — files + network syslog")


def _start_scheduled_drain(store: EventStore) -> None:
    global _scheduled_drain
    settings = get_settings()
    if not (settings.llm_enabled and settings.analysis_auto):
        return
    _scheduled_drain = ScheduledAnalysisDrain(store)
    _scheduled_drain.start()
    log.info(
        "Hub automatic analysis drain enabled (interval=%ss)",
        settings.analysis_interval_sec,
    )


def _start_meta_worker(store: EventStore) -> None:
    global _meta_worker
    settings = get_settings()
    if not (settings.llm_enabled and settings.meta_summary_enabled):
        return
    _meta_worker = MetaSummaryWorker(store)
    _meta_worker.start()
    log.info("Meta summary worker enabled")


def _start_mist_poller(hub: HubState) -> None:
    global _mist_poller
    settings = get_settings()
    if not (settings.mist_enabled and settings.mist_api_key.strip()):
        return
    _mist_poller = MistPoller(hub)
    _mist_poller.start()
    log.info(
        "Mist cloud ingest enabled (interval=%ss, lookback=%sh)",
        settings.mist_poll_interval_sec,
        settings.mist_lookback_hours,
    )


def reconfigure_hub_llm_workers() -> None:
    """Start/stop hub background LLM workers after Settings save or reload."""
    global _scheduled_drain, _meta_worker
    if _hub is None:
        return

    settings = get_settings()
    want_drain = settings.llm_enabled and settings.analysis_auto
    if want_drain and _scheduled_drain is None:
        _start_scheduled_drain(_hub.store)
    elif not want_drain and _scheduled_drain is not None:
        _scheduled_drain.stop()
        _scheduled_drain = None
        log.info("Hub automatic analysis drain disabled")

    want_meta = settings.llm_enabled and settings.meta_summary_enabled
    if want_meta and _meta_worker is None:
        _start_meta_worker(_hub.store)
    elif not want_meta and _meta_worker is not None:
        _meta_worker.stop()
        _meta_worker = None
        log.info("Meta summary worker disabled")


def reconfigure_mist_poller() -> None:
    """Start/stop Mist cloud poller after Settings save or reload."""
    global _mist_poller
    if _hub is None:
        return

    settings = get_settings()
    want_mist = settings.mist_enabled and bool(settings.mist_api_key.strip())
    alive = _mist_poller is not None and _mist_poller.is_alive()
    if want_mist and not alive:
        _start_mist_poller(_hub)
    elif not want_mist and _mist_poller is not None:
        _mist_poller.stop()
        _mist_poller = None
        log.info("Mist cloud ingest disabled")


def init_hub_services() -> HubState:
    """Create hub store, workers, and start syslog ingest (idempotent)."""
    global _hub, _geo
    if _hub is not None:
        return _hub

    settings = get_settings()
    _align_syslogb_env(settings)

    sources = load_sources()
    store = EventStore(settings.sqlite_path, max_events=settings.max_events)
    alert_engine = AlertEngine(store)
    analysis_worker = AnalysisWorker(store)
    hub = HubState(
        store=store,
        alert_engine=alert_engine,
        analysis_worker=analysis_worker,
        loggy=LoggyReader(),
        netsyslog=NetsyslogReader(),
        sources=sources,
    )

    _start_scheduled_drain(store)
    _start_meta_worker(store)
    _start_mist_poller(hub)

    _geo = GeoLookup(settings.geoip_mmdb_path)
    init_hub(hub, _geo)
    start_hub_ingest(hub, _geo)
    _hub = hub
    log.info("Hub services ready (events DB: %s)", settings.sqlite_path)
    return hub


def create_application() -> Flask:
    """WSGI factory: syslogb core + hub network features."""
    from log_intel.settings_bridge import bootstrap_settings_store

    bootstrap_settings_store()
    _init_logging()
    init_hub_services()
    return init_syslogb()


def run() -> None:
    """Dev server (single process). Production: gunicorn log_intel.wsgi:application."""
    settings = get_settings()
    app = create_application()
    log.info(
        "log-intel on http://%s:%s (syslogb UI + hub at /hub)",
        settings.http_host,
        settings.http_port,
    )
    try:
        app.run(
            host=settings.http_host,
            port=settings.http_port,
            threaded=True,
            use_reloader=False,
        )
    finally:
        shutdown_syslogb()
        stop_hub_ingest()
        if _scheduled_drain:
            _scheduled_drain.stop()
        if _meta_worker:
            _meta_worker.stop()
        if _mist_poller:
            _mist_poller.stop()
        if _geo:
            _geo.close()
        if _hub:
            _hub.analysis_worker.stop()
            _hub.store.close()


if __name__ == "__main__":
    run()
