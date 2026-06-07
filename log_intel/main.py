"""log-intel entry point — syslogb Flask UI + background hub syslog ingest."""

from __future__ import annotations

import logging
import os

from flask import Flask

from log_intel.adapters.loggy_reader import LoggyReader
from log_intel.adapters.netsyslog_reader import NetsyslogReader
from log_intel.alerts.engine import AlertEngine
from log_intel.analysis.worker import AnalysisWorker
from log_intel.config import get_settings
from log_intel.geo.geoip import GeoLookup
from log_intel.hub_flask import init_hub
from log_intel.hub_ingest import start_hub_ingest, stop_hub_ingest
from log_intel.hub_state import HubState
from log_intel.store import EventStore
from log_intel.syslogb.bootstrap import init_syslogb, shutdown_syslogb

log = logging.getLogger(__name__)

_hub: HubState | None = None
_geo: GeoLookup | None = None


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


def init_hub_services() -> HubState:
    """Create hub store, workers, and start syslog ingest (idempotent)."""
    global _hub, _geo
    if _hub is not None:
        return _hub

    settings = get_settings()
    _align_syslogb_env(settings)

    store = EventStore(settings.sqlite_path, max_events=settings.max_events)
    alert_engine = AlertEngine(store)
    analysis_worker = AnalysisWorker(store)
    hub = HubState(
        store=store,
        alert_engine=alert_engine,
        analysis_worker=analysis_worker,
        loggy=LoggyReader(),
        netsyslog=NetsyslogReader(),
    )
    if settings.llm_enabled:
        analysis_worker.start()

    _geo = GeoLookup(settings.geoip_mmdb_path)
    init_hub(hub, _geo)
    start_hub_ingest(hub, _geo)
    _hub = hub
    log.info("Hub services ready (events DB: %s)", settings.sqlite_path)
    return hub


def create_application() -> Flask:
    """WSGI factory: syslogb core + hub network features."""
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
        if _geo:
            _geo.close()
        if _hub:
            _hub.analysis_worker.stop()
            _hub.store.close()


if __name__ == "__main__":
    run()
