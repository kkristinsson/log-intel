"""Bootstrap syslogb services inside log-intel (adapted from syslogb/run.py)."""

from __future__ import annotations

import atexit
import logging
import sys
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv
from flask import Flask

load_dotenv()

from log_intel.syslogb.app import config
from log_intel.syslogb.app.analysis_scheduler import AnalysisScheduler
from log_intel.syslogb.app.analyze_worker import AnalyzeWorker
from log_intel.syslogb.app.alert_engine import AlertEngine
from log_intel.syslogb.app.runtime_config import refresh_config_module
from log_intel.syslogb.app.store import AppStore
from log_intel.syslogb.app.tail_service import TailService
from log_intel.syslogb.web.routes import create_app

log = logging.getLogger("log_intel.syslogb")


@dataclass
class SyslogbRuntime:
    app: Flask
    store: AppStore
    tail_service: TailService
    worker: AnalyzeWorker
    alert_engine: AlertEngine
    analysis_scheduler: AnalysisScheduler


_runtime: Optional[SyslogbRuntime] = None
_shutdown_done = False


def shutdown_syslogb(*_args: object) -> None:
    global _shutdown_done, _runtime
    if _shutdown_done or _runtime is None:
        return
    _shutdown_done = True
    log.info("Shutting down syslogb core…")
    _runtime.analysis_scheduler.stop()
    _runtime.worker.stop()
    _runtime.tail_service.stop()
    _runtime.alert_engine.shutdown()
    _runtime = None


def init_syslogb() -> Flask:
    """Start file-tail + LLM + alerts and return the Flask app (idempotent)."""
    global _runtime
    if _runtime is not None:
        return _runtime.app

    config.DATA_DIR.mkdir(parents=True, exist_ok=True)

    store = AppStore()
    store.seed_settings_if_empty()
    store.ensure_legacy_setup_complete()
    store.seed_settings_values_from_env_if_empty()
    refresh_config_module(store)

    from log_intel.syslogb.app.timestamp_parsers import refresh_parsers_cache

    refresh_parsers_cache(store.list_timestamp_parsers())

    alert_engine = AlertEngine(store)
    tail_service = TailService(alert_engine=alert_engine)
    worker = AnalyzeWorker(store)
    worker.start()
    analysis_scheduler = AnalysisScheduler(store, worker)
    analysis_scheduler.start()

    ok, msg = tail_service.start()
    if ok:
        log.info(msg)
    else:
        log.warning(msg)

    app = create_app(tail_service, store, worker, alert_engine, analysis_scheduler)

    from log_intel.hub_flask import register_hub_routes

    register_hub_routes(app)

    _runtime = SyslogbRuntime(
        app=app,
        store=store,
        tail_service=tail_service,
        worker=worker,
        alert_engine=alert_engine,
        analysis_scheduler=analysis_scheduler,
    )
    atexit.register(shutdown_syslogb)

    from log_intel.syslogb.app.llm_client import chat_model_name, embed_model_name

    log.info(
        "log-intel syslogb core v%s ready: provider=%s LOG_DIRS=%s chat=%s embed=%s",
        config.APP_VERSION,
        config.LLM_PROVIDER,
        config.LOG_DIRS,
        chat_model_name(),
        embed_model_name(),
    )
    return app


def get_runtime() -> Optional[SyslogbRuntime]:
    return _runtime
