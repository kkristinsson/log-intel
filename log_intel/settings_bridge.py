"""Load unified log-intel settings from SQLite (authoritative) with .env bootstrap fallback."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from log_intel.config import PaloIndices, Settings, _coerce_from_registry, _env_bool, _env_float, _env_int

if TYPE_CHECKING:
    from log_intel.syslogb.app.store import AppStore

_store: AppStore | None = None


def _bootstrap_data_dir() -> Path:
    raw = os.environ.get("DATA_DIR") or os.environ.get("LOG_INTEL_DATA_DIR") or "./data"
    return Path(raw).expanduser().resolve()


def get_app_store() -> AppStore | None:
    return _store


def bootstrap_settings_store() -> AppStore:
    """Open analyses.db, seed from .env on first run, sync registry keys."""
    global _store
    if _store is not None:
        return _store

    from log_intel.syslogb.app.store import AppStore

    data_dir = _bootstrap_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("DATA_DIR", str(data_dir))
    _store = AppStore(db_path=data_dir / "analyses.db")
    _store.seed_settings_if_empty()
    _store.seed_settings_values_from_env_if_empty()
    _store.sync_registry_settings()
    _store.ensure_legacy_setup_complete()
    refresh_all_settings(_store)
    return _store


def _effective(store: AppStore, key: str) -> str:
    from log_intel.syslogb.app.runtime_config import effective_value

    val, _ = effective_value(key, store)
    return val


def build_settings(store: AppStore | None = None) -> Settings:
    """Build hub+shared Settings from DB when store exists, else from env defaults."""
    if store is None:
        store = _store

    if store is not None:
        data_dir = Path(_effective(store, "DATA_DIR")).expanduser().resolve()
        events_sqlite = data_dir / "events.sqlite"
        palo = PaloIndices()
        return Settings(
            http_host=_effective(store, "FLASK_HOST"),
            http_port=_coerce_from_registry(store, "FLASK_PORT", "int", 9088),
            syslog_udp_host=os.environ.get("LOG_INTEL_SYSLOG_UDP_HOST", "0.0.0.0"),
            syslog_udp_port=_env_int("LOG_INTEL_SYSLOG_UDP_PORT", 514),
            syslog_tcp_host=os.environ.get("LOG_INTEL_SYSLOG_TCP_HOST", "0.0.0.0"),
            syslog_tcp_port=_env_int("LOG_INTEL_SYSLOG_TCP_PORT", 514),
            tcp_framing=os.environ.get("LOG_INTEL_TCP_FRAMING", "line"),
            queue_maxsize=_coerce_from_registry(store, "LOG_INTEL_QUEUE_MAXSIZE", "int", 50000),
            raw_truncate=_coerce_from_registry(store, "LOG_INTEL_RAW_TRUNCATE", "int", 2048),
            data_dir=str(data_dir),
            sqlite_path=str(events_sqlite),
            max_events=_coerce_from_registry(store, "LOG_INTEL_MAX_EVENTS", "int", 500_000),
            retention_hours=_coerce_from_registry(store, "LOG_INTEL_RETENTION_HOURS", "float", 0.0),
            geoip_mmdb_path=_effective(store, "LOG_INTEL_GEOIP_MMDB_PATH"),
            ollama_base_url=_effective(store, "OLLAMA_BASE_URL").rstrip("/"),
            ollama_model=_effective(store, "OLLAMA_MODEL"),
            ollama_timeout_sec=_coerce_from_registry(store, "OLLAMA_TIMEOUT_SEC", "int", 1200),
            ollama_num_predict=_coerce_from_registry(store, "OLLAMA_NUM_PREDICT", "int", 768),
            ollama_json_format=_coerce_from_registry(store, "OLLAMA_JSON_FORMAT", "bool", True),
            llm_enabled=_coerce_from_registry(store, "LOG_INTEL_LLM_ENABLED", "bool", False),
            analysis_auto=_coerce_from_registry(store, "LOG_INTEL_ANALYSIS_AUTO", "bool", False),
            analysis_batch_size=_coerce_from_registry(store, "LOG_INTEL_ANALYSIS_BATCH_SIZE", "int", 3),
            analysis_interval_sec=_coerce_from_registry(
                store, "LOG_INTEL_ANALYSIS_INTERVAL_SEC", "int", 3600
            ),
            log_line_max_chars=_coerce_from_registry(store, "LOG_LINE_MAX_CHARS", "int", 1200),
            syslogb_base_url=os.environ.get("SYSLOGB_BASE_URL", "http://127.0.0.1:9080").rstrip("/"),
            loggy_db_path=_effective(store, "LOGGY_DB_PATH"),
            netsyslog_db_path=_effective(store, "NETSYSLOG_DB_PATH"),
            netsyslog_api_url=os.environ.get("NETSYSLOG_API_URL", "http://127.0.0.1:8000").rstrip("/"),
            alert_max_per_minute=_coerce_from_registry(store, "ALERT_MAX_PER_MINUTE", "int", 30),
            alert_cooldown_sec=_coerce_from_registry(store, "ALERT_COOLDOWN_SEC", "int", 300),
            log_level=_effective(store, "LOG_INTEL_LOG_LEVEL"),
            palo_indices=palo,
            meta_summary_enabled=_coerce_from_registry(store, "META_SUMMARY_ENABLED", "bool", False),
            meta_weekly_enabled=_coerce_from_registry(store, "META_WEEKLY_ENABLED", "bool", False),
            meta_daily_interval_sec=_coerce_from_registry(store, "META_DAILY_INTERVAL_SEC", "int", 86400),
            meta_weekly_interval_sec=_coerce_from_registry(
                store, "META_WEEKLY_INTERVAL_SEC", "int", 604800
            ),
            meta_worker_poll_sec=_coerce_from_registry(store, "META_WORKER_POLL_SEC", "int", 1800),
            meta_min_retry_sec=_coerce_from_registry(store, "META_MIN_RETRY_SEC", "int", 3600),
            meta_context_max_analyses=_coerce_from_registry(
                store, "META_CONTEXT_MAX_ANALYSES", "int", 80
            ),
            meta_min_analyses_daily=_coerce_from_registry(store, "META_MIN_ANALYSES_DAILY", "int", 2),
            meta_min_analyses_weekly=_coerce_from_registry(
                store, "META_MIN_ANALYSES_WEEKLY", "int", 4
            ),
            meta_ollama_timeout_sec=_coerce_from_registry(
                store, "META_OLLAMA_TIMEOUT_SEC", "int", 1800
            ),
            meta_num_predict=_coerce_from_registry(store, "META_NUM_PREDICT", "int", 2048),
            max_meta_summaries=_coerce_from_registry(store, "MAX_META_SUMMARIES", "int", 2000),
            max_analyses=_coerce_from_registry(store, "MAX_ANALYSES", "int", 5000),
            analysis_skip_blocked_traffic=_coerce_from_registry(
                store, "ANALYSIS_SKIP_BLOCKED_TRAFFIC", "bool", True
            ),
            analysis_inter_batch_sleep_sec=_coerce_from_registry(
                store, "ANALYSIS_INTER_BATCH_SLEEP_SEC", "float", 2.0
            ),
            on_demand_max_batches=_coerce_from_registry(store, "ON_DEMAND_MAX_BATCHES", "int", 0),
            on_demand_max_wall_sec=_coerce_from_registry(store, "ON_DEMAND_MAX_WALL_SEC", "int", 0),
            ollama_think=_effective(store, "OLLAMA_THINK"),
            ollama_think_min_num_predict=_coerce_from_registry(
                store, "OLLAMA_THINK_MIN_NUM_PREDICT", "int", 4096
            ),
            mist_enabled=_coerce_from_registry(store, "MIST_ENABLED", "bool", False),
            mist_api_key=_effective(store, "MIST_API_KEY"),
            mist_base_url=_effective(store, "MIST_BASE_URL").rstrip("/") or "https://api.eu.mist.com/api/v1",
            mist_org_id=_effective(store, "MIST_ORG_ID"),
            mist_poll_interval_sec=_coerce_from_registry(store, "MIST_POLL_INTERVAL_SEC", "int", 300),
            mist_poll_limit=_coerce_from_registry(store, "MIST_POLL_LIMIT", "int", 100),
            mist_lookback_hours=_coerce_from_registry(store, "MIST_LOOKBACK_HOURS", "float", 24.0),
            reserve_events_mist=_coerce_from_registry(store, "LOG_INTEL_RESERVE_EVENTS_MIST", "int", 1000),
            reserve_events_palo=_coerce_from_registry(store, "LOG_INTEL_RESERVE_EVENTS_PALO", "int", 0),
        )

    from log_intel.config import _settings_from_env

    return _settings_from_env()


def refresh_all_settings(store: AppStore) -> None:
    """Apply DB settings to syslogb config module, hub config, and cached Settings."""
    from log_intel.syslogb.app.runtime_config import refresh_config_module

    refresh_config_module(store)
    from log_intel.config import invalidate_settings_cache

    invalidate_settings_cache()
    from log_intel import hub_config

    hub_config.refresh_from_settings(build_settings(store))
