"""Loggy-compatible config surface for ported modules (reads log-intel settings)."""

from __future__ import annotations

import os

from log_intel.config import get_settings

_s = get_settings()

DATA_DIR = _s.data_dir
SQLITE_PATH = _s.sqlite_path
GEOIP_DB_PATH = _s.geoip_mmdb_path
OLLAMA_BASE_URL = _s.ollama_base_url
OLLAMA_MODEL = _s.ollama_model
OLLAMA_TIMEOUT_SEC = _s.ollama_timeout_sec
OLLAMA_NUM_PREDICT = _s.ollama_num_predict
OLLAMA_JSON_FORMAT = _s.ollama_json_format
LOG_LINE_MAX_CHARS = _s.log_line_max_chars
ANALYSIS_BATCH_SIZE = _s.analysis_batch_size
ANALYSIS_INTERVAL_SEC = _s.analysis_interval_sec
LLM_ENABLED = _s.llm_enabled
MAX_EVENTS = _s.max_events


def _env_int(key: str, default: int) -> int:
    v = os.environ.get(key)
    if v is None or v.strip() == "":
        return default
    return int(v)


def _env_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


META_SUMMARY_ENABLED = _env_bool("META_SUMMARY_ENABLED", False)
META_DAILY_INTERVAL_SEC = _env_int("META_DAILY_INTERVAL_SEC", 86400)
META_WEEKLY_INTERVAL_SEC = _env_int("META_WEEKLY_INTERVAL_SEC", 604800)
META_WEEKLY_ENABLED = _env_bool("META_WEEKLY_ENABLED", False)
META_WORKER_POLL_SEC = _env_int("META_WORKER_POLL_SEC", 1800)
META_MIN_RETRY_SEC = _env_int("META_MIN_RETRY_SEC", 3600)
META_CONTEXT_MAX_ANALYSES = _env_int("META_CONTEXT_MAX_ANALYSES", 80)
META_MIN_ANALYSES_DAILY = _env_int("META_MIN_ANALYSES_DAILY", 2)
META_MIN_ANALYSES_WEEKLY = _env_int("META_MIN_ANALYSES_WEEKLY", 4)
META_OLLAMA_TIMEOUT_SEC = _env_int("META_OLLAMA_TIMEOUT_SEC", 1800)
META_NUM_PREDICT = _env_int("META_NUM_PREDICT", 2048)
MAX_META_SUMMARIES = _env_int("MAX_META_SUMMARIES", 2000)
