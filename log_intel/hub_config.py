"""Loggy-compatible config surface for ported modules (reads log-intel settings)."""

from __future__ import annotations

from log_intel.config import Settings

# Module-level names for loggy_ported imports — updated via refresh_from_settings().
DATA_DIR = "./data"
SQLITE_PATH = "./data/events.sqlite"
GEOIP_DB_PATH = "./geoip/dbip-city-lite.mmdb"
OLLAMA_BASE_URL = "http://127.0.0.1:11434"
OLLAMA_MODEL = "qwen3.6:27b-q8_0"
OLLAMA_TIMEOUT_SEC = 1200
OLLAMA_NUM_PREDICT = 768
OLLAMA_JSON_FORMAT = True
LOG_LINE_MAX_CHARS = 1200
ANALYSIS_BATCH_SIZE = 3
ANALYSIS_INTERVAL_SEC = 3600
LLM_ENABLED = False
ANALYSIS_AUTO = False
MAX_EVENTS = 500_000
META_SUMMARY_ENABLED = False
META_DAILY_INTERVAL_SEC = 86400
META_WEEKLY_INTERVAL_SEC = 604800
META_WEEKLY_ENABLED = False
META_WORKER_POLL_SEC = 1800
META_MIN_RETRY_SEC = 3600
META_CONTEXT_MAX_ANALYSES = 80
META_MIN_ANALYSES_DAILY = 2
META_MIN_ANALYSES_WEEKLY = 4
META_OLLAMA_TIMEOUT_SEC = 1800
META_NUM_PREDICT = 2048
MAX_META_SUMMARIES = 2000
MAX_ANALYSES = 5000
ANALYSIS_SKIP_BLOCKED_TRAFFIC = True
ANALYSIS_INTER_BATCH_SLEEP_SEC = 2.0
ON_DEMAND_MAX_BATCHES = 0
ON_DEMAND_MAX_WALL_SEC = 0
OLLAMA_THINK = "medium"
OLLAMA_THINK_MIN_NUM_PREDICT = 4096


def refresh_from_settings(settings: Settings) -> None:
    global DATA_DIR, SQLITE_PATH, GEOIP_DB_PATH, OLLAMA_BASE_URL, OLLAMA_MODEL
    global OLLAMA_TIMEOUT_SEC, OLLAMA_NUM_PREDICT, OLLAMA_JSON_FORMAT, LOG_LINE_MAX_CHARS
    global ANALYSIS_BATCH_SIZE, ANALYSIS_INTERVAL_SEC, LLM_ENABLED, ANALYSIS_AUTO, MAX_EVENTS
    global META_SUMMARY_ENABLED, META_DAILY_INTERVAL_SEC, META_WEEKLY_INTERVAL_SEC
    global META_WEEKLY_ENABLED, META_WORKER_POLL_SEC, META_MIN_RETRY_SEC
    global META_CONTEXT_MAX_ANALYSES, META_MIN_ANALYSES_DAILY, META_MIN_ANALYSES_WEEKLY
    global META_OLLAMA_TIMEOUT_SEC, META_NUM_PREDICT, MAX_META_SUMMARIES, MAX_ANALYSES
    global ANALYSIS_SKIP_BLOCKED_TRAFFIC, ANALYSIS_INTER_BATCH_SLEEP_SEC
    global ON_DEMAND_MAX_BATCHES, ON_DEMAND_MAX_WALL_SEC, OLLAMA_THINK, OLLAMA_THINK_MIN_NUM_PREDICT

    DATA_DIR = settings.data_dir
    SQLITE_PATH = settings.sqlite_path
    GEOIP_DB_PATH = settings.geoip_mmdb_path
    OLLAMA_BASE_URL = settings.ollama_base_url
    OLLAMA_MODEL = settings.ollama_model
    OLLAMA_TIMEOUT_SEC = settings.ollama_timeout_sec
    OLLAMA_NUM_PREDICT = settings.ollama_num_predict
    OLLAMA_JSON_FORMAT = settings.ollama_json_format
    LOG_LINE_MAX_CHARS = settings.log_line_max_chars
    ANALYSIS_BATCH_SIZE = settings.analysis_batch_size
    ANALYSIS_INTERVAL_SEC = settings.analysis_interval_sec
    LLM_ENABLED = settings.llm_enabled
    ANALYSIS_AUTO = settings.analysis_auto
    MAX_EVENTS = settings.max_events
    META_SUMMARY_ENABLED = settings.meta_summary_enabled
    META_DAILY_INTERVAL_SEC = settings.meta_daily_interval_sec
    META_WEEKLY_INTERVAL_SEC = settings.meta_weekly_interval_sec
    META_WEEKLY_ENABLED = settings.meta_weekly_enabled
    META_WORKER_POLL_SEC = settings.meta_worker_poll_sec
    META_MIN_RETRY_SEC = settings.meta_min_retry_sec
    META_CONTEXT_MAX_ANALYSES = settings.meta_context_max_analyses
    META_MIN_ANALYSES_DAILY = settings.meta_min_analyses_daily
    META_MIN_ANALYSES_WEEKLY = settings.meta_min_analyses_weekly
    META_OLLAMA_TIMEOUT_SEC = settings.meta_ollama_timeout_sec
    META_NUM_PREDICT = settings.meta_num_predict
    MAX_META_SUMMARIES = settings.max_meta_summaries
    MAX_ANALYSES = settings.max_analyses
    ANALYSIS_SKIP_BLOCKED_TRAFFIC = settings.analysis_skip_blocked_traffic
    ANALYSIS_INTER_BATCH_SLEEP_SEC = settings.analysis_inter_batch_sleep_sec
    ON_DEMAND_MAX_BATCHES = settings.on_demand_max_batches
    ON_DEMAND_MAX_WALL_SEC = settings.on_demand_max_wall_sec
    OLLAMA_THINK = settings.ollama_think
    OLLAMA_THINK_MIN_NUM_PREDICT = settings.ollama_think_min_num_predict
