"""Environment configuration for log-intel."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env_int(key: str, default: int) -> int:
    v = os.environ.get(key)
    if v is None or v.strip() == "":
        return default
    return int(v)


def _env_float(key: str, default: float) -> float:
    v = os.environ.get(key)
    if v is None or v.strip() == "":
        return default
    return float(v)


@dataclass(frozen=True)
class PaloIndices:
    type_col: int = 3
    subtype: int = 4
    src: int = 8
    dst: int = 9
    action: int = 13
    proto: int = 28
    sport: int = 29
    dport: int = 30
    bytes_col: int | None = None


@dataclass
class Settings:
    http_host: str = "0.0.0.0"
    http_port: int = 9088
    syslog_udp_host: str = "0.0.0.0"
    syslog_udp_port: int = 514
    syslog_tcp_host: str = "0.0.0.0"
    syslog_tcp_port: int = 514
    tcp_framing: str = "line"
    queue_maxsize: int = 50000
    raw_truncate: int = 2048
    data_dir: str = "./data"
    sqlite_path: str = "./data/events.sqlite"
    max_events: int = 500000
    retention_hours: float = 0.0
    geoip_mmdb_path: str = "./geoip/dbip-city-lite.mmdb"
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3.6:27b-q8_0"
    ollama_timeout_sec: int = 1200
    ollama_num_predict: int = 768
    ollama_json_format: bool = True
    llm_enabled: bool = False
    analysis_batch_size: int = 3
    analysis_interval_sec: int = 3600
    log_line_max_chars: int = 1200
    syslogb_base_url: str = "http://127.0.0.1:9080"
    loggy_db_path: str = ""
    netsyslog_db_path: str = ""
    netsyslog_api_url: str = "http://127.0.0.1:8000"
    alert_max_per_minute: int = 30
    alert_cooldown_sec: int = 300
    log_level: str = "INFO"
    palo_indices: PaloIndices = field(default_factory=PaloIndices)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    data_dir = os.environ.get("LOG_INTEL_DATA_DIR", "./data")
    sqlite = os.environ.get("LOG_INTEL_SQLITE_PATH", f"{data_dir}/events.sqlite")
    palo = PaloIndices()
    raw_palo = os.environ.get("LOG_INTEL_PALO_INDICES", "")
    if raw_palo.strip():
        try:
            d = json.loads(raw_palo)
            palo = PaloIndices(
                type_col=int(d.get("type_col", palo.type_col)),
                subtype=int(d.get("subtype", palo.subtype)),
                src=int(d.get("src", palo.src)),
                dst=int(d.get("dst", palo.dst)),
                action=int(d.get("action", palo.action)),
                proto=int(d.get("proto", palo.proto)),
                sport=int(d.get("sport", palo.sport)),
                dport=int(d.get("dport", palo.dport)),
                bytes_col=d.get("bytes"),
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    for attr, env_key in (
        ("type_col", "PALO_TYPE_COL"),
        ("src", "PALO_SRC"),
        ("dst", "PALO_DST"),
        ("action", "PALO_ACTION"),
        ("proto", "PALO_PROTO"),
        ("sport", "PALO_SPORT"),
        ("dport", "PALO_DPORT"),
    ):
        v = os.environ.get(env_key)
        if v is not None and v.strip():
            object.__setattr__(palo, attr, int(v))

    return Settings(
        http_host=os.environ.get("LOG_INTEL_HTTP_HOST", "0.0.0.0"),
        http_port=_env_int("LOG_INTEL_HTTP_PORT", 9088),
        syslog_udp_host=os.environ.get("LOG_INTEL_SYSLOG_UDP_HOST", "0.0.0.0"),
        syslog_udp_port=_env_int("LOG_INTEL_SYSLOG_UDP_PORT", 514),
        syslog_tcp_host=os.environ.get("LOG_INTEL_SYSLOG_TCP_HOST", "0.0.0.0"),
        syslog_tcp_port=_env_int("LOG_INTEL_SYSLOG_TCP_PORT", 514),
        tcp_framing=os.environ.get("LOG_INTEL_TCP_FRAMING", "line"),
        queue_maxsize=_env_int("LOG_INTEL_QUEUE_MAXSIZE", 50000),
        raw_truncate=_env_int("LOG_INTEL_RAW_TRUNCATE", 2048),
        data_dir=data_dir,
        sqlite_path=sqlite,
        max_events=_env_int("LOG_INTEL_MAX_EVENTS", 500000),
        retention_hours=_env_float("LOG_INTEL_RETENTION_HOURS", 0.0),
        geoip_mmdb_path=os.environ.get(
            "LOG_INTEL_GEOIP_MMDB_PATH", "./geoip/dbip-city-lite.mmdb"
        ),
        ollama_base_url=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/"),
        ollama_model=os.environ.get("OLLAMA_MODEL", "qwen3.6:27b-q8_0"),
        ollama_timeout_sec=_env_int("OLLAMA_TIMEOUT_SEC", 1200),
        ollama_num_predict=_env_int("OLLAMA_NUM_PREDICT", 768),
        ollama_json_format=_env_bool("OLLAMA_JSON_FORMAT", True),
        llm_enabled=_env_bool("LOG_INTEL_LLM_ENABLED", False),
        analysis_batch_size=_env_int("LOG_INTEL_ANALYSIS_BATCH_SIZE", 3),
        analysis_interval_sec=_env_int("LOG_INTEL_ANALYSIS_INTERVAL_SEC", 3600),
        log_line_max_chars=_env_int("LOG_LINE_MAX_CHARS", 1200),
        syslogb_base_url=os.environ.get("SYSLOGB_BASE_URL", "http://127.0.0.1:9080").rstrip("/"),
        loggy_db_path=os.environ.get("LOGGY_DB_PATH", ""),
        netsyslog_db_path=os.environ.get("NETSYSLOG_DB_PATH", ""),
        netsyslog_api_url=os.environ.get("NETSYSLOG_API_URL", "http://127.0.0.1:8000").rstrip("/"),
        alert_max_per_minute=_env_int("LOG_INTEL_ALERT_MAX_PER_MINUTE", 30),
        alert_cooldown_sec=_env_int("LOG_INTEL_ALERT_COOLDOWN_SEC", 300),
        log_level=os.environ.get("LOG_INTEL_LOG_LEVEL", "INFO"),
        palo_indices=palo,
    )


def get_palo_indices() -> PaloIndices:
    return get_settings().palo_indices
