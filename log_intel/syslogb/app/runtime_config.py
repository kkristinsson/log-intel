from __future__ import annotations

import os
from pathlib import Path

from log_intel.syslogb.app import config
from log_intel.syslogb.app.settings_registry import BOOTSTRAP_ENV_KEYS, registry_by_key
from log_intel.syslogb.app.store import AppStore


def _parse_bool(raw: str) -> bool:
    return raw.lower() in ("1", "true", "yes", "on")


def _coerce(value: str, value_type: str):
    if value_type == "int":
        try:
            return int(value)
        except ValueError:
            return 0
    if value_type == "float":
        try:
            return float(value)
        except ValueError:
            return 0.0
    if value_type == "bool":
        return _parse_bool(value)
    return value


def _parse_log_dirs(raw: str, fallback: str) -> list[Path]:
    text = raw.strip() or fallback
    parts = [p.strip() for p in text.split(",") if p.strip()] if "," in text or raw.strip() else [text.strip() or fallback]
    if not parts:
        parts = [fallback]
    out: list[Path] = []
    seen: set[Path] = set()
    for part in parts:
        path = Path(part).expanduser().resolve()
        if path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def _log_dir_labels(dirs: list[Path]) -> dict[Path, str]:
    if not dirs:
        return {}
    by_name: dict[str, list[Path]] = {}
    for d in dirs:
        key = d.name or str(d)
        by_name.setdefault(key, []).append(d)
    labels: dict[Path, str] = {}
    for name, group in by_name.items():
        if len(group) == 1:
            labels[group[0].resolve()] = name
            continue
        for d in group:
            labels[d.resolve()] = str(d.resolve())
    return labels


def effective_value(key: str, store: AppStore) -> tuple[str, str]:
    """Return (value, source) where source is env|db|default.

    Saved SQLite values win for normal settings so the web UI is authoritative.
    Environment variables are used as fallback when a key is not in the DB.
    BOOTSTRAP_ENV_KEYS (e.g. DATA_DIR) still prefer env when set.
    """
    if key in BOOTSTRAP_ENV_KEYS:
        env_val = os.environ.get(key)
        if env_val is not None and env_val != "":
            return env_val, "env"
    db_val = store.get(key)
    if db_val is not None:
        return db_val, "db"
    env_val = os.environ.get(key)
    if env_val is not None and env_val != "":
        return env_val, "env"
    defs = registry_by_key()
    if key in defs:
        return defs[key].default, "default"
    return "", "default"


def refresh_config_module(store: AppStore) -> None:
    """Apply settings store + env onto app.config module attributes."""
    defs = registry_by_key()
    values: dict[str, str] = {}
    for key in defs:
        values[key], _ = effective_value(key, store)

    config.FLASK_HOST = values.get("FLASK_HOST", "0.0.0.0")
    config.FLASK_PORT = _coerce(values.get("FLASK_PORT", "9080"), "int")
    data_dir = Path(values.get("DATA_DIR", "./data")).expanduser().resolve()
    config.DATA_DIR = data_dir
    config.CHROMA_DIR = data_dir / "chroma"
    config.SQLITE_PATH = data_dir / "analyses.db"
    config.FLASK_SECRET_KEY = values.get("FLASK_SECRET_KEY", "")

    log_dirs = _parse_log_dirs(values.get("LOG_DIRS", ""), values.get("LOG_DIR", "/var/log"))
    config.LOG_DIRS = log_dirs
    config.LOG_DIR = log_dirs[0] if log_dirs else Path("/var/log").resolve()
    config.LOG_DIR_LABELS = _log_dir_labels(log_dirs)
    config.LOG_GLOB = values["LOG_GLOB"]
    config.LOG_RECURSIVE = _coerce(values["LOG_RECURSIVE"], "bool")
    config.LOG_READ_COMPRESSED = _coerce(values.get("LOG_READ_COMPRESSED", "0"), "bool")
    config.SCAN_INTERVAL_SEC = _coerce(values["SCAN_INTERVAL_SEC"], "float")
    config.TAIL_BUFFER_SIZE = _coerce(values["TAIL_BUFFER_SIZE"], "int")
    config.TAIL_DEFAULT_ORDER = values["TAIL_DEFAULT_ORDER"].lower()
    config.FILE_RECENT_BYTES = _coerce(values["FILE_RECENT_BYTES"], "int")
    config.SEARCH_MAX_RESULTS = _coerce(values["SEARCH_MAX_RESULTS"], "int")
    config.SEARCH_MAX_BYTES_PER_FILE = _coerce(values["SEARCH_MAX_BYTES_PER_FILE"], "int")
    config.SEARCH_CASE_SENSITIVE = _coerce(values["SEARCH_CASE_SENSITIVE"], "bool")
    config.EXPORT_MAX_ROWS = _coerce(values.get("EXPORT_MAX_ROWS", "10000"), "int")
    config.LLM_ENABLED = _coerce(values.get("LLM_ENABLED", "1"), "bool")
    config.OLLAMA_BASE_URL = values["OLLAMA_BASE_URL"].rstrip("/")
    config.OLLAMA_MODEL = values["OLLAMA_MODEL"]
    config.OLLAMA_EMBED_MODEL = values["OLLAMA_EMBED_MODEL"]
    config.OLLAMA_TIMEOUT_SEC = _coerce(values["OLLAMA_TIMEOUT_SEC"], "int")
    config.OLLAMA_EMBED_TIMEOUT_SEC = _coerce(values["OLLAMA_EMBED_TIMEOUT_SEC"], "int")
    config.OLLAMA_NUM_PREDICT = _coerce(values["OLLAMA_NUM_PREDICT"], "int")
    config.OLLAMA_JSON_FORMAT = _coerce(values["OLLAMA_JSON_FORMAT"], "bool")
    config.LLM_PROVIDER = values["LLM_PROVIDER"].lower()
    config.LLM_API_BASE_URL = values["LLM_API_BASE_URL"].rstrip("/")
    config.LLM_API_KEY = values.get("LLM_API_KEY", "")
    config.LLM_CHAT_MODEL = values["LLM_CHAT_MODEL"] or config.OLLAMA_MODEL
    config.LLM_EMBED_MODEL = values["LLM_EMBED_MODEL"] or config.OLLAMA_EMBED_MODEL
    config.LOG_LINE_MAX_CHARS = _coerce(values["LOG_LINE_MAX_CHARS"], "int")
    config.LLM_SKIP_LOW_LEVELS = _coerce(values["LLM_SKIP_LOW_LEVELS"], "bool")
    config.LLM_MAX_FILE_BYTES = _coerce(values["LLM_MAX_FILE_BYTES"], "int")
    config.LLM_DIRECT_MAX_BYTES = _coerce(values["LLM_DIRECT_MAX_BYTES"], "int")
    config.RAG_CHUNK_LINES = _coerce(values["RAG_CHUNK_LINES"], "int")
    config.RAG_CHUNK_OVERLAP = _coerce(values["RAG_CHUNK_OVERLAP"], "int")
    config.RAG_TOP_K = _coerce(values["RAG_TOP_K"], "int")
    config.RAG_MAX_LINES = _coerce(values["RAG_MAX_LINES"], "int")
    config.RAG_MAX_CHUNKS = _coerce(values["RAG_MAX_CHUNKS"], "int")
    config.EMBED_BATCH_SIZE = _coerce(values["EMBED_BATCH_SIZE"], "int")
    config.EMBED_MAX_CHARS = _coerce(values["EMBED_MAX_CHARS"], "int")
    config.EMBED_LINE_MAX_CHARS = _coerce(values["EMBED_LINE_MAX_CHARS"], "int")
    config.EMBED_MAX_TOKENS_PER_INPUT = _coerce(values["EMBED_MAX_TOKENS_PER_INPUT"], "int")
    config.EMBED_MAX_TOKENS_PER_REQUEST = _coerce(
        values["EMBED_MAX_TOKENS_PER_REQUEST"], "int"
    )
    config.EMBED_MAX_RETRIES = _coerce(values["EMBED_MAX_RETRIES"], "int")
    config.RAG_QUERY = values["RAG_QUERY"]
    config.LLM_AUDIT_ENABLED = _coerce(values.get("LLM_AUDIT_ENABLED", "1"), "bool")
    config.LLM_AUDIT_LOG = values.get("LLM_AUDIT_LOG", "")
    config.LLM_AUDIT_MAX_CHARS = _coerce(values.get("LLM_AUDIT_MAX_CHARS", "8000"), "int")
    config.ANALYSIS_HISTORY_KEEP = _coerce(values.get("ANALYSIS_HISTORY_KEEP", "5"), "int")
    config.APP_PUBLIC_URL = (values.get("APP_PUBLIC_URL") or "").rstrip("/")
    config.LOG_SKIP_NAMES = values["LOG_SKIP_NAMES"]
    config.APP_NAME = values["APP_NAME"]
    from log_intel.syslogb.app.version import __version__ as _default_ver
    config.APP_VERSION = values["APP_VERSION"] or _default_ver
    config.BRAND_LOGO = values["BRAND_LOGO"]
    config.BRAND_LOGO_LINK = values["BRAND_LOGO_LINK"]
    config.BRAND_TAGLINE = values["BRAND_TAGLINE"]
    config.COPYRIGHT_TEXT = values["COPYRIGHT_TEXT"]
    config.AUTH_ENABLED = _coerce(values["AUTH_ENABLED"], "bool")
    config.LOCAL_AUTH_USERNAME = values["LOCAL_AUTH_USERNAME"]
    config.LOCAL_AUTH_PASSWORD = values.get("LOCAL_AUTH_PASSWORD", "")
    config.LDAP_URI = values["LDAP_URI"].strip()
    config.LDAP_USE_SSL = _coerce(values["LDAP_USE_SSL"], "bool")
    config.LDAP_TIMEOUT_SEC = _coerce(values["LDAP_TIMEOUT_SEC"], "int")
    config.LDAP_BIND_DN = values["LDAP_BIND_DN"]
    config.LDAP_BIND_PASSWORD = values.get("LDAP_BIND_PASSWORD", "")
    config.LDAP_USER_DN_TEMPLATE = values["LDAP_USER_DN_TEMPLATE"]
    config.LDAP_USER_SEARCH_BASE = values["LDAP_USER_SEARCH_BASE"]
    config.LDAP_USER_SEARCH_FILTER = values["LDAP_USER_SEARCH_FILTER"]
    config.LDAP_GROUP_SEARCH_BASE = values["LDAP_GROUP_SEARCH_BASE"]
    config.LDAP_REQUIRED_GROUP = values["LDAP_REQUIRED_GROUP"]
    config.LDAP_REQUIRED_GROUP_CN = values["LDAP_REQUIRED_GROUP_CN"]
    config.LDAP_MEMBER_OF_ATTR = values["LDAP_MEMBER_OF_ATTR"]
    config.SMTP_HOST = values.get("SMTP_HOST", "")
    config.SMTP_PORT = _coerce(values.get("SMTP_PORT", "587"), "int")
    config.SMTP_USER = values.get("SMTP_USER", "")
    config.SMTP_FROM = values.get("SMTP_FROM", "")
    config.SMTP_TLS = _coerce(values.get("SMTP_TLS", "1"), "bool")
    config.SMTP_PASSWORD = values.get("SMTP_PASSWORD", "")
    config.ALERT_MAX_PER_MINUTE = _coerce(values.get("ALERT_MAX_PER_MINUTE", "30"), "int")
