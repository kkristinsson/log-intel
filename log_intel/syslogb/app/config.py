import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _env(name: str, default: str) -> str:
    v = os.environ.get(name)
    return v if v is not None and v != "" else default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def _parse_log_dirs() -> list[Path]:
    raw = _env("LOG_DIRS", "").strip()
    if raw:
        parts = [p.strip() for p in raw.split(",") if p.strip()]
    else:
        parts = [_env("LOG_DIR", "/var/log")]
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


LOG_DIRS = _parse_log_dirs()
LOG_DIR = LOG_DIRS[0] if LOG_DIRS else Path("/var/log").resolve()
LOG_DIR_LABELS = _log_dir_labels(LOG_DIRS)
LOG_GLOB = _env("LOG_GLOB", "*")
LOG_RECURSIVE = _env("LOG_RECURSIVE", "0").lower() in ("1", "true", "yes", "on")

# systemd journal (journalctl) — any systemd-based distro
JOURNAL_ENABLED = _env("JOURNAL_ENABLED", "1").lower() in ("1", "true", "yes", "on")
JOURNAL_DIRECTORY = _env("JOURNAL_DIRECTORY", "")
JOURNAL_BOOT_ONLY = _env("JOURNAL_BOOT_ONLY", "0").lower() in ("1", "true", "yes", "on")
JOURNAL_MERGE_SYSTEM = _env("JOURNAL_MERGE_SYSTEM", "0").lower() in ("1", "true", "yes", "on")
JOURNAL_UNITS = _env("JOURNAL_UNITS", "")
JOURNAL_PRIORITY = _env("JOURNAL_PRIORITY", "")
JOURNAL_MATCH = _env("JOURNAL_MATCH", "")
JOURNAL_OUTPUT = _env("JOURNAL_OUTPUT", "short-iso")
JOURNAL_FOLLOW_LINES = _env_int("JOURNAL_FOLLOW_LINES", 0)
JOURNAL_PAGE_LINES = _env_int("JOURNAL_PAGE_LINES", 500)
JOURNAL_SEARCH_LINES = _env_int("JOURNAL_SEARCH_LINES", 5000)
JOURNAL_READ_TIMEOUT_SEC = _env_int("JOURNAL_READ_TIMEOUT_SEC", 120)
JOURNAL_SEARCH_SINCE = _env("JOURNAL_SEARCH_SINCE", "24 hours ago")

FLASK_HOST = _env("FLASK_HOST", "0.0.0.0")
FLASK_PORT = _env_int("FLASK_PORT", 9080)
SCAN_INTERVAL_SEC = _env_float("SCAN_INTERVAL_SEC", 5.0)
TAIL_BUFFER_SIZE = _env_int("TAIL_BUFFER_SIZE", 2000)
TAIL_DEFAULT_ORDER = _env("TAIL_DEFAULT_ORDER", "desc").lower()

OLLAMA_BASE_URL = _env("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = _env("OLLAMA_MODEL", "qwen3.6:27b-q8_0")
OLLAMA_EMBED_MODEL = _env("OLLAMA_EMBED_MODEL", "nomic-embed-text")
OLLAMA_TIMEOUT_SEC = _env_int("OLLAMA_TIMEOUT_SEC", 600)
OLLAMA_EMBED_TIMEOUT_SEC = _env_int("OLLAMA_EMBED_TIMEOUT_SEC", 600)
OLLAMA_NUM_PREDICT = _env_int("OLLAMA_NUM_PREDICT", 1024)
OLLAMA_JSON_FORMAT = _env("OLLAMA_JSON_FORMAT", "1").lower() in ("1", "true", "yes", "on")

# LLM provider: ollama | openai | hybrid (remote chat + local Ollama embeddings)
LLM_ENABLED = _env_bool("LLM_ENABLED", True)
LLM_PROVIDER = _env("LLM_PROVIDER", "ollama").lower()
LLM_API_BASE_URL = _env("LLM_API_BASE_URL", "").rstrip("/")
LLM_API_KEY = _env("LLM_API_KEY", "")
LLM_CHAT_MODEL = _env("LLM_CHAT_MODEL", "") or OLLAMA_MODEL
LLM_EMBED_MODEL = _env("LLM_EMBED_MODEL", "") or OLLAMA_EMBED_MODEL

LOG_LINE_MAX_CHARS = _env_int("LOG_LINE_MAX_CHARS", 4096)
LLM_SKIP_LOW_LEVELS = _env("LLM_SKIP_LOW_LEVELS", "1").lower() in (
    "1", "true", "yes", "on"
)

LLM_MAX_FILE_BYTES = _env_int("LLM_MAX_FILE_BYTES", 20_971_520)
LLM_DIRECT_MAX_BYTES = _env_int("LLM_DIRECT_MAX_BYTES", 524_288)
RAG_CHUNK_LINES = _env_int("RAG_CHUNK_LINES", 40)
RAG_CHUNK_OVERLAP = _env_int("RAG_CHUNK_OVERLAP", 8)
RAG_TOP_K = _env_int("RAG_TOP_K", 12)
RAG_MAX_LINES = _env_int("RAG_MAX_LINES", 200_000)
RAG_MAX_CHUNKS = _env_int("RAG_MAX_CHUNKS", 1500)
EMBED_BATCH_SIZE = _env_int("EMBED_BATCH_SIZE", 8)
EMBED_MAX_CHARS = _env_int("EMBED_MAX_CHARS", 4000)
EMBED_LINE_MAX_CHARS = _env_int("EMBED_LINE_MAX_CHARS", 512)
EMBED_MAX_TOKENS_PER_INPUT = _env_int("EMBED_MAX_TOKENS_PER_INPUT", 512)
EMBED_MAX_TOKENS_PER_REQUEST = _env_int("EMBED_MAX_TOKENS_PER_REQUEST", 512)
EMBED_MAX_RETRIES = _env_int("EMBED_MAX_RETRIES", 4)
RAG_QUERY = _env(
    "RAG_QUERY",
    "security anomalies errors failures authentication denials",
)

LLM_AUDIT_ENABLED = _env_bool("LLM_AUDIT_ENABLED", True)
LLM_AUDIT_LOG = _env("LLM_AUDIT_LOG", "")
LLM_AUDIT_MAX_CHARS = _env_int("LLM_AUDIT_MAX_CHARS", 8000)
ANALYSIS_HISTORY_KEEP = _env_int("ANALYSIS_HISTORY_KEEP", 5)
APP_PUBLIC_URL = _env("APP_PUBLIC_URL", "").rstrip("/")

LOG_READ_COMPRESSED = _env_bool("LOG_READ_COMPRESSED", False)
FILE_RECENT_BYTES = _env_int("FILE_RECENT_BYTES", 5_242_880)
SEARCH_MAX_RESULTS = _env_int("SEARCH_MAX_RESULTS", 5000)
SEARCH_MAX_BYTES_PER_FILE = _env_int("SEARCH_MAX_BYTES_PER_FILE", 52_428_800)
SEARCH_CASE_SENSITIVE = _env("SEARCH_CASE_SENSITIVE", "0").lower() in (
    "1", "true", "yes", "on"
)
EXPORT_MAX_ROWS = _env_int("EXPORT_MAX_ROWS", 10_000)
LOG_SKIP_NAMES = _env(
    "LOG_SKIP_NAMES",
    "wtmp,btmp,lastlog,faillog,README.logs",
)
DATA_DIR = Path(_env("DATA_DIR", "./data")).resolve()
CHROMA_DIR = DATA_DIR / "chroma"
SQLITE_PATH = DATA_DIR / "analyses.db"

COMPRESSED_SUFFIXES = (
    ".gz",
    ".bz2",
    ".xz",
    ".zst",
    ".lz4",
    ".zip",
)

APP_NAME = _env("APP_NAME", "syslogb")
# Path under web/static/, or full https:// URL. Empty = no logo.
BRAND_LOGO = _env("BRAND_LOGO", "branding/syslogb.jpg")
BRAND_LOGO_LINK = _env("BRAND_LOGO_LINK", "https://www.comlink.se")
BRAND_TAGLINE = _env("BRAND_TAGLINE", "")
COPYRIGHT_TEXT = _env("COPYRIGHT_TEXT", "SyslogB by Kristinsson Consulting")

from log_intel.syslogb.app.version import __version__ as _APP_VERSION_DEFAULT

APP_VERSION = _env("APP_VERSION", _APP_VERSION_DEFAULT)

AUTH_ENABLED = _env("AUTH_ENABLED", "0").lower() in ("1", "true", "yes", "on")
FLASK_SECRET_KEY = _env("FLASK_SECRET_KEY", "")

LOCAL_AUTH_USERNAME = _env("LOCAL_AUTH_USERNAME", "")
LOCAL_AUTH_PASSWORD = _env("LOCAL_AUTH_PASSWORD", "")

LDAP_URI = _env("LDAP_URI", "").strip()
LDAP_USE_SSL = _env("LDAP_USE_SSL", "0").lower() in ("1", "true", "yes", "on")
LDAP_TIMEOUT_SEC = _env_int("LDAP_TIMEOUT_SEC", 10)
LDAP_BIND_DN = _env("LDAP_BIND_DN", "")
LDAP_BIND_PASSWORD = _env("LDAP_BIND_PASSWORD", "")
LDAP_USER_DN_TEMPLATE = _env("LDAP_USER_DN_TEMPLATE", "")
LDAP_USER_SEARCH_BASE = _env("LDAP_USER_SEARCH_BASE", "")
LDAP_USER_SEARCH_FILTER = _env("LDAP_USER_SEARCH_FILTER", "(sAMAccountName={username})")
LDAP_GROUP_SEARCH_BASE = _env("LDAP_GROUP_SEARCH_BASE", "")
LDAP_REQUIRED_GROUP = _env("LDAP_REQUIRED_GROUP", "")
LDAP_REQUIRED_GROUP_CN = _env("LDAP_REQUIRED_GROUP_CN", "")
LDAP_MEMBER_OF_ATTR = _env("LDAP_MEMBER_OF_ATTR", "memberOf")

SMTP_HOST = _env("SMTP_HOST", "")
SMTP_PORT = _env_int("SMTP_PORT", 587)
SMTP_USER = _env("SMTP_USER", "")
SMTP_PASSWORD = _env("SMTP_PASSWORD", "")
SMTP_FROM = _env("SMTP_FROM", "")
SMTP_TLS = _env("SMTP_TLS", "1").lower() in ("1", "true", "yes", "on")
ALERT_MAX_PER_MINUTE = _env_int("ALERT_MAX_PER_MINUTE", 30)
