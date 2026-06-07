from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SettingType = Literal["str", "int", "float", "bool", "secret"]

# Only used before SQLite exists; everything else is web-configurable in DB.
BOOTSTRAP_ENV_KEYS = frozenset({"DATA_DIR"})

SECRET_KEYS = frozenset({
    "FLASK_SECRET_KEY",
    "LLM_API_KEY",
    "LDAP_BIND_PASSWORD",
    "LOCAL_AUTH_PASSWORD",
    "SMTP_PASSWORD",
})

SETUP_COMPLETE_KEY = "SETUP_COMPLETE"


@dataclass(frozen=True)
class SettingDef:
    key: str
    default: str
    value_type: SettingType
    section: str
    label: str
    description: str = ""
    requires_restart: bool = False


def registry() -> list[SettingDef]:
    return [
        SettingDef("FLASK_HOST", "0.0.0.0", "str", "server", "Bind address", requires_restart=True),
        SettingDef("FLASK_PORT", "9080", "int", "server", "HTTP port", requires_restart=True),
        SettingDef("DATA_DIR", "./data", "str", "server", "Data directory", requires_restart=True),
        SettingDef("FLASK_SECRET_KEY", "", "secret", "server", "Session secret key", requires_restart=True),
        SettingDef("LOG_DIR", "/var/log", "str", "logging", "Log directory", "Used when LOG_DIRS is empty"),
        SettingDef("LOG_DIRS", "", "str", "logging", "Log directories", "Comma-separated roots", True),
        SettingDef("LOG_GLOB", "*", "str", "logging", "File glob", requires_restart=True),
        SettingDef("LOG_RECURSIVE", "0", "bool", "logging", "Recursive scan", requires_restart=True),
        SettingDef("LOG_READ_COMPRESSED", "0", "bool", "logging", "List/read .gz logs (no live tail)", requires_restart=True),
        SettingDef("LOG_SKIP_NAMES", "wtmp,btmp,lastlog,faillog,README.logs", "str", "logging", "Skip basenames"),
        SettingDef("JOURNAL_ENABLED", "1", "bool", "logging", "Tail systemd journal (journalctl)", requires_restart=True),
        SettingDef("JOURNAL_DIRECTORY", "", "str", "logging", "Journal directory (-D)", "Docker: /run/log/journal", True),
        SettingDef("JOURNAL_BOOT_ONLY", "0", "bool", "logging", "Current boot only (-b)", requires_restart=True),
        SettingDef("JOURNAL_MERGE_SYSTEM", "0", "bool", "logging", "Merge system journals (--merge)", requires_restart=True),
        SettingDef("JOURNAL_UNITS", "", "str", "logging", "Filter units (-u)", "Comma-separated, e.g. ssh.service,nginx.service", True),
        SettingDef("JOURNAL_PRIORITY", "", "str", "logging", "Min priority", "debug, info, warning, err, …", True),
        SettingDef("JOURNAL_MATCH", "", "str", "logging", "Extra --grep filters", "Comma-separated", True),
        SettingDef("JOURNAL_OUTPUT", "short-iso", "str", "logging", "journalctl output format", requires_restart=True),
        SettingDef("JOURNAL_PAGE_LINES", "500", "int", "logging", "Journal file-view line count"),
        SettingDef("JOURNAL_SEARCH_SINCE", "24 hours ago", "str", "search", "Journal search window"),
        SettingDef("SCAN_INTERVAL_SEC", "5", "float", "logging", "Scan interval (s)", requires_restart=True),
        SettingDef("TAIL_BUFFER_SIZE", "2000", "int", "logging", "Live buffer size", requires_restart=True),
        SettingDef("TAIL_DEFAULT_ORDER", "desc", "str", "logging", "Default sort order"),
        SettingDef("FILE_RECENT_BYTES", "5242880", "int", "logging", "File view tail bytes"),
        SettingDef("SEARCH_MAX_RESULTS", "5000", "int", "search", "Max search results"),
        SettingDef("SEARCH_MAX_BYTES_PER_FILE", "52428800", "int", "search", "Search bytes per file"),
        SettingDef("SEARCH_CASE_SENSITIVE", "0", "bool", "search", "Case-sensitive search"),
        SettingDef("EXPORT_MAX_ROWS", "10000", "int", "search", "Max export rows"),
        SettingDef("LLM_ENABLED", "1", "bool", "llm", "Enable LLM features (explain & anomaly analysis)"),
        SettingDef("LLM_PROVIDER", "ollama", "str", "llm", "LLM provider (ollama, openai, hybrid)"),
        SettingDef("OLLAMA_BASE_URL", "http://127.0.0.1:11434", "str", "llm", "Ollama base URL"),
        SettingDef("OLLAMA_MODEL", "qwen3.6:27b-q8_0", "str", "llm", "Ollama chat model"),
        SettingDef("OLLAMA_EMBED_MODEL", "nomic-embed-text", "str", "llm", "Ollama embed model"),
        SettingDef("OLLAMA_TIMEOUT_SEC", "600", "int", "llm", "Chat timeout (s)"),
        SettingDef("OLLAMA_EMBED_TIMEOUT_SEC", "600", "int", "llm", "Embed timeout (s)"),
        SettingDef("OLLAMA_NUM_PREDICT", "1024", "int", "llm", "Max tokens"),
        SettingDef(
            "OLLAMA_JSON_FORMAT",
            "0",
            "bool",
            "llm",
            "Request JSON format (disable for qwen3.x / thinking models)",
        ),
        SettingDef("LLM_API_BASE_URL", "https://api.openai.com/v1", "str", "llm", "OpenAI-compatible API URL"),
        SettingDef("LLM_API_KEY", "", "secret", "llm", "API key"),
        SettingDef("LLM_CHAT_MODEL", "", "str", "llm", "OpenAI-compatible chat model"),
        SettingDef("LLM_EMBED_MODEL", "text-embedding-3-small", "str", "llm", "OpenAI embed model"),
        SettingDef("LOG_LINE_MAX_CHARS", "4096", "int", "llm", "Max line chars for LLM"),
        SettingDef("LLM_SKIP_LOW_LEVELS", "1", "bool", "llm", "Skip INFO/DEBUG for LLM"),
        SettingDef("LLM_MAX_FILE_BYTES", "20971520", "int", "llm", "Max file bytes for LLM"),
        SettingDef("LLM_DIRECT_MAX_BYTES", "524288", "int", "llm", "Direct LLM max bytes"),
        SettingDef("RAG_CHUNK_LINES", "40", "int", "llm", "RAG chunk lines"),
        SettingDef("RAG_CHUNK_OVERLAP", "8", "int", "llm", "RAG chunk overlap"),
        SettingDef("RAG_TOP_K", "12", "int", "llm", "RAG top K"),
        SettingDef("RAG_MAX_LINES", "200000", "int", "llm", "RAG max lines"),
        SettingDef("RAG_MAX_CHUNKS", "1500", "int", "llm", "RAG max chunks"),
        SettingDef("EMBED_BATCH_SIZE", "8", "int", "llm", "Embed batch size"),
        SettingDef("EMBED_MAX_CHARS", "4000", "int", "llm", "Embed max chars per chunk"),
        SettingDef("EMBED_LINE_MAX_CHARS", "512", "int", "llm", "Embed line max chars"),
        SettingDef(
            "EMBED_MAX_TOKENS_PER_INPUT",
            "512",
            "int",
            "llm",
            "Max tokens per embed input (Berget e5: 512)",
        ),
        SettingDef(
            "EMBED_MAX_TOKENS_PER_REQUEST",
            "512",
            "int",
            "llm",
            "Max total tokens per embed API call (0 = no cap)",
        ),
        SettingDef("EMBED_MAX_RETRIES", "4", "int", "llm", "Embed max retries"),
        SettingDef("RAG_QUERY", "security anomalies errors failures authentication denials", "str", "llm", "RAG query"),
        SettingDef("LLM_AUDIT_ENABLED", "1", "bool", "llm", "Write LLM audit plain log"),
        SettingDef("LLM_AUDIT_LOG", "", "str", "llm", "LLM audit log path (empty = data/llm-audit.log)"),
        SettingDef("LLM_AUDIT_MAX_CHARS", "8000", "int", "llm", "Max chars per request/response in audit log"),
        SettingDef("ANALYSIS_HISTORY_KEEP", "5", "int", "llm", "Saved LLM analyses to keep (1–50)"),
        SettingDef(
            "APP_PUBLIC_URL",
            "",
            "str",
            "llm",
            "Public URL for analysis links in alerts (empty = http://127.0.0.1:FLASK_PORT)",
        ),
        SettingDef("APP_NAME", "syslogb", "str", "branding", "Application name"),
        SettingDef("APP_VERSION", "", "str", "branding", "Version override"),
        SettingDef("BRAND_LOGO", "branding/syslogb.jpg", "str", "branding", "Logo path or URL"),
        SettingDef("BRAND_LOGO_LINK", "https://www.comlink.se", "str", "branding", "Logo link"),
        SettingDef("BRAND_TAGLINE", "", "str", "branding", "Tagline"),
        SettingDef("COPYRIGHT_TEXT", "SyslogB by Kristinsson Consulting", "str", "branding", "Copyright"),
        SettingDef("AUTH_ENABLED", "0", "bool", "auth", "Require sign-in"),
        SettingDef("LOCAL_AUTH_USERNAME", "admin", "str", "auth", "Local admin username"),
        SettingDef("LOCAL_AUTH_PASSWORD", "", "secret", "auth", "Local admin password"),
        SettingDef("LDAP_URI", "", "str", "auth", "LDAP URI"),
        SettingDef("LDAP_USE_SSL", "0", "bool", "auth", "LDAP SSL"),
        SettingDef("LDAP_TIMEOUT_SEC", "10", "int", "auth", "LDAP timeout"),
        SettingDef("LDAP_BIND_DN", "", "str", "auth", "LDAP bind DN"),
        SettingDef("LDAP_BIND_PASSWORD", "", "secret", "auth", "LDAP bind password"),
        SettingDef("LDAP_USER_DN_TEMPLATE", "", "str", "auth", "LDAP user DN template"),
        SettingDef("LDAP_USER_SEARCH_BASE", "", "str", "auth", "LDAP user search base"),
        SettingDef("LDAP_USER_SEARCH_FILTER", "(sAMAccountName={username})", "str", "auth", "LDAP user filter"),
        SettingDef("LDAP_GROUP_SEARCH_BASE", "", "str", "auth", "LDAP group search base"),
        SettingDef("LDAP_REQUIRED_GROUP", "", "str", "auth", "LDAP required group DN"),
        SettingDef("LDAP_REQUIRED_GROUP_CN", "", "str", "auth", "LDAP required group CN"),
        SettingDef("LDAP_MEMBER_OF_ATTR", "memberOf", "str", "auth", "LDAP memberOf attr"),
        SettingDef("SMTP_HOST", "", "str", "alerts", "SMTP host"),
        SettingDef("SMTP_PORT", "587", "int", "alerts", "SMTP port"),
        SettingDef("SMTP_USER", "", "str", "alerts", "SMTP user"),
        SettingDef("SMTP_PASSWORD", "", "secret", "alerts", "SMTP password"),
        SettingDef("SMTP_FROM", "", "str", "alerts", "SMTP from address"),
        SettingDef("SMTP_TLS", "1", "bool", "alerts", "SMTP TLS"),
        SettingDef("ALERT_MAX_PER_MINUTE", "30", "int", "alerts", "Global alert cap per minute"),
    ]


def registry_by_key() -> dict[str, SettingDef]:
    return {d.key: d for d in registry()}
