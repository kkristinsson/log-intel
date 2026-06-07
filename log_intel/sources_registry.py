"""Load config/sources.yaml for ingest routing and adapter resolution."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

DEFAULT_PATH = "config/sources.yaml"


@dataclass(frozen=True)
class MatchRule:
    type: str
    pattern: str


@dataclass(frozen=True)
class SourceDef:
    id: str
    source_type: str
    ingest: str
    description: str = ""
    enabled: bool = True
    default: bool = False
    match: tuple[MatchRule, ...] = ()
    adapter: str | None = None
    base_url_env: str | None = None
    db_path_env: str | None = None
    uri: str | None = None
    retention_hours: float | None = None


def _parse_match(raw: Any) -> tuple[MatchRule, ...]:
    if not raw:
        return ()
    rules: list[MatchRule] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        t = str(item.get("type", "")).strip()
        p = str(item.get("pattern", "")).strip()
        if t and p:
            rules.append(MatchRule(type=t, pattern=p))
    return tuple(rules)


def _parse_source(raw: dict[str, Any]) -> SourceDef | None:
    sid = str(raw.get("id", "")).strip()
    if not sid:
        return None
    return SourceDef(
        id=sid,
        source_type=str(raw.get("source_type", "generic")),
        ingest=str(raw.get("ingest", "syslog")),
        description=str(raw.get("description", "")),
        enabled=bool(raw.get("enabled", True)),
        default=bool(raw.get("default", False)),
        match=_parse_match(raw.get("match")),
        adapter=raw.get("adapter"),
        base_url_env=raw.get("base_url_env"),
        db_path_env=raw.get("db_path_env"),
        uri=raw.get("uri"),
        retention_hours=raw.get("retention_hours"),
    )


def _default_sources() -> tuple[SourceDef, ...]:
    return (
        SourceDef("palo_alto", "palo_alto", "syslog", "Palo Alto syslog"),
        SourceDef("windows_syslogpusher", "windows", "syslog", "Windows Syslog Pusher"),
        SourceDef("generic_syslog", "generic", "syslog", "Generic syslog", default=True),
    )


@lru_cache(maxsize=1)
def load_sources(path: str | None = None) -> tuple[SourceDef, ...]:
    yaml_path = path or os.environ.get("LOG_INTEL_SOURCES_YAML", DEFAULT_PATH)
    p = Path(yaml_path)
    if not p.is_file():
        log.warning("sources.yaml not found at %s — using built-in defaults", p)
        return _default_sources()
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        log.warning("Failed to load sources.yaml: %s", e)
        return _default_sources()
    if not isinstance(data, dict):
        return _default_sources()
    items = data.get("sources") or []
    out: list[SourceDef] = []
    for raw in items:
        if isinstance(raw, dict):
            s = _parse_source(raw)
            if s:
                out.append(s)
    return tuple(out) if out else _default_sources()


def reload_sources() -> tuple[SourceDef, ...]:
    cache_clear = getattr(load_sources, "cache_clear", None)
    if cache_clear is not None:
        cache_clear()
    return load_sources()


def enabled_syslog_sources() -> tuple[SourceDef, ...]:
    return tuple(s for s in load_sources() if s.enabled and s.ingest == "syslog")


def classify_source_type(raw: str, msg_body: str) -> str | None:
    """Return source_type from first matching registry rule, or None to use defaults."""
    from log_intel.parsers.generic import is_windows_rfc5424
    from log_intel.parsers.palo_alto import is_palo_alto_message

    haystack = f"{raw}\n{msg_body}".lower()
    for src in enabled_syslog_sources():
        if src.default:
            continue
        if src.source_type == "palo_alto" and (
            is_palo_alto_message(msg_body) or is_palo_alto_message(raw)
        ):
            return "palo_alto"
        for rule in src.match:
            if rule.type == "message_contains" and rule.pattern.lower() in haystack:
                return src.source_type
            if rule.type == "rfc5424_appname" and rule.pattern.lower() in haystack:
                return src.source_type
        if src.source_type == "windows" and is_windows_rfc5424(raw):
            return "windows"
    return None


def resolve_env_path(env_key: str | None) -> str:
    if not env_key:
        return ""
    return os.environ.get(env_key, "").strip()


def adapter_source(adapter: str) -> SourceDef | None:
    for s in load_sources():
        if s.adapter == adapter and s.enabled:
            return s
    return None


def sources_health() -> list[dict[str, Any]]:
    return [
        {
            "id": s.id,
            "source_type": s.source_type,
            "ingest": s.ingest,
            "enabled": s.enabled,
            "adapter": s.adapter,
        }
        for s in load_sources()
    ]
