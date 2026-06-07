"""Append-only plain-text audit log for LLM API calls."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from log_intel.syslogb.app import config

_lock = threading.Lock()


def audit_enabled() -> bool:
    return bool(config.LLM_ENABLED) and bool(config.LLM_AUDIT_ENABLED)


def audit_path() -> Path:
    raw = (config.LLM_AUDIT_LOG or "").strip()
    if raw:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = (config.DATA_DIR / path).resolve()
        return path
    return (config.DATA_DIR / "llm-audit.log").resolve()


def _truncate(text: str, limit: int | None = None) -> str:
    cap = limit if limit is not None else config.LLM_AUDIT_MAX_CHARS
    if cap <= 0:
        return text
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if len(text) <= cap:
        return text
    return text[: cap - 1] + "…"


def _summarize_messages(messages: list[dict[str, str]]) -> str:
    parts: list[str] = []
    for msg in messages:
        role = msg.get("role", "?")
        content = msg.get("content") or ""
        parts.append(f"{role}:{len(content)}c")
    return "messages=" + ",".join(parts) if parts else "messages=0"


def _format_meta(meta: dict[str, Any] | None) -> str:
    if not meta:
        return ""
    bits = [f"{k}={v}" for k, v in meta.items() if v is not None and v != ""]
    return "  meta: " + " ".join(bits) + "\n" if bits else ""


def log_event(
    *,
    op: str,
    status: str,
    model: str = "",
    endpoint: str = "",
    duration_ms: float | None = None,
    error: str = "",
    meta: dict[str, Any] | None = None,
    request_note: str = "",
    response_note: str = "",
    request_body: str = "",
    response_body: str = "",
) -> None:
    if not audit_enabled():
        return

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    ms_part = f" ms={duration_ms:.0f}" if duration_ms is not None else ""
    line = (
        f"[{ts}] {status.upper()} {op} "
        f"provider={config.LLM_PROVIDER} model={model or '-'} "
        f"endpoint={endpoint or '-'}{ms_part}\n"
    )
    if error:
        line += f"  error: {_truncate(error, 2000)}\n"
    line += _format_meta(meta)
    if request_note:
        line += f"  request: {request_note}\n"
    if response_note:
        line += f"  response: {response_note}\n"
    if request_body:
        line += "  --- request ---\n"
        for body_line in _truncate(request_body).split("\n"):
            line += f"  {body_line}\n"
    if response_body:
        line += "  --- response ---\n"
        for body_line in _truncate(response_body).split("\n"):
            line += f"  {body_line}\n"
    line += "-" * 72 + "\n"

    path = audit_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _lock:
            with path.open("a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        pass


def log_ok(**kwargs: Any) -> None:
    log_event(status="ok", **kwargs)


def log_fail(**kwargs: Any) -> None:
    log_event(status="fail", **kwargs)
