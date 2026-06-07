"""Backward-compatible re-exports; prefer app.llm_client."""

from log_intel.syslogb.app.llm_client import (
    SYSTEM_PROMPT,
    analyze_lines,
    health_check,
    resolve_chat_model,
)

__all__ = [
    "SYSTEM_PROMPT",
    "analyze_lines",
    "health_check",
    "resolve_chat_model",
]
