from __future__ import annotations

import re

from log_intel.syslogb.app import config

# RFC5424: severity 6=info, 7=debug (facility*8 + severity)
_RFC5424_PRI = re.compile(r"^<(\d{1,3})>")

# Common textual level markers in syslog / app logs
_LOW_LEVEL_TEXT = re.compile(
    r"(?i)(?:"
    r"\[(?:debug|info|trace)\]|"
    r"\b(?:debug|trace)\b|"
    r"\binfo\b|"
    r"\binformational\b|"
    r"level=(?:debug|info|trace)\b|"
    r"severity=(?:debug|info|trace)\b|"
    r"\.(?:DEBUG|INFO|TRACE)\b|"
    r":\s*(?:debug|info|trace)\s*[-:]"
    r")"
)


def _rfc5424_severity(line: str) -> int | None:
    m = _RFC5424_PRI.match(line)
    if not m:
        return None
    pri = int(m.group(1))
    return pri % 8


def is_info_or_debug_line(line: str) -> bool:
    """True if the line looks like INFO/DEBUG (or TRACE) and should be skipped for LLM."""
    if not line or not line.strip():
        return True

    sev = _rfc5424_severity(line)
    if sev is not None and sev >= 6:
        return True

    return bool(_LOW_LEVEL_TEXT.search(line))


def filter_lines_for_llm(lines: list[str]) -> tuple[list[str], int]:
    """Drop INFO/DEBUG lines when LLM_SKIP_LOW_LEVELS is enabled. Returns (kept, skipped)."""
    if not config.LLM_SKIP_LOW_LEVELS:
        return lines, 0
    kept: list[str] = []
    skipped = 0
    for line in lines:
        if is_info_or_debug_line(line):
            skipped += 1
        else:
            kept.append(line)
    return kept, skipped
