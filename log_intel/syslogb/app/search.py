from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Literal

from log_intel.syslogb.app import config
from log_intel.syslogb.app.file_reader import read_tail
from log_intel.syslogb.app.log_dirs import belongs_to_localhost_group, log_dirs
from log_intel.syslogb.app.parser import parse_timestamp, sort_key
from log_intel.syslogb.app.query_parser import compile_text_query, line_matches
from log_intel.syslogb.app.scanner import is_gzip_path, is_readable_file, list_log_files
from log_intel.syslogb.app.severity import classify_line, meets_importance_min

SearchMode = Literal["text", "regex"]


def _compile_pattern(query: str, mode: SearchMode):
    if mode == "regex":
        flags = 0 if config.SEARCH_CASE_SENSITIVE else re.IGNORECASE
        try:
            return re.compile(query, flags)
        except re.error as e:
            raise ValueError(f"Invalid regexp: {e}") from e
    return compile_text_query(query)


def _line_matches(line: str, pattern, mode: SearchMode) -> bool:
    if mode == "regex":
        assert isinstance(pattern, re.Pattern)
        return pattern.search(line) is not None
    ast, _terms = pattern
    return line_matches(ast, line)


def search_file(
    path: Path,
    query: str,
    mode: SearchMode,
    *,
    max_bytes: int | None = None,
    limit: int | None = None,
    importance_min: str | None = None,
) -> list[dict[str, Any]]:
    if not is_readable_file(path):
        return []
    max_bytes = max_bytes or config.SEARCH_MAX_BYTES_PER_FILE
    limit = limit or config.SEARCH_MAX_RESULTS
    pattern = _compile_pattern(query, mode)
    source = str(path.resolve())

    read_from, lines, err = read_tail(path, max_bytes)
    if err:
        return []

    compressed = is_gzip_path(path)
    events: list[dict[str, Any]] = []
    now = time.time()
    line_base = read_from if compressed else 0
    for i, line in enumerate(lines):
        if not line or not _line_matches(line, pattern, mode):
            continue
        if not meets_importance_min(line, importance_min):
            continue
        ts = parse_timestamp(line, now, source=source)
        abs_line = line_base + i
        events.append({
            "id": f"s{abs(hash(source)) % (10 ** 8)}-{read_from}-{i}",
            "source": source,
            "line": line,
            "ts": ts,
            "received_at": sort_key(ts, now),
            "line_index": abs_line,
            "read_from": read_from,
            "compressed": compressed,
            "forward_only": compressed,
            "severity": classify_line(line),
        })
        if len(events) >= limit:
            break
    return events


def search_highlight_terms(query: str, mode: SearchMode) -> list[str]:
    if mode == "regex":
        return []
    _ast, terms = compile_text_query(query)
    return terms


def search_logs(
    query: str,
    mode: SearchMode = "text",
    *,
    path: Path | None = None,
    log_dir: Path | None = None,
    localhost_only: bool = False,
    order: str = "desc",
    limit: int | None = None,
    importance_min: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    if not query.strip():
        return [], "query required"

    limit = limit or config.SEARCH_MAX_RESULTS
    if path is not None:
        if not path.is_file():
            return [], f"Not a file: {path}"
        events = search_file(path, query, mode, limit=limit, importance_min=importance_min)
    else:
        roots = log_dirs()
        if log_dir is not None:
            roots = [log_dir.resolve()]
        events = []
        for root in roots:
            root_resolved = root.resolve()
            for fp in list_log_files(root):
                if not is_readable_file(fp):
                    continue
                if localhost_only:
                    if not belongs_to_localhost_group(fp, root_resolved):
                        continue
                remaining = limit - len(events)
                if remaining <= 0:
                    break
                events.extend(
                    search_file(fp, query, mode, limit=remaining, importance_min=importance_min)
                )
            if len(events) >= limit:
                break

    reverse = order != "asc"
    events.sort(key=lambda e: e["received_at"], reverse=reverse)
    return events, None
