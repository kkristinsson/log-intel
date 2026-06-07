from __future__ import annotations

import gzip
import re
import time
from collections import deque
from pathlib import Path
from typing import Any, TextIO

from log_intel.syslogb.app import config
from log_intel.syslogb.app.fail_filter import is_failure_line
from log_intel.syslogb.app.parser import parse_timestamp, sort_key
from log_intel.syslogb.app.scanner import is_gzip_path, should_skip_file

_WINDOW_RE = re.compile(r"^(\d+)(m|h|d)$", re.IGNORECASE)
_WINDOW_UNITS = {"m": 60, "h": 3600, "d": 86400}


def window_to_since_ts(window: str | None) -> float | None:
    """Parse UI window (15m, 1h, 6h, 24h, 7d) to unix timestamp; None = all / byte tail only."""
    if not window:
        return None
    w = window.strip().lower()
    if w in ("all", "full", ""):
        return None
    m = _WINDOW_RE.match(w)
    if not m:
        return None
    unit = m.group(2).lower()
    if unit not in _WINDOW_UNITS:
        return None
    return time.time() - int(m.group(1)) * _WINDOW_UNITS[unit]


def _filter_lines_since(
    lines: list[str],
    since_ts: float,
    source: str | None = None,
) -> list[str]:
    now = time.time()
    out: list[str] = []
    for line in lines:
        if not line:
            continue
        ts = parse_timestamp(line, now, source=source)
        if ts is None or ts >= since_ts:
            out.append(line)
    return out


def _oldest_ts_in_lines(lines: list[str], source: str | None = None) -> float | None:
    now = time.time()
    oldest: float | None = None
    for line in lines:
        if not line:
            continue
        ts = parse_timestamp(line, now, source=source)
        if ts is None:
            continue
        if oldest is None or ts < oldest:
            oldest = ts
    return oldest


def _open_text(path: Path) -> TextIO:
    if is_gzip_path(path):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _binary_file_error(path: Path) -> str | None:
    if is_gzip_path(path):
        return None
    if should_skip_file(path):
        return "Binary or non-text log file (not supported)"
    return None


def file_meta(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"error": f"Not a file: {path}"}
    bin_err = _binary_file_error(path)
    if bin_err:
        return {"error": bin_err, "path": str(path.resolve()), "binary": True}
    try:
        st = path.stat()
    except OSError as e:
        return {"error": str(e)}
    compressed = is_gzip_path(path)
    return {
        "path": str(path.resolve()),
        "file_size": st.st_size,
        "mtime": st.st_mtime,
        "compressed": compressed,
        "forward_only": compressed,
    }


def read_tail(path: Path, max_bytes: int | None = None) -> tuple[int, list[str], str | None]:
    """Read tail of a plain file. Returns (read_from_byte, lines, error)."""
    if max_bytes is None:
        max_bytes = config.FILE_RECENT_BYTES
    bin_err = _binary_file_error(path)
    if bin_err:
        return 0, [], bin_err
    if is_gzip_path(path):
        return _read_gzip_tail(path, max_bytes)
    if not path.is_file():
        return 0, [], f"Not a file: {path}"
    try:
        size = path.stat().st_size
        read_from = max(0, size - max_bytes)
        with open(path, "rb") as fh:
            if read_from:
                fh.seek(read_from)
            raw = fh.read()
    except OSError as e:
        return 0, [], f"Cannot read {path}: {e}"

    text = raw.decode("utf-8", errors="replace")
    if read_from > 0:
        text = text.split("\n", 1)[-1]
    lines = [ln.rstrip("\r") for ln in text.splitlines()]
    return read_from, lines, None


def _read_gzip_tail(path: Path, max_bytes: int) -> tuple[int, list[str], str | None]:
    if not path.is_file():
        return 0, [], f"Not a file: {path}"
    try:
        buf: deque[tuple[int, str]] = deque()
        total_bytes = 0
        line_no = 0
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.rstrip("\r\n")
                if not line:
                    line_no += 1
                    continue
                nbytes = len(line.encode("utf-8")) + 1
                buf.append((line_no, line))
                total_bytes += nbytes
                line_no += 1
                while total_bytes > max_bytes and buf:
                    _, old = buf.popleft()
                    total_bytes -= len(old.encode("utf-8")) + 1
        if not buf:
            return 0, [], None
        start_line = buf[0][0]
        lines = [line for _, line in buf]
        return start_line, lines, None
    except OSError as e:
        return 0, [], f"Cannot read {path}: {e}"


def read_tail_since(
    path: Path,
    since_ts: float,
    max_bytes: int | None = None,
) -> tuple[int, list[str], str | None]:
    """Read from file end until lines cover since_ts, capped by max_bytes total read."""
    if max_bytes is None:
        max_bytes = config.FILE_RECENT_BYTES
    cap = max(max_bytes, max_bytes * 4)
    if is_gzip_path(path):
        return _read_gzip_tail_since(path, since_ts, cap)
    if not path.is_file():
        return 0, [], f"Not a file: {path}"
    try:
        size = path.stat().st_size
    except OSError as e:
        return 0, [], f"Cannot read {path}: {e}"
    if size == 0:
        return 0, [], None

    chunk = min(512 * 1024, cap)
    read_from = max(0, size - chunk)
    while True:
        try:
            with open(path, "rb") as fh:
                fh.seek(read_from)
                raw = fh.read()
        except OSError as e:
            return 0, [], f"Cannot read {path}: {e}"
        text = raw.decode("utf-8", errors="replace")
        if read_from > 0:
            text = text.split("\n", 1)[-1]
        lines = [ln.rstrip("\r") for ln in text.splitlines()]
        source = str(path.resolve())
        oldest = _oldest_ts_in_lines(lines, source=source)
        span = size - read_from
        if oldest is None or oldest >= since_ts or read_from == 0 or span >= cap:
            return read_from, _filter_lines_since(lines, since_ts, source=source), None
        expand = min(chunk, read_from)
        if expand <= 0:
            return read_from, _filter_lines_since(lines, since_ts, source=source), None
        read_from = max(0, read_from - expand)


def _read_gzip_tail_since(
    path: Path,
    since_ts: float,
    cap: int,
) -> tuple[int, list[str], str | None]:
    chunk = min(512 * 1024, cap)
    read_from = 0
    lines: list[str] = []
    while True:
        read_from, lines, err = _read_gzip_tail(path, chunk)
        if err:
            return 0, [], err
        source = str(path.resolve())
        oldest = _oldest_ts_in_lines(lines, source=source)
        if oldest is None or oldest >= since_ts or read_from == 0 or chunk >= cap:
            return read_from, _filter_lines_since(lines, since_ts, source=source), None
        chunk = min(chunk * 2, cap)


def read_range_plain(
    path: Path,
    start_byte: int,
    max_bytes: int,
) -> tuple[int, int, list[str], str | None]:
    """Read a byte range from a plain file. Returns (read_from, read_to, lines, error)."""
    if is_gzip_path(path):
        return 0, 0, [], "use line-based paging for compressed files"
    if not path.is_file():
        return 0, 0, [], f"Not a file: {path}"
    try:
        size = path.stat().st_size
        start_byte = max(0, min(start_byte, size))
        with open(path, "rb") as fh:
            fh.seek(start_byte)
            raw = fh.read(max_bytes)
        read_to = start_byte + len(raw)
        text = raw.decode("utf-8", errors="replace")
        if start_byte > 0:
            text = text.split("\n", 1)[-1]
        lines = [ln.rstrip("\r") for ln in text.splitlines()]
        if read_to < size and lines:
            lines = lines[:-1]
            partial = lines[-1] if lines else ""
            if partial and not text.endswith("\n"):
                read_to -= len(partial.encode("utf-8")) + 1
                lines.pop()
        return start_byte, read_to, lines, None
    except OSError as e:
        return 0, 0, [], f"Cannot read {path}: {e}"


def read_forward_lines(
    path: Path,
    *,
    start_line: int = 0,
    max_bytes: int | None = None,
    max_lines: int | None = None,
) -> tuple[int, int, list[str], bool, str | None]:
    """
    Forward read from start_line (0-based line index in file).
    Returns (line_start, line_end_exclusive, lines, has_more, error).
    """
    if max_bytes is None:
        max_bytes = config.FILE_RECENT_BYTES
    if max_lines is None:
        max_lines = 50_000
    if not path.is_file():
        return start_line, start_line, [], False, f"Not a file: {path}"

    lines_out: list[str] = []
    bytes_read = 0
    line_no = 0
    line_start = start_line
    try:
        with _open_text(path) as fh:
            for raw in fh:
                line = raw.rstrip("\r\n")
                if line_no < start_line:
                    line_no += 1
                    continue
                if not line:
                    line_no += 1
                    continue
                nbytes = len(line.encode("utf-8")) + 1
                if lines_out and bytes_read + nbytes > max_bytes:
                    return line_start, line_no, lines_out, True, None
                if len(lines_out) >= max_lines:
                    return line_start, line_no, lines_out, True, None
                lines_out.append(line)
                bytes_read += nbytes
                line_no += 1
        end = line_start + len(lines_out)
        return line_start, end, lines_out, False, None
    except OSError as e:
        return start_line, start_line, [], False, f"Cannot read {path}: {e}"


def lines_to_events(
    path: Path,
    read_from: int,
    lines: list[str],
    *,
    failures_only: bool = False,
    line_start: int | None = None,
) -> list[dict[str, Any]]:
    from log_intel.syslogb.app.severity import classify_line

    source = str(path.resolve())
    now = time.time()
    base_line = line_start if line_start is not None else 0
    events: list[dict[str, Any]] = []
    for i, line in enumerate(lines):
        if not line:
            continue
        if failures_only and not is_failure_line(line):
            continue
        ts = parse_timestamp(line, now, source=source)
        abs_line = base_line + i
        events.append({
            "id": f"f{read_from}-{abs_line}",
            "source": source,
            "line": line,
            "ts": ts,
            "received_at": sort_key(ts, now),
            "line_index": abs_line,
            "read_from": read_from,
            "severity": classify_line(line),
        })
    return events


def _page_result(
    path: Path,
    events: list[dict[str, Any]],
    *,
    read_from: int,
    read_to: int,
    file_size: int,
    compressed: bool,
    line_start: int | None = None,
    line_end: int | None = None,
    has_older: bool = False,
    has_newer: bool = False,
    err: str | None = None,
    extra: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str | None]:
    if err:
        return {}, err
    meta = {
        "path": str(path.resolve()),
        "file_size": file_size,
        "read_from": read_from,
        "read_to": read_to,
        "line_start": line_start,
        "line_end": line_end,
        "line_count": len(events),
        "compressed": compressed,
        "forward_only": compressed,
        "has_older": has_older,
        "has_newer": has_newer,
        "events": events,
    }
    if extra:
        meta.update(extra)
    return meta, None


def _tail_with_window_fallback(
    path: Path,
    since_ts: float,
    max_bytes: int,
    failures_only: bool,
    file_size: int,
    *,
    compressed: bool,
) -> tuple[dict[str, Any], str | None]:
    """Tail load with since_ts; if the window has no lines, show recent tail instead."""
    if compressed:
        read_from, lines, err = read_tail_since(path, since_ts, max_bytes)
        if err:
            return {}, err
        line_start = read_from if isinstance(read_from, int) else 0
        events = lines_to_events(path, 0, lines, failures_only=failures_only, line_start=line_start)
        line_end = line_start + len(lines)
        extra: dict[str, Any] = {}
        if not events and file_size > 0:
            read_from, lines, err = read_tail(path, max_bytes)
            if err:
                return {}, err
            line_start = read_from if isinstance(read_from, int) else 0
            events = lines_to_events(path, 0, lines, failures_only=failures_only, line_start=line_start)
            line_end = line_start + len(lines)
            extra = {
                "window_fallback": True,
                "window_fallback_message": (
                    "No lines in the selected time range; showing the most recent lines instead."
                ),
            }
        return _page_result(
            path,
            events,
            read_from=0,
            read_to=file_size,
            file_size=file_size,
            compressed=True,
            line_start=line_start,
            line_end=line_end,
            has_older=line_start > 0,
            has_newer=False,
            extra=extra or None,
        )

    read_from, lines, err = read_tail_since(path, since_ts, max_bytes)
    if err:
        return {}, err
    read_to = file_size
    events = lines_to_events(path, read_from, lines, failures_only=failures_only)
    extra_plain: dict[str, Any] = {}
    if not events and file_size > 0:
        read_from, lines, err = read_tail(path, max_bytes)
        if err:
            return {}, err
        events = lines_to_events(path, read_from, lines, failures_only=failures_only)
        extra_plain = {
            "window_fallback": True,
            "window_fallback_message": (
                "No lines in the selected time range; showing the most recent lines instead."
            ),
        }
    return _page_result(
        path,
        events,
        read_from=read_from,
        read_to=read_to,
        file_size=file_size,
        compressed=False,
        has_older=read_from > 0,
        has_newer=False,
        extra=extra_plain or None,
    )


def read_file_page(
    path: Path,
    *,
    direction: str = "tail",
    before_byte: int | None = None,
    after_byte: int | None = None,
    before_line: int | None = None,
    after_line: int | None = None,
    max_bytes: int | None = None,
    failures_only: bool = False,
    since_ts: float | None = None,
) -> tuple[dict[str, Any], str | None]:
    """Paged file read. direction: tail | older | newer | forward."""
    if max_bytes is None:
        max_bytes = config.FILE_RECENT_BYTES
    if not path.is_file():
        return {}, f"Not a file: {path}"
    bin_err = _binary_file_error(path)
    if bin_err:
        return {}, bin_err

    try:
        file_size = path.stat().st_size
    except OSError as e:
        return {}, str(e)

    compressed = is_gzip_path(path)

    if compressed:
        if direction == "tail":
            if since_ts is not None:
                return _tail_with_window_fallback(
                    path,
                    since_ts,
                    max_bytes,
                    failures_only,
                    file_size,
                    compressed=True,
                )
            read_from, lines, err = read_tail(path, max_bytes)
            if err:
                return {}, err
            line_start = read_from if isinstance(read_from, int) else 0
            events = lines_to_events(path, 0, lines, failures_only=failures_only, line_start=line_start)
            line_end = line_start + len(lines)
            has_older = line_start > 0
            return _page_result(
                path,
                events,
                read_from=0,
                read_to=file_size,
                file_size=file_size,
                compressed=True,
                line_start=line_start,
                line_end=line_end,
                has_older=has_older,
                has_newer=False,
            )
        if direction == "older":
            start = max(0, (before_line or 0) - 1)
            chunk = min(max_bytes, config.FILE_RECENT_BYTES)
            approx_lines = max(500, chunk // 80)
            start = max(0, start - approx_lines)
            ls, le, lines, has_more, err = read_forward_lines(
                path, start_line=start, max_bytes=chunk,
            )
            if err:
                return {}, err
            events = lines_to_events(path, 0, lines, failures_only=failures_only, line_start=ls)
            return _page_result(
                path, events,
                read_from=0, read_to=file_size, file_size=file_size, compressed=True,
                line_start=ls, line_end=le,
                has_older=ls > 0, has_newer=has_more or (before_line or 0) < le,
            )
        if direction in ("newer", "forward"):
            start = after_line if after_line is not None else 0
            ls, le, lines, has_more, err = read_forward_lines(
                path, start_line=start, max_bytes=max_bytes,
            )
            if err:
                return {}, err
            events = lines_to_events(path, 0, lines, failures_only=failures_only, line_start=ls)
            return _page_result(
                path, events,
                read_from=0, read_to=file_size, file_size=file_size, compressed=True,
                line_start=ls, line_end=le,
                has_older=ls > 0, has_newer=has_more,
            )
        return {}, f"invalid direction for compressed file: {direction}"

    # Plain file
    if direction == "tail":
        if since_ts is not None:
            return _tail_with_window_fallback(
                path,
                since_ts,
                max_bytes,
                failures_only,
                file_size,
                compressed=False,
            )
        read_from, lines, err = read_tail(path, max_bytes)
        if err:
            return {}, err
        read_to = file_size
        events = lines_to_events(path, read_from, lines, failures_only=failures_only)
        return _page_result(
            path,
            events,
            read_from=read_from,
            read_to=read_to,
            file_size=file_size,
            compressed=False,
            has_older=read_from > 0,
            has_newer=False,
        )

    if direction == "older":
        end_byte = before_byte if before_byte is not None else file_size
        start_byte = max(0, end_byte - max_bytes)
        read_from, read_to, lines, err = read_range_plain(path, start_byte, end_byte - start_byte)
        if err:
            return {}, err
        events = lines_to_events(path, read_from, lines, failures_only=failures_only)
        return _page_result(
            path, events,
            read_from=read_from, read_to=read_to, file_size=file_size, compressed=False,
            has_older=read_from > 0, has_newer=read_to < file_size,
        )

    if direction == "newer":
        start_byte = after_byte if after_byte is not None else 0
        read_from, read_to, lines, err = read_range_plain(path, start_byte, max_bytes)
        if err:
            return {}, err
        events = lines_to_events(path, read_from, lines, failures_only=failures_only)
        return _page_result(
            path, events,
            read_from=read_from, read_to=read_to, file_size=file_size, compressed=False,
            has_older=read_from > 0, has_newer=read_to < file_size,
        )

    return {}, f"invalid direction: {direction}"


def recent_lines(
    path: Path,
    max_bytes: int | None = None,
    *,
    failures_only: bool = False,
) -> tuple[list[dict[str, Any]], str | None]:
    page, err = read_file_page(path, direction="tail", max_bytes=max_bytes, failures_only=failures_only)
    if err:
        return [], err
    return page.get("events", []), None


def full_log_lines(
    path: Path,
    max_bytes: int | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    if max_bytes is None:
        max_bytes = config.SEARCH_MAX_BYTES_PER_FILE
    page, err = read_file_page(path, direction="tail", max_bytes=max_bytes, failures_only=False)
    if err:
        return [], err
    return page.get("events", []), None
