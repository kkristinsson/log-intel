from __future__ import annotations

from typing import Iterator

from log_intel.syslogb.app import config


def _trim_line(line: str) -> str:
    limit = config.EMBED_LINE_MAX_CHARS
    if limit <= 0 or len(line) <= limit:
        return line
    return line[: limit - 1] + "…"


def chunk_lines(
    lines: list[str],
    chunk_size: int,
    overlap: int,
) -> Iterator[tuple[int, str]]:
    if chunk_size <= 0:
        chunk_size = 40
    overlap = max(0, min(overlap, chunk_size - 1))
    step = max(1, chunk_size - overlap)
    i = 0
    while i < len(lines):
        block = [_trim_line(x) for x in lines[i : i + chunk_size]]
        block = [x for x in block if x.strip()]
        if not block:
            i += step
            continue
        text = "\n".join(block)
        yield i, text
        i += step
