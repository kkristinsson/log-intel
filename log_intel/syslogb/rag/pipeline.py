from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path

from log_intel.syslogb.app import config
from log_intel.syslogb.app import llm_audit
from log_intel.syslogb.app.file_reader import read_tail, read_tail_since, window_to_since_ts
from log_intel.syslogb.app.journal_reader import read_journal_window
from log_intel.syslogb.app.journal_source import is_journal_source
from log_intel.syslogb.app.llm_filter import filter_lines_for_llm
from log_intel.syslogb.app.llm_client import analyze_lines, llm_provider
from log_intel.syslogb.rag.chunker import chunk_lines
from log_intel.syslogb.rag.chroma_store import ChromaStore
from log_intel.syslogb.rag.embedder import embed_texts, embeddings_available, resolve_embed_model

logger = logging.getLogger(__name__)

ProgressFn = Callable[[int, str], None]
CancelFn = Callable[[], bool]


def read_log_file(path: Path) -> list[str]:
    raw = path.read_bytes()[: config.LLM_MAX_FILE_BYTES]
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    return _filter_for_llm(path, lines)


def _filter_for_llm(path: Path, lines: list[str]) -> list[str]:
    filtered, skipped = filter_lines_for_llm(lines)
    if skipped:
        logger.info(
            "LLM input %s: dropped %d INFO/DEBUG lines, kept %d",
            path.name,
            skipped,
            len(filtered),
        )
    return filtered


def _lines_byte_size(lines: list[str]) -> int:
    return sum(len(line.encode("utf-8", errors="replace")) + 1 for line in lines)


def read_log_file_window(path: Path, window: str | None) -> tuple[list[str], str]:
    """Load lines for a UI time range (15m, 1h, …) or recent tail when window is all."""
    cap = config.LLM_MAX_FILE_BYTES
    w = (window or "1h").strip().lower()
    since_ts = window_to_since_ts(w)
    if since_ts is not None:
        _read_from, lines, err = read_tail_since(path, since_ts, cap)
        if err:
            raise RuntimeError(err)
        label = w
    else:
        max_b = min(cap, config.FILE_RECENT_BYTES)
        _read_from, lines, err = read_tail(path, max_b)
        if err:
            raise RuntimeError(err)
        label = "recent tail"
    filtered = _filter_for_llm(path, lines)
    note = f"Time range ({label}) from {path.name}: {len(filtered)} lines"
    return filtered, note


def tail_lines(lines: list[str], max_bytes: int) -> list[str]:
    out: list[str] = []
    total = 0
    for line in reversed(lines):
        total += len(line) + 1
        if total > max_bytes and out:
            break
        out.append(line)
    out.reverse()
    return out


def _lines_for_rag(lines: list[str]) -> list[str]:
    cap = config.RAG_MAX_LINES
    if cap > 0 and len(lines) > cap:
        logger.info("RAG: using last %d of %d lines", cap, len(lines))
        return lines[-cap:]
    return lines


def _chunks_for_rag(lines: list[str]) -> list[tuple[int, str]]:
    chunks = list(chunk_lines(lines, config.RAG_CHUNK_LINES, config.RAG_CHUNK_OVERLAP))
    cap = config.RAG_MAX_CHUNKS
    if cap > 0 and len(chunks) > cap:
        logger.info("RAG: using last %d of %d chunks", cap, len(chunks))
        chunks = chunks[-cap:]
    return chunks


def _check_cancel(should_cancel: CancelFn | None) -> None:
    if should_cancel and should_cancel():
        from log_intel.syslogb.app.job_cancel import JobCancelled

        raise JobCancelled()


def _report(
    on_progress: ProgressFn | None,
    pct: int,
    stage: str,
    *,
    should_cancel: CancelFn | None = None,
) -> None:
    _check_cancel(should_cancel)
    if on_progress:
        on_progress(pct, stage)


def _direct(
    path: Path,
    lines: list[str],
    note: str,
    mode: str,
    on_progress: ProgressFn | None,
    should_cancel: CancelFn | None = None,
) -> tuple[dict, str, str]:
    _report(on_progress, 35, "Preparing prompt", should_cancel=should_cancel)
    capped = tail_lines(lines, config.LLM_DIRECT_MAX_BYTES)
    if len(capped) < len(lines):
        note = f"{note} (last {len(capped)} of {len(lines)} lines)"
        logger.info(
            "Direct analyze %s: using tail %d/%d lines (~%d byte budget)",
            path.name,
            len(capped),
            len(lines),
            config.LLM_DIRECT_MAX_BYTES,
        )
    _report(on_progress, 55, "Running LLM analysis", should_cancel=should_cancel)
    parsed, raw = analyze_lines(capped, context_note=note)
    _report(on_progress, 92, "Parsing LLM response", should_cancel=should_cancel)
    return parsed, raw, mode


def _rag_analyze(
    path: Path,
    lines: list[str],
    size: int,
    on_progress: ProgressFn | None,
    should_cancel: CancelFn | None = None,
) -> tuple[dict, str, str]:
    rag_lines = _lines_for_rag(lines)
    _report(on_progress, 12, f"Preparing {len(rag_lines)} lines for RAG", should_cancel=should_cancel)
    chunks = _chunks_for_rag(rag_lines)
    if not chunks:
        return _direct(path, [], f"Empty file: {path.name}", "rag-empty", on_progress, should_cancel)

    model = resolve_embed_model()
    texts = [text for _, text in chunks]
    logger.info(
        "RAG %s: %d bytes, %d lines, %d chunks, embed model %s",
        path.name,
        size,
        len(rag_lines),
        len(chunks),
        model,
    )

    _report(on_progress, 18, f"Embedding {len(chunks)} chunks", should_cancel=should_cancel)

    def embed_progress(done: int, total: int) -> None:
        pct = 18 + int(52 * done / max(total, 1))
        _report(on_progress, pct, f"Embedding chunks {done}/{total}", should_cancel=should_cancel)

    embeddings = embed_texts(texts, on_progress=embed_progress)
    _report(on_progress, 72, "Indexing embeddings", should_cancel=should_cancel)
    store = ChromaStore()
    store.ingest_chunks(path, chunks, embeddings)

    _report(on_progress, 78, "Retrieving relevant log segments", should_cancel=should_cancel)
    query_emb = embed_texts([config.RAG_QUERY])[0]
    hits = store.query(path, query_emb, config.RAG_TOP_K)
    retrieved_lines: list[str] = []
    for hit in hits:
        retrieved_lines.extend(hit["text"].splitlines())

    note = (
        f"RAG from {path.name} ({size} bytes, {len(chunks)} chunks embedded, "
        f"{len(hits)} retrieved). Query: {config.RAG_QUERY}"
    )
    return _direct(path, retrieved_lines, note, "rag", on_progress, should_cancel)


def analyze_file(
    path: Path,
    on_progress: ProgressFn | None = None,
    should_cancel: CancelFn | None = None,
    *,
    window: str | None = None,
) -> tuple[dict, str, str]:
    """Returns (parsed_result, raw_response, mode_used).

    window: when set (e.g. 1h, 24h, all), analyze only that UI time range instead of the full file.
    """
    t0 = time.perf_counter()
    file_meta = {"file": str(path)}
    if window is not None:
        file_meta["window"] = window
    try:
        return _analyze_file_inner(path, on_progress, file_meta, should_cancel, window=window)
    except Exception as e:
        ms = (time.perf_counter() - t0) * 1000
        llm_audit.log_fail(
            op="analyze_file",
            model="",
            duration_ms=ms,
            error=str(e),
            meta=file_meta,
        )
        raise


def _analyze_file_inner(
    path: Path,
    on_progress: ProgressFn | None,
    file_meta: dict,
    should_cancel: CancelFn | None = None,
    *,
    window: str | None = None,
) -> tuple[dict, str, str]:
    t0 = time.perf_counter()
    _report(on_progress, 5, "Reading log file", should_cancel=should_cancel)
    if window is not None:
        lines, scope_note = read_log_file_window(path, window)
        size = _lines_byte_size(lines)
        direct_mode = "direct-window"
    else:
        lines = read_log_file(path)
        size = path.stat().st_size
        scope_note = f"Full file: {path.name}"
        direct_mode = "direct"
    file_meta["bytes"] = size
    file_meta["lines"] = len(lines)
    _report(on_progress, 10, f"Loaded {len(lines)} lines", should_cancel=should_cancel)

    if size <= config.LLM_DIRECT_MAX_BYTES:
        parsed, raw, mode = _direct(
            path, lines, scope_note, direct_mode, on_progress, should_cancel
        )
        ms = (time.perf_counter() - t0) * 1000
        llm_audit.log_ok(
            op="analyze_file",
            duration_ms=ms,
            meta={**file_meta, "mode": mode},
            response_note=f"severity={parsed.get('severity', '?')}",
        )
        return parsed, raw, mode

    if not embeddings_available():
        if llm_provider() == "openai":
            hint = (
                f"Configure LLM_EMBED_MODEL or ensure your API supports embeddings"
            )
        else:
            hint = (
                f"Ensure Ollama is running at {config.OLLAMA_BASE_URL} and run: "
                f"ollama pull {config.OLLAMA_EMBED_MODEL}"
            )
        raise RuntimeError(
            f"File {path.name} ({size} bytes) requires RAG but embed model "
            f"{config.OLLAMA_EMBED_MODEL!r} is not available. {hint}"
        )

    parsed, raw, mode = _rag_analyze(path, lines, size, on_progress, should_cancel)
    ms = (time.perf_counter() - t0) * 1000
    llm_audit.log_ok(
        op="analyze_file",
        duration_ms=ms,
        meta={**file_meta, "mode": mode},
        response_note=f"severity={parsed.get('severity', '?')}",
    )
    return parsed, raw, mode


def analyze_source(
    source: str | Path,
    on_progress: ProgressFn | None = None,
    should_cancel: CancelFn | None = None,
    *,
    window: str | None = None,
) -> tuple[dict, str, str]:
    """Analyze a file path or journal:// URI. Journal sources require window mode."""
    if isinstance(source, str) and is_journal_source(source):
        if window is None:
            raise ValueError("Journal analysis requires a time window (scope=window)")
        return _analyze_journal_inner(source, on_progress, should_cancel, window=window)
    return analyze_file(Path(source), on_progress=on_progress, should_cancel=should_cancel, window=window)


def _analyze_journal_inner(
    uri: str,
    on_progress: ProgressFn | None,
    should_cancel: CancelFn | None,
    *,
    window: str,
) -> tuple[dict, str, str]:
    t0 = time.perf_counter()
    file_meta = {"source": uri, "window": window}
    _report(on_progress, 5, "Reading journal window", should_cancel=should_cancel)
    lines, scope_note = read_journal_window(uri, window)
    filtered = _filter_for_llm(Path(uri), lines)
    size = _lines_byte_size(filtered)
    file_meta["bytes"] = size
    file_meta["lines"] = len(filtered)
    _report(on_progress, 10, f"Loaded {len(filtered)} lines", should_cancel=should_cancel)
    parsed, raw, mode = _direct(
        Path(uri), filtered, scope_note, "direct-journal-window", on_progress, should_cancel
    )
    ms = (time.perf_counter() - t0) * 1000
    llm_audit.log_ok(
        op="analyze_journal",
        duration_ms=ms,
        meta={**file_meta, "mode": mode},
        response_note=f"severity={parsed.get('severity', '?')}",
    )
    return parsed, raw, mode
