from __future__ import annotations

import logging
import time
from typing import Any, Callable

import requests

from log_intel.syslogb.app import config
from log_intel.syslogb.app import llm_audit
from log_intel.syslogb.app.llm_client import (
    embed_model_name,
    embed_texts_openai,
    embeddings_available,
    llm_provider,
    resolve_embed_model,
    uses_ollama_embed,
)

logger = logging.getLogger(__name__)

__all__ = ["embed_texts", "embeddings_available", "resolve_embed_model"]


def sanitize_embed_text(text: str, max_chars: int | None = None) -> str:
    limit = max_chars if max_chars is not None else config.EMBED_MAX_CHARS
    text = text.replace("\x00", "").strip()
    if not text:
        return " "
    if limit > 0 and len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _ollama_error(resp: requests.Response) -> str:
    try:
        return str(resp.json().get("error", resp.text[:300]))
    except Exception:
        return resp.text[:300]


def _embed_batch_api(model: str, texts: list[str], max_chars: int) -> list[list[float]]:
    url = f"{config.OLLAMA_BASE_URL}/api/embed"
    cleaned = [sanitize_embed_text(t, max_chars) for t in texts]
    payload: dict[str, Any] = {
        "model": model,
        "input": cleaned,
    }
    t0 = time.perf_counter()
    total_chars = sum(len(t) for t in cleaned)
    try:
        resp = requests.post(url, json=payload, timeout=config.OLLAMA_EMBED_TIMEOUT_SEC)
        if not resp.ok:
            raise requests.HTTPError(
                f"{resp.status_code} {_ollama_error(resp)}",
                response=resp,
            )
        data = resp.json()
        embs = data.get("embeddings")
        if isinstance(embs, list) and len(embs) == len(texts):
            ms = (time.perf_counter() - t0) * 1000
            dims = len(embs[0]) if embs else 0
            llm_audit.log_ok(
                op="embed",
                model=model,
                endpoint=url,
                duration_ms=ms,
                meta={"count": len(texts), "total_chars": total_chars},
                request_note=f"texts={len(texts)} chars={total_chars}",
                response_note=f"vectors={len(embs)} dims={dims}",
            )
            return embs
        raise ValueError(f"Unexpected /api/embed response: {list(data.keys())}")
    except Exception as e:
        ms = (time.perf_counter() - t0) * 1000
        llm_audit.log_fail(
            op="embed",
            model=model,
            endpoint=url,
            duration_ms=ms,
            error=str(e),
            meta={"count": len(texts), "total_chars": total_chars},
            request_note=f"texts={len(texts)} chars={total_chars}",
        )
        raise


def _embed_legacy_one(model: str, text: str, max_chars: int) -> list[float]:
    url = f"{config.OLLAMA_BASE_URL}/api/embeddings"
    payload: dict[str, Any] = {
        "model": model,
        "prompt": sanitize_embed_text(text, max_chars),
    }
    resp = requests.post(url, json=payload, timeout=config.OLLAMA_EMBED_TIMEOUT_SEC)
    if not resp.ok:
        raise requests.HTTPError(
            f"{resp.status_code} {_ollama_error(resp)}",
            response=resp,
        )
    data = resp.json()
    emb = data.get("embedding")
    if not isinstance(emb, list):
        raise ValueError("Ollama /api/embeddings response missing embedding vector")
    return emb


def _embed_one(model: str, text: str, max_chars: int) -> list[float]:
    last_err: Exception | None = None
    for shrink in (max_chars, max_chars // 2, max_chars // 4, 1024):
        if shrink < 256:
            break
        try:
            return _embed_batch_api(model, [text], shrink)[0]
        except Exception as e:
            last_err = e
            logger.debug("embed batch single failed at %d chars: %s", shrink, e)
        try:
            return _embed_legacy_one(model, text, shrink)
        except Exception as e:
            last_err = e
            logger.debug("embed legacy single failed at %d chars: %s", shrink, e)
    raise RuntimeError(f"Cannot embed text ({len(text)} chars): {last_err}") from last_err


def _embed_batch_adaptive(
    model: str,
    texts: list[str],
    max_chars: int,
) -> list[list[float]]:
    if not texts:
        return []
    if len(texts) == 1:
        return [_embed_one(model, texts[0], max_chars)]

    try:
        return _embed_batch_api(model, texts, max_chars)
    except Exception as batch_err:
        logger.debug(
            "Batch embed failed (%d texts): %s — splitting",
            len(texts),
            batch_err,
        )
        mid = len(texts) // 2
        left = _embed_batch_adaptive(model, texts[:mid], max_chars)
        right = _embed_batch_adaptive(model, texts[mid:], max_chars)
        return left + right


def _embed_batch_provider(batch: list[str], max_chars: int) -> list[list[float]]:
    if not uses_ollama_embed():
        cleaned = [sanitize_embed_text(t, max_chars) for t in batch]
        return embed_texts_openai(cleaned, max_chars)
    model = resolve_embed_model()
    if not model:
        raise RuntimeError(
            f"Embed model {embed_model_name()!r} not found in Ollama at "
            f"{config.OLLAMA_BASE_URL}. Run: ollama pull {embed_model_name()}"
        )
    return _embed_batch_adaptive(model, batch, max_chars)


def embed_texts(
    texts: list[str],
    on_progress: Callable[[int, int], None] | None = None,
) -> list[list[float]]:
    if not texts:
        return []

    if not resolve_embed_model():
        if llm_provider() == "openai":
            raise RuntimeError(
                "LLM_API_KEY and LLM_EMBED_MODEL are required for openai embeddings"
            )
        raise RuntimeError(
            f"Embed model {embed_model_name()!r} not found in Ollama at "
            f"{config.OLLAMA_BASE_URL}. Run: ollama pull {embed_model_name()}"
        )

    max_chars = config.EMBED_MAX_CHARS
    batch_size = max(1, config.EMBED_BATCH_SIZE)
    out: list[list[float]] = []
    total = len(texts)

    for i in range(0, total, batch_size):
        batch = texts[i : i + batch_size]
        last_err: Exception | None = None
        for attempt in range(1, config.EMBED_MAX_RETRIES + 1):
            try:
                embs = _embed_batch_provider(batch, max_chars)
                out.extend(embs)
                last_err = None
                done = i + len(batch)
                if on_progress:
                    on_progress(done, total)
                if done % 100 == 0 or done == total:
                    logger.info("Embedded %d/%d chunks", done, total)
                break
            except Exception as e:
                last_err = e
                logger.warning(
                    "Embed progress %d-%d attempt %d/%d: %s",
                    i,
                    i + len(batch),
                    attempt,
                    config.EMBED_MAX_RETRIES,
                    e,
                )
                time.sleep(min(2 ** attempt, 10))
        if last_err is not None:
            llm_audit.log_fail(
                op="embed",
                model=embed_model_name(),
                endpoint=config.OLLAMA_BASE_URL + "/api/embed",
                error=str(last_err),
                meta={
                    "chunk_from": i,
                    "chunk_to": i + len(batch),
                    "attempts": config.EMBED_MAX_RETRIES,
                },
            )
            raise RuntimeError(
                f"Embedding failed at chunk {i}-{i + len(batch)} "
                f"after {config.EMBED_MAX_RETRIES} attempts: {last_err}"
            ) from last_err

    return out
