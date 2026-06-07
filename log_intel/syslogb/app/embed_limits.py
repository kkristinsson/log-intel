"""Token/character limits for remote embedding APIs (e.g. Berget multilingual-e5 512 tokens)."""

from __future__ import annotations

from log_intel.syslogb.app import config


def estimate_tokens(text: str) -> int:
    """Conservative token estimate for log text (~4 chars per token)."""
    return max(1, (len(text) + 3) // 4)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    if max_tokens <= 0 or not text:
        return text or " "
    max_chars = max(16, max_tokens * 4)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1] + "…"


def embed_max_tokens_per_input() -> int:
    return max(0, int(config.EMBED_MAX_TOKENS_PER_INPUT))


def embed_max_tokens_per_request() -> int:
    return max(0, int(config.EMBED_MAX_TOKENS_PER_REQUEST))


def is_embed_token_limit_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    if "maximum context length" in msg:
        return True
    if "embed" in msg and "token" in msg:
        return True
    if "too many tokens" in msg or "token limit" in msg:
        return True
    return False


def prepare_embed_texts(texts: list[str], max_chars: int) -> list[str]:
    """Sanitize and apply per-input token cap before packing into API requests."""
    per_input = embed_max_tokens_per_input()
    out: list[str] = []
    for raw in texts:
        t = (raw or "").replace("\x00", "").strip() or " "
        if max_chars > 0 and len(t) > max_chars:
            t = t[: max_chars - 1] + "…"
        if per_input > 0:
            t = truncate_to_tokens(t, per_input)
        out.append(t)
    return out


def pack_embed_texts_for_request(
    texts: list[str],
    *,
    max_tokens_per_input: int | None = None,
    max_tokens_per_request: int | None = None,
) -> list[list[str]]:
    """
    Split texts into API sub-batches so each request stays within token budgets.
    When max_tokens_per_request is 0, returns one batch per text (safest for strict APIs).
    """
    if not texts:
        return []

    per_in = embed_max_tokens_per_input() if max_tokens_per_input is None else max_tokens_per_input
    per_req = embed_max_tokens_per_request() if max_tokens_per_request is None else max_tokens_per_request

    prepared = []
    for t in texts:
        pt = t
        if per_in > 0:
            pt = truncate_to_tokens(pt, per_in)
        prepared.append(pt)

    if per_req <= 0:
        return [prepared]

    batches: list[list[str]] = []
    current: list[str] = []
    current_tokens = 0

    for t in prepared:
        t_tokens = estimate_tokens(t)
        if t_tokens > per_req:
            if current:
                batches.append(current)
                current = []
                current_tokens = 0
            batches.append([t])
            continue
        if current and current_tokens + t_tokens > per_req:
            batches.append(current)
            current = []
            current_tokens = 0
        current.append(t)
        current_tokens += t_tokens

    if current:
        batches.append(current)
    return batches
