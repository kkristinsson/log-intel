from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import requests

from log_intel.syslogb.app import config
from log_intel.syslogb.app import llm_audit

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "Linux/rsyslog file triage. Flag errors, auth failures, resource issues, crashes, "
    "denials, timeouts, and unusual patterns; skip routine info unless clearly anomalous.\n"
    "Reply with ONE JSON object only (no markdown, no text outside JSON). Schema:\n"
    '{"severity":"info|low|medium|high|critical","summary":"<string>","anomalies":['
    '{"title":"<string>","detail":"<string>","related_log_indexes":[<ints>]}]}\n'
    "Hard caps: summary ≤220 chars; ≤4 anomalies; each title ≤56 chars; "
    "each detail ≤130 chars. related_log_indexes uses i from lines formatted as i|<log>.\n"
    "If nothing actionable: severity info, summary ≤120 chars, anomalies []."
)

_cached_ollama_chat_model: str | None = None
_cached_ollama_chat_at: float = 0.0
_cached_ollama_embed_model: str | None = None
_cached_ollama_embed_at: float = 0.0
_CACHE_TTL = 60.0


def llm_provider() -> str:
    return (config.LLM_PROVIDER or "ollama").lower()


def uses_remote_chat() -> bool:
    return llm_provider() in ("openai", "hybrid")


def uses_ollama_embed() -> bool:
    return llm_provider() in ("ollama", "hybrid")


def is_openai_provider() -> bool:
    """True when chat uses the OpenAI-compatible HTTP API (openai or hybrid)."""
    return uses_remote_chat()


def llm_enabled() -> bool:
    return bool(config.LLM_ENABLED)


def chat_base_url() -> str:
    if uses_remote_chat():
        return (config.LLM_API_BASE_URL or "https://api.openai.com/v1").rstrip("/")
    return config.OLLAMA_BASE_URL


def chat_model_name() -> str:
    return config.LLM_CHAT_MODEL or config.OLLAMA_MODEL


def embed_model_name() -> str:
    if uses_ollama_embed():
        return config.OLLAMA_EMBED_MODEL
    return config.LLM_EMBED_MODEL or config.OLLAMA_EMBED_MODEL


def _auth_headers() -> dict[str, str]:
    if uses_remote_chat() and config.LLM_API_KEY:
        return {"Authorization": f"Bearer {config.LLM_API_KEY}"}
    return {}


def _ollama_listed_models() -> list[str]:
    r = requests.get(f"{config.OLLAMA_BASE_URL}/api/tags", timeout=10)
    r.raise_for_status()
    return [m.get("name", "") for m in r.json().get("models", [])]


def _resolve_ollama_model(target: str, kind: str) -> str | None:
    global _cached_ollama_chat_model, _cached_ollama_chat_at
    global _cached_ollama_embed_model, _cached_ollama_embed_at
    now = time.time()
    if kind == "chat":
        if _cached_ollama_chat_model and (now - _cached_ollama_chat_at) < _CACHE_TTL:
            return _cached_ollama_chat_model
    elif _cached_ollama_embed_model and (now - _cached_ollama_embed_at) < _CACHE_TTL:
        return _cached_ollama_embed_model

    base = target.split(":", 1)[0] if ":" in target else target
    try:
        names = _ollama_listed_models()
    except Exception as e:
        logger.warning("Cannot list Ollama models: %s", e)
        return None

    resolved = None
    for n in names:
        if n == target:
            resolved = n
            break
    if not resolved:
        for n in names:
            if n.split(":", 1)[0] == base or n.startswith(base + ":"):
                resolved = n
                break

    if resolved:
        if kind == "chat":
            _cached_ollama_chat_model = resolved
            _cached_ollama_chat_at = now
        else:
            _cached_ollama_embed_model = resolved
            _cached_ollama_embed_at = now
    return resolved


def resolve_chat_model() -> str | None:
    if uses_remote_chat():
        return chat_model_name() if config.LLM_API_KEY else None
    return _resolve_ollama_model(chat_model_name(), "chat")


def resolve_embed_model() -> str | None:
    if uses_ollama_embed():
        return _resolve_ollama_model(embed_model_name(), "embed")
    return embed_model_name() if config.LLM_API_KEY else None


def embeddings_available() -> bool:
    return resolve_embed_model() is not None


def _trim_line(s: str) -> str:
    m = config.LOG_LINE_MAX_CHARS
    if m <= 0 or len(s) <= m:
        return s
    return s[: m - 1] + "…"


def _iter_balanced_json_objects(text: str):
    """Yield complete {...} substrings (brace-balanced, string-aware)."""
    i = 0
    n = len(text)
    while i < n:
        start = text.find("{", i)
        if start < 0:
            return
        depth = 0
        in_str = False
        esc = False
        for j in range(start, n):
            ch = text[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    yield text[start : j + 1]
                    i = j + 1
                    break
        else:
            return


def _json_dict_candidates(text: str) -> list[str]:
    """Ordered list of dict-shaped JSON substrings to try (prefer last / fenced)."""
    if not text:
        return []
    stripped = text.strip()
    candidates: list[str] = []
    for m in re.finditer(r"```(?:json)?\s*([\s\S]*?)\s*```", stripped, re.IGNORECASE):
        block = m.group(1).strip()
        if block:
            candidates.append(block)
    candidates.extend(_iter_balanced_json_objects(stripped))
    if stripped.startswith("{") and stripped not in candidates:
        candidates.append(stripped)
    # De-dupe while preserving order; try later objects first (model often answers last).
    seen: set[str] = set()
    ordered: list[str] = []
    for c in reversed(candidates):
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


def _parse_json_dict(text: str) -> dict[str, Any] | None:
    for candidate in _json_dict_candidates(text):
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


def _extract_json_object(text: str) -> dict[str, Any]:
    parsed = _parse_json_dict(text)
    if parsed is not None:
        return parsed
    return {
        "severity": "low",
        "summary": "Model returned non-JSON; inspect raw response.",
        "anomalies": [],
    }


def _clamp_output(parsed: dict[str, Any]) -> dict[str, Any]:
    sev = str(parsed.get("severity", "info")).lower()
    if sev not in ("info", "low", "medium", "high", "critical"):
        sev = "low"
    summary = str(parsed.get("summary", "")).strip() or "(no summary)"
    summary = summary[:220]
    raw_items = parsed.get("anomalies") or []
    if not isinstance(raw_items, list):
        raw_items = []
    norm: list[dict[str, Any]] = []
    for item in raw_items[:4]:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "Note")).strip()[:56]
        detail = str(item.get("detail", "")).strip()[:130]
        idx = item.get("related_log_indexes") or []
        idx_list: list[int] = []
        if isinstance(idx, list):
            for x in idx:
                if isinstance(x, bool):
                    continue
                if isinstance(x, int):
                    idx_list.append(x)
                elif isinstance(x, float):
                    idx_list.append(int(x))
                elif isinstance(x, str) and x.removeprefix("-").isdigit():
                    idx_list.append(int(x))
        norm.append({"title": title or "Note", "detail": detail, "related_log_indexes": idx_list})
    return {"severity": sev, "summary": summary, "anomalies": norm}


def _api_error(resp: requests.Response, provider: str) -> str:
    try:
        data = resp.json()
        if isinstance(data.get("error"), dict):
            return str(data["error"].get("message", data["error"]))
        if isinstance(data.get("error"), str):
            return data["error"]
        return resp.text[:300]
    except Exception:
        return resp.text[:300]


def _raise_for_llm(resp: requests.Response) -> None:
    if resp.ok:
        return
    provider = "OpenAI-compatible API" if uses_remote_chat() else "Ollama"
    err = _api_error(resp, provider)
    if resp.status_code in (401, 403):
        raise RuntimeError(f"{provider}: authentication failed ({err})") from None
    if resp.status_code == 404 and err:
        raise RuntimeError(f"{provider}: {err}") from None
    raise RuntimeError(f"{provider}: HTTP {resp.status_code} {err}") from None


def _messages_audit_body(messages: list[dict[str, str]]) -> str:
    parts: list[str] = []
    for msg in messages:
        role = msg.get("role", "?")
        content = msg.get("content") or ""
        parts.append(f"[{role}]\n{content}")
    return "\n\n".join(parts)


def _chat_openai(messages: list[dict[str, str]]) -> str:
    model = resolve_chat_model()
    if not model:
        raise RuntimeError(
            "LLM_API_KEY and LLM_CHAT_MODEL are required for openai/hybrid provider"
        )
    url = f"{chat_base_url()}/chat/completions"
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "top_p": 0.9,
        "max_tokens": max(64, config.OLLAMA_NUM_PREDICT),
    }
    if config.OLLAMA_JSON_FORMAT:
        payload["response_format"] = {"type": "json_object"}
    resp = requests.post(
        url,
        json=payload,
        headers=_auth_headers(),
        timeout=config.OLLAMA_TIMEOUT_SEC,
    )
    _raise_for_llm(resp)
    data = resp.json()
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("OpenAI-compatible API returned no choices")
    msg = choices[0].get("message") or {}
    return (msg.get("content") or "").strip(), model, url


def _ollama_assistant_text(data: dict[str, Any]) -> str:
    """Best text for JSON parsing from Ollama /api/chat (content and/or thinking)."""
    msg = data.get("message") or {}
    content = (msg.get("content") or "").strip()
    thinking = (msg.get("thinking") or "").strip()
    for blob in (content, thinking, f"{content}\n{thinking}".strip()):
        if not blob:
            continue
        for candidate in _json_dict_candidates(blob):
            try:
                obj = json.loads(candidate)
                if isinstance(obj, dict):
                    return candidate
            except json.JSONDecodeError:
                continue
    if content:
        return content
    return thinking


def _chat_ollama(messages: list[dict[str, str]]) -> tuple[str, str, str]:
    model = resolve_chat_model()
    if not model:
        try:
            names = _ollama_listed_models()
        except Exception as e:
            names = []
        raise RuntimeError(
            f"Chat model {chat_model_name()!r} not found in Ollama. "
            f"Installed: {', '.join(names) or 'none'}. "
            f"Set OLLAMA_MODEL in .env or run: ollama pull {chat_model_name()}"
        ) from e

    url = f"{config.OLLAMA_BASE_URL}/api/chat"
    # Thinking models (qwen3) burn tokens on prose; need headroom when JSON mode is off.
    num_predict = max(2048, config.OLLAMA_NUM_PREDICT) if not config.OLLAMA_JSON_FORMAT else max(
        64, config.OLLAMA_NUM_PREDICT
    )
    payload: dict[str, Any] = {
        "model": model,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": num_predict,
        },
        "messages": messages,
    }
    if config.OLLAMA_JSON_FORMAT:
        payload["format"] = "json"
    else:
        # Ask Ollama to skip chain-of-thought; syslogb prompts already demand JSON only.
        payload["think"] = False
    resp = requests.post(url, json=payload, timeout=config.OLLAMA_TIMEOUT_SEC)
    _raise_for_llm(resp)
    data = resp.json()
    text = _ollama_assistant_text(data)
    if not text:
        raise RuntimeError(
            "Ollama returned an empty response. If using qwen3.x, set "
            "OLLAMA_JSON_FORMAT=0 in Settings, or try a smaller chat model."
        )
    return text, model, url


def chat_completion(
    messages: list[dict[str, str]],
    *,
    operation: str = "chat",
    meta: dict[str, Any] | None = None,
) -> str:
    t0 = time.perf_counter()
    req_note = llm_audit._summarize_messages(messages)
    req_body = _messages_audit_body(messages)
    model = ""
    endpoint = ""
    try:
        if uses_remote_chat():
            content, model, endpoint = _chat_openai(messages)
        else:
            content, model, endpoint = _chat_ollama(messages)
        ms = (time.perf_counter() - t0) * 1000
        llm_audit.log_ok(
            op=operation,
            model=model,
            endpoint=endpoint,
            duration_ms=ms,
            meta=meta,
            request_note=req_note,
            response_note=f"chars={len(content)}",
            request_body=req_body,
            response_body=content,
        )
        return content
    except Exception as e:
        ms = (time.perf_counter() - t0) * 1000
        llm_audit.log_fail(
            op=operation,
            model=model or chat_model_name(),
            endpoint=endpoint or chat_base_url(),
            duration_ms=ms,
            error=str(e),
            meta=meta,
            request_note=req_note,
            request_body=req_body,
        )
        raise


ENTRY_EXPLAIN_PROMPT = (
    "You are a Linux/syslog expert helping operators understand individual log lines. "
    "Reply with ONE JSON object only (no markdown outside JSON). Schema:\n"
    '{"severity":"info|low|medium|high|critical","summary":"<one short sentence>",'
    '"explanation":"<clear plain-language explanation of what happened and why>",'
    '"actions":["<optional short follow-up steps>"]}\n'
    "Keep summary ≤160 chars and explanation ≤800 chars. actions may be empty."
)


def _clamp_explain_output(parsed: dict[str, Any]) -> dict[str, Any]:
    sev = str(parsed.get("severity", "info")).lower()
    if sev not in ("info", "low", "medium", "high", "critical"):
        sev = "info"
    summary = str(parsed.get("summary", "")).strip()[:160] or "Log entry explanation"
    explanation = str(parsed.get("explanation", "")).strip()[:800] or str(
        parsed.get("summary", "")
    ).strip()[:800]
    actions_raw = parsed.get("actions") or []
    actions: list[str] = []
    if isinstance(actions_raw, list):
        for item in actions_raw[:4]:
            text = str(item).strip()
            if text:
                actions.append(text[:120])
    return {
        "severity": sev,
        "summary": summary,
        "explanation": explanation,
        "actions": actions,
    }


def explain_log_entry(
    line: str,
    *,
    question: str = "",
    source: str = "",
) -> tuple[dict[str, Any], str]:
    line = _trim_line(line.strip())
    if not line:
        raise ValueError("line required")

    user_question = question.strip() or (
        "Explain this log entry. What does it mean, what likely caused it, "
        "and should I be concerned?"
    )
    source_note = f"Source file: {source}\n" if source else ""
    user_content = (
        f"{source_note}"
        f"Log line:\n{line}\n\n"
        f"Operator question:\n{user_question}"
    )
    messages = [
        {"role": "system", "content": ENTRY_EXPLAIN_PROMPT},
        {"role": "user", "content": user_content},
    ]
    raw = chat_completion(
        messages,
        operation="explain",
        meta={"source": source} if source else None,
    )
    parsed = _extract_json_object(raw or "{}")
    return _clamp_explain_output(parsed), raw


def analyze_lines(log_lines: list[str], context_note: str = "") -> tuple[dict[str, Any], str]:
    trimmed = [_trim_line(x) for x in log_lines]
    n = len(trimmed)
    prefix = f"{context_note}\n" if context_note else ""
    body = "\n".join(f"{i}|{line}" for i, line in enumerate(trimmed))
    user_content = f"{prefix}{n} lines. JSON only.\n{body}"
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]
    note = context_note.strip()[:200] if context_note else ""
    raw = chat_completion(
        messages,
        operation="analyze",
        meta={"lines": n, "context": note} if note else {"lines": n},
    )
    parsed = _extract_json_object(raw or "{}")
    return _clamp_output(parsed), raw


def _embed_openai_post(texts: list[str], *, meta: dict[str, Any] | None = None) -> list[list[float]]:
    """Single embeddings API request (caller enforces token budgets)."""
    model = resolve_embed_model()
    if not model:
        raise RuntimeError("LLM_API_KEY and LLM_EMBED_MODEL are required for openai embeddings")
    url = f"{chat_base_url()}/embeddings"
    payload = {
        "model": model,
        "input": texts,
    }
    t0 = time.perf_counter()
    total_chars = sum(len(t) for t in texts)
    batch_meta = {"count": len(texts), "total_chars": total_chars, **(meta or {})}
    try:
        resp = requests.post(
            url,
            json=payload,
            headers=_auth_headers(),
            timeout=config.OLLAMA_EMBED_TIMEOUT_SEC,
        )
        _raise_for_llm(resp)
        data = resp.json()
        rows = data.get("data") or []
        if len(rows) != len(texts):
            raise ValueError(f"Unexpected embeddings response: {len(rows)} vs {len(texts)}")
        rows.sort(key=lambda r: r.get("index", 0))
        out: list[list[float]] = []
        for row in rows:
            emb = row.get("embedding")
            if not isinstance(emb, list):
                raise ValueError("Embedding row missing vector")
            out.append(emb)
        ms = (time.perf_counter() - t0) * 1000
        dims = len(out[0]) if out else 0
        llm_audit.log_ok(
            op="embed",
            model=model,
            endpoint=url,
            duration_ms=ms,
            meta=batch_meta,
            request_note=f"texts={len(texts)} chars={total_chars}",
            response_note=f"vectors={len(out)} dims={dims}",
        )
        return out
    except Exception as e:
        ms = (time.perf_counter() - t0) * 1000
        llm_audit.log_fail(
            op="embed",
            model=model or embed_model_name(),
            endpoint=url,
            duration_ms=ms,
            error=str(e),
            meta=batch_meta,
            request_note=f"texts={len(texts)} chars={total_chars}",
        )
        raise


def _embed_openai_request_adaptive(
    texts: list[str],
    *,
    meta: dict[str, Any] | None = None,
) -> list[list[float]]:
    if not texts:
        return []
    from log_intel.syslogb.app.embed_limits import is_embed_token_limit_error, truncate_to_tokens, estimate_tokens

    try:
        return _embed_openai_post(texts, meta=meta)
    except Exception as e:
        if not is_embed_token_limit_error(e):
            raise
        if len(texts) == 1:
            last_err = e
            for factor in (3, 4):
                shorter = truncate_to_tokens(texts[0], max(16, estimate_tokens(texts[0]) // factor))
                if shorter == texts[0]:
                    continue
                try:
                    return _embed_openai_post([shorter], meta=meta)
                except Exception as e2:
                    last_err = e2
                    if not is_embed_token_limit_error(e2):
                        raise
            raise last_err
        mid = len(texts) // 2
        return _embed_openai_request_adaptive(
            texts[:mid], meta=meta
        ) + _embed_openai_request_adaptive(texts[mid:], meta=meta)


def embed_texts_openai(
    texts: list[str],
    max_chars: int,
    *,
    meta: dict[str, Any] | None = None,
) -> list[list[float]]:
    from log_intel.syslogb.app.embed_limits import pack_embed_texts_for_request, prepare_embed_texts

    if not texts:
        return []
    prepared = prepare_embed_texts(texts, max_chars)
    sub_batches = pack_embed_texts_for_request(prepared)
    out: list[list[float]] = []
    for sub in sub_batches:
        out.extend(_embed_openai_request_adaptive(sub, meta=meta))
    if len(out) != len(prepared):
        raise ValueError(f"Embedding count mismatch: {len(out)} vs {len(prepared)}")
    return out


def _check_remote_chat() -> tuple[bool, str]:
    if not config.LLM_API_KEY:
        return False, "LLM_API_KEY is not set"
    chat = chat_model_name()
    base = chat_base_url()
    try:
        resp = requests.get(
            f"{base}/models",
            headers=_auth_headers(),
            timeout=10,
        )
        if resp.ok:
            return True, f"chat OK ({base}); chat={chat}"
    except Exception as e:
        logger.debug("OpenAI models list failed: %s", e)
    return True, f"chat configured ({base}); chat={chat}"


def _check_ollama_embed() -> tuple[bool, str]:
    try:
        names = _ollama_listed_models()
    except Exception as e:
        return False, f"Ollama embed unreachable at {config.OLLAMA_BASE_URL}: {e}"
    embed_target = embed_model_name()
    embed_base = embed_target.split(":", 1)[0] if ":" in embed_target else embed_target
    embed_ok = any(
        n == embed_target or n.startswith(embed_base + ":") for n in names
    )
    if embed_ok:
        return True, f"embed={embed_target} @ {config.OLLAMA_BASE_URL}"
    return (
        False,
        f"embed={embed_target} missing at {config.OLLAMA_BASE_URL} "
        f"(have: {', '.join(names) or 'none'}; "
        f"run: ollama pull {embed_target})",
    )


def health_check() -> tuple[bool, str]:
    if not llm_enabled():
        return False, "LLM disabled in settings"

    provider = llm_provider()

    if provider == "hybrid":
        chat_ok, chat_msg = _check_remote_chat()
        embed_ok, embed_msg = _check_ollama_embed()
        parts = [chat_msg, embed_msg]
        ok = chat_ok and embed_ok
        prefix = "Hybrid OK; " if ok else "Hybrid issue; "
        return ok, prefix + "; ".join(parts)

    if provider == "openai":
        if not config.LLM_API_KEY:
            return False, "LLM provider=openai but LLM_API_KEY is not set"
        chat_ok, chat_msg = _check_remote_chat()
        embed = embed_model_name()
        return chat_ok, f"{chat_msg}, embed={embed}"

    try:
        names = _ollama_listed_models()
        chat = resolve_chat_model()
        embed_target = embed_model_name()
        embed_base = embed_target.split(":", 1)[0] if ":" in embed_target else embed_target
        embed_ok = any(
            n == embed_target or n.startswith(embed_base + ":") for n in names
        )
        parts = []
        if chat:
            parts.append(f"chat={chat}")
        else:
            parts.append(
                f"chat={chat_model_name()} missing "
                f"(have: {', '.join(names) or 'none'})"
            )
        if embed_ok:
            parts.append(f"embed={embed_target}")
        else:
            parts.append(f"embed={embed_target} missing")
        ok = bool(chat) and embed_ok
        return ok, ("Ollama OK; " if ok else "Ollama issue; ") + ", ".join(parts)
    except Exception as e:
        return False, str(e)
