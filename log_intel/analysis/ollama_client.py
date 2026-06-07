"""Hub-owned Ollama client (adapted from loggy patterns)."""

from __future__ import annotations

import json
import re
from typing import Any

import requests

from log_intel import hub_config as hub_cfg
from log_intel.config import get_settings

SYSTEM_PROMPT = (
    "Unified log triage for syslog from firewalls, Windows hosts, and generic sources. "
    "Flag threats, auth failures, denies, anomalies, and cross-source patterns.\n"
    "Reply with ONE JSON object only. Schema:\n"
    '{"severity":"info|low|medium|high|critical","summary":"<string>","anomalies":['
    '{"title":"<string>","detail":"<string>","related_log_indexes":[<ints>]}]}\n'
    "Caps: summary ≤220 chars; ≤4 anomalies; each title ≤56 chars; each detail ≤130 chars."
)

META_SYSTEM_PROMPT = (
    "You are log-intel's meta-analyst reviewing many syslog Ollama verdicts over a time window. "
    "Anomalies here mean cross-batch patterns: drift, clusters, recurring themes, calibration issues, or "
    "things no single batch could see. Do not invent incidents not supported by the snippets.\n"
    "Reply with ONE JSON object only (no markdown). Schema:\n"
    '{"headline":"<string>","summary":"<string>","findings":['
    '{"title":"<string>","detail":"<string>"}],'
    '"confidence":"low|medium|high"}\n'
    "Caps: headline ≤100 chars; summary ≤420 chars; ≤10 findings; each title ≤70 chars; each detail ≤200 chars. "
    "If evidence is thin, use confidence low and say so in summary."
)


def _trim_line(s: str, max_chars: int) -> str:
    if max_chars <= 0 or len(s) <= max_chars:
        return s
    return s[: max_chars - 1] + "…"


def _read_model_text(data: dict[str, Any]) -> tuple[str, str]:
    msg = data.get("message") or {}
    content = (msg.get("content") or "").strip()
    thinking = (msg.get("thinking") or "").strip()
    if content:
        if thinking:
            raw = f"--- thinking ---\n{thinking}\n\n--- content ---\n{content}"
        else:
            raw = content
        return content, raw
    return "", thinking


def _effective_think(think: bool | str | None) -> bool | str:
    return hub_cfg.OLLAMA_THINK if think is None else think


def _num_predict(base: int, think: bool | str | None = None) -> int:
    n = max(64, base)
    if _effective_think(think) is not False:
        n = max(n, hub_cfg.OLLAMA_THINK_MIN_NUM_PREDICT)
    return n


def _chat_payload(
    system: str,
    user: str,
    *,
    num_predict: int,
    temperature: float,
    think: bool | str | None = None,
    timeout_sec: int | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    effective_think = _effective_think(think)
    payload: dict[str, Any] = {
        "model": settings.ollama_model,
        "stream": False,
        "options": {
            "temperature": temperature,
            "top_p": 0.9,
            "num_predict": _num_predict(num_predict, think),
        },
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    if effective_think is not False:
        payload["think"] = effective_think
    if settings.ollama_json_format:
        payload["format"] = "json"
    return payload


def _empty_response_fallback(data: dict[str, Any], thinking: str) -> dict[str, Any]:
    if thinking:
        summary = "Model returned thinking trace only; JSON content was empty."
    else:
        done = data.get("done_reason") or "unknown"
        summary = f"Model returned empty content (done_reason={done})."
    return {"severity": "low", "summary": summary, "anomalies": []}


def _extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if m:
        text = m.group(1).strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        try:
            obj = json.loads(text[start : end + 1])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    return {
        "severity": "low",
        "summary": "Model returned non-JSON; inspect raw response.",
        "anomalies": [],
    }


def _clamp_output(parsed: dict[str, Any]) -> dict[str, Any]:
    sev = str(parsed.get("severity", "info")).lower()
    if sev not in ("info", "low", "medium", "high", "critical"):
        sev = "low"
    summary = str(parsed.get("summary", "")).strip()[:220] or "(no summary)"
    raw_items = parsed.get("anomalies") or []
    if not isinstance(raw_items, list):
        raw_items = []
    norm: list[dict[str, Any]] = []
    for item in raw_items[:4]:
        if not isinstance(item, dict):
            continue
        norm.append(
            {
                "title": str(item.get("title", "Note")).strip()[:56] or "Note",
                "detail": str(item.get("detail", "")).strip()[:130],
                "related_log_indexes": item.get("related_log_indexes") or [],
            }
        )
    return {"severity": sev, "summary": summary, "anomalies": norm}


def _clamp_meta(parsed: dict[str, Any]) -> dict[str, Any]:
    headline = str(parsed.get("headline", "")).strip()[:100] or "(no headline)"
    summary = str(parsed.get("summary", "")).strip()[:420] or "(no summary)"
    conf = str(parsed.get("confidence", "low")).lower()
    if conf not in ("low", "medium", "high"):
        conf = "low"
    raw_items = parsed.get("findings") or parsed.get("anomalies") or []
    if not isinstance(raw_items, list):
        raw_items = []
    findings: list[dict[str, str]] = []
    for item in raw_items[:10]:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "Finding")).strip()[:70]
        detail = str(item.get("detail", "")).strip()[:200]
        findings.append({"title": title or "Finding", "detail": detail})
    return {"headline": headline, "summary": summary, "findings": findings, "confidence": conf}


def analyze_batch(
    log_lines: list[str], *, think: bool | str | None = None
) -> tuple[dict[str, Any], str]:
    settings = get_settings()
    trimmed = [_trim_line(x, settings.log_line_max_chars) for x in log_lines]
    body = "\n".join(f"{i}|{line}" for i, line in enumerate(trimmed))
    user_content = f"{len(trimmed)} lines. JSON only.\n{body}"

    url = f"{settings.ollama_base_url}/api/chat"
    payload = _chat_payload(
        SYSTEM_PROMPT,
        user_content,
        num_predict=settings.ollama_num_predict,
        temperature=0.1,
        think=think,
    )

    resp = requests.post(url, json=payload, timeout=settings.ollama_timeout_sec)
    resp.raise_for_status()
    data = resp.json()
    text, raw = _read_model_text(data)
    if not text:
        parsed = _clamp_output(_empty_response_fallback(data, raw))
        return parsed, raw
    return _clamp_output(_extract_json_object(text)), raw


def meta_summarize(granularity: str, user_content: str) -> tuple[dict[str, Any], str]:
    settings = get_settings()
    hint = f"GRANULARITY={granularity}\n\n{user_content}"
    url = f"{settings.ollama_base_url}/api/chat"
    payload = _chat_payload(
        META_SYSTEM_PROMPT,
        hint,
        num_predict=hub_cfg.META_NUM_PREDICT,
        temperature=0.15,
    )

    resp = requests.post(url, json=payload, timeout=hub_cfg.META_OLLAMA_TIMEOUT_SEC)
    resp.raise_for_status()
    data = resp.json()
    text, raw = _read_model_text(data)
    if not text:
        parsed = _clamp_meta(_empty_response_fallback(data, raw))
        return parsed, raw
    parsed = _clamp_meta(_extract_json_object(text))
    return parsed, raw


def health_check() -> tuple[bool, str]:
    settings = get_settings()
    try:
        r = requests.get(f"{settings.ollama_base_url}/api/tags", timeout=5)
        r.raise_for_status()
        return True, f"Ollama OK at {settings.ollama_base_url}"
    except Exception as e:
        return False, str(e)
