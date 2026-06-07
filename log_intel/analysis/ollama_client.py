"""Hub-owned Ollama client (adapted from loggy patterns)."""

from __future__ import annotations

import json
import re
from typing import Any

import requests

from log_intel.config import get_settings

SYSTEM_PROMPT = (
    "Unified log triage for syslog from firewalls, Windows hosts, and generic sources. "
    "Flag threats, auth failures, denies, anomalies, and cross-source patterns.\n"
    "Reply with ONE JSON object only. Schema:\n"
    '{"severity":"info|low|medium|high|critical","summary":"<string>","anomalies":['
    '{"title":"<string>","detail":"<string>","related_log_indexes":[<ints>]}]}\n'
    "Caps: summary ≤220 chars; ≤4 anomalies; each title ≤56 chars; each detail ≤130 chars."
)


def _trim_line(s: str, max_chars: int) -> str:
    if max_chars <= 0 or len(s) <= max_chars:
        return s
    return s[: max_chars - 1] + "…"


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


def analyze_batch(log_lines: list[str]) -> tuple[dict[str, Any], str]:
    settings = get_settings()
    trimmed = [_trim_line(x, settings.log_line_max_chars) for x in log_lines]
    body = "\n".join(f"{i}|{line}" for i, line in enumerate(trimmed))
    user_content = f"{len(trimmed)} lines. JSON only.\n{body}"

    payload: dict[str, Any] = {
        "model": settings.ollama_model,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": settings.ollama_num_predict,
        },
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    }
    if settings.ollama_json_format:
        payload["format"] = "json"

    url = f"{settings.ollama_base_url}/api/chat"
    resp = requests.post(url, json=payload, timeout=settings.ollama_timeout_sec)
    resp.raise_for_status()
    data = resp.json()
    msg = data.get("message") or {}
    text = (msg.get("content") or "").strip()
    raw = text or json.dumps(data)
    if not text:
        parsed = _clamp_output(
            {"severity": "low", "summary": "Empty model response.", "anomalies": []}
        )
        return parsed, raw
    return _clamp_output(_extract_json_object(text)), raw


def health_check() -> tuple[bool, str]:
    settings = get_settings()
    try:
        r = requests.get(f"{settings.ollama_base_url}/api/tags", timeout=5)
        r.raise_for_status()
        return True, f"Ollama OK at {settings.ollama_base_url}"
    except Exception as e:
        return False, str(e)
