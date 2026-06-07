"""Outbound alert delivery."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from log_intel.syslogb.app.security import validate_outbound_webhook_url

log = logging.getLogger(__name__)


def is_discord_webhook(url: str) -> bool:
    return "discord.com/api/webhooks/" in url.lower()


def deliver_webhook(url: str, payload: dict[str, Any]) -> bool:
    ok, err = validate_outbound_webhook_url(url)
    if not ok:
        log.warning("webhook blocked: %s", err)
        return False
    try:
        if is_discord_webhook(url):
            content = (
                f"**log-intel alert**\n"
                f"Rule: {payload.get('rule', 'unknown')}\n"
                f"Source: {payload.get('source', '')}\n"
                f"```\n{payload.get('line', '')[:1800]}\n```"
            )
            body = {"content": content[:2000]}
        else:
            body = payload
        with httpx.Client(timeout=10.0) as client:
            r = client.post(url, json=body)
            r.raise_for_status()
        return True
    except Exception as e:
        log.warning("webhook delivery failed: %s", e)
        return False


def build_alert_payload(
    *,
    rule_name: str,
    rule_id: str,
    source: str,
    line: str,
    ts: float,
    origin: str = "hub",
) -> dict[str, Any]:
    return {
        "app": "log-intel",
        "origin": origin,
        "rule": rule_name,
        "rule_id": rule_id,
        "source": source,
        "line": line,
        "ts": ts,
    }
