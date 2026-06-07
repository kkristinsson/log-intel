"""Outbound webhook and email notifications (shared by alerts and scheduled analysis)."""

from __future__ import annotations

import logging
import smtplib
from datetime import datetime
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlparse

import requests

from log_intel.syslogb.app import config
from log_intel.syslogb.app.security import validate_outbound_webhook_url

logger = logging.getLogger(__name__)

DISCORD_CONTENT_MAX = 2000


def is_discord_webhook_url(url: str) -> bool:
    """True for Discord channel webhook URLs (discord.com / discordapp.com)."""
    try:
        host = (urlparse(url.strip()).hostname or "").lower()
    except ValueError:
        return False
    if host not in ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"):
        return False
    path = (urlparse(url.strip()).path or "").lower()
    return path.startswith("/api/webhooks/")


def format_webhook_payload(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Return JSON body for POST; Discord URLs get a channel message instead of raw JSON."""
    if is_discord_webhook_url(url):
        return {"content": format_discord_message(payload)}
    return payload


def format_discord_message(payload: dict[str, Any]) -> str:
    """Human-readable Discord message from an alert or scheduled-analysis payload."""
    app = payload.get("app") or config.APP_NAME
    typ = payload.get("type")

    if typ == "scheduled_analysis":
        file_path = payload.get("file") or "?"
        severity = payload.get("severity") or "?"
        summary = payload.get("summary") or ""
        n = payload.get("anomaly_count", 0)
        url = payload.get("analysis_url") or ""
        parts = [
            f"**[{app}] Scheduled log analysis**",
            f"**File:** `{file_path}`",
            f"**Severity:** {severity} · **Anomalies:** {n}",
        ]
        if summary:
            parts.append(f"**Summary:** {summary}")
        if url:
            parts.append(f"**Report:** {url}")
        text = "\n".join(parts)
    elif typ == "scheduled_analysis_failed":
        file_path = payload.get("file") or "?"
        err = payload.get("error") or "unknown error"
        text = (
            f"**[{app}] Scheduled analysis failed**\n"
            f"**File:** `{file_path}`\n"
            f"**Error:** {err}"
        )
    else:
        rule = payload.get("rule") or "alert"
        source = payload.get("source") or "?"
        line = payload.get("line") or ""
        ts = payload.get("ts")
        when = ""
        if ts is not None:
            try:
                when = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError, OSError):
                when = str(ts)
        parts = [f"**[{app}] Alert: {rule}**"]
        if when:
            parts.append(f"**When:** {when}")
        parts.append(f"**Source:** `{source}`")
        if line:
            parts.append(f"```\n{line}\n```")
        text = "\n".join(parts)

    if len(text) > DISCORD_CONTENT_MAX:
        return text[: DISCORD_CONTENT_MAX - 3] + "..."
    return text


def send_webhook(url: str, payload: dict[str, Any]) -> tuple[bool, str]:
    url = (url or "").strip()
    if not url:
        return False, "webhook_url empty"
    ok, err = validate_outbound_webhook_url(url)
    if not ok:
        return False, err
    body = format_webhook_payload(url, payload)
    try:
        resp = requests.post(url, json=body, timeout=30)
        if resp.ok:
            return True, "sent"
        return False, resp.text[:500]
    except Exception as e:
        logger.warning("Webhook failed: %s", e)
        return False, str(e)


def send_email(to: str, subject: str, body: str) -> tuple[bool, str]:
    host = config.SMTP_HOST
    if not host:
        return False, "SMTP_HOST not configured"
    recipients = [x.strip() for x in (to or "").split(",") if x.strip()]
    if not recipients:
        return False, "email_to empty"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config.SMTP_FROM or config.SMTP_USER or "syslogb@localhost"
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, config.SMTP_PORT, timeout=20) as smtp:
            if config.SMTP_TLS:
                smtp.starttls()
            if config.SMTP_USER and config.SMTP_PASSWORD:
                smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
            smtp.send_message(msg)
        return True, "sent"
    except Exception as e:
        logger.warning("Email failed: %s", e)
        return False, str(e)
