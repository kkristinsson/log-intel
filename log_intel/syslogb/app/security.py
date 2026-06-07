"""Web security helpers (redirects, CSRF, outbound webhook validation)."""

from __future__ import annotations

import ipaddress
import logging
import os
import secrets
import socket
from urllib.parse import urlparse

from flask import Request, request, url_for

log = logging.getLogger(__name__)

CSRF_HEADER = "X-Requested-With"
CSRF_HEADER_VALUE = "XMLHttpRequest"
WEBHOOK_SECRET_HEADER = "X-Webhook-Secret"

_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "metadata.google",
    }
)


def _allow_private_webhook_urls() -> bool:
    return os.environ.get("LOG_INTEL_WEBHOOK_ALLOW_PRIVATE", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def validate_outbound_webhook_url(url: str) -> tuple[bool, str]:
    """Return (ok, error_message). Empty URL is allowed."""
    url = (url or "").strip()
    if not url:
        return True, ""
    if _allow_private_webhook_urls():
        return True, ""

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "invalid webhook URL"

    if parsed.scheme not in ("http", "https"):
        return False, "webhook URL must use http or https"
    if parsed.username or parsed.password:
        return False, "webhook URL must not contain embedded credentials"

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False, "webhook URL missing host"
    if host in _BLOCKED_HOSTS:
        return False, "webhook URL host not allowed"

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False, "webhook URL host could not be resolved"

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False, "webhook URL resolved to invalid address"
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False, "webhook URL must not target private or internal addresses"
        if ip == ipaddress.ip_address("169.254.169.254"):
            return False, "webhook URL must not target cloud metadata endpoints"

    return True, ""


def safe_redirect_target(next_url: str | None, *, default_endpoint: str = "index") -> str:
    """Only allow same-application relative paths (blocks open redirects)."""
    default = url_for(default_endpoint)
    raw = (next_url or "").strip()
    if not raw or not raw.startswith("/") or raw.startswith("//"):
        return default
    return raw


def csrf_exempt_path(path: str) -> bool:
    if path == "/logout":
        return True
    if path.endswith("/webhooks/syslogb"):
        return True
    return False


def check_csrf(req: Request | None = None) -> bool:
    """Require custom header on mutating API requests when auth is enabled."""
    req = req or request
    if req.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return True
    path = req.path or ""
    if not (path.startswith("/api/") or path.startswith("/hub/api/")):
        return True
    if csrf_exempt_path(path):
        return True
    return req.headers.get(CSRF_HEADER) == CSRF_HEADER_VALUE


def webhook_ingest_authorized(expected_secret: str) -> bool:
    """Shared-secret header, or authenticated settings admin when no secret configured."""
    secret = (expected_secret or "").strip()
    if secret:
        provided = (request.headers.get(WEBHOOK_SECRET_HEADER) or "").strip()
        auth = (request.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            provided = auth[7:].strip()
        if not provided:
            return False
        return secrets.compare_digest(provided, secret)

    from log_intel.syslogb.app.admin_auth import is_settings_admin

    return is_settings_admin() and check_csrf(request)
