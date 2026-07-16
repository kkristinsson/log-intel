"""Web security helpers (redirects, CSRF, outbound webhook validation)."""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import secrets
import socket
import ssl
from typing import Any
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
        if _is_blocked_ip(ip):
            return False, "webhook URL must not target private or internal addresses"

    return True, ""


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip == ipaddress.ip_address("169.254.169.254")
    )


def resolve_webhook_connect_ip(url: str) -> tuple[bool, str, str | None]:
    """Re-resolve webhook host and return a public connect IP (anti DNS-rebinding)."""
    url = (url or "").strip()
    if not url:
        return False, "empty webhook URL", None
    if _allow_private_webhook_urls():
        return True, "", None

    ok, err = validate_outbound_webhook_url(url)
    if not ok:
        return False, err, None

    parsed = urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False, "webhook URL host could not be resolved", None

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if _is_blocked_ip(ip):
            continue
        return True, "", str(ip)
    return False, "webhook URL must not target private or internal addresses", None


def post_json_webhook(url: str, body: dict[str, Any], *, timeout: float = 10.0) -> None:
    """POST JSON to a webhook after re-validating DNS and pinning the connect IP."""
    url = (url or "").strip()
    if not url:
        raise ValueError("empty webhook URL")

    parsed = urlparse(url)
    host = (parsed.hostname or "").strip()
    if not host:
        raise ValueError("webhook URL missing host")
    scheme = (parsed.scheme or "http").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    if _allow_private_webhook_urls():
        connect_host = host
        server_hostname = host
    else:
        ok, err, ip = resolve_webhook_connect_ip(url)
        if not ok or not ip:
            raise ValueError(err or "webhook URL blocked")
        connect_host = ip
        server_hostname = host

    payload = json.dumps(body).encode("utf-8")
    headers = {
        "Host": host if parsed.port is None else f"{host}:{parsed.port}",
        "Content-Type": "application/json",
        "Content-Length": str(len(payload)),
        "User-Agent": "log-intel-webhook/1",
        "Connection": "close",
    }

    if scheme == "https":
        context = ssl.create_default_context()
        sock = socket.create_connection((connect_host, port), timeout=timeout)
        try:
            ssock = context.wrap_socket(sock, server_hostname=server_hostname)
        except Exception:
            sock.close()
            raise
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            server_hostname, port, timeout=timeout, context=context
        )
        conn.sock = ssock
    else:
        conn = http.client.HTTPConnection(connect_host, port, timeout=timeout)

    try:
        conn.request("POST", path, body=payload, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read()
        if resp.status >= 400:
            raise OSError(f"webhook HTTP {resp.status}: {resp_body[:200]!r}")
    finally:
        conn.close()


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
