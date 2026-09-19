"""Shared HTTP helpers for Ollama (local or Cloudflare Access)."""

from __future__ import annotations


def cf_access_headers(client_id: str = "", client_secret: str = "") -> dict[str, str]:
    """Return Cloudflare Access service-token headers when both values are set."""
    headers: dict[str, str] = {}
    cid = (client_id or "").strip()
    secret = (client_secret or "").strip()
    if cid:
        headers["CF-Access-Client-Id"] = cid
    if secret:
        headers["CF-Access-Client-Secret"] = secret
    return headers
