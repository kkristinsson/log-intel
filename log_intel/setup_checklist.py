"""First-run and ongoing setup checklist for the Settings wizard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from log_intel.config import get_settings


def compute_setup_checklist(hub=None) -> list[dict[str, Any]]:
    settings = get_settings()
    items: list[dict[str, Any]] = []

    log_dirs_ok = False
    try:
        from log_intel.syslogb.app.log_dirs import log_dirs

        log_dirs_ok = bool(log_dirs())
    except Exception:
        pass

    items.append(
        {
            "id": "log_dirs",
            "label": "File log directories (LOG_DIRS)",
            "done": log_dirs_ok,
            "hint": "Settings → Logging",
        }
    )

    geo_ok = bool(settings.geoip_mmdb_path) and Path(settings.geoip_mmdb_path).is_file()
    items.append(
        {
            "id": "geoip",
            "label": "GeoIP database for hub map",
            "done": geo_ok,
            "hint": "Settings → Hub → LOG_INTEL_GEOIP_MMDB_PATH",
        }
    )

    mist_ok = bool(settings.mist_enabled and settings.mist_api_key.strip())
    items.append(
        {
            "id": "mist",
            "label": "Juniper Mist cloud ingest",
            "done": mist_ok,
            "hint": "Settings → Juniper Mist",
        }
    )

    items.append(
        {
            "id": "llm",
            "label": "LLM enabled (optional)",
            "done": bool(settings.llm_enabled),
            "hint": "Settings → LLM options",
        }
    )

    items.append(
        {
            "id": "auth",
            "label": "Sign-in enabled",
            "done": False,
            "hint": "Settings → Authentication",
        }
    )
    try:
        from log_intel.syslogb.app import config as sb_config

        items[-1]["done"] = bool(sb_config.AUTH_ENABLED)
    except Exception:
        pass

    webhook_ok = False
    try:
        from log_intel.syslogb.app import config as sb_config

        webhook_ok = bool(getattr(sb_config, "WEBHOOK_INGEST_SECRET", "").strip())
    except Exception:
        pass
    items.append(
        {
            "id": "webhook_secret",
            "label": "Webhook ingest secret (external alert POSTs)",
            "done": webhook_ok,
            "hint": "Settings → Hub → WEBHOOK_INGEST_SECRET",
        }
    )

    if hub is not None:
        items.append(
            {
                "id": "hub_events",
                "label": "Hub receiving syslog or cloud events",
                "done": hub.store.count_events() > 0,
                "hint": "Point firewalls/clients at syslog port; enable Mist",
            }
        )

    done = sum(1 for i in items if i["done"])
    return items
