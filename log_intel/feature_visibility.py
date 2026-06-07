"""Decide which product UI surfaces are visible (configured or populated)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from log_intel.config import get_settings
from log_intel.hub_state import HubState


def _geoip_configured() -> bool:
    settings = get_settings()
    path = (settings.geoip_mmdb_path or "").strip()
    return bool(path) and Path(path).is_file()


def _journal_ok() -> bool:
    try:
        from log_intel.syslogb.bootstrap import get_runtime

        runtime = get_runtime()
        if runtime and runtime.tail_service:
            return bool(runtime.tail_service.journal_status.get("ok"))
    except Exception:
        pass
    return False


def compute_ui_features(hub: HubState | None = None) -> dict[str, bool]:
    """Return booleans for product UI (not Settings admin panels).

    A surface is visible when it is configured and/or has data to show.
    """
    settings = get_settings()
    features: dict[str, bool] = {
        "hub": False,
        "hub_firewall": False,
        "hub_geo": False,
        "hub_analysis": False,
        "hub_analysis_hourly": False,
        "hub_analysis_trends": False,
        "hub_analysis_ondemand": False,
        "hub_loggy_search": False,
        "hub_netsyslog_search": False,
        "hub_mist": False,
        "hub_health_loggy": False,
        "hub_health_netsyslog": False,
        "hub_health_mist": False,
        "hub_health_journal": False,
        "hub_health_ollama": False,
    }

    if hub is None:
        features["hub_health_journal"] = _journal_ok()
        return features

    loggy_health = hub.loggy.health()
    loggy_ok = bool(loggy_health.get("ok"))
    netsyslog_ok = bool(hub.netsyslog.health().get("ok"))

    mist_configured = bool(settings.mist_enabled and settings.mist_api_key.strip())
    mist_count = hub.store.count_events_by_source_type("mist")
    mist_health = hub.mist_health()
    mist_populated = mist_count > 0 or int(mist_health.get("last_inserted") or 0) > 0
    mist_visible = mist_configured or mist_populated

    palo_count = hub.store.count_events_by_source_type("palo_alto")
    features["hub_firewall"] = palo_count > 0

    has_hub_flows = bool(hub.store.flow_aggregates(None, None, limit=1))
    if not has_hub_flows and netsyslog_ok:
        try:
            has_hub_flows = bool(hub.netsyslog.fetch_flow_aggregates(hours=168, limit=1))
        except Exception:
            has_hub_flows = False
    features["hub_geo"] = _geoip_configured() and has_hub_flows

    stats = hub.store.analysis_window_stats(0, 9e9)
    analyses_total = int(stats.get("analyses_total") or 0)
    has_meta = bool(hub.store.recent_meta_summaries("daily", 1)) or bool(
        hub.store.recent_meta_summaries("weekly", 1)
    )
    llm = bool(settings.llm_enabled)
    features["hub_analysis"] = llm
    features["hub_analysis_hourly"] = llm and (settings.analysis_auto or analyses_total > 0)
    features["hub_analysis_trends"] = llm and (
        settings.meta_summary_enabled or has_meta or analyses_total >= 2
    )
    features["hub_analysis_ondemand"] = llm

    features["hub_loggy_search"] = loggy_ok
    features["hub_netsyslog_search"] = netsyslog_ok
    features["hub_mist"] = mist_visible

    features["hub_health_loggy"] = loggy_ok
    features["hub_health_netsyslog"] = netsyslog_ok
    features["hub_health_mist"] = mist_visible
    features["hub_health_journal"] = _journal_ok()
    features["hub_health_ollama"] = llm

    total_events = hub.store.count_events()
    features["hub"] = (
        total_events > 0
        or features["hub_firewall"]
        or features["hub_geo"]
        or loggy_ok
        or netsyslog_ok
        or mist_visible
    )
    return features


def ui_features_payload(hub: HubState | None = None) -> dict[str, Any]:
    ui = compute_ui_features(hub)
    parts = ["Live syslog", "Search"]
    if ui.get("hub_firewall"):
        parts.append("Firewall")
    if ui.get("hub_mist"):
        parts.append("Mist")
    if ui.get("hub_geo"):
        parts.append("Geo map")
    parts.extend(["Alerts"])
    if ui.get("hub_analysis"):
        parts.append("Analysis")
    return {"ui": ui, "tagline": ", ".join(parts)}
