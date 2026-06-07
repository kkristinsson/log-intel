"""Flask routes for hub network syslog, geo map, firewall (loggy + netsyslog)."""

from __future__ import annotations

import json
import queue as qmod
import time
from pathlib import Path

from flask import Blueprint, Response, jsonify, render_template, request

from log_intel import __version__
from log_intel.config import get_settings
from log_intel.geo.geoip import GeoLookup
from log_intel.hub_state import HubState
from log_intel.loggy_ported.pan_log import parse_allowed_traffic_flow
from log_intel.store import to_stream_event

_hub: HubState | None = None
_geo: GeoLookup | None = None

_HUB_ROOT = Path(__file__).resolve().parent / "hub_templates"


def init_hub(state: HubState, geo: GeoLookup) -> None:
    global _hub, _geo
    _hub = state
    _geo = geo


def _require_hub() -> HubState:
    if _hub is None:
        raise RuntimeError("Hub not initialized")
    return _hub


hub_bp = Blueprint(
    "hub",
    __name__,
    template_folder=str(_HUB_ROOT),
    static_folder=str(_HUB_ROOT / "static"),
    static_url_path="/hub/static",
)


def _render_dashboard(active_tab: str = "overview"):
    return render_template("dashboard.html", active_tab=active_tab)


@hub_bp.route("/hub")
@hub_bp.route("/hub/")
def hub_overview():
    return _render_dashboard("overview")


@hub_bp.route("/hub/live")
def hub_live_page():
    return _render_dashboard("live")


@hub_bp.route("/hub/geo")
def hub_geo_page():
    return _render_dashboard("geo")


@hub_bp.route("/hub/firewall")
def hub_firewall_page():
    return _render_dashboard("firewall")


@hub_bp.route("/health")
def hub_health_alias():
    return hub_health()


@hub_bp.route("/api/v1/health")
def hub_health():
    hub = _require_hub()
    from log_intel.analysis import ollama_client

    ok, msg = ollama_client.health_check()
    return jsonify(
        {
            "status": "ok",
            "version": __version__,
            "ollama": {"ok": ok, "message": msg},
            "adapters": hub.health_snapshot(),
        }
    )


@hub_bp.route("/api/v1/events")
def hub_events():
    hub = _require_hub()
    hours = float(request.args.get("hours", 24))
    limit = int(request.args.get("limit", 100))
    since = time.time() - hours * 3600
    events = hub.store.list_events(since=since, limit=limit)
    return jsonify({"events": [e.to_dict() for e in events], "count": len(events)})


@hub_bp.route("/api/v1/search")
def hub_search():
    hub = _require_hub()
    q = request.args.get("q", "")
    if not q:
        return jsonify({"error": "q required"}), 400
    include_loggy = request.args.get("include_loggy", "false").lower() == "true"
    events = hub.store.search(q, limit=int(request.args.get("limit", 200)))
    results = [{"origin": "hub", **e.to_dict()} for e in events]
    if include_loggy:
        for ev in hub.loggy.fetch_raw_logs(limit=200):
            if q.lower() in (ev.message or "").lower():
                results.append({"origin": "loggy", **ev.to_dict()})
    return jsonify({"results": results, "count": len(results)})


@hub_bp.route("/api/v1/flows")
def hub_flows():
    hub = _require_hub()
    hours = float(request.args.get("hours", 24))
    limit = int(request.args.get("limit", 2000))
    since = time.time() - hours * 3600
    edges = hub.store.flow_aggregates(since, time.time(), limit=limit)
    if request.args.get("include_archive", "true").lower() == "true":
        archive = hub.netsyslog.fetch_flow_aggregates(hours=hours, limit=limit)
        seen = {(e["src_ip"], e["dst_ip"]) for e in edges}
        for e in archive:
            key = (e.get("src_ip"), e.get("dst_ip"))
            if key not in seen:
                edges.append(e)
                seen.add(key)
    return jsonify({"since": since, "until": time.time(), "hours": hours, "edges": edges[:limit]})


@hub_bp.route("/api/v1/stream")
def hub_stream():
    hub = _require_hub()
    imp_min = request.args.get("importance_min", "info")
    levels = {"info": 0, "warning": 1, "error": 2, "critical": 3}
    min_level = levels.get(imp_min, 0)

    def gen():
        q: qmod.Queue = qmod.Queue(maxsize=200)
        hub.sync_stream_subscribers.append(q)
        try:
            for ev in list(hub.recent_stream):
                if levels.get(ev.importance, 0) >= min_level:
                    yield f"data: {json.dumps(ev.__dict__)}\n\n"
            while True:
                try:
                    ev = q.get(timeout=30)
                except qmod.Empty:
                    yield ": keepalive\n\n"
                    continue
                if ev is None:
                    break
                if levels.get(ev.importance, 0) >= min_level:
                    yield f"data: {json.dumps(ev.__dict__)}\n\n"
        finally:
            if q in hub.sync_stream_subscribers:
                hub.sync_stream_subscribers.remove(q)

    return Response(gen(), mimetype="text/event-stream")


@hub_bp.route("/api/v1/firewall")
def hub_firewall():
    hub = _require_hub()
    hours = float(request.args.get("hours", 24))
    log_type = request.args.get("log_type", "TRAFFIC")
    since = time.time() - hours * 3600
    events = hub.store.list_events(since=since, source_type="palo_alto", log_type=log_type, limit=500)
    action = request.args.get("action")
    if action:
        events = [e for e in events if (e.action or "").lower() == action.lower()]
    return jsonify({"events": [e.to_dict() for e in events[:200]]})


@hub_bp.route("/api/v1/flows-map")
def hub_flows_map_data():
    hub = _require_hub()
    settings = get_settings()
    hours = float(request.args.get("hours", 24))
    since = time.time() - hours * 3600
    events = hub.store.list_events(
        since=since, source_type="palo_alto", log_type="TRAFFIC", limit=settings.max_events
    )
    geo = _geo or GeoLookup(settings.geoip_mmdb_path)
    by_dst: dict[str, dict] = {}
    for ev in events:
        flow = parse_allowed_traffic_flow(ev.message)
        if not flow:
            continue
        g = geo.lookup(flow.dst_ip) if geo else None
        if not g:
            continue
        bucket = by_dst.setdefault(
            flow.dst_ip,
            {"dst_ip": flow.dst_ip, "count": 0, "lat": g["lat"], "lon": g["lon"], "country": g.get("country")},
        )
        bucket["count"] += 1
    return jsonify({"points": list(by_dst.values())})


@hub_bp.route("/api/v1/alert-events")
def hub_alert_events():
    hub = _require_hub()
    limit = int(request.args.get("limit", 100))
    return jsonify({"events": hub.store.list_alert_events(limit=limit)})


@hub_bp.route("/api/v1/analyze", methods=["POST"])
def hub_analyze():
    hub = _require_hub()
    body = request.get_json(force=True, silent=True) or {}
    ids = body.get("event_ids") or []
    if not ids:
        return jsonify({"error": "event_ids required"}), 400
    job_id = hub.analysis_worker.run_on_demand([int(x) for x in ids])
    return jsonify({"job_id": job_id})


@hub_bp.route("/api/v1/analyze/<job_id>")
def hub_analyze_status(job_id: str):
    hub = _require_hub()
    job = hub.store.get_analysis_job(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify(job)


@hub_bp.route("/api/v1/webhooks/syslogb", methods=["POST"])
def hub_syslogb_webhook():
    hub = _require_hub()
    body = request.get_json(force=True, silent=True) or {}
    hub.alert_engine.ingest_syslogb_webhook(body)
    return jsonify({"ok": True})


@hub_bp.route("/metrics")
def hub_metrics():
    from log_intel.metrics import metrics_bytes

    return Response(metrics_bytes(), mimetype="text/plain; version=0.0.4")


def register_hub_routes(app) -> None:
    """Attach hub blueprint and nav links."""
    app.register_blueprint(hub_bp)

    @app.context_processor
    def hub_nav():
        return {
            "hub_nav": True,
            "hub_links": [
                {"href": "/", "label": "Files"},
                {"href": "/hub", "label": "Network hub"},
                {"href": "/hub/live", "label": "Live syslog"},
                {"href": "/hub/geo", "label": "Geo map"},
                {"href": "/hub/firewall", "label": "Firewall"},
            ],
        }
