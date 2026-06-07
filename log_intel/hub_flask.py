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
from log_intel.syslogb.app.admin_auth import is_settings_admin
from log_intel.syslogb.app.security import validate_outbound_webhook_url, webhook_ingest_authorized

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
    mode = request.args.get("mode", "text").lower()
    if mode not in ("text", "regex"):
        return jsonify({"error": "mode must be text or regex"}), 400
    from log_intel.unified_search import unified_search

    result = unified_search(
        hub.store,
        hub.loggy,
        q,
        mode=mode,
        hours=float(request.args.get("hours", 168)),
        limit=int(request.args.get("limit", 200)),
        order=request.args.get("order", "desc"),
        importance_min=request.args.get("importance_min") or None,
        include_hub=request.args.get("include_hub", "true").lower() != "false",
        include_syslogb=request.args.get("include_syslogb", "false").lower() == "true",
        include_loggy=request.args.get("include_loggy", "false").lower() == "true",
        source_type=request.args.get("source_type") or None,
    )
    return jsonify(
        {
            "query": result.query,
            "mode": result.mode,
            "order": result.order,
            "limit": result.limit,
            "count": result.count,
            "counts_by_origin": result.counts_by_origin,
            "highlight_terms": result.highlight_terms,
            "errors": result.errors,
            "results": result.results,
        }
    )


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
    include_syslogb = request.args.get("include_syslogb", "false").lower() == "true"
    levels = {"info": 0, "warning": 1, "error": 2, "critical": 3}
    min_level = levels.get(imp_min, 0)

    tail_q = None
    if include_syslogb:
        try:
            from log_intel.syslogb.bootstrap import get_runtime

            runtime = get_runtime()
            if runtime and runtime.tail_service:
                tail_q = runtime.tail_service.subscribe_sse()
        except Exception:
            tail_q = None

    def _importance_ok(ev_dict: dict) -> bool:
        return levels.get(ev_dict.get("importance", "info"), 0) >= min_level

    def _normalize_tail(payload: str) -> dict | None:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return None
        if isinstance(data, dict):
            data.setdefault("origin", "syslogb")
            if "message" not in data and "line" in data:
                data["message"] = data["line"]
            if "importance" not in data:
                data["importance"] = "error"
            return data
        return None

    def gen():
        q: qmod.Queue = qmod.Queue(maxsize=200)
        hub.sync_stream_subscribers.append(q)
        try:
            for ev in list(hub.recent_stream):
                d = ev.__dict__.copy()
                if _importance_ok(d):
                    yield f"data: {json.dumps(d)}\n\n"
            while True:
                got = False
                if tail_q is not None:
                    try:
                        raw = tail_q.get_nowait()
                        norm = _normalize_tail(raw)
                        if norm and _importance_ok(norm):
                            yield f"data: {json.dumps(norm)}\n\n"
                            got = True
                    except qmod.Empty:
                        pass
                try:
                    ev = q.get(timeout=0.5 if tail_q else 30)
                except qmod.Empty:
                    if not got:
                        yield ": keepalive\n\n"
                    continue
                if ev is None:
                    break
                d = ev.__dict__.copy()
                if _importance_ok(d):
                    yield f"data: {json.dumps(d)}\n\n"
        finally:
            if q in hub.sync_stream_subscribers:
                hub.sync_stream_subscribers.remove(q)
            if tail_q is not None:
                try:
                    from log_intel.syslogb.bootstrap import get_runtime

                    runtime = get_runtime()
                    if runtime and runtime.tail_service:
                        runtime.tail_service.unsubscribe_sse(tail_q)
                except Exception:
                    pass

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


@hub_bp.route("/hub/analysis")
def hub_analysis_page():
    return _render_dashboard("analysis")


@hub_bp.route("/hub/summary/hourly")
def hub_summary_hourly():
    return _render_dashboard("analysis")


@hub_bp.route("/hub/api/analyses/recent")
def hub_analyses_recent():
    hub = _require_hub()
    hours = float(request.args.get("hours", 168))
    since = time.time() - hours * 3600
    until = time.time()
    limit = int(request.args.get("limit", 50))
    analyses = hub.store.recent_analyses(limit=limit, since_ts=since, until_ts=until)
    win = hub.store.counts_in_window(since, until)
    pending = hub.store.count_unanalyzed_in_range(since, until)
    return jsonify(
        {
            "analyses": analyses,
            "since": since,
            "until": until,
            "raw_in_window": win["raw_in_window"],
            "analyses_in_window": win["analyses_in_window"],
            "pending_in_window": pending,
        }
    )


@hub_bp.route("/hub/api/trends/daily")
def hub_trends_daily():
    hub = _require_hub()
    from log_intel.loggy_ported import trends as trendutil

    days = int(request.args.get("days", 14))
    days = max(7, min(90, days))
    raw = hub.store.daily_analysis_trend(days)
    filled = trendutil.fill_daily_gaps(raw, days)
    coverage = hub.store.analysis_calendar_coverage()
    baseline = trendutil.baseline_status(
        coverage.get("distinct_days", 0),
        coverage.get("oldest_day"),
        coverage.get("newest_day"),
    )
    return jsonify(
        {
            "days": days,
            "rows": filled,
            "bar_max": trendutil.max_bar_scalar(filled),
            "narrative": trendutil.delta_narrative(filled, "day"),
            "baseline": baseline,
            "meta": {
                "daily": hub.store.recent_meta_summaries("daily", 1),
                "weekly": hub.store.recent_meta_summaries("weekly", 1),
            },
        }
    )


def _require_admin():
    if not is_settings_admin():
        return jsonify({"error": "forbidden"}), 403
    return None


def _validate_alert_rule_body(body: dict) -> tuple[dict | None, tuple]:
    url = (body.get("webhook_url") or "").strip()
    if url:
        ok, err = validate_outbound_webhook_url(url)
        if not ok:
            return None, (jsonify({"error": err}), 400)
    return body, ()


@hub_bp.route("/hub/api/analyze/start", methods=["POST"])
def hub_analyze_start():
    denied = _require_admin()
    if denied:
        return denied
    hub = _require_hub()
    from log_intel.loggy_ported import analysis_service

    body = request.get_json(force=True, silent=True) or {}
    hours = float(body.get("hours", 24))
    since = float(body.get("since_ts") or (time.time() - hours * 3600))
    until = float(body.get("until_ts") or time.time())
    thinking = body.get("thinking_enabled", True)
    ok, msg = analysis_service.start_on_demand_analysis(
        hub.store, since, until_ts=until, thinking_enabled=bool(thinking)
    )
    if not ok:
        return jsonify({"ok": False, "message": msg}), 409
    return jsonify({"ok": True, "message": msg})


@hub_bp.route("/hub/api/analyze/status")
def hub_analyze_on_demand_status():
    from log_intel.loggy_ported import analysis_service

    return jsonify(analysis_service.get_on_demand_status())


@hub_bp.route("/hub/api/analyze/cancel", methods=["POST"])
def hub_analyze_cancel():
    denied = _require_admin()
    if denied:
        return denied
    from log_intel.loggy_ported import analysis_service

    ok, msg = analysis_service.cancel_on_demand_analysis()
    return jsonify({"ok": ok, "message": msg})


@hub_bp.route("/api/v1/alert-rules", methods=["GET"])
def hub_alert_rules_list():
    hub = _require_hub()
    return jsonify({"rules": hub.store.list_alert_rules()})


@hub_bp.route("/api/v1/alert-rules", methods=["PUT"])
def hub_alert_rules_upsert():
    denied = _require_admin()
    if denied:
        return denied
    hub = _require_hub()
    body = request.get_json(force=True, silent=True) or {}
    if not body.get("name") or not body.get("query"):
        return jsonify({"error": "name and query required"}), 400
    _, err = _validate_alert_rule_body(body)
    if err:
        return err
    rid = hub.store.upsert_alert_rule(body)
    hub.alert_engine.reload_rules()
    rules = {r["id"]: r for r in hub.store.list_alert_rules()}
    return jsonify(rules.get(rid, {"id": rid}))


@hub_bp.route("/api/v1/alert-rules/<rule_id>", methods=["DELETE"])
def hub_alert_rules_delete(rule_id: str):
    denied = _require_admin()
    if denied:
        return denied
    hub = _require_hub()
    if not hub.store.delete_alert_rule(rule_id):
        return jsonify({"error": "not found"}), 404
    hub.alert_engine.reload_rules()
    return jsonify({"ok": True})


@hub_bp.route("/api/v1/alert-rules/<rule_id>/test", methods=["POST"])
def hub_alert_rules_test(rule_id: str):
    denied = _require_admin()
    if denied:
        return denied
    hub = _require_hub()
    try:
        hub.alert_engine.send_test(rule_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify({"status": "ok"})


@hub_bp.route("/api/v1/analyze", methods=["POST"])
def hub_analyze():
    denied = _require_admin()
    if denied:
        return denied
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
    from log_intel.syslogb.app import config

    if not webhook_ingest_authorized(config.WEBHOOK_INGEST_SECRET):
        return jsonify({"error": "forbidden"}), 403
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
                {"href": "/hub?tab=search&all=1", "label": "Search all"},
                {"href": "/hub/geo", "label": "Geo map"},
                {"href": "/hub/firewall", "label": "Firewall"},
                {"href": "/hub/analysis", "label": "Analysis"},
            ],
        }
