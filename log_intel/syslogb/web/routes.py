from __future__ import annotations

import json
import logging
import queue
import secrets
from pathlib import Path

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from flask_login import LoginManager, current_user, login_user, logout_user

from log_intel.syslogb.app import config
from log_intel.syslogb.app.analyze_worker import AnalyzeWorker
from log_intel.syslogb.app.auth import AuthUser, auth_required, authenticate
from log_intel.syslogb.app.journal_source import is_journal_source
from log_intel.syslogb.app.journal_reader import journal_meta, read_journal_file_page, read_journal_page
from log_intel.syslogb.app.file_reader import file_meta, full_log_lines, read_file_page, window_to_since_ts
from log_intel.syslogb.app.llm_client import (
    chat_model_name,
    embed_model_name,
    explain_log_entry,
    health_check,
    llm_enabled,
)
from log_intel.syslogb.app.search import search_highlight_terms, search_logs
from log_intel.syslogb.app.admin_auth import can_access_settings, is_settings_admin, is_setup_complete
from log_intel.syslogb.app.columnizers import enrich_event, resolve_columnizer
from log_intel.syslogb.app.export import collect_file_events, collect_search_events, stream_csv, stream_jsonl, stream_txt
from log_intel.syslogb.app.store import AppStore
from log_intel.syslogb.app.severity import IMPORTANCE_MIN_CHOICES, filter_events_by_importance, meets_importance_min
from log_intel.syslogb.app.log_dirs import (
    log_dirs,
    log_dirs_info,
    resolve_log_dir,
    resolve_log_dir_scope,
    resolve_safe_path,
)
from log_intel.syslogb.app.security import (
    check_csrf,
    safe_redirect_target,
    validate_outbound_webhook_url,
    webhook_ingest_authorized,
)

logger = logging.getLogger(__name__)

login_manager = LoginManager()


def _unified_alert_store(fallback: AppStore):
    try:
        from log_intel.main import get_hub

        hub = get_hub()
        if hub is not None:
            return hub.store
    except Exception:
        pass
    return fallback


def _unified_alert_engine(fallback):
    try:
        from log_intel.main import get_hub

        hub = get_hub()
        if hub is not None:
            return hub.alert_engine
    except Exception:
        pass
    return fallback


def _init_auth(app: Flask, store: AppStore) -> None:
    secret = config.FLASK_SECRET_KEY.strip()
    if config.AUTH_ENABLED:
        if not secret:
            raise RuntimeError("AUTH_ENABLED requires FLASK_SECRET_KEY (set in web settings or .env)")
        has_ldap = bool(config.LDAP_URI.strip())
        has_local = bool(config.LOCAL_AUTH_USERNAME.strip() and config.LOCAL_AUTH_PASSWORD)
        if not has_ldap and not has_local:
            raise RuntimeError(
                "AUTH_ENABLED requires LDAP URI or local admin username and password"
            )
    app.secret_key = secret or "dev-insecure-change-me"
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    login_manager.init_app(app)
    login_manager.login_view = "login"

    @login_manager.user_loader
    def load_user(user_id: str) -> AuthUser | None:
        method = session.get("auth_method", "local")
        if method not in ("local", "ldap"):
            method = "local"
        return AuthUser(username=user_id, method=method)

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify({"error": "authentication required"}), 401
        return redirect(url_for("login", next=request.url))

    @app.before_request
    def enforce_auth():
        if not auth_required():
            return None
        if not is_setup_complete(store):
            if request.endpoint in (
                None,
                "login",
                "static",
                "settings_page",
                "api_settings_get",
                "api_settings_put",
                "api_settings_reload",
                "api_setup_status",
                "api_setup_skip",
            ):
                return None
        if request.endpoint in (None, "login", "static"):
            return None
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        return None

    @app.before_request
    def enforce_csrf():
        if not auth_required():
            return None
        if check_csrf():
            return None
        return jsonify({"error": "csrf"}), 403


def _validate_alert_rule_body(body: dict) -> tuple[dict | None, tuple]:
    url = (body.get("webhook_url") or "").strip()
    if url:
        ok, err = validate_outbound_webhook_url(url)
        if not ok:
            return None, (jsonify({"error": err}), 400)
    return body, ()


from log_intel.syslogb.app.tail_service import TailService


def _enrich_events(events: list, store: AppStore) -> list:
    columnizers = store.list_columnizers()
    return [
        enrich_event(ev, resolve_columnizer(ev.get("source", ""), columnizers))
        for ev in events
    ]


def _importance_min_arg() -> str | None:
    raw = request.args.get("importance_min", "").strip().lower()
    if not raw or raw not in IMPORTANCE_MIN_CHOICES:
        return None
    return raw


def _paging_fields(page: dict) -> dict:
    return {
        k: page.get(k)
        for k in (
            "read_from",
            "read_to",
            "line_start",
            "line_end",
            "line_count",
            "has_older",
            "has_newer",
            "compressed",
            "forward_only",
            "file_size",
        )
    }


def create_app(
    tail_service: TailService,
    store: AppStore,
    worker: AnalyzeWorker,
    alert_engine,
    analysis_scheduler=None,
) -> Flask:
    from log_intel.syslogb.app.runtime_config import refresh_config_module

    refresh_config_module(store)
    _web_root = Path(__file__).resolve().parent
    app = Flask(
        __name__,
        template_folder=str(_web_root / "templates"),
        static_folder=str(_web_root / "static"),
    )
    _init_auth(app, store)

    @app.context_processor
    def inject_branding():
        logo = config.BRAND_LOGO.strip()
        if logo.startswith(("http://", "https://")):
            logo_url = logo
        elif logo:
            logo_url = url_for("static", filename=logo.lstrip("/"))
        else:
            logo_url = ""
        return {
            "app_name": config.APP_NAME,
            "app_version": config.APP_VERSION,
            "brand_logo_url": logo_url,
            "brand_logo_link": config.BRAND_LOGO_LINK,
            "brand_tagline": config.BRAND_TAGLINE,
            "copyright_text": config.COPYRIGHT_TEXT,
            "auth_enabled": auth_required(),
            "setup_complete": is_setup_complete(store),
            "llm_enabled": llm_enabled(),
        }

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not auth_required():
            return redirect(url_for("index"))
        if current_user.is_authenticated:
            return redirect(url_for("index"))

        error = None
        if request.method == "POST":
            user = authenticate(
                request.form.get("username", ""),
                request.form.get("password", ""),
            )
            if user:
                login_user(user)
                session["auth_method"] = user.method
                dest = safe_redirect_target(request.args.get("next"))
                return redirect(dest)
            error = "Invalid username or password."

        return render_template(
            "login.html",
            error=error,
            ldap_configured=bool(config.LDAP_URI.strip()),
        )

    @app.post("/logout")
    def logout():
        if current_user.is_authenticated:
            logout_user()
            session.pop("auth_method", None)
        return redirect(url_for("login" if auth_required() else "index"))

    @app.get("/")
    def index():
        if not is_setup_complete(store):
            return redirect(url_for("settings_page", setup=1))
        ok, ollama_msg = health_check()
        return render_template(
            "index.html",
            log_dirs=[str(d) for d in log_dirs()],
            default_order=config.TAIL_DEFAULT_ORDER,
            ollama_ok=ok,
            ollama_msg=ollama_msg,
            llm_provider=config.LLM_PROVIDER,
            llm_chat_model=chat_model_name(),
            llm_embed_model=embed_model_name(),
        )

    @app.get("/analysis/<job_id>")
    def analysis_page(job_id: str):
        job = store.get_job(job_id)
        if not job:
            return "Job not found", 404
        recent = (
            store.list_saved_analyses(store.analysis_history_keep())
            if llm_enabled()
            else []
        )
        return render_template("analysis.html", job=job, recent_analyses=recent)

    @app.get("/api/analyses/recent")
    def api_analyses_recent():
        if not llm_enabled():
            return jsonify({"analyses": []})
        limit = request.args.get("limit", default=5, type=int)
        limit = max(1, min(limit, store.analysis_history_keep()))
        items = store.list_saved_analyses(limit)
        return jsonify({"analyses": items})

    @app.get("/api/analysis-schedules")
    def api_analysis_schedules_list():
        if not llm_enabled():
            return jsonify({"schedules": []})
        path = request.args.get("path", "").strip()
        if path:
            try:
                resolved = str(resolve_safe_path(path))
            except PermissionError as e:
                return jsonify({"error": str(e)}), 403
            one = store.get_analysis_schedule_for_path(resolved)
            return jsonify({"schedules": [one] if one else []})
        return jsonify({"schedules": store.list_analysis_schedules()})

    @app.put("/api/analysis-schedules")
    def api_analysis_schedules_upsert():
        if not llm_enabled():
            return jsonify({"error": "LLM features are disabled"}), 503
        body = request.get_json(silent=True) or {}
        path_str = (body.get("file_path") or "").strip()
        if not path_str:
            return jsonify({"error": "file_path required"}), 400
        try:
            path = resolve_safe_path(path_str)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        if not path.is_file():
            return jsonify({"error": f"Not a file: {path}"}), 404
        body = {**body, "file_path": str(path.resolve())}
        _, err = _validate_alert_rule_body(body)
        if err:
            return err
        try:
            sched = store.upsert_analysis_schedule(body)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        if analysis_scheduler:
            analysis_scheduler.reload()
        return jsonify(sched)

    @app.delete("/api/analysis-schedules/<schedule_id>")
    def api_analysis_schedules_delete(schedule_id: str):
        if not llm_enabled():
            return jsonify({"error": "LLM features are disabled"}), 503
        if not store.delete_analysis_schedule(schedule_id):
            return jsonify({"error": "not found"}), 404
        if analysis_scheduler:
            analysis_scheduler.reload()
        return jsonify({"ok": True})

    @app.get("/api/health")
    def api_health():
        from log_intel.syslogb.app.tail_service import check_log_dirs_access

        ok, msg = health_check()
        dir_ok, dir_msg = check_log_dirs_access(log_dirs())
        journal = tail_service.journal_status
        return jsonify({
            "version": config.APP_VERSION,
            "auth_enabled": auth_required(),
            "log_dirs": [str(d) for d in log_dirs()],
            "llm_enabled": llm_enabled(),
            "ollama_ok": ok,
            "ollama_msg": msg,
            "llm_provider": config.LLM_PROVIDER,
            "llm_chat_model": chat_model_name(),
            "llm_embed_model": embed_model_name(),
            "log_dir_ok": dir_ok,
            "log_dir_msg": dir_msg,
            "journal_ok": journal.get("ok", False),
            "journal_msg": journal.get("message", ""),
        })

    @app.get("/api/files")
    def api_files():
        return jsonify({
            "files": tail_service.watched_files(),
            "log_dirs": log_dirs_info(),
            "groups": tail_service.log_groups(),
        })

    @app.get("/api/stream")
    def api_stream():
        order = request.args.get("order", config.TAIL_DEFAULT_ORDER)
        if order not in ("asc", "desc"):
            order = config.TAIL_DEFAULT_ORDER
        importance_min = _importance_min_arg()
        source: str | None = request.args.get("source") or None
        if source:
            try:
                source = str(resolve_safe_path(source))
            except PermissionError:
                return jsonify({"error": "invalid source path"}), 403

        def generate():
            columnizers = store.list_columnizers()
            q = tail_service.subscribe_sse()
            try:
                for event in tail_service.buffer.snapshot(order, source=source):
                    ev_dict = event.to_dict()
                    if not meets_importance_min(ev_dict.get("line", ""), importance_min):
                        continue
                    ev = enrich_event(
                        ev_dict,
                        resolve_columnizer(ev_dict.get("source", ""), columnizers),
                    )
                    yield f"data: {json.dumps(ev)}\n\n"
                while True:
                    try:
                        payload = q.get(timeout=15)
                        data = json.loads(payload)
                        if source and data.get("source") != source:
                            continue
                        if not meets_importance_min(data.get("line", ""), importance_min):
                            continue
                        data = enrich_event(
                            data,
                            resolve_columnizer(data.get("source", ""), columnizers),
                        )
                        yield f"data: {json.dumps(data)}\n\n"
                    except queue.Empty:
                        yield ": keepalive\n\n"
            finally:
                tail_service.unsubscribe_sse(q)

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/file/meta")
    def api_file_meta():
        path_str = request.args.get("path", "")
        if not path_str:
            return jsonify({"error": "path required"}), 400
        try:
            path = resolve_safe_path(path_str)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        if is_journal_source(path_str):
            meta = journal_meta(path_str)
            if meta.get("error"):
                return jsonify(meta), 404
            return jsonify(meta)
        meta = file_meta(path)
        if meta.get("error"):
            return jsonify(meta), 404
        return jsonify(meta)

    @app.get("/api/file/page")
    def api_file_page():
        path_str = request.args.get("path", "")
        direction = request.args.get("direction", "tail").lower()
        order = request.args.get("order", config.TAIL_DEFAULT_ORDER)
        failures_only = request.args.get("failures_only", "0").lower() in (
            "1", "true", "yes", "on"
        )
        importance_min = _importance_min_arg()
        if not path_str:
            return jsonify({"error": "path required"}), 400
        if direction not in ("tail", "older", "newer", "forward"):
            return jsonify({"error": "invalid direction"}), 400
        try:
            path = resolve_safe_path(path_str)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        window = request.args.get("window", "").strip()
        since_ts = window_to_since_ts(window) if direction == "tail" else None
        if is_journal_source(path_str):
            page, err = read_journal_file_page(
                path_str,
                direction=direction,
                failures_only=failures_only,
                since_ts=since_ts,
            )
        else:
            if not path.is_file():
                return jsonify({"error": f"Not a file: {path}"}), 404
            page, err = read_file_page(
                path,
                direction=direction,
                before_byte=request.args.get("before_byte", type=int),
                after_byte=request.args.get("after_byte", type=int),
                before_line=request.args.get("before_line", type=int),
                after_line=request.args.get("after_line", type=int),
                failures_only=failures_only,
                since_ts=since_ts,
            )
        if err:
            return jsonify({"error": err}), 403
        events = filter_events_by_importance(page.get("events", []), importance_min)
        reverse = order != "asc"
        events.sort(key=lambda e: e["received_at"], reverse=reverse)
        page["events"] = _enrich_events(events, store)
        page["failures_only"] = failures_only
        page["importance_min"] = importance_min
        if window:
            page["window"] = window
        if since_ts is not None:
            page["window_since"] = since_ts
        return jsonify(page)

    @app.get("/api/file/recent")
    def api_file_recent():
        path_str = request.args.get("path", "")
        order = request.args.get("order", config.TAIL_DEFAULT_ORDER)
        failures_only = request.args.get("failures_only", "0").lower() in (
            "1", "true", "yes", "on"
        )
        importance_min = _importance_min_arg()
        if not path_str:
            return jsonify({"error": "path required"}), 400
        try:
            path = resolve_safe_path(path_str)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        window = request.args.get("window", "").strip()
        since_ts = window_to_since_ts(window)
        if is_journal_source(path_str):
            page, err = read_journal_file_page(
                path_str,
                direction="tail",
                failures_only=failures_only,
                since_ts=since_ts,
            )
            if err:
                return jsonify({"error": err, "events": []}), 403
            events = filter_events_by_importance(page.get("events", []), importance_min)
            reverse = order != "asc"
            events.sort(key=lambda e: e["received_at"], reverse=reverse)
            payload = {
                "path": path_str,
                "events": _enrich_events(events, store),
                "failures_only": failures_only,
                "importance_min": importance_min,
                **_paging_fields(page),
            }
            if window:
                payload["window"] = window
            if since_ts is not None:
                payload["window_since"] = since_ts
            return jsonify(payload)
        if not path.is_file():
            return jsonify({"error": f"Not a file: {path}"}), 404
        page, err = read_file_page(
            path,
            direction="tail",
            failures_only=failures_only,
            since_ts=since_ts,
        )
        if err:
            return jsonify({"error": err, "events": []}), 403
        events = filter_events_by_importance(page.get("events", []), importance_min)
        reverse = order != "asc"
        events.sort(key=lambda e: e["received_at"], reverse=reverse)
        payload = {
            "path": str(path),
            "events": _enrich_events(events, store),
            "failures_only": failures_only,
            "importance_min": importance_min,
            **_paging_fields(page),
        }
        if window:
            payload["window"] = window
        if since_ts is not None:
            payload["window_since"] = since_ts
        return jsonify(payload)

    @app.get("/api/file/full")
    def api_file_full():
        """Full tail window for LogExpert-style split view (file line order)."""
        path_str = request.args.get("path", "")
        if not path_str:
            return jsonify({"error": "path required"}), 400
        try:
            path = resolve_safe_path(path_str)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        if is_journal_source(path_str):
            events, err = read_journal_page(
                path_str,
                direction="tail",
                max_lines=config.JOURNAL_SEARCH_LINES,
            )
            if err:
                return jsonify({"error": err, "events": []}), 403
            events.sort(key=lambda e: e.get("line_index", 0))
            return jsonify({
                "path": path_str,
                "events": _enrich_events(events, store),
            })
        if not path.is_file():
            return jsonify({"error": f"Not a file: {path}"}), 404
        events, err = full_log_lines(path)
        if err:
            return jsonify({"error": err, "events": []}), 403
        events.sort(key=lambda e: e.get("line_index", 0))
        read_from = events[0]["read_from"] if events else 0
        events = _enrich_events(events, store)
        return jsonify({
            "path": str(path),
            "read_from": read_from,
            "events": events,
        })

    @app.get("/api/search")
    def api_search():
        query = request.args.get("q", "").strip()
        mode = request.args.get("mode", "text").lower()
        if mode not in ("text", "regex"):
            return jsonify({"error": "mode must be text or regex"}), 400
        order = request.args.get("order", config.TAIL_DEFAULT_ORDER)
        path_str = request.args.get("path", "").strip()
        log_dir_str = request.args.get("log_dir", "").strip()
        path = None
        log_dir = None
        localhost_only = False
        if path_str:
            try:
                path = resolve_safe_path(path_str)
            except PermissionError as e:
                return jsonify({"error": str(e)}), 403
        elif log_dir_str:
            try:
                log_dir, localhost_only = resolve_log_dir_scope(log_dir_str)
            except PermissionError as e:
                return jsonify({"error": str(e)}), 403
        try:
            events, err = search_logs(
                query,
                mode,
                path=path,
                log_dir=log_dir,
                localhost_only=localhost_only,
                order=order,
                importance_min=_importance_min_arg(),
            )
        except ValueError as e:
            return jsonify({"error": str(e), "events": []}), 400
        if err:
            return jsonify({"error": err, "events": []}), 400
        return jsonify({
            "query": query,
            "mode": mode,
            "path": str(path) if path else None,
            "log_dir": str(log_dir) if log_dir else None,
            "count": len(events),
            "highlight_terms": search_highlight_terms(query, mode) if mode == "text" else [],
            "importance_min": _importance_min_arg(),
            "events": _enrich_events(events, store),
        })

    @app.get("/api/saved-searches")
    def api_saved_searches_list():
        return jsonify({"searches": store.list_saved_searches()})

    @app.post("/api/saved-searches")
    def api_saved_searches_upsert():
        body = request.get_json(silent=True) or {}
        name = str(body.get("name", "")).strip()
        query = str(body.get("query", "")).strip()
        if not name or not query:
            return jsonify({"error": "name and query required"}), 400
        mode = str(body.get("mode", "text")).lower()
        if mode not in ("text", "regex"):
            return jsonify({"error": "mode must be text or regex"}), 400
        scope = str(body.get("scope", "all"))
        saved = store.upsert_saved_search({
            "id": body.get("id"),
            "name": name,
            "query": query,
            "mode": mode,
            "scope": scope,
            "log_dir": body.get("log_dir"),
            "file_path": body.get("file_path"),
        })
        return jsonify(saved)

    @app.delete("/api/saved-searches/<search_id>")
    def api_saved_searches_delete(search_id: str):
        if store.delete_saved_search(search_id):
            return jsonify({"ok": True})
        return jsonify({"error": "not found"}), 404

    @app.post("/api/explain")
    def api_explain():
        if not llm_enabled():
            return jsonify({"error": "LLM features are disabled"}), 503
        body = request.get_json(silent=True) or {}
        line = str(body.get("line", "")).strip()
        question = str(body.get("question", "")).strip()
        source = str(body.get("source", "")).strip()
        if not line:
            return jsonify({"error": "line required"}), 400
        if source:
            try:
                resolve_safe_path(source)
            except PermissionError as e:
                return jsonify({"error": str(e)}), 403
        try:
            result, raw = explain_log_entry(line, question=question, source=source)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        return jsonify({"result": result, "raw": raw})

    @app.post("/api/analyze")
    def api_analyze():
        if not llm_enabled():
            return jsonify({"error": "LLM features are disabled"}), 503
        body = request.get_json(silent=True) or {}
        path_str = body.get("path", "")
        if not path_str:
            return jsonify({"error": "path required"}), 400
        scope = (body.get("scope") or "full").strip().lower()
        window = (body.get("window") or "").strip().lower()
        if scope not in ("full", "window"):
            return jsonify({"error": "scope must be 'full' or 'window'"}), 400
        if scope == "window" and not window:
            window = "1h"
        if is_journal_source(path_str):
            if scope == "full":
                return jsonify({"error": "Full journal analysis is not supported; use scope=window"}), 400
            if scope != "window":
                return jsonify({"error": "Journal sources require scope=window"}), 400
            job_mode = f"window:{window or '1h'}"
            job_id = store.create_job(path_str, mode=job_mode)
            worker.enqueue(job_id, path_str, window=window or "1h")
            return jsonify({"job_id": job_id, "status": "pending", "scope": scope, "window": window or "1h"})
        try:
            path = resolve_safe_path(path_str)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        if not path.is_file():
            return jsonify({"error": f"Not a file: {path}"}), 404
        job_mode = f"window:{window}" if scope == "window" else "full"
        job_id = store.create_job(str(path), mode=job_mode)
        worker.enqueue(job_id, path, window=window if scope == "window" else None)
        return jsonify({"job_id": job_id, "status": "pending", "scope": scope, "window": window or None})

    @app.get("/api/analyze/<job_id>")
    def api_analyze_status(job_id: str):
        job = store.get_job(job_id)
        if not job:
            return jsonify({"error": "not found"}), 404
        return jsonify(job)

    @app.delete("/api/analyze/<job_id>")
    def api_analyze_cancel(job_id: str):
        if not llm_enabled():
            return jsonify({"error": "LLM features are disabled"}), 503
        if not store.cancel_job(job_id):
            job = store.get_job(job_id)
            if not job:
                return jsonify({"error": "not found"}), 404
            return jsonify({"error": "job cannot be cancelled", "status": job["status"]}), 409
        return jsonify({"job_id": job_id, "status": "cancelled"})

    @app.get("/settings")
    def settings_page():
        if not can_access_settings(store):
            return "Forbidden", 403
        setup_mode = request.args.get("setup") == "1" or not is_setup_complete(store)
        return render_template(
            "settings.html",
            setup_mode=setup_mode,
            setup_complete=is_setup_complete(store),
        )

    @app.get("/alerts")
    def alerts_page():
        return render_template("alerts.html")

    @app.get("/api/setup/status")
    def api_setup_status():
        return jsonify({"setup_complete": is_setup_complete(store)})

    @app.post("/api/setup/skip")
    def api_setup_skip():
        if not is_setup_complete(store):
            store.mark_setup_complete()
        return jsonify({"ok": True, "redirect": url_for("index")})

    @app.get("/api/settings")
    def api_settings_get():
        if not can_access_settings(store):
            return jsonify({"error": "forbidden"}), 403
        return jsonify({
            "sections": store.list_settings_grouped(),
            "setup_complete": is_setup_complete(store),
        })

    @app.put("/api/settings")
    def api_settings_put():
        if not can_access_settings(store):
            return jsonify({"error": "forbidden"}), 403
        body = request.get_json(silent=True) or {}
        updates = body.get("settings") or {}
        if not isinstance(updates, dict):
            return jsonify({"error": "settings object required"}), 400
        updates = {str(k): str(v) for k, v in updates.items()}
        if body.get("complete_setup"):
            from log_intel.syslogb.app.runtime_config import effective_value
            auth_on, _ = effective_value("AUTH_ENABLED", store)
            if auth_on.lower() in ("1", "true", "yes", "on"):
                sk, _ = effective_value("FLASK_SECRET_KEY", store)
                if not sk and "FLASK_SECRET_KEY" not in updates:
                    updates["FLASK_SECRET_KEY"] = secrets.token_hex(32)
        store.set_many(updates)
        from log_intel.settings_bridge import refresh_all_settings

        refresh_all_settings(store)
        app.secret_key = config.FLASK_SECRET_KEY.strip() or "dev-insecure-change-me"
        try:
            from log_intel.main import reconfigure_hub_llm_workers, reconfigure_mist_poller

            reconfigure_hub_llm_workers()
            reconfigure_mist_poller()
        except Exception:
            logger.exception("Failed to reconfigure hub workers after settings save")
        if body.get("complete_setup"):
            store.mark_setup_complete()
        return jsonify({
            "ok": True,
            "setup_complete": is_setup_complete(store),
            "sections": store.list_settings_grouped(),
        })

    @app.post("/api/settings/reload")
    def api_settings_reload():
        if not can_access_settings(store):
            return jsonify({"error": "forbidden"}), 403
        from log_intel.settings_bridge import refresh_all_settings
        from log_intel.syslogb.app.timestamp_parsers import refresh_parsers_cache

        refresh_all_settings(store)
        refresh_parsers_cache(store.list_timestamp_parsers())
        ok, msg = tail_service.reload()
        alert_engine.reload_rules()
        try:
            from log_intel.main import reconfigure_hub_llm_workers, reconfigure_mist_poller

            reconfigure_hub_llm_workers()
            reconfigure_mist_poller()
        except Exception:
            logger.exception("Failed to reconfigure hub workers after settings reload")
        return jsonify({"ok": ok, "message": msg})

    @app.get("/api/columnizers")
    def api_columnizers_list():
        return jsonify({"columnizers": store.list_columnizers()})

    @app.put("/api/columnizers")
    def api_columnizers_upsert():
        if not is_settings_admin():
            return jsonify({"error": "forbidden"}), 403
        body = request.get_json(silent=True) or {}
        col = store.upsert_columnizer(body)
        return jsonify(col)

    @app.delete("/api/columnizers/<cid>")
    def api_columnizers_delete(cid: str):
        if not is_settings_admin():
            return jsonify({"error": "forbidden"}), 403
        if not store.delete_columnizer(cid):
            return jsonify({"error": "not found or builtin"}), 404
        return jsonify({"ok": True})

    @app.get("/api/timestamp-parsers")
    def api_timestamp_parsers_list():
        return jsonify({"timestamp_parsers": store.list_timestamp_parsers()})

    @app.put("/api/timestamp-parsers")
    def api_timestamp_parsers_upsert():
        if not is_settings_admin():
            return jsonify({"error": "forbidden"}), 403
        from log_intel.syslogb.app.timestamp_parsers import refresh_parsers_cache

        body = request.get_json(silent=True) or {}
        parser = store.upsert_timestamp_parser(body)
        refresh_parsers_cache(store.list_timestamp_parsers())
        return jsonify(parser)

    @app.delete("/api/timestamp-parsers/<pid>")
    def api_timestamp_parsers_delete(pid: str):
        if not is_settings_admin():
            return jsonify({"error": "forbidden"}), 403
        from log_intel.syslogb.app.timestamp_parsers import refresh_parsers_cache

        if not store.delete_timestamp_parser(pid):
            return jsonify({"error": "not found or builtin"}), 404
        refresh_parsers_cache(store.list_timestamp_parsers())
        return jsonify({"ok": True})

    @app.get("/api/alert-rules")
    def api_alert_rules_list():
        ustore = _unified_alert_store(store)
        return jsonify({"rules": ustore.list_alert_rules()})

    @app.put("/api/alert-rules")
    def api_alert_rules_upsert():
        if not is_settings_admin():
            return jsonify({"error": "forbidden"}), 403
        body = request.get_json(silent=True) or {}
        _, err = _validate_alert_rule_body(body)
        if err:
            return err
        ustore = _unified_alert_store(store)
        uengine = _unified_alert_engine(alert_engine)
        rid = ustore.upsert_alert_rule(body)
        uengine.reload_rules()
        rules = {r["id"]: r for r in ustore.list_alert_rules()}
        return jsonify(rules.get(rid, {"id": rid}))

    @app.delete("/api/alert-rules/<rid>")
    def api_alert_rules_delete(rid: str):
        if not is_settings_admin():
            return jsonify({"error": "forbidden"}), 403
        ustore = _unified_alert_store(store)
        uengine = _unified_alert_engine(alert_engine)
        if not ustore.delete_alert_rule(rid):
            return jsonify({"error": "not found"}), 404
        uengine.reload_rules()
        return jsonify({"ok": True})

    @app.post("/api/alert-rules/<rid>/test")
    def api_alert_rules_test(rid: str):
        if not is_settings_admin():
            return jsonify({"error": "forbidden"}), 403
        uengine = _unified_alert_engine(alert_engine)
        try:
            return jsonify(uengine.send_test(rid))
        except ValueError as e:
            return jsonify({"error": str(e)}), 404

    @app.get("/api/alert-events")
    def api_alert_events():
        limit = request.args.get("limit", 100, type=int)
        return jsonify({"events": store.list_alert_events(limit=limit)})

    @app.get("/api/export")
    def api_export():
        source = request.args.get("source", "search")
        fmt = request.args.get("format", "txt").lower()
        if fmt not in ("txt", "csv", "jsonl"):
            return jsonify({"error": "format must be txt, csv, or jsonl"}), 400
        order = request.args.get("order", config.TAIL_DEFAULT_ORDER)
        try:
            if source == "file":
                path_str = request.args.get("path", "")
                if not path_str:
                    return jsonify({"error": "path required"}), 400
                path = resolve_safe_path(path_str)
                failures_only = request.args.get("failures_only", "0").lower() in (
                    "1", "true", "yes", "on"
                )
                events = collect_file_events(
                    path, failures_only=failures_only, order=order, store=store
                )
            elif source == "search":
                query = request.args.get("q", "").strip()
                mode = request.args.get("mode", "text").lower()
                path_str = request.args.get("path", "").strip()
                log_dir_str = request.args.get("log_dir", "").strip()
                path = None
                log_dir = None
                localhost_only = False
                if path_str:
                    path = resolve_safe_path(path_str)
                elif log_dir_str:
                    log_dir, localhost_only = resolve_log_dir_scope(log_dir_str)
                events = collect_search_events(
                    query,
                    mode,
                    path=path,
                    log_dir=log_dir,
                    localhost_only=localhost_only,
                    order=order,
                    store=store,
                )
            else:
                return jsonify({"error": "source must be search or file"}), 400
        except (ValueError, PermissionError) as e:
            return jsonify({"error": str(e)}), 400

        if fmt == "txt":
            gen = stream_txt(events)
            mime = "text/plain"
        elif fmt == "csv":
            gen = stream_csv(events)
            mime = "text/csv"
        else:
            gen = stream_jsonl(events)
            mime = "application/x-ndjson"
        return Response(gen, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="syslogb-export.{fmt}"'
        })

    @app.get("/api/jobs")
    def api_jobs():
        return jsonify({"jobs": store.list_jobs()})

    return app


def run_flask(
    tail_service: TailService,
    store: AppStore,
    worker: AnalyzeWorker,
    alert_engine,
    analysis_scheduler=None,
) -> None:
    app = create_app(
        tail_service, store, worker, alert_engine, analysis_scheduler
    )
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        threaded=True,
        use_reloader=False,
    )
