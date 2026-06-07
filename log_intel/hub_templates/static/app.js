/* log-intel unified dashboard */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function fmtTs(ts) {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleString();
}

function renderLine(container, item, cls = "") {
  const div = document.createElement("div");
  const sev = item.llm_severity || item.severity;
  div.className = `log-line ${cls} ${item.importance || ""} ${sev ? `sev-${sev}` : ""}`;
  const meta = document.createElement("div");
  meta.className = "meta";
  const parts = [
    item.origin || item.source_type || "hub",
    item.source,
    fmtTs(item.received_at || item.ts),
    item.remote_ip,
    item.log_type,
    item.action,
  ].filter(Boolean);
  if (sev) parts.push(`LLM:${sev}`);
  meta.textContent = parts.join(" · ");
  const body = document.createElement("div");
  body.textContent = item.message || item.line || item.summary || JSON.stringify(item);
  div.append(meta, body);
  container.prepend(div);
  while (container.children.length > 300) {
    container.removeChild(container.lastChild);
  }
}

async function loadHealth() {
  const r = await fetch("/health");
  const data = await r.json();
  if (data.ui) applyUiFeatures(data.ui);
  const cards = $("#health-cards");
  cards.innerHTML = "";
  const ui = data.ui || window.__HUB_UI_FEATURES__ || {};
  const add = (title, value, ok) => {
    const c = document.createElement("div");
    c.className = `card ${ok ? "ok" : "bad"}`;
    c.innerHTML = `<h3>${title}</h3><div class="value">${value}</div>`;
    cards.appendChild(c);
  };
  add("Events stored", data.adapters?.events_stored ?? "—", true);
  if (ui.hub_health_ollama !== false) {
    add("Ollama", data.ollama?.ok ? "OK" : "Down", data.ollama?.ok);
  }
  add("File logs", data.adapters?.syslogb?.integrated ? "Integrated" : (data.adapters?.syslogb?.ok ? "OK" : "N/A"), true);
  if (ui.hub_health_loggy) {
    add("loggy archive", data.adapters?.loggy?.ok ? "OK" : "N/A", data.adapters?.loggy?.ok);
  }
  if (ui.hub_health_netsyslog) {
    add("netsyslog archive", data.adapters?.netsyslog?.ok ? "OK" : "N/A", data.adapters?.netsyslog?.ok);
  }
  if (ui.hub_health_mist) {
    const mist = data.adapters?.mist || {};
    const mistOk = mist.ok || mist.configured;
    add("Juniper Mist", mistOk ? "OK" : "Off", !!mistOk);
  }
  const journalOk = data.adapters?.ingest?.journal_ok ?? data.journal_ok;
  if (ui.hub_health_journal && journalOk !== undefined) {
    add("systemd journal", journalOk ? "OK" : "Off", !!journalOk);
  }
}

function applyUiFeatures(ui) {
  if (!ui) return;
  window.__HUB_UI_FEATURES__ = ui;
  document.querySelectorAll("[data-ui-feature]").forEach((el) => {
    const key = el.dataset.uiFeature;
    el.classList.toggle("hidden", !ui[key]);
  });
  const activeTabBtn = document.querySelector("#tabs button.active");
  if (activeTabBtn?.classList.contains("hidden")) {
    document.querySelector('#tabs button[data-tab="overview"]')?.click();
  }
  const activeAnalysisBtn = document.querySelector(".analysis-subtabs button.active");
  if (activeAnalysisBtn?.classList.contains("hidden")) {
    const first = document.querySelector(".analysis-subtabs button:not(.hidden)");
    if (first) showAnalysisPane(first.dataset.analysis);
  }
}

async function loadOverviewEvents() {
  const r = await fetch("/api/v1/events?hours=24&limit=30");
  const data = await r.json();
  const box = $("#overview-events");
  box.innerHTML = "";
  for (const ev of data.events || []) {
    const imp = (ev.action === "deny" || ev.log_type === "THREAT") ? "error" : "info";
    renderLine(box, { ...ev, importance: imp });
  }
}

let liveSource = null;
function startLive() {
  if (liveSource) liveSource.close();
  const imp = $("#live-importance").value;
  const syslogb = $("#include-syslogb-live")?.checked ? "true" : "false";
  liveSource = new EventSource(
    `/api/v1/stream?importance_min=${imp}&include_syslogb=${syslogb}`
  );
  const box = $("#live-feed");
  liveSource.onmessage = (e) => {
    const ev = JSON.parse(e.data);
    renderLine(box, ev, ev.importance);
  };
}

async function doSearch(e) {
  e.preventDefault();
  const q = $("#search-q").value.trim();
  if (!q) return;
  const syslogb = $("#include-syslogb").checked;
  const loggy = $("#include-loggy").checked;
  const mode = $("#search-mode").value;
  const hours = $("#search-hours").value;
  const r = await fetch(
    `/api/v1/search?q=${encodeURIComponent(q)}&mode=${mode}&hours=${hours}` +
    `&include_syslogb=${syslogb}&include_loggy=${loggy}`
  );
  const data = await r.json();
  const meta = $("#search-meta");
  if (meta) {
    const parts = Object.entries(data.counts_by_origin || {}).map(
      ([k, v]) => `${k}: ${v}`
    );
    meta.textContent = parts.length ? `Matches — ${parts.join(", ")}` : "";
  }
  const box = $("#search-results");
  box.innerHTML = "";
  for (const item of data.results || []) {
    renderLine(box, item);
  }
}

async function loadFirewall() {
  const hours = $("#fw-hours").value;
  const logType = $("#fw-log-type").value;
  const r = await fetch(`/api/v1/firewall?hours=${hours}&log_type=${logType}&limit=100`);
  const data = await r.json();
  const box = $("#firewall-table");
  box.innerHTML = "";
  for (const ev of data.events || []) {
    renderLine(box, ev);
  }
}

async function loadMist() {
  const hours = $("#mist-hours").value;
  const r = await fetch(`/api/v1/mist?hours=${hours}`);
  const data = await r.json();
  const status = $("#mist-status");
  if (status) {
    const poller = data.poller || {};
    const parts = [`${data.count ?? (data.events || []).length} event(s) in window`];
    if (poller.last_poll_at) {
      parts.push(`last poll ${fmtTs(poller.last_poll_at)}`);
    }
    if (poller.last_inserted != null) {
      parts.push(`+${poller.last_inserted} on last poll`);
    }
    if (poller.last_error) {
      parts.push(`error: ${poller.last_error}`);
    }
    status.textContent = parts.join(" · ");
  }
  const box = $("#mist-table");
  box.innerHTML = "";
  for (const ev of data.events || []) {
    renderLine(box, ev);
  }
}

let map, mapLayer;
function initMap() {
  if (map) return;
  map = L.map("map").setView([20, 0], 2);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: "&copy; OSM & Carto",
  }).addTo(map);
  mapLayer = L.layerGroup().addTo(map);
}

async function loadGeo() {
  initMap();
  const hours = $("#geo-hours").value;
  const r = await fetch(`/api/v1/flows?hours=${hours}&limit=500`);
  const data = await r.json();
  mapLayer.clearLayers();
  for (const e of data.edges || []) {
    if (e.src_lat == null || e.dst_lat == null) continue;
    const line = L.polyline(
      [[e.src_lat, e.src_lon], [e.dst_lat, e.dst_lon]],
      { weight: Math.min(8, 1 + Math.log10((e.cnt || 1) + 1)), opacity: 0.7 }
    );
    line.bindPopup(`${e.src_ip} → ${e.dst_ip}<br>count: ${e.cnt}`);
    mapLayer.addLayer(line);
  }
}

async function loadAlertRules() {
  const r = await fetch("/api/v1/alert-rules");
  const data = await r.json();
  const box = $("#alert-rules-list");
  if (!box) return;
  box.innerHTML = "";
  for (const rule of data.rules || []) {
    const div = document.createElement("div");
    div.className = "log-line";
    div.innerHTML = `<div class="meta">${rule.name} · ${rule.mode} · ${rule.scope} · ${rule.enabled ? "on" : "off"}</div>` +
      `<div>${rule.query}</div>`;
    box.appendChild(div);
  }
}

async function saveAlertRule(e) {
  e.preventDefault();
  const body = {
    id: $("#alert-rule-id").value || undefined,
    name: $("#alert-rule-name").value.trim(),
    query: $("#alert-rule-query").value.trim(),
    mode: $("#alert-rule-mode").value,
    scope: $("#alert-rule-scope").value,
    webhook_url: $("#alert-rule-webhook").value.trim() || null,
    enabled: $("#alert-rule-enabled").checked,
  };
  await fetch("/api/v1/alert-rules", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  await loadAlertRules();
}

async function loadAlerts() {
  await loadAlertRules();
  const r = await fetch("/api/v1/alert-events?limit=100");
  const data = await r.json();
  const box = $("#alert-events");
  box.innerHTML = "";
  for (const ev of data.events || []) {
    renderLine(box, {
      message: ev.line,
      origin: ev.origin,
      ts: ev.ts,
      importance: ev.status === "sent" ? "warning" : "info",
    });
  }
}

async function loadAnalysisHourly() {
  const hours = $("#analysis-hours")?.value || 168;
  const r = await fetch(`/hub/api/analyses/recent?hours=${hours}`);
  const data = await r.json();
  const box = $("#analysis-cards");
  if (!box) return;
  box.innerHTML = "";
  for (const a of data.analyses || []) {
    renderLine(box, {
      severity: a.severity,
      summary: a.summary,
      ts: a.created_at,
      importance: a.severity === "critical" || a.severity === "high" ? "error" : "info",
    });
  }
  const st = await fetch("/hub/api/analyze/status");
  const status = await st.json();
  const out = $("#analysis-status");
  if (out) {
    out.textContent = `Pending ${data.pending_in_window} · ${status.state}: ${status.message || ""}`;
  }
}

async function loadTrends() {
  const days = $("#trends-days")?.value || 14;
  const r = await fetch(`/hub/api/trends/daily?days=${days}`);
  const data = await r.json();
  const meta = $("#trends-meta");
  if (meta) {
    meta.textContent = `${data.baseline?.title || ""} — ${data.narrative || ""}`;
  }
  const box = $("#trends-bars");
  if (!box) return;
  box.innerHTML = "";
  for (const row of data.rows || []) {
    const div = document.createElement("div");
    div.className = "log-line";
    div.textContent = `${row.day}: ${row.analyses_total} analyses, elevated ${row.elevated_total}`;
    box.appendChild(div);
  }
}

async function startWindowAnalysis() {
  const hours = parseFloat($("#analysis-hours")?.value || 24);
  await fetch("/hub/api/analyze/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hours }),
  });
  const poll = setInterval(async () => {
    await loadAnalysisHourly();
    const st = await fetch("/hub/api/analyze/status");
    const status = await st.json();
    if (status.state !== "running") clearInterval(poll);
  }, 3000);
}

async function cancelWindowAnalysis() {
  await fetch("/hub/api/analyze/cancel", { method: "POST" });
  loadAnalysisHourly();
}

function showAnalysisPane(name) {
  const ui = window.__HUB_UI_FEATURES__ || {};
  const featureKey = `hub_analysis_${name}`;
  if (ui[featureKey] === false) {
    const first = document.querySelector(".analysis-subtabs button:not(.hidden)");
    if (first) name = first.dataset.analysis;
  }
  $$(".analysis-pane").forEach((p) => p.classList.remove("active"));
  $$(".analysis-subtabs button").forEach((b) => b.classList.remove("active"));
  $(`#analysis-${name}`)?.classList.add("active");
  $(`.analysis-subtabs button[data-analysis="${name}"]`)?.classList.add("active");
  if (name === "hourly") loadAnalysisHourly();
  if (name === "trends") loadTrends();
}

async function runAnalyze(e) {
  e.preventDefault();
  const raw = $("#analyze-ids").value.trim();
  const ids = raw.split(/[\s,]+/).map((x) => parseInt(x, 10)).filter((n) => !isNaN(n));
  if (!ids.length) return;
  const r = await fetch("/api/v1/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event_ids: ids }),
  });
  const { job_id } = await r.json();
  const out = $("#analyze-result");
  out.textContent = `Job ${job_id} running…`;
  const poll = async () => {
    const jr = await fetch(`/api/v1/analyze/${job_id}`);
    const job = await jr.json();
    if (job.status === "pending" || job.status === "running") {
      setTimeout(poll, 2000);
      return;
    }
    out.textContent = JSON.stringify(job, null, 2);
  };
  poll();
}

$$("#tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$("#tabs button").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    $$(".panel").forEach((p) => p.classList.remove("active"));
    $(`#panel-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "live") startLive();
    if (btn.dataset.tab === "geo") { initMap(); loadGeo(); }
    if (btn.dataset.tab === "firewall") loadFirewall();
    if (btn.dataset.tab === "mist") loadMist();
    if (btn.dataset.tab === "alerts") loadAlerts();
    if (btn.dataset.tab === "analysis") showAnalysisPane("hourly");
  });
});

$$(".analysis-subtabs button").forEach((btn) => {
  btn.addEventListener("click", () => showAnalysisPane(btn.dataset.analysis));
});

$("#live-importance").addEventListener("change", startLive);
const syslogbLiveCb = $("#include-syslogb-live");
if (syslogbLiveCb) syslogbLiveCb.addEventListener("change", startLive);
$("#search-form").addEventListener("submit", doSearch);
$("#fw-refresh").addEventListener("click", loadFirewall);
$("#mist-refresh")?.addEventListener("click", loadMist);
$("#geo-refresh").addEventListener("click", loadGeo);
$("#analyze-form")?.addEventListener("submit", runAnalyze);
$("#alert-rule-form")?.addEventListener("submit", saveAlertRule);
$("#alert-rules-refresh")?.addEventListener("click", loadAlertRules);
$("#analysis-refresh")?.addEventListener("click", loadAnalysisHourly);
$("#analysis-start")?.addEventListener("click", startWindowAnalysis);
$("#analysis-cancel")?.addEventListener("click", cancelWindowAnalysis);
$("#trends-refresh")?.addEventListener("click", loadTrends);

loadHealth();
loadOverviewEvents();
setInterval(loadHealth, 60000);

applyUiFeatures(window.__HUB_UI_FEATURES__);

const bootTab = window.__HUB_ACTIVE_TAB__;
if (bootTab && bootTab !== "overview") {
  const btn = document.querySelector(`#tabs button[data-tab="${bootTab}"]`);
  if (btn && !btn.classList.contains("hidden")) btn.click();
}
