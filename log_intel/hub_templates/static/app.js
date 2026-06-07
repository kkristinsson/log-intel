/* log-intel unified dashboard */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function fmtTs(ts) {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleString();
}

function renderLine(container, item, cls = "") {
  const div = document.createElement("div");
  div.className = `log-line ${cls} ${item.importance || ""}`;
  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = [
    item.origin || item.source_type || "hub",
    fmtTs(item.received_at || item.ts),
    item.remote_ip,
    item.log_type,
    item.action,
  ].filter(Boolean).join(" · ");
  const body = document.createElement("div");
  body.textContent = item.message || item.line || JSON.stringify(item);
  div.append(meta, body);
  container.prepend(div);
  while (container.children.length > 300) {
    container.removeChild(container.lastChild);
  }
}

async function loadHealth() {
  const r = await fetch("/health");
  const data = await r.json();
  const cards = $("#health-cards");
  cards.innerHTML = "";
  const add = (title, value, ok) => {
    const c = document.createElement("div");
    c.className = `card ${ok ? "ok" : "bad"}`;
    c.innerHTML = `<h3>${title}</h3><div class="value">${value}</div>`;
    cards.appendChild(c);
  };
  add("Events stored", data.adapters?.events_stored ?? "—", true);
  add("Ollama", data.ollama?.ok ? "OK" : "Down", data.ollama?.ok);
  add("syslogb", data.adapters?.syslogb?.integrated ? "Integrated" : (data.adapters?.syslogb?.ok ? "OK" : "N/A"), true);
  add("loggy archive", data.adapters?.loggy?.ok ? "OK" : "N/A", data.adapters?.loggy?.ok);
  add("netsyslog archive", data.adapters?.netsyslog?.ok ? "OK" : "N/A", data.adapters?.netsyslog?.ok);
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
  liveSource = new EventSource(`/api/v1/stream?importance_min=${imp}`);
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
  const r = await fetch(
    `/api/v1/search?q=${encodeURIComponent(q)}&include_syslogb=${syslogb}&include_loggy=${loggy}`
  );
  const data = await r.json();
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

async function loadAlerts() {
  const r = await fetch("/api/v1/alert-events?limit=100");
  const data = await r.json();
  const box = $("#alert-events");
  box.innerHTML = "";
  for (const ev of data.events || []) {
    renderLine(box, { message: ev.line, origin: ev.origin, ts: ev.ts, importance: "warning" });
  }
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
    if (btn.dataset.tab === "alerts") loadAlerts();
  });
});

$("#live-importance").addEventListener("change", startLive);
$("#search-form").addEventListener("submit", doSearch);
$("#fw-refresh").addEventListener("click", loadFirewall);
$("#geo-refresh").addEventListener("click", loadGeo);
$("#analyze-form").addEventListener("submit", runAnalyze);

loadHealth();
loadOverviewEvents();
setInterval(loadHealth, 60000);

const bootTab = window.__HUB_ACTIVE_TAB__;
if (bootTab && bootTab !== "overview") {
  const btn = document.querySelector(`#tabs button[data-tab="${bootTab}"]`);
  if (btn) btn.click();
}
