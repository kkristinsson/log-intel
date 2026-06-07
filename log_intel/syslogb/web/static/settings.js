(() => {
  const pageEl = document.querySelector(".settings-page");
  const setupMode = pageEl?.dataset.setupMode === "1";
  const sectionsEl = document.getElementById("settings-sections");
  const statusEl = document.getElementById("settings-status");
  const colList = document.getElementById("columnizers-list");
  const tsParserList = document.getElementById("timestamp-parsers-list");
  let timestampParsersCache = [];
  const rulesList = document.getElementById("alert-rules-list");
  const providerCards = document.getElementById("llm-provider-cards");
  const providerActive = document.getElementById("llm-provider-active");
  const providerPanel = document.getElementById("llm-provider-panel");
  let pending = {};
  let fieldInputs = {};
  let currentProvider = "ollama";

  const SECTION_ORDER = ["server", "logging", "search", "llm", "hub", "mist", "auth", "alerts", "branding"];
  const SECTION_LABELS = {
    server: "Server",
    logging: "Logging",
    search: "Search & export",
    llm: "LLM options",
    hub: "Hub & network syslog",
    mist: "Juniper Mist",
    auth: "Authentication",
    alerts: "Email alerts",
    branding: "Branding",
  };
  const OLLAMA_KEYS = new Set([
    "OLLAMA_BASE_URL", "OLLAMA_MODEL", "OLLAMA_EMBED_MODEL",
    "OLLAMA_TIMEOUT_SEC", "OLLAMA_EMBED_TIMEOUT_SEC", "OLLAMA_NUM_PREDICT", "OLLAMA_JSON_FORMAT",
  ]);
  const OLLAMA_CHAT_MODEL_KEY = "OLLAMA_MODEL";
  const OLLAMA_EMBED_KEYS = new Set([
    "OLLAMA_BASE_URL", "OLLAMA_EMBED_MODEL", "OLLAMA_EMBED_TIMEOUT_SEC",
  ]);
  const OPENAI_KEYS = new Set([
    "LLM_API_BASE_URL", "LLM_API_KEY", "LLM_CHAT_MODEL", "LLM_EMBED_MODEL",
  ]);
  const OPENAI_CHAT_KEYS = new Set([
    "LLM_API_BASE_URL", "LLM_API_KEY", "LLM_CHAT_MODEL",
  ]);
  const HIDDEN_IN_GRID = new Set(["LLM_PROVIDER"]);

  function normalizeProvider(value) {
    const p = String(value || "ollama").toLowerCase();
    if (p === "openai" || p === "hybrid") return p;
    return "ollama";
  }

  function esc(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function isFieldVisible(key) {
    if (HIDDEN_IN_GRID.has(key)) return false;
    if (currentProvider === "ollama") {
      return !OPENAI_KEYS.has(key);
    }
    if (currentProvider === "openai") {
      return OPENAI_KEYS.has(key) || !OLLAMA_KEYS.has(key);
    }
    if (key === OLLAMA_CHAT_MODEL_KEY || key === "LLM_EMBED_MODEL") return false;
    if (OPENAI_CHAT_KEYS.has(key) || OLLAMA_EMBED_KEYS.has(key)) return true;
    if (OLLAMA_KEYS.has(key)) return true;
    return true;
  }

  function isLlmFeatureEnabled() {
    const input = fieldInputs.LLM_ENABLED;
    if (!input) return true;
    return input.checked;
  }

  function updateFieldVisibility(key, field) {
    if (!field) return;
    const section = field.closest(".settings-panel");
    if (section?.dataset.section === "llm" && key !== "LLM_ENABLED") {
      field.hidden = !isLlmFeatureEnabled() || !isFieldVisible(key);
    } else {
      field.hidden = !isFieldVisible(key);
    }
  }

  function applyLlmEnabledUi() {
    const enabled = isLlmFeatureEnabled();
    if (providerPanel) providerPanel.hidden = !enabled;
    Object.entries(fieldInputs).forEach(([key, input]) => {
      if (key === "LLM_ENABLED") return;
      updateFieldVisibility(key, input.closest(".settings-field"));
    });
  }

  function applyProviderUi() {
    providerCards?.querySelectorAll(".llm-provider-card").forEach((card) => {
      card.classList.toggle("active", card.dataset.provider === currentProvider);
    });
    if (providerActive) {
      if (currentProvider === "hybrid") {
        providerActive.textContent =
          "Remote API for chat (OpenAI, Grok/xAI, etc.): set API URL, key, and chat model below. " +
          "Grok/xAI has no embeddings API — large files use the local embed server at OLLAMA_BASE_URL (install.sh).";
      } else if (currentProvider === "ollama") {
        providerActive.textContent =
          "All models run on local Ollama — configure OLLAMA_MODEL and pull models with ollama pull.";
      } else {
        providerActive.textContent =
          "Remote API for chat and embeddings — your provider must support /embeddings.";
      }
    }
    Object.entries(fieldInputs).forEach(([key, input]) => {
      updateFieldVisibility(key, input.closest(".settings-field"));
    });
  }

  function setProvider(provider) {
    currentProvider = normalizeProvider(provider);
    pending.LLM_PROVIDER = currentProvider;
    applyProviderUi();
  }

  function makeInput(item) {
    const input = document.createElement("input");
    input.name = item.key;
    input.title = item.description || "";
    if (item.value_type === "bool") {
      input.type = "checkbox";
      input.checked = item.value === "1" || item.value === "true";
    } else if (item.secret) {
      input.type = "password";
      input.value = "";
      input.placeholder = item.configured ? "•••••• (configured — leave blank to keep)" : "Enter value";
      input.autocomplete = "new-password";
    } else {
      input.type = "text";
      input.value = item.value ?? "";
    }
    input.addEventListener("change", () => {
      pending[item.key] = item.value_type === "bool"
        ? (input.checked ? "1" : "0")
        : input.value;
      if (item.key === "LLM_ENABLED") applyLlmEnabledUi();
    });
    input.addEventListener("input", () => {
      if (item.secret) pending[item.key] = input.value;
    });
    return input;
  }

  async function loadSettings() {
    const res = await fetch("/api/settings");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    sectionsEl.innerHTML = "";
    pending = {};
    fieldInputs = {};

    const sections = data.sections || {};
    const llmItems = sections.llm || [];
    const providerItem = llmItems.find((i) => i.key === "LLM_PROVIDER");
    currentProvider = normalizeProvider(providerItem?.value);

    for (const section of SECTION_ORDER) {
      const items = sections[section];
      if (!items?.length) continue;
      const sec = document.createElement("section");
      sec.className = "settings-panel";
      sec.dataset.section = section;
      sec.innerHTML = `<h3>${esc(SECTION_LABELS[section] || section)}</h3>`;
      const grid = document.createElement("div");
      grid.className = "settings-grid";
      for (const item of items) {
        if (HIDDEN_IN_GRID.has(item.key)) continue;
        const label = document.createElement("label");
        label.className = "settings-field";
        label.dataset.key = item.key;
        const input = makeInput(item);
        fieldInputs[item.key] = input;
        const meta = document.createElement("span");
        meta.innerHTML = `${esc(item.label)} <small class="hint">(${esc(item.source)}${item.requires_restart ? " · restart" : ""})</small>`;
        label.appendChild(meta);
        if (item.description) {
          const desc = document.createElement("small");
          desc.className = "hint";
          desc.textContent = item.description;
          label.appendChild(desc);
        }
        label.appendChild(input);
        grid.appendChild(label);
      }
      sec.appendChild(grid);
      sectionsEl.appendChild(sec);
    }
    applyProviderUi();
    applyLlmEnabledUi();
  }

  async function saveSettings({ completeSetup = false } = {}) {
    statusEl.textContent = "Saving…";
    const body = { settings: pending };
    if (completeSetup) body.complete_setup = true;
    const res = await fetch("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    pending = {};
    statusEl.textContent = completeSetup ? "Setup complete — opening viewer…" : "Saved";
    await loadSettings();
    if (completeSetup && data.setup_complete) {
      window.location.href = "/";
    }
  }

  async function reloadTail() {
    statusEl.textContent = "Reloading…";
    const res = await fetch("/api/settings/reload", { method: "POST" });
    const data = await res.json();
    statusEl.textContent = data.message || (data.ok ? "Reloaded" : "Reload failed");
  }

  async function saveTimestampParser(existing) {
    const cfg = existing?.config || {};
    const name = prompt("Parser name", existing?.name || "Custom app logs");
    if (name === null) return;
    const fileGlob = prompt("File glob", existing?.file_glob || "App*.log");
    if (fileGlob === null) return;
    const pattern = prompt(
      "Regex with event_date and optional event_time groups",
      cfg.pattern || String.raw`\[sms\.(?P<event_date>\d{4}-\d{2}-\d{2})\](?:\s*-\s+(?P<event_time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[)?`
    );
    if (pattern === null) return;
    const dateGroup = prompt("Date capture group name", cfg.date_group || "event_date");
    if (dateGroup === null) return;
    const timeGroup = prompt("Time capture group name (leave empty to skip)", cfg.time_group || "event_time");
    if (timeGroup === null) return;
    const timeDefault = prompt("Default time when time group is missing", cfg.time_default || "00:00:00");
    if (timeDefault === null) return;
    const priorityRaw = prompt("Priority (higher matches first)", String(existing?.priority ?? 1));
    if (priorityRaw === null) return;
    const enabledRaw = prompt("Enabled? (1=yes, 0=no)", existing?.enabled === false ? "0" : "1");
    if (enabledRaw === null) return;
    if (!name.trim() || !fileGlob.trim() || !pattern.trim()) return;

    const body = {
      name: name.trim(),
      type: existing?.type || "regex",
      file_glob: fileGlob.trim(),
      priority: parseInt(priorityRaw, 10) || 0,
      enabled: enabledRaw.trim() !== "0",
      config: {
        pattern: pattern.trim(),
        date_group: dateGroup.trim() || "event_date",
        time_group: timeGroup.trim(),
        time_default: timeDefault.trim() || "00:00:00",
      },
    };
    if (existing?.id) {
      body.id = existing.id;
      body.created_at = existing.created_at;
    }

    const res = await fetch("/api/timestamp-parsers", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      statusEl.textContent = data.error || "Failed to save timestamp parser";
      return;
    }
    statusEl.textContent = existing?.id ? "Timestamp parser updated" : "Timestamp parser added";
    loadTimestampParsers();
  }

  async function loadTimestampParsers() {
    if (!tsParserList) return;
    const res = await fetch("/api/timestamp-parsers");
    const data = await res.json();
    timestampParsersCache = data.timestamp_parsers || [];
    tsParserList.innerHTML = timestampParsersCache.map((p) => `
      <div class="columnizer-card">
        <strong>${esc(p.name)}</strong> · ${esc(p.type)} · ${esc(p.file_glob)}
        ${p.enabled ? "" : " · <span class='hint'>disabled</span>"}
        <button data-edit-ts="${esc(p.id)}" class="btn btn-link" type="button">Edit</button>
        ${p.id.startsWith("builtin-") ? "" : `<button data-del-ts="${esc(p.id)}" class="btn btn-link" type="button">Delete</button>`}
      </div>
    `).join("");
    tsParserList.querySelectorAll("[data-edit-ts]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const parser = timestampParsersCache.find((p) => p.id === btn.dataset.editTs);
        if (parser) saveTimestampParser(parser);
      });
    });
    tsParserList.querySelectorAll("[data-del-ts]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!window.confirm("Delete this timestamp parser?")) return;
        await fetch(`/api/timestamp-parsers/${btn.dataset.delTs}`, { method: "DELETE" });
        loadTimestampParsers();
      });
    });
  }

  async function loadColumnizers() {
    const res = await fetch("/api/columnizers");
    const data = await res.json();
    colList.innerHTML = (data.columnizers || []).map((c) => `
      <div class="columnizer-card">
        <strong>${esc(c.name)}</strong> · ${esc(c.type)} · ${esc(c.file_glob)}
        ${c.id.startsWith("builtin-") ? "" : `<button data-del-col="${esc(c.id)}" class="btn btn-link" type="button">Delete</button>`}
      </div>
    `).join("");
    colList.querySelectorAll("[data-del-col]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await fetch(`/api/columnizers/${btn.dataset.delCol}`, { method: "DELETE" });
        loadColumnizers();
      });
    });
  }

  async function loadRules() {
    const res = await fetch("/api/alert-rules");
    const data = await res.json();
    rulesList.innerHTML = (data.rules || []).map((r) => `
      <div class="alert-rule-card">
        <strong>${esc(r.name)}</strong> · ${esc(r.query)} · ${r.enabled ? "on" : "off"}
        <button data-test-rule="${esc(r.id)}" class="btn btn-link" type="button">Test</button>
        <button data-del-rule="${esc(r.id)}" class="btn btn-link" type="button">Delete</button>
      </div>
    `).join("");
    rulesList.querySelectorAll("[data-test-rule]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await fetch(`/api/alert-rules/${btn.dataset.testRule}/test`, { method: "POST" });
        statusEl.textContent = "Test alert sent";
      });
    });
    rulesList.querySelectorAll("[data-del-rule]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await fetch(`/api/alert-rules/${btn.dataset.delRule}`, { method: "DELETE" });
        loadRules();
      });
    });
  }

  providerCards?.querySelectorAll(".llm-provider-card").forEach((card) => {
    card.addEventListener("click", () => setProvider(card.dataset.provider));
  });

  document.getElementById("settings-skip-btn")?.addEventListener("click", async () => {
    statusEl.textContent = "Skipping…";
    const res = await fetch("/api/setup/skip", { method: "POST" });
    const data = await res.json();
    if (!res.ok) {
      statusEl.textContent = data.error || "Skip failed";
      return;
    }
    window.location.href = data.redirect || "/";
  });

  document.getElementById("settings-save-btn")?.addEventListener("click", () => {
    saveSettings().catch((e) => { statusEl.textContent = String(e.message || e); });
  });
  document.getElementById("settings-complete-btn")?.addEventListener("click", () => {
    saveSettings({ completeSetup: true }).catch((e) => { statusEl.textContent = String(e.message || e); });
  });
  document.getElementById("settings-reload-btn")?.addEventListener("click", () => {
    reloadTail().catch((e) => { statusEl.textContent = String(e.message || e); });
  });
  document.getElementById("columnizer-add-btn")?.addEventListener("click", async () => {
    const name = prompt("Columnizer name", "Custom regex");
    const pattern = prompt("Regex with named groups", "(?P<level>\\w+): (?P<message>.*)");
    if (!name || !pattern) return;
    await fetch("/api/columnizers", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name, type: "regex", file_glob: "*", priority: 1,
        config: { pattern },
      }),
    });
    loadColumnizers();
  });
  document.getElementById("timestamp-parser-add-btn")?.addEventListener("click", () => {
    saveTimestampParser(null);
  });
  document.getElementById("alert-rule-add-btn")?.addEventListener("click", async () => {
    const name = prompt("Rule name", "SSH failures");
    const query = prompt("Query", "Failed AND ssh");
    if (!name || !query) return;
    const webhook = prompt(
      "Webhook URL (optional)\nDiscord: https://discord.com/api/webhooks/…\nOther: JSON webhook",
      ""
    ) || null;
    const email = prompt("Email to (optional)", "") || null;
    await fetch("/api/alert-rules", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name, query, mode: "text", scope: "all", cooldown_sec: 300,
        webhook_url: webhook, email_to: email,
      }),
    });
    loadRules();
  });

  if (setupMode) {
    document.querySelectorAll(".settings-advanced").forEach((el) => { el.hidden = true; });
  }

  loadSettings().catch((e) => { statusEl.textContent = String(e.message || e); });
  if (!setupMode) {
    loadColumnizers();
    loadTimestampParsers();
    loadRules();
  }
})();
