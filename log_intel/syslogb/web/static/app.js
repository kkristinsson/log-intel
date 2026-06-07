(() => {
  const feedSingle = document.getElementById("log-view-single");
  const logViewStack = document.getElementById("log-view-stack");
  const feedSplit = document.getElementById("log-view-split");
  const resultsFeed = document.getElementById("search-results-feed");
  const logColumnHeader = document.getElementById("log-column-header");
  const searchColumnHeader = document.getElementById("search-column-header");
  const logModal = document.getElementById("log-modal");
  const logModalBackdrop = document.getElementById("log-modal-backdrop");
  const logModalClose = document.getElementById("log-modal-close");
  const logModalTitle = document.getElementById("log-modal-title");
  const logModalExplainBtn = document.getElementById("log-modal-explain-btn");
  const logModalFeed = document.getElementById("log-modal-feed");
  const fileList = document.getElementById("file-list");
  const sidebarGroupsHint = document.getElementById("sidebar-groups-hint");
  const sortOrder = document.getElementById("sort-order");
  const pauseBtn = document.getElementById("pause-btn");
  const streamStatus = document.getElementById("stream-status");
  const viewLabel = document.getElementById("view-label");
  const analyzeBtn = document.getElementById("analyze-btn");
  const analyzeBtnToolbar = document.getElementById("analyze-btn-toolbar");
  const fileContextMenu = document.getElementById("file-context-menu");
  const fileContextAnalyzeBtn = fileContextMenu?.querySelector('[data-action="analyze"]');
  const scheduleModal = document.getElementById("schedule-modal");
  const scheduleModalBackdrop = document.getElementById("schedule-modal-backdrop");
  const scheduleModalClose = document.getElementById("schedule-modal-close");
  const scheduleModalFile = document.getElementById("schedule-modal-file");
  const scheduleEnabled = document.getElementById("schedule-enabled");
  const scheduleInterval = document.getElementById("schedule-interval");
  const scheduleHour = document.getElementById("schedule-hour");
  const scheduleScope = document.getElementById("schedule-scope");
  const scheduleWindowWrap = document.getElementById("schedule-window-wrap");
  const scheduleWindow = document.getElementById("schedule-window");
  const scheduleMinSeverity = document.getElementById("schedule-min-severity");
  const scheduleAlertAnomalies = document.getElementById("schedule-alert-anomalies");
  const scheduleWebhook = document.getElementById("schedule-webhook");
  const scheduleEmail = document.getElementById("schedule-email");
  const scheduleStatus = document.getElementById("schedule-status");
  const scheduleSaveBtn = document.getElementById("schedule-save-btn");
  const scheduleDeleteBtn = document.getElementById("schedule-delete-btn");
  let scheduleEditPath = null;
  let scheduleEditId = null;
  const analyzeStatus = document.getElementById("analyze-status");
  const analysisHistoryList = document.getElementById("analysis-history-list");
  const analysisHistoryEmpty = document.getElementById("analysis-history-empty");
  const analyzeProgress = document.getElementById("analyze-progress");
  const analyzeProgressStage = document.getElementById("analyze-progress-stage");
  const analyzeProgressPct = document.getElementById("analyze-progress-pct");
  const analyzeProgressFill = document.getElementById("analyze-progress-fill");
  const searchInput = document.getElementById("search-input");
  const searchScope = document.getElementById("search-scope");
  const searchMode = document.getElementById("search-mode");
  const searchBtn = document.getElementById("search-btn");
  const searchClearBtn = document.getElementById("search-clear-btn");
  const searchHelpBtn = document.getElementById("search-help-btn");
  const searchHelpModal = document.getElementById("search-help-modal");
  const searchHelpBackdrop = document.getElementById("search-help-backdrop");
  const searchHelpClose = document.getElementById("search-help-close");
  const explainModal = document.getElementById("explain-modal");
  const explainModalBackdrop = document.getElementById("explain-modal-backdrop");
  const explainModalClose = document.getElementById("explain-modal-close");
  const explainEntrySource = document.getElementById("explain-entry-source");
  const explainEntryLine = document.getElementById("explain-entry-line");
  const explainQuestion = document.getElementById("explain-question");
  const explainSubmitBtn = document.getElementById("explain-submit-btn");
  const explainStatus = document.getElementById("explain-status");
  const explainResult = document.getElementById("explain-result");
  const explainProgress = document.getElementById("explain-progress");
  const explainProgressStage = document.getElementById("explain-progress-stage");
  const explainProgressPct = document.getElementById("explain-progress-pct");
  const explainProgressFill = document.getElementById("explain-progress-fill");
  const columnsToggleBtn = document.getElementById("columns-toggle-btn");
  const exportBtn = document.getElementById("export-btn");
  const exportFormat = document.getElementById("export-format");
  const importanceMinSelect = document.getElementById("importance-min");
  const loadOlderBtn = document.getElementById("load-older-btn");
  const loadNewerBtn = document.getElementById("load-newer-btn");
  const fileRangeHint = document.getElementById("file-range-hint");
  const savedSearchSelect = document.getElementById("saved-search-select");
  const savedSearchSaveBtn = document.getElementById("saved-search-save-btn");
  const savedSearchDeleteBtn = document.getElementById("saved-search-delete-btn");
  const activityProgress = document.getElementById("activity-progress");
  const activityProgressStage = document.getElementById("activity-progress-stage");
  const activityProgressPct = document.getElementById("activity-progress-pct");
  const activityProgressFill = document.getElementById("activity-progress-fill");
  const logTimeWindow = document.getElementById("log-time-window");
  const logTimeWindowWrap = document.getElementById("log-time-window-wrap");
  const analyzeCancelBtn = document.getElementById("analyze-cancel-btn");
  const activityCancelBtn = document.getElementById("activity-cancel-btn");
  const explainCancelBtn = document.getElementById("explain-cancel-btn");
  const explainProgressCancelBtn = document.getElementById("explain-progress-cancel-btn");
  const explainModalCancelBtn = document.getElementById("explain-modal-cancel-btn");

  const llmEnabled = window.SYSLOGB_LLM_ENABLED !== false;

  let selectedPath = null;
  let selectedReadable = true;
  let selectedJournal = false;
  let explainEntry = null;
  let logModalFocusEv = null;
  let contextMenuPath = null;
  let filterPath = null;
  let filterGroup = null;
  let fileGroups = [];
  let allFilesCache = [];
  /** @type {Map<string, object>} resolved file_path -> schedule */
  let scheduledByPath = new Map();
  const expandedGroups = new Set();
  let paused = false;
  let searchActive = false;
  let es = null;
  let pollTimer = null;
  let lastSearchQuery = "";
  let lastSearchMode = "text";
  let lastHighlightTerms = [];
  let columnsMode = false;
  let columnSortKey = null;
  let columnSortDir = "asc";
  const columnFilters = {};
  let columnKeys = [];
  let currentViewEvents = [];
  let currentViewOpts = {};
  let isPopulatingFeed = false;
  const PREFERRED_COLUMN_ORDER = ["timestamp", "host", "unit", "pid", "message", "line"];
  const SYSLOG_ISO_COL_RE =
    /^(?<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?<host>\S+)\s+(?:(?<unit>[\w./@-]+)(?:\[(?<pid>\d+)\])?:\s+)?(?<message>.*)$/;
  const SYSLOG_RFC3164_COL_RE =
    /^(?<mon>[A-Z][a-z]{2})\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+(?:(?<unit>[\w./@-]+)(?:\[(?<pid>\d+)\])?:\s+)?(?<message>.*)$/;

  function parseSyslogColumns(line) {
    if (!line) return null;
    let m = line.match(SYSLOG_ISO_COL_RE);
    if (m?.groups) {
      return {
        timestamp: m.groups.ts || "",
        host: m.groups.host || "",
        unit: m.groups.unit || "",
        pid: m.groups.pid || "",
        message: m.groups.message || "",
      };
    }
    m = line.match(SYSLOG_RFC3164_COL_RE);
    if (m?.groups) {
      return {
        timestamp: `${m.groups.mon} ${m.groups.day} ${m.groups.time}`,
        host: m.groups.host || "",
        unit: m.groups.unit || "",
        pid: m.groups.pid || "",
        message: m.groups.message || "",
      };
    }
    return null;
  }

  function ensureEventColumns(ev) {
    if (ev.columns) return ev;
    const parsed = parseSyslogColumns(ev.line || "");
    if (!parsed) return ev;
    return { ...ev, columns: parsed };
  }
  const fullLogCache = new Map();
  const seenIds = new Set();
  const maxRows = 20000;
  const virtualFeeds = new Map();
  const TAIL_FOLLOW_PX = 48;
  let fileViewport = null;
  let savedSearches = [];
  let explainAbortController = null;
  let searchAbortController = null;
  let activeAnalyzeJobId = null;
  /** @type {"analyze"|"explain"|"search"|null} */
  let cancellableOperation = null;

  function useVirtualFeed(el) {
    return (el === feedSingle || el === resultsFeed) && !columnsMode && typeof VirtualLogFeed !== "undefined";
  }

  function getVirtualFeed(el) {
    if (!useVirtualFeed(el)) return null;
    if (!virtualFeeds.has(el)) {
      virtualFeeds.set(el, new VirtualLogFeed(el, renderRow));
    }
    return virtualFeeds.get(el);
  }

  function importanceMinParam() {
    return importanceMinSelect?.value || "";
  }

  function rowActionOpts(extra = {}) {
    const opts = { selectable: true, ...extra };
    if (llmEnabled && !opts.onDblClick) {
      opts.onDblClick = openExplainModal;
      opts.dblClickTitle = opts.dblClickTitle || "Double-click to explain with LLM";
    }
    return opts;
  }

  function captureFeedScrollState(el) {
    const desc = sortOrder.value === "desc";
    const vf = getVirtualFeed(el);
    if (vf && vf.events.length) {
      const tailFollow = vf.isTailFollow(desc, TAIL_FOLLOW_PX);
      const anchor = tailFollow ? null : vf.anchorEvent();
      return {
        desc,
        tailFollow,
        anchorEvent: anchor ? scrollAnchorFromEvent(anchor) : null,
        scrollTop: vf.container.scrollTop,
        vf: true,
      };
    }
    const { scrollTop, scrollHeight, clientHeight } = el;
    const maxScroll = Math.max(0, scrollHeight - clientHeight);
    const tailFollow = desc
      ? scrollTop <= TAIL_FOLLOW_PX
      : scrollTop >= maxScroll - TAIL_FOLLOW_PX;
    return {
      desc,
      tailFollow,
      scrollTop,
      scrollRatio: maxScroll > 0 ? scrollTop / maxScroll : 0,
      vf: false,
    };
  }

  function restoreFeedScrollState(el, state) {
    if (!state) return;
    const vf = getVirtualFeed(el);
    if (vf) {
      if (state.tailFollow) {
        if (state.desc) vf.scrollToTop();
        else vf.scrollToBottom();
        return;
      }
      vf.setPendingAnchor(state.anchorEvent);
      if (state.anchorEvent && vf.focusEvent(state.anchorEvent, { pulse: true })) return;
      vf.container.scrollTop = state.scrollTop || 0;
      vf.render();
      return;
    }
    if (state.tailFollow) {
      if (state.desc) el.scrollTop = 0;
      else el.scrollTop = el.scrollHeight;
      return;
    }
    const maxScroll = Math.max(0, el.scrollHeight - el.clientHeight);
    el.scrollTop = state.scrollRatio != null
      ? Math.round(state.scrollRatio * maxScroll)
      : Math.min(state.scrollTop || 0, maxScroll);
  }

  function scheduleFeedScrollRestore(el, state) {
    if (!state) return;
    const run = () => restoreFeedScrollState(el, state);
    requestAnimationFrame(() => {
      run();
      requestAnimationFrame(() => {
        run();
        window.setTimeout(run, 50);
      });
    });
  }

  function isFileTailFollow() {
    if (!filterPath || !currentViewEvents.length) return true;
    return captureFeedScrollState(feedSingle).tailFollow;
  }

  function appendImportance(url) {
    const imp = importanceMinParam();
    return imp ? `${url}&importance_min=${encodeURIComponent(imp)}` : url;
  }

  function updatePagingUi() {
    const fileMode = Boolean(filterPath);
    if (loadOlderBtn) {
      loadOlderBtn.hidden = !fileMode;
      loadOlderBtn.disabled = !fileMode || !fileViewport?.has_older;
    }
    if (loadNewerBtn) {
      loadNewerBtn.hidden = !fileMode;
      loadNewerBtn.disabled = !fileMode || !fileViewport?.has_newer;
    }
    if (fileRangeHint) {
      if (!fileMode || !fileViewport) {
        fileRangeHint.classList.add("hidden");
        fileRangeHint.textContent = "";
        return;
      }
      fileRangeHint.classList.remove("hidden");
      if (fileViewport.compressed) {
        const start = (fileViewport.line_start ?? 0) + 1;
        const end = fileViewport.line_end ?? start;
        fileRangeHint.textContent = fileViewport.forward_only
          ? `Lines ${start}–${end} · gz (forward-only)`
          : `Lines ${start}–${end}`;
      } else {
        fileRangeHint.textContent = `Bytes ${fileViewport.read_from ?? 0}–${fileViewport.read_to ?? 0}`;
      }
    }
  }

  function applyFileViewport(data) {
    fileViewport = {
      read_from: data.read_from ?? 0,
      read_to: data.read_to ?? 0,
      line_start: data.line_start ?? null,
      line_end: data.line_end ?? null,
      compressed: Boolean(data.compressed),
      forward_only: Boolean(data.forward_only),
      has_older: Boolean(data.has_older),
      has_newer: Boolean(data.has_newer),
      file_size: data.file_size ?? null,
    };
    updatePagingUi();
  }

  function mergeFileEvents(existing, incoming) {
    const map = new Map(existing.map((e) => [e.id, e]));
    for (const ev of incoming) map.set(ev.id, ev);
    const merged = [...map.values()].sort((a, b) => (a.line_index ?? 0) - (b.line_index ?? 0));
    return sortOrder.value === "desc" ? merged.reverse() : merged;
  }

  function fileWindowParam() {
    const w = logTimeWindow?.value || "1h";
    return w && w !== "all" ? w : "";
  }

  function appendFileWindow(url, direction, { skip = false } = {}) {
    if (skip || direction !== "tail") return url;
    const w = fileWindowParam();
    if (w) return `${url}&window=${encodeURIComponent(w)}`;
    return url;
  }

  function scrollAnchorFromEvent(ev) {
    if (!ev) return null;
    return {
      id: ev.id,
      source: ev.source,
      line_index: ev.line_index,
      read_from: ev.read_from,
      line: ev.line,
    };
  }

  function updateTimeWindowUi() {
    if (!logTimeWindowWrap) return;
    logTimeWindowWrap.classList.toggle("hidden", !filterPath);
  }

  function buildFilePageUrl(path, direction) {
    const order = sortOrder.value;
    let url = `/api/file/page?path=${encodeURIComponent(path)}&order=${order}&direction=${direction}&failures_only=0`;
    url = appendImportance(url);
    url = appendFileWindow(url, direction);
    if (direction === "older" && fileViewport) {
      if (fileViewport.compressed) {
        url += `&before_line=${fileViewport.line_start ?? 0}`;
      } else {
        url += `&before_byte=${fileViewport.read_from ?? 0}`;
      }
    } else if (direction === "newer" && fileViewport) {
      if (fileViewport.compressed) {
        url += `&after_line=${fileViewport.line_end ?? 0}`;
      } else {
        url += `&after_byte=${fileViewport.read_to ?? 0}`;
      }
    }
    return url;
  }

  async function loadFilePage(path, {
    direction = "tail",
    replace = true,
    afterLine = null,
    afterByte = null,
    silent = false,
    scrollTo = null,
    skipWindow = false,
  } = {}) {
    const order = sortOrder.value;
    let url = `/api/file/page?path=${encodeURIComponent(path)}&order=${order}&direction=${direction}&failures_only=0`;
    url = appendImportance(url);
    url = appendFileWindow(url, direction, { skip: skipWindow });
    if (direction === "forward" && afterLine != null) {
      url += `&after_line=${afterLine}`;
    } else if (direction === "newer" && afterByte != null) {
      url += `&after_byte=${afterByte}`;
    } else if (direction === "older" || direction === "newer") {
      url = buildFilePageUrl(path, direction);
    }

    startActivity(fileLoadStage(path, direction), { silent });
    const preserveScroll = replace && path === filterPath && currentViewEvents.length > 0;
    const scrollState = preserveScroll ? captureFeedScrollState(feedSingle) : null;
    try {
      const res = await fetch(url);
      let data;
      try {
        data = await res.json();
      } catch (_) {
        streamStatus.textContent = "Bad response from server";
        if (replace) clearFeed(feedSingle);
        stopActivity({ stage: "Bad response from server", error: true, silent });
        return null;
      }
      if (!res.ok) {
        streamStatus.textContent = data.error || res.statusText;
        if (replace) clearFeed(feedSingle);
        stopActivity({ stage: data.error || res.statusText, error: true, silent });
        return null;
      }

      applyFileViewport(data);
      const events = data.events || [];
      if (replace) {
        populateFeed(feedSingle, order === "asc" ? events : [...events].reverse());
        if (scrollTo) {
          const anchor = scrollAnchorFromEvent(scrollTo);
          scheduleFeedScrollRestore(feedSingle, {
            desc: order === "desc",
            tailFollow: false,
            anchorEvent: anchor,
          });
          for (const delay of [0, 80, 200, 450]) {
            window.setTimeout(() => focusRowInFeed(feedSingle, scrollTo), delay);
          }
        } else {
          scheduleFeedScrollRestore(
            feedSingle,
            scrollState || { tailFollow: true, desc: order === "desc" }
          );
        }
      } else {
        const mergeScroll = captureFeedScrollState(feedSingle);
        const merged = mergeFileEvents(currentViewEvents, events);
        populateFeed(feedSingle, merged, { skipSeen: true });
        scheduleFeedScrollRestore(feedSingle, mergeScroll);
      }
      const suffix = fileViewport?.forward_only ? " · gz" : "";
      const win = fileWindowParam();
      const winLabel = win ? ` · ${win}` : "";
      let status = `${events.length} lines loaded${suffix}${winLabel}`;
      if (data.window_fallback) {
        status = `${events.length} lines (time range empty — showing recent tail)${suffix}`;
        if (data.window_fallback_message) {
          streamStatus.title = data.window_fallback_message;
        }
      } else {
        streamStatus.removeAttribute("title");
      }
      streamStatus.textContent = status;
      stopActivity({ stage: status, silent });
      return data;
    } catch (e) {
      streamStatus.textContent = String(e.message || e);
      if (replace) clearFeed(feedSingle);
      stopActivity({ stage: String(e.message || e), error: true, silent });
      return null;
    }
  }

  async function loadFilePageAtHit(path, ev) {
    const gzip = /\.gz$/i.test(path) || ev.compressed || ev.forward_only;
    const jump = { replace: true, scrollTo: ev, skipWindow: true };
    if (gzip && ev.line_index != null) {
      await loadFilePage(path, {
        direction: "forward",
        afterLine: Math.max(0, ev.line_index - 20),
        ...jump,
      });
      return;
    }
    if (ev.read_from != null || ev.line_index != null) {
      await loadFilePage(path, {
        direction: "newer",
        afterByte: Math.max(0, (ev.read_from ?? 0) - 8192),
        ...jump,
      });
      return;
    }
    await loadFilePage(path, { direction: "tail", ...jump });
  }

  async function loadRecentForFile(path) {
    if (!isFileTailFollow()) return;
    // Live follow: read only bytes appended since last viewport (no time-window re-filter).
    if (fileViewport && !fileViewport.compressed && !fileViewport.forward_only) {
      await loadFilePage(path, {
        direction: "newer",
        replace: false,
        silent: true,
        skipWindow: true,
      });
      return;
    }
    await loadFilePage(path, { direction: "tail", replace: true, silent: true });
  }

  async function reloadSavedSearches() {
    if (!savedSearchSelect) return;
    try {
      const res = await fetch("/api/saved-searches");
      const data = await res.json();
      savedSearches = data.searches || [];
      const current = savedSearchSelect.value;
      savedSearchSelect.innerHTML = '<option value="">Saved searches…</option>';
      for (const s of savedSearches) {
        const opt = document.createElement("option");
        opt.value = s.id;
        opt.textContent = s.name;
        savedSearchSelect.appendChild(opt);
      }
      if (current && savedSearches.some((s) => s.id === current)) {
        savedSearchSelect.value = current;
      }
      if (savedSearchDeleteBtn) {
        savedSearchDeleteBtn.hidden = !savedSearchSelect.value;
      }
    } catch (_) { /* ignore */ }
  }

  function applySavedSearch(id) {
    const saved = savedSearches.find((s) => s.id === id);
    if (!saved) return;
    searchInput.value = saved.query;
    searchMode.value = saved.mode || "text";
    if (saved.scope && [...searchScope.options].some((o) => o.value === saved.scope)) {
      searchScope.value = saved.scope;
    }
    if (savedSearchDeleteBtn) savedSearchDeleteBtn.hidden = false;
  }

  async function saveCurrentSearch() {
    const query = searchInput.value.trim();
    if (!query) return;
    const name = window.prompt("Name for this saved search:");
    if (!name?.trim()) return;
    const scope = searchScope.value;
    const body = {
      name: name.trim(),
      query,
      mode: searchMode.value,
      scope,
    };
    if (scope === "file" && filterPath) body.file_path = filterPath;
    else if (scope !== "all") body.log_dir = scope;
    try {
      const res = await fetch("/api/saved-searches", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      await reloadSavedSearches();
      if (savedSearchSelect) savedSearchSelect.value = data.id;
      if (savedSearchDeleteBtn) savedSearchDeleteBtn.hidden = false;
    } catch (e) {
      streamStatus.textContent = String(e.message || e);
    }
  }

  async function deleteCurrentSavedSearch() {
    const id = savedSearchSelect?.value;
    if (!id) return;
    if (!window.confirm("Delete this saved search?")) return;
    try {
      const res = await fetch(`/api/saved-searches/${encodeURIComponent(id)}`, { method: "DELETE" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      if (savedSearchSelect) savedSearchSelect.value = "";
      if (savedSearchDeleteBtn) savedSearchDeleteBtn.hidden = true;
      await reloadSavedSearches();
    } catch (e) {
      streamStatus.textContent = String(e.message || e);
    }
  }

  function activeFeed() {
    return searchActive ? resultsFeed : feedSingle;
  }

  let analyzePollTimer = null;
  let explainProgressTimer = null;
  let activityProgressTimer = null;
  let activityProgressDepth = 0;

  function setActivityProgress(pct, stage, state = "") {
    if (!activityProgress) return;
    activityProgress.classList.remove("hidden", "is-indeterminate", "is-done", "is-error");
    if (state) activityProgress.classList.add(state);
    activityProgress.setAttribute("aria-busy", state === "is-done" || state === "is-error" ? "false" : "true");
    const safePct = Math.max(0, Math.min(100, Number(pct) || 0));
    if (activityProgressStage) activityProgressStage.textContent = stage || "Loading…";
    if (activityProgressPct) activityProgressPct.textContent = `${safePct}%`;
    if (activityProgressFill) activityProgressFill.style.width = `${safePct}%`;
  }

  function hideActivityProgress() {
    if (activityProgressTimer) {
      clearInterval(activityProgressTimer);
      activityProgressTimer = null;
    }
    if (!activityProgress) return;
    activityProgress.classList.add("hidden");
    activityProgress.classList.remove("is-indeterminate", "is-done", "is-error");
    activityProgress.setAttribute("aria-busy", "false");
    if (activityProgressFill) activityProgressFill.style.width = "0%";
    logViewStack?.classList.remove("is-loading");
    feedSplit?.classList.remove("is-loading");
  }

  function showOperationCancel(op) {
    cancellableOperation = op;
    if (activityCancelBtn) activityCancelBtn.classList.remove("hidden");
  }

  function hideOperationCancel() {
    cancellableOperation = null;
    if (activityCancelBtn) activityCancelBtn.classList.add("hidden");
  }

  function showExplainCancelButtons() {
    if (explainCancelBtn) explainCancelBtn.classList.remove("hidden");
    if (explainProgressCancelBtn) explainProgressCancelBtn.classList.remove("hidden");
    if (explainModalCancelBtn) explainModalCancelBtn.classList.remove("hidden");
    showOperationCancel("explain");
  }

  function hideExplainCancelButtons() {
    if (explainCancelBtn) explainCancelBtn.classList.add("hidden");
    if (explainProgressCancelBtn) explainProgressCancelBtn.classList.add("hidden");
    if (explainModalCancelBtn) explainModalCancelBtn.classList.add("hidden");
    if (cancellableOperation === "explain") hideOperationCancel();
  }

  function abortSearchRequest() {
    if (searchAbortController) {
      searchAbortController.abort();
      searchAbortController = null;
    }
    if (cancellableOperation === "search") hideOperationCancel();
    streamStatus.textContent = "Search cancelled";
    stopActivity({ stage: "Search cancelled", error: true });
  }

  function cancelActiveOperation() {
    if (cancellableOperation === "analyze") cancelAnalyzeJob();
    else if (cancellableOperation === "explain") abortExplainRequest();
    else if (cancellableOperation === "search") abortSearchRequest();
  }

  function startActivity(stage, { silent = false } = {}) {
    if (silent) return;
    activityProgressDepth += 1;
    logViewStack?.classList.toggle("is-loading", !searchActive);
    feedSplit?.classList.toggle("is-loading", searchActive);
    setActivityProgress(8, stage, "is-indeterminate");
    if (activityProgressTimer) return;
    let pct = 10;
    activityProgressTimer = setInterval(() => {
      pct = Math.min(pct + 2 + Math.random() * 6, 92);
      const busy = activityProgressStage?.textContent || stage;
      setActivityProgress(Math.round(pct), busy, pct < 45 ? "is-indeterminate" : "");
    }, 380);
  }

  function stopActivity({ stage = "Done", error = false, silent = false } = {}) {
    if (silent) return;
    activityProgressDepth = Math.max(0, activityProgressDepth - 1);
    if (activityProgressDepth > 0) return;
    if (activityProgressTimer) {
      clearInterval(activityProgressTimer);
      activityProgressTimer = null;
    }
    setActivityProgress(100, stage, error ? "is-error" : "is-done");
    logViewStack?.classList.remove("is-loading");
    feedSplit?.classList.remove("is-loading");
    const delay = error ? 1400 : 550;
    setTimeout(() => hideActivityProgress(), delay);
  }

  function fileLoadStage(path, direction) {
    const name = basename(path);
    if (direction === "older") return `Loading older lines from ${name}…`;
    if (direction === "newer") return `Loading newer lines from ${name}…`;
    if (direction === "forward") return `Jumping to line in ${name}…`;
    return `Loading ${name}…`;
  }

  function getAnalyzeButtons(scope = null) {
    if (scope) {
      return document.querySelectorAll(`[data-analyze-scope="${scope}"]`);
    }
    return document.querySelectorAll(".analyze-trigger");
  }

  function setAnalyzeButtonsDisabled(disabled, scope = null) {
    getAnalyzeButtons(scope).forEach((btn) => {
      btn.disabled = disabled;
    });
  }

  function updateAnalyzeButtonsEnabled() {
    const canAnalyze = Boolean(selectedPath && selectedReadable);
    const fullOk = canAnalyze && !selectedJournal;
    setAnalyzeButtonsDisabled(!fullOk, "full");
    const viewingFile = Boolean(
      canAnalyze && filterPath && selectedPath === filterPath && !searchActive
    );
    setAnalyzeButtonsDisabled(!viewingFile, "window");
  }

  function formatAnalysisWhen(ts) {
    if (!ts) return "";
    const d = new Date(ts * 1000);
    if (Number.isNaN(d.getTime())) return "";
    const diff = Date.now() - d.getTime();
    if (diff < 60_000) return "just now";
    if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`;
    return d.toLocaleString();
  }

  function analysisModeLabel(mode) {
    if (!mode || mode === "full" || mode === "auto") return "full file";
    if (mode.startsWith("window:")) return mode.slice(7);
    return mode;
  }

  async function refreshAnalysisHistory() {
    if (!llmEnabled || !analysisHistoryList) return;
    try {
      const res = await fetch("/api/analyses/recent?limit=5");
      const data = await res.json();
      const items = data.analyses || [];
      if (analysisHistoryEmpty) {
        analysisHistoryEmpty.classList.toggle("hidden", items.length > 0);
      }
      if (!items.length) {
        analysisHistoryList.innerHTML = "";
        return;
      }
      analysisHistoryList.innerHTML = items
        .map((a) => {
          const name = escapeHtml(a.file_name || basename(a.file_path || ""));
          const when = formatAnalysisWhen(a.finished_at || a.created_at);
          const mode = escapeHtml(analysisModeLabel(a.mode));
          const href = `/analysis/${encodeURIComponent(a.id)}`;
          if (a.status === "done" && a.result) {
            const sev = escapeHtml(a.severity || a.result.severity || "info");
            const summary = escapeHtml(a.summary || a.result.summary || "");
            return `<li class="analysis-history-item">
              <a class="analysis-history-link" href="${href}">
                <span class="analysis-history-file">${name}</span>
                <span class="analysis-history-meta">
                  <span class="analysis-history-badge severity-${sev}">${sev}</span>
                  <span class="analysis-history-summary">${summary}</span>
                </span>
                <span class="analysis-history-time">${when} · ${mode}</span>
              </a>
            </li>`;
          }
          const err = escapeHtml(a.error || "Analysis failed");
          return `<li class="analysis-history-item">
            <a class="analysis-history-link" href="${href}">
              <span class="analysis-history-file">${name}</span>
              <span class="analysis-history-meta">
                <span class="analysis-history-badge">failed</span>
                <span class="analysis-history-summary">${err}</span>
              </span>
              <span class="analysis-history-time">${when}</span>
            </a>
          </li>`;
        })
        .join("");
    } catch (_) {
      /* ignore */
    }
  }

  function hideFileContextMenu() {
    if (!fileContextMenu) return;
    fileContextMenu.classList.add("hidden");
    contextMenuPath = null;
  }

  function closeScheduleModal() {
    scheduleModal?.classList.add("hidden");
    scheduleEditPath = null;
    scheduleEditId = null;
    if (
      logModal?.classList.contains("hidden") &&
      searchHelpModal?.classList.contains("hidden") &&
      explainModal?.classList.contains("hidden") &&
      scheduleModal?.classList.contains("hidden")
    ) {
      document.body.classList.remove("modal-open");
    }
  }

  function updateScheduleWindowUi() {
    if (!scheduleWindowWrap || !scheduleScope) return;
    scheduleWindowWrap.classList.toggle("hidden", scheduleScope.value !== "window");
  }

  async function openScheduleModal(path) {
    if (!scheduleModal || !path) return;
    hideFileContextMenu();
    scheduleEditPath = path;
    scheduleEditId = null;
    if (scheduleModalFile) {
      scheduleModalFile.textContent = path;
    }
    if (scheduleStatus) scheduleStatus.textContent = "";
    if (scheduleDeleteBtn) scheduleDeleteBtn.hidden = true;
    if (scheduleEnabled) scheduleEnabled.checked = true;
    if (scheduleInterval) scheduleInterval.value = "1";
    if (scheduleHour) scheduleHour.value = "2";
    if (scheduleScope) scheduleScope.value = "full";
    if (scheduleWindow) scheduleWindow.value = "24h";
    if (scheduleMinSeverity) scheduleMinSeverity.value = "medium";
    if (scheduleAlertAnomalies) scheduleAlertAnomalies.checked = true;
    if (scheduleWebhook) scheduleWebhook.value = "";
    if (scheduleEmail) scheduleEmail.value = "";
    updateScheduleWindowUi();
    try {
      const res = await fetch(`/api/analysis-schedules?path=${encodeURIComponent(path)}`);
      const data = await res.json();
      if (res.ok && data.schedules?.[0]) {
        const s = data.schedules[0];
        scheduleEditId = s.id;
        if (scheduleEnabled) scheduleEnabled.checked = Boolean(s.enabled);
        if (scheduleInterval) scheduleInterval.value = String(s.interval_days || 1);
        if (scheduleHour) scheduleHour.value = String(s.run_at_hour ?? 2);
        if (scheduleScope) scheduleScope.value = s.scope || "full";
        if (scheduleWindow) scheduleWindow.value = s.window || "24h";
        if (scheduleMinSeverity) scheduleMinSeverity.value = s.min_severity || "medium";
        if (scheduleAlertAnomalies) {
          scheduleAlertAnomalies.checked = Boolean(s.alert_on_anomalies);
        }
        if (scheduleWebhook) scheduleWebhook.value = s.webhook_url || "";
        if (scheduleEmail) scheduleEmail.value = s.email_to || "";
        if (scheduleDeleteBtn) scheduleDeleteBtn.hidden = false;
        if (scheduleStatus && s.next_run_at) {
          scheduleStatus.textContent = `Next run: ${new Date(s.next_run_at * 1000).toLocaleString()}`;
        }
      }
    } catch (_) { /* new schedule */ }
    scheduleModal.classList.remove("hidden");
    document.body.classList.add("modal-open");
  }

  async function saveSchedule() {
    if (!scheduleEditPath) return;
    const body = {
      id: scheduleEditId || undefined,
      file_path: scheduleEditPath,
      enabled: scheduleEnabled?.checked ?? true,
      interval_days: Number(scheduleInterval?.value || 1),
      run_at_hour: Number(scheduleHour?.value || 2),
      scope: scheduleScope?.value || "full",
      window: scheduleScope?.value === "window" ? (scheduleWindow?.value || "24h") : "",
      min_severity: scheduleMinSeverity?.value || "medium",
      alert_on_anomalies: scheduleAlertAnomalies?.checked ?? true,
      webhook_url: scheduleWebhook?.value?.trim() || "",
      email_to: scheduleEmail?.value?.trim() || "",
    };
    if (scheduleStatus) scheduleStatus.textContent = "Saving…";
    try {
      const res = await fetch("/api/analysis-schedules", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      scheduleEditId = data.id;
      if (scheduleDeleteBtn) scheduleDeleteBtn.hidden = false;
      if (scheduleStatus) {
        const nxt = data.next_run_at
          ? new Date(data.next_run_at * 1000).toLocaleString()
          : "";
        scheduleStatus.textContent = nxt ? `Saved. Next run: ${nxt}` : "Saved.";
      }
      await refreshScheduleSidebarMarkers();
    } catch (e) {
      if (scheduleStatus) scheduleStatus.textContent = String(e.message || e);
    }
  }

  async function deleteSchedule() {
    if (!scheduleEditId) return;
    if (scheduleStatus) scheduleStatus.textContent = "Removing…";
    try {
      const res = await fetch(`/api/analysis-schedules/${encodeURIComponent(scheduleEditId)}`, {
        method: "DELETE",
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      closeScheduleModal();
      await refreshScheduleSidebarMarkers();
    } catch (e) {
      if (scheduleStatus) scheduleStatus.textContent = String(e.message || e);
    }
  }

  function showFileContextMenu(x, y, path) {
    if (!fileContextMenu || !path) return;
    contextMenuPath = path;
    fileContextMenu.style.left = `${x}px`;
    fileContextMenu.style.top = `${y}px`;
    fileContextMenu.classList.remove("hidden");
  }

  function stopExplainProgressTimer() {
    if (explainProgressTimer) {
      clearInterval(explainProgressTimer);
      explainProgressTimer = null;
    }
  }

  function setExplainProgress(pct, stage, state = "") {
    if (!explainProgress) return;
    explainProgress.classList.remove("hidden", "is-indeterminate", "is-done", "is-error");
    if (state) explainProgress.classList.add(state);
    const safePct = Math.max(0, Math.min(100, Number(pct) || 0));
    if (explainProgressStage) explainProgressStage.textContent = stage || "Working…";
    if (explainProgressPct) explainProgressPct.textContent = `${safePct}%`;
    if (explainProgressFill) explainProgressFill.style.width = `${safePct}%`;
  }

  function hideExplainProgress() {
    stopExplainProgressTimer();
    if (!explainProgress) return;
    explainProgress.classList.add("hidden");
    explainProgress.classList.remove("is-indeterminate", "is-done", "is-error");
    if (explainProgressFill) explainProgressFill.style.width = "0%";
  }

  function startExplainProgress() {
    stopExplainProgressTimer();
    setExplainProgress(6, "Sending to LLM…", "is-indeterminate");
    let pct = 6;
    explainProgressTimer = setInterval(() => {
      pct = Math.min(pct + 4 + Math.random() * 7, 93);
      const stage = pct < 35 ? "Sending to LLM…" : "Waiting for response…";
      const state = pct < 30 ? "is-indeterminate" : "";
      setExplainProgress(Math.round(pct), stage, state);
    }, 450);
  }

  function formatFileSize(bytes) {
    if (bytes == null || bytes < 0) return "";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  function setAnalyzeProgress(pct, stage, state = "") {
    const safePct = Math.max(0, Math.min(100, Number(pct) || 0));
    const label = stage || "Working…";
    if (analyzeProgress) {
      analyzeProgress.classList.remove("hidden", "is-indeterminate", "is-done", "is-error");
      if (state) analyzeProgress.classList.add(state);
      if (analyzeProgressStage) analyzeProgressStage.textContent = label;
      if (analyzeProgressPct) analyzeProgressPct.textContent = `${safePct}%`;
      if (analyzeProgressFill) analyzeProgressFill.style.width = `${safePct}%`;
    }
    setActivityProgress(safePct, label, state);
  }

  function hideAnalyzeProgress() {
    if (analyzeProgress) {
      analyzeProgress.classList.add("hidden");
      analyzeProgress.classList.remove("is-indeterminate", "is-done", "is-error");
      if (analyzeProgressFill) analyzeProgressFill.style.width = "0%";
    }
    if (activityProgressDepth <= 0) hideActivityProgress();
  }

  function stopAnalyzePoll() {
    if (analyzePollTimer) {
      clearInterval(analyzePollTimer);
      analyzePollTimer = null;
    }
  }

  async function pollAnalyzeJob(jobId) {
    const res = await fetch(`/api/analyze/${jobId}`);
    const job = await res.json();
    if (!res.ok) throw new Error(job.error || res.statusText);

    const pct = job.progress_pct ?? 0;
    const stage = job.progress_stage || job.status || "Working…";

    if (job.status === "pending") {
      setAnalyzeProgress(Math.max(pct, 3), stage || "Queued…", "is-indeterminate");
    } else if (job.status === "running") {
      setAnalyzeProgress(Math.max(pct, 5), stage, pct < 8 ? "is-indeterminate" : "");
    } else if (job.status === "done") {
      setAnalyzeProgress(100, "Analysis complete", "is-done");
      stopAnalyzePoll();
      activeAnalyzeJobId = null;
      if (analyzeCancelBtn) analyzeCancelBtn.classList.add("hidden");
      hideOperationCancel();
      const link = `<a href="/analysis/${jobId}">View results</a>`;
      if (analyzeStatus) analyzeStatus.innerHTML = `Analysis finished. ${link}`;
      streamStatus.textContent = "Analysis complete — opening results…";
      updateAnalyzeButtonsEnabled();
      refreshAnalysisHistory();
      setTimeout(() => {
        window.location.href = `/analysis/${jobId}`;
      }, 700);
      return job;
    } else if (job.status === "error") {
      setAnalyzeProgress(100, "Analysis failed", "is-error");
      stopAnalyzePoll();
      activeAnalyzeJobId = null;
      if (analyzeCancelBtn) analyzeCancelBtn.classList.add("hidden");
      hideOperationCancel();
      const msg = job.error || "Analysis failed";
      if (analyzeStatus) analyzeStatus.textContent = msg;
      streamStatus.textContent = msg;
      updateAnalyzeButtonsEnabled();
      refreshAnalysisHistory();
      setTimeout(() => hideAnalyzeProgress(), 1400);
      return job;
    } else if (job.status === "cancelled") {
      setAnalyzeProgress(100, "Cancelled", "is-error");
      stopAnalyzePoll();
      activeAnalyzeJobId = null;
      if (analyzeCancelBtn) analyzeCancelBtn.classList.add("hidden");
      hideOperationCancel();
      if (analyzeStatus) analyzeStatus.textContent = "Analysis cancelled.";
      streamStatus.textContent = "Analysis cancelled";
      updateAnalyzeButtonsEnabled();
      setTimeout(() => hideAnalyzeProgress(), 900);
      return job;
    } else {
      setAnalyzeProgress(pct, stage);
    }
    return job;
  }

  async function cancelAnalyzeJob() {
    if (!activeAnalyzeJobId) return;
    const jobId = activeAnalyzeJobId;
    try {
      await fetch(`/api/analyze/${jobId}`, { method: "DELETE" });
    } catch (_) { /* ignore */ }
    stopAnalyzePoll();
    activeAnalyzeJobId = null;
    if (analyzeCancelBtn) analyzeCancelBtn.classList.add("hidden");
    hideOperationCancel();
    setAnalyzeProgress(100, "Cancelling…", "is-error");
    if (analyzeStatus) analyzeStatus.textContent = "Cancelling analysis…";
    streamStatus.textContent = "Cancelling analysis…";
    updateAnalyzeButtonsEnabled();
    pollAnalyzeJob(jobId).catch(() => {});
    setTimeout(() => hideAnalyzeProgress(), 900);
  }

  function startAnalyzePoll(jobId) {
    stopAnalyzePoll();
    activeAnalyzeJobId = jobId;
    if (analyzeCancelBtn) analyzeCancelBtn.classList.remove("hidden");
    showOperationCancel("analyze");
    if (activityProgressTimer) {
      clearInterval(activityProgressTimer);
      activityProgressTimer = null;
    }
    activityProgressDepth = 0;
    logViewStack?.classList.remove("is-loading");
    feedSplit?.classList.remove("is-loading");
    setAnalyzeProgress(2, "Submitting LLM analysis…", "is-indeterminate");
    streamStatus.textContent = "LLM analysis running…";
    pollAnalyzeJob(jobId).catch((e) => {
      const msg = String(e.message || e);
      if (analyzeStatus) analyzeStatus.textContent = msg;
      streamStatus.textContent = msg;
      hideAnalyzeProgress();
      updateAnalyzeButtonsEnabled();
    });
    analyzePollTimer = setInterval(() => {
      pollAnalyzeJob(jobId).catch((e) => {
        const msg = String(e.message || e);
        if (analyzeStatus) analyzeStatus.textContent = msg;
        streamStatus.textContent = msg;
        stopAnalyzePoll();
        hideAnalyzeProgress();
        updateAnalyzeButtonsEnabled();
      });
    }, 1000);
  }
  function searchScopeLabel(scopeValue, dirs, groups) {
    if (scopeValue === "all") {
      return (dirs && dirs.length > 1) ? "all directories" : "all files";
    }
    if (scopeValue === "file" && filterPath) {
      return basename(filterPath);
    }
    const g = (groups || fileGroups).find((x) => x.path === scopeValue);
    if (g) return g.label;
    const match = (dirs || []).find((d) => d.path === scopeValue);
    return match ? match.label : scopeValue;
  }

  function updateSelectedFileScopeOption() {
    let fileOpt = searchScope.querySelector('option[value="file"]');
    if (filterPath) {
      if (!fileOpt) {
        fileOpt = document.createElement("option");
        fileOpt.value = "file";
        searchScope.insertBefore(fileOpt, searchScope.options[1] || null);
      }
      fileOpt.textContent = `Selected file: ${basename(filterPath)}`;
    } else if (fileOpt) {
      fileOpt.remove();
      if (searchScope.value === "file") {
        searchScope.value = "all";
      }
    }
  }

  function updateSearchScopeOptions(dirs, groups) {
    const previous = searchScope.value;
    const groupList = groups || fileGroups;
    searchScope.innerHTML = "";

    const allOpt = document.createElement("option");
    allOpt.value = "all";
    allOpt.textContent = dirs.length > 1 ? "All directories" : "All files";
    searchScope.appendChild(allOpt);

    for (const g of groupList) {
      const opt = document.createElement("option");
      opt.value = g.path;
      const prefix = dirs.length > 1 && g.log_dir_label ? `${g.log_dir_label} / ` : "";
      opt.textContent = `${prefix}${g.label}`;
      opt.title = g.path;
      searchScope.appendChild(opt);
    }

    for (const d of dirs) {
      const opt = document.createElement("option");
      opt.value = d.path;
      opt.textContent = d.label;
      opt.title = d.path;
      searchScope.appendChild(opt);
    }

    updateSelectedFileScopeOption();

    const values = new Set([...searchScope.options].map((o) => o.value));
    searchScope.value = values.has(previous) ? previous : "all";
  }

  function basename(p) {
    const i = p.lastIndexOf("/");
    return i >= 0 ? p.slice(i + 1) : p;
  }

  function escapeHtml(s) {
    return s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function highlightTermsInLine(line, terms) {
    if (!terms.length) return escapeHtml(line);
    const lower = line.toLowerCase();
    const spans = [];
    for (const term of terms) {
      const q = term.toLowerCase();
      if (!q) continue;
      let pos = 0;
      while (true) {
        const idx = lower.indexOf(q, pos);
        if (idx < 0) break;
        spans.push([idx, idx + term.length]);
        pos = idx + term.length;
      }
    }
    if (!spans.length) return escapeHtml(line);
    spans.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
    const merged = [];
    for (const span of spans) {
      const last = merged[merged.length - 1];
      if (!last || span[0] > last[1]) {
        merged.push(span);
      } else if (span[1] > last[1]) {
        last[1] = span[1];
      }
    }
    let out = "";
    let pos = 0;
    for (const [start, end] of merged) {
      out += escapeHtml(line.slice(pos, start));
      out += `<mark class="hl">${escapeHtml(line.slice(start, end))}</mark>`;
      pos = end;
    }
    out += escapeHtml(line.slice(pos));
    return out;
  }

  function highlightLine(line, query, mode, terms = []) {
    const safe = escapeHtml(line);
    if (!query && !terms.length) return safe;
    try {
      if (mode === "regex" && query) {
        const re = new RegExp(query, "gi");
        return safe.replace(re, (m) => `<mark class="hl">${m}</mark>`);
      }
      if (terms.length) return highlightTermsInLine(line, terms);
      const lower = line.toLowerCase();
      const q = query.toLowerCase();
      let out = "";
      let pos = 0;
      while (true) {
        const idx = lower.indexOf(q, pos);
        if (idx < 0) {
          out += escapeHtml(line.slice(pos));
          break;
        }
        out += escapeHtml(line.slice(pos, idx));
        out += `<mark class="hl">${escapeHtml(line.slice(idx, idx + q.length))}</mark>`;
        pos = idx + q.length;
      }
      return out;
    } catch (_) {
      return safe;
    }
  }

  function orderedColumnKeys(events) {
    const keys = new Set();
    for (const ev of events) {
      if (ev.columns) Object.keys(ev.columns).forEach((k) => keys.add(k));
    }
    const ordered = PREFERRED_COLUMN_ORDER.filter((k) => keys.has(k));
    for (const k of keys) {
      if (!ordered.includes(k)) ordered.push(k);
    }
    return ordered;
  }

  function passesColumnFilters(ev) {
    if (!ev.columns) return true;
    for (const [key, raw] of Object.entries(columnFilters)) {
      const needle = String(raw || "").trim().toLowerCase();
      if (!needle) continue;
      const hay = String(ev.columns[key] || "").toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  }

  function prepareColumnViewEvents(events) {
    let out = events.filter(passesColumnFilters);
    if (columnSortKey) {
      out = [...out].sort((a, b) => {
        const av = String(a.columns?.[columnSortKey] || "").toLowerCase();
        const bv = String(b.columns?.[columnSortKey] || "").toLowerCase();
        const cmp = av.localeCompare(bv, undefined, { numeric: true, sensitivity: "base" });
        return columnSortDir === "desc" ? -cmp : cmp;
      });
    }
    return out;
  }

  function columnGridTemplate(showSource, numbered = false) {
    const parts = [];
    if (numbered) parts.push("3.5rem");
    if (showSource) parts.push("minmax(90px, auto)");
    for (let i = 0; i < columnKeys.length; i += 1) {
      parts.push("minmax(80px, 1fr)");
    }
    return parts.join(" ");
  }

  function applyColumnGrid(el, showSource, numbered = false) {
    if (!columnKeys.length) return;
    el.style.gridTemplateColumns = columnGridTemplate(showSource, numbered);
  }

  function columnHeaderEl() {
    return searchActive ? searchColumnHeader : logColumnHeader;
  }

  function syncColumnHeaderVisibility() {
    const active = columnHeaderEl();
    const inactive = searchActive ? logColumnHeader : searchColumnHeader;
    if (inactive && inactive !== active) {
      inactive.classList.add("hidden");
      inactive.setAttribute("aria-hidden", "true");
      inactive.innerHTML = "";
    }
    return active;
  }

  function removeColumnHeader(el) {
    el?.classList.remove("columns-view");
    for (const header of [logColumnHeader, searchColumnHeader]) {
      if (!header) continue;
      header.classList.add("hidden");
      header.setAttribute("aria-hidden", "true");
      header.innerHTML = "";
    }
  }

  function ensureColumnHeader(el, keys, showSource) {
    const header = syncColumnHeaderVisibility();
    if (!columnsMode || !keys.length || !header) {
      removeColumnHeader(el);
      return;
    }
    el.classList.add("columns-view");
    header.classList.remove("hidden");
    header.setAttribute("aria-hidden", "false");
    header.innerHTML = "";
    if (currentViewOpts.numbered) {
      const spacer = document.createElement("span");
      spacer.className = "col-header-spacer line-no";
      header.appendChild(spacer);
    }
    if (showSource) {
      const src = document.createElement("span");
      src.className = "col-header-spacer source";
      src.textContent = "File";
      header.appendChild(src);
    }
    for (const key of keys) {
      const cell = document.createElement("div");
      cell.className = "col-header-cell";
      const sortBtn = document.createElement("button");
      sortBtn.type = "button";
      sortBtn.className = "col-sort-btn";
      const arrow = columnSortKey === key ? (columnSortDir === "asc" ? " ▲" : " ▼") : "";
      sortBtn.textContent = `${key}${arrow}`;
      sortBtn.title = "Click to sort by this column";
      sortBtn.addEventListener("click", () => {
        if (columnSortKey === key) {
          columnSortDir = columnSortDir === "asc" ? "desc" : "asc";
        } else {
          columnSortKey = key;
          columnSortDir = "asc";
        }
        rerenderActiveFeed();
      });
      const filter = document.createElement("input");
      filter.type = "search";
      filter.className = "col-filter-input";
      filter.placeholder = `Filter ${key}`;
      filter.value = columnFilters[key] || "";
      filter.addEventListener("input", () => {
        if (isPopulatingFeed) return;
        columnFilters[key] = filter.value;
        rerenderActiveFeed();
      });
      cell.appendChild(sortBtn);
      cell.appendChild(filter);
      header.appendChild(cell);
    }
    applyColumnGrid(header, showSource, currentViewOpts.numbered);
  }

  function rerenderActiveFeed() {
    const el = activeFeed();
    if (!currentViewEvents.length) return;
    populateFeed(el, currentViewEvents, { ...currentViewOpts, resetSeen: true });
  }

  function renderRow(ev, opts = {}) {
    const {
      query = "",
      mode = "text",
      highlightTerms = [],
      showSource = false,
      numbered = false,
      selectable = false,
      onDblClick = null,
      dblClickTitle = "",
      skipSeen = false,
      skipSelectionHandler = false,
    } = opts;
    const key = String(ev.id);
    if (!skipSeen) {
      if (seenIds.has(key)) return null;
      seenIds.add(key);
    }

    const row = document.createElement("div");
    row.className = "log-row";
    row.dataset.id = key;
    if (ev.source) row.dataset.source = ev.source;
    if (ev.line_index != null) row.dataset.lineIndex = String(ev.line_index);
    if (ev.read_from != null) row.dataset.readFrom = String(ev.read_from);

    if (ev.line) row.dataset.line = ev.line;

    if (numbered) {
      const num = document.createElement("span");
      num.className = "line-no";
      num.textContent = String((ev.line_index ?? 0) + 1);
      row.appendChild(num);
    }

    if (showSource) {
      const src = document.createElement("span");
      src.className = "source";
      src.title = ev.source;
      src.textContent = basename(ev.source);
      row.appendChild(src);
    }

    const sev = ev.severity;
    if (
      !columnsMode
      && sev
      && !["unknown", "info", "debug", "notice"].includes(sev)
    ) {
      const badge = document.createElement("span");
      badge.className = `severity severity-${sev}`;
      badge.textContent = sev;
      row.appendChild(badge);
    }

    const colEv = columnsMode ? ensureEventColumns(ev) : ev;
    if (columnsMode && colEv.columns) {
      row.classList.add("log-row-columns");
      applyColumnGrid(row, showSource, numbered);
      const keys = columnKeys.length ? columnKeys : orderedColumnKeys([colEv]);
      for (const colKey of keys) {
        const cell = document.createElement("span");
        cell.className = "col-cell";
        cell.dataset.col = colKey;
        const val = colEv.columns[colKey] || "";
        if (query || highlightTerms.length) {
          cell.innerHTML = highlightLine(val, query, mode, highlightTerms);
        } else {
          cell.textContent = val;
        }
        row.appendChild(cell);
      }
      const line = document.createElement("span");
      line.className = "line line-raw";
      line.hidden = true;
      line.textContent = ev.line;
      row.appendChild(line);
    } else {
      const line = document.createElement("span");
      line.className = "line";
      if (query || highlightTerms.length) {
        line.innerHTML = highlightLine(ev.line, query, mode, highlightTerms);
      } else {
        line.textContent = ev.line;
      }
      row.appendChild(line);
    }

    if (selectable) {
      row.classList.add("selectable");
      if (!skipSelectionHandler) {
        row.addEventListener("click", (e) => {
          e.stopPropagation();
          const id = row.dataset.id;
          if (!id) return;
          const vf = getVirtualFeed(activeFeed());
          if (vf) vf.toggleSelection(id, row);
          else row.classList.toggle("selected");
          updateSelectionHint();
        });
      }
    }

    if (onDblClick) {
      row.classList.add("dblclick-action");
      row.title = dblClickTitle || "Double-click for action";
      row.addEventListener("dblclick", (e) => {
        e.preventDefault();
        e.stopPropagation();
        onDblClick(ev);
      });
    }

    return row;
  }

  function trimFeed(el) {
    const vf = getVirtualFeed(el);
    if (vf) {
      vf.trimTo(maxRows);
      return;
    }
    let rows = el.querySelectorAll(".log-row");
    while (rows.length > maxRows) {
      rows[rows.length - 1].remove();
      rows = el.querySelectorAll(".log-row");
    }
  }

  function clearFeed(el) {
    seenIds.clear();
    const vf = getVirtualFeed(el);
    if (vf) {
      vf.clear();
    } else {
      el.innerHTML = "";
    }
    if (el === activeFeed()) {
      currentViewEvents = [];
      currentViewOpts = {};
    }
  }

  function populateFeed(el, events, opts = {}) {
    const merged = rowActionOpts({
      ...opts,
    });
    const resetSeen = merged.resetSeen !== false;
    if (el === activeFeed()) {
      currentViewEvents = (columnsMode ? events.map(ensureEventColumns) : events).slice();
      currentViewOpts = { ...merged };
    }
    const sourceEvents = columnsMode ? events.map(ensureEventColumns) : events;
    const displayEvents = columnsMode ? prepareColumnViewEvents(sourceEvents) : sourceEvents;
    if (columnsMode) {
      columnKeys = orderedColumnKeys(displayEvents.length ? displayEvents : sourceEvents);
    }

    const vf = getVirtualFeed(el);
    if (vf) {
      isPopulatingFeed = true;
      try {
        seenIds.clear();
        if (columnsMode && columnKeys.length) {
          ensureColumnHeader(el, columnKeys, merged.showSource);
        } else {
          removeColumnHeader(el);
        }
        vf.setEvents(displayEvents, {
          ...merged,
          onSelectionChange: el === activeFeed() ? updateSelectionHint : merged.onSelectionChange,
        });
      } finally {
        isPopulatingFeed = false;
      }
      return;
    }

    isPopulatingFeed = true;
    try {
      if (resetSeen) {
        seenIds.clear();
        el.innerHTML = "";
      } else {
        el.innerHTML = "";
      }
      if (columnsMode && columnKeys.length) {
        ensureColumnHeader(el, columnKeys, merged.showSource);
      } else {
        removeColumnHeader(el);
      }
      const frag = document.createDocumentFragment();
      for (const ev of displayEvents) {
        const row = renderRow(ev, merged);
        if (row) frag.appendChild(row);
      }
      el.appendChild(frag);
      trimFeed(el);
    } finally {
      isPopulatingFeed = false;
    }
  }

  async function fetchFullLog(path) {
    if (fullLogCache.has(path)) return fullLogCache.get(path);
    startActivity(`Loading full log ${basename(path)}…`);
    try {
      const res = await fetch(`/api/file/full?path=${encodeURIComponent(path)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      fullLogCache.set(path, data);
      stopActivity({ stage: `${(data.events || []).length} lines loaded` });
      return data;
    } catch (e) {
      stopActivity({ stage: String(e.message || e), error: true });
      throw e;
    }
  }

  function destroyVirtualFeed(el) {
    if (!virtualFeeds.has(el)) return;
    virtualFeeds.delete(el);
    el.classList.remove("virtual-feed-host");
    el.innerHTML = "";
  }

  function getSelectedExportEvents() {
    const vf = getVirtualFeed(activeFeed());
    if (vf) return vf.selectedEvents();
    return selectedRows().map(eventFromRow).filter((e) => e?.line);
  }

  let jumpHighlightTimer = null;

  function applyJumpHighlight(row) {
    if (!row) return;
    row.classList.add("focused", "jump-target");
    clearTimeout(jumpHighlightTimer);
    jumpHighlightTimer = setTimeout(() => {
      row.classList.remove("jump-target");
    }, 2600);
  }

  function focusRowInFeed(feed, ev) {
    if (!ev) return;
    const vf = getVirtualFeed(feed);
    if (vf) {
      vf.focusEvent(ev, { pulse: true });
      return;
    }
    const path = ev.source;
    let row = Array.from(feed.querySelectorAll(".log-row")).find(
      (r) =>
        r.dataset.source === path &&
        (ev.line_index == null || r.dataset.lineIndex === String(ev.line_index)) &&
        (ev.read_from == null || r.dataset.readFrom === String(ev.read_from))
    );
    if (!row && ev.line) {
      row = Array.from(feed.querySelectorAll(".log-row")).find((r) => {
        const lineEl = r.querySelector(".line-raw") || r.querySelector(".line");
        return (r.dataset.line || lineEl?.textContent) === ev.line;
      });
    }
    if (!row) return;
    feed.querySelectorAll(".log-row.focused").forEach((r) => {
      r.classList.remove("focused", "jump-target");
    });
    applyJumpHighlight(row);
    row.scrollIntoView({ block: "center", behavior: "auto" });
  }

  function abortExplainRequest() {
    if (explainAbortController) {
      explainAbortController.abort();
      explainAbortController = null;
    }
    stopExplainProgressTimer();
    hideExplainProgress();
    hideExplainCancelButtons();
    if (explainSubmitBtn) explainSubmitBtn.disabled = false;
  }

  function closeExplainModal() {
    abortExplainRequest();
    explainModal?.classList.add("hidden");
    explainEntry = null;
    explainStatus.textContent = "";
    if (
      logModal.classList.contains("hidden") &&
      searchHelpModal.classList.contains("hidden") &&
      explainModal?.classList.contains("hidden")
    ) {
      document.body.classList.remove("modal-open");
    }
  }

  function renderExplainResult(result) {
    const actions = Array.isArray(result.actions) && result.actions.length
      ? `<ul class="explain-actions-list">${result.actions.map((a) => `<li>${escapeHtml(a)}</li>`).join("")}</ul>`
      : "";
    explainResult.innerHTML = `
      <div class="explain-result-card severity-${escapeHtml(result.severity || "info")}">
        <p class="explain-result-summary"><strong>${escapeHtml(result.summary || "")}</strong></p>
        <p class="explain-result-text">${escapeHtml(result.explanation || "")}</p>
        ${actions}
      </div>
    `;
  }

  function eventFromRow(row) {
    if (!row) return null;
    const lineEl = row.querySelector(".line-raw") || row.querySelector(".line");
    return {
      source: row.dataset.source || "",
      line: row.dataset.line || lineEl?.textContent || "",
      line_index: row.dataset.lineIndex != null ? Number(row.dataset.lineIndex) : undefined,
      read_from: row.dataset.readFrom != null ? Number(row.dataset.readFrom) : undefined,
    };
  }

  function selectedRows() {
    return [...activeFeed().querySelectorAll(".log-row.selected")];
  }

  function updateSelectionHint() {
    const vf = getVirtualFeed(activeFeed());
    const count = vf ? vf.selectedIds.size : selectedRows().length;
    if (!viewLabel) return;
    const base = viewLabel.dataset.baseLabel || viewLabel.textContent.replace(/ · \d+ selected$/, "");
    if (!viewLabel.dataset.baseLabel) viewLabel.dataset.baseLabel = base;
    viewLabel.textContent = count ? `${base} · ${count} selected` : base;
  }

  function clearRowSelection() {
    const vf = getVirtualFeed(activeFeed());
    if (vf) vf.clearSelection();
    else activeFeed().querySelectorAll(".log-row.selected").forEach((r) => r.classList.remove("selected"));
    updateSelectionHint();
  }

  function downloadBlob(content, filename, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportSelectedOrAll() {
    const events = getSelectedExportEvents();
    if (!events.length) {
      window.location.href = buildExportUrl();
      return;
    }
    const fmt = exportFormat?.value || "txt";
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    if (fmt === "jsonl") {
      const body = events.map((ev) => JSON.stringify(ev)).join("\n") + "\n";
      downloadBlob(body, `syslogb-selected-${stamp}.jsonl`, "application/x-ndjson");
      return;
    }
    if (fmt === "csv") {
      const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
      const body = ["source,line", ...events.map((ev) => `${esc(ev.source)},${esc(ev.line)}`)].join("\n") + "\n";
      downloadBlob(body, `syslogb-selected-${stamp}.csv`, "text/csv");
      return;
    }
    const body = events.map((ev) => ev.line).join("\n") + "\n";
    downloadBlob(body, `syslogb-selected-${stamp}.txt`, "text/plain");
  }

  async function jumpToSearchHit(ev) {
    const path = ev.source;
    if (!path) return;
    searchActive = false;
    searchClearBtn.hidden = true;
    showSingleView();
    clearFeed(resultsFeed);
    removeColumnHeader(resultsFeed);
    await selectFile(path, basename(path), true, { focusEv: ev });
  }

  function eventFromFocusedRow(row) {
    if (!row) return null;
    const lineEl = row.querySelector(".line-raw") || row.querySelector(".line");
    return {
      source: row.dataset.source || logModalFocusEv?.source || "",
      line: row.dataset.line || lineEl?.textContent || "",
      line_index: row.dataset.lineIndex != null ? Number(row.dataset.lineIndex) : undefined,
      read_from: row.dataset.readFrom != null ? Number(row.dataset.readFrom) : undefined,
    };
  }

  function setLogModalFocus(row, ev) {
    logModalFeed.querySelectorAll(".log-row.focused").forEach((r) => r.classList.remove("focused"));
    if (!row) {
      if (logModalExplainBtn) logModalExplainBtn.disabled = !logModalFocusEv;
      return;
    }
    row.classList.add("focused");
    logModalFocusEv = eventFromFocusedRow(row) || ev || logModalFocusEv;
    if (logModalExplainBtn) logModalExplainBtn.disabled = !logModalFocusEv?.line;
  }

  function closeLogModal() {
    logModal.classList.add("hidden");
    logModalFocusEv = null;
    if (logModalExplainBtn) logModalExplainBtn.disabled = true;
    if (
      logModal.classList.contains("hidden") &&
      searchHelpModal.classList.contains("hidden") &&
      explainModal?.classList.contains("hidden")
    ) {
      document.body.classList.remove("modal-open");
    }
  }

  function openExplainModal(ev) {
    if (!llmEnabled) return;
    explainEntry = ev;
    explainEntrySource.textContent = ev.source ? `Source: ${ev.source}` : "";
    explainEntryLine.textContent = ev.line || "";
    explainQuestion.value = "";
    explainStatus.textContent = "";
    hideExplainProgress();
    hideExplainCancelButtons();
    explainResult.classList.add("hidden");
    explainResult.innerHTML = "";
    explainSubmitBtn.disabled = false;
    explainModal.classList.remove("hidden");
    document.body.classList.add("modal-open");
    explainQuestion.focus();
  }

  async function submitExplain() {
    if (!explainEntry || !explainEntry.line) return;
    abortExplainRequest();
    explainSubmitBtn.disabled = true;
    explainStatus.textContent = "";
    explainResult.classList.add("hidden");
    showExplainCancelButtons();
    startExplainProgress();
    explainAbortController = new AbortController();
    const { signal } = explainAbortController;
    try {
      const res = await fetch("/api/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          line: explainEntry.line,
          source: explainEntry.source || "",
          question: explainQuestion.value.trim(),
        }),
        signal,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      stopExplainProgressTimer();
      setExplainProgress(100, "Complete", "is-done");
      renderExplainResult(data.result || {});
      explainResult.classList.remove("hidden");
      explainStatus.textContent = "";
      setTimeout(() => hideExplainProgress(), 900);
    } catch (e) {
      stopExplainProgressTimer();
      if (e.name === "AbortError") {
        setExplainProgress(100, "Cancelled", "is-error");
        explainStatus.textContent = "Cancelled.";
        setTimeout(() => hideExplainProgress(), 600);
      } else {
        setExplainProgress(100, String(e.message || e), "is-error");
        explainStatus.textContent = "";
      }
    } finally {
      explainAbortController = null;
      hideExplainCancelButtons();
      explainSubmitBtn.disabled = false;
    }
  }

  function openSearchHelp() {
    searchHelpModal.classList.remove("hidden");
    document.body.classList.add("modal-open");
  }

  function closeSearchHelp() {
    searchHelpModal.classList.add("hidden");
    if (
      logModal.classList.contains("hidden") &&
      searchHelpModal.classList.contains("hidden") &&
      explainModal?.classList.contains("hidden")
    ) {
      document.body.classList.remove("modal-open");
    }
  }

  async function openLogModal(ev) {
    const path = ev.source;
    if (!path) return;

    logModalFocusEv = ev;
    logModal.classList.remove("hidden");
    document.body.classList.add("modal-open");
    logModalTitle.textContent = `Loading ${basename(path)}…`;
    logModalFeed.innerHTML = "";
    if (logModalExplainBtn) logModalExplainBtn.disabled = true;

    try {
      const data = await fetchFullLog(path);
      const truncated = data.read_from > 0 ? " (tail)" : "";
      const lineNo = (ev.line_index ?? 0) + 1;
      logModalTitle.textContent = `${basename(path)}${truncated} · line ${lineNo}`;
      populateFeed(logModalFeed, data.events || [], rowActionOpts({
        numbered: true,
        skipSeen: true,
        resetSeen: false,
        query: lastSearchQuery,
        mode: lastSearchMode,
        highlightTerms: lastHighlightTerms,
      }));
      requestAnimationFrame(() => {
        const row = Array.from(logModalFeed.querySelectorAll(".log-row")).find(
          (r) =>
            r.dataset.source === path &&
            r.dataset.lineIndex === String(ev.line_index) &&
            r.dataset.readFrom === String(ev.read_from)
        ) || Array.from(logModalFeed.querySelectorAll(".log-row")).find(
          (r) => r.querySelector(".line")?.textContent === ev.line
        );
        if (row) {
          setLogModalFocus(row, ev);
          row.scrollIntoView({ block: "center", behavior: "auto" });
        } else {
          focusRowInFeed(logModalFeed, ev);
          logModalExplainBtn.disabled = !logModalFocusEv?.line;
        }
      });
    } catch (e) {
      logModalTitle.textContent = `Full log — ${e.message || e}`;
      logModalFeed.innerHTML = "";
    }
  }

  function showSingleView() {
    if (logViewStack) logViewStack.classList.remove("hidden");
    feedSplit.classList.add("hidden");
  }

  function showSplitView() {
    if (logViewStack) logViewStack.classList.add("hidden");
    feedSplit.classList.remove("hidden");
  }

  function stopPoll() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function stopLive() {
    stopPoll();
    if (es) {
      es.close();
      es = null;
    }
  }

  function connectStream() {
    if (searchActive) return;
    stopLive();
    if (filterPath) return;
    showSingleView();
    clearFeed(feedSingle);
    fileViewport = null;
    updatePagingUi();
    const order = sortOrder.value;
    let streamUrl = `/api/stream?order=${order}`;
    const imp = importanceMinParam();
    if (imp) streamUrl += `&importance_min=${encodeURIComponent(imp)}`;
    es = new EventSource(streamUrl);
    streamStatus.textContent = "Live (failures only)";
    es.onopen = () => { streamStatus.textContent = "Live (failures only)"; };
    es.onerror = () => { streamStatus.textContent = "Reconnecting…"; };
    es.onmessage = (msg) => {
      try {
        const ev = JSON.parse(msg.data);
        if (paused) return;
        if (!searchActive && !filterPath) {
          currentViewEvents.push(ev);
          if (currentViewEvents.length > maxRows) {
            currentViewEvents.splice(0, currentViewEvents.length - maxRows);
          }
        }
        const streamEv = columnsMode ? ensureEventColumns(ev) : ev;
        if (columnsMode && !passesColumnFilters(streamEv)) return;
        if (columnsMode && streamEv.columns && columnKeys.length === 0) {
          columnKeys = orderedColumnKeys(currentViewEvents.length ? currentViewEvents : [streamEv]);
          ensureColumnHeader(feedSingle, columnKeys, true);
        }
        const vf = getVirtualFeed(feedSingle);
        const streamOpts = rowActionOpts({ showSource: true, sortDesc: order === "desc" });
        if (vf) {
          vf.opts = { ...vf.opts, ...streamOpts };
          vf.appendEvent(streamEv, { toTop: order !== "asc" });
          vf.trimTo(maxRows);
          return;
        }
        const row = renderRow(streamEv, streamOpts);
        if (!row) return;
        if (order === "asc") {
          feedSingle.appendChild(row);
          feedSingle.scrollTop = feedSingle.scrollHeight;
        } else {
          feedSingle.insertBefore(row, feedSingle.firstChild);
        }
        trimFeed(feedSingle);
      } catch (_) { /* keepalive */ }
    };
  }

  function buildExportUrl() {
    const fmt = exportFormat?.value || "txt";
    const order = sortOrder.value;
    let url = `/api/export?format=${encodeURIComponent(fmt)}&order=${encodeURIComponent(order)}`;
    if (searchActive && searchInput.value.trim()) {
      url += `&source=search&q=${encodeURIComponent(searchInput.value.trim())}`;
      url += `&mode=${encodeURIComponent(searchMode.value)}`;
      const scope = searchScope.value;
      if (scope === "file" && filterPath) {
        url += `&path=${encodeURIComponent(filterPath)}`;
      } else if (scope !== "all") {
        url += `&log_dir=${encodeURIComponent(scope)}`;
      }
    } else if (filterPath) {
      url += `&source=file&path=${encodeURIComponent(filterPath)}`;
    } else {
      url += "&source=search&q=";
    }
    return url;
  }

  async function runSearch() {
    const query = searchInput.value.trim();
    if (!query) return;

    if (searchAbortController) {
      searchAbortController.abort();
      searchAbortController = null;
    }

    stopLive();
    searchActive = true;
    updateAnalyzeButtonsEnabled();
    searchClearBtn.hidden = false;
    Object.keys(columnFilters).forEach((k) => { delete columnFilters[k]; });
    removeColumnHeader(feedSingle);
    showSplitView();

    const mode = searchMode.value;
    const order = sortOrder.value;
    lastSearchQuery = query;
    lastSearchMode = mode;
    let url = `/api/search?q=${encodeURIComponent(query)}&mode=${mode}&order=${order}`;
    url = appendImportance(url);
    const scope = searchScope.value;
    if (scope === "file" && filterPath) {
      url += `&path=${encodeURIComponent(filterPath)}`;
    } else if (scope !== "all") {
      url += `&log_dir=${encodeURIComponent(scope)}`;
    }

    streamStatus.textContent = "Searching…";
    viewLabel.textContent = `Search in ${searchScopeLabel(scope)}`;
    startActivity(`Searching ${searchScopeLabel(scope)}…`);
    searchAbortController = new AbortController();
    const { signal } = searchAbortController;
    showOperationCancel("search");

    try {
      const res = await fetch(url, { signal });
      const data = await res.json();
      if (!res.ok) {
        streamStatus.textContent = data.error || res.statusText;
        clearFeed(resultsFeed);
        stopActivity({ stage: data.error || res.statusText, error: true });
        return;
      }

      const events = data.events || [];
      lastHighlightTerms = data.highlight_terms || [];
      const ordered = order === "asc" ? events : [...events];
      populateFeed(resultsFeed, ordered, rowActionOpts({
        query: lastSearchQuery,
        mode,
        highlightTerms: lastHighlightTerms,
        showSource: scope !== "file",
        onDblClick: jumpToSearchHit,
        dblClickTitle: "Double-click to open file at this line",
        skipSeen: true,
      }));
      if (events.length && !resultsFeed.querySelector(".log-row")) {
        const note = document.createElement("p");
        note.className = "hint search-empty-note";
        note.textContent = columnsMode
          ? `${events.length} hit(s) hidden by column filters — clear filters in the header row above.`
          : "Hits were returned but could not be displayed.";
        resultsFeed.appendChild(note);
      }

      const scopeLabel = data.path
        ? basename(data.path)
        : (data.log_dir ? searchScopeLabel(data.log_dir) : searchScopeLabel("all"));
      streamStatus.textContent = `${data.count} hit(s) · ${mode} · ${scopeLabel}`;
      stopActivity({ stage: `${data.count} hit(s) found` });
    } catch (e) {
      if (e.name === "AbortError") return;
      streamStatus.textContent = String(e.message || e);
      clearFeed(resultsFeed);
      stopActivity({ stage: String(e.message || e), error: true });
    } finally {
      searchAbortController = null;
      if (cancellableOperation === "search") hideOperationCancel();
    }
  }

  function clearSearch() {
    searchActive = false;
    updateAnalyzeButtonsEnabled();
    searchClearBtn.hidden = true;
    searchInput.value = "";
    lastSearchQuery = "";
    lastHighlightTerms = [];
    closeLogModal();
    clearFeed(resultsFeed);
    showSingleView();
    clearFeed(feedSingle);
    if (filterPath) {
      selectFile(filterPath, basename(filterPath), true);
    } else {
      viewLabel.textContent = "All files (failures only)";
      connectStream();
    }
  }

  function isGroupExpanded(groupPath) {
    return expandedGroups.has(groupPath);
  }

  function setGroupExpanded(groupPath, expanded) {
    if (!groupPath) return;
    if (expanded) expandedGroups.add(groupPath);
    else expandedGroups.delete(groupPath);
    const header = document.querySelector(
      `li.file-group[data-group-path="${CSS.escape(groupPath)}"]`
    );
    const nested = document.querySelector(
      `ul.file-list-nested[data-group-for="${CSS.escape(groupPath)}"]`
    );
    if (header) {
      header.classList.toggle("collapsed", !expanded);
      const chev = header.querySelector(".file-group-chevron");
      if (chev) chev.textContent = expanded ? "▾" : "▸";
    }
    if (nested) nested.hidden = !expanded;
  }

  function toggleGroupExpanded(groupPath) {
    setGroupExpanded(groupPath, !isGroupExpanded(groupPath));
  }

  function syncSidebarSelection() {
    document.querySelectorAll(".file-list li[data-path]").forEach((el) => {
      el.classList.toggle("selected", el.dataset.path === (filterPath || ""));
    });
    document.querySelectorAll(".file-list li.file-group").forEach((el) => {
      const active = Boolean(filterGroup && el.dataset.groupPath === filterGroup && !filterPath);
      el.classList.toggle("selected", active);
    });
    const allRow = document.querySelector(".file-list li.file-list-all");
    if (allRow) {
      allRow.classList.toggle("selected", !filterPath && !filterGroup);
    }
  }

  function scheduleTooltip(sched) {
    if (!sched) return "";
    const parts = ["Scheduled LLM analysis"];
    if (!sched.enabled) parts.push("(disabled)");
    if (sched.interval_days) {
      const n = Number(sched.interval_days);
      parts.push(n === 1 ? "Daily" : `Every ${n} days`);
    }
    if (sched.next_run_at) {
      parts.push(`Next: ${new Date(sched.next_run_at * 1000).toLocaleString()}`);
    }
    return parts.join(" · ");
  }

  function ingestAnalysisSchedules(schedules) {
    scheduledByPath = new Map();
    for (const s of schedules || []) {
      if (s?.file_path) scheduledByPath.set(s.file_path, s);
    }
  }

  async function fetchAnalysisSchedules() {
    if (!llmEnabled) {
      ingestAnalysisSchedules([]);
      return;
    }
    try {
      const res = await fetch("/api/analysis-schedules");
      const data = await res.json();
      if (res.ok) ingestAnalysisSchedules(data.schedules);
    } catch (_) {
      /* keep previous map */
    }
  }

  function applyScheduleIndicators() {
    document.querySelectorAll(".file-list li.file-list-file[data-path]").forEach((li) => {
      const sched = scheduledByPath.get(li.dataset.path);
      let icon = li.querySelector(".file-schedule-icon");
      if (sched) {
        if (!icon) {
          icon = document.createElement("span");
          icon.className = "file-schedule-icon";
          icon.setAttribute("aria-hidden", "true");
          const name = li.querySelector(".file-name");
          if (name) li.insertBefore(icon, name);
          else li.prepend(icon);
        }
        icon.classList.toggle("disabled", !sched.enabled);
        icon.textContent = "⏱";
        icon.title = scheduleTooltip(sched);
      } else if (icon) {
        icon.remove();
      }
    });
  }

  async function refreshScheduleSidebarMarkers() {
    await fetchAnalysisSchedules();
    applyScheduleIndicators();
  }

  function appendFileRow(parent, f, prevFilter) {
    const li = document.createElement("li");
    li.className = "file-list-file";
    const sched = scheduledByPath.get(f.path);
    if (sched) {
      const icon = document.createElement("span");
      icon.className = "file-schedule-icon" + (sched.enabled ? "" : " disabled");
      icon.textContent = "⏱";
      icon.title = scheduleTooltip(sched);
      icon.setAttribute("aria-hidden", "true");
      li.appendChild(icon);
    }
    const name = document.createElement("span");
    name.className = "file-name";
    name.textContent = f.name + (f.readable ? "" : " 🔒");
    li.appendChild(name);
    const meta = document.createElement("span");
    meta.className = "file-meta";
    if (!f.group_label && f.log_dir_label && fileGroups.length === 0) {
      const dir = document.createElement("span");
      dir.className = "file-dir";
      dir.textContent = f.log_dir_label;
      dir.title = f.log_dir || f.log_dir_label;
      meta.appendChild(dir);
    }
    if (f.size_bytes != null) {
      const size = document.createElement("span");
      size.className = "file-size";
      size.textContent = formatFileSize(f.size_bytes);
      meta.appendChild(size);
    }
    if (f.compressed) {
      const gz = document.createElement("span");
      gz.className = "file-badge gz";
      gz.textContent = "gz";
      gz.title = "Compressed log (forward-only paging)";
      meta.appendChild(gz);
    }
    if (meta.childNodes.length) li.appendChild(meta);
    li.title = f.readable ? f.path : `${f.path}\n(no read permission)`;
    li.dataset.path = f.path;
    if (!f.readable) li.classList.add("locked");
    if (f.watching) li.classList.add("watching");
    if (f.path === prevFilter) li.classList.add("selected");
    li.addEventListener("click", (e) => {
      e.stopPropagation();
      selectFile(f.path, f.name, f.readable);
    });
    if (llmEnabled) {
      li.addEventListener("contextmenu", (e) => {
        if (!f.readable) return;
        e.preventDefault();
        selectFile(f.path, f.name, f.readable);
        showFileContextMenu(e.clientX, e.clientY, f.path);
      });
    }
    parent.appendChild(li);
    return li;
  }

  function isLocalhostGroupPath(groupPath) {
    return Boolean(groupPath && groupPath.endsWith("#localhost"));
  }

  function appendLocalhostGroupFiles(parent, files, prevFilter) {
    const buckets = new Map();
    for (const f of files) {
      const sub = f.local_subdir || "";
      if (!buckets.has(sub)) buckets.set(sub, []);
      buckets.get(sub).push(f);
    }
    const keys = [...buckets.keys()].sort((a, b) => {
      if (a === "") return -1;
      if (b === "") return 1;
      return a.localeCompare(b);
    });
    for (const sub of keys) {
      const bucketFiles = buckets.get(sub);
      bucketFiles.sort((a, b) => a.name.localeCompare(b.name));
      if (sub) {
        const subLi = document.createElement("li");
        subLi.className = "file-subgroup";
        const subName = document.createElement("span");
        subName.className = "file-subgroup-name";
        subName.textContent = sub;
        subLi.appendChild(subName);
        const subCount = document.createElement("span");
        subCount.className = "file-size";
        subCount.textContent = `${bucketFiles.length}`;
        subLi.appendChild(subCount);
        parent.appendChild(subLi);
        const subUl = document.createElement("ul");
        subUl.className = "file-list file-list-nested file-list-subnested";
        for (const f of bucketFiles) {
          appendFileRow(subUl, f, prevFilter);
        }
        parent.appendChild(subUl);
      } else {
        for (const f of bucketFiles) {
          appendFileRow(parent, f, prevFilter);
        }
      }
    }
  }

  function selectGroup(groupPath, label) {
    if (searchActive && searchInput.value.trim()) {
      filterGroup = groupPath || null;
      filterPath = null;
      selectedPath = null;
      updateAnalyzeButtonsEnabled();
      syncSidebarSelection();
      if (groupPath) searchScope.value = groupPath;
      updateSelectedFileScopeOption();
      runSearch();
      return;
    }

    stopLive();
    filterGroup = groupPath || null;
    filterPath = null;
    selectedPath = null;
    selectedReadable = true;
    selectedJournal = false;
    updateAnalyzeButtonsEnabled();
    clearRowSelection();
    showSingleView();
    clearFeed(feedSingle);
    feedSingle.classList.remove("single-file");
    fileViewport = null;
    updatePagingUi();
    updateTimeWindowUi();

    if (groupPath) {
      viewLabel.textContent = `Group: ${label}`;
      viewLabel.dataset.baseLabel = viewLabel.textContent;
      streamStatus.textContent = "Select a log file below";
      if (searchScope.querySelector(`option[value="${CSS.escape(groupPath)}"]`)) {
        searchScope.value = groupPath;
      }
    } else {
      viewLabel.textContent = "All files (failures only)";
      viewLabel.dataset.baseLabel = viewLabel.textContent;
      connectStream();
    }
    syncSidebarSelection();
    updateSelectedFileScopeOption();
  }

  async function selectFile(path, name, readable = true, { focusEv = null } = {}) {
    if (searchActive) {
      filterPath = path;
      let fileMeta = null;
      if (path) {
        fileMeta = allFilesCache.find((f) => f.path === path);
        filterGroup = fileMeta?.group_path || filterGroup;
      } else {
        filterGroup = null;
      }
      selectedPath = path;
      selectedReadable = readable;
      selectedJournal = Boolean(
        path && (path.startsWith("journal://") || fileMeta?.journal)
      );
      updateAnalyzeButtonsEnabled();
      syncSidebarSelection();
      updateSelectedFileScopeOption();
      if (searchInput.value.trim()) {
        await runSearch();
      }
      return;
    }

    stopLive();
    filterPath = path;
    let fileMeta = null;
    if (path) {
      fileMeta = allFilesCache.find((f) => f.path === path);
      filterGroup = fileMeta?.group_path || null;
    } else {
      filterGroup = null;
    }
    selectedPath = path;
    selectedReadable = readable;
    selectedJournal = Boolean(
      path && (path.startsWith("journal://") || fileMeta?.journal)
    );
    updateAnalyzeButtonsEnabled();
    clearRowSelection();
    Object.keys(columnFilters).forEach((k) => { delete columnFilters[k]; });
    const groupLabel = filterGroup
      ? (fileGroups.find((g) => g.path === filterGroup)?.label || basename(filterGroup))
      : null;
    const localSub = fileMeta?.local_subdir;
    let viewing = name ? `Viewing: ${name}` : "All files (failures only)";
    if (name && groupLabel) {
      viewing = localSub
        ? `Viewing: ${groupLabel} / ${localSub} / ${name}`
        : `Viewing: ${groupLabel} / ${name}`;
    }
    viewLabel.textContent = viewing + (readable || !name ? "" : " (no read permission)");
    viewLabel.dataset.baseLabel = viewLabel.textContent;
    syncSidebarSelection();
    updateSelectedFileScopeOption();
    showSingleView();
    clearFeed(feedSingle);
    feedSingle.classList.toggle("single-file", Boolean(path));
    updateTimeWindowUi();

    if (!path) {
      fileViewport = null;
      updatePagingUi();
      connectStream();
      return;
    }

    if (!readable) {
      fileViewport = null;
      updatePagingUi();
      streamStatus.textContent = "Permission denied — try: newgrp adm";
      return;
    }

    if (focusEv) {
      await loadFilePageAtHit(path, focusEv);
    } else {
      fileViewport = null;
      await loadFilePage(path, { direction: "tail", replace: true });
    }
    if (focusEv) {
      requestAnimationFrame(() => focusRowInFeed(feedSingle, focusEv));
    }
    if (!fileViewport?.forward_only) {
      pollTimer = setInterval(() => {
        if (filterPath !== path) return;
        if (!isFileTailFollow()) return;
        loadRecentForFile(path);
      }, 2500);
    }
  }

  async function loadFiles() {
    const filesPromise = fetch("/api/files");
    const schedulesPromise = llmEnabled ? fetch("/api/analysis-schedules") : null;
    const res = await filesPromise;
    const data = await res.json();
    if (schedulesPromise) {
      try {
        const schedRes = await schedulesPromise;
        const schedData = await schedRes.json();
        if (schedRes.ok) ingestAnalysisSchedules(schedData.schedules);
      } catch (_) {
        /* keep previous map */
      }
    } else {
      ingestAnalysisSchedules([]);
    }
    const prevFilter = filterPath;
    const prevGroup = filterGroup;
    fileList.innerHTML = "";
    allFilesCache = data.files || [];
    fileGroups = data.groups || [];
    if (sidebarGroupsHint) {
      sidebarGroupsHint.classList.toggle("hidden", fileGroups.length === 0);
    }

    const allLi = document.createElement("li");
    allLi.className = "file-list-all";
    const allName = document.createElement("span");
    allName.className = "file-name";
    allName.textContent = "All files";
    allLi.appendChild(allName);
    allLi.dataset.path = "";
    allLi.addEventListener("click", () => selectGroup(null, null));
    fileList.appendChild(allLi);

    if (fileGroups.length) {
      const byGroup = new Map();
      for (const g of fileGroups) byGroup.set(g.path, { ...g, files: [] });
      const ungrouped = [];
      for (const f of allFilesCache) {
        if (f.group_path && byGroup.has(f.group_path)) {
          byGroup.get(f.group_path).files.push(f);
        } else {
          ungrouped.push(f);
        }
      }
      for (const g of fileGroups) {
        const files = byGroup.get(g.path)?.files || [];
        const expanded = expandedGroups.has(g.path)
          || (prevFilter && files.some((f) => f.path === prevFilter))
          || (prevGroup === g.path && prevFilter);
        if (expanded) expandedGroups.add(g.path);

        const groupLi = document.createElement("li");
        groupLi.className = "file-group" + (expanded ? "" : " collapsed");
        groupLi.dataset.groupPath = g.path;
        const chevron = document.createElement("span");
        chevron.className = "file-group-chevron";
        chevron.textContent = expanded ? "▾" : "▸";
        groupLi.appendChild(chevron);
        const groupName = document.createElement("span");
        groupName.className = "file-name";
        groupName.textContent = g.label;
        groupLi.appendChild(groupName);
        const count = document.createElement("span");
        count.className = "file-size";
        count.textContent = `${files.length}`;
        groupLi.appendChild(count);
        groupLi.title = `${g.path}\nClick to expand · double-click to search this host`;
        groupLi.addEventListener("click", (e) => {
          e.stopPropagation();
          toggleGroupExpanded(g.path);
        });
        groupLi.addEventListener("dblclick", (e) => {
          e.stopPropagation();
          if (!isGroupExpanded(g.path)) setGroupExpanded(g.path, true);
          selectGroup(g.path, g.label);
        });
        fileList.appendChild(groupLi);

        const nested = document.createElement("ul");
        nested.className = "file-list file-list-nested";
        nested.dataset.groupFor = g.path;
        nested.hidden = !expanded;
        if (isLocalhostGroupPath(g.path)) {
          appendLocalhostGroupFiles(nested, files, prevFilter);
        } else {
          for (const f of files) {
            appendFileRow(nested, f, prevFilter);
          }
        }
        fileList.appendChild(nested);
      }
      for (const f of ungrouped) {
        appendFileRow(fileList, f, prevFilter);
      }
    } else {
      for (const f of allFilesCache) {
        appendFileRow(fileList, f, prevFilter);
      }
    }

    filterGroup = prevGroup;
    if (prevFilter) {
      const still = allFilesCache.find((f) => f.path === prevFilter);
      if (still && (!filterGroup || still.group_path === filterGroup)) {
        filterPath = prevFilter;
      } else {
        filterPath = null;
      }
    }
    syncSidebarSelection();
    updateSearchScopeOptions(data.log_dirs || [], fileGroups);
  }

  async function submitAnalyze(path = selectedPath, { scope = "full" } = {}) {
    if (!path) return;
    if (scope === "window" && (!filterPath || path !== filterPath)) {
      streamStatus.textContent = "Open this log file to analyze its time range.";
      return;
    }
    setAnalyzeButtonsDisabled(true);
    analyzeStatus.textContent = "";
    const body = { path, scope };
    if (scope === "window") {
      body.window = fileWindowParam() || "1h";
    }
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      startAnalyzePoll(data.job_id);
    } catch (e) {
      const msg = String(e.message || e);
      if (analyzeStatus) analyzeStatus.textContent = msg;
      streamStatus.textContent = msg;
      hideAnalyzeProgress();
      updateAnalyzeButtonsEnabled();
    }
  }

  if (llmEnabled) {
    if (analyzeBtn) {
      analyzeBtn.addEventListener("click", () => {
        submitAnalyze(selectedPath, { scope: "full" });
      });
    }
    if (analyzeBtnToolbar) {
      analyzeBtnToolbar.addEventListener("click", () => {
        submitAnalyze(filterPath || selectedPath, { scope: "window" });
      });
    }

    if (fileContextAnalyzeBtn) {
      fileContextAnalyzeBtn.addEventListener("click", () => {
        const path = contextMenuPath || selectedPath;
        hideFileContextMenu();
        if (path) submitAnalyze(path, { scope: "full" });
      });
    }
    if (fileContextMenu) {
      fileContextMenu.addEventListener("click", (e) => {
        const btn = e.target.closest("[data-action]");
        if (!btn) return;
        const path = contextMenuPath || selectedPath;
        if (btn.dataset.action === "schedule" && path) {
          openScheduleModal(path);
        }
      });
    }
    scheduleModalClose?.addEventListener("click", closeScheduleModal);
    scheduleModalBackdrop?.addEventListener("click", closeScheduleModal);
    scheduleScope?.addEventListener("change", updateScheduleWindowUi);
    scheduleSaveBtn?.addEventListener("click", saveSchedule);
    scheduleDeleteBtn?.addEventListener("click", deleteSchedule);
  }

  document.addEventListener("click", (e) => {
    if (!fileContextMenu || fileContextMenu.classList.contains("hidden")) return;
    if (fileContextMenu.contains(e.target)) return;
    hideFileContextMenu();
  });
  window.addEventListener("scroll", hideFileContextMenu, true);
  window.addEventListener("resize", hideFileContextMenu);

  sortOrder.addEventListener("change", async () => {
    if (searchActive && searchInput.value.trim()) {
      await runSearch();
    } else if (filterPath) {
      await loadFilePage(filterPath, { direction: "tail", replace: true });
    } else {
      clearFeed(feedSingle);
      connectStream();
    }
  });

  pauseBtn.addEventListener("click", () => {
    paused = !paused;
    pauseBtn.textContent = paused ? "Resume" : "Pause";
  });

  if (logTimeWindow) {
    logTimeWindow.addEventListener("change", () => {
      if (filterPath) {
        fileViewport = null;
        loadFilePage(filterPath, { direction: "tail", replace: true });
      }
    });
  }

  if (analyzeCancelBtn) {
    analyzeCancelBtn.addEventListener("click", () => cancelAnalyzeJob());
  }
  if (activityCancelBtn) {
    activityCancelBtn.addEventListener("click", () => cancelActiveOperation());
  }

  if (explainCancelBtn) {
    explainCancelBtn.addEventListener("click", () => abortExplainRequest());
  }
  if (explainProgressCancelBtn) {
    explainProgressCancelBtn.addEventListener("click", () => abortExplainRequest());
  }
  if (explainModalCancelBtn) {
    explainModalCancelBtn.addEventListener("click", () => abortExplainRequest());
  }

  if (columnsToggleBtn) {
    columnsToggleBtn.addEventListener("click", () => {
      columnsMode = !columnsMode;
      columnsToggleBtn.classList.toggle("active", columnsMode);
      if (!columnsMode) {
        columnSortKey = null;
        columnSortDir = "asc";
        Object.keys(columnFilters).forEach((k) => { delete columnFilters[k]; });
      } else {
        destroyVirtualFeed(feedSingle);
        destroyVirtualFeed(resultsFeed);
      }
      if (currentViewEvents.length) {
        rerenderActiveFeed();
        return;
      }
      if (searchActive && searchInput.value.trim()) {
        runSearch();
      } else if (filterPath) {
        loadFilePage(filterPath, { direction: "tail", replace: true });
      }
    });
  }
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      exportSelectedOrAll();
    });
  }

  if (importanceMinSelect) {
    importanceMinSelect.addEventListener("change", async () => {
      if (searchActive && searchInput.value.trim()) {
        await runSearch();
      } else if (filterPath) {
        await loadFilePage(filterPath, { direction: "tail", replace: true });
      } else {
        connectStream();
      }
    });
  }

  if (loadOlderBtn) {
    loadOlderBtn.addEventListener("click", () => {
      if (filterPath) loadFilePage(filterPath, { direction: "older", replace: false });
    });
  }

  if (loadNewerBtn) {
    loadNewerBtn.addEventListener("click", () => {
      if (filterPath) loadFilePage(filterPath, { direction: "newer", replace: false });
    });
  }

  if (savedSearchSelect) {
    savedSearchSelect.addEventListener("change", () => {
      const id = savedSearchSelect.value;
      if (savedSearchDeleteBtn) savedSearchDeleteBtn.hidden = !id;
      if (id) applySavedSearch(id);
    });
  }
  if (savedSearchSaveBtn) {
    savedSearchSaveBtn.addEventListener("click", () => saveCurrentSearch());
  }
  if (savedSearchDeleteBtn) {
    savedSearchDeleteBtn.addEventListener("click", () => deleteCurrentSavedSearch());
  }

  reloadSavedSearches();

  searchBtn.addEventListener("click", runSearch);
  searchClearBtn.addEventListener("click", clearSearch);
  searchScope.addEventListener("change", () => {
    if (searchActive && searchInput.value.trim()) {
      runSearch();
    }
  });
  searchInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") runSearch();
  });

  searchHelpBtn.addEventListener("click", openSearchHelp);
  searchHelpClose.addEventListener("click", closeSearchHelp);
  searchHelpBackdrop.addEventListener("click", closeSearchHelp);

  if (llmEnabled) {
    explainModalClose?.addEventListener("click", closeExplainModal);
    explainModalBackdrop?.addEventListener("click", closeExplainModal);
    explainSubmitBtn?.addEventListener("click", submitExplain);
    logModalExplainBtn?.addEventListener("click", () => {
      if (logModalFocusEv?.line) openExplainModal(logModalFocusEv);
    });
  }

  logModalClose.addEventListener("click", closeLogModal);
  logModalBackdrop.addEventListener("click", closeLogModal);
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (!fileContextMenu?.classList.contains("hidden")) {
      hideFileContextMenu();
      return;
    }
    if (scheduleModal && !scheduleModal.classList.contains("hidden")) {
      closeScheduleModal();
    } else if (explainModal && !explainModal.classList.contains("hidden")) {
      closeExplainModal();
    } else if (!searchHelpModal.classList.contains("hidden")) {
      closeSearchHelp();
    } else if (!logModal.classList.contains("hidden")) {
      closeLogModal();
    }
  });

  updateTimeWindowUi();
  loadFiles();
  connectStream();
  setInterval(loadFiles, 10000);
  if (llmEnabled) refreshAnalysisHistory();
})();
