(() => {
  const DEFAULT_ROW_HEIGHT = 26;
  const OVERSCAN = 20;

  function binarySearchPrefix(prefix, y) {
    let lo = 0;
    let hi = prefix.length - 2;
    while (lo < hi) {
      const mid = Math.floor((lo + hi + 1) / 2);
      if (prefix[mid] <= y) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  }

  class VirtualLogFeed {
    constructor(containerEl, renderRowFn) {
      this.container = containerEl;
      this.renderRow = renderRowFn;
      this.events = [];
      this.opts = {};
      this.selectedIds = new Set();
      this.rowHeights = [];
      this.prefixTop = [0];
      this.defaultRowHeight = DEFAULT_ROW_HEIGHT;
      this.overscan = OVERSCAN;
      this._scrollRaf = null;
      this._clickTimer = null;
      this._lastDblClickAt = 0;
      this._pendingAnchor = null;
      this.focusedAnchor = null;
      this.jumpHighlight = false;
      this._jumpHighlightTimer = null;

      this.container.classList.add("virtual-feed-host");
      this.container.innerHTML = "";

      this.spacer = document.createElement("div");
      this.spacer.className = "virtual-feed-spacer";
      this.rowsEl = document.createElement("div");
      this.rowsEl.className = "virtual-feed-rows";
      this.container.appendChild(this.spacer);
      this.container.appendChild(this.rowsEl);

      this.container.addEventListener("scroll", () => this._scheduleRender(), { passive: true });
      this.container.addEventListener("click", (e) => this._onClick(e));
      this.container.addEventListener("dblclick", () => {
        this._lastDblClickAt = Date.now();
        if (this._clickTimer) {
          clearTimeout(this._clickTimer);
          this._clickTimer = null;
        }
      });
    }

    _scheduleRender() {
      if (this._scrollRaf != null) return;
      this._scrollRaf = requestAnimationFrame(() => {
        this._scrollRaf = null;
        this.render();
      });
    }

    _anchorFromEvent(ev) {
      return {
        id: ev.id,
        source: ev.source,
        line_index: ev.line_index,
        read_from: ev.read_from,
        line: ev.line,
      };
    }

    _matchesAnchor(ev, anchor) {
      if (!anchor) return false;
      if (anchor.id && ev.id === anchor.id) return true;
      if (anchor.line && ev.line === anchor.line && ev.source === anchor.source) return true;
      if (
        anchor.line_index != null
        && ev.line_index === anchor.line_index
        && ev.source === anchor.source
        && (anchor.read_from == null || ev.read_from === anchor.read_from)
      ) {
        return true;
      }
      return false;
    }

    focusEvent(ev, { pulse = true } = {}) {
      if (!ev) {
        this.focusedAnchor = null;
        this.jumpHighlight = false;
        this.render();
        return false;
      }
      this.focusedAnchor = this._anchorFromEvent(ev);
      if (pulse) {
        this.jumpHighlight = true;
        clearTimeout(this._jumpHighlightTimer);
        this._jumpHighlightTimer = setTimeout(() => {
          this.jumpHighlight = false;
          this.render();
        }, 2600);
      }
      return this.scrollToEvent(ev);
    }

    _onClick(e) {
      if (Date.now() - this._lastDblClickAt < 350) return;
      const row = e.target.closest(".log-row.selectable");
      if (!row || !this.container.contains(row)) return;
      const id = row.dataset.id;
      if (!id) return;
      if (this._clickTimer) clearTimeout(this._clickTimer);
      this._clickTimer = setTimeout(() => {
        this._clickTimer = null;
        this.toggleSelection(id, row);
        this.opts.onSelectionChange?.();
      }, 0);
    }

    toggleSelection(id, rowEl = null) {
      const key = String(id);
      if (this.selectedIds.has(key)) this.selectedIds.delete(key);
      else this.selectedIds.add(key);
      if (rowEl) rowEl.classList.toggle("selected", this.selectedIds.has(key));
      else {
        const row = this.container.querySelector(`.log-row[data-id="${CSS.escape(key)}"]`);
        if (row) row.classList.toggle("selected", this.selectedIds.has(key));
      }
    }

    clearSelection() {
      this.selectedIds.clear();
      this.container.querySelectorAll(".log-row.selected").forEach((r) => r.classList.remove("selected"));
    }

    selectedEvents() {
      if (!this.selectedIds.size) return [];
      const wanted = this.selectedIds;
      return this.events.filter((ev) => wanted.has(String(ev.id)));
    }

    _pruneSelection() {
      if (!this.selectedIds.size) return;
      const ids = new Set(this.events.map((ev) => String(ev.id)));
      for (const id of [...this.selectedIds]) {
        if (!ids.has(id)) this.selectedIds.delete(id);
      }
    }

    _rebuildPrefix() {
      const tops = [0];
      for (const h of this.rowHeights) tops.push(tops[tops.length - 1] + h);
      this.prefixTop = tops;
      this.spacer.style.height = `${tops[tops.length - 1]}px`;
    }

    _visibleStartIndex() {
      if (!this.events.length) return 0;
      return Math.max(
        0,
        Math.min(
          this.events.length - 1,
          binarySearchPrefix(this.prefixTop, this.container.scrollTop)
        )
      );
    }

    isTailFollow(sortDesc, threshold = 48) {
      if (!this.events.length) return true;
      const { scrollTop, clientHeight, scrollHeight } = this.container;
      if (sortDesc) return scrollTop <= threshold;
      return scrollTop + clientHeight >= scrollHeight - threshold;
    }

    anchorEvent() {
      if (!this.events.length) return null;
      return this.events[this._visibleStartIndex()];
    }

    scrollToIndex(index) {
      if (index < 0 || index >= this.events.length) return false;
      this.container.scrollTop = this.prefixTop[index] || 0;
      this.render();
      return true;
    }

    setPendingAnchor(anchor) {
      this._pendingAnchor = anchor || null;
    }

    _applyPendingAnchor() {
      if (!this._pendingAnchor) return false;
      const anchor = this._pendingAnchor;
      this._pendingAnchor = null;
      if (this.scrollToEvent(anchor)) return true;
      if (anchor.line_index != null) {
        const idx = this.events.findIndex(
          (e) =>
            e.source === anchor.source
            && e.line_index === anchor.line_index
            && (anchor.read_from == null || e.read_from === anchor.read_from)
        );
        if (idx >= 0) return this.scrollToIndex(idx);
      }
      if (anchor.line) {
        const idx = this.events.findIndex((e) => e.line === anchor.line);
        if (idx >= 0) return this.scrollToIndex(idx);
      }
      return false;
    }

    scrollToTop() {
      this.container.scrollTop = 0;
      this.render();
    }

    scrollToBottom() {
      const max = Math.max(0, this.container.scrollHeight - this.container.clientHeight);
      this.container.scrollTop = max;
      this.render();
    }

    _resetHeights() {
      this.rowHeights = new Array(this.events.length).fill(this.defaultRowHeight);
      this._rebuildPrefix();
    }

    setEvents(events, opts = {}) {
      this.events = events.slice();
      this.opts = { ...opts };
      this._pruneSelection();
      this._resetHeights();
      if (!opts.preserveFocus) {
        this.focusedAnchor = null;
        this.jumpHighlight = false;
      }
      this.render();
    }

    clear() {
      this.events = [];
      this.opts = {};
      this.focusedAnchor = null;
      this.jumpHighlight = false;
      clearTimeout(this._jumpHighlightTimer);
      this.selectedIds.clear();
      this.rowHeights = [];
      this.prefixTop = [0];
      this.spacer.style.height = "0px";
      this.rowsEl.innerHTML = "";
      this.rowsEl.style.transform = "translateY(0px)";
    }

    appendEvent(ev, { toTop = false } = {}) {
      if (toTop) this.events.unshift(ev);
      else this.events.push(ev);
      if (toTop) this.rowHeights.unshift(this.defaultRowHeight);
      else this.rowHeights.push(this.defaultRowHeight);
      this._rebuildPrefix();
      this.render();
    }

    trimTo(maxEvents) {
      if (this.events.length <= maxEvents) return;
      const drop = this.events.length - maxEvents;
      if (this.opts.sortDesc) {
        this.events.splice(maxEvents);
        this.rowHeights.splice(maxEvents);
      } else {
        this.events.splice(0, drop);
        this.rowHeights.splice(0, drop);
      }
      this._pruneSelection();
      this._rebuildPrefix();
      this.render();
    }

    render() {
      if (!this.events.length) {
        this.rowsEl.innerHTML = "";
        this.rowsEl.style.transform = "translateY(0px)";
        return;
      }

      const scrollTop = this.container.scrollTop;
      const viewHeight = this.container.clientHeight || 600;
      const start = Math.max(0, binarySearchPrefix(this.prefixTop, scrollTop) - this.overscan);
      const end = Math.min(
        this.events.length,
        binarySearchPrefix(this.prefixTop, scrollTop + viewHeight) + this.overscan + 1
      );

      const top = this.prefixTop[start] || 0;
      this.rowsEl.style.transform = `translateY(${top}px)`;
      this.rowsEl.innerHTML = "";

      const frag = document.createDocumentFragment();
      const rowOpts = {
        ...this.opts,
        selectable: this.opts.selectable !== false,
        skipSeen: true,
        skipSelectionHandler: true,
      };

      for (let i = start; i < end; i += 1) {
        const ev = this.events[i];
        const row = this.renderRow(ev, rowOpts);
        if (!row) continue;
        row.dataset.virtualIndex = String(i);
        if (this.selectedIds.has(String(ev.id))) row.classList.add("selected");
        if (this.focusedAnchor && this._matchesAnchor(ev, this.focusedAnchor)) {
          row.classList.add("focused");
          if (this.jumpHighlight) row.classList.add("jump-target");
        }
        frag.appendChild(row);
      }
      this.rowsEl.appendChild(frag);

      requestAnimationFrame(() => this._measureVisible(start, end));
    }

    _measureVisible(start, end) {
      const rows = this.rowsEl.querySelectorAll(".log-row");
      let changed = false;
      rows.forEach((row) => {
        const i = Number(row.dataset.virtualIndex);
        if (Number.isNaN(i)) return;
        const h = Math.max(row.offsetHeight, this.defaultRowHeight);
        if (Math.abs(h - this.rowHeights[i]) > 1) {
          this.rowHeights[i] = h;
          changed = true;
        }
      });
      if (!changed) {
        this._applyPendingAnchor();
        return;
      }
      this._rebuildPrefix();
      const scrollTop = this.container.scrollTop;
      const viewHeight = this.container.clientHeight || 600;
      const newStart = Math.max(0, binarySearchPrefix(this.prefixTop, scrollTop) - this.overscan);
      const newEnd = Math.min(
        this.events.length,
        binarySearchPrefix(this.prefixTop, scrollTop + viewHeight) + this.overscan + 1
      );
      if (newStart !== start || newEnd !== end) this.render();
      else {
        const top = this.prefixTop[newStart] || 0;
        this.rowsEl.style.transform = `translateY(${top}px)`;
      }
      this._applyPendingAnchor();
    }

    scrollToEvent(ev) {
      let idx = this.events.findIndex((e) => e.id === ev.id);
      if (idx < 0 && ev.line_index != null) {
        idx = this.events.findIndex(
          (e) =>
            e.source === ev.source
            && e.line_index === ev.line_index
            && (ev.read_from == null || e.read_from === ev.read_from)
        );
      }
      if (idx < 0 && ev.line) {
        idx = this.events.findIndex((e) => e.line === ev.line);
      }
      if (idx < 0) return false;
      if (ev) {
        this.focusedAnchor = this._anchorFromEvent(ev);
      }
      this.container.scrollTop = this.prefixTop[idx] || 0;
      this.render();
      return true;
    }
  }

  window.VirtualLogFeed = VirtualLogFeed;
})();
