(() => {
  const origFetch = window.fetch.bind(window);
  const MUTATING = new Set(["POST", "PUT", "DELETE", "PATCH"]);

  window.fetch = (input, init = {}) => {
    const method = String(init.method || "GET").toUpperCase();
    if (!MUTATING.has(method)) {
      return origFetch(input, init);
    }
    const headers = new Headers(init.headers || {});
    if (!headers.has("X-Requested-With")) {
      headers.set("X-Requested-With", "XMLHttpRequest");
    }
    return origFetch(input, { ...init, headers });
  };
})();
