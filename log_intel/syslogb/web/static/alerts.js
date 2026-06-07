(() => {
  const table = document.getElementById("alert-events-table");
  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }
  fetch("/api/alert-events?limit=200")
    .then((r) => r.json())
    .then((data) => {
      const rows = data.events || [];
      if (!rows.length) {
        table.innerHTML = "<p class=\"hint\">No alert events yet.</p>";
        return;
      }
      table.innerHTML = `<table class="data-table"><thead><tr>
        <th>Time</th><th>Channel</th><th>Status</th><th>Source</th><th>Line</th>
      </tr></thead><tbody>${rows.map((e) => `
        <tr>
          <td>${esc(new Date(e.created_at * 1000).toLocaleString())}</td>
          <td>${esc(e.channel)}</td>
          <td>${esc(e.status)}</td>
          <td>${esc(e.source)}</td>
          <td class="mono">${esc(e.line)}</td>
        </tr>
      `).join("")}</tbody></table>`;
    })
    .catch((e) => {
      table.textContent = String(e.message || e);
    });
})();
