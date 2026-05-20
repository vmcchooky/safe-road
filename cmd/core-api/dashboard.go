package main

import "net/http"

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(dashboardHTML))
}

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Safe Road Dashboard</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #172026;
      --muted: #66727c;
      --line: #d9e1e7;
      --bg: #f6f8fa;
      --panel: #ffffff;
      --safe: #1f8a5b;
      --warn: #b7791f;
      --bad: #bd2b2b;
      --accent: #246b8f;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      color: var(--ink);
      background: var(--bg);
      font: 15px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 18px clamp(16px, 4vw, 40px);
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }

    h1 {
      margin: 0;
      font-size: 22px;
      font-weight: 750;
      letter-spacing: 0;
    }

    main {
      display: grid;
      gap: 18px;
      width: min(1120px, calc(100vw - 32px));
      margin: 24px auto 40px;
    }

    .toolbar {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 10px;
      align-items: center;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
    }

    input, button {
      min-height: 42px;
      border-radius: 7px;
      font: inherit;
    }

    input {
      width: 100%;
      border: 1px solid var(--line);
      padding: 0 12px;
      color: var(--ink);
      background: #fff;
    }

    button {
      border: 0;
      padding: 0 18px;
      color: #fff;
      background: var(--accent);
      font-weight: 700;
      cursor: pointer;
    }

    button:disabled {
      opacity: .65;
      cursor: wait;
    }

    .grid {
      display: grid;
      grid-template-columns: minmax(280px, .9fr) minmax(0, 1.4fr);
      gap: 18px;
      align-items: start;
    }

    section {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      overflow: hidden;
    }

    .section-head {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 13px 14px;
      border-bottom: 1px solid var(--line);
      color: var(--muted);
      font-size: 13px;
      font-weight: 750;
      text-transform: uppercase;
    }

    .result {
      display: grid;
      gap: 14px;
      padding: 16px;
    }

    .verdict {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--line);
    }

    .verdict strong {
      font-size: 28px;
      letter-spacing: 0;
    }

    .SAFE { color: var(--safe); }
    .SUSPICIOUS { color: var(--warn); }
    .MALICIOUS, .INVALID { color: var(--bad); }

    dl {
      display: grid;
      grid-template-columns: 110px 1fr;
      gap: 8px 12px;
      margin: 0;
    }

    dt { color: var(--muted); }
    dd {
      margin: 0;
      overflow-wrap: anywhere;
      font-weight: 650;
    }

    .reasons {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 0;
      padding: 0;
      list-style: none;
    }

    .reasons li {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 9px;
      color: var(--muted);
      background: #fbfcfd;
      font-size: 13px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }

    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }

    th {
      color: var(--muted);
      font-size: 13px;
      font-weight: 750;
    }

    tr:last-child td { border-bottom: 0; }

    .empty {
      padding: 18px;
      color: var(--muted);
    }

    @media (max-width: 760px) {
      header { align-items: flex-start; flex-direction: column; }
      .toolbar { grid-template-columns: 1fr; }
      .grid { grid-template-columns: 1fr; }
      table { table-layout: auto; }
      th:nth-child(5), td:nth-child(5) { display: none; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Safe Road</h1>
    <span id="api-status">core-api</span>
  </header>

  <main>
    <form class="toolbar" id="analyze-form">
      <input id="domain" name="domain" autocomplete="off" spellcheck="false" placeholder="example.com">
      <button id="submit" type="submit">Analyze</button>
    </form>

    <div class="grid">
      <section>
        <div class="section-head"><span>Result</span><span id="cache-state">cache</span></div>
        <div class="result" id="result">
          <div class="empty">No result yet.</div>
        </div>
      </section>

      <section>
        <div class="section-head"><span>Recent</span><span id="recent-count">0</span></div>
        <div id="recent"></div>
      </section>
    </div>
  </main>

  <script>
    const form = document.querySelector("#analyze-form");
    const domainInput = document.querySelector("#domain");
    const submit = document.querySelector("#submit");
    const result = document.querySelector("#result");
    const recent = document.querySelector("#recent");
    const recentCount = document.querySelector("#recent-count");
    const cacheState = document.querySelector("#cache-state");
    const apiStatus = document.querySelector("#api-status");

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const domain = domainInput.value.trim();
      if (!domain) return;

      submit.disabled = true;
      try {
        const response = await fetch("/v1/analyze?domain=" + encodeURIComponent(domain));
        const payload = await response.json();
        renderResult(payload);
        await loadRecent();
      } catch (error) {
        result.innerHTML = '<div class="empty">Request failed.</div>';
      } finally {
        submit.disabled = false;
      }
    });

    async function loadRecent() {
      try {
        const response = await fetch("/v1/analysis/recent");
        const payload = await response.json();
        const items = payload.items || [];
        recentCount.textContent = items.length;
        if (!items.length) {
          recent.innerHTML = '<div class="empty">No cached history.</div>';
          return;
        }

        recent.innerHTML = '<table><thead><tr><th>Domain</th><th>Verdict</th><th>Score</th><th>Signal</th><th>Time</th></tr></thead><tbody>' +
          items.map(item => '<tr><td>' + escapeHTML(item.domain) + '</td><td class="' + item.verdict + '">' + item.verdict + '</td><td>' + item.score + '</td><td>' + primarySignal(item) + '</td><td>' + formatTime(item.analyzed_at) + '</td></tr>').join("") +
          '</tbody></table>';
      } catch (error) {
        recent.innerHTML = '<div class="empty">Recent unavailable.</div>';
      }
    }

    async function checkHealth() {
      try {
        const response = await fetch("/healthz");
        const payload = await response.json();
        apiStatus.textContent = payload.status === "ok" ? "core-api ok" : "core-api";
      } catch (error) {
        apiStatus.textContent = "core-api offline";
      }
    }

    function renderResult(item) {
      cacheState.textContent = item.cache_hit ? "cache hit" : "fresh";
      const reasons = item.reasons && item.reasons.length
        ? '<ul class="reasons">' + item.reasons.map(reason => '<li>' + escapeHTML(reason) + '</li>').join("") + '</ul>'
        : '<ul class="reasons"><li>no risk signals</li></ul>';

      result.innerHTML =
        '<div class="verdict"><strong class="' + item.verdict + '">' + item.verdict + '</strong><span>' + Math.round(item.confidence * 100) + '%</span></div>' +
        '<dl><dt>Domain</dt><dd>' + escapeHTML(item.domain) + '</dd><dt>Score</dt><dd>' + item.score + '</dd><dt>Analyzed</dt><dd>' + formatTime(item.analyzed_at) + '</dd></dl>' +
        reasons;
    }

    function formatTime(value) {
      if (!value) return "";
      return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    }

    function primarySignal(item) {
      if (!item.reasons || !item.reasons.length) return "none";
      return escapeHTML(item.reasons[0]);
    }

    function escapeHTML(value) {
      return String(value || "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
      }[char]));
    }

    checkHealth();
    loadRecent();
  </script>
</body>
</html>`
