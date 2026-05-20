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
      --ink: #12212d;
      --muted: #61707d;
      --line: rgba(18, 33, 45, 0.12);
      --bg: #edf2f7;
      --panel: rgba(255, 255, 255, 0.88);
      --panel-strong: #ffffff;
      --safe: #177d53;
      --warn: #a96d18;
      --bad: #ab2f3f;
      --accent: #1d6f8a;
      --accent-2: #4b5ed7;
      --shadow: 0 18px 55px rgba(13, 28, 43, 0.12);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(29, 111, 138, 0.14), transparent 33%),
        radial-gradient(circle at 88% 8%, rgba(75, 94, 215, 0.12), transparent 28%),
        linear-gradient(180deg, #f7fbfe 0%, var(--bg) 100%);
      font: 15px/1.5 "Segoe UI Variable Text", "Aptos", "Trebuchet MS", sans-serif;
      min-height: 100vh;
    }

    .shell {
      width: min(1180px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 20px 0 40px;
    }

    header {
      display: grid;
      gap: 16px;
      padding: 18px 22px 20px;
      margin-bottom: 18px;
      border: 1px solid var(--line);
      border-radius: 24px;
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.96), rgba(245, 249, 252, 0.84));
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
    }

    .hero {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 20px;
      flex-wrap: wrap;
    }

    .title {
      display: grid;
      gap: 8px;
      max-width: 720px;
    }

    .eyebrow {
      color: var(--accent);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.16em;
      text-transform: uppercase;
    }

    h1 {
      margin: 0;
      font-size: clamp(30px, 4vw, 46px);
      line-height: 1.02;
      letter-spacing: -0.04em;
    }

    .subtitle {
      margin: 0;
      max-width: 60ch;
      color: var(--muted);
    }

    .status-pills {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      justify-content: flex-end;
    }

    .chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-height: 36px;
      padding: 0 14px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.78);
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
      white-space: nowrap;
    }

    .chip strong {
      color: var(--ink);
    }

    .chip.ok { color: var(--safe); }
    .chip.warn { color: var(--warn); }
    .chip.bad { color: var(--bad); }

    main {
      display: grid;
      gap: 18px;
    }

    .toolbar {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 20px;
      background: var(--panel);
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
    }

    input, button {
      min-height: 42px;
      border-radius: 14px;
      font: inherit;
    }

    input {
      width: 100%;
      border: 1px solid var(--line);
      padding: 0 14px;
      color: var(--ink);
      background: var(--panel-strong);
      outline: none;
      transition: border-color 140ms ease, box-shadow 140ms ease, transform 140ms ease;
    }

    input:focus {
      border-color: rgba(29, 111, 138, 0.45);
      box-shadow: 0 0 0 4px rgba(29, 111, 138, 0.12);
    }

    button {
      border: 0;
      padding: 0 18px;
      color: #fff;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 12px 24px rgba(29, 111, 138, 0.18);
      transition: transform 140ms ease, box-shadow 140ms ease, opacity 140ms ease;
    }

    button:hover:not(:disabled) {
      transform: translateY(-1px);
      box-shadow: 0 16px 30px rgba(29, 111, 138, 0.22);
    }

    button:disabled {
      opacity: .65;
      cursor: wait;
    }

    .grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 340px;
      gap: 18px;
      align-items: start;
    }

    .panel {
      border: 1px solid var(--line);
      border-radius: 20px;
      background: var(--panel);
      box-shadow: var(--shadow);
      overflow: hidden;
      backdrop-filter: blur(12px);
    }

    .panel-head {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.6);
    }

    .panel-head h2 {
      margin: 0;
      font-size: 14px;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }

    .panel-head span {
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }

    .stack {
      display: grid;
      gap: 18px;
    }

    .hero-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      padding: 16px;
    }

    .metric {
      display: grid;
      gap: 4px;
      padding: 14px 14px 15px;
      border-radius: 16px;
      background: linear-gradient(180deg, rgba(248, 251, 254, 0.95), rgba(241, 246, 251, 0.92));
      border: 1px solid rgba(18, 33, 45, 0.08);
    }

    .metric strong {
      font-size: 24px;
      line-height: 1;
      letter-spacing: -0.03em;
    }

    .metric span {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      padding: 0 16px 16px;
    }

    .ghost {
      background: transparent;
      color: var(--ink);
      border: 1px solid var(--line);
      box-shadow: none;
    }

    .ghost:hover:not(:disabled) {
      box-shadow: none;
      background: rgba(255, 255, 255, 0.9);
    }

    .content {
      display: grid;
      gap: 18px;
    }

    .result {
      overflow: hidden;
    }

    .result-body {
      display: grid;
      gap: 16px;
      padding: 16px;
    }

    .verdict-banner {
      display: grid;
      gap: 10px;
      padding: 16px;
      border-radius: 18px;
      background: linear-gradient(135deg, rgba(29, 111, 138, 0.08), rgba(75, 94, 215, 0.08));
      border: 1px solid rgba(18, 33, 45, 0.08);
    }

    .verdict-row {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
    }

    .verdict-row strong {
      font-size: 30px;
      letter-spacing: -0.04em;
    }

    .verdict-meta {
      color: var(--muted);
      font-weight: 700;
    }

    .verdict {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 7px 12px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 800;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      background: rgba(255, 255, 255, 0.72);
      border: 1px solid rgba(18, 33, 45, 0.1);
    }

    .SAFE { color: var(--safe); }
    .SUSPICIOUS { color: var(--warn); }
    .MALICIOUS, .INVALID { color: var(--bad); }

    .subgrid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }

    .subcard {
      padding: 12px 13px;
      border-radius: 16px;
      border: 1px solid rgba(18, 33, 45, 0.08);
      background: rgba(255, 255, 255, 0.82);
      display: grid;
      gap: 4px;
    }

    .subcard span {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 800;
    }

    .subcard strong {
      font-size: 18px;
      letter-spacing: -0.02em;
    }

    dl {
      display: grid;
      grid-template-columns: 110px 1fr;
      gap: 10px 12px;
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
      padding: 4px 10px;
      color: var(--muted);
      background: rgba(255, 255, 255, 0.82);
      font-size: 13px;
    }

    .empty {
      padding: 18px;
      color: var(--muted);
    }

    .recent-list {
      display: grid;
      gap: 12px;
      padding: 16px;
    }

    .recent-item {
      padding: 14px;
      border-radius: 16px;
      border: 1px solid rgba(18, 33, 45, 0.08);
      background: rgba(255, 255, 255, 0.82);
      display: grid;
      gap: 10px;
    }

    .recent-top {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
    }

    .recent-domain {
      font-weight: 800;
      overflow-wrap: anywhere;
    }

    .recent-meta {
      color: var(--muted);
      font-size: 13px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px 12px;
    }

    .recent-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    .recent-tags span {
      padding: 4px 8px;
      border-radius: 999px;
      background: rgba(29, 111, 138, 0.08);
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
    }

    .quick-grid {
      display: grid;
      gap: 10px;
      padding: 16px;
    }

    .quick-grid button {
      width: 100%;
      justify-content: flex-start;
      text-align: left;
    }

    @media (max-width: 980px) {
      .grid, .hero-grid, .subgrid { grid-template-columns: 1fr 1fr; }
      .grid { grid-template-columns: 1fr; }
    }

    @media (max-width: 720px) {
      .shell { width: min(100vw - 20px, 1180px); padding-top: 10px; }
      header { padding: 16px; border-radius: 20px; }
      .toolbar { grid-template-columns: 1fr; }
      .hero-grid, .subgrid { grid-template-columns: 1fr; }
      .status-pills { justify-content: flex-start; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header>
      <div class="hero">
        <div class="title">
          <div class="eyebrow">OPEX-first local control plane</div>
          <h1>Safe Road Dashboard</h1>
          <p class="subtitle">Analyze suspicious domains, inspect recent verdicts, and keep the local system readable without dragging in a heavy frontend stack.</p>
        </div>
        <div class="status-pills">
          <span class="chip" id="api-status"><strong>core-api</strong> checking</span>
          <span class="chip" id="cache-state"><strong>cache</strong> idle</span>
        </div>
      </div>
      <div class="hero-grid">
        <div class="metric"><strong id="metric-total">0</strong><span>Recent items</span></div>
        <div class="metric"><strong id="metric-safe">0</strong><span>Safe verdicts</span></div>
        <div class="metric"><strong id="metric-suspicious">0</strong><span>Suspicious verdicts</span></div>
        <div class="metric"><strong id="metric-malicious">0</strong><span>Malicious verdicts</span></div>
      </div>
    </header>

    <main>
      <form class="toolbar" id="analyze-form">
        <input id="domain" name="domain" autocomplete="off" spellcheck="false" placeholder="secure-login-wallet-example.com">
        <button id="submit" type="submit">Analyze domain</button>
      </form>

      <div class="actions" id="quick-actions">
        <button class="ghost" type="button" data-domain="example.com">Example domain</button>
        <button class="ghost" type="button" data-domain="secure-login-wallet-example.com">Suspicious sample</button>
        <button class="ghost" type="button" data-domain="login.bank-verify-support.com">Phishing-style sample</button>
        <button class="ghost" type="button" data-domain="xn--pple-43d.com">Punycode sample</button>
      </div>

      <div class="grid">
        <section class="panel content">
          <div class="panel-head">
            <h2>Live result</h2>
            <span id="result-state">waiting</span>
          </div>
          <div class="result" id="result">
            <div class="empty">No result yet. Run a domain through the analyzer.</div>
          </div>
        </section>

        <div class="stack">
          <section class="panel">
            <div class="panel-head">
              <h2>Recent activity</h2>
              <span id="recent-count">0</span>
            </div>
            <div class="recent-list" id="recent">
              <div class="empty">No cached history.</div>
            </div>
          </section>

          <section class="panel">
            <div class="panel-head">
              <h2>Quick checks</h2>
              <span>local only</span>
            </div>
            <div class="quick-grid">
              <div class="empty" style="padding: 0;">The dashboard polls health and recent activity every 15 seconds, so it stays cheap to run on a single VPS.</div>
            </div>
          </section>
        </div>
      </div>
    </main>
  </div>

  <script>
    const form = document.querySelector("#analyze-form");
    const domainInput = document.querySelector("#domain");
    const submit = document.querySelector("#submit");
    const result = document.querySelector("#result");
    const recent = document.querySelector("#recent");
    const recentCount = document.querySelector("#recent-count");
    const cacheState = document.querySelector("#cache-state");
    const apiStatus = document.querySelector("#api-status");
    const resultState = document.querySelector("#result-state");
    const metricTotal = document.querySelector("#metric-total");
    const metricSafe = document.querySelector("#metric-safe");
    const metricSuspicious = document.querySelector("#metric-suspicious");
    const metricMalicious = document.querySelector("#metric-malicious");
    const quickActions = document.querySelector("#quick-actions");

    const state = {
      latest: null,
      recent: []
    };

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const domain = domainInput.value.trim();
      if (!domain) return;
      await analyzeDomain(domain);
    });

    quickActions.addEventListener("click", async (event) => {
      const button = event.target.closest("button[data-domain]");
      if (!button) return;
      domainInput.value = button.dataset.domain;
      await analyzeDomain(button.dataset.domain);
    });

    async function analyzeDomain(domain) {
      submit.disabled = true;
      resultState.textContent = "analyzing";
      try {
        const response = await fetch("/v1/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain })
        });
        const payload = await response.json();
        state.latest = payload;
        renderResult(payload);
        await loadRecent();
        resultState.textContent = "fresh result";
      } catch (error) {
        result.innerHTML = '<div class="empty">Request failed.</div>';
        resultState.textContent = "request failed";
      } finally {
        submit.disabled = false;
      }
    }

    async function loadRecent() {
      try {
        const response = await fetch("/v1/analysis/recent");
        const payload = await response.json();
        const items = payload.items || [];
        state.recent = items;
        recentCount.textContent = items.length;
        updateMetrics(items);
        if (!items.length) {
          recent.innerHTML = '<div class="empty">No cached history.</div>';
          return;
        }

        recent.innerHTML = items.map(renderRecentItem).join("");
      } catch (error) {
        recent.innerHTML = '<div class="empty">Recent unavailable.</div>';
      }
    }

    async function checkHealth() {
      try {
        const response = await fetch("/healthz");
        const payload = await response.json();
        const ok = payload.status === "ok";
        apiStatus.className = ok ? "chip ok" : "chip warn";
        apiStatus.innerHTML = ok ? "<strong>core-api</strong> healthy" : "<strong>core-api</strong> limited";
      } catch (error) {
        apiStatus.className = "chip bad";
        apiStatus.innerHTML = "<strong>core-api</strong> offline";
      }
    }

    function renderResult(item) {
      cacheState.innerHTML = item.cache_hit ? "<strong>cache</strong> hit" : "<strong>cache</strong> fresh";
      const reasons = item.reasons && item.reasons.length
        ? '<ul class="reasons">' + item.reasons.map(reason => '<li>' + escapeHTML(reason) + '</li>').join("") + '</ul>'
        : '<ul class="reasons"><li>no risk signals</li></ul>';

      result.innerHTML =
        '<div class="verdict-banner">' +
          '<div class="verdict-row">' +
            '<strong class="' + item.verdict + '">' + item.verdict + '</strong>' +
            '<span class="verdict-meta">' + Math.round(item.confidence * 100) + '% confidence · score ' + item.score + '</span>' +
          '</div>' +
          '<span class="verdict ' + item.verdict + '">' + item.verdict + '</span>' +
        '</div>' +
        '<div class="subgrid">' +
          '<div class="subcard"><span>Domain</span><strong>' + escapeHTML(item.domain) + '</strong></div>' +
          '<div class="subcard"><span>Analyzed</span><strong>' + formatTime(item.analyzed_at) + '</strong></div>' +
          '<div class="subcard"><span>Source</span><strong>' + (item.cache_hit ? 'cache' : 'fresh') + '</strong></div>' +
        '</div>' +
        '<dl><dt>Reasons</dt><dd>' + reasons + '</dd></dl>';
    }

    function updateMetrics(items) {
      const summary = items.reduce((accumulator, item) => {
        accumulator.total += 1;
        if (item.verdict === "SAFE") accumulator.safe += 1;
        if (item.verdict === "SUSPICIOUS") accumulator.suspicious += 1;
        if (item.verdict === "MALICIOUS") accumulator.malicious += 1;
        return accumulator;
      }, { total: 0, safe: 0, suspicious: 0, malicious: 0 });

      metricTotal.textContent = summary.total;
      metricSafe.textContent = summary.safe;
      metricSuspicious.textContent = summary.suspicious;
      metricMalicious.textContent = summary.malicious;
    }

    function renderRecentItem(item) {
      const tags = item.reasons && item.reasons.length
        ? item.reasons.slice(0, 3).map(reason => '<span>' + escapeHTML(reason) + '</span>').join("")
        : '<span>no signals</span>';

      return '<article class="recent-item">' +
        '<div class="recent-top">' +
          '<div class="recent-domain">' + escapeHTML(item.domain) + '</div>' +
          '<span class="verdict ' + item.verdict + '">' + item.verdict + '</span>' +
        '</div>' +
        '<div class="recent-meta"><span>Score ' + item.score + '</span><span>' + Math.round(item.confidence * 100) + '% confidence</span><span>' + formatTime(item.analyzed_at) + '</span></div>' +
        '<div class="recent-tags">' + tags + '</div>' +
      '</article>';
    }

    function formatTime(value) {
      if (!value) return "";
      return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
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

    async function refreshShell() {
      await Promise.all([checkHealth(), loadRecent()]);
      if (!state.latest && state.recent.length) {
        renderResult(state.recent[0]);
      }
    }

    refreshShell();
    setInterval(refreshShell, 15000);
  </script>
</body>
</html>`
