# Tasks: Admin Dashboard v2

## Phase 1: Tab Navigation & Layout Restructuring

- [ ] Add CSS for tab bar, tab content sections, and responsive breakpoints.
- [ ] Restructure existing HTML into `#tab-analysis` content section.
- [ ] Create empty tab content sections: `#tab-telemetry`, `#tab-overrides`, `#tab-system`.
- [ ] Add tab switching JS logic with state management.
- [ ] Verify existing analysis functionality still works after restructuring.

## Phase 2: Telemetry Tab

- [ ] Add telemetry stats cards (Total, Safe, Suspicious, Malicious, Cache Hits).
- [ ] Add period selector (24h / 7d / 30d) with active state.
- [ ] Add Chart.js `<script>` from CDN with graceful fallback.
- [ ] Add doughnut chart for verdict distribution.
- [ ] Add paginated telemetry recent table.
- [ ] Add pagination controls (Prev / Next / Page indicator).
- [ ] Wire up period selector to re-fetch stats and update chart.
- [ ] Wire up auto-refresh for active telemetry tab.

## Phase 3: Overrides Tab

- [ ] Add "Add Override" form: domain input, action toggle (allow/block), reason input.
- [ ] Add form submission handler with API call to `POST /v1/overrides`.
- [ ] Add override list table rendering from `GET /v1/overrides`.
- [ ] Add action filter buttons (All / Allow / Block).
- [ ] Add delete button per override with confirmation prompt.
- [ ] Add inline success/error toast messages.
- [ ] Wire up auto-refresh for override list.

## Phase 4: System Tab

- [ ] Add service status cards (core-api, Redis, SQLite).
- [ ] Add uptime display (from `/metrics` uptime_seconds).
- [ ] Add request summary table (from `/metrics` request_summary).
- [ ] Calculate and display average latency per endpoint.
- [ ] Wire up auto-refresh.

## Phase 5: Polish & Responsive

- [ ] Add smooth tab transition animations.
- [ ] Test mobile layout (375px+) for all tabs.
- [ ] Add dark mode CSS via `@media (prefers-color-scheme: dark)`.
- [ ] Verify Chart.js graceful degradation when CDN unavailable.
- [ ] Update header metrics to use telemetry stats instead of recent list.

## Phase 6: Verification

- [ ] `go build ./cmd/core-api/...` — compiles with updated embed.
- [ ] Manual test: all 4 tabs render correctly.
- [ ] Manual test: override CRUD works from UI.
- [ ] Manual test: telemetry chart updates on period change.
- [ ] Manual test: mobile layout on Chrome DevTools.
