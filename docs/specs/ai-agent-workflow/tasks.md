# Tasks: AI Agent Workflow

## Milestone 1: Agent Engine

- [ ] Thêm bảng `agent_audit_log` vào schema SQLite (`internal/store/sqlite.go`).
- [ ] Thêm methods `RecordAgentEvent`, `QueryAgentEvents`, `QuerySuspiciousDomains` vào `store.DB`.
- [ ] Viết tests cho các store methods mới.
- [ ] Tạo package `internal/agent/engine.go` — Task interface, Engine struct, Register, Start, Stop, Trigger.
- [ ] Viết `engine_test.go` — test lifecycle, scheduling, manual trigger, timeout, disabled skip.
- [ ] Expose `StoreDB()`, `AIClient()`, `RedisCache()` trên `risk.Service`.
- [ ] Thêm API routes `/v1/agent/status` và `POST /v1/agent/trigger` vào `cmd/core-api/main.go`.
- [ ] Cập nhật `.env.example` với `SAFE_ROAD_AGENT_ENABLED` và env vars Engine.

## Milestone 2: Telemetry Audit Task

- [ ] Tạo `internal/agent/audit.go` — AuditTask struct, implement Task interface.
- [ ] Logic: query suspicious domains → check override → enrich (TLS+WHOIS) → AI refine (optional) → auto-block.
- [ ] Viết `audit_test.go` — test full flow với in-memory SQLite, mock enrichment.
- [ ] Cập nhật `.env.example` với env vars Audit (interval, timeout, min_occurrences, max_per_cycle, confidence_threshold).

## Milestone 3: Multi-Source Feed Sync Task

- [ ] Tạo `internal/agent/feedsync.go` — FeedSyncTask struct, implement Task interface.
- [ ] Logic: parse comma-separated sources → call `feed.Sync()` cho mỗi source → additive SADD → audit log.
- [ ] Viết `feedsync_test.go` — test multi-source, partial failure, audit log recording.
- [ ] Cập nhật `.env.example` với `SAFE_ROAD_AGENT_FEED_SOURCES` và env vars FeedSync.

## Milestone 4: Webhook Alert Task

- [ ] Tạo `internal/agent/alert.go` — AlertTask struct, implement Task interface.
- [ ] Logic: query recent agent events → build payload → detect Discord format → POST webhook.
- [ ] Viết `alert_test.go` — test payload format, Discord detect, empty skip, HTTP errors.
- [ ] Cập nhật `.env.example` với `SAFE_ROAD_AGENT_WEBHOOK_URL` và env vars Alert.

## Milestone 5: Dashboard Integration

- [ ] Cập nhật `cmd/core-api/dashboard.html` tab System: hiển thị Agent status, task list, trigger buttons.

## Milestone 6: Verification

- [ ] `go build ./...` pass.
- [ ] `go test ./...` pass.
- [ ] `go test -race ./internal/agent/...` pass.
- [ ] Smoke test: bật Agent, chờ audit cycle, kiểm tra auto-block trong overrides.
- [ ] Cập nhật README với Agent Workflow documentation.

## Completion Rule

Không thêm task mới ngoài danh sách này trừ khi có spec entry mới được tạo.
