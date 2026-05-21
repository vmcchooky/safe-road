# Safe Road

Safe Road is a zero-cost-first anti-phishing system whose default deployment target is a single budget VPS, with local-friendly Go services for development and validation.

Legacy note: [docs/Safe_Road_SRS_Zero_Cost_v1.0.md](docs/Safe_Road_SRS_Zero_Cost_v1.0.md) is kept for historical reference only. The active roadmap is [docs/Safe_Road_OPEX_Estimate.md](docs/Safe_Road_OPEX_Estimate.md) plus the OPEX-first spec pack under [docs/specs/opex-cost-optimization](docs/specs/opex-cost-optimization).

## Current build

- `core-api`: HTTP API for health checks, cached domain analysis, `/metrics`, and the local dashboard
- `dns-resolver`: local policy service with a real DoH `/dns-query` endpoint and `/metrics`
- `feed-syncd`: optional interval-based threat-feed sync daemon for scheduled updates
- `redis`: optional local cache for analysis results and dashboard history
- `internal/analysis`: deterministic lexical scoring for the first release
- `internal/cache`: Redis JSON helpers with fail-open behavior
- `internal/feed`: feed parsing and sync helpers shared by the CLI and daemon
- `internal/ai`: optional Gemini 2.5 Flash Lite refinement for ambiguous domains
- `internal/observability`: in-memory request metrics registry used by both HTTP services
- `internal/risk`: shared analysis, cache, policy, and status service used by both binaries
- `internal/serve`: graceful shutdown helper for local and container runs

## Run locally

```bash
go run ./cmd/core-api
go run ./cmd/dns-resolver
```

Defaults:

- `core-api` listens on `:8080`
- `dns-resolver` listens on `:8081`
- Redis is disabled unless `SAFE_ROAD_REDIS_ADDR` is set
- Dashboard: <http://localhost:8080/dashboard>

Optional local Redis:

```bash
docker run --rm -p 6379:6379 redis:7-alpine
$env:SAFE_ROAD_REDIS_ADDR = "localhost:6379"
```

Useful endpoints:

```bash
curl "http://localhost:8080/"
curl "http://localhost:8080/metrics"
curl "http://localhost:8080/v1/analyze?domain=secure-login-wallet-example.com"
curl "http://localhost:8081/"
curl "http://localhost:8081/metrics"
curl "http://localhost:8081/v1/policy?domain=secure-login-wallet-example.com"
```

## Threat feed

Threat feed entries are normalized domains stored in Redis Set `safe-road:threat:feed`. Use `feed-sync` manually first:

```bash
go run ./cmd/feed-sync -source ./feeds/local.txt -dry-run
go run ./cmd/feed-sync -source ./feeds/local.txt -redis-addr localhost:6379
```

Threat feed sync also accepts `.gz` feeds over local file paths or HTTP(S) URLs.
The optional daemon is available as `go run ./cmd/feed-syncd --once` or through the Compose `feed-sync` profile.

Accepted feed formats are simple TXT files with one domain per line or CSV files where any field may contain the domain. Exact matches and subdomain suffix matches return `MALICIOUS` with reason `matched local threat feed`.

The DoH endpoint accepts standard DNS wire-format GET or POST requests at:

```text
http://localhost:8081/dns-query
```

## Local AI

Safe Road can optionally refine ambiguous risk results using Gemini 2.5 Flash Lite.

Defaults:

- `SAFE_ROAD_GEMINI_BASE_URL`: `https://generativelanguage.googleapis.com/v1beta`
- `SAFE_ROAD_GEMINI_API_KEY`: empty, so AI is disabled unless explicitly configured
- `SAFE_ROAD_GEMINI_MODEL`: `gemini-2.5-flash-lite`
- `SAFE_ROAD_GEMINI_TIMEOUT_MS`: `3000`

The AI path is fail-open: if Gemini is unavailable or returns invalid JSON, analysis continues with lexical and threat-feed results.

## Build

```bash
go build ./...
```

## Docker

```bash
docker compose up --build
```

Compose starts `core-api`, `dns-resolver`, and an internal Redis service for local validation. The production baseline is a single budget VPS, and overrides live in a local `.env` file based on `.env.example`.
The runtime image includes an internal HTTP healthcheck, and the optional `feed-syncd` service is gated behind the `feed-sync` Compose profile.

## Operations

Use the PowerShell helper for day-to-day deployment and storage maintenance:

```powershell
pwsh ./scripts/safe-road.ps1 deploy
pwsh ./scripts/safe-road.ps1 status
pwsh ./scripts/safe-road.ps1 backup
pwsh ./scripts/safe-road.ps1 restore
pwsh ./scripts/safe-road.ps1 prune
```

- `deploy` builds and starts the Compose stack, then waits for the health endpoints.
- `backup` writes a Redis RDB snapshot to `backups/redis/<timestamp>/dump.rdb`.
- `restore` reloads Redis from the newest snapshot or a path you pass in.
- `prune` keeps the newest backups and removes stale `tmp/*.log` files.

The same actions are also available as VS Code tasks in [.vscode/tasks.json](.vscode/tasks.json).

For a Linux VPS, [ops/cron/safe-road.cron.example](ops/cron/safe-road.cron.example) provides a ready-made cron template for daily backup and prune jobs.

## Deployment Baseline

- Default production target: single budget VPS
- Preferred node: Hetzner CPX21 or equivalent 2 vCPU / 4 GB RAM
- Budget ceiling for the baseline path: about $10/month
- Higher tiers such as Vultr, DigitalOcean, Linode, or HA multi-node setups require explicit exception and cost justification

## Optional Services

- Redis is optional for local development and stays disabled unless `SAFE_ROAD_REDIS_ADDR` is set.
- `feed-syncd` is optional and only runs when the `feed-sync` Compose profile is enabled.
- Metrics, health checks, and the current local dashboard remain self-hosted and dependency-free.

## Notes

This build is still local-first. DoT, Gemini, public TLS, DuckDNS, and production Caddy wiring can layer on top of the current Redis and DoH foundation.
Roadmap decisions should follow [docs/Safe_Road_OPEX_Estimate.md](docs/Safe_Road_OPEX_Estimate.md) as the source of truth for cost and deployment targets.
Cost-sensitive changes should follow [docs/specs/opex-cost-optimization/policy.md](docs/specs/opex-cost-optimization/policy.md) and the PR checklist at [.github/pull_request_template.md](.github/pull_request_template.md).
