# Safe Road

Safe Road is a zero-cost-first anti-phishing system that starts as a local-friendly Go service stack and can later move to a single budget VPS.

## Current build

- `core-api`: HTTP API for health checks, cached domain analysis, and the local dashboard
- `dns-resolver`: local policy service with a real DoH `/dns-query` endpoint
- `redis`: optional local cache for analysis results and dashboard history
- `internal/analysis`: deterministic lexical scoring for the first release
- `internal/cache`: Redis JSON helpers with fail-open behavior
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
curl "http://localhost:8080/v1/analyze?domain=secure-login-wallet-example.com"
curl "http://localhost:8081/"
curl "http://localhost:8081/v1/policy?domain=secure-login-wallet-example.com"
```

## Threat feed

Threat feed entries are normalized domains stored in Redis Set `safe-road:threat:feed`. Use `feed-sync` manually first:

```bash
go run ./cmd/feed-sync -source ./feeds/local.txt -dry-run
go run ./cmd/feed-sync -source ./feeds/local.txt -redis-addr localhost:6379
```

Threat feed sync also accepts `.gz` feeds over local file paths or HTTP(S) URLs.

Accepted feed formats are simple TXT files with one domain per line or CSV files where any field may contain the domain. Exact matches and subdomain suffix matches return `MALICIOUS` with reason `matched local threat feed`.

The DoH endpoint accepts standard DNS wire-format GET or POST requests at:

```text
http://localhost:8081/dns-query
```

## Build

```bash
go build ./...
```

## Docker

```bash
docker compose up --build
```

Compose starts `core-api`, `dns-resolver`, and an internal Redis service. Override values through a local `.env` file based on `.env.example`.

## Notes

This build is still local-first. DoT, Ollama, public TLS, DuckDNS, and production Caddy wiring can layer on top of the current Redis and DoH foundation.
