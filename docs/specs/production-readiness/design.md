# Design: Production Readiness

## Overview

This milestone set keeps Safe Road local-first while adding the minimum operational surface needed for a real deployment: visibility, repeatable feed ingestion, container health, and test-backed contracts.

## Observability Design

- Use an in-memory registry inside each HTTP service.
- Capture request counts, response bytes, and latency by method, route, and status code.
- Expose the snapshot as JSON from `/metrics`.
- Keep the registry dependency-free so it works in every environment.

## Feed Sync Design

- Keep parsing and Redis writes in `internal/feed`.
- Make `cmd/feed-sync` a one-shot wrapper around the shared sync implementation.
- Make `cmd/feed-syncd` a loop around the same sync implementation.
- Support local files, HTTP/HTTPS URLs, and gzip-compressed feeds.
- Allow `--once` for manual or scheduled single-run execution.

## Container Design

- Use the same runtime image for all binaries.
- Configure the internal healthcheck endpoint through environment variables.
- Keep `core-api` on port 8080 and `dns-resolver` on port 8081.
- Add an optional Compose profile for the feed-sync daemon so local dev does not start it accidentally.

## Testing Design

- HTTP status endpoints should be tested through a real `httptest.NewServer`.
- Metrics should be validated through actual HTTP requests against the service mux.
- Feed sync should be tested at the library layer, not by shelling into the command.
- A small number of integration tests should protect the milestone boundaries instead of broad end-to-end duplication.

## Non-Goals

- Prometheus, OpenTelemetry, or external tracing systems.
- Queue-based scheduling or a database-backed job runner.
- Production orchestration beyond Docker Compose.
- Broad feature expansion beyond the four milestones.