# Tasks: Production Readiness

## Milestone 1: Observability Baseline

- [x] Add an in-memory request metrics registry.
- [x] Expose `/metrics` on `core-api`.
- [x] Expose `/metrics` on `dns-resolver`.
- [x] Expand request logging with status, bytes, and duration.
- [x] Add HTTP tests for the status and metrics endpoints.

## Milestone 2: Automated Threat Feed Sync

- [x] Extract reusable sync logic into `internal/feed`.
- [x] Keep the one-shot `cmd/feed-sync` wrapper thin.
- [x] Add `cmd/feed-syncd` for interval-based sync.
- [x] Support gzip-compressed feed sources in the shared sync path.
- [x] Add tests for dry-run, gzip sources, and Redis writes.

## Milestone 3: Container Hardening

- [x] Add an internal Docker healthcheck with configurable port/path.
- [x] Run the runtime image as a non-root user.
- [x] Remove container-specific Compose healthcheck duplication.
- [x] Add an optional Compose profile for `feed-syncd`.
- [x] Add environment defaults for healthcheck and sync interval settings.

## Milestone 4: Integration Coverage

- [x] Convert `core-api` status validation into HTTP integration coverage.
- [x] Add `dns-resolver` root status integration coverage.
- [x] Add metrics endpoint integration coverage.
- [x] Add feed sync library integration coverage.
- [x] Verify the full repository with `go test ./...` and `go build ./...`.

## Completion Rule

Do not add new production-readiness work outside these milestones unless it first gets a new spec entry here.