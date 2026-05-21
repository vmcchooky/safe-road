# Tasks: TLS Certificate (x.509) & WHOIS Age Analysis Module

## Phase 1: TLS Inspector

- [ ] Create `internal/tlsinspect/inspect.go`:
  - `Result` struct (HasTLS, Valid, SelfSigned, Expired, Issuer, SANMatch, CertAge, Score, Reasons).
  - `Inspect(ctx, domain) Result` — TLS handshake to port 443, cert extraction.
  - `certMatchesDomain(cert, domain)` — SAN/CN validation.
  - Scoring logic (self-signed, expired, fresh cert, SAN mismatch).
  - Graceful failure (return zero-score result on error).
- [ ] Create `internal/tlsinspect/inspect_test.go`:
  - Test with local `httptest.NewTLSServer` (valid cert).
  - Test self-signed detection.
  - Test expired cert detection.
  - Test SAN mismatch detection.
  - Test timeout handling.
  - Test connection refused (no TLS).

## Phase 2: WHOIS Lookup

- [ ] Create `internal/whois/lookup.go`:
  - `Result` struct (Found, RegisteredDate, DomainAgeDays, Registrar, PrivacyGuard, Score, Reasons).
  - `Lookup(ctx, domain) Result` — WHOIS TCP query.
  - `extractRegisteredDomain(domain)` — get base domain from full FQDN.
  - `whoisServers` map for common TLDs.
  - `parseCreationDate(response)` — regex-based date extraction.
  - Scoring logic (< 7d, < 30d, < 90d, privacy guard).
- [ ] Create `internal/whois/lookup_test.go`:
  - Test date parsing with various WHOIS response formats.
  - Test registered domain extraction.
  - Test scoring logic (fresh vs old domains).
  - Test with mock TCP WHOIS server.
  - Test timeout handling.
  - Test unsupported TLD handling.

## Phase 3: Pipeline Integration

- [ ] Add `enrichSuspicious(ctx, domain, result)` to `internal/risk/service.go`:
  - Run TLS + WHOIS in parallel with `sync.WaitGroup`.
  - Apply combined timeout from config.
  - Merge scores and reasons into result.
  - Recalculate verdict from updated score.
- [ ] Add enrichment call between lexical analysis and AI refinement in `analyze()`.
- [ ] Add enrichment config to `internal/risk/env.go`:
  - `SAFE_ROAD_ENRICH_ENABLED` (default: true).
  - `SAFE_ROAD_ENRICH_TIMEOUT_MS` (default: 3000).
- [ ] Add Redis caching for TLS and WHOIS results.

## Phase 4: Configuration & Documentation

- [ ] Update `.env.example` with enrichment env vars.
- [ ] Update `docker-compose.yml` with enrichment env vars.
- [ ] Update `config.AnalysisConfig` if enrichment scoring is configurable.

## Phase 5: Verification

- [ ] `go test ./internal/tlsinspect/...` — all pass.
- [ ] `go test ./internal/whois/...` — all pass.
- [ ] `go test ./internal/risk/...` — all pass (enrichment tests + no regression).
- [ ] `go test ./...` — full suite passes.
- [ ] `go build ./...` — compiles clean.
- [ ] Manual test: analyze a known-phishing domain and verify TLS/WHOIS signals appear.
- [ ] Manual test: analyze `google.com` and verify no false positive enrichment.
