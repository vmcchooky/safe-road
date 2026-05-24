# Production edge runbook

## Goal

Run Safe Road on a single VPS with public HTTPS for the dashboard/API and DoH, plus direct DoT on port 853, while keeping internal ports `8080` and `8081` reachable only on loopback.

## Prerequisites

- Docker Engine with the Compose plugin.
- DNS record pointing `SAFE_ROAD_PUBLIC_HOST` to the VPS, or DuckDNS credentials.
- Firewall/security group allows inbound `22/tcp`, `80/tcp`, `443/tcp`, and `853/tcp` only.
- `.env` created from `.env.example`.

## Deploy

```sh
cp .env.example .env
vi .env
mkdir -p ops/certs/dot
mkdir -p ops/secrets
scripts/safe-road.sh deploy
```

Set at minimum:

- `SAFE_ROAD_ENV=production`
- `SAFE_ROAD_PUBLIC_HOST`
- `SAFE_ROAD_CADDY_EMAIL`
- `SAFE_ROAD_BLOCK_PAGE_IP` set to the public IPv4 that serves the block page
- `SAFE_ROAD_ADMIN_PASSWORD` or `SAFE_ROAD_ADMIN_PASSWORD_FILE`
- `SAFE_ROAD_ADMIN_API_KEY` or `SAFE_ROAD_ADMIN_API_KEY_FILE`

Recommended file-based secret layout:

```env
SAFE_ROAD_ENV=production
SAFE_ROAD_ADMIN_PASSWORD_FILE=./ops/secrets/admin_password
SAFE_ROAD_ADMIN_API_KEY_FILE=./ops/secrets/admin_api_key
SAFE_ROAD_GEMINI_API_KEY_FILE=./ops/secrets/gemini_api_key
SAFE_ROAD_DUCKDNS_TOKEN_FILE=./ops/secrets/duckdns_token
SAFE_ROAD_AGENT_WEBHOOK_URL_FILE=./ops/secrets/agent_webhook_url
SAFE_ROAD_BLOCK_PAGE_SUPPORT_EMAIL=security@example.com
```

The services mount `./ops/secrets` into `/app/ops/secrets`, so the same relative path works in local binaries, Compose containers, and the DuckDNS helper script.

Production deploy now uses:

- `docker-compose.yml` as the internal service baseline
- `docker-compose.production.yml` for public edge bindings
- `127.0.0.1:8080` and `127.0.0.1:8081` for host-local health/debug only
- `80`, `443`, and `853` as the intended public surface

## Verify

```sh
scripts/check-production-ports.sh
curl -fsS https://$SAFE_ROAD_PUBLIC_HOST/healthz
curl -fsS "https://$SAFE_ROAD_PUBLIC_HOST/v1/analyze?domain=example.com"
scripts/public-edge-smoke.sh "$SAFE_ROAD_PUBLIC_HOST"
scripts/check-block-page.sh "$SAFE_ROAD_PUBLIC_HOST" "$SAFE_ROAD_BLOCK_PAGE_IP" blocked.example.test
```

DoH uses the same host at `/dns-query`. DoT is published on host port `853` and mapped to container port `8533` by default so the non-root resolver process does not need to bind a privileged port inside the container.

If you use UFW on the VPS, the expected rule set is:

```sh
sudo ufw default deny incoming
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 853/tcp
sudo ufw status verbose
```

Cloud firewalls/security groups should mirror the same rule set. The public smoke script verifies the public endpoints, but the cloud rule confirmation itself still needs to be recorded per environment.

## Block page behavior

The production edge now supports two block-page flows:

- Plain HTTP sinkhole requests for arbitrary blocked domains are rewritten by Caddy to `/block` and rendered by `core-api`.
- Canonical HTTPS access is available at `https://$SAFE_ROAD_PUBLIC_HOST/block?domain=...`.

Direct HTTPS access to an arbitrary blocked third-party domain will still hit a browser certificate warning before any block page can render. That is an expected TLS hostname-validation limit, not an application bug.

## DuckDNS

Set `SAFE_ROAD_DUCKDNS_DOMAIN` and `SAFE_ROAD_DUCKDNS_TOKEN`, then run:

```sh
scripts/safe-road.sh duckdns
```

`SAFE_ROAD_DUCKDNS_TOKEN_FILE` is also supported for file-based or Docker-secret-style setups.

Install `ops/cron/safe-road-production.cron.example` to keep the record fresh.

## DoT certificates

The production override mounts `${SAFE_ROAD_DNS_DOT_CERTS_DIR:-./ops/certs/dot}` into `dns-resolver`.
The resolver expects:

- `fullchain.pem`
- `privkey.pem`

Export them into place with:

```sh
scripts/export-dot-cert.sh /path/to/fullchain.pem /path/to/privkey.pem
docker compose -f docker-compose.yml -f docker-compose.production.yml restart dns-resolver
```
