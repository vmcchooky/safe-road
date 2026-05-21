# Production edge runbook

## Goal

Run Safe Road on a single VPS with public HTTPS for the dashboard/API and DoH, plus direct DoT on port 853.

## Prerequisites

- Docker Engine with the Compose plugin.
- DNS record pointing `SAFE_ROAD_PUBLIC_HOST` to the VPS, or DuckDNS credentials.
- Firewall allows inbound `80/tcp`, `443/tcp`, `853/tcp`, and SSH.

## Deploy

```sh
cp .env.example .env
vi .env
scripts/safe-road.sh deploy
```

Set at minimum:

- `SAFE_ROAD_PUBLIC_HOST`
- `SAFE_ROAD_CADDY_EMAIL`
- `SAFE_ROAD_ADMIN_PASSWORD`
- `SAFE_ROAD_ADMIN_API_KEY`

## Verify

```sh
curl -fsS https://$SAFE_ROAD_PUBLIC_HOST/healthz
curl -fsS "https://$SAFE_ROAD_PUBLIC_HOST/v1/analyze?domain=example.com"
```

DoH uses the same host at `/dns-query`. DoT is published on host port `853` and mapped to container port `8533` by default so the non-root resolver process does not need to bind a privileged port inside the container.

## DuckDNS

Set `SAFE_ROAD_DUCKDNS_DOMAIN` and `SAFE_ROAD_DUCKDNS_TOKEN`, then run:

```sh
scripts/safe-road.sh duckdns
```

Install `ops/cron/safe-road-production.cron.example` to keep the record fresh.
