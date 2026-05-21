# Certificate renewal runbook

Caddy manages public HTTPS certificates automatically for `SAFE_ROAD_PUBLIC_HOST`.

## Detect

```sh
docker compose logs caddy --tail=200
curl -Iv https://$SAFE_ROAD_PUBLIC_HOST/healthz
```

## Common causes

- DNS record does not point to the VPS.
- Ports `80/tcp` or `443/tcp` are blocked.
- `SAFE_ROAD_PUBLIC_HOST` is still set to `localhost`.
- Let's Encrypt rate limits after repeated failed attempts.

## Mitigate

```sh
scripts/safe-road.sh duckdns
docker compose --profile production-edge restart caddy
```

DoT certificates are configured separately through:

- `SAFE_ROAD_DNS_DOT_CERT_FILE`
- `SAFE_ROAD_DNS_DOT_KEY_FILE`

If they are empty, the resolver generates a temporary self-signed certificate for development.
