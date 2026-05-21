# Redis outage runbook

Safe Road is designed to fail open when Redis is unavailable. Domain analysis and policy checks continue with lexical, feed-independent, TLS, WHOIS, and optional AI signals, but cache hits and Redis-backed feed matches are degraded.

## Detect

```sh
scripts/safe-road.sh status
docker compose logs redis --tail=100
```

The dashboard system panel also reports Redis state.

## Mitigate

```sh
docker compose restart redis
docker compose exec redis redis-cli ping
```

If Redis data is corrupt, restore the newest known-good RDB:

```sh
scripts/safe-road.sh restore backups/<timestamp>/redis-dump.rdb
```

## Follow-up

- Confirm `/v1/analyze` works.
- Run `scripts/safe-road.sh feed-sync` to repopulate threat feeds if needed.
- Check memory pressure against `SAFE_ROAD_REDIS_MAXMEMORY`.
