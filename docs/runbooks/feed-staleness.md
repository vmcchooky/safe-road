# Threat feed staleness runbook

Threat feeds are defense-in-depth. If feed sync fails, Safe Road continues to analyze domains, but known-bad coverage degrades over time.

## Detect

```sh
docker compose logs feed-syncd --tail=200
grep -i "feed" logs/feed-sync.log
```

When the agent is enabled, feed sync events are recorded in SQLite agent events.

## Manual sync

```sh
. ./.env
scripts/safe-road.sh feed-sync
```

Recommended free source preset:

```sh
SAFE_ROAD_AGENT_FEED_SOURCES=https://urlhaus.abuse.ch/downloads/csv_recent/,https://rescure.me/rescure_domain_blacklist.txt
```

## Follow-up

- Keep sources additive unless a feed is known compromised.
- Prefer HTTPS feed URLs.
- Review parser stats for high invalid counts, which may indicate feed format drift.
