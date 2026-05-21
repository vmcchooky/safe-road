#!/usr/bin/env sh
set -eu

compose="${SAFE_ROAD_COMPOSE:-docker compose}"
project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
backup_dir="${SAFE_ROAD_BACKUP_DIR:-${project_dir}/backups}"

cd "$project_dir"

cmd="${1:-help}"
case "$cmd" in
  deploy)
    $compose --profile production-edge up -d --build
    ;;
  deploy-dev)
    $compose up -d --build
    ;;
  status)
    $compose ps
    echo
    wget -qO- http://127.0.0.1:8080/healthz || true
    echo
    wget -qO- http://127.0.0.1:8081/healthz || true
    echo
    ;;
  logs)
    $compose logs -f --tail="${SAFE_ROAD_LOG_TAIL:-100}"
    ;;
  backup)
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    target="${backup_dir}/${ts}"
    mkdir -p "$target"
    $compose exec -T redis redis-cli SAVE >/dev/null
    docker cp "$($compose ps -q redis):/data/dump.rdb" "${target}/redis-dump.rdb"
    if [ -f .env ]; then
      cp .env "${target}/env.snapshot"
    fi
    echo "Backup written to ${target}"
    ;;
  restore)
    src="${2:-}"
    if [ -z "$src" ]; then
      echo "usage: scripts/safe-road.sh restore /path/to/redis-dump.rdb" >&2
      exit 2
    fi
    $compose stop redis
    docker cp "$src" "$($compose ps -aq redis):/data/dump.rdb"
    $compose start redis
    ;;
  feed-sync)
    sources="${SAFE_ROAD_AGENT_FEED_SOURCES:-${SAFE_ROAD_THREAT_FEED_SOURCE:-}}"
    if [ -z "$sources" ]; then
      echo "No feed sources configured. Set SAFE_ROAD_AGENT_FEED_SOURCES or SAFE_ROAD_THREAT_FEED_SOURCE." >&2
      exit 2
    fi
    old_ifs="$IFS"
    IFS=","
    for source in $sources; do
      SAFE_ROAD_THREAT_FEED_SOURCE="$source" $compose --profile feed-sync run --rm feed-sync /app/service -source "$source"
    done
    IFS="$old_ifs"
    ;;
  duckdns)
    scripts/duckdns-update.sh
    ;;
  help|*)
    cat <<'USAGE'
Usage: scripts/safe-road.sh <command>

Commands:
  deploy       Build and start production-edge stack with Caddy.
  deploy-dev   Build and start core services without Caddy.
  status       Show compose status and health endpoints.
  logs         Follow compose logs.
  backup       Save Redis RDB and env snapshot under backups/.
  restore      Restore Redis from a dump.rdb path.
  feed-sync    Sync configured free threat feeds once.
  duckdns      Update DuckDNS record.
USAGE
    ;;
esac
