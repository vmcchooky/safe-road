#!/usr/bin/env sh
set -eu

compose="${SAFE_ROAD_COMPOSE:-docker compose}"
project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
backup_dir="${SAFE_ROAD_BACKUP_DIR:-${project_dir}/backups}"
stack="${SAFE_ROAD_STACK:-production}"

cd "$project_dir"

compose_stack() {
  selected_stack="$1"
  shift
  case "$selected_stack" in
    production)
      $compose -f docker-compose.yml -f docker-compose.production.yml "$@"
      ;;
    dev)
      $compose -f docker-compose.yml -f docker-compose.dev.yml "$@"
      ;;
    *)
      echo "unknown SAFE_ROAD_STACK: $selected_stack" >&2
      exit 2
      ;;
  esac
}

resolve_feed_sources() {
  if [ -n "${SAFE_ROAD_AGENT_FEED_SOURCES:-}" ]; then
    printf '%s' "$SAFE_ROAD_AGENT_FEED_SOURCES"
    return 0
  fi

  case "${SAFE_ROAD_AGENT_FEED_PRESET:-}" in
    production-free)
      printf '%s' "https://urlhaus.abuse.ch/downloads/csv_recent/,https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
      return 0
      ;;
  esac

  if [ -n "${SAFE_ROAD_THREAT_FEED_SOURCE:-}" ]; then
    printf '%s' "$SAFE_ROAD_THREAT_FEED_SOURCE"
    return 0
  fi

  return 1
}

cmd="${1:-help}"
case "$cmd" in
  deploy)
    compose_stack production --profile production-edge up -d --build
    ;;
  deploy-dev)
    compose_stack dev up -d --build
    ;;
  status)
    compose_stack "$stack" ps
    echo
    wget -qO- http://127.0.0.1:8080/healthz || true
    echo
    wget -qO- http://127.0.0.1:8081/healthz || true
    echo
    ;;
  logs)
    compose_stack "$stack" logs -f --tail="${SAFE_ROAD_LOG_TAIL:-100}"
    ;;
  backup)
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    target="${backup_dir}/${ts}"
    mkdir -p "$target"
    compose_stack "$stack" exec -T redis redis-cli SAVE >/dev/null
    docker cp "$(compose_stack "$stack" ps -q redis):/data/dump.rdb" "${target}/redis-dump.rdb"
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
    compose_stack "$stack" stop redis
    docker cp "$src" "$(compose_stack "$stack" ps -aq redis):/data/dump.rdb"
    compose_stack "$stack" start redis
    ;;
  feed-sync)
    sources="$(resolve_feed_sources || true)"
    if [ -z "$sources" ]; then
      echo "No feed sources configured. Set SAFE_ROAD_AGENT_FEED_SOURCES, SAFE_ROAD_AGENT_FEED_PRESET, or SAFE_ROAD_THREAT_FEED_SOURCE." >&2
      exit 2
    fi
    old_ifs="$IFS"
    IFS=","
    for source in $sources; do
      SAFE_ROAD_THREAT_FEED_SOURCE="$source" compose_stack "$stack" --profile feed-sync run --rm feed-sync /app/service -source "$source"
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
  deploy       Build and start the production stack with Caddy and loopback-only internal ports.
  deploy-dev   Build and start the local developer stack on loopback ports.
  status       Show compose status and loopback health endpoints for SAFE_ROAD_STACK (default: production).
  logs         Follow compose logs for SAFE_ROAD_STACK (default: production).
  backup       Save Redis RDB and env snapshot under backups/.
  restore      Restore Redis from a dump.rdb path.
  feed-sync    Sync configured free threat feeds once.
  duckdns      Update DuckDNS record.

Environment:
  SAFE_ROAD_STACK=production|dev  Choose the stack for status/logs/backup/restore/feed-sync.
USAGE
    ;;
esac
