#!/usr/bin/env sh
set -eu

echo "Checking loopback health endpoints..."
curl -fsS http://127.0.0.1:8080/healthz >/dev/null
curl -fsS http://127.0.0.1:8081/healthz >/dev/null

if command -v ss >/dev/null 2>&1; then
  echo "Checking listener exposure for 8080/8081..."
  bad_listeners="$(
    ss -ltnH |
      awk '$4 ~ /:8080$|:8081$/ {print $4}' |
      grep -Ev '^(127\.0\.0\.1:8080|127\.0\.0\.1:8081|\[::1\]:8080|\[::1\]:8081)$' || true
  )"
  if [ -n "$bad_listeners" ]; then
    echo "unexpected public listener detected:" >&2
    echo "$bad_listeners" >&2
    exit 1
  fi
fi

echo "Production port exposure looks correct."
