#!/usr/bin/env sh
set -eu

domain="${SAFE_ROAD_DUCKDNS_DOMAIN:-}"
token="${SAFE_ROAD_DUCKDNS_TOKEN:-}"

if [ -z "$domain" ] || [ -z "$token" ]; then
  echo "SAFE_ROAD_DUCKDNS_DOMAIN and SAFE_ROAD_DUCKDNS_TOKEN are required" >&2
  exit 2
fi

response="$(wget -qO- "https://www.duckdns.org/update?domains=${domain}&token=${token}&ip=")"
if [ "$response" != "OK" ]; then
  echo "DuckDNS update failed: ${response}" >&2
  exit 1
fi

echo "DuckDNS record updated for ${domain}.duckdns.org"
