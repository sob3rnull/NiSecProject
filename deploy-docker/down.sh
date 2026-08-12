#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi
sudo $DC down
echo "[deploy-docker] stopped (volumes kept; add -v to wipe data)."
