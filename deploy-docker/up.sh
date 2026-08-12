#!/usr/bin/env bash
# Bring up the containerised Wazuh stack (alternative to the all-in-one installer).
set -euo pipefail
cd "$(dirname "$0")"

# --- credentials ----------------------------------------------------------
# We never boot with a default/known password. If there's no .env we generate
# strong random credentials; if there is one, we refuse to proceed while it
# still holds the CHANGE_ME placeholder.
gen_pw() {
  # 24 chars, alphanumeric + safe symbols; avoids quoting problems in yaml/env
  tr -dc 'A-Za-z0-9!@#%^_+=' </dev/urandom | head -c 24
}

if [ ! -f .env ]; then
  echo "[deploy-docker] no .env — generating strong random credentials..."
  {
    echo "# Generated $(date). Keep this file secret; it is gitignored."
    echo "INDEXER_PASSWORD=$(gen_pw)"
    echo "API_PASSWORD=$(gen_pw)"
  } > .env
  chmod 600 .env
  echo "[deploy-docker] credentials written to .env (mode 600)."
fi

# shellcheck disable=SC1091
set -a; . ./.env; set +a

if [ "${INDEXER_PASSWORD:-CHANGE_ME}" = "CHANGE_ME" ] || [ "${API_PASSWORD:-CHANGE_ME}" = "CHANGE_ME" ]; then
  cat >&2 <<'ERR'
[deploy-docker] REFUSING TO START.
  .env still contains the CHANGE_ME placeholder.
  Set real passwords, or delete .env and re-run to auto-generate them:
      rm .env && ./up.sh
ERR
  exit 1
fi

# --- certificates ---------------------------------------------------------
# The official single-node stack needs TLS certs generated before first boot.
# Failing loudly here is deliberate: silently continuing produces a confusing
# TLS error several minutes later, which is far harder to diagnose.
if [ ! -d config/wazuh_indexer_ssl_certs ]; then
  cat >&2 <<'ERR'
[deploy-docker] MISSING CERTIFICATES — cannot start.

  This compose file needs the certificates produced by the official
  wazuh-docker cert generator. One-time setup:

    git clone --depth 1 -b v4.14.0 https://github.com/wazuh/wazuh-docker.git /tmp/wazuh-docker
    cd /tmp/wazuh-docker/single-node
    docker compose -f generate-indexer-certs.yml run --rm generator
    cp -r config/wazuh_indexer_ssl_certs <this-directory>/config/

  Then re-run ./up.sh

  (Or just use the all-in-one installer, which handles certs for you:
   provision/wazuh-server.sh — see README.md for the trade-offs.)
ERR
  exit 1
fi

# --- kernel tunable the indexer requires ---------------------------------
CURRENT="$(sysctl -n vm.max_map_count)"
if [ "$CURRENT" -lt 262144 ]; then
  echo "[deploy-docker] raising vm.max_map_count (was ${CURRENT})..."
  sudo sysctl -w vm.max_map_count=262144
  echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf >/dev/null
fi

if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi

echo "[deploy-docker] starting stack (first run pulls several GB)..."
sudo -E $DC up -d

echo "[deploy-docker] waiting for dashboard..."
for i in $(seq 1 40); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/ || true)"
  if [ "$code" = "200" ] || [ "$code" = "302" ]; then
    echo "[deploy-docker] up! https://192.168.56.40"
    echo "[deploy-docker] user: admin   password: see INDEXER_PASSWORD in .env"
    exit 0
  fi
  sleep 5
done
echo "[deploy-docker] not ready yet — check: sudo $DC logs wazuh.dashboard" >&2
exit 1
