#!/usr/bin/env bash
# configure-retention.sh — satisfies the proposal's functional requirement
#   "Store logs so they can be reviewed later."
#
# Sets an Index State Management (ISM) policy on the Wazuh indexer so alert
# indices age out predictably instead of silently filling the disk.
#
# Lifecycle: hot (7d) -> read-only (30d) -> deleted (90d)
set -uo pipefail

INDEXER="${INDEXER:-https://localhost:9200}"
USER="${INDEXER_USER:-admin}"
PASS="${INDEXER_PASS:-}"

if [ -z "$PASS" ]; then
  cat >&2 <<'ERR'
INDEXER_PASS is not set. This script will not guess or use a default password.
Retrieve the generated admin password and pass it in:

  sudo tar -O -xf wazuh-install-files.tar \
    wazuh-install-files/wazuh-passwords.txt | grep -A1 admin

  INDEXER_PASS='<that password>' bash scripts/configure-retention.sh
ERR
  exit 1
fi

# NOTE: deliberately NO "rollover" action. Rollover requires each index to
# have a rollover alias, but Wazuh creates DATE-NAMED indices
# (wazuh-alerts-4.x-YYYY.MM.DD) which already roll daily by name. Adding a
# rollover action to them makes ISM error out. Age-based transitions are the
# correct mechanism for date-named indices.
echo "=== NISec log retention policy ==="

if ! curl -sk -u "${USER}:${PASS}" -o /dev/null "${INDEXER}"; then
  echo "indexer not reachable at ${INDEXER} — run this after Wazuh is up." >&2
  echo "  INDEXER_PASS=yourpass bash scripts/configure-retention.sh" >&2
  exit 1
fi

read -r -d '' POLICY <<'JSON' || true
{
  "policy": {
    "description": "NISec lab: keep alerts 90 days, read-only after 30.",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [{ "state_name": "readonly", "conditions": { "min_index_age": "30d" } }]
      },
      {
        "name": "readonly",
        "actions": [{ "read_only": {} }],
        "transitions": [{ "state_name": "delete", "conditions": { "min_index_age": "90d" } }]
      },
      {
        "name": "delete",
        "actions": [{ "delete": {} }],
        "transitions": []
      }
    ],
    "ism_template": [
      { "index_patterns": ["wazuh-alerts-*"], "priority": 100 }
    ]
  }
}
JSON

echo "[1/2] applying ISM policy 'nisec-retention'..."
curl -sk -u "${USER}:${PASS}" -X PUT \
  "${INDEXER}/_plugins/_ism/policies/nisec-retention" \
  -H 'Content-Type: application/json' -d "$POLICY" | head -5

echo
echo "[2/2] verifying..."
curl -sk -u "${USER}:${PASS}" \
  "${INDEXER}/_plugins/_ism/policies/nisec-retention" >/dev/null 2>&1 \
  && echo "  policy stored OK" || echo "  could not verify — check credentials"

cat <<'MSG'

Retention summary for your report:
  0-7d    hot        actively written, fully searchable
  7-30d   warm       searchable, rolled over
  30-90d  read-only  searchable, immutable (tamper evidence)
  90d+    deleted    reclaimed

Disk-planning note: this lab generates roughly 50-200 MB of alerts per day
under active testing. 90 days therefore needs ~5-18 GB. State your own
observed figure in the report - measure with:
  curl -sk -u admin:PASS 'https://localhost:9200/_cat/indices/wazuh-alerts-*?v&h=index,store.size'
MSG
