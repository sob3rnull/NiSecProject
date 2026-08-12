#!/usr/bin/env bash
# Unauthorized access test — covers the proposal's "Unauthorized access" threat
# and the NFR "only authorized users should be able to access the dashboard".
#
# Run from KALI. All of these SHOULD FAIL — failure is the successful result.
source "$(dirname "$0")/_lib.sh"   # WAZUH_SERVER + LOGDIR + helpers live there

# Every curl below carries -m: a firewalled port DROPs rather than refuses, so
# without a timeout these tests hang for minutes instead of reporting a result.
log "TEST 1/3 — anonymous access to the Wazuh API (should be 401)"
run_logged "unauth_api" curl -sk -m 5 -o /dev/null -w 'HTTP %{http_code}\n' \
  "https://${WAZUH_SERVER}:55000/agents" || true
log "  -> 401 Unauthorized = access control working"

log "TEST 2/3 — default/guessed dashboard credentials (should all fail)"
# Logged to a file like the other tests: this is evidence you need to
# screenshot/cite, so it must not exist only in terminal scrollback.
CREDLOG="$(log_path default_creds)"
{
  echo "# $(_ts)  default-credential check against ${WAZUH_SERVER}"
  for creds in "admin:admin" "admin:password" "wazuh:wazuh" "admin:changeme"; do
    code="$(curl -sk -m 5 -o /dev/null -w '%{http_code}' -u "$creds" \
      "https://${WAZUH_SERVER}:55000/security/user/authenticate" || true)"
    echo "  ${creds} -> HTTP ${code:-timeout}"
  done
} 2>&1 | tee "$CREDLOG"
log "  saved: ${CREDLOG}"
log "  -> all non-200 = no default credentials left in place"

log "TEST 3/3 — direct indexer access from the network (should be refused)"
run_logged "unauth_indexer" curl -sk -m 5 -o /dev/null -w 'HTTP %{http_code}\n' \
  "https://${WAZUH_SERVER}:9200/_cat/indices" || true
log "  -> 401/timeout = indexer not exposed to the client zone"

log "Done. These failures are your access-control evidence — screenshot them."
