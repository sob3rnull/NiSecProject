#!/usr/bin/env bash
# DoS: ICMP ping flood with hping3. Auto-stops after DURATION seconds.
# Expect: Suricata ICMP-flood alert (our threshold SID 9000001).
source "$(dirname "$0")/_lib.sh"

DURATION="${DURATION:-8}"
log "flooding ${TARGET} with ICMP for ${DURATION}s (auto-stop)..."
# timeout guarantees we don't flood forever; needs root for raw sockets.
run_logged "ping_flood" sudo timeout "${DURATION}" hping3 --icmp --flood "$TARGET" || true
log "ping flood stopped."
