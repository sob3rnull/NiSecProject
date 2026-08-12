#!/usr/bin/env bash
# 07_evasion_test.sh — the test that shows you understand your own detections.
#
# Every other script here proves the system WORKS. This one probes where it
# STOPS working, on purpose. A 4th-year project that only demonstrates success
# is describing a product; one that maps its own detection boundary is doing
# security engineering.
#
# Each sub-test deliberately stays UNDER a threshold in config/suricata/
# local.rules. For most of them, NO ALERT IS THE EXPECTED RESULT — that is the
# finding, not a failure. Record it and explain it in report §7.4.
#
#   SID 9000002  30 SYN  / 5s   track by_src
#   SID 9000001  500 ICMP/ 10s  track by_dst
#   SID 9000003  20 SSH  / 30s  track by_src
#
# THE HEADLINE RESULT is test 4: a slow SSH brute-force slips under the
# network threshold while Wazuh's HOST rules catch it anyway, because they
# count authentication failures rather than packets. That single contrast is
# the empirical argument for this project's two-tool design — cite it in the
# viva before anyone asks why one sensor was not enough.
#
# Run from KALI, ideally right after `make measure` so you can compare against
# the detections that DID fire:
#     vagrant ssh kali -c 'bash /vagrant/attacks/07_evasion_test.sh'
source "$(dirname "$0")/_lib.sh"

PORTS="${PORTS:-21,22,23,25,80,110,143,443,3306,8080}"

log "############################################################"
log "# Detection-boundary (evasion) tests against ${TARGET}"
log "# For tests 1-3 and 5, NO ALERT is the expected outcome."
log "############################################################"

# ---------------------------------------------------------------------------
log ""
log "TEST 1/5 — slow SYN scan, deliberately under the 30-SYN/5s threshold"
log "  technique: --scan-delay spreads probes so the rate never trips SID 9000002"
log "  expect   : ports still enumerated, NO port-scan alert"
run_logged "evasion_slow_scan" \
  sudo nmap -sS -p "$PORTS" --scan-delay 1s --max-retries 0 "$TARGET" || true
log "  -> if no SID 9000002 alert fired, the threshold is rate-based and evadable."

# ---------------------------------------------------------------------------
log ""
log "TEST 2/5 — decoy scan, hiding the real source among spoofed ones"
log "  technique: -D sprays decoy source IPs; SID 9000002 tracks by_src, so the"
log "             real attacker's own count stays below the threshold"
log "  expect   : alerts may fire, but attributed to the WRONG source"
run_logged "evasion_decoy_scan" \
  sudo nmap -sS -p "$PORTS" -D RND:10 "$TARGET" || true
log "  -> check the dashboard: which src IP is blamed? Attribution, not just detection."

# ---------------------------------------------------------------------------
log ""
log "TEST 3/5 — fragmented packets"
log "  technique: -f splits probes across IP fragments to defeat naive matching"
log "  expect   : Suricata's defrag engine SHOULD reassemble and still detect."
log "             This one is a control - it should FAIL to evade."
run_logged "evasion_fragmented" \
  sudo nmap -sS -f -p "$PORTS" "$TARGET" || true
log "  -> detection here proves defrag is on; absence would be a real config finding."

# ---------------------------------------------------------------------------
log ""
log "TEST 4/5 — SLOW SSH brute-force  ** the important one **"
log "  technique: one connection at a time, throttled below 20 SSH SYNs/30s,"
log "             so the network signature SID 9000003 never trips"
log "  expect   : Suricata SILENT, but Wazuh host rules 5710/5712 STILL ALERT,"
log "             because they count failed logins in auth.log, not packets."
SLOW_USERS="${SLOW_USERS:-admin root testuser oracle postgres}"
{
  echo "# $(_ts)  slow SSH attempts against ${TARGET}"
  for u in $SLOW_USERS; do
    echo "  trying ${u} ..."
    # -o BatchMode so it fails fast instead of prompting; each attempt is a
    # separate connection, spaced out to stay under the network threshold.
    ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        -o PreferredAuthentications=password,keyboard-interactive \
        "${u}@${TARGET}" true 2>&1 | tail -1
    sleep 8
  done
} 2>&1 | tee "$(log_path evasion_slow_bruteforce)"
log "  -> THE FINDING: network rule evaded, host rule caught it. That contrast"
log "     is the entire justification for running Suricata AND Wazuh together."

# ---------------------------------------------------------------------------
log ""
log "TEST 5/5 — encrypted payload (the IDS blind spot)"
log "  technique: send an obvious SQL-injection string over HTTPS instead of HTTP"
log "  expect   : the plaintext probe is detectable; the TLS one is NOT, because"
log "             Suricata sees only an encrypted stream without TLS interception."
SQLI="id=1' OR '1'='1"
log "  5a: same payload over plain HTTP (control - should be detectable)"
run_logged "evasion_sqli_plain" \
  curl -s -o /dev/null -m 10 -G "http://${TARGET}/vulnerabilities/sqli/" \
    --data-urlencode "$SQLI" || true
log "  5b: same payload over HTTPS (expect NO web-attack signature)"
run_logged "evasion_sqli_tls" \
  curl -sk -o /dev/null -m 10 -G "https://${WAZUH_SERVER}/" \
    --data-urlencode "$SQLI" || true
log "  -> Encrypted traffic is a structural blind spot for a passive IDS. Report"
log "     it in §7.4 alongside the mitigations: TLS termination/inspection at a"
log "     proxy, or host-based visibility (Wazuh agents) where plaintext exists."

# ---------------------------------------------------------------------------
log ""
log "############################################################"
log "# Done. Now open the dashboard and record, for EACH test:"
log "#   did an alert fire? which rule? attributed to which source IP?"
log "#"
log "# Write the results into report §7.4 (Limitations) as a table of"
log "# 'technique -> detected? -> why'. Thresholds that can be evaded are not"
log "# a flaw in your build; failing to know where they stop would be."
log "############################################################"
