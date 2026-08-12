#!/usr/bin/env bash
# run_all.sh — runs the tests that map to the SUBMITTED PROPOSAL's threat list,
# pausing between each so alerts are easy to correlate on the dashboard.
#
# Resilient by design: several of these tools exit non-zero on their EXPECTED
# outcome (hydra finds no password, hping3 is killed by timeout, nikto reports
# findings). The suite records each result and carries on, then prints a
# summary — so one expected failure can never hide the rest of your evidence.
NISEC_RUNNER=1
source "$(dirname "$0")/_lib.sh"

PAUSE="${PAUSE:-20}"
here="$(dirname "$0")"
BONUS="${BONUS:-false}"

declare -a RESULTS=()

run_step() {
  local name="$1" script="$2"
  log ""
  log "----- ${name} -----"
  if bash "${here}/${script}"; then
    RESULTS+=("PASS  ${name}")
  else
    # Non-zero is common and usually expected here; record, don't abort.
    RESULTS+=("done  ${name} (tool exited non-zero - normal for this test)")
  fi
  log "sleeping ${PAUSE}s so alerts settle on the dashboard..."
  sleep "$PAUSE"
}

log "############################################################"
log "# NISec detection test suite"
log "# target: ${TARGET}   dashboard: https://${WAZUH_SERVER}"
log "############################################################"

# --- Proposal-scope network attacks (run from Kali) ---------------------
run_step "1. Port scan (recon)"        01_nmap_scan.sh
run_step "2. SSH brute-force"          02_ssh_bruteforce.sh
run_step "3. Ping flood (DoS)"         03_ping_flood.sh

# --- Access control test (from Kali, against the Wazuh server) ----------
run_step "5. Unauthorized access"      06_unauthorized_access_test.sh

# --- Bonus: web attack (only if DVWA is up) -----------------------------
if [ "$BONUS" = "true" ]; then
  log "BONUS: web attack (beyond submitted scope)"
  run_step "7. Web attack (bonus)"     04_web_attack.sh
else
  log "skipping web attack (bonus). Enable with: BONUS=true ./run_all.sh"
fi

# --- Summary --------------------------------------------------------------
echo
echo "==================== SUITE SUMMARY ===================="
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo "======================================================="

cat <<'MSG'

------------------------------------------------------------------
REMAINING TEST — must run ON THE MONITORED SERVER, not Kali:

  vagrant ssh monitored -c 'sudo bash /vagrant/attacks/05_malware_fim_test.sh'

It simulates malware/ransomware behaviour (safe EICAR test file + mass
file modification), which covers the HIGH-risk "Malware or ransomware"
threat from your proposal.

ALSO CHECK (no script needed):
  Dashboard -> Modules -> Security Configuration Assessment
  -> screenshot the CIS benchmark score. That covers the
     "Misconfiguration" threat from your risk assessment.
------------------------------------------------------------------
MSG

log "Suite complete. Capture screenshots into evidence/screenshots/."
