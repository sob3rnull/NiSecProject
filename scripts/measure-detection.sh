#!/usr/bin/env bash
# measure-detection.sh — turns this lab from apparatus into an experiment.
#
# Every other script here BUILDS or ATTACKS. This one MEASURES: for each attack
# it records whether detection happened, which rule fired, and how many seconds
# elapsed between launching the attack and the alert landing on the manager.
# It writes a markdown results table straight into evidence/ so the numbers can
# be pasted into report §6.8 with a defensible method behind them.
#
# Run from the HOST after `make up` and `make healthcheck`:
#     make measure                 # all tests
#     bash scripts/measure-detection.sh portscan bruteforce
#
# ---------------------------------------------------------------------------
# METHOD — state this in the report; it is what makes the numbers citable
#
#  1. CLOCK. Every timestamp comes from the Wazuh manager. T0 is read with
#     `date +%s` on the manager immediately before the attack launches, and the
#     alert time is read from the manager's own alerts.json. Because both come
#     from one clock, skew between the four VMs cannot contaminate the latency.
#     (Host wall-clock is used only to decide when to stop polling.)
#
#  2. NO STALE CREDIT. Only alerts at or after T0 count, so an alert left over
#     from a previous run can never be credited to this one.
#
#  3. NEGATIVE RESULTS ARE RESULTS. A test that does not fire inside its
#     timeout is recorded as NOT DETECTED, with the timeout stated. Do not
#     delete those rows — an honest miss, explained, scores better than a table
#     where everything conveniently worked.
#
#  4. LATENCY IS END-TO-END, and includes deliberate delay inside the attack
#     scripts (e.g. the FIM test sleeps while it waits for a baseline). It is
#     detection latency for the scenario as run, not the manager's processing
#     time. Say which you are reporting.
#
#  5. RESOLUTION is one second — that is the granularity of the Wazuh alert
#     timestamp. Do not report these numbers to decimal places.
# ---------------------------------------------------------------------------
set -uo pipefail

cd "$(dirname "$0")/.."
EVIDENCE_DIR="evidence"
mkdir -p "$EVIDENCE_DIR"
OUT="${EVIDENCE_DIR}/detection-results_$(date +%Y%m%d_%H%M%S).md"

POLL_SECONDS=3
declare -a ROWS=()

c_ok()   { printf '\033[32m%s\033[0m\n' "$1"; }
c_bad()  { printf '\033[31m%s\033[0m\n' "$1"; }
info()   { printf '  %s\n' "$1"; }

# vagrant ssh on a Windows host emits CRLF; strip it or the arithmetic breaks.
mgr()  { vagrant ssh wazuh-server -c "$1" 2>/dev/null | tr -d '\r'; }
mon()  { vagrant ssh monitored    -c "$1" 2>/dev/null | tr -d '\r'; }

# Suricata's own packet accounting. Under a flood this is the number that
# matters: an IDS that drops packets is an IDS with blind spots, and quoting a
# measured drop rate is far stronger than asserting the sensor "kept up".
suricata_drops() {
  mon "sudo grep -E 'capture.kernel_(packets|drops)' /var/log/suricata/stats.log 2>/dev/null | tail -2 | awk '{print \$1\"=\"\$NF}' | paste -sd' '"
}

# run_test <label> <rule-id-regex> <remote-launch-command> <timeout-seconds>
run_test() {
  local label="$1" ids="$2" cmd="$3" timeout="$4"
  local t0 hit epoch rid desc latency elapsed deadline

  printf '\n=== %s ===\n' "$label"

  t0="$(mgr 'date +%s')"
  if ! [[ "$t0" =~ ^[0-9]+$ ]]; then
    c_bad "  cannot read the manager clock - is wazuh-server up?"
    ROWS+=("| ${label} | ERROR | - | - | manager unreachable |")
    return
  fi
  info "manager T0 = ${t0}"
  info "launching: ${cmd}"

  # Launch in the background so polling overlaps the attack instead of waiting
  # for it to finish - otherwise every latency would be floored at the attack's
  # own duration.
  bash -c "$cmd" >/dev/null 2>&1 &
  local attack_pid=$!

  deadline=$(( $(date +%s) + timeout ))
  hit=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    hit="$(mgr "sudo bash /vagrant/scripts/_alert-probe.sh '${ids}' ${t0}")"
    [ -n "$hit" ] && break
    sleep "$POLL_SECONDS"
  done

  wait "$attack_pid" 2>/dev/null || true

  if [ -n "$hit" ]; then
    IFS=$'\t' read -r epoch rid desc <<<"$hit"
    latency=$(( epoch - t0 ))
    c_ok "  DETECTED in ~${latency}s by rule ${rid}"
    info "${desc}"
    ROWS+=("| ${label} | DETECTED | ${rid} | ${latency} s | ${desc} |")
  else
    elapsed=$timeout
    c_bad "  NOT DETECTED within ${elapsed}s (watched rule ids: ${ids})"
    ROWS+=("| ${label} | **NOT DETECTED** | - | >${elapsed} s | no matching alert within timeout |")
  fi
}

# ---------------------------------------------------------------------------
# Baseline: the false-positive floor. Without this number, "we saw N alerts
# during the attack" means nothing - some of those alerts fire on idle lab
# traffic too. Report §7.3 asks for a false-positive discussion; this is the
# measurement that lets you write one instead of guessing.
# ---------------------------------------------------------------------------
run_baseline() {
  local seconds="${BASELINE_SECONDS:-120}"
  local t0 count rate
  printf '\n=== Baseline (no attack) ===\n'
  info "observing ${seconds}s of idle lab traffic..."
  t0="$(mgr 'date +%s')"
  if ! [[ "$t0" =~ ^[0-9]+$ ]]; then
    c_bad "  cannot read the manager clock"
    return
  fi
  sleep "$seconds"
  count="$(mgr "sudo jq -r --argjson t0 ${t0} 'select((.timestamp | sub(\"[.].*\$\"; \"\") | strptime(\"%Y-%m-%dT%H:%M:%S\") | mktime) >= \$t0) | .rule.id' /var/ossec/logs/alerts/alerts.json 2>/dev/null | wc -l")"
  count="${count:-0}"
  rate=$(( count * 3600 / seconds ))
  info "alerts while idle: ${count} in ${seconds}s  (~${rate}/hour)"
  ROWS+=("| _Baseline (idle, no attack)_ | ${count} alerts in ${seconds}s | - | - | ~${rate}/hour noise floor |")
  BASELINE_NOTE="Idle baseline: ${count} alerts in ${seconds}s (~${rate}/hour). Any attack row below should be read against this floor."
}

usage() {
  cat <<'USAGE'
usage: bash scripts/measure-detection.sh [test ...]

  portscan     nmap SYN scan          -> Suricata / SID 9000002
  bruteforce   hydra SSH              -> Wazuh host rules 5710/5712
  pingflood    hping3 ICMP flood      -> Suricata / SID 9000001
  fim          EICAR + mass modify    -> Wazuh FIM 100200/100201/100202
  baseline     idle observation       -> false-positive floor
  all          every test above (default)

env: BASELINE_SECONDS=120  PORTSCAN_TIMEOUT=120  ...
USAGE
}

TESTS=("$@")
[ ${#TESTS[@]} -eq 0 ] && TESTS=("all")
case "${TESTS[0]}" in -h|--help|help) usage; exit 0 ;; esac
if [ "${TESTS[0]}" = "all" ]; then
  TESTS=(baseline portscan bruteforce pingflood fim)
fi

echo "############################################################"
echo "# NISec detection measurement"
echo "# results -> ${OUT}"
echo "############################################################"

BASELINE_NOTE=""
DROPS_BEFORE=""
DROPS_AFTER=""

for t in "${TESTS[@]}"; do
  case "$t" in
    baseline)
      run_baseline
      ;;
    portscan)
      run_test "1. Port scan (nmap -sS)" '100120|100101|100102|86601' \
        "vagrant ssh kali -c 'sudo bash /vagrant/attacks/01_nmap_scan.sh'" \
        "${PORTSCAN_TIMEOUT:-180}"
      ;;
    bruteforce)
      run_test "2. SSH brute-force (hydra)" '5710|5712|5716|5720|100002' \
        "vagrant ssh kali -c 'bash /vagrant/attacks/02_ssh_bruteforce.sh'" \
        "${BRUTEFORCE_TIMEOUT:-180}"
      ;;
    pingflood)
      DROPS_BEFORE="$(suricata_drops)"
      run_test "3. Ping flood (hping3)" '100120|100101|86601' \
        "vagrant ssh kali -c 'bash /vagrant/attacks/03_ping_flood.sh'" \
        "${PINGFLOOD_TIMEOUT:-120}"
      DROPS_AFTER="$(suricata_drops)"
      info "suricata counters before: ${DROPS_BEFORE:-unavailable}"
      info "suricata counters after : ${DROPS_AFTER:-unavailable}"
      ;;
    fim)
      # Runs on the monitored server, not Kali - it simulates post-compromise
      # behaviour. Its timeout must exceed the sleeps inside the script itself.
      run_test "4. Malware / FIM (EICAR + mass modify)" '100200|100201|100202|550|554' \
        "vagrant ssh monitored -c 'sudo bash /vagrant/attacks/05_malware_fim_test.sh'" \
        "${FIM_TIMEOUT:-240}"
      ;;
    *)
      echo "unknown test: $t" >&2; usage; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Results file
# ---------------------------------------------------------------------------
{
  echo "# Detection measurement results"
  echo
  echo "Generated by \`scripts/measure-detection.sh\` on $(date '+%Y-%m-%d %H:%M:%S')."
  echo
  echo "| Test | Result | Rule fired | Time to alert | Detail |"
  echo "|---|---|---|---|---|"
  for r in "${ROWS[@]}"; do echo "$r"; done
  echo
  [ -n "$BASELINE_NOTE" ] && { echo "$BASELINE_NOTE"; echo; }
  if [ -n "$DROPS_BEFORE" ] || [ -n "$DROPS_AFTER" ]; then
    echo "## Sensor performance under flood"
    echo
    echo '```'
    echo "before: ${DROPS_BEFORE:-unavailable}"
    echo "after : ${DROPS_AFTER:-unavailable}"
    echo '```'
    echo
    echo "\`capture.kernel_drops\` is the count of packets the kernel discarded before"
    echo "Suricata could inspect them. Every dropped packet is traffic the IDS never"
    echo "saw, so a non-zero delta here is a measured blind spot, not a rounding error."
    echo "Report the drop rate as (drops delta) / (packets delta)."
    echo
  fi
  cat <<'METHOD'
## Method

- All timestamps are read from the **Wazuh manager's** clock: `T0` immediately
  before launching the attack, alert time from the manager's `alerts.json`.
  One clock means VM skew cannot contaminate the latency figure.
- Only alerts at or after `T0` are counted, so no stale alert can be credited.
- Latency is **end-to-end for the scenario as run** and includes any deliberate
  sleeps inside the attack script (notably the FIM test, which waits for a
  baseline before modifying). It is not manager processing time.
- Resolution is 1 second — the granularity of the Wazuh alert timestamp.
- `NOT DETECTED` means no matching alert inside the stated timeout. Keep those
  rows and explain them; a documented miss is a finding.
METHOD
} > "$OUT"

echo
echo "============================================================"
cat "$OUT"
echo "============================================================"
echo "saved: ${OUT}"
