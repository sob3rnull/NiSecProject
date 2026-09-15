#!/usr/bin/env bash
# score-signatures.sh — Signature Confidence Scorer
#
# For every test scenario that appears in your detection-results_*.md files,
# computes a CONFIDENCE SCORE based on how consistently the rule fired:
#
#   Confidence = (runs where DETECTED) ÷ (total runs that exercised that test)
#
# Also uses the idle baseline alert rate already captured in each results file
# to contextualise the noise floor against which detections must stand out.
#
# No live VMs required — runs entirely from the evidence files on disk.
#
# Usage:
#   make score
#   bash scripts/score-signatures.sh
#
set -uo pipefail
cd "$(dirname "$0")/.."

EVIDENCE_DIR="evidence"
OUT="${EVIDENCE_DIR}/confidence-scores_$(date +%Y%m%d_%H%M%S).md"

c_ok()   { printf '\033[32m%s\033[0m\n' "$1"; }
c_bad()  { printf '\033[31m%s\033[0m\n' "$1"; }
c_info() { printf '  %s\n' "$1"; }

echo "############################################################"
echo "# NISec Signature Confidence Scorer"
echo "# output -> ${OUT}"
echo "############################################################"

# ---------------------------------------------------------------------------
# Collect results files
# ---------------------------------------------------------------------------
mapfile -t RESULT_FILES < <(ls -1 "${EVIDENCE_DIR}"/detection-results_*.md 2>/dev/null | sort)

if [[ ${#RESULT_FILES[@]} -eq 0 ]]; then
  c_bad "No detection-results_*.md files found in ${EVIDENCE_DIR}/."
  c_bad "Run 'make measure' at least once first."
  exit 1
fi

c_info "found ${#RESULT_FILES[@]} run(s) to score"

# ---------------------------------------------------------------------------
# Test definitions — must match the labels in measure-detection.sh ROWS output
# ---------------------------------------------------------------------------
TEST_KEYS=("portscan" "bruteforce" "pingflood" "fim")
declare -A TEST_PREFIX=(
  ["portscan"]="1. Port scan"
  ["bruteforce"]="2. SSH brute"
  ["pingflood"]="3. Ping flood"
  ["fim"]="4. Malware"
)
declare -A TEST_DISPLAY=(
  ["portscan"]="Port scan (nmap -sS)"
  ["bruteforce"]="SSH brute-force (hydra)"
  ["pingflood"]="Ping flood (hping3)"
  ["fim"]="Malware / FIM (EICAR + mass modify)"
)
# Primary expected rules per test (for report context)
declare -A TEST_EXPECTED_RULES=(
  ["portscan"]="100120 / 100101 / 86601"
  ["bruteforce"]="5710 / 5712 / 5716 / 5720"
  ["pingflood"]="100120 / 100101 / 86601"
  ["fim"]="100200 / 100201 / 100202 / 550 / 554"
)

# ---------------------------------------------------------------------------
# Per-test counters
# ---------------------------------------------------------------------------
declare -A DETECTED_COUNT     # [test] = N
declare -A MISS_COUNT         # [test] = N
declare -A RULE_SEEN          # [test] = "r1 r2 r3 ..." (all observed, may repeat)
declare -A ALL_LATENCIES      # [test] = "s1 s2 s3 ..." (numeric seconds per detected run)

# Baseline accumulators
TOTAL_BASELINE_ALERTS=0
TOTAL_BASELINE_SECS=0
BASELINE_RUN_COUNT=0

for f in "${RESULT_FILES[@]}"; do
  # ---- Baseline row: "| _Baseline (idle, no attack)_ | 5 alerts in 120s | ..."
  baseline_row="$(grep "Baseline (idle" "$f" 2>/dev/null | head -1)"
  if [[ -n "$baseline_row" ]]; then
    b_count="$(printf '%s\n' "$baseline_row" | grep -oE '[0-9]+ alerts'    | grep -oE '[0-9]+'  | head -1)"
    b_secs="$( printf '%s\n' "$baseline_row" | grep -oE 'in [0-9]+s'       | grep -oE '[0-9]+' | head -1)"
    TOTAL_BASELINE_ALERTS=$(( TOTAL_BASELINE_ALERTS + ${b_count:-0} ))
    TOTAL_BASELINE_SECS=$(( TOTAL_BASELINE_SECS + ${b_secs:-120} ))
    (( BASELINE_RUN_COUNT++ )) || true
  fi

  # ---- Detection rows: "| <label> | DETECTED | <rule> | <Xs> | ... |"
  while IFS='|' read -r _ label result rule latency _; do
    label="$(printf '%s' "$label" | sed 's/^ *//;s/ *$//')"
    result="$(printf '%s' "$result" | sed 's/^ *//;s/ *$//')"
    rule="$(printf '%s' "$rule"   | sed 's/^ *//;s/ *$//')"
    latency="$(printf '%s' "$latency" | sed 's/^ *//;s/ *$//;s/[^0-9]//g')"

    for key in "${TEST_KEYS[@]}"; do
      [[ "$label" == "${TEST_PREFIX[$key]}"* ]] || continue
      if printf '%s\n' "$result" | grep -q "NOT DETECTED"; then
        MISS_COUNT["$key"]=$(( ${MISS_COUNT["$key"]:-0} + 1 ))
      elif printf '%s\n' "$result" | grep -qi "DETECTED"; then
        DETECTED_COUNT["$key"]=$(( ${DETECTED_COUNT["$key"]:-0} + 1 ))
        [[ "$rule" != "-" && -n "$rule" ]] && \
          RULE_SEEN["$key"]="${RULE_SEEN["$key"]:-} $rule"
        [[ "${latency:-0}" -gt 0 ]] && \
          ALL_LATENCIES["$key"]="${ALL_LATENCIES["$key"]:-} $latency"
      fi
      break
    done
  done < <(grep "^|" "$f" 2>/dev/null)
done

# ---------------------------------------------------------------------------
# Derived metrics
# ---------------------------------------------------------------------------
BASELINE_RATE_PER_HOUR=0
if [[ "$TOTAL_BASELINE_SECS" -gt 0 ]]; then
  BASELINE_RATE_PER_HOUR=$(( TOTAL_BASELINE_ALERTS * 3600 / TOTAL_BASELINE_SECS ))
fi

# confidence_score <test> — prints integer 0-100 or "NA"
confidence_score() {
  local key="$1"
  local det="${DETECTED_COUNT[$key]:-0}"
  local mis="${MISS_COUNT[$key]:-0}"
  local total=$(( det + mis ))
  [[ "$total" -eq 0 ]] && { printf 'NA'; return; }
  printf '%d' $(( (det * 100) / total ))
}

# confidence_label <score> — prints coloured label
confidence_label() {
  local s="$1"
  if [[ "$s" == "NA" ]]; then  printf '🔵 N/A'
  elif [[ "$s" -ge 90 ]];     then printf '🟢 HIGH'
  elif [[ "$s" -ge 60 ]];     then printf '🟡 MEDIUM'
  else                              printf '🔴 LOW'
  fi
}

# avg_latency <test> — mean latency over detected runs
avg_latency() {
  local key="$1"
  local vals="${ALL_LATENCIES[$key]:-}"
  [[ -z "${vals// }" ]] && { printf '—'; return; }
  printf '%s\n' $vals \
    | awk '{s+=$1; n++} END { if(n>0) printf "%ds avg", s/n; else print "—" }'
}

# primary_rule <test> — most-frequently-seen rule ID
primary_rule() {
  local key="$1"
  local vals="${RULE_SEEN[$key]:-}"
  [[ -z "${vals// }" ]] && { printf '—'; return; }
  printf '%s\n' $vals \
    | grep -v '^$' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'
}

# ---------------------------------------------------------------------------
# Write report
# ---------------------------------------------------------------------------
{
  echo '# Signature Confidence Scores'
  echo
  printf '**Generated by** `scripts/score-signatures.sh` on %s  \n' \
    "$(date '+%Y-%m-%d %H:%M:%S')"
  printf '**Runs analysed:** %s  \n' "${#RESULT_FILES[@]}"
  printf '**Baseline noise:** ~%s alerts/hour (idle, %s observation windows)\n\n' \
    "$BASELINE_RATE_PER_HOUR" "$BASELINE_RUN_COUNT"
  echo '---'
  echo

  # ---- Main score table ----
  echo '## Confidence Score Table'
  echo
  echo '**Confidence** = DETECTED runs ÷ total runs exercising that test scenario.'
  echo '100%% means the rule fired every single time.'
  echo
  echo '| Test Scenario | Primary Rule | Expected Rules | Det | Miss | Avg Latency | Score | Rating |'
  echo '|---|---|---|---|---|---|---|---|'

  for key in "${TEST_KEYS[@]}"; do
    det="${DETECTED_COUNT[$key]:-0}"
    mis="${MISS_COUNT[$key]:-0}"
    score="$(confidence_score "$key")"
    label="$(confidence_label "$score")"
    prule="$(primary_rule "$key")"
    avglt="$(avg_latency "$key")"
    score_disp="$([ "$score" == "NA" ] && printf 'N/A' || printf '%s%%' "$score")"
    printf '| %s | `%s` | `%s` | %s | %s | %s | %s | %s |\n' \
      "${TEST_DISPLAY[$key]}" "$prule" "${TEST_EXPECTED_RULES[$key]}" \
      "$det" "$mis" "$avglt" "$score_disp" "$label"
  done

  echo '\n---'
  echo

  # ---- Baseline noise section ----
  echo '## Baseline Noise Context'
  echo
  echo '| Metric | Value |'
  echo '|---|---|'
  printf '| Runs with baseline captured | %s |\n'      "$BASELINE_RUN_COUNT"
  printf '| Total idle alerts (all baselines) | %s |\n' "$TOTAL_BASELINE_ALERTS"
  printf '| Combined observation window | %ss |\n'      "$TOTAL_BASELINE_SECS"
  printf '| **Average idle alert rate** | **~%s alerts/hour** |\n\n' \
    "$BASELINE_RATE_PER_HOUR"

  if [[ "$BASELINE_RATE_PER_HOUR" -gt 100 ]]; then
    printf '> ⚠️ **High baseline noise (>%s/hr).** Your idle lab generates significant\n' \
      "$BASELINE_RATE_PER_HOUR"
    echo '> alert traffic, which makes it harder to claim any single alert was caused'
    echo '> by the attack rather than background noise. Consider tuning rule thresholds'
    echo '> or filtering known-good traffic (VM heartbeats, agent keepalives) in `ossec.conf`.'
    echo
  elif [[ "$BASELINE_RATE_PER_HOUR" -gt 30 ]]; then
    printf '> 🟡 **Moderate baseline noise (~%s/hr).** Some idle alerts are normal\n' \
      "$BASELINE_RATE_PER_HOUR"
    echo '> (Wazuh agent keepalives, rootcheck cycles). Document this rate in report §7.3'
    echo '> and use it to qualify your detection claims: "we saw N alerts during the attack,'
    printf '> against a baseline of ~%s/hr idle."\n\n' "$BASELINE_RATE_PER_HOUR"
  else
    printf '> 🟢 **Low baseline noise (~%s/hr).** Clean detection environment.\n' \
      "$BASELINE_RATE_PER_HOUR"
    echo '> Any alert fired during an attack run is almost certainly attack-caused,'
    echo '> which strengthens your detection claims in the report.'
    echo
  fi
  echo '---'
  echo

  # ---- Per-test deep dive ----
  echo '## Per-Test Analysis'
  echo
  for key in "${TEST_KEYS[@]}"; do
    score="$(confidence_score "$key")"
    label="$(confidence_label "$score")"
    det="${DETECTED_COUNT[$key]:-0}"
    mis="${MISS_COUNT[$key]:-0}"
    total=$(( det + mis ))
    printf '### %s\n\n' "${TEST_DISPLAY[$key]}"
    echo '| Field | Value |'
    echo '|---|---|'
    printf '| Confidence | **%s** %s |\n' "$([ "$score" == "NA" ] && printf 'N/A' || printf '%s%%' "$score")" "$label"
    printf '| Detected / Total | %d / %d runs |\n' "$det" "$total"
    printf '| Missed / Total | %d / %d runs |\n' "$mis" "$total"
    printf '| Average latency (detected runs) | %s |\n' "$(avg_latency "$key")"
    printf '| Primary rule fired | `%s` |\n' "$(primary_rule "$key")"
    printf '| All rules observed | `%s` |\n\n' "$(printf '%s\n' ${RULE_SEEN[$key]:-—} | sort -u | tr '\n' ' ')"

    if [[ "$score" == "NA" ]]; then
      echo '> 🔵 This scenario was not found in any results file. Run `make measure` with this test included.'
      echo
    elif [[ "$score" -ge 90 ]]; then
      echo '> 🟢 **HIGH confidence.** This rule fires reliably — cite its latency in the report with confidence.'
      echo '> Use it as primary evidence for this threat category.'
      echo
    elif [[ "$score" -ge 60 ]]; then
      printf '> 🟡 **MEDIUM confidence.** The rule fires most of the time but missed %d run(s).\n' "$mis"
      echo '> Investigate the misses: was the VM under load? Was the attack timing different?'
      echo '> Document the variability in report §7 as an honest finding.'
      echo
    else
      printf '> 🔴 **LOW confidence.** This rule misses more often than it detects (%d miss / %d total).\n' \
        "$mis" "$total"
      echo '> Either the rule threshold is too conservative, or the attack scenario'
      echo '> does not reliably trigger the detection path. Name this as a **limitation**'
      echo '> in report §7 — a documented limitation scores better than a hidden one.'
      echo
    fi
  done
  echo '---'
  echo

  # ---- How to use this in the report ----
  echo '## Using These Scores in Your Report'
  echo
  echo '### For HIGH confidence rules (≥90%%)'
  echo
  echo 'State the score and cite the detection latency directly:'
  echo
  printf '> *"The SSH brute-force detection rule fired in 100%% of test runs (N=%d),\n' \
    "${#RESULT_FILES[@]}"
  echo '>  with an average latency of X seconds. We assign HIGH confidence to this detection."*'
  echo
  echo '### For MEDIUM confidence rules (60–89%%)'
  echo
  echo 'Name the variability and explain it:'
  echo
  echo '> *"The port-scan rule detected in 75%% of runs. The two misses occurred when'
  echo '>  the host was under high load — Suricata dropped packets and the threshold'
  echo '>  was not crossed. This is a documented limitation, not a result artefact."*'
  echo
  echo '### For LOW confidence rules (<60%%)'
  echo
  echo 'Report the score as a finding, not a failure:'
  echo
  echo '> *"The ping-flood rule has LOW confidence (50%%), suggesting the threshold'
  printf '>  in local.rules (count:100, seconds:5) is conservative for this lab'\''s\n'
  echo '>  virtual NIC. Lowering the threshold to count:50 would be a recommended'
  echo '>  remediation — but we chose not to retune mid-project to preserve'
  echo '>  measurement consistency."*'
  echo
  echo '---'
  echo

  echo '## Method'
  echo
  echo '- Data parsed from `evidence/detection-results_*.md` (no live VMs required).'
  echo '- Confidence = DETECTED ÷ (DETECTED + MISS), per test scenario, across all runs.'
  echo '- "Primary rule" = the rule ID most frequently observed in DETECTED rows for that test.'
  echo '- Average latency computed over detected runs only (misses excluded from mean).'
  echo '- Baseline noise rate computed from the idle observation rows in each results file.'
  echo '- Increase statistical confidence by running `make measure` multiple times.'
  echo

} > "$OUT"

c_ok "Confidence scores -> ${OUT}"
echo
echo "Summary:"
for key in "${TEST_KEYS[@]}"; do
  score="$(confidence_score "$key")"
  label="$(confidence_label "$score")"
  det="${DETECTED_COUNT[$key]:-0}"
  mis="${MISS_COUNT[$key]:-0}"
  score_disp="$([ "$score" == "NA" ] && printf 'N/A' || printf '%s%%' "$score")"
  printf '  %-35s  %s  %s  (det=%s miss=%s)\n' \
    "${TEST_DISPLAY[$key]}" "$score_disp" "$label" "$det" "$mis"
done
printf '\n  Baseline noise: ~%s alerts/hour\n' "$BASELINE_RATE_PER_HOUR"
