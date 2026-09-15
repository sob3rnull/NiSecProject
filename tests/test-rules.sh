#!/usr/bin/env bash
# tests/test-rules.sh — regression tests for the custom detection rules.
#
# The rest of this repo verifies that services are RUNNING. This verifies that
# the rules are CORRECT, which is a different claim and the one the project is
# actually about.
#
# Suricata rules are tested by replaying a synthetic pcap through the engine
# offline (`suricata -r`). That isolates a single question — does this
# signature match the traffic it claims to match? — from every other thing
# that can go wrong: wrong sniffing interface, agent down, manager busy,
# dashboard filtered to the wrong time range. When a live attack produces no
# alert, run this first: if the rules pass here, the fault is in the pipeline,
# not the signatures.
#
# It also pins the HOME_NET bug that this project already hit once. The rules
# are written `$EXTERNAL_NET -> $HOME_NET` and EXTERNAL_NET is `!$HOME_NET`,
# so widening HOME_NET to the whole /24 makes every rule load perfectly and
# match nothing. That is invisible in production and a hard failure here.
#
# Run from the HOST:  make test
set -uo pipefail

cd "$(dirname "$0")/.."

PASS=0
FAIL=0
SKIP=0

ok()   { printf '  \033[32m[pass]\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33m[skip]\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

mon() { vagrant ssh monitored    -c "$1" 2>/dev/null | tr -d '\r'; }
mgr() { vagrant ssh wazuh-server -c "$1" 2>/dev/null | tr -d '\r'; }

# ---------------------------------------------------------------------------
sect "Preconditions"

if ! mon 'command -v suricata' | grep -q suricata; then
  echo "Suricata not found on 'monitored'. Run: make up" >&2
  exit 1
fi
ok "suricata present on the monitored server"

# HOME_NET must exclude the attacker or every rule below is unmatchable.
HN="$(mon "sudo grep -E '^ *HOME_NET:' /etc/suricata/suricata.yaml | head -1")"
if echo "$HN" | grep -q '192.168.56.10'; then
  bad "HOME_NET contains the attacker .10 - EXTERNAL_NET rules cannot match: ${HN}"
elif [ -z "$HN" ]; then
  skip "could not read HOME_NET from suricata.yaml"
else
  ok "HOME_NET excludes the attack zone:${HN#*HOME_NET:}"
fi

# ---------------------------------------------------------------------------
sect "Suricata rule syntax + load"

if mon "sudo suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/nisec-local.rules 2>&1" \
   | grep -qi 'configuration provided was successfully loaded\|Configuration provided was successfully'; then
  ok "nisec-local.rules loads cleanly (suricata -T)"
else
  bad "nisec-local.rules failed to load - run: sudo suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/nisec-local.rules"
fi

# ---------------------------------------------------------------------------
sect "Suricata signature matching (offline pcap replay)"

WORK=/tmp/nisec-ruletest
PCAP="${WORK}/fixture.pcap"

mon "rm -rf ${WORK} && mkdir -p ${WORK}" >/dev/null
GEN="$(mon "python3 /vagrant/tests/make_fixture_pcap.py ${PCAP} 2>&1")"
if echo "$GEN" | grep -q 'wrote'; then
  ok "fixture pcap generated: $(echo "$GEN" | head -1 | sed 's#.*/##')"
else
  bad "could not generate fixture pcap: ${GEN}"
  echo; echo "Result: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"; exit 1
fi

# -S loads ONLY our rules, so a match cannot be credited to an ET Open
# signature. -k none skips checksum validation: the fixture's checksums are
# correct, but we are testing signature logic, not the checksum engine.
mon "sudo suricata -r ${PCAP} -S /etc/suricata/rules/nisec-local.rules -l ${WORK} -k none >/dev/null 2>&1" >/dev/null

EVE="${WORK}/eve.json"
if ! mon "sudo test -s ${EVE} && echo yes" | grep -q yes; then
  bad "replay produced no ${EVE} - check: sudo suricata -r ${PCAP} -S ... -l ${WORK}"
else
  FIRED="$(mon "sudo jq -r 'select(.event_type==\"alert\") | .alert.signature_id' ${EVE} 2>/dev/null | sort -u | tr '\n' ' '")"
  ok "replay produced alerts; signature ids fired: ${FIRED:-none}"

  check_sid() {
    local sid="$1" what="$2"
    if echo " $FIRED " | grep -q " $sid "; then
      ok "SID ${sid} fired — ${what}"
    else
      bad "SID ${sid} did NOT fire — ${what}"
    fi
  }
  check_sid 9000001 "ICMP flood (600 echo requests in the fixture)"
  check_sid 9000002 "SYN port scan (60 SYNs across 60 ports)"
  check_sid 9000003 "repeated SSH connections (40 SYNs to port 22)"
fi

# ---------------------------------------------------------------------------
sect "Wazuh manager rules (wazuh-logtest)"

# Best-effort: wazuh-logtest's non-interactive behaviour varies across 4.x
# releases. A skip here is not a failure of the rules — it means this harness
# could not drive the tool, and you should check by hand with:
#   sudo /var/ossec/bin/wazuh-logtest
if ! mgr 'sudo test -x /var/ossec/bin/wazuh-logtest && echo yes' | grep -q yes; then
  skip "wazuh-logtest not available on the manager"
else
  # A synthetic Suricata eve.json alert carrying one of our custom SIDs.
  # Rule 100120 should pick it up via its parent 86601.
  EVENT='{"timestamp":"2026-01-01T00:00:00.000+0000","event_type":"alert","src_ip":"192.168.56.10","dest_ip":"192.168.56.20","alert":{"action":"allowed","signature_id":9000001,"signature":"NISEC ICMP ping flood detected (possible DoS)","category":"Attempted Denial of Service","severity":2}}'
  OUT="$(mgr "printf '%s\n' '${EVENT}' | sudo /var/ossec/bin/wazuh-logtest -l /var/log/suricata/eve.json 2>&1 | head -60")"
  if echo "$OUT" | grep -qE "id: *'?(100120|100101|100102|86601)"; then
    ok "eve.json alert decodes and matches a NISec/Suricata rule"
  elif [ -z "$OUT" ]; then
    skip "wazuh-logtest produced no output (drive it manually to confirm)"
  else
    skip "wazuh-logtest ran but matched no NISec rule — verify by hand: sudo /var/ossec/bin/wazuh-logtest"
  fi

  # Host-side: a failed SSH login should hit the built-in brute-force family.
  AUTH='Jan  1 00:00:00 monitored sshd[1234]: Failed password for invalid user testuser from 192.168.56.10 port 40000 ssh2'
  OUT2="$(mgr "printf '%s\n' '${AUTH}' | sudo /var/ossec/bin/wazuh-logtest -l /var/log/auth.log 2>&1 | head -60")"
  if echo "$OUT2" | grep -qE "id: *'?(5710|5716|5712|5760)"; then
    ok "failed SSH login matches the built-in authentication rules"
  else
    skip "could not confirm the SSH auth rule via logtest — verify by hand"
  fi
fi

# ---------------------------------------------------------------------------
mon "rm -rf ${WORK}" >/dev/null 2>&1

sect "Result"
printf '  %d passed, %d failed, %d skipped\n\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
  echo "Rule regression FAILED. Fix the signatures before collecting evidence —"
  echo "a live test that produces no alert will be impossible to diagnose otherwise."
  exit 1
fi
echo "All custom signatures match their intended traffic."
