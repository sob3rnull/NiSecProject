#!/usr/bin/env bash
# Web attack against DVWA: Nikto scan (+ a sample SQLi request).
# Expect: Suricata web-attack signatures (SQLi/XSS/scanner) -> Wazuh rule 100110.
source "$(dirname "$0")/_lib.sh"

log "1/2 Nikto scan of ${DVWA_URL} ..."
run_logged "nikto_dvwa" nikto -h "${DVWA_URL}/" -Tuning 1234567890 || true

log "2/2 sample SQL-injection request (classic ' OR '1'='1) ..."
run_logged "sqli_probe" curl -s -G "${DVWA_URL}/vulnerabilities/sqli/" \
  --data-urlencode "id=1' OR '1'='1" \
  --data-urlencode "Submit=Submit" || true
