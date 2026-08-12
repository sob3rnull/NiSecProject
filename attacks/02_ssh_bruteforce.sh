#!/usr/bin/env bash
# SSH brute-force with hydra. THE headline detection (Wazuh host rules).
# Uses a short built-in list by default so the demo finishes fast; pass
# WORDLIST=/usr/share/wordlists/rockyou.txt for the full run.
source "$(dirname "$0")/_lib.sh"

# Not named USER: that is the login name the shell exports, and overwriting it
# hands a bogus username to every command this script runs.
SSH_LOGIN="${SSH_USER:-testuser}"
WORDLIST="${WORDLIST:-}"

if [ -z "$WORDLIST" ]; then
  # small demo list -> plenty of failed logins to trip the brute-force rule
  WORDLIST="$(mktemp)"
  trap 'rm -f "$WORDLIST"' EXIT
  printf '%s\n' 123456 password admin root toor letmein qwerty abc123 password1 welcome \
    monkey dragon master hello login passw0rd trustno1 iloveyou starwars > "$WORDLIST"
  log "using built-in demo wordlist (set WORDLIST=... for rockyou)"
fi

# hydra exits non-zero when it finds NO password — which is the outcome we want
# — so run_all.sh records that as "done", not as a failure.
run_logged "ssh_bruteforce" hydra -l "$SSH_LOGIN" -P "$WORDLIST" -t 4 -f "ssh://$TARGET"
