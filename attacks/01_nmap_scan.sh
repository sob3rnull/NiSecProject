#!/usr/bin/env bash
# Recon: stealth SYN scan + service/version detection.
# Expect: Suricata reconnaissance / port-scan alerts (+ our SID 9000002).
source "$(dirname "$0")/_lib.sh"
# -sS crafts raw packets, so it needs root — without sudo nmap refuses to run
# ("You requested a scan type which requires root privileges") and no scan,
# and therefore no Suricata alert, ever happens.
run_logged "nmap_scan" sudo nmap -sS -sV -T4 "$TARGET"
