#!/usr/bin/env bash
# Recon: stealth SYN scan + service/version detection.
# Expect: Suricata reconnaissance / port-scan alerts (+ our SID 9000002).
source "$(dirname "$0")/_lib.sh"
run_logged "nmap_scan" nmap -sS -sV -T4 "$TARGET"
