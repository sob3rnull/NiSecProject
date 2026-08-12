#!/usr/bin/env bash
# healthcheck.sh — quick sanity check of the whole lab. Run from the host
# (uses `vagrant ssh`) after `make up`. Green = good, red = look here.
set -uo pipefail

ok()   { printf '  \033[32m[ ok ]\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m[fail]\033[0m %s\n' "$1"; }
head() { printf '\n== %s ==\n' "$1"; }

vssh() { vagrant ssh "$1" -c "$2" 2>/dev/null; }

head "Reachability (host-only network)"
for ip in 192.168.56.40 192.168.56.20 192.168.56.30 192.168.56.10; do
  if ping -c1 -W1 "$ip" >/dev/null 2>&1; then ok "ping $ip"; else bad "ping $ip"; fi
done

head "Wazuh server services"
if vssh wazuh-server "systemctl is-active wazuh-manager"  | grep -q active; then ok "wazuh-manager active";  else bad "wazuh-manager";  fi
if vssh wazuh-server "systemctl is-active wazuh-indexer"  | grep -q active; then ok "wazuh-indexer active";  else bad "wazuh-indexer";  fi
if vssh wazuh-server "systemctl is-active wazuh-dashboard" | grep -q active; then ok "wazuh-dashboard active"; else bad "wazuh-dashboard"; fi

head "Agents"
for vm in monitored client; do
  if vssh "$vm" "systemctl is-active wazuh-agent" | grep -q active; then ok "$vm agent active"; else bad "$vm agent"; fi
done

head "Suricata (monitored)"
if vssh monitored "systemctl is-active suricata" | grep -q active; then ok "suricata active"; else bad "suricata"; fi
if vssh monitored "sudo test -s /var/log/suricata/eve.json && echo yes" | grep -q yes; then
  ok "eve.json exists and is non-empty"
else
  bad "eve.json missing/empty (generate traffic to populate it)"
fi
# Custom threshold rules must be MERGED into the compiled ruleset, not just
# copied next to it — otherwise the ping-flood detection silently never fires.
if vssh monitored "sudo grep -c 'sid:900000' /var/lib/suricata/rules/suricata.rules" | grep -qE '[1-9]'; then
  ok "custom NISec signatures (9000001-3) loaded"
else
  bad "custom NISec signatures NOT loaded - run: sudo suricata-update --local /etc/suricata/rules/nisec-local.rules"
fi

head "DVWA (monitored)"
if vssh monitored "curl -s -o /dev/null -w '%{http_code}' http://localhost/ | grep -q '200\|302' && echo up"; then
  ok "DVWA responding on :80"
else
  bad "DVWA not up (run: cd /vagrant/dvwa && ./up.sh)"
fi

head "Attacker tools (kali)"
for t in nmap hydra hping3 nikto; do
  if vssh kali "command -v $t" | grep -q "$t"; then ok "$t present"; else bad "$t missing"; fi
done

printf '\nDone. Dashboard: https://192.168.56.40\n'
