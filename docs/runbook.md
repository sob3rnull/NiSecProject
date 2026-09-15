# Runbook — Operations & Troubleshooting

Day-to-day reference for a lab that's **already built**.

> **Building it for the first time?** Use [`step-by-step-guide.md`](step-by-step-guide.md) instead.
> This document assumes the lab exists and something needs checking, fixing, or re-running.

---

## Command reference

On Windows, run these from PowerShell in the repo root. `nisec.ps1` is the preferred wrapper
because it avoids PowerShell accidentally calling WSL `bash.exe` for host-side scripts.

### Lifecycle

```powershell
.\nisec.ps1 up              # build/start the full 4-VM lab
.\nisec.ps1 up-budget       # 3-VM lab (no client) for 8 GB hosts
.\nisec.ps1 up-docker       # build with a containerised Wazuh stack
.\nisec.ps1 halt            # stop all VMs (keeps state)
.\nisec.ps1 destroy         # delete all VMs (irreversible)
.\nisec.ps1 status          # what's running
.\nisec.ps1 reload          # restart + re-provision
.\nisec.ps1 provision       # re-run provisioners only (no restart)
```

### Operations

```powershell
.\nisec.ps1 healthcheck     # verify connectivity + every service across the lab
.\nisec.ps1 harden          # apply dashboard access-control hardening
.\nisec.ps1 retention -IndexerPass '<admin password>'
.\nisec.ps1 capture         # 60s packet capture on the monitored server
```

### Testing

```powershell
.\nisec.ps1 test                # offline regression test for custom signatures
.\nisec.ps1 attacks             # detection suite from Kali (tests 1,2,3,5)
.\nisec.ps1 malware-test        # FIM/ransomware test (on monitored server)
.\nisec.ps1 evasion             # detection boundary tests
.\nisec.ps1 measure             # detection rate + latency table -> evidence/
.\nisec.ps1 seal                # hash evidence/ into a manifest
.\nisec.ps1 dvwa                # [bonus] start DVWA
```

For the bonus `BONUS=true` and `PAUSE=45` variants, use Git Bash with `make` or run the
underlying Kali command directly with the environment variable set.

### Shell access

```powershell
.\nisec.ps1 ssh-wazuh-server
.\nisec.ps1 ssh-monitored
.\nisec.ps1 ssh-client
.\nisec.ps1 ssh-kali
```

If you are in Git Bash or Linux, the equivalent commands are still `make up`, `make status`,
`make healthcheck`, `make attacks`, and so on.

---

## Service management

### On the Wazuh server

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
sudo systemctl restart wazuh-manager

# logs
sudo tail -f /var/ossec/logs/ossec.log
sudo journalctl -u wazuh-indexer -f

# list agents
sudo /var/ossec/bin/agent_control -l

# test a rule against a sample log line (extremely useful)
sudo /var/ossec/bin/wazuh-logtest
```

### On the monitored server

```bash
sudo systemctl status suricata wazuh-agent
sudo tail -f /var/log/suricata/eve.json | jq .        # live alerts, pretty
sudo tail -f /var/ossec/logs/ossec.log                # agent log

# test the Suricata config without restarting
sudo suricata -T -c /etc/suricata/suricata.yaml
```

---

## Troubleshooting by symptom

### No alerts appear in the dashboard

Work backwards through the chain — the fault is always at one specific link:

```bash
# 1. Is Suricata seeing traffic at all?
vagrant ssh monitored -c "sudo tail -5 /var/log/suricata/eve.json"

# 2. Is the agent running and connected?
vagrant ssh monitored -c "systemctl is-active wazuh-agent"
vagrant ssh wazuh-server -c "sudo /var/ossec/bin/agent_control -l"

# 3. Is the eve.json localfile block present?
vagrant ssh monitored -c "sudo grep -A2 'suricata/eve.json' /var/ossec/etc/ossec.conf"

# 4. Is the manager processing anything?
vagrant ssh wazuh-server -c "sudo tail -20 /var/ossec/logs/alerts/alerts.log"
```

Whichever step is empty is your fault line.

### Custom Suricata rules not firing (the ping flood especially)

**The most common silent failure in this project.**

```bash
# Are our SIDs actually in the compiled ruleset?
vagrant ssh monitored -c "sudo grep -c 'sid:900000' /var/lib/suricata/rules/suricata.rules"
# expect 3; if 0:
vagrant ssh monitored -c "sudo suricata-update --local /etc/suricata/rules/nisec-local.rules && sudo systemctl restart suricata"
```

**Why this happens:** Suricata only loads files listed under `rule-files:` in `suricata.yaml`, and
`suricata-update` regenerates that directory. Copying a `.rules` file alongside it does nothing.
`--local` is the supported way to merge custom rules in. `.\nisec.ps1 healthcheck` / `make
healthcheck` checks this for you.

### Indexer won't start / everything crawls

Nearly always RAM. The indexer is a JVM and is genuinely memory-hungry.

```bash
vagrant ssh wazuh-server -c "free -h"
vagrant ssh wazuh-server -c "sudo journalctl -u wazuh-indexer -n 50 --no-pager"
```

Fixes, in order of preference: raise the VM's memory in the `Vagrantfile` (6–8 GB), or run
`.\nisec.ps1 up-budget` / `make up-budget` to drop the client VM and free ~1.5 GB.

On a 16 GB Windows host, it is normal to keep `client` powered off while learning the lab. That
makes the `client agent` healthcheck fail, but the core Wazuh + Suricata detection path can still
be valid.

### Suricata sees no traffic

Wrong interface — it's sniffing the NAT adapter instead of the host-only one.

```bash
vagrant ssh monitored -c "ip -o -4 addr"                    # find the 192.168.56.x NIC
vagrant ssh monitored -c "grep -A3 af-packet: /etc/suricata/suricata.yaml"
```

The interface under `af-packet:` must match. Fix and `sudo systemctl restart suricata`.

### Agent shows Disconnected / Never connected

```bash
vagrant ssh monitored -c "nc -zv 192.168.56.40 1514"   # can it reach the manager?
vagrant ssh monitored -c "sudo /var/ossec/bin/agent-auth -m 192.168.56.40"   # re-register
vagrant ssh monitored -c "sudo systemctl restart wazuh-agent"
```

If the firewall is the culprit, confirm 1514/1515 are allowed:
`vagrant ssh wazuh-server -c "sudo ufw status"`

### Locked out of the dashboard

```bash
vagrant ssh wazuh-server
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh \
  -u admin -p 'NewStrongPassword123!'
sudo systemctl restart wazuh-dashboard
```

### Docker stack won't start

```bash
cd deploy-docker
sudo docker compose logs wazuh.indexer | tail -40
```

| Error | Cause | Fix |
|---|---|---|
| `INDEXER_PASSWORD must be set` | No `.env`, or still `CHANGE_ME` | `rm .env && ./up.sh` to auto-generate strong credentials |
| `MISSING CERTIFICATES` | Certs not generated | Follow the exact instructions the script prints |
| Indexer exits immediately | `vm.max_map_count` too low | `sudo sysctl -w vm.max_map_count=262144` |
| Port 443 in use | Something else has it | Change the dashboard port mapping in `docker-compose.yml` |

### Hydra "finds nothing"

That's the expected outcome and not a problem. The **failed** attempts are what trip the
brute-force rule — you don't need a successful login. Hydra exiting non-zero here is normal; the
test runner accounts for it and continues.

---

## Health check reference

```powershell
.\nisec.ps1 healthcheck
```

Verifies: reachability of all four IPs · Wazuh manager/indexer/dashboard active · both agents
active · Suricata active · `eve.json` non-empty · **custom SIDs loaded** · DVWA responding ·
attack tools present on Kali.

Expected red items in partial/budget runs:

- `client agent` when the `client` VM is powered off.
- `DVWA not up` unless you deliberately started the optional vulnerable web app.

Anything marked `[fail]` maps to a section above.

---

## Where things live

| What | Path |
|---|---|
| Agent config | `/var/ossec/etc/ossec.conf` |
| Manager custom rules | `/var/ossec/etc/rules/local_rules.xml` |
| Manager alert log | `/var/ossec/logs/alerts/alerts.log` |
| Wazuh service log | `/var/ossec/logs/ossec.log` |
| Suricata config | `/etc/suricata/suricata.yaml` |
| Suricata custom rules (source) | `/etc/suricata/rules/nisec-local.rules` |
| Suricata compiled ruleset | `/var/lib/suricata/rules/suricata.rules` |
| Suricata alerts | `/var/log/suricata/eve.json` |
| Repo inside every VM | `/vagrant` |
| Your evidence | `evidence/{screenshots,logs,pcaps}/` |

---

## Resetting

```bash
# re-run one machine's provisioning
vagrant provision monitored

# rebuild a single VM from scratch
vagrant destroy -f monitored && vagrant up monitored

# nuclear option
.\nisec.ps1 destroy
.\nisec.ps1 up
```

> Before destroying anything, copy `evidence/` somewhere safe. Screenshots and logs are your
> marks — the VMs are replaceable.
