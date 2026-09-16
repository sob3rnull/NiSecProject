# Runbook — NISec Operations & Troubleshooting

This is the operational reference for a lab that has already been provisioned.
For a first-time build, use [`step-by-step-guide.md`](step-by-step-guide.md).

---

## 1. Command reference

### Lifecycle

```powershell
.\nisec.ps1 up
.\nisec.ps1 up-budget
.\nisec.ps1 up-docker
.\nisec.ps1 status
.\nisec.ps1 halt
.\nisec.ps1 reload
.\nisec.ps1 provision
.\nisec.ps1 destroy
```

### Core verification and testing

```powershell
.\nisec.ps1 healthcheck
.\nisec.ps1 test
.\nisec.ps1 attacks
.\nisec.ps1 malware-test
.\nisec.ps1 capture
.\nisec.ps1 evasion
```

### Evidence and analysis

```powershell
.\nisec.ps1 measure
.\nisec.ps1 hunt
.\nisec.ps1 compare
.\nisec.ps1 score
.\nisec.ps1 seal
```

### AI-assisted analysis

```powershell
.\nisec.ps1 correlate
.\nisec.ps1 correlate-test
.\nisec.ps1 correlate --dry-run

.\nisec.ps1 report
.\nisec.ps1 report-test
.\nisec.ps1 report --dry-run
```

### Optional controls / bonus

```powershell
.\nisec.ps1 harden
.\nisec.ps1 retention -IndexerPass '<admin password>'
.\nisec.ps1 active-response
.\nisec.ps1 dvwa
```

The equivalent `make` targets are listed by:

```bash
make help
```

---

## 2. Recommended execution order

For a clean experimental run:

```text
up
 ↓
healthcheck
 ↓
test
 ↓
attacks + malware-test
 ↓
capture
 ↓
measure
 ↓
hunt
 ↓
evasion
 ↓
compare + score
 ↓
correlate
 ↓
report
 ↓
seal
```

Run `make test` before relying on a custom Suricata result. Run `make measure` only after the
test traffic has been generated so that the measurement is tied to the intended run.

---

## 3. Service management

### Wazuh server

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
sudo systemctl restart wazuh-manager

sudo tail -f /var/ossec/logs/ossec.log
sudo tail -f /var/ossec/logs/alerts/alerts.log

sudo /var/ossec/bin/agent_control -l
sudo /var/ossec/bin/wazuh-logtest
```

### Monitored server

```bash
sudo systemctl status suricata wazuh-agent
sudo tail -f /var/log/suricata/eve.json | jq .
sudo tail -f /var/ossec/logs/ossec.log
sudo suricata -T -c /etc/suricata/suricata.yaml
```

---

## 4. Troubleshooting by pipeline stage

### A. No network alert

Check traffic first:

```bash
sudo tail -20 /var/log/suricata/eve.json
ip -o -4 addr
```

Then verify Suricata's interface:

```bash
grep -A5 'af-packet:' /etc/suricata/suricata.yaml
```

The interface must be the one carrying the `192.168.56.x` traffic.

Then verify the custom rules are loaded:

```bash
sudo grep -c 'sid:900000' /var/lib/suricata/rules/suricata.rules
```

Expected: `3`.

If they are missing:

```bash
sudo suricata-update --local /etc/suricata/rules/nisec-local.rules
sudo systemctl restart suricata
```

Finally run:

```bash
make test
```

If offline rule replay passes but live traffic fails, the problem is likely visibility,
interface configuration, threshold conditions, or downstream collection—not the signature
itself.

---

### B. Suricata alert exists but Wazuh does not show it

Check:

```bash
sudo grep -A4 'suricata/eve.json' /var/ossec/etc/ossec.conf
sudo systemctl status wazuh-agent
sudo /var/ossec/bin/agent_control -l
```

Then inspect the Manager:

```bash
sudo tail -50 /var/ossec/logs/alerts/alerts.log
sudo tail -50 /var/ossec/logs/ossec.log
```

The intended path is:

```text
eve.json → Wazuh Agent → 1514/tcp → Manager → rule → Indexer → Dashboard
```

---

### C. Agent is disconnected

From the agent host:

```bash
nc -zv 192.168.56.40 1514
nc -zv 192.168.56.40 1515
sudo systemctl status wazuh-agent
```

On the server:

```bash
sudo /var/ossec/bin/agent_control -l
sudo ufw status
```

If re-enrolment is necessary:

```bash
sudo /var/ossec/bin/agent-auth -m 192.168.56.40
sudo systemctl restart wazuh-agent
```

---

### D. Indexer is slow or fails to start

Inspect memory:

```bash
free -h
sudo journalctl -u wazuh-indexer -n 50 --no-pager
```

The Indexer is memory intensive. On an 8 GB host use:

```powershell
.\nisec.ps1 up-budget
```

Budget mode intentionally omits the `client` VM.

---

### E. Dashboard authentication problems

The lab dashboard is:

```text
https://192.168.56.40
```

Retrieve the generated credentials:

```bash
sudo tar -O -xf wazuh-install-files.tar \
  wazuh-install-files/wazuh-passwords.txt | grep -A1 admin
```

If the password must be reset, use the Wazuh password-management tooling installed by the
current Wazuh deployment and restart the affected service.

Do not put passwords into source control, `.env` files committed to Git, or documentation.

---

## 5. Measurement troubleshooting

`measure` is intended to produce evidence, not merely a count of alerts.

If a row is `NOT DETECTED`:

1. Check whether the source event exists.
2. Check the event timestamp.
3. Check whether the expected rule/SID is loaded.
4. Check whether the attack actually crossed the relevant threshold.
5. Do not replace `NOT DETECTED` with a guessed value.

For latency comparisons, keep the same lab configuration and measurement method between runs.
Use `compare` after several measurement files exist.

---

## 6. Packet capture troubleshooting

Start a capture while the attack is running:

```powershell
.\nisec.ps1 capture
```

Or from the monitored VM:

```bash
sudo bash /vagrant/capture/capture.sh 60
```

Useful filters:

| Purpose | Wireshark filter |
|---|---|
| SYN scan | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| SYN/ACK responses | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| ICMP echo | `icmp.type == 8` |
| SSH | `tcp.port == 22` |
| Kali source | `ip.src == 192.168.56.10` |
| HTTP | `http.request` |

---

## 7. AI correlation troubleshooting

Safe default:

```powershell
.\nisec.ps1 correlate
```

This uses mock mode and makes no external API call.

For offline input:

```powershell
python scripts/correlate.py --mock --from-file evidence/sample-alerts.json
```

For a zero-network preview:

```powershell
python scripts/correlate.py --dry-run --from-file evidence/sample-alerts.json
```

Real Gemini mode is explicit:

```powershell
$env:GEMINI_API_KEY = "..."
$env:AI_CORRELATION_MODE = "gemini"
.\nisec.ps1 correlate
```

Important controls:

- deterministic grouping occurs before AI;
- isolated single alerts are skipped;
- cached candidate groups do not require another call;
- `--dry-run` makes no API call;
- `GEMINI_MAX_REQUESTS_PER_RUN` is enforced.

See [`ai-correlation.md`](ai-correlation.md).

---

## 8. HTML report troubleshooting

Run the deterministic test suite first:

```powershell
.\nisec.ps1 report-test
```

Generate without AI:

```powershell
.\nisec.ps1 report
```

Inspect the result under:

```text
evidence/report_*.html
```

If Gemini is unavailable, the deterministic tables/charts should still render. AI-generated
narrative may fall back to clearly labelled text.

---

## 9. Active response

Active response is opt-in:

```powershell
.\nisec.ps1 active-response
```

Enable it only after detection evidence has been captured.

Why: it changes the lab from **detect-only** to **detect + automatic block**, which can alter
subsequent measurement results and may block the attacker VM.

If evaluating active response experimentally, record:

1. attack start time;
2. detection time;
3. block time;
4. whether subsequent packets were dropped;
5. whether the allowlist/whitelist behaved as intended.

---

## 10. Docker troubleshooting

From `deploy-docker/`:

```bash
./up.sh
docker compose ps
docker compose logs wazuh.indexer
docker compose logs wazuh.manager
docker compose logs wazuh.dashboard
```

Common causes:

| Symptom | Likely cause |
|---|---|
| Indexer exits immediately | insufficient `vm.max_map_count` or memory |
| Certificate error | generated certificates/configuration missing |
| Authentication error | indexer password/hash mismatch |
| Port 443 conflict | another service owns the host port |
| Dashboard unavailable | indexer/manager not healthy yet |

See [`deploy-docker/README.md`](../deploy-docker/README.md).

---

## 11. Healthcheck interpretation

Expected healthy state:

- Wazuh server reachable;
- Manager, Indexer, Dashboard active;
- monitored Agent active;
- client Agent active in full mode;
- Suricata active;
- `eve.json` exists/has data;
- custom SIDs loaded;
- Kali attack tooling available.

Expected exceptions:

- `client` is absent in `up-budget` mode;
- DVWA is absent unless the bonus target was started.

A healthcheck failure should be investigated before interpreting detection measurements.

---

## 12. Evidence integrity

Before final submission:

```powershell
.\nisec.ps1 seal
```

Preserve:

- screenshots,
- logs,
- packet captures,
- measurement reports,
- threat-hunt reports,
- correlation reports,
- HTML reports.

The SHA-256 manifest demonstrates whether the recorded files changed after sealing. It does
not establish an independent chain of custody when the manifest is stored beside the files.

---

## 13. Destructive operations

Before:

```powershell
.\nisec.ps1 destroy
```

copy the `evidence/` directory somewhere safe.

The VMs are reproducible. Your captured evidence is not.
