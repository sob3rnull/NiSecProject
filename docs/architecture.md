# Architecture

The one-line story of the whole system:

> **Suricata detects it on the network → writes an alert to `eve.json` → the Wazuh agent on that
> machine reads the file → the Wazuh server analyses it and shows it on the dashboard, right next
> to the host-based alerts.**

## Zone model (proposal §3.3)

The proposal defines four security zones. Here is how they map onto the lab:

```
  +==================== Private Lab Network 192.168.56.0/24 ====================+
  |                                                                             |
  |  +--- ATTACK/TEST ZONE ---+          +------- MONITORING ZONE -------+       |
  |  |  KALI          .10     |  attack  |  MONITORED         .20        |       |
  |  |  nmap, hydra           |=========>|  Suricata IDS -> eve.json     |       |
  |  |  hping3, nikto         |          |  Wazuh Agent + FIM            |       |
  |  |  wireshark             |          |  tshark capture               |       |
  |  +------------------------+          |  [bonus] DVWA (Docker :80)    |       |
  |                                      +---------------+---------------+       |
  |                                                      | agent traffic         |
  |  +--- CLIENT ZONE --------+                          | 1514/1515 tcp         |
  |  |  CLIENT        .30     |  agent traffic           v                       |
  |  |  Wazuh Agent + FIM     |============> +---- MANAGEMENT ZONE -----------+   |
  |  +------------------------+              |  WAZUH SERVER        .40      |   |
  |                                          |  Manager  (rules+decoders)    |   |
  |                              you browse  |  Indexer  (storage+search)    |   |
  |                              https ----> |  Dashboard (:443)             |   |
  |                                          +-------------------------------+   |
  +=============================================================================+
```

| Zone | VM | IP | Purpose | Enforcement |
|---|---|---|---|---|
| Management | `wazuh-server` | `.40` | Wazuh server + dashboard access | ufw: 443/55000 limited; 9200 denied |
| Monitoring | `monitored` | `.20` | Suricata IDS watching traffic | agent → manager only |
| Client | `client` | `.30` | Machines sending logs to Wazuh | 1514/1515 outbound only |
| Attack/Test | `kali` | `.10` | Pen-testing / attack simulation | host-only; no route off-lab |

> **Documented limitation.** All four zones share one `/24` subnet, so separation is enforced by
> **host firewall rules** (`scripts/harden-dashboard.sh`), not routed subnets or VLANs. On a
> single-laptop lab this is a standard simplification. Production would place each zone on its own
> VLAN with an enforcing firewall between them. Say this out loud in the viva before you're asked.

## Components

| Component | Where | Job |
|---|---|---|
| Wazuh Manager | wazuh-server | Decodes + rule-matches incoming data, raises alerts |
| Wazuh Indexer | wazuh-server | Stores + searches alerts (OpenSearch) |
| Wazuh Dashboard | wazuh-server | Web UI for viewing alerts |
| Wazuh Agent | monitored, client | Collects host logs, FIM, rootcheck; forwards encrypted |
| Suricata | monitored | Network IDS; matches packets to signatures → `eve.json` |
| tshark/Wireshark | monitored, kali | Packet-level evidence + detection debugging |
| Docker | wazuh-server, monitored | Containerised Wazuh stack (alt) and DVWA (bonus) |
| Attack tools | kali | nmap, hydra, hping3, nikto |

> Your proposal names only the "Wazuh Manager". In the report, name **all three** server
> components — Manager, Indexer, Dashboard. It's a small correction that reads as competence.

## The integration (core deliverable)

Suricata and Wazuh are joined by **one file**: `/var/log/suricata/eve.json`.

1. Suricata writes JSON alerts to `eve.json`.
2. The agent's `ossec.conf` has a `<localfile>` block (`config/wazuh-agent/ossec.conf.snippet`)
   tailing that file as `json`.
3. The agent ships each line to the Manager.
4. The Manager's built-in JSON decoder parses the fields; our custom rules
   (`config/wazuh-manager/local_rules.xml`, IDs 100100+) grade them by severity and category.

## Alert lifecycle (the seven steps)

1. **Attack launched** from Kali.
2. **Recorded** — the OS writes to `/var/log/auth.log`; Suricata writes to `eve.json`.
3. **Collected** — the Wazuh agent tails both and forwards them encrypted.
4. **Analysed** — the Manager decodes and rule-matches, assigning a severity.
5. **Stored** — written to the Indexer for searching.
6. **Displayed** — visible on the dashboard within seconds.
7. **Responded** *(optional)* — active response blocks the attacking IP.

## Detection matrix

| Threat (from proposal) | Caught by | Rule / signature | Test script |
|---|---|---|---|
| Port scanning | Suricata | ET recon + SID 9000002 | `01_nmap_scan.sh` |
| Brute-force login | Wazuh host rules | built-in 5710/5712 family | `02_ssh_bruteforce.sh` |
| DoS attack | Suricata threshold | SID 9000001 | `03_ping_flood.sh` |
| Malware / ransomware | Wazuh FIM + rootcheck | 100200, 100201, 100202 | `05_malware_fim_test.sh` |
| Unauthorized access | Access control + auth rules | ufw + built-in auth rules | `06_unauthorized_access_test.sh` |
| Misconfiguration | Wazuh SCA (built-in) | CIS benchmark module | Dashboard → SCA |
| _Bonus:_ web attack | Suricata | ET web sigs → rule 100110 | `04_web_attack.sh` |

The viva point: **network** threats are caught by **Suricata**, **host** threats by **Wazuh's own
rules and FIM** — and both land in one dashboard. That contrast is the entire argument for the
two-tool design.

## Ports

- `1514/tcp` — agent → manager data
- `1515/tcp` — agent enrolment
- `443/tcp` — dashboard
- `55000/tcp` — Wazuh API
- `9200/tcp` — indexer (localhost only; externally denied by design)
