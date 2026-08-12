# Proposal → Implementation Traceability

Every commitment in the submitted proposal (*NISec Project Proposal Outline — Zwe Nyi Nyar,
TNT-2061*) mapped to the artefact that delivers it. Bring this to the viva: when a marker asks
"you said you'd do X — where is it?", this table is the answer.

Status: **DONE** = scaffolded and ready to run · **RUN** = you must execute and capture evidence

## Objectives

| # | Proposal objective | Where it lives | Status |
|---|---|---|---|
| 1 | Design a centralized security monitoring system | `docs/architecture.md`, `Vagrantfile` | DONE |
| 2 | Set up Wazuh for log collection and monitoring | `provision/wazuh-server.sh`, `deploy-docker/` | DONE |
| 3 | Configure Suricata to detect suspicious traffic | `provision/monitored-server.sh`, `config/suricata/` | DONE |
| 4 | Connect Wazuh and Suricata together | `config/wazuh-agent/ossec.conf.snippet` + rules `100100-100120` | DONE |
| 5 | Test with simulated attacks | `attacks/01`–`attacks/06` | RUN |
| 6 | Analyze results, suggest improvements | `scripts/measure-detection.sh`, `attacks/07_evasion_test.sh`, `docs/risk-assessment.md`, `docs/report-skeleton.md` §7–8 | RUN |

> **Objective 6 is where marks are won or lost.** Objectives 1–5 are build work and this repo
> completes them. Objective 6 asks you to *analyse*, and analysis needs numbers: `make measure`
> produces the detection/latency/baseline table, `make evasion` produces the boundary where
> detection stops, and `docs/risk-assessment.md` turns asserted risk ratings into derived ones
> with a residual column. Run them and the analysis writes itself from real data.

## Functional requirements

| Proposal requirement | Implementation | Status |
|---|---|---|
| Collect logs from monitored devices | Wazuh agents on `monitored` + `client` | DONE |
| Detect suspicious network activity (Suricata) | Suricata IDS + ET Open + `config/suricata/local.rules` | DONE |
| Send security logs to Wazuh | `<localfile>` tailing `eve.json` → manager | DONE |
| Display logs/alerts on a central dashboard | Wazuh Dashboard, `https://192.168.56.40` | DONE |
| Generate alerts on attacks | Built-in rules + custom `local_rules.xml` | DONE |
| **Store logs for later review** | `scripts/configure-retention.sh` (ISM: 90-day lifecycle) | DONE |

## Non-functional requirements

| Proposal requirement | Implementation | Status |
|---|---|---|
| Run 24/7 without crashing | `systemd` units w/ `restart: always`; `scripts/healthcheck.sh` | DONE |
| Alerts appear as quickly as possible | Suricata realtime + FIM `realtime="yes"`; **measured** by `make measure` (single-clock method, 1 s resolution) | RUN |
| Dashboard easy to understand | Severity-graded rules so high-severity stands out | DONE |
| **Monitor more than one device at once** | Two agents (`monitored`, `client`) — keep both if RAM allows | DONE |
| **Only authorized users access the dashboard** | `scripts/harden-dashboard.sh` (ufw, roles, timeout, no defaults) | DONE |

## Tools declared in the proposal

| Tool | Used for | Where | Status |
|---|---|---|---|
| Wazuh | SIEM: collection, analysis, alerting, dashboard | `provision/wazuh-server.sh` | DONE |
| Suricata | Network IDS | `provision/monitored-server.sh` | DONE |
| Docker | Containerised deployment | `deploy-docker/` (Wazuh stack), `dvwa/` | DONE |
| Ubuntu Linux | Server + client OS | `Vagrantfile` (3 VMs) | DONE |
| Kali Linux | Attack simulation | `Vagrantfile`, `provision/kali.sh` | DONE |
| **Wireshark** | Packet-level evidence + detection debugging | `capture/` (tshark + filters) | DONE |
| Nmap | Port scanning / recon | `attacks/01_nmap_scan.sh` | DONE |
| VirtualBox | Hypervisor | `Vagrantfile` provider | DONE |

> Every declared tool now has a real, defensible role. Wireshark was the one gap — it's now the
> corroboration and debugging layer (see `capture/README.md`).

## Threats → detection coverage

Your proposal's threat list, and what actually catches each one:

| Proposal threat | Risk level | Detected by | Test | Status |
|---|---|---|---|---|
| Port scanning | Medium | Suricata (ET + SID 9000002) | `attacks/01_nmap_scan.sh` | RUN |
| Brute-force login | **High** | Wazuh host rules (`auth.log`) | `attacks/02_ssh_bruteforce.sh` | RUN |
| **Malware / ransomware** | **High** | Wazuh FIM + rootcheck (rules 100200-100202) | `attacks/05_malware_fim_test.sh` | RUN |
| **Unauthorized access** | High | Access control + auth failure rules | `attacks/06_unauthorized_access_test.sh` | RUN |
| DoS attack | Medium | Suricata threshold (SID 9000001) | `attacks/03_ping_flood.sh` | RUN |
| Suspicious network traffic | Medium | Suricata ET Open ruleset | all network attacks | RUN |
| Misconfiguration | Medium | Wazuh SCA (built-in CIS benchmark) | Dashboard → Security Configuration Assessment | RUN |

> **Misconfiguration** needs no extra code — Wazuh's built-in SCA module already audits each
> agent against CIS benchmarks. Just open the SCA dashboard and screenshot the score. Free marks.

## Security zones (proposal §3)

| Proposal zone | VM | IP | Enforcement |
|---|---|---|---|
| Management Zone | `wazuh-server` | `.40` | ufw: 443/55000 restricted; 9200 denied externally |
| Monitoring Zone | `monitored` | `.20` | Suricata sniffing; agent → manager only |
| Client Zone | `client` | `.30` | agent → manager on 1514/1515 only |
| Attack/Test Zone | `kali` | `.10` | isolated host-only net; no route off-lab |

**Honest limitation to state in your report:** all four zones share one `192.168.56.0/24`
subnet, so separation is enforced by *host firewall rules*, not by routed subnets or VLANs.
On a single laptop this is a standard, defensible simplification — say so explicitly and note
that production would use separate VLANs with an enforcing firewall between them. Naming the
limitation yourself scores better than hoping nobody notices.

## Beyond the proposal (bonus)

Clearly-labelled extras. Present as "additional work", never as core scope:

| Extra | Where | Why it's worth keeping |
|---|---|---|
| DVWA + web attacks (SQLi/Nikto) | `dvwa/`, `attacks/04_web_attack.sh` | Application-layer detection; shows depth |
| Containerised Wazuh stack | `deploy-docker/` | Two deployment models to compare |
| Custom Suricata threshold rules | `config/suricata/local.rules` | Demonstrates real rule-writing skill |
| Packet capture + analysis | `capture/` | Corroborates alerts with raw evidence |
| **Detection measurement harness** | `scripts/measure-detection.sh` | Turns the lab from apparatus into an experiment: detection rate, rule fired, time-to-alert, idle baseline — with a stated method |
| **Offline rule regression tests** | `tests/` | Proves the signatures match their traffic independently of the live pipeline. Dependency-free pcap generator; no lab traffic needed |
| **Evasion / boundary testing** | `attacks/07_evasion_test.sh` | Maps where detection stops. Reproduces Ptacek & Newsham (1998) in your own lab |
| **Derived risk assessment** | `docs/risk-assessment.md` | NIST SP 800-30 method: L × I scoring plus a residual-risk column quantifying what the system bought |
| **ATT&CK + NIST CSF mapping** | `docs/attack-mapping.md` | Coverage claims made checkable against a public framework, with the mapping's own limits stated |
| **Active response** | `config/wazuh-manager/active-response.xml.snippet` | Implements step 7 of the alert lifecycle that `architecture.md` describes. Opt-in, with a white list that cannot lock you out |
| **Evidence integrity manifest** | `scripts/seal-evidence.sh` | SHA-256 over `evidence/`, with an honest note on what a co-located manifest does and does not prove |
