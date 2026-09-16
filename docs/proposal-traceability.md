# Proposal → Implementation Traceability

This matrix maps the submitted NISec proposal to the implementation currently present in the
repository. Use it during the viva and while writing the final report.

**Status meanings**

- **DONE** — implementation exists in the repository.
- **RUN** — the implementation exists, but final evidence must still be collected for the
  submitted experiment.
- **OPTIONAL** — additional work beyond the original core scope.

---

## 1. Objectives

| # | Proposal objective | Implementation | Status |
|---|---|---|---|
| 1 | Design a centralized security monitoring system | `Vagrantfile`, `docs/architecture.md` | DONE |
| 2 | Set up Wazuh for centralized monitoring | `provision/wazuh-server.sh`, `deploy-docker/` | DONE |
| 3 | Configure Suricata for suspicious network traffic | `provision/monitored-server.sh`, `config/suricata/` | DONE |
| 4 | Integrate Wazuh and Suricata | `config/wazuh-agent/ossec.conf.snippet`, `config/wazuh-manager/local_rules.xml` | DONE |
| 5 | Test the system using simulated attacks | `attacks/01`–`06` | RUN |
| 6 | Analyse results and recommend improvements | `measure`, `hunt`, `evasion`, `compare`, `score`, risk/report docs | RUN |

---

## 2. Functional requirements

| Requirement | Implementation | Status |
|---|---|---|
| Collect logs from monitored devices | Wazuh Agents on `monitored` and `client` | DONE |
| Detect suspicious network activity | Suricata + ET Open + local rules | DONE |
| Send Suricata events to Wazuh | `eve.json` `<localfile>` integration | DONE |
| Display alerts centrally | Wazuh Dashboard | DONE |
| Generate alerts for attack tests | built-in + custom Wazuh rules | DONE |
| Retain logs for later review | `scripts/configure-retention.sh` | DONE |

---

## 3. Non-functional requirements

| Requirement | Implementation | Status |
|---|---|---|
| Continuous service operation | systemd services + healthcheck | DONE |
| Alerts appear quickly | realtime collection + `measure` timing harness | RUN |
| Understandable dashboard | Wazuh severity/rule structure | DONE |
| Monitor multiple devices | `monitored` + `client` agents | DONE |
| Restrict dashboard access | `scripts/harden-dashboard.sh` + Wazuh authentication | DONE |

---

## 4. Proposal tools

| Tool | Role | Implementation | Status |
|---|---|---|---|
| Wazuh | SIEM/host monitoring/central alerting | Manager, Indexer, Dashboard, Agents | DONE |
| Suricata | Network IDS | `monitored` + local/ET rules | DONE |
| Docker | Container deployment | `deploy-docker/`, DVWA | OPTIONAL |
| Ubuntu | Server/endpoint OS | Vagrant boxes | DONE |
| Kali Linux | Attack simulation | `provision/kali.sh`, `attacks/` | DONE |
| Wireshark/tshark | packet evidence/debugging | `capture/` | DONE |
| Nmap | reconnaissance test | `attacks/01_nmap_scan.sh` | DONE |
| VirtualBox | VM hypervisor | Vagrant provider | DONE |

---

## 5. Threat coverage

| Threat / test | Detector | Primary artefact | Evidence status |
|---|---|---|---|
| Port scanning | Suricata | ET + SID `9000002` | RUN |
| SSH brute force | Wazuh auth rules | built-in rules | RUN |
| Ping flood / DoS | Suricata | SID `9000001` | RUN |
| Malware / ransomware-like file activity | Wazuh FIM | `100200–100202` | RUN |
| Unauthorized access | Wazuh/auth + host controls | `06_unauthorized_access_test.sh` | RUN |
| Misconfiguration | Wazuh SCA | Dashboard SCA/CIS view | RUN |
| Web attack | Suricata | ET web rules | OPTIONAL |
| Detection evasion | both sensors | `07_evasion_test.sh` | RUN |

---

## 6. Security-zone traceability

| Zone | VM | IP | Implementation |
|---|---|---|---|
| Management | `wazuh-server` | `.40` | Wazuh stack + hardening |
| Monitoring | `monitored` | `.20` | Suricata + Agent |
| Client | `client` | `.30` | Agent + FIM |
| Attack/Test | `kali` | `.10` | attack suite |

**Architectural limitation:** the four zones share one host-only `/24`. The project therefore
does not claim production-grade VLAN segmentation. See `docs/architecture.md`.

---

## 7. Evidence and evaluation

| Evaluation goal | Tool / document | Output |
|---|---|---|
| Signature correctness | `make test` | offline regression result |
| Detection rate / latency | `make measure` | `detection-results_*.md` |
| Packet corroboration | `make capture` | `.pcap` |
| Detection boundary | `make evasion` | evasion results |
| Threat hunt | `make hunt` | `threat-hunt_*.md` |
| Run-to-run comparison | `make compare` | `latency-drift_*.md` |
| Rule reliability | `make score` | `confidence-scores_*.md` |
| Evidence integrity | `make seal` | SHA-256 manifest |

---

## 8. Additional implementation beyond the core proposal

| Feature | Location | Purpose | Status |
|---|---|---|---|
| Custom Suricata threshold signatures | `config/suricata/local.rules` | demonstrates rule authoring | OPTIONAL |
| Offline pcap regression tests | `tests/` | separates signature correctness from live pipeline | OPTIONAL |
| Evasion/boundary testing | `attacks/07_evasion_test.sh` | measures detection limits | OPTIONAL |
| Packet capture workflow | `capture/` | raw evidence and debugging | OPTIONAL |
| Derived risk assessment | `docs/risk-assessment.md` | likelihood × impact + residual risk | OPTIONAL |
| ATT&CK/NIST mapping | `docs/attack-mapping.md` | framework-based coverage description | OPTIONAL |
| Active response | `config/wazuh-manager/active-response.xml.snippet` | opt-in detect-to-block loop | OPTIONAL |
| Evidence sealing | `scripts/seal-evidence.sh` | SHA-256 integrity manifest | OPTIONAL |
| AI attack-chain correlation | `scripts/nisec_correlate/` | semantic interpretation of existing alerts | OPTIONAL |
| AI-narrated HTML report | `scripts/nisec_report/` | single browser-readable evidence report | OPTIONAL |
| Docker deployment | `deploy-docker/` | alternate reproducible Wazuh deployment | OPTIONAL |
| DVWA web target | `dvwa/` | application-layer bonus test | OPTIONAL |

---

## 9. Important scope distinction

The following are **not** the same thing:

- Suricata/Wazuh detection;
- Wazuh storage and dashboard presentation;
- deterministic evidence analysis;
- optional Gemini-assisted interpretation;
- active response.

Keeping these layers separate makes the architecture easier to explain and prevents the AI
features from being described as an autonomous SOC or as the underlying detection engine.
