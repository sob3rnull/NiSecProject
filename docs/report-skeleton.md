# Report Skeleton

Structured to match **your submitted proposal**, so the final report reads as the delivery of
exactly what you promised. Replace _italics_ with your own text and screenshots.
Evidence: `../evidence/screenshots/`, logs: `../evidence/logs/`, captures: `../evidence/pcaps/`.

Cross-reference `proposal-traceability.md` while writing — it maps every promise to its artefact.

---

## 1. Introduction
- **1.1 Project background** — _reuse your proposal's background paragraph; expand with a current
  statistic on attack volume or dwell time (cite it)._
- **1.2 Problem statement** — firewalls alone don't detect what's already inside; logs are
  scattered across machines with nobody reading them.
- **1.3 Objectives** — _the six objectives, verbatim from the proposal._
- **1.4 Scope** — _the eight scope items. State explicitly what is OUT of scope (production
  scale, IPS blocking, cloud sources)._

## 2. Literature / Background
- SIEM, IDS/IPS, host-based vs network-based, defence in depth.
- Why Wazuh over commercial SIEMs (cost, openness, built-in ruleset).
- Why Suricata alongside Wazuh (packet inspection is the gap Wazuh alone leaves).
- _Optional: one paragraph on OSSEC → Wazuh lineage; shows reading._

## 3. Requirement Analysis
Mirror your proposal's numbered subsections exactly:

- **3.1 Functional requirements** — _the six items._
- **3.2 Non-functional requirements** — _the five items._
- **3.3 System requirements** — hardware + software tables. _State your ACTUAL host specs._
- **3.4 Assets to protect** — network traffic, system logs, user accounts, server configs,
  security alerts/reports.
- **3.5 Possible threats** — the six threats.
- **3.6 Vulnerabilities** — the five weaknesses.
- **3.7 Risk assessment** — _your Threat/Risk Level/Reason table. Consider adding Likelihood and
  Impact columns so the rating is derived rather than asserted — markers like visible reasoning._
- **3.8 Expected solution** — _your paragraph; now point at the traceability table as proof._

## 4. Security Design Architecture
- **4.1 System overview** — _one paragraph + the architecture diagram (`architecture.md`)._
- **4.2 Main components** — Wazuh Manager, Suricata IDS, Ubuntu Server, Kali Linux
  (_plus Indexer and Dashboard — name all three Wazuh components, your proposal only named the
  Manager, and markers notice_).
- **4.3 Security zones** — _the four-zone table + which VM sits in each zone. **State the honest
  limitation**: one subnet, separation enforced by host firewall, production would use VLANs._
- **4.4 Data flow** — _the five steps from your proposal, expanded into the full seven-step
  alert lifecycle in `architecture.md`._
- **4.5 Security controls** — intrusion detection, log collection, centralized monitoring,
  access control, alerting. _Point each at its implementing artefact._
- **4.6 Expected architecture outcome** — _your paragraph._

## 5. Implementation
- **5.1 Environment setup** — VirtualBox + Vagrant, VM specs, network config.
  _Screenshot: `vagrant status` / VirtualBox showing four VMs._
- **5.2 Wazuh deployment** — _screenshot: dashboard login + agent list._
  _Mention BOTH deployment paths (installer and Docker) and justify which you ran._
- **5.3 Agent enrolment** — _screenshot: two agents showing Active — this evidences the
  "monitor more than one device" requirement._
- **5.4 Suricata configuration** — interface, HOME_NET, ruleset update.
  _Screenshot: `eve.json` filling._
- **5.5 Wazuh–Suricata integration** ⭐ — the `<localfile>` block + custom rules.
  _Screenshot: a Suricata alert displayed inside the Wazuh dashboard._
  **This is your core deliverable — give it the most space.**
- **5.6 Access control** — firewall rules, roles, password change. _Screenshot: `ufw status`._
- **5.7 Log retention** — the ISM policy and your measured daily log volume.

## 6. Testing and Results
One subsection per attack: objective → command → expected → observed → evidence.

| # | Test | Tool | Detected by | Evidence |
|---|---|---|---|---|
| 1 | Port scan | Nmap | Suricata | _screenshot + pcap_ |
| 2 | SSH brute-force | Hydra | Wazuh host rules | _screenshot + log_ |
| 3 | Ping flood (DoS) | hping3 | Suricata threshold | _screenshot + pcap_ |
| 4 | Malware / ransomware | EICAR + FIM | Wazuh FIM/rootcheck | _screenshot_ |
| 5 | Unauthorized access | curl/API | Access control | _screenshot_ |
| 6 | Misconfiguration | Wazuh SCA | SCA module | _screenshot of CIS score_ |
| 7 | _Bonus:_ web attack | Nikto/SQLi | Suricata | _screenshot_ |

- **6.8 Detection summary table** — attack vs detected (Y/N) vs time-to-alert.
  _A measured latency column directly evidences your "alerts as quickly as possible" NFR._
- **6.9 Packet-level corroboration** — _Wireshark screenshots backing 1–3._

## 7. Analysis and Discussion
- **7.1 What worked** — _which detections were clean out of the box._
- **7.2 What needed tuning** — _the ping flood almost certainly needed the custom threshold rule.
  Explain WHY the default ruleset missed it — this is your best "real understanding" moment._
- **7.3 False positives** — _how many, what caused them, what you tuned._
- **7.4 Limitations** — signature-based (zero-days evade), single subnet, IDS not IPS,
  lab scale, encrypted traffic blind spot.
- **7.5 Security recommendations** ⭐ — _proposal objective 6 explicitly promises this. Give
  concrete recommendations: enforce key-based SSH, patch cadence, close unused ports, MFA on the
  dashboard, network segmentation. Tie each back to a vulnerability you listed in §3.6._

## 8. Conclusion and Future Work
- _Restate the outcome against each objective (use the traceability table)._
- Future work: IPS mode, active response, email/Telegram alerting, Windows endpoint,
  MITRE ATT&CK mapping, anomaly-based detection.

## References
_IEEE or your department's style. Cite: Wazuh docs, Suricata docs, ET Open ruleset,
OWASP for the web attacks, MITRE ATT&CK, NIST SP 800-94 (IDS/IPS guide) — the NIST citation
is an easy credibility win._

## Appendices
- **A** — Configuration files (`config/`)
- **B** — Command logs (`evidence/logs/`)
- **C** — Traceability matrix (`docs/proposal-traceability.md`)
- **D** — Glossary
