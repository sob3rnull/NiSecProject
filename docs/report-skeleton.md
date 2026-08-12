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
- **3.7 Risk assessment** — use **[`risk-assessment.md`](risk-assessment.md)**: Likelihood ×
  Impact scales, derived scores, and a **residual risk** table showing what this system actually
  bought. Include the "where this disagrees with the proposal" table — revising an earlier
  judgement with stated reasoning reads as analysis; silently replacing it reads as an error.
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

- **6.8 Detection summary table** — run **`make measure`**; it writes this table into
  `evidence/detection-results_*.md` with rule fired and time-to-alert per test, plus the method
  note explaining why the numbers are trustworthy (single clock, no stale credit, 1 s resolution).
  This is what evidences the "alerts as quickly as possible" NFR. _Keep any NOT DETECTED rows._
- **6.9 Packet-level corroboration** — _Wireshark screenshots backing 1–3._
- **6.10 Rule verification** — **`make test`** replays a synthetic pcap through Suricata offline
  and asserts each custom SID fires. Cite it as evidence the signatures were validated
  independently of the live pipeline, not just observed working once.
- **6.11 Detection boundary** — **`make evasion`**. Report the technique → detected? → why table.
  The slow-brute-force result (network signature evaded, host rule still catches it) is the
  strongest single finding available here; give it its own paragraph.

## 7. Analysis and Discussion
- **7.1 What worked** — _which detections were clean out of the box._
- **7.2 What needed tuning** — _the ping flood almost certainly needed the custom threshold rule.
  Explain WHY the default ruleset missed it — this is your best "real understanding" moment._
- **7.3 False positives** — `make measure` records an **idle baseline** (alerts/hour with no
  attack running). Report attack alert counts against that floor, and cite Axelsson's base-rate
  fallacy [16 in `references.md`] to explain why a high-accuracy detector still floods an analyst
  at realistic traffic volumes. A measurement plus the theory behind it beats either alone.
- **7.4 Limitations** — driven by your `make evasion` results, not by guesswork: rate-based
  thresholds are evadable by slowing down, `track by_src` is defeated by decoys, and encrypted
  traffic is a structural blind spot for a passive IDS. Cite Ptacek & Newsham [15] — your results
  are a lab reproduction of a 1998 paper, which reframes the section from "what failed" to
  "what I replicated". Then the standing ones: single subnet, IDS not IPS, lab scale.
  The **residual risk** table in `risk-assessment.md` §3 quantifies what remains.
- **7.5 Security recommendations** ⭐ — _proposal objective 6 explicitly promises this. Give
  concrete recommendations: enforce key-based SSH, patch cadence, close unused ports, MFA on the
  dashboard, network segmentation. Tie each back to a vulnerability you listed in §3.6._

## 8. Conclusion and Future Work
- _Restate the outcome against each objective (use the traceability table)._
- **Coverage** — use [`attack-mapping.md`](attack-mapping.md): nine ATT&CK techniques across six
  tactics, with the uncovered tactics named explicitly and the mapping's own limits stated.
- Future work: IPS mode, email/Telegram alerting, Windows endpoint, anomaly-based detection, and
  **quantifying active response** — enable `make active-response`, re-run `make measure`, and
  report the change in time-to-block. `risk-assessment.md` §3 explains why that number is the
  ceiling on every residual risk reduction in the project.

## References
Use [`references.md`](references.md) — IEEE-formatted, with a table of which reference does real
work where. The three that carry the most weight: **NIST SP 800-94** for IDS framing,
**Ptacek & Newsham** for your evasion results, and **Axelsson** for your false-positive baseline.

## Appendices
- **A** — Configuration files (`config/`)
- **B** — Command logs (`evidence/logs/`)
- **C** — Traceability matrix (`docs/proposal-traceability.md`)
- **D** — Glossary
