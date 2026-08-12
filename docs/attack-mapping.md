# Detection coverage — MITRE ATT&CK and NIST CSF mapping

The project's own `report-skeleton.md` listed ATT&CK mapping under *future work*.
It belongs in the report instead: mapping detections to a public framework is how
coverage claims are made checkable by someone who did not build the system.

Two frameworks, doing two different jobs:

- **MITRE ATT&CK** — *what adversary behaviour do we detect?* Technique-level.
- **NIST CSF** — *what kind of control is each part?* Function-level.

---

## 1. ATT&CK coverage of the implemented tests

| Test | Tactic | Technique | Detected by | Rule |
|---|---|---|---|---|
| `01_nmap_scan.sh` | Discovery (TA0007) | **T1046** Network Service Discovery | Suricata | SID 9000002, ET recon |
| `01_nmap_scan.sh` | Reconnaissance (TA0043) | **T1595.001** Active Scanning: Scanning IP Blocks | Suricata | SID 9000002 |
| `02_ssh_bruteforce.sh` | Credential Access (TA0006) | **T1110.001** Brute Force: Password Guessing | Wazuh host rules | 5710, 5712 |
| `03_ping_flood.sh` | Impact (TA0040) | **T1498.001** Network DoS: Direct Network Flood | Suricata | SID 9000001 |
| `05_malware_fim_test.sh` (EICAR) | Command and Control (TA0011) | **T1105** Ingress Tool Transfer | Wazuh FIM | 100200 |
| `05_malware_fim_test.sh` (mass modify) | Impact (TA0040) | **T1486** Data Encrypted for Impact | Wazuh FIM | 100202 |
| `05_malware_fim_test.sh` (binary tamper) | Persistence (TA0003) | **T1554** Compromise Host Software Binary | Wazuh FIM | 100201 |
| `06_unauthorized_access_test.sh` | Initial Access (TA0001) | **T1078.001** Valid Accounts: Default Accounts | Access control | ufw + auth rules |
| `04_web_attack.sh` *(bonus)* | Initial Access (TA0001) | **T1190** Exploit Public-Facing Application | Suricata | ET web sigs → 100110 |
| `07_evasion_test.sh` (5b) | Command and Control (TA0011) | **T1573** Encrypted Channel | **Not detected — by design** | — |

### Reading this table honestly

Coverage is **nine techniques across six tactics**. That is respectable for a
lab, and it is also narrow — state both. The tactics with no coverage at all are
worth naming out loud in the viva before a marker names them for you:

- **Lateral Movement (TA0008)** — nothing here moves between hosts.
- **Exfiltration (TA0010)** — no data-volume or destination baselining.
- **Defense Evasion (TA0005)** — see the limitation below.
- **Privilege Escalation (TA0004)** — rootcheck touches this, untested.

---

## 2. Where this mapping breaks down

A mapping is only useful if you can say where it stops fitting. Two honest problems:

**ATT&CK under-represents packet-level IDS evasion.** `07_evasion_test.sh`
tests slow scanning, decoy source addresses, and IP fragmentation. Enterprise
ATT&CK has no clean technique for any of them — it is a host- and
behaviour-centric model, and these are properties of *how packets are shaped on
the wire*. Forcing them into T1027 (Obfuscated Files or Information) or T1036
(Masquerading) would be mapping-by-vibes. The correct answer is that this class
of evasion sits outside the model, which is itself a finding about the model.
Only the encrypted-channel test (T1573) maps cleanly.

**One technique detected is not one technique covered.** T1110.001 is detected
here only for *SSH password guessing against one host with default sshd
logging*. The same technique against RDP, a web login form, or a Kerberos
service would be invisible to this build. Claiming "we detect T1110" without
that qualifier overstates the result. Say "we detect T1110.001 in the SSH
case", and the claim survives questioning.

---

## 3. NIST CSF function mapping

ATT&CK says what is detected. CSF says what kind of thing each control is —
which exposes the shape of the project immediately.

| CSF function | Implemented here | Artefact |
|---|---|---|
| **Identify** (ID.AM, ID.RA) | Asset and threat inventory, derived risk scoring | `docs/risk-assessment.md` |
| **Protect** (PR.AC, PR.DS) | Host firewall, no default credentials, session timeout, least-privilege analyst role | `scripts/harden-dashboard.sh` |
| **Detect** (DE.AE, DE.CM) | Suricata NIDS, Wazuh host rules, FIM, rootcheck, SCA | `config/`, `attacks/` |
| **Respond** (RS.AN, RS.MI) | **Weak** — analysis is manual; active response is provided but opt-in | `config/wazuh-manager/active-response.xml` |
| **Recover** (RC.RP) | **Absent** — out of scope, and say so rather than implying otherwise | — |

**The shape this reveals:** the project is overwhelmingly a **Detect** system,
with meaningful **Protect** work and deliberately thin **Respond**/**Recover**.
That is a perfectly defensible scope for one semester. What is *not* defensible
is implying full lifecycle coverage. Use this table to state the scope boundary
in report §1.4 and again in §7.4 — declaring a limitation yourself consistently
scores better than having it found.

---

## 4. Using this in the viva

If asked *"how do you know your coverage is real?"*:

> "Each detection maps to a specific ATT&CK technique, and each mapping is
> backed by a test script that triggers it and a rule that fires. Where I could
> not map cleanly — packet-level evasion — I said so rather than forcing it.
> By CSF function the system is a Detect capability with supporting Protect
> controls; Respond is opt-in and Recover is out of scope."

That answer states coverage, evidence, limits, and scope in four sentences.
