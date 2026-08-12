# NISec — Centralized Security Monitoring System (Wazuh + Suricata)

**Zwe Nyi Nyar — TNT-2061**
CST-8415 Network & Internet Security · Faculty of Computer Systems and Technologies
University of Information Technology

Implementation of the submitted proposal: *Design and Implementation of a Centralized Security
Monitoring System Using Wazuh and Suricata.*

Suricata watches the network, Wazuh agents watch each machine, and both report to one Wazuh server
you view from a single dashboard.

---

## 📖 Start here

| I want to… | Read |
|---|---|
| **Build the lab from scratch** | **[`docs/step-by-step-guide.md`](docs/step-by-step-guide.md)** ← start here |
| Fix something / look up a command | [`docs/runbook.md`](docs/runbook.md) |
| Understand the design | [`docs/architecture.md`](docs/architecture.md) |
| Prove I delivered what I promised | [`docs/proposal-traceability.md`](docs/proposal-traceability.md) |
| Write the report | [`docs/report-skeleton.md`](docs/report-skeleton.md) |
| Justify my risk ratings | [`docs/risk-assessment.md`](docs/risk-assessment.md) |
| Show coverage against a framework | [`docs/attack-mapping.md`](docs/attack-mapping.md) |
| Cite something | [`docs/references.md`](docs/references.md) |

**Quickest path:** `make up` → wait → `make healthcheck` → `make test` → `make measure`.

---

## Lab topology — the four security zones

| Zone (proposal §3.3) | VM | IP | Role |
|---|---|---|---|
| **Management** | `wazuh-server` | `192.168.56.40` | Manager + Indexer + Dashboard |
| **Monitoring** | `monitored` | `192.168.56.20` | Suricata IDS + agent + FIM + tshark |
| **Client** | `client` | `192.168.56.30` | Ordinary monitored endpoint (agent + FIM) |
| **Attack/Test** | `kali` | `192.168.56.10` | nmap, hydra, hping3, nikto, wireshark |

All four sit on one private host-only network — attacks never leave the lab.

---

## Quick start

Requires **VirtualBox** + **Vagrant** on your host.

```bash
make up                  # build the lab (4 VMs; ~30-60 min on first run)
make up-budget           # 3 VMs instead, for 8 GB hosts
make healthcheck         # verify every service across the lab
```

> **On Windows:** `make` is not installed by default, so none of the commands in this
> repo will run until you have it. Either install it —
> `choco install make` or `scoop install make`, then use Git Bash — or skip `make`
> entirely and run the underlying command, which is always in the Makefile:
>
> ```bash
> vagrant up                          # instead of: make up
> bash scripts/healthcheck.sh         # instead of: make healthcheck
> bash scripts/measure-detection.sh   # instead of: make measure
> ```
>
> Everything else assumes Git Bash rather than PowerShell — the scripts are POSIX shell.

Get your dashboard password (randomly generated at install):

```bash
vagrant ssh wazuh-server
sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep -A1 admin
```

Then browse **https://192.168.56.40** and accept the self-signed certificate.

```bash
make harden              # access control (proposal NFR)
make retention           # 90-day log lifecycle (proposal FR)
make attacks             # run the detection suite from Kali
make malware-test        # FIM / ransomware test (on the monitored server)
make capture             # 60s packet capture for Wireshark evidence
```

Run `make help` for every target.

---

## From apparatus to evidence

Building the lab is not the project — **producing defensible results is**. Four
targets take you from "it runs" to "here are the numbers, and here is why you
can trust them":

```bash
make test        # 1. Do the rules match the traffic they claim to? (offline, no lab traffic needed)
make measure     # 2. Detection rate, which rule fired, time-to-alert -> evidence/*.md
make evasion     # 3. Where does detection STOP working? (misses are the result)
make seal        # 4. Hash the evidence so you can prove it didn't change
```

**`make test`** replays a synthetic pcap through Suricata offline and asserts each
custom SID fires. Run it first whenever a live attack produces no alert: if the
rules pass here, the fault is in the pipeline, not the signatures — that one
distinction saves hours of blind debugging.

**`make measure`** is the instrument this project needs to make a quantitative
claim. It reads every timestamp from the Wazuh manager's own clock, so VM skew
cannot contaminate the latency, records a `NOT DETECTED` row when nothing fires,
and measures an idle baseline so "we saw N alerts" can be read against the noise
floor. It writes a markdown table straight into `evidence/`.

**`make evasion`** is the one that separates a good project from a working one.
It deliberately stays under each threshold — slow scan, decoy sources,
fragmentation, throttled brute-force, encrypted payload. Most of it is *expected
not to alert*. The headline result: a slow SSH brute-force slips past the network
signature while Wazuh's host rules catch it anyway, because they count failed
logins rather than packets. That is the empirical argument for running Suricata
**and** Wazuh — have it ready before anyone asks why one sensor wasn't enough.

Optionally, `make active-response` closes the loop from detect to respond. It is
opt-in by design: it writes firewall DROP rules from log events, so enable it
deliberately and only after your detection evidence is captured.

---

## Test suite → proposal threats

Each test maps to a threat from your proposal's risk assessment:

| # | Test | Script | Threat covered | Run from |
|---|---|---|---|---|
| 1 | Port scan | `01_nmap_scan.sh` | Port scanning (Medium) | Kali |
| 2 | SSH brute-force | `02_ssh_bruteforce.sh` | Brute-force login (**High**) | Kali |
| 3 | Ping flood | `03_ping_flood.sh` | DoS attack (Medium) | Kali |
| 4 | Malware / ransomware | `05_malware_fim_test.sh` | Malware (**High**) | **monitored** |
| 5 | Unauthorized access | `06_unauthorized_access_test.sh` | Unauthorized access | Kali |
| 6 | Misconfiguration | *no script* — Dashboard → SCA | Misconfiguration (Medium) | Dashboard |
| 7 | Web attack | `04_web_attack.sh` | *BONUS — beyond submitted scope* | Kali |
| 8 | **Detection boundary** | `07_evasion_test.sh` | *Maps the limits of 1–3* | Kali |

Test 4 is safe: it uses the **EICAR test string** (the industry-standard harmless AV test file),
creates its own throwaway binary rather than touching real system commands, and cleans up
automatically even if interrupted.

The viva point to make: **network** threats are caught by **Suricata**, **host** threats by
**Wazuh's own rules and FIM** — and both land in one dashboard. That contrast is the whole argument
for the two-tool design.

---

## Deployment options

Your proposal states the Ubuntu server *"runs Docker containers for easier deployment."* Both paths
are provided:

```bash
make up                                        # all-in-one installer (default, recommended)
WAZUH_DEPLOY=docker vagrant up wazuh-server    # containerised Wazuh stack
```

Build with the installer first and capture a clean detection. Only try Docker once your results are
safely recorded. See [`deploy-docker/README.md`](deploy-docker/README.md) for the trade-offs and a
ready-made viva answer covering both.

---

## Repo layout

```
nisec-lab/
├── Vagrantfile              # 4 VMs mapped to the 4 security zones
├── Makefile                 # make up / healthcheck / attacks / ...
├── provision/               # per-VM setup scripts (idempotent bash)
├── deploy-docker/           # ALT: containerised Wazuh stack
├── config/
│   ├── suricata/            #   custom threshold rules + config notes
│   ├── wazuh-agent/         #   eve.json localfile + FIM/rootcheck snippets
│   └── wazuh-manager/       #   custom rules (100101+) & decoders
├── attacks/                 # 7 test scripts: 6 threats + the evasion boundary
├── capture/                 # Wireshark/tshark capture + analysis
├── tests/                   # offline rule regression (pcap replay, no lab needed)
├── scripts/                 # healthcheck, hardening, retention, MEASUREMENT
├── dvwa/                    # [BONUS] vulnerable web app target
├── evidence/                # screenshots / logs / pcaps / results (media git-ignored)
└── docs/                    # guide, runbook, architecture, traceability, report,
                             #   risk assessment, ATT&CK mapping, references
```

---

## The core deliverable

Everything in this repo exists to make one thing happen:

> **Suricata detects it on the network → writes an alert to `eve.json` → the Wazuh agent reads that
> file → the Wazuh server analyses it and shows it on the dashboard, right beside the host-based
> alerts.**

That single sentence is your project. When you see a Suricata network alert sitting in the Wazuh
dashboard next to an SSH brute-force alert, the system works — screenshot it, because it's the most
important figure in your report.

---

## Verification built in

Two failure modes in this project are **silent** — nothing errors, the detection just never fires.
Both are now checked automatically:

- **Custom Suricata rules not loading.** Copying a `.rules` file next to the ruleset doesn't load
  it; `suricata-update` regenerates that directory. The provisioner uses `suricata-update --local`
  and then verifies the SIDs landed in the compiled ruleset. `make healthcheck` re-checks it.
- **The test suite stopping early.** Several tools exit non-zero on their *expected* outcome (hydra
  finding no password). The runner records each result and continues, then prints a summary.

If `make healthcheck` is all green, the lab is genuinely working — not just running.

---

## Safety and legality

Everything runs on an **isolated host-only network** against **your own** VMs. That is legal and
expected for this coursework. Never point these tools at machines you don't own or across the
internet or your university network.
