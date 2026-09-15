# Step-by-Step Build Guide

**NISec — Centralized Security Monitoring System (Wazuh + Suricata)**
Zwe Nyi Nyar · TNT-2061 · CST-8415

This is the **main build document**. Follow it top to bottom. Every stage has:

- **Goal** — what you're building and why
- **Do this** — the exact commands
- **✅ Checkpoint** — how you know it worked (don't move on until this passes)
- **📸 Screenshot** — evidence to capture for your report
- **🔧 If it breaks** — the fixes for what actually goes wrong

> **The golden rule:** don't skip a checkpoint. Every stage depends on the one before it. A failed
> checkpoint caught now takes five minutes; caught three stages later it takes an evening.

**Time budget:** roughly 8–12 hours of hands-on work, best spread over several sessions. Stage 4
and Stage 5 are the ones you must not rush — Stage 5 is your core deliverable.

---

## Stage map

| Stage | What you build | Maps to proposal | Time |
|---|---|---|---|
| [0](#stage-0--prepare-your-host) | Host prep: VirtualBox + Vagrant | System requirements | 30 min |
| [1](#stage-1--bring-up-the-four-vms) | Four VMs, private network | Security zones §3 | 1–2 h |
| [2](#stage-2--stand-up-the-wazuh-server) | Manager + Indexer + Dashboard | Objective 2 | 1 h |
| [3](#stage-3--enrol-the-agents) | Agents on monitored + client | Objective 2, FR1 | 45 min |
| [4](#stage-4--install-and-verify-suricata) | Suricata IDS + custom rules | Objective 3 | 1–2 h |
| [5](#stage-5--connect-suricata-to-wazuh-) | ⭐ **The integration** | Objective 4 | 1 h |
| [6](#stage-6--harden-and-set-retention) | Access control + retention | NFR5, FR6 | 30 min |
| [7](#stage-7--run-the-detection-tests) | Six attack tests + evidence | Objective 5 | 2–3 h |
| [8](#stage-8--optional-extras) | DVWA, Docker deploy | Bonus | optional |
| [9](#stage-9--write-it-up) | Report + viva prep | Objective 6 | 3–4 h |

---

## Stage 0 — Prepare your host

**Goal:** get the two tools that run everything else, and confirm your machine can cope.

### Check your hardware first

| Resource | Minimum | Comfortable |
|---|---|---|
| RAM | 8 GB (budget mode) | 16 GB |
| CPU | 4 cores, virtualization enabled | 6+ cores |
| Free disk | 80 GB | 120 GB |

**Virtualization must be enabled in BIOS/UEFI** (Intel VT-x or AMD-V). Check on Windows:

```powershell
# Task Manager -> Performance -> CPU -> "Virtualization: Enabled"
# or:
systeminfo | findstr /I "Hyper-V"
```

If it says virtualization is disabled, reboot into BIOS and enable it. Nothing works without it.

> ⚠️ **Windows users:** VirtualBox and Hyper-V/WSL2 conflict. If VMs run at a crawl or refuse to
> start, disable Hyper-V: `bcdedit /set hypervisorlaunchtype off` then reboot. (Re-enable later
> with `auto` if you need WSL2.)

### Do this

1. Install **VirtualBox** — https://www.virtualbox.org/wiki/Downloads
2. Install **Vagrant** — https://developer.hashicorp.com/vagrant/downloads
3. On Windows, open **PowerShell** in the `nisec-lab` folder. On Linux/macOS or Git Bash, `make`
   is also supported.

### ✅ Checkpoint

```bash
vagrant --version      # expect: Vagrant 2.x
VBoxManage --version   # expect: 7.x
```

Both must print a version. If `VBoxManage` isn't found, add VirtualBox's install folder to your PATH.

On Windows, also confirm the wrapper runs:

```powershell
.\nisec.ps1 status
```

### 🔧 If it breaks

| Symptom | Fix |
|---|---|
| `VBoxManage: command not found` | Add `C:\Program Files\Oracle\VirtualBox` to PATH, reopen terminal |
| VirtualBox won't install on Windows | Disable Hyper-V (above), reboot, retry |
| "VT-x is not available" | Enable virtualization in BIOS |

---

## Stage 1 — Bring up the four VMs

**Goal:** four machines on an isolated private network that can all see each other. **No security
tools yet** — prove the plumbing works first.

This builds the four security zones from your proposal:

| Zone | VM | IP |
|---|---|---|
| Management | `wazuh-server` | 192.168.56.40 |
| Monitoring | `monitored` | 192.168.56.20 |
| Client | `client` | 192.168.56.30 |
| Attack/Test | `kali` | 192.168.56.10 |

### Do this

```powershell
.\nisec.ps1 up            # 16 GB host - all four VMs
.\nisec.ps1 up-budget     # 8 GB host  - three VMs (drops the client)
```

First run downloads several GB of base images. Expect 30–60 minutes. It's normal for this to look
stalled while boxes download.

> **Budget mode note:** dropping the client means you can't demonstrate "monitors more than one
> device at once" — which is an explicit non-functional requirement in your proposal. If you can
> possibly spare the RAM, run all four. If you can't, say so in your report as a documented
> constraint (that scores better than silently omitting it).

### ✅ Checkpoint

```powershell
.\nisec.ps1 status                           # all VMs "running"
vagrant ssh kali -c "ping -c2 192.168.56.20" # attacker reaches target
vagrant ssh kali -c "ping -c2 192.168.56.40" # attacker reaches server
```

All pings must succeed.

### 📸 Screenshot

- `.\nisec.ps1 status` output, or the VirtualBox window showing four VMs running → **report §5.1**

### 🔧 If it breaks

| Symptom | Fix |
|---|---|
| Boots then hangs at "SSH auth method" | Usually just slow. Wait 5 min. If it persists: `vagrant reload` |
| `Vagrant was unable to mount VirtualBox shared folders` | Install the plugin: `vagrant plugin install vagrant-vbguest`, then `vagrant reload` |
| Ping fails between VMs | Host-only adapter issue. In VirtualBox: File → Tools → Network Manager, confirm a `192.168.56.1/24` adapter exists with DHCP **off** |
| "Address 192.168.56.x is not within the allowed ranges" | Create `/etc/vbox/networks.conf` (Linux/macOS) or `C:\ProgramData\VirtualBox\networks.conf` containing `* 192.168.56.0/21` |
| Everything is unbearably slow | Not enough RAM. Use `.\nisec.ps1 up-budget` / `make up-budget` |

---

## Stage 2 — Stand up the Wazuh server

**Goal:** the control room — Manager (analyses), Indexer (stores/searches), Dashboard (you look at it).

This happens automatically during `.\nisec.ps1 up` / `make up`, but it's the longest single step (~10–15 min) and
worth understanding.

### Do this

If Stage 1 completed, the server is already installing. To watch or re-run:

```bash
vagrant provision wazuh-server
```

Then retrieve your admin password — **it is randomly generated, save it somewhere**:

```bash
vagrant ssh wazuh-server
sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep -A1 admin
exit
```

Open **https://192.168.56.40** in your host browser. You'll get a certificate warning — that's
expected (self-signed cert on a private lab). Click through it and log in as `admin`.

### ✅ Checkpoint

```bash
vagrant ssh wazuh-server -c "sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard"
# expect three lines: active / active / active
```

And the dashboard loads in your browser.

### 📸 Screenshot

- The dashboard login page, and the empty overview after logging in → **report §5.2**

### 🔧 If it breaks

| Symptom | Fix |
|---|---|
| `wazuh-indexer` inactive/failed | Almost always RAM. Give the VM 6–8 GB in the `Vagrantfile`, then `vagrant reload wazuh-server` |
| Browser: "can't reach this page" | Check the VM is up and ufw allows 443: `vagrant ssh wazuh-server -c "sudo ufw status"` |
| Forgot the password | `sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p 'NewPass123!'` |
| Installer failed halfway | `vagrant ssh wazuh-server -c "sudo bash wazuh-install.sh -a -i -o"` (`-o` overwrites) |

---

## Stage 3 — Enrol the agents

**Goal:** the Wazuh agent on `monitored` and `client`, reporting home. This is what makes the
system *centralized* — the whole point of your project title.

### Do this

Also automatic during `.\nisec.ps1 up` / `make up`. To re-run:

```bash
vagrant provision monitored
vagrant provision client
```

### ✅ Checkpoint

In the dashboard: **Agents** → both `monitored` and `client` show status **Active** (green).

Or from the terminal:

```bash
vagrant ssh wazuh-server -c "sudo /var/ossec/bin/agent_control -l"
```

### 📸 Screenshot

- The agent list with **two agents Active** → **report §5.3**

This single screenshot evidences your NFR *"the system should be able to monitor more than one
device at the same time."* Don't skip it.

### 🔧 If it breaks

| Symptom | Fix |
|---|---|
| Agent shows "Disconnected" / "Never connected" | Check the agent can reach the manager: `vagrant ssh monitored -c "nc -zv 192.168.56.40 1514"` |
| Agent won't register | Re-register manually: `vagrant ssh monitored -c "sudo /var/ossec/bin/agent-auth -m 192.168.56.40"` then restart the agent |
| Both agents show the same name | Each needs a unique name — remove the duplicate in Agents → the ⋮ menu, then re-provision |

---

## Stage 4 — Install and verify Suricata

**Goal:** the network sensor. Suricata reads every packet on the wire and matches it against
thousands of attack signatures.

**This stage has the one failure mode that silently ruins the demo**, so it has an explicit
verification step. Read the checkpoint carefully.

### Do this

Automatic during provisioning. To re-run:

```bash
vagrant provision monitored
```

The provisioner:

1. Installs Suricata
2. Sets `HOME_NET` to the protected hosts `[.20, .30, .40]` — deliberately **not**
   the whole `/24`, because `EXTERNAL_NET` is `!$HOME_NET` and Kali (`.10`) has to
   stay outside it or no `$EXTERNAL_NET -> $HOME_NET` rule can ever match
3. Points it at the correct network interface (auto-detected)
4. Installs our custom rules and **merges them** with `suricata-update --local`
5. **Verifies the merge worked** and shouts if it didn't

### ✅ Checkpoint — read this one carefully

```bash
# 1. Suricata is running
vagrant ssh monitored -c "systemctl is-active suricata"

# 2. It's producing output
vagrant ssh monitored -c "sudo tail -3 /var/log/suricata/eve.json"

# 3. CRITICAL — our custom signatures actually loaded
vagrant ssh monitored -c "sudo grep -c 'sid:900000' /var/lib/suricata/rules/suricata.rules"
# expect: 3
```

**If check 3 returns 0, stop and fix it before continuing.** Copying a rules file next to the
ruleset does *not* load it — Suricata only reads what's listed in `rule-files:`, and
`suricata-update` regenerates that file. Without the merge, your **ping-flood detection will never
fire** and nothing will tell you why.

`.\nisec.ps1 healthcheck` / `make healthcheck` also reports this.

### 📸 Screenshot

- `eve.json` filling with entries → **report §5.4**
- The `grep -c 'sid:900000'` output showing 3 → good evidence you verified your own work

### 🔧 If it breaks

| Symptom | Fix |
|---|---|
| **Custom SIDs return 0** | `vagrant ssh monitored -c "sudo suricata-update --local /etc/suricata/rules/nisec-local.rules && sudo systemctl restart suricata"` |
| `eve.json` empty | Wrong interface. `vagrant ssh monitored -c "ip -o -4 addr"`, find the `192.168.56.x` NIC, ensure `af-packet: - interface:` in `/etc/suricata/suricata.yaml` matches |
| Suricata won't start | Test the config: `sudo suricata -T -c /etc/suricata/suricata.yaml` — it names the bad line |
| `suricata-update` fails | Needs internet. The VM has NAT so it should work; if offline, run it once when connected |

---

## Stage 5 — Connect Suricata to Wazuh ⭐

**Goal: this is your core deliverable.** Everything else is scaffolding around this one thing.

Suricata and Wazuh are joined by a single file: `/var/log/suricata/eve.json`. Suricata writes
alerts to it; the Wazuh agent tails it and ships each line to the Manager. That's what turns two
separate tools into **one centralized system**.

### Do this

The provisioner adds this block to `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
</ossec_config>
```

Verify it's there:

```bash
vagrant ssh monitored -c "sudo grep -A2 'suricata/eve.json' /var/ossec/etc/ossec.conf"
```

### ✅ Checkpoint — the money shot

Run a scan from Kali and watch it appear in the dashboard:

```bash
vagrant ssh kali -c "cd /vagrant/attacks && ./01_nmap_scan.sh"
```

Then in the dashboard: **Modules → Security events**, set the time filter to *Last 15 minutes*.
You should see Suricata alerts with source `192.168.56.10`.

**When you see a Suricata network alert sitting in the Wazuh dashboard, your project works.**

### 📸 Screenshot

- **A Suricata alert displayed inside the Wazuh Dashboard** → **report §5.5**

This is the single most important screenshot in your entire report. Take several: the alert list,
one alert expanded showing the rule that fired, and the source IP. Give this the most space in
your write-up.

### 🔧 If it breaks

| Symptom | Fix |
|---|---|
| No alerts at all | Work backwards: is `eve.json` growing? (`sudo tail -f`) Is the agent Active? Did you restart it after the config change? |
| `eve.json` has entries but nothing in the dashboard | `vagrant ssh monitored -c "sudo systemctl restart wazuh-agent"`, wait 60s, re-check |
| Alerts appear but with no useful fields | Confirm `<log_format>json</log_format>` (not `syslog`) |
| Time filter shows nothing | The dashboard defaults to a narrow window — widen it to *Last 24 hours* |

---

## Stage 6 — Harden and set retention

**Goal:** two of your proposal's stated requirements that are easy to forget:

- NFR: *"Only authorized users should be able to access the dashboard"*
- FR: *"Store logs so they can be reviewed later"*

### Do this

```powershell
.\nisec.ps1 harden        # firewall rules, session timeout, credential guidance
```

Then set retention — you must supply the password (the script refuses to guess a default):

```bash
vagrant ssh wazuh-server
sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep -A1 admin
INDEXER_PASS='<paste that password>' sudo -E bash /vagrant/scripts/configure-retention.sh
exit
```

Also create a least-privilege user, which makes the access-control story concrete:
**Dashboard → Security → Internal users → Create user** (`analyst`), then
**Roles** → assign `readall` + `wazuh_ui_user`.

### ✅ Checkpoint

```bash
vagrant ssh wazuh-server -c "sudo ufw status numbered"   # rules listed, 9200 denied
```

And logging in as `analyst` shows the dashboard but no admin settings.

### 📸 Screenshot

- `ufw status numbered` → **report §5.6**
- The retention policy output → **report §5.7**
- Admin vs analyst view side by side → strong access-control evidence

---

## Stage 7 — Run the detection tests

**Goal:** prove each threat from your proposal's risk assessment is actually detected. This is
your results chapter.

### The six tests

| # | Test | Covers | Run from |
|---|---|---|---|
| 1 | Port scan (nmap) | Port scanning — Medium | Kali |
| 2 | SSH brute-force (hydra) | Brute-force — **High** | Kali |
| 3 | Ping flood (hping3) | DoS — Medium | Kali |
| 4 | Malware/ransomware (EICAR + FIM) | Malware — **High** | **monitored** |
| 5 | Unauthorized access | Unauthorized access | Kali |
| 6 | Misconfiguration | Misconfiguration — Medium | Dashboard only |

### Do this

**First, start a packet capture** in a second terminal (this gives you the Wireshark evidence):

```bash
vagrant ssh monitored -c "sudo bash /vagrant/capture/capture.sh 300"
```

**Then run the suite** from Kali:

```powershell
.\nisec.ps1 attacks
```

It runs tests 1, 2, 3, 5 with pauses between each so alerts are easy to correlate, then prints a
summary. Tools exiting non-zero is normal — hydra returns non-zero when it finds no password,
which is exactly what you want.

**Test 4 runs on the monitored server** (it simulates what an attacker does *after* landing):

```powershell
.\nisec.ps1 malware-test
```

Safe by design: it uses the EICAR test string (a harmless industry-standard AV test file), creates
its own throwaway binary rather than touching real system commands, and cleans up automatically
even if interrupted.

**Test 6 needs no script.** In the dashboard: **Modules → Security Configuration Assessment** →
screenshot the CIS benchmark score. Free marks — Wazuh audits this automatically.

### ✅ Checkpoint

For each test, find the corresponding alert in **Modules → Security events**:

| Test | Look for |
|---|---|
| 1 | Suricata recon/scan alerts from `192.168.56.10` |
| 2 | *"Multiple SSH authentication failures"* — high severity |
| 3 | ICMP flood alert (our custom SID 9000001) |
| 4 | FIM alerts: new file, binary modified, mass modification |
| 5 | HTTP 401s in the test output (failure *is* the pass) |
| 6 | SCA score with passed/failed checks |

### 📸 Screenshot

**One screenshot per test**, each showing the attack command *and* the resulting alert →
**report §6**. Also record **time-to-alert** for each — that measured latency directly evidences
your *"alerts should appear as quickly as possible"* requirement.

Then analyse the capture:

```bash
vagrant ssh monitored -c "bash /vagrant/capture/analyze.sh /vagrant/evidence/pcaps/<file>.pcap"
```

Copy the `.pcap` to your host and open it in Wireshark for §6.9. Useful filters are in
`capture/README.md`.

### 🔧 If it breaks

| Symptom | Fix |
|---|---|
| **Ping flood: no alert** | The classic. Verify custom SIDs loaded (Stage 4 checkpoint 3). This is *why* that check exists |
| Brute-force: no alert | Confirm SSH is reachable: `vagrant ssh kali -c "nc -zv 192.168.56.20 22"` |
| FIM alerts don't appear | FIM needs to baseline first. Wait 2 min after provisioning, then re-run |
| Alerts appear late | Normal — the indexer batches. Widen the time filter |
| Suite stops early | Shouldn't happen anymore; the runner survives non-zero exits and prints a summary |

---

## Stage 8 — Optional extras

Beyond your submitted scope. Present as *additional work*, never as core scope.

### DVWA + web attack

```powershell
.\nisec.ps1 dvwa                                 # start the vulnerable web app
```

Then run the bonus suite from Kali:

```bash
vagrant ssh kali -c "cd /vagrant/attacks && BONUS=true ./run_all.sh"
```

First visit http://192.168.56.20/ and click **Create / Reset Database**. Login `admin` / `password`.

### Containerised Wazuh deployment

Your proposal says the Ubuntu server *"runs Docker containers for easier deployment."* You can
demonstrate that literally:

```bash
WAZUH_DEPLOY=docker vagrant up wazuh-server
```

On Windows, the wrapper equivalent is:

```powershell
.\nisec.ps1 up-docker
```

Needs one-time certificate generation — `deploy-docker/up.sh` prints exact instructions if they're
missing. See `deploy-docker/README.md` for the trade-offs and a ready-made viva answer.

> Build with the installer first and get a clean detection working. Only try Docker once your
> results are safely captured.

---

## Stage 9 — Write it up

**Goal:** turn your evidence into the report.

### Do this

1. Open `docs/report-skeleton.md` — it mirrors your submitted proposal's structure section by section.
2. Keep `docs/proposal-traceability.md` beside it — it maps every promise you made to the artefact
   that delivers it.
3. Fill each section, dropping in the screenshots from `evidence/screenshots/`.

### Don't forget these

- **§7.5 Security recommendations** — proposal objective 6 explicitly promises this. Tie each
  recommendation back to a vulnerability from §3.6.
- **Name all three Wazuh components** — Manager, Indexer, Dashboard. Your proposal named only the
  Manager.
- **State the zone limitation honestly** — one subnet, separation by host firewall, production
  would use VLANs. Naming it yourself beats being caught.
- **Explain why the ping flood needed a custom rule** — your best opportunity to show real
  understanding rather than tool-following.

### Viva prep

Be able to recite the alert lifecycle without notes:

> Attack launched → the OS logs it and Suricata sees it on the wire → the Wazuh agent collects
> both and sends them encrypted → the Manager decodes and rule-matches → the alert is stored in
> the Indexer → it appears on my dashboard within seconds.

And the one-sentence summary:

> *"I built a centralized security monitoring system. Suricata watches the network, Wazuh agents
> watch each machine, and both send their findings to one Wazuh server where I see every alert on
> a single dashboard."*

---

## Building without Vagrant

If you'd rather create the VMs by hand in VirtualBox, the same provisioning scripts work. Create
four VMs on a Host-Only network with the IPs from Stage 1, put this repo at `/vagrant` on each
(or edit the paths inside the scripts), then:

```bash
# wazuh-server
sudo NODE_NAME=wazuh-server SECURITY_ZONE=Management bash provision/common.sh
sudo bash provision/wazuh-server.sh

# monitored
sudo NODE_NAME=monitored SECURITY_ZONE=Monitoring bash provision/common.sh
sudo WAZUH_SERVER_IP=192.168.56.40 bash provision/monitored-server.sh

# client
sudo NODE_NAME=client SECURITY_ZONE=Client bash provision/common.sh
sudo WAZUH_SERVER_IP=192.168.56.40 bash provision/client.sh

# kali
sudo NODE_NAME=kali SECURITY_ZONE=Attack/Test bash provision/common.sh
sudo bash provision/kali.sh
```

All checkpoints above still apply — just use `ssh` instead of `vagrant ssh`.

---

## Quick command reference

```powershell
.\nisec.ps1 up            # build the lab (4 VMs)
.\nisec.ps1 up-budget     # build the lab (3 VMs, 8 GB hosts)
.\nisec.ps1 help          # list wrapper targets
.\nisec.ps1 status        # VM status
.\nisec.ps1 healthcheck   # verify connectivity + every service
.\nisec.ps1 test          # offline rule regression
.\nisec.ps1 harden        # apply access-control hardening
.\nisec.ps1 retention -IndexerPass '<admin password>'
.\nisec.ps1 attacks       # run the detection suite from Kali
.\nisec.ps1 malware-test  # run the FIM/ransomware test
.\nisec.ps1 measure       # detection rate + latency -> evidence/
.\nisec.ps1 evasion       # detection boundary tests
.\nisec.ps1 seal          # hash evidence/
.\nisec.ps1 capture       # 60s packet capture
.\nisec.ps1 dvwa          # [bonus] start DVWA
.\nisec.ps1 ssh-kali      # shell into a VM (also ssh-monitored, ssh-wazuh-server)
.\nisec.ps1 halt          # stop everything
.\nisec.ps1 destroy       # delete everything
```

If you are using Git Bash or Linux, every wrapper target above has the equivalent `make <target>`.

**Safety:** everything runs on an isolated host-only network against your own VMs. That's legal
and expected. Never point these tools at machines you don't own or across the internet.
