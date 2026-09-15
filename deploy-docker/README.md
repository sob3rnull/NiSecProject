# Containerised Wazuh deployment (alternative path)

Your proposal states the Ubuntu Server *"runs Docker containers for easier deployment."*
This directory delivers exactly that: the full Wazuh stack (Manager + Indexer + Dashboard)
as Docker containers.

## Which path should I actually use?

| | All-in-one installer (default) | Docker Compose (this dir) |
|---|---|---|
| Script | `provision/wazuh-server.sh` | `deploy-docker/up.sh` |
| RAM needed | ~4 GB | ~6 GB (three JVM-ish containers) |
| Setup time | ~10 min | ~15 min + several GB of image pulls |
| Debugging | `journalctl`, normal systemd | `docker logs`, layered networking |
| Risk for a beginner | **Low** | Medium |

**Recommendation: build with the installer first.** Get one clean brute-force detection working
end-to-end. *Then*, if you have time, tear down and redo it with Docker — you'll understand what
the containers are doing because you've already seen the services running natively.

Either way your proposal is satisfied: Docker is genuinely used in the project (for this stack
and/or for the DVWA bonus target), and you can speak to both deployment models in the viva —
which is a stronger answer than only knowing one.

## Usage

Recommended from the repo root on Windows:

```powershell
.\nisec.ps1 up-docker
```

Manual use inside the VM or from a Linux/Git Bash shell:

```bash
cd deploy-docker
cp .env.example .env      # then EDIT the passwords
./up.sh
# dashboard: https://192.168.56.40   (user: admin)
./down.sh                 # stop; add -v inside the script to wipe volumes
```

Equivalent without the PowerShell wrapper:

```bash
WAZUH_DEPLOY=docker vagrant up wazuh-server
```

## After the stack is up

The analysis pipeline works identically regardless of whether you used the installer or Docker:

```powershell
.\nisec.ps1 attacks    # run attack suite from Kali
.\nisec.ps1 measure    # record detection latency
.\nisec.ps1 hunt       # threat hunt report from alerts.json
.\nisec.ps1 compare    # latency drift across runs (offline, no VMs needed)
.\nisec.ps1 score      # rule confidence scores (offline, no VMs needed)
.\nisec.ps1 seal       # hash the evidence
```

`hunt` SSHes into `wazuh-server` and reads `/var/ossec/logs/alerts/alerts.json` — this path
is the same whether Wazuh is running natively or in Docker, because the container mounts it
at the same location.

## Gotchas

- **Indexer exits immediately** → `vm.max_map_count` too low. `up.sh` fixes this, but if you run
  compose by hand: `sudo sysctl -w vm.max_map_count=262144`.
- **Certificates + config** — this compose file mounts the official single-node config tree, so
  before the first `./up.sh` you must clone `github.com/wazuh/wazuh-docker` (branch `v4.14.0`),
  run its cert generator, and copy the whole `single-node/config/*` into `deploy-docker/config/`
  (certs, `wazuh_indexer/`, `wazuh_dashboard/`). `up.sh` checks for all three and tells you if
  any are missing.
- **Indexer password** — the indexer's real admin password is the bcrypt hash in
  `config/wazuh_indexer/internal_users.yml`; `INDEXER_PASSWORD` in `.env` is only what the manager
  and dashboard *present* when connecting. They have to match, or the dashboard shows an
  authentication error. `up.sh` prints the `hash.sh` command for generating the hash.
- **Port 443 clash** — if the host already serves something on 443, change the dashboard mapping.
- **Agents still install natively.** The agents on `monitored` and `client` are unchanged; they
  just point at `192.168.56.40:1514` as before.
- **Guest Additions mismatch warning** — if `vagrant up` warns about a version mismatch between
  VirtualBox (7.1) and Guest Additions (7.2.4), verify `/vagrant` is mounted inside the VM before
  proceeding. See the root `README.md` → *Known issues* for the fix.

## Viva answer

> *"I deployed Wazuh two ways. The all-in-one installer runs Manager, Indexer and Dashboard as
> systemd services on the Ubuntu server. I also containerised the same stack with Docker Compose,
> which makes the deployment reproducible and portable — the trade-off is higher memory use and
> more complex networking to debug. For the lab I ran the native install for stability and used
> Docker for the containerised workload components."*
