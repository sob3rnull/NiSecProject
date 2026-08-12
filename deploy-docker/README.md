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

```bash
cd deploy-docker
cp .env.example .env      # then EDIT the passwords
./up.sh
# dashboard: https://192.168.56.40   (user: admin)
./down.sh                 # stop; add -v inside the script to wipe volumes
```

To use this instead of the installer when provisioning:

```bash
WAZUH_DEPLOY=docker vagrant up wazuh-server
```

## Gotchas

- **Indexer exits immediately** → `vm.max_map_count` too low. `up.sh` fixes this, but if you run
  compose by hand: `sudo sysctl -w vm.max_map_count=262144`.
- **Certificates** — the official single-node repo ships a `generate-certs.yml`. If you hit TLS
  errors, clone `github.com/wazuh/wazuh-docker` (branch `v4.14.0`), run its cert generator, and
  copy the resulting `config/wazuh_indexer_ssl_certs/` next to this compose file.
- **Port 443 clash** — if the host already serves something on 443, change the dashboard mapping.
- **Agents still install natively.** The agents on `monitored` and `client` are unchanged; they
  just point at `192.168.56.40:1514` as before.

## Viva answer

> *"I deployed Wazuh two ways. The all-in-one installer runs Manager, Indexer and Dashboard as
> systemd services on the Ubuntu server. I also containerised the same stack with Docker Compose,
> which makes the deployment reproducible and portable — the trade-off is higher memory use and
> more complex networking to debug. For the lab I ran the native install for stability and used
> Docker for the containerised workload components."*
