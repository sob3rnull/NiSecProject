# NISec lab — convenience wrapper around vagrant. `make help` for the list.
SHELL := /bin/bash

.PHONY: help up up-budget up-docker halt destroy status reload provision \
        healthcheck harden retention attacks malware-test capture dvwa ssh-% \
        test measure evasion active-response seal hunt compare score

help:  ## Show this help
	@grep -E '^[a-zA-Z_%-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

up:            ## Bring up the full 4-VM lab (installer deployment)
	vagrant up

up-budget:     ## Bring up the 3-VM lab (no client) for 8 GB hosts
	CLIENT_ENABLED=false vagrant up

up-docker:     ## Bring up the lab with a containerised Wazuh stack
	WAZUH_DEPLOY=docker vagrant up

halt:          ## Stop all VMs
	vagrant halt

destroy:       ## Delete all VMs (irreversible)
	vagrant destroy -f

status:        ## Show VM status
	vagrant status

reload:        ## Reload + re-provision all VMs
	vagrant reload --provision

provision:     ## Re-run provisioners only
	vagrant provision

healthcheck:   ## Check connectivity + services across the lab
	bash scripts/healthcheck.sh

harden:        ## Apply dashboard access-control hardening
	vagrant ssh wazuh-server -c 'sudo bash /vagrant/scripts/harden-dashboard.sh'

retention:     ## Apply the 90-day log retention policy (INDEXER_PASS=... required)
	@test -n "$(INDEXER_PASS)" || { \
	  echo "usage: make retention INDEXER_PASS='<wazuh admin password>'"; \
	  echo "  the script refuses to guess a password, so it must be passed through."; \
	  echo "  find it with: make ssh-wazuh-server, then"; \
	  echo "  sudo tar -O -xf wazuh-install-files.tar \\"; \
	  echo "    wazuh-install-files/wazuh-passwords.txt | grep -A1 admin"; \
	  exit 1; }
	vagrant ssh wazuh-server -c 'sudo INDEXER_PASS="$(INDEXER_PASS)" bash /vagrant/scripts/configure-retention.sh'

attacks:       ## Run the detection test suite from Kali
	vagrant ssh kali -c 'cd /vagrant/attacks && ./run_all.sh'

malware-test:  ## Run the FIM / ransomware test on the monitored server
	vagrant ssh monitored -c 'sudo bash /vagrant/attacks/05_malware_fim_test.sh'

test:          ## Regression-test the detection rules offline (pcap replay)
	bash tests/test-rules.sh

measure:       ## MEASURE detection: rate, rule, time-to-alert -> evidence/
	bash scripts/measure-detection.sh

evasion:       ## Probe the detection BOUNDARY (expect misses - that's the result)
	vagrant ssh kali -c 'bash /vagrant/attacks/07_evasion_test.sh'

active-response: ## [OPT-IN] Enable automatic blocking (detect -> respond)
	vagrant ssh wazuh-server -c 'sudo bash /vagrant/scripts/enable-active-response.sh'

seal:          ## Hash evidence/ into a manifest (use --verify later)
	bash scripts/seal-evidence.sh

capture:       ## 60s packet capture on the monitored server (Wireshark evidence)
	vagrant ssh monitored -c 'sudo bash /vagrant/capture/capture.sh 60'

dvwa:          ## [BONUS] Bring up DVWA on the monitored server
	vagrant ssh monitored -c 'cd /vagrant/dvwa && ./up.sh'

ssh-%:         ## SSH into a VM, e.g. `make ssh-kali`
	vagrant ssh $*

hunt:          ## Threat Hunt Report — parse live alerts.json -> evidence/
	bash scripts/hunt.sh

compare:       ## Latency Drift Report — compare detection speed across measure runs -> evidence/
	bash scripts/compare-runs.sh

score:         ## Confidence Score — rate each rule's reliability across measure runs -> evidence/
	bash scripts/score-signatures.sh

report:        ## AI-narrated HTML Security Report (charts + tables + Gemini narrative, mock by default) -> evidence/
	python3 scripts/generate_html_report.py

report-dry:    ## Show what report would send to Gemini, without calling it
	python3 scripts/generate_html_report.py --dry-run

report-basic:  ## Charts/tables only, no AI, no Python dependency (original bash generator) -> evidence/
	bash scripts/generate-report.sh

report-test:   ## Offline unit tests for the report generator — no network, no API key needed
	python3 -m unittest tests.test_report -v

correlate:     ## AI-assisted attack chain correlation (mock by default, zero API cost) -> evidence/
	python3 scripts/correlate.py

correlate-dry: ## Show what correlate would send to Gemini, without calling it
	python3 scripts/correlate.py --dry-run

correlate-test: ## Offline unit tests for the correlation pipeline — no network, no API key needed
	python3 -m unittest tests.test_correlate -v
