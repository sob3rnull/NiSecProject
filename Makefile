# NISec lab — convenience wrapper around vagrant. `make help` for the list.
SHELL := /bin/bash

.PHONY: help up up-budget up-docker halt destroy status reload provision \
        healthcheck harden retention attacks malware-test capture dvwa ssh-%

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
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

retention:     ## Apply the 90-day log retention policy
	vagrant ssh wazuh-server -c 'sudo bash /vagrant/scripts/configure-retention.sh'

attacks:       ## Run the detection test suite from Kali
	vagrant ssh kali -c 'cd /vagrant/attacks && ./run_all.sh'

malware-test:  ## Run the FIM / ransomware test on the monitored server
	vagrant ssh monitored -c 'sudo bash /vagrant/attacks/05_malware_fim_test.sh'

capture:       ## 60s packet capture on the monitored server (Wireshark evidence)
	vagrant ssh monitored -c 'sudo bash /vagrant/capture/capture.sh 60'

dvwa:          ## [BONUS] Bring up DVWA on the monitored server
	vagrant ssh monitored -c 'cd /vagrant/dvwa && ./up.sh'

ssh-%:         ## SSH into a VM, e.g. `make ssh-kali`
	vagrant ssh $*
