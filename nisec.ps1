# nisec.ps1 - PowerShell-native equivalents for NiSecProject's Makefile
# Run this from inside the nisec-lab directory.
# Usage examples:
#   .\nisec.ps1 up
#   .\nisec.ps1 up-budget
#   .\nisec.ps1 status
#   .\nisec.ps1 retention -IndexerPass 'yourAdminPassword'
#   .\nisec.ps1 ssh-kali

param(
    [Parameter(Position=0, Mandatory=$true)]
    [string]$Target,

    [string]$IndexerPass
)

switch -Regex ($Target) {
    "^up$"            { vagrant up }
    "^up-budget$"     { $env:CLIENT_ENABLED = "false"; vagrant up }
    "^up-docker$"     { $env:WAZUH_DEPLOY   = "docker"; vagrant up }
    "^halt$"          { vagrant halt }
    "^destroy$"       { vagrant destroy -f }
    "^status$"        { vagrant status }
    "^reload$"        { vagrant reload --provision }
    "^provision$"     { vagrant provision }

    "^harden$" {
        vagrant ssh wazuh-server -c 'sudo bash /vagrant/scripts/harden-dashboard.sh'
    }

    "^retention$" {
        if (-not $IndexerPass) {
            Write-Host "usage: .\nisec.ps1 retention -IndexerPass '<wazuh admin password>'"
            Write-Host "  find it with: .\nisec.ps1 ssh-wazuh-server, then run inside the VM:"
            Write-Host "  sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep -A1 admin"
            exit 1
        }
        vagrant ssh wazuh-server -c "sudo INDEXER_PASS='$IndexerPass' bash /vagrant/scripts/configure-retention.sh"
    }

    "^attacks$"          { vagrant ssh kali -c 'cd /vagrant/attacks && ./run_all.sh' }
    "^malware-test$"     { vagrant ssh monitored -c 'sudo bash /vagrant/attacks/05_malware_fim_test.sh' }
    "^evasion$"          { vagrant ssh kali -c 'bash /vagrant/attacks/07_evasion_test.sh' }
    "^active-response$"  { vagrant ssh wazuh-server -c 'sudo bash /vagrant/scripts/enable-active-response.sh' }
    "^capture$"          { vagrant ssh monitored -c 'sudo bash /vagrant/capture/capture.sh 60' }
    "^dvwa$"             { vagrant ssh monitored -c 'cd /vagrant/dvwa && ./up.sh' }

    "^ssh-(.+)$" {
        $vmName = $Matches[1]
        vagrant ssh $vmName
    }

    "^(healthcheck|test|measure|seal)$" {
        Write-Host "'$Target' runs a POSIX shell script on the HOST (not inside a VM)."
        Write-Host "PowerShell can't run these. Open Git Bash instead and run:"
        switch ($Target) {
            "healthcheck" { Write-Host "  bash scripts/healthcheck.sh" }
            "test"        { Write-Host "  bash tests/test-rules.sh" }
            "measure"     { Write-Host "  bash scripts/measure-detection.sh" }
            "seal"        { Write-Host "  bash scripts/seal-evidence.sh" }
        }
        Write-Host ""
        Write-Host "Git Bash ships with Git for Windows, which you already have (you used it to clone this repo)."
        Write-Host "Right-click the nisec-lab folder in Explorer -> 'Git Bash Here', or search 'Git Bash' in Start."
    }

    default {
        Write-Host "Unknown target: $Target"
        Write-Host ""
        Write-Host "Available (PowerShell-native):"
        Write-Host "  up, up-budget, up-docker, halt, destroy, status, reload, provision,"
        Write-Host "  harden, retention, attacks, malware-test, evasion, active-response,"
        Write-Host "  capture, dvwa, ssh-<vmname>"
        Write-Host ""
        Write-Host "Need Git Bash instead:"
        Write-Host "  healthcheck, test, measure, seal"
    }
}
