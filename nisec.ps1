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

function Get-GitBash {
    $candidates = @(
        "C:\Program Files\Git\bin\bash.exe",
        "C:\Program Files\Git\usr\bin\bash.exe",
        "${env:ProgramFiles}\Git\bin\bash.exe",
        "${env:ProgramFiles}\Git\usr\bin\bash.exe",
        "${env:LocalAppData}\Programs\Git\bin\bash.exe"
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }

    return $null
}

function Invoke-HostBashScript {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath
    )

    $bash = Get-GitBash
    if (-not $bash) {
        Write-Host "Git Bash was not found. Install Git for Windows or add Git Bash to PATH."
        Write-Host "Then run this target again from the nisec-lab folder."
        exit 1
    }

    & $bash $ScriptPath
    exit $LASTEXITCODE
}

function Show-Help {
    Write-Host "Available PowerShell targets:"
    Write-Host "  up, up-budget, up-docker, halt, destroy, status, reload, provision,"
    Write-Host "  healthcheck, test, measure, seal, harden, retention, attacks,"
    Write-Host "  malware-test, evasion, active-response, capture, dvwa, ssh-<vmname>"
    Write-Host "  --- Analysis pipeline (run after 'measure') ---"
    Write-Host "  hunt     Threat Hunt Report from live alerts.json -> evidence/"
    Write-Host "  compare  Latency Drift Report across all measure runs -> evidence/"
    Write-Host "  score    Signature Confidence Scores across all measure runs -> evidence/"
}

switch -Regex ($Target) {
    "^help$"          { Show-Help }
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

    "^(healthcheck|test|measure|seal|hunt|compare|score)$" {
        switch ($Target) {
            "healthcheck" { Invoke-HostBashScript "scripts/healthcheck.sh" }
            "test"        { Invoke-HostBashScript "tests/test-rules.sh" }
            "measure"     { Invoke-HostBashScript "scripts/measure-detection.sh" }
            "seal"        { Invoke-HostBashScript "scripts/seal-evidence.sh" }
            "hunt"        { Invoke-HostBashScript "scripts/hunt.sh" }
            "compare"     { Invoke-HostBashScript "scripts/compare-runs.sh" }
            "score"       { Invoke-HostBashScript "scripts/score-signatures.sh" }
        }
    }

    default {
        Write-Host "Unknown target: $Target"
        Write-Host ""
        Show-Help
    }
}
