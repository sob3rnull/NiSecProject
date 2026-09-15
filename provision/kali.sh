#!/usr/bin/env bash
# kali.sh — the attacker box (Attack/Test Zone).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[kali] ensuring attack + analysis tools are installed..."
sudo apt-get update -y || true

# nmap + hydra are named in the proposal; hping3/nikto support the DoS and
# bonus web tests. wireshark/tshark is in the proposal's tool list.
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo apt-get install -y nmap hydra hping3 nikto wireshark tshark wordlists || true

# Kali's NetworkManager can race Vagrant's systemd-networkd static config for
# the host-only adapter. Leave eth1 to systemd-networkd so 192.168.56.10 sticks.
sudo mkdir -p /etc/NetworkManager/conf.d
cat <<'EOF' | sudo tee /etc/NetworkManager/conf.d/99-vagrant-hostonly.conf >/dev/null
[keyfile]
unmanaged-devices=interface-name:eth1
EOF
sudo nmcli device set eth1 managed no 2>/dev/null || true
sudo systemctl restart NetworkManager systemd-networkd || true

# rockyou ships gzipped on Kali — unpack for hydra
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
  sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz || true
fi

echo "[kali] tools ready."
echo "[kali] run attacks with: cd /vagrant/attacks && ./run_all.sh"
