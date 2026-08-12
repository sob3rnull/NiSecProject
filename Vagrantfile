# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# NISec lab — four VMs mapped onto the FOUR SECURITY ZONES defined in the
# project proposal (Security Design Architecture §3):
#
#   Management Zone  -> wazuh-server  (.40)  Wazuh server + dashboard access
#   Monitoring Zone  -> monitored     (.20)  Suricata IDS watching traffic
#   Client Zone      -> client        (.30)  machines sending logs to Wazuh
#   Attack/Test Zone -> kali          (.10)  penetration testing / simulation
#
# All zones sit on one private host-only network (192.168.56.0/24). Zone
# SEPARATION is enforced at the host firewall (scripts/harden-dashboard.sh),
# not by separate subnets — a deliberate, documented simplification for a
# single-laptop lab. See docs/architecture.md "Zone model".
#
# Usage:
#   vagrant up                       # all VMs
#   vagrant up wazuh-server          # one VM
#   CLIENT_ENABLED=false vagrant up  # 3-VM budget mode (8 GB hosts)
#   WAZUH_DEPLOY=docker vagrant up wazuh-server   # containerised Wazuh stack

CLIENT_ENABLED = ENV.fetch("CLIENT_ENABLED", "true") == "true"
WAZUH_DEPLOY   = ENV.fetch("WAZUH_DEPLOY", "installer")   # installer | docker

# name => [box, ip, cpus, memory_MB, provisioner, zone]
NODES = {
  "wazuh-server" => ["bento/ubuntu-22.04", "192.168.56.40", 2, 6144,
                     "provision/wazuh-server.sh",     "Management"],
  "monitored"    => ["bento/ubuntu-22.04", "192.168.56.20", 2, 2560,
                     "provision/monitored-server.sh", "Monitoring"],
  "client"       => ["bento/ubuntu-22.04", "192.168.56.30", 1, 1536,
                     "provision/client.sh",           "Client"],
  "kali"         => ["kalilinux/rolling",  "192.168.56.10", 2, 3072,
                     "provision/kali.sh",             "Attack/Test"],
}

Vagrant.configure("2") do |config|
  config.vm.boot_timeout = 600

  NODES.each do |name, (box, ip, cpus, mem, script, zone)|
    next if name == "client" && !CLIENT_ENABLED

    config.vm.define name do |node|
      node.vm.box      = box
      node.vm.hostname = name
      node.vm.network "private_network", ip: ip

      node.vm.provider "virtualbox" do |vb|
        # zone may contain "/" (Attack/Test); VirtualBox uses the VM name as a
        # directory name, so sanitise it or VM creation can fail.
        vb.name   = "nisec-#{name} [#{zone.tr('/', '-')}]"
        vb.cpus   = cpus
        vb.memory = mem
        vb.customize ["modifyvm", :id, "--paravirtprovider", "kvm"]
      end

      shared_env = {
        "WAZUH_SERVER_IP" => "192.168.56.40",
        "MONITORED_IP"    => "192.168.56.20",
        "CLIENT_IP"       => "192.168.56.30",
        "KALI_IP"         => "192.168.56.10",
        "NODE_NAME"       => name,
        "SECURITY_ZONE"   => zone,
      }

      node.vm.provision "shell", path: "provision/common.sh", env: shared_env

      node.vm.provision "shell",
        path: script,
        env: shared_env.merge({
          "WAZUH_VERSION" => ENV.fetch("WAZUH_VERSION", "4.14"),
          "WAZUH_DEPLOY"  => WAZUH_DEPLOY,
        })
    end
  end
end
