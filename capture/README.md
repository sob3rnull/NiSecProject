# Packet capture (Wireshark / tshark)

Wireshark is in your proposal's tool list, so it needs a defensible role. Here it is:

> **Suricata tells you *that* something happened; Wireshark shows you *exactly what* happened
> on the wire.** Suricata's alert is a verdict; the packet capture is the raw evidence behind it.

Concretely you use it for three things:

1. **Corroboration** — an alert fires, you open the matching `.pcap` and point at the actual
   SYN flood / ICMP storm / credential attempts. Very strong report material.
2. **Debugging detection** — when Suricata *doesn't* alert, the capture tells you whether the
   traffic even reached the sensor (wrong interface? wrong HOME_NET?) or whether it arrived but
   no signature matched. This distinction saves hours.
3. **Explaining a signature** — open a packet, show the exact bytes a rule matched on.

`tshark` is Wireshark's command-line version — same engine, no GUI needed on a server. Capture
headlessly on the monitored server, then open the `.pcap` in the Wireshark GUI on your host for
the screenshots.

## Usage

From the Windows host, the convenience wrapper starts a standard 60-second capture:

```powershell
.\nisec.ps1 capture
```

For custom durations or filters, run the capture command inside the monitored VM:

```bash
# On the monitored server — capture while you attack from Kali
sudo bash /vagrant/capture/capture.sh 60          # capture 60 seconds
sudo bash /vagrant/capture/capture.sh 60 icmp     # only ICMP (ping flood)
sudo bash /vagrant/capture/capture.sh 120 'tcp port 22'   # only SSH

# Then summarise what you caught
bash /vagrant/capture/analyze.sh evidence/pcaps/capture_20260806_101500.pcap
```

Copy the `.pcap` to your host and open it in Wireshark for the screenshots.

## Useful Wireshark display filters for your report

| Goal | Filter |
|---|---|
| Nmap SYN scan | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Ports that answered | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| Ping flood | `icmp.type == 8` |
| SSH attempts | `tcp.port == 22` |
| Traffic from the attacker | `ip.src == 192.168.56.10` |
| HTTP requests (DVWA bonus) | `http.request` |

**Statistics → Conversations** is the quickest way to show one host hammering another.
