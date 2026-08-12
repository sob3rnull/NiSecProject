#!/usr/bin/env python3
"""make_fixture_pcap.py — build a deterministic pcap that exercises the NISec
custom Suricata signatures, using ONLY the Python standard library.

WHY THIS EXISTS
Testing an IDS rule by launching a real attack and looking at a dashboard is
slow, needs the whole lab running, and is not repeatable — if the alert does
not appear you cannot tell whether the rule is wrong, the sensor is on the
wrong interface, the agent is down, or the manager dropped it. Replaying a
fixed pcap through Suricata offline isolates ONE question: does the signature
match the traffic it claims to match?

No scapy, no tcpreplay, no network access, no root. Just struct.

The packets are synthesised with timestamps INSIDE each rule's threshold
window, and with the attacker as source, so the fixture also regression-tests
the HOME_NET definition: these rules are written $EXTERNAL_NET -> $HOME_NET,
and if HOME_NET is ever widened to swallow the attacker they stop matching
even though they still load. That failure is silent in production and loud
here, which is the point.

    usage: python3 make_fixture_pcap.py <output.pcap>
"""
import struct
import sys

ATTACKER = "192.168.56.10"   # Kali - must be OUTSIDE HOME_NET
TARGET = "192.168.56.20"     # monitored - must be INSIDE HOME_NET

BASE_TS = 1700000000         # fixed epoch: identical bytes on every run

SRC_MAC = bytes.fromhex("080027aabbcc")
DST_MAC = bytes.fromhex("080027ddeeff")


def checksum(data: bytes) -> int:
    """Standard internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip_to_bytes(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    ver_ihl = 0x45
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, ident & 0xFFFF, 0, 64, proto, 0,
        ip_to_bytes(src), ip_to_bytes(dst),
    )
    csum = checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, ident & 0xFFFF, 0, 64, proto, csum,
        ip_to_bytes(src), ip_to_bytes(dst),
    )
    return header + payload


def icmp_echo_request(ident: int, seq: int) -> bytes:
    """itype 8 — what SID 9000001 counts."""
    body = b"nisec-fixture-payload"
    header = struct.pack("!BBHHH", 8, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    csum = checksum(header + body)
    header = struct.pack("!BBHHH", 8, 0, csum, ident & 0xFFFF, seq & 0xFFFF)
    return header + body


def tcp_syn(src: str, dst: str, sport: int, dport: int, seq: int) -> bytes:
    """flags:S only — what SIDs 9000002 and 9000003 count."""
    offset_flags = (5 << 12) | 0x002          # data offset 5, SYN
    header = struct.pack(
        "!HHIIHHHH", sport, dport, seq & 0xFFFFFFFF, 0, offset_flags, 8192, 0, 0
    )
    pseudo = struct.pack(
        "!4s4sBBH", ip_to_bytes(src), ip_to_bytes(dst), 0, 6, len(header)
    )
    csum = checksum(pseudo + header)
    return struct.pack(
        "!HHIIHHHH", sport, dport, seq & 0xFFFFFFFF, 0, offset_flags, 8192, csum, 0
    )


def ethernet(payload: bytes) -> bytes:
    return DST_MAC + SRC_MAC + struct.pack("!H", 0x0800) + payload


class PcapWriter:
    def __init__(self, path):
        self.fh = open(path, "wb")
        # magic, major, minor, thiszone, sigfigs, snaplen, network=1 (Ethernet)
        self.fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.count = 0

    def write(self, frame: bytes, ts_sec: int, ts_usec: int = 0):
        self.fh.write(struct.pack("!IIII", ts_sec, ts_usec, len(frame), len(frame)))
        self.fh.write(frame)
        self.count += 1

    def close(self):
        self.fh.close()


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = sys.argv[1]
    w = PcapWriter(out)

    # --- SID 9000001: ICMP flood, threshold 500 in 10s, track by_dst --------
    # 600 echo requests inside a 6-second window: comfortably over.
    t = BASE_TS
    for i in range(600):
        pkt = ipv4(ATTACKER, TARGET, 1, icmp_echo_request(0x1234, i), 1000 + i)
        w.write(ethernet(pkt), t + (i // 100), (i % 100) * 10000)

    # --- SID 9000002: SYN scan, threshold 30 in 5s, track by_src ------------
    # 60 SYNs to 60 different ports across ~3 seconds.
    t = BASE_TS + 60
    for i in range(60):
        pkt = ipv4(ATTACKER, TARGET, 6,
                   tcp_syn(ATTACKER, TARGET, 40000 + i, 1 + i, 0x1000 + i),
                   2000 + i)
        w.write(ethernet(pkt), t + (i // 20), (i % 20) * 50000)

    # --- SID 9000003: repeated SSH, threshold 20 in 30s, track by_src -------
    # 40 SYNs to port 22 across ~20 seconds.
    t = BASE_TS + 120
    for i in range(40):
        pkt = ipv4(ATTACKER, TARGET, 6,
                   tcp_syn(ATTACKER, TARGET, 50000 + i, 22, 0x2000 + i),
                   3000 + i)
        w.write(ethernet(pkt), t + (i // 2), 0)

    w.close()
    print("wrote %s (%d packets)" % (out, w.count))
    print("  %d ICMP echo requests   -> expect SID 9000001" % 600)
    print("  %d TCP SYN to 60 ports  -> expect SID 9000002" % 60)
    print("  %d TCP SYN to port 22   -> expect SID 9000003" % 40)
    print("  all %s -> %s (attacker must be OUTSIDE HOME_NET)" % (ATTACKER, TARGET))
    return 0


if __name__ == "__main__":
    sys.exit(main())
