"""
Simple Web Traffic Analyzer
----------------------------
A beginner cybersecurity/networking project using Scapy.

Captures live network packets and prints out HTTP/HTTPS
(port 80/443) traffic, showing source IP, destination IP,
protocol, and ports.

Requirements:
- Python 3
- Scapy (pip install scapy)
- Npcap installed (Windows) with "WinPcap API-compatible mode" checked
- Must be run with Administrator (Windows) / sudo (Linux/macOS) privileges,
  since raw packet capture requires elevated permissions.

Usage:
    python webtraffic.py

Note: Change IFACE below to match your own network adapter name.
Run scapy.show_interfaces() to list available adapters.
"""

import scapy.all as scapy

# Change this to match your own active network adapter
IFACE = "Intel(R) Wireless-AC 9462"

# Number of packets to capture before stopping
PACKET_COUNT = 20


def get_protocol_name(proto_num):
    """Convert an IP protocol number into a human-readable name."""
    if proto_num == 6:
        return "TCP"
    elif proto_num == 17:
        return "UDP"
    else:
        return str(proto_num)


def process_packet(pkt):
    """Extract and print relevant fields from a single packet, if it's web traffic."""
    if not pkt.haslayer(scapy.IP):
        return

    src_ip = pkt[scapy.IP].src
    dst_ip = pkt[scapy.IP].dst
    proto_name = get_protocol_name(pkt[scapy.IP].proto)

    sport = None
    dport = None
    if pkt.haslayer(scapy.TCP):
        sport = pkt[scapy.TCP].sport
        dport = pkt[scapy.TCP].dport
    elif pkt.haslayer(scapy.UDP):
        sport = pkt[scapy.UDP].sport
        dport = pkt[scapy.UDP].dport

    # Only show HTTP (80) or HTTPS (443) traffic
    if sport in (80, 443) or dport in (80, 443):
        print(f"{proto_name} | {src_ip}:{sport} -> {dst_ip}:{dport}")


def main():
    print(f"Capturing {PACKET_COUNT} packets on interface: {IFACE}")
    print("Generate some web traffic (open a browser) while this runs.\n")

    packets = scapy.sniff(iface=IFACE, count=PACKET_COUNT)

    for pkt in packets:
        process_packet(pkt)

