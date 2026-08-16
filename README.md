A simple Python packet sniffer built with Scapy as a learning project for cybersecurity and networking fundamentals. It captures live network traffic and identifies HTTP/HTTPS (web) traffic, printing the source IP, destination IP, protocol, and ports for each packet.

## Requirements

- Python 3.8+
- Scapy (`pip install scapy`)
- **Windows only:** Npcap installed with "Install Npcap in WinPcap API-compatible Mode" checked
- **Linux/macOS:** libpcap (usually preinstalled)

## Installation

pip install scapy

## Usage

**Windows** (run from an Administrator PowerShell/Command Prompt):
python webtraffic.py

**Linux/macOS:**
sudo python3 webtraffic.py

Before running, open `webtraffic.py` and update the `IFACE` variable to match your own network adapter name. List adapters with:

    import scapy.all as scapy
    scapy.show_interfaces()

## Example Output

    TCP | 192.168.100.65:53073 -> 150.171.109.163:443
    TCP | 150.171.109.163:443 -> 192.168.100.65:53073

## Roadmap / Possible Improvements

- Live loop using Scapy's prn= callback instead of fixed count
- Use Scapy's BPF filter syntax (sniff(filter="tcp port 80 or tcp port 443"))
- Per-IP or per-protocol packet counters
- Log output to a file
- Resolve IPs to hostnames

## ⚠️ Ethical Use Notice

For educational purposes only, intended for networks you own or have explicit permission to monitor.
