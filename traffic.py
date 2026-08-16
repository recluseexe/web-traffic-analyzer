import scapy.all as scapy

packets = scapy.sniff(iface="Intel(R) Wireless-AC 9462", count=5)

for pkt in packets:
    if pkt.haslayer(scapy.IP):
        src_ip = pkt[scapy.IP].src
        dst_ip = pkt[scapy.IP].dst
        proto_num = pkt[scapy.IP].proto

        if proto_num == 6:
            proto_name = "TCP"
        elif proto_num == 17:
            proto_name = "UDP"
        else:
            proto_name = str(proto_num)

        sport = None
        dport = None
        if pkt.haslayer(scapy.TCP):
            sport = pkt[scapy.TCP].sport
            dport = pkt[scapy.TCP].dport
        elif pkt.haslayer(scapy.UDP):
            sport = pkt[scapy.UDP].sport
            dport = pkt[scapy.UDP].dport

        print(f"{proto_name} | {src_ip}:{sport} -> {dst_ip}:{dport}")
