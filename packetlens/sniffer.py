from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP

def print_summary(captured):

    if captured.haslayer(IP) and captured.haslayer(TCP):
        src_ip = captured[IP].src
        dst_ip = captured[IP].dst
        s_port = captured[TCP].sport
        d_port = captured[TCP].dport

        print(f"{src_ip}:{s_port} → {dst_ip}:{d_port} | TCP")

    elif captured.haslayer(UDP):
        print("UDP packet")
        print(captured.summary())

    elif captured.haslayer(ARP):
        print("ARP packet")
        print(captured.summary())


def capturer_start():
    print("Starting capture")
    sniff(prn=print_summary, store=False, count=10)