from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
import datetime
FILTER="DNS"

def print_summary(captured):

    if FILTER =="TCP" and not captured.haslayer(TCP):
        return
    
    if FILTER =="UDP" and not captured.haslayer(UDP):
        return
    
    if FILTER =="DNS" and not captured.haslayer(DNS):
        return
    
    packet_time = datetime.datetime.fromtimestamp(captured.time).strftime("%H:%M:%S")
    packet_size = len(captured)

    if captured.haslayer(DNS) and captured.haslayer(IP):

        if captured[DNS].qd:
            ip_src = captured[IP].src
            dns_query_target = captured[DNS].qd.qname.decode('utf-8')

            print(f"{ip_src} → DNS Query: {dns_query_target} | Time: {packet_time}")

    elif captured.haslayer(IP) and captured.haslayer(TCP):
        src_ip = captured[IP].src
        dst_ip = captured[IP].dst
        s_port = captured[TCP].sport
        d_port = captured[TCP].dport

        print(f"{src_ip}:{s_port} → {dst_ip}:{d_port} | TCP | Time: {packet_time} | Size: {packet_size}B")

    elif captured.haslayer(IP) and captured.haslayer(UDP):
        src_ip = captured[IP].src
        dst_ip = captured[IP].dst
        s_port = captured[UDP].sport
        d_port = captured[UDP].dport

        print(f"{src_ip}:{s_port} → {dst_ip}:{d_port} | UDP | Time: {packet_time} | Size: {packet_size}B")

    elif captured.haslayer(ARP):
        print(f"ARP | Time: {packet_time} | Size: {packet_size}B")

    elif captured.haslayer(ICMP):
        print(f"ICMP | Time: {packet_time} | Size: {packet_size}B")


def capturer_start():
    print("Starting capture")
    sniff(prn=print_summary, store=False)
    