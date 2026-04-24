from scapy.all import *
from scapy.all import IPv6,IP,sniff,TCP,UDP
def print_summary(packet): #print summary for each packet
    ip_printer(packet)

def ip_printer(packet): #prtocol extraction and printer
    if packet.haslayer(IP):
        src_port=0
        dst_port=0
        if packet.haslayer(TCP):
            src_port=packet[TCP].sport
            dst_port=packet[TCP].sport
        elif packet.haslayer(TCP):
            src_port=packet[UDP].sport
            dst_port=packet[UDP].sport
        ip_src=packet[IP].src
        ip_dst=packet[IP].dst
        protocel=packet[IP].payload.name
        print(f"[IPv4 | {protocel}] | Src:{ip_src}-> {src_port} Dst:{ip_dst}-> {dst_port} ")
    elif packet.haslayer(IPv6):
        src_port=0
        dst_port=0
        if packet.haslayer(TCP):
            src_port=packet[TCP].sport
            dst_port=packet[TCP].sport
        elif packet.haslayer(TCP):
            src_port=packet[UDP].sport
            dst_port=packet[UDP].sport
        ip_Src=packet[IPv6].src
        ip_Dst=packet[IPv6].dst
        protocyl=packet[IPv6].payload.name
        print(f"[IPv6 | {protocyl}] | Src: {ip_Src}-> {src_port} | Dst: {ip_Dst}-> {dst_port}")
def printer():
    packet=sniff(count=10,prn=print_summary)
    
