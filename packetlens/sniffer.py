from scapy.all import *
def print_summary(packet): #print summary for each packet
    print(f"Received packet: {packet.summary()} Protocol: {packet.layers()}")
    ip_printer(packet)
def ip_printer(packet):
    if IP in packet:
        ip_src=packet[IP].src
        ip_dst=packet[IP].dst
        print ("IP SRC:"+str(ip_src)+"IP DST:"+str(ip_dst))
    
def printer():
    packet=sniff(count=10,prn=print_summary)
    
