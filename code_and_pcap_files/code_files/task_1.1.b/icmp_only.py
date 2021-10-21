from scapy.all import *

def print_pkt(pkt):
    pkt.show()
    
sniff(iface="br-1a115f7b3a07", filter="icmp", prn=print_pkt)
