from scapy.all import *

def print_pkt(pkt):
    pkt.show()
    
# filter port 23 from a specific host's IP (for example 10.0.9.5)   
sniff(iface="br-1a115f7b3a07", filter="dst port 23 and src host 10.0.9.5", prn=print_pkt)
