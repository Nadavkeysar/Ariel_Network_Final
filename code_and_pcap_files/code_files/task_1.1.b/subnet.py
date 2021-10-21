from scapy.all import *

def print_pkt(pkt):
    pkt.show()
    
# filter whole subnet  
sniff(iface="ens33", filter="net 192.168.1.0/24", prn=print_pkt)
