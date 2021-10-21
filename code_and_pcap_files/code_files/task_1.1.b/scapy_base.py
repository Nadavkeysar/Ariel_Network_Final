#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pkt):
    pkt.show()
    
pkt = sniff(iface="br-7b82f036ad6c", filter="icmp", prn=print_pkt)
