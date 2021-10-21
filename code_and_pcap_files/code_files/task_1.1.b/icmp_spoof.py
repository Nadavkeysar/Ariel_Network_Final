from scapy.all import *

#create the IP packet
a = IP()
# set src and dst IPs
a.src = "8.8.8.8" 
a.dst = "10.9.0.1" 
# create the ICMP packet
b = ICMP() 
# generate the ICMP+IP payload
p = a/b 
# send the packet
send(p)
