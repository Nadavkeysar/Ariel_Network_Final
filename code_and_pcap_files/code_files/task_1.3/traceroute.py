from scapy.all import *


traceroute_destination = "8.8.8.8"

def print_route(ttl, source_address):
    print("Round number: %s . Reply from: %s" % (ttl, source_address))


if __name__ == '__main__':
    print("Traceroute to %s started\n" % traceroute_destination)
    ttl = 1
    while True:
        a = IP()
        a.dst = traceroute_destination
        # setting packet TTL to the ttl counter
        a.ttl = ttl
        b = ICMP()
        # sending packet and saving the reply. Setting timeout to listen up to 10 seconds. Setting verbose=0 so not output will be printed from scapy
        reply = sr1(a/b, timeout=10, verbose=0)
        # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
        # If no reply from source we only printing the ttl
        if not reply:
            print("Round number: %s . No reply from source address." % ttl)
            ttl += 1
            continue
        # checking if ICMP reply is type 0 (echo reply) if so the traceroute is completed
        if reply[ICMP].type == 0:
            print_route(ttl, reply.src)
            break
        # checking if ICMP reply is type 11 (Time exceeded) and subcode 0 (TTL expired in transit ) if so raising the TTL counter in 1
        if reply[ICMP].type == 11 and reply[ICMP].code == 0:
            print_route(ttl, reply.src)
            ttl += 1

    print("Traceroute ended! Bye")