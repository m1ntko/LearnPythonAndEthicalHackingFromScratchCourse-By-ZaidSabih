#!/usr/bin/env python

import argparse
import scapy.all as scapy


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target ip, use --help for more info.")
    return options


def scan(ip):
    # Create arp request directed to broadcast MAC asking for IP
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Send and receive packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Parse the response
    client_list =[]

    for element in answered_list:
        client_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dictionary)
    return client_list


def print_result(result_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for element in result_list:
        print(element["ip"] + "\t\t" + element["mac"])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
