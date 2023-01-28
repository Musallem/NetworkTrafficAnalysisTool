# """
# [{'name': 'Intel(R) Dual Band Wireless-AC 8265',
#   'win_index': '4',
#   'description': 'Ethernet0',
#   'guid': '{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}',
#   'mac': '00:0C:29:5C:EE:6D',
#   'netid': 'Ethernet0'}]
# """
# from pprint import pprint
# from scapy.arch.windows import get_windows_if_list
# from scapy.all import *
#
# # disable verbose mode
# conf.verb = 0
#
#
# def parse_packet(packet):
#     """sniff callback function.
#     """
#     if packet and packet.haslayer('UDP'):
#         udp = packet.getlayer('UDP')
#         udp.show()
#
#
# def udp_sniffer():
#     """start a sniffer.
#     """
#     interfaces = get_windows_if_list()
#     pprint(interfaces)
#
#     print('\n[*] start udp sniffer')
#     sniff(
#         filter="udp port 53",
#         iface=r'Intel(R) Dual Band Wireless-AC 8265', prn=parse_packet
#     )
#
#
# if __name__ == '__main__':
#     udp_sniffer()

from scapy.all import *
import socket
import datetime
import os
import time

from scapy.layers.inet import TCP, IP, UDP, ICMP


def network_monitoring_for_visualization_version(pkt):
    time = datetime.datetime.now()
    # classifying packets into TCP
    if pkt.haslayer(TCP):
        # classyfying packets into TCP Incoming packets
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print(str("[") + str(time) + str("]") + "  " + "TCP-IN:{}".format(
                len(pkt[TCP])) + " Bytes" + "    " + "SRC-MAC:" + str(pkt.src) + "    " + "DST-MAC:" + str(
                pkt.dst) + "    " + "SRC-PORT:" + str(pkt.sport) + "    " + "DST-PORT:" + str(
                pkt.dport) + "    " + "SRC-IP:" + str(pkt[IP].src) + "    " + "DST-IP:" + str(pkt[IP].dst))

        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print(str("[") + str(time) + str("]") + "  " + "TCP-OUT:{}".format(
                len(pkt[TCP])) + " Bytes" + "    " + "SRC-MAC:" + str(pkt.src) + "    " + "DST-MAC:" + str(
                pkt.dst) + "    " + "SRC-PORT:" + str(pkt.sport) + "    " + "DST-PORT:" + str(
                pkt.dport) + "    " + "SRC-IP:" + str(pkt[IP].src) + "    " + "DST-IP:" + str(pkt[IP].dst))
    # classifying packets into UDP
    if pkt.haslayer(UDP):
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            # classyfying packets into UDP Outgoing packets
            print(str("[") + str(time) + str("]") + "  " + "UDP-OUT:{}".format(
                len(pkt[UDP])) + " Bytes " + "    " + "SRC-MAC:" + str(pkt.src) + "    " + "DST-MAC:" + str(
                pkt.dst) + "    " + "SRC-PORT:" + str(pkt.sport) + "    " + "DST-PORT:" + str(
                pkt.dport) + "    " + "SRC-IP:" + str(pkt[IP].src) + "    " + "DST-IP:" + str(pkt[IP].dst))

        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            # classyfying packets into UDP Incoming packets
            print(str("[") + str(time) + str("]") + "  " + "UDP-IN:{}".format(
                len(pkt[UDP])) + " Bytes " + "    " + "SRC-MAC:" + str(pkt.src) + "    " + "DST-MAC:" + str(
                pkt.dst) + "    " + "SRC-PORT:" + str(pkt.sport) + "    " + "DST-PORT:" + str(
                pkt.dport) + "    " + "SRC-IP:" + str(pkt[IP].src) + "    " + "DST-IP:" + str(pkt[IP].dst))
    # classifying packets into ICMP
    if pkt.haslayer(ICMP):
        # classyfying packets into UDP Incoming packets
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print(str("[") + str(time) + str("]") + "  " + "ICMP-OUT:{}".format(
                len(pkt[ICMP])) + " Bytes" + "    " + "IP-Version:" + str(
                pkt[IP].version) + "    " * 1 + " SRC-MAC:" + str(pkt.src) + "    " + "DST-MAC:" + str(
                pkt.dst) + "    " + "SRC-IP: " + str(pkt[IP].src) + "    " + "DST-IP:  " + str(pkt[IP].dst))

        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print(str("[") + str(time) + str("]") + "  " + "ICMP-IN:{}".format(
                len(pkt[ICMP])) + " Bytes" + "    " + "IP-Version:" + str(
                pkt[IP].version) + "    " * 1 + "	 SRC-MAC:" + str(pkt.src) + "    " + "DST-MAC:" + str(
                pkt.dst) + "    " + "SRC-IP: " + str(pkt[IP].src) + "    " + "DST-IP:  " + str(pkt[IP].dst))


if __name__ == '__main__':
    sniff(prn=network_monitoring_for_visualization_version)