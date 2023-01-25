import socket
import struct
import textwrap
import getopt, sys
import dpkt
from libpcap import pcap
import binascii

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

HOST = '192.168.43.99'
print(HOST)###new line###
def main():
    # HOST = socket.gethostbyname(socket.gethostname())
    # print(HOST)
    # pcap = pcap.pcap('capture.pcap')
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    # conn.bind(('192.168.43.99', 0))
    conn.bind((HOST, 0))
    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # receive all packages
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


    while True:



        raw_data, addr = conn.recvfrom(65565)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame: ')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac,src_mac, eth_proto))

        # 8 for ipv4
        if eth_proto == 8:
            (version, header_length,ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet: ')
            print(TAB_2 + 'Version: {}, Header length: {}, TTL: {}'.format(version, header_length,ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet: ')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum,))
                print(TAB_2 + 'Data: ')
                print(format_mutli_line(DATA_TAB_3,data))

            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: ')
                print(format_mutli_line(DATA_TAB_3, data))

            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            # Other
            else:
                print(TAB_1 + 'Data: ')
                print(format_mutli_line(DATA_TAB_2, data))

        else:
            print('Data: ')
            print(format_mutli_line(DATA_TAB_1, data))





# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6s2s', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), (proto), data[14:]

# Return formatted mac address ( ie AA:BB:CC:DD:FF)
def get_mac_address(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length,ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# return formated IPv4 address
def ipv4(addr):
    return '.'.join(map(str,addr))

# unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# unpacks tcp segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# unpacks udp segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# format multi line data
def format_mutli_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])





#
# def main():
#     # Get host
#     # host = socket.gethostbyname(socket.gethostname())
#     print('IP: {}'.format(host))
#
#     name = None
#     pc = pcap.pcap(name)
#     decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
#                pcap.DLT_NULL:dpkt.loopback.Loopback,
#                pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()]
#     try:
#         print('listening on %s: %s' % (pc.name, pc.filter))
#         for ts, pkt in pc:
#             pkt = str(decode(pkt))
#             dest_mac, src_mac, eth_proto, data = ethernet_frame(pkt)
#
#             print('\nEthernet Frame:')
#             print("Destination MAC: {}".format(dest_mac))
#             print("Source: {}".format(src_mac))
#             print("Protocol: {}".format(eth_proto))
#     except KeyboardInterrupt:
#         nrecv, ndrop, nifdrop = pc.stats()
#         print('\n%d packets received by filter' % nrecv)
#         print('%d packets dropped by kernel' % ndrop)



if __name__ == '__main__':
    main()