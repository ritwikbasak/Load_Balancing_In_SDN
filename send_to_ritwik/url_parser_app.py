from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from scapy.all import *

# Assuming packet_in is the incoming packet received by the Ryu controller
def parse_packet(packet_in):
    pkt = packet.Packet(data=packet_in.data)
    eth_pkt = pkt.get_protocol(ethernet.ethernet)
    ip_pkt = pkt.get_protocol(ipv4.ipv4)
    tcp_pkt = pkt.get_protocol(tcp.tcp)

    if eth_pkt and ip_pkt and tcp_pkt:
        # Check if it's an HTTP packet
        if tcp_pkt.src_port == 80 or tcp_pkt.dst_port == 80:
            # Use Scapy to parse the packet at the raw level
            raw_data = pkt.protocols[-1].data

            # Parse as HTTP using Scapy
            http_pkt = HTTP(raw_data)
            if http_pkt:
                # Access HTTP fields
                print(http_pkt.show())  # Print HTTP packet fields (modify as needed)
                # Perform your HTTP packet analysis here
