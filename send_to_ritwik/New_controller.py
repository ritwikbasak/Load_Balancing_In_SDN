import sys
import requests
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.mac import haddr_to_int
from ryu.lib.packet.ether_types import ETH_TYPE_IP
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
import random
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json
import socket
import threading
from ryu.lib.packet import icmp

selected_server = 1
server_mac_and_ip = []
info={}
server_weights={}
lock=threading.Lock()


class SimpleController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # _CONTEXTS={
    #     'wsgi': WSGIApplication
    # }

    VIRTUAL_IP = '10.0.0.100'  # The virtual server IP

    SERVER1_IP = '10.0.0.1'
    SERVER1_MAC = '00:00:00:00:00:01'
    SERVER1_PORT = 1
    SERVER2_IP = '10.0.0.2'
    SERVER2_MAC = '00:00:00:00:00:02'
    SERVER2_PORT = 2

    #-selected_server = 1

    #-server_mac_and_ip = []

    def __init__(self, *args, **kwargs):
        super(SimpleController, self).__init__(*args, **kwargs)
        self.logger.info("Inside init of controller")
        my_thread = threading.Thread(target=collect_info)
        my_thread.start()
        self.mac_to_port = {}
        self.server_weights = {}  # Dictionary to store server weights
        #wsgi = kwargs['wsgi']
        #wsgi.register(SimpleController, {'app':self})
        self.selected_server = 1
        self.server_mac_and_ip = [["00:00:00:00:00:0"+str(i), "10.0.0.10"+str(i)+"/24"] for i in range(1, 6)]
        print('inside init')

    


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore ipv6 packets
            return
        dst_mac = eth.dst
        src_mac = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 10, match, actions)

        # Handle ARP Packet
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_header = pkt.get_protocol(arp.arp)

            if arp_header.dst_ip == self.VIRTUAL_IP and arp_header.opcode == arp.ARP_REQUEST:
                self.logger.info("***")
                self.logger.info("---Handle ARP Packet---")
                # Build an ARP reply packet using source IP and source MAC
                reply_packet = self.generate_arp_reply(arp_header.src_ip, arp_header.src_mac)
                actions = [parser.OFPActionOutput(in_port)]
                packet_out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY,
                                                 data=reply_packet.data, actions=actions, buffer_id=0xffffffff)
                datapath.send_msg(packet_out)
                self.logger.info("Sent the ARP reply packet")
                return

        # Handle TCP Packet
        if eth.ethertype == ETH_TYPE_IP:
            self.logger.info("***")
            self.logger.info("---Handle TCP Packet---")
            ip_header = pkt.get_protocol(ipv4.ipv4)

            packet_handled = self.handle_tcp_packet(datapath, in_port, ip_header, parser, dst_mac, src_mac)
            self.logger.info("TCP packet handled: " + str(packet_handled))
            if packet_handled:
                return

        # Send if other packet
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst=pkt_ethernet.src,src=self.hw_addr))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,src=self.ip_addr,proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,code=icmp.ICMP_ECHO_REPLY_CODE,csum=0,data=pkt_icmp.data))
        self._send_packet(datapath, port, pkt)
    
    # Source IP and MAC passed here now become the destination for the reply packet
    def generate_arp_reply(self, dst_ip, dst_mac):
        self.logger.info("Generating ARP Reply Packet")
        self.logger.info("ARP request client ip: " + dst_ip + ", client mac: " + dst_mac)
        arp_target_ip = dst_ip  # the sender ip
        arp_target_mac = dst_mac  # the sender mac
        # Making the load balancer IP as source IP
        src_ip = self.VIRTUAL_IP

        # load balancing
        '''if haddr_to_int(arp_target_mac) % 2 == 1:
            src_mac = self.SERVER1_MAC
        else:
            src_mac = self.SERVER2_MAC'''
        self.selected_server = random.randint(1, 5)
        src_mac = self.server_mac_and_ip[selected_server][0]
        self.logger.info("Selected server MAC: " + src_mac)

        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP)
        )
        pkt.add_protocol(
            arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip,
                    dst_mac=arp_target_mac, dst_ip=arp_target_ip)
        )
        pkt.serialize()
        self.logger.info("Done with processing the ARP reply packet")
        return pkt

    def handle_tcp_packet(self, datapath, in_port, ip_header, parser, dst_mac, src_mac):
        packet_handled = False

        if ip_header.dst == self.VIRTUAL_IP:
            # if dst_mac == self.SERVER1_MAC:
            #     server_dst_ip = self.SERVER1_IP
            #     server_out_port = self.SERVER1_PORT
            # else:
            #     server_dst_ip = self.SERVER2_IP
            #     server_out_port = self.SERVER2_PORT

            # load balancing
            self.selected_server = random.randint(1, 5)
            server_out_port = selected_server
            server_dst_ip = server_mac_and_ip[self.selected_server][1]

            # Modify the destination IP address of the TCP packet
            # new_dst_ip = "192.168.1.100"  # Replace with the actual destination IP address
            # ip_header.dst = new_dst_ip
            ip_header.dst = server_dst_ip

            # Construct the modified packet
            modified_pkt = packet.Packet()
            modified_pkt.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_IP))
            modified_pkt.add_protocol(ip_header)
            modified_pkt.serialize()

            # Send the modified packet using OFPacketOut message
            actions = [parser.OFPActionOutput(server_out_port)]
            packet_out = parser.OFPPacketOut(datapath=datapath, in_port=in_port,
                                             data=modified_pkt.data, actions=actions, buffer_id=0xffffffff)
            datapath.send_msg(packet_out)

            self.logger.info("<==== Modified TCP Packet Sent ====>")
            packet_handled = True

            # Add flow entry for the modified packet (forward route)
            match = parser.OFPMatch(in_port=in_port, eth_type=ETH_TYPE_IP, ip_proto=ip_header.proto,
                                    ipv4_dst=self.VIRTUAL_IP, ipv4_src=ip_header.src)
            actions = [parser.OFPActionOutput(server_out_port)]
            self.add_flow(datapath, 20, match, actions)
            self.logger.info("<==== Added TCP Flow for Modified Packet (Forward Route) ====>")

            # Add flow entry for the reverse route from the server
            reverse_route_match = parser.OFPMatch(in_port=server_out_port, eth_type=ETH_TYPE_IP,
                                                  ip_proto=ip_header.proto, ipv4_src=server_dst_ip,
                                                  ipv4_dst=ip_header.src, eth_dst=src_mac)
            reverse_route_actions = [parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 20, reverse_route_match, reverse_route_actions)
            self.logger.info("<==== Added TCP Flow for Reverse Route from Server ====>")

        return packet_handled
    
def update_server_weight(server_info):
    server_name = server_info.get('server_name')
    cpu_utilization = server_info.get('cpu_utilization')
    memory_usage = server_info.get('memory_usage')
    disk_space = server_info.get('disk_space')
    #self.logger.info("Recieved Server weight from "+ server_name)
    server_weight_update(server_name, cpu_utilization, memory_usage, disk_space)
    

def server_weight_update(server_name, cpu_utilization, memory_usage, disk_space):
    
    #self.logger.info("inside Servere_weight update")
    with lock:
        server_weights[server_name] = {
            'cpu_utilization': cpu_utilization,
            'memory_usage': memory_usage,
            'disk_space': disk_space
        }

    
def listen(server_socket,server_address):
    while True:
        data = server_socket.recv(1024)  # Adjust buffer size as needed
        if data:
            print(data)
            server_info = json.loads(data.decode('utf-8'))
            print(server_info)
            update_server_weight(server_info)


def collect_info():
    print("inside collect info")
    
    controller_host = '127.0.0.1'
    controller_port = 5000  

    controller_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(controller_socket)
    try:
        controller_socket.bind((controller_host, controller_port))
    except Exception as e:
        print(f"Error binding socket: {e}")
        sys.exit("Exiting due to socket binding error.")
    controller_socket.listen(5)  # Maximum number of queued connections

    try:
        while True:
            server_socket, server_address = controller_socket.accept()
            print(server_socket)
            print(server_address)
            new_thread=threading.Thread(target=listen,args=(server_socket,server_address))
            new_thread.start()

    except KeyboardInterrupt:
        controller_socket.close()
        print("Controller socket closed. Exiting.")
    