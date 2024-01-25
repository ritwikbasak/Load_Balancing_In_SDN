"""
Ryu Controller

This controller allows OpenFlow datapaths to act as Ethernet Hubs. Using the
tutorial you should convert this to a layer 2 learning switch.

"""

from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import ethernet, ether_types, ipv4, in_proto, arp,tcp
import load_balancer as lb
from ryu.lib import hub
from time import sleep

class Controller(RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    mac_to_port = {}
    ipMacMap = {}
    no_of_servers = None
    load_balancer = None
    VIRTUAL_IP = '10.0.0.10'
    VIRTUAL_MAC='00:00:00:00:01:11'
    selected_server = None
    server_weight={}

    SwitchMap = {}

    throughput_list=[0,0,0,0,0]
    index = 0
    

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        #self.monitor_thread = hub.spawn(self._monitor)
        print('# servers = ', end = '')
        self.no_of_servers = int(input())
        self.link_statistics=[{'initial_bytes': [], 'final_bytes': [], 'initial_time': [], 'final_time': []} for _ in range(self.no_of_servers)]
        self.ipMacMap = {}
        for i in range(1, self.no_of_servers + 1):
            self.ipMacMap[i] = [f'10.0.0.10{i}', f'00:00:00:00:00:0{i}']
        self.load_balancer = lb.Load_Balancer(1, self.no_of_servers)
        self.selected_server = self.load_balancer.get_server({}, [], self.no_of_servers)

    # def _monitor(self):
    #     while True:
    #         hub.sleep(10)
    #         self.Prober()
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        '''
        Handshake: Features Request Response Handler

        Installs a low level (0) flow table modification that pushes packets to
        the controller. This acts as a rule for flow-table misses.
        '''
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        self.SwitchMap[datapath.id] = datapath
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        self.add_flow(datapath, 0, match, actions)
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

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
        dst_mac = eth.dst
        src_mac = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

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
                self.logger.info("***************************")
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
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            self.logger.info("***************************")
            self.logger.info("---Handle TCP Packet---")
            ip_header = pkt.get_protocol(ipv4.ipv4)

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                if tcp_pkt.dst_port==81:
                    raw_data = msg.data
                    self.handle_load(raw_data)
                    #self.logger.info(f"Raw Data: {raw_data}")

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

    def handle_tcp_packet(self, datapath, in_port, ip_header, parser, dst_mac, src_mac):
        packet_handled = False
        if ip_header.dst == self.VIRTUAL_IP:
            self.selected_server = self.load_balancer.get_server(self.server_weight, [], self.no_of_servers)
            print(f"New server at controller.py: {self.selected_server}")
            
            server_out_port = self.selected_server
            server_dst_ip = self.ipMacMap[self.selected_server][0]
            server_dst_mac=self.ipMacMap[self.selected_server][1]
            
            # Route to server
            match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ip_proto=ip_header.proto,
                                    ipv4_dst=self.VIRTUAL_IP)

            actions = [parser.OFPActionSetField(eth_dst=server_dst_mac), parser.OFPActionSetField(ipv4_dst=server_dst_ip), 
                       parser.OFPActionOutput(server_out_port)]

            self.add_flow(datapath, 20, match, actions, hard_timeout=10)
            self.logger.info("<==== Added TCP Flow- Route to Server: " + str(server_dst_ip) +
                             " from Client :" + str(ip_header.src) + " on Switch Port:" +
                             str(server_out_port) + "====>")

            # Reverse route from server
            match = parser.OFPMatch(in_port=server_out_port, eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=ip_header.proto,
                                    ipv4_src=server_dst_ip,
                                    eth_dst=src_mac)
            actions = [parser.OFPActionSetField(eth_src=self.VIRTUAL_MAC), parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP), 
                       parser.OFPActionOutput(in_port)]

            self.add_flow(datapath, 20, match, actions, hard_timeout=10)
            self.logger.info("<==== Added TCP Flow- Reverse route from Server: " + str(server_dst_ip) +
                             " to Client: " + str(src_mac) + " on Switch Port:" +
                             str(in_port) + "====>")
            packet_handled = True
        return packet_handled
    
    def generate_arp_reply(self, dst_ip, dst_mac):
        self.logger.info("Generating ARP Reply Packet")
        self.logger.info("ARP request client ip: " + dst_ip + ", client mac: " + dst_mac)
        arp_target_ip = dst_ip  # the sender ip
        arp_target_mac = dst_mac  # the sender mac
        # Making the load balancer IP as source IP
        src_ip = self.VIRTUAL_IP

        src_mac=self.VIRTUAL_MAC

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

    def add_flow(self, datapath, priority, match, actions, hard_timeout=None):
        '''
        Install Flow Table Modification

        Takes a set of OpenFlow Actions and a OpenFlow Packet Match and creates
        the corresponding Flow-Mod. This is then installed to a given datapath
        at a given priority.
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if hard_timeout is not None:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, hard_timeout=hard_timeout)
        else:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)

        datapath.send_msg(mod)
    
    def handle_load(self,raw_data):
        data=str(raw_data)
        location=data.find("Load")
        load_info=data[location:]
        load=load_info.split('-')[0].split('=')[1]
        server_host=load_info.split('-')[1]
        print(f"Load = {load}")
        print(f"Server host from where load is recieved is {server_host}")
        weight=10-(float(load)/10)
        self.server_weight[server_host]=weight



            

    # @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    # def flow_stats_reply_handler(self, ev):
    #     msg = ev.msg
    #     body = msg.body
    #     #print(body)

    #     for stat in body:
    #         for i in range(1,self.no_of_servers+1):
    #             if 'in_port' in stat.match and stat.match['in_port'] == i:
    #                 print(f"index = {self.index} byte count = {stat.byte_count} time = {stat.duration_sec}")
                    
    #                 link_stats = self.link_statistics[i-1]
    #                 if self.index==0:
    #                     link_stats['initial_bytes'].append(stat.byte_count)
    #                     link_stats['initial_time'].append(stat.duration_sec)

    #                 else:
    #                     link_stats['final_bytes'].append(stat.byte_count)
    #                     link_stats['final_time'].append(stat.duration_sec)
        
    #     self.index=(self.index+1)%2

    #     if self.index == 0:
    #         server_throughputs = []
    #         for link_stats in self.link_statistics:
    #             throughput = 0
    #             for i in range(len(link_stats['initial_bytes'])):
    #                 initial_byte_count = link_stats['initial_bytes'][i]
    #                 final_byte_count = link_stats['final_bytes'][i]
    #                 initial_time = link_stats['initial_time'][i]
    #                 final_time = link_stats['final_time'][i]
    #                 throughput += (final_byte_count - initial_byte_count) / (final_time - initial_time)

    #             server_throughputs.append(throughput / (100000))  

    #         print("**************Throughput_list********************")
    #         print(server_throughputs)
    #         #self.load_balancer.least_loaded(server_throughputs)

    #         for link_stats in self.link_statistics:
    #             link_stats['initial_bytes'].clear()
    #             link_stats['final_bytes'].clear()
    #             link_stats['initial_time'].clear()
    #             link_stats['final_time'].clear()
            

    # def Prober(self):
    #     datapath = self.SwitchMap[1]
    #     parser  = datapath.ofproto_parser
    #     req = parser.OFPFlowStatsRequest(datapath)
    #     datapath.send_msg(req)

    #     sleep(5)

    #     datapath.send_msg(req)
