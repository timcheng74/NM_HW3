# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, dhcp, udp
from ryu.lib.packet import ether_types
from ryu.lib import addrconv



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.hw_addr='00:00:00:00:00:10'
        self.ip = '10.0.0.100'
    
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
        req = parser.OFPSetConfig(datapath, ofproto.OFPC_FRAG_NORMAL, 512)
        datapath.send_msg(req)        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,512)]
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
            print("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
 
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
        # if the packet is DHCP message, send to _handle_dhcp for futher use 
        if pkt_dhcp :
            self.logger.info("Recieve DHCP message")
            self._handle_dhcp(pkt_dhcp, datapath, in_port)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Uses a group table to forward etherent packet 
        group_id = 1
        actions = [parser.OFPActionGroup(group_id)]
        group_action = [parser.OFPActionOutput(out_port)]
        weight = 0
        watch_port = ofproto.OFPP_ANY
        watch_group = ofproto.OFPQ_ALL
        buckets = [parser.OFPBucket(weight, watch_port, watch_group, group_action)]
        req = parser.OFPGroupMod(datapath = datapath, 
                                command = ofproto.OFPGC_ADD,
                                group_id = group_id,
                                buckets = buckets)
        datapath.send_msg(req)
        
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _handle_dhcp(self, pkt_dhcp, datapath, in_port):
        dhcp_type = ord(pkt_dhcp.options.option_list[0].value)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if dhcp_type == 1:
            self.logger.info("Recieve DHCP_DISCOVERY")
            dhcp_offer = '\x02'
            self.logger.info("Send DHCP_OFFER")
            msg_option = dhcp.option(tag = 53, value = dhcp_offer)
            options = dhcp.options(option_list=[msg_option])
        
            pkt_dhcp = dhcp.dhcp(op=2,
                                 chaddr=pkt_dhcp.chaddr, 
                                 options=options,
                                 hlen=6,
                                 htype=1,
                                 xid=pkt_dhcp.xid,
                                 ciaddr=pkt_dhcp.ciaddr,
                                 yiaddr='10.0.1.1')
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(src=self.hw_addr, dst="ff:ff:ff:ff:ff:ff"))
            pkt.add_protocol(ipv4.ipv4(src=self.ip, dst="255.255.255.255", proto=17))
            pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
            pkt.add_protocol(pkt_dhcp)
            self._send_packet(datapath, in_port, pkt)
        if dhcp_type == 3:
            self.logger.info("Recieve DHCP_REQUEST")
            dhcp_ack = '\x05'
            self.logger.info("Send DHCP_ACK")
            msg_option = dhcp.option(tag = 53, value = dhcp_ack)
            time_option = dhcp.option(tag = 51, value = '\x00\xFF\xFF\xFF')
            options = dhcp.options(option_list=[msg_option, time_option])
            pkt_dhcp = dhcp.dhcp(op=5,
                         chaddr=pkt_dhcp.chaddr,
                         options=options,
                         hlen=6,
                         htype=1,
                         xid=pkt_dhcp.xid,
                         ciaddr=pkt_dhcp.ciaddr,
                         yiaddr='10.0.1.1')
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(src=self.hw_addr, dst="ff:ff:ff:ff:ff:ff"))
            pkt.add_protocol(ipv4.ipv4(src=self.ip, dst="255.255.255.255", proto=17))
            pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
            pkt.add_protocol(pkt_dhcp)
            self._send_packet(datapath, in_port, pkt)

            # install flow table 1
            cookie = 0
            cookie_mask = 0
            table_id = 0
            next_table_id = 3
            priority = 2000
            buffer_id = ofproto.OFP_NO_BUFFER
            print(pkt_dhcp.chaddr)
            match = parser.OFPMatch(eth_type=0x800,eth_src=pkt_dhcp.chaddr, ip_proto=17, udp_src=68)
            instruction = [parser.OFPInstructionGotoTable(next_table_id)]
            req = parser.OFPFlowMod(datapath = datapath,
                                    command = ofproto.OFPFC_ADD,
                                    cookie = cookie,
                                    cookie_mask = cookie_mask,
                                    table_id = table_id,
                                    priority = priority,
                                    match = match,
                                    instructions = instruction)
            datapath.send_msg(req)
            table_id = 3
            priority = 3000
            instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
            req = parser.OFPFlowMod(datapath = datapath,
                                    command = ofproto.OFPFC_ADD,
                                    cookie = cookie,
                                    cookie_mask = cookie_mask,
                                    table_id = table_id,
                                    priority = priority,
                                    out_port = ofproto.OFPP_ANY,
                                    match = match,
                                    instructions = instruction)
            datapath.send_msg(req)
   
            

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
