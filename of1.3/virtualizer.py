#!/usr/bin/python
#ToDo: update the incoming and outgoing ports between switch and virtualizer
#in our case teh incoming is always from port 1 ?? 
import socket
import select
import time
import sys
import struct
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import ofproto_v1_3 as of13
from ryu.ofproto import ofproto_v1_3_parser as of
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4 
from ryu.lib.packet import vlan
import ryu.lib.packet.packet_base as pkt
from ryu.lib.packet import lldp 
from ryu.lib.packet import fakelldp
from ryu.ofproto.ofproto_protocol import ProtocolDesc
from ryu.controller import ofp_event
from ryu.lib.mac import haddr_to_str
from ryu.ofproto import ether

buffer_size = 32384#16192
delay = 0.0001
forward_to = ('192.168.1.40', 6633)
controller1 = '192.168.1.40'
controller2 = '192.168.1.50'
controller_port = 6633

OFPXMC_OPENFLOW_BASIC= 0x8000
OFPXMT_OFB_VLAN_VID= 6
BROADCAST_STR = 'ff:ff:ff:ff:ff:ff'
BROADCAST = '\xff\xff\xff\xff\xff\xff'
LLDP_DST_STR = '01:80:c2:00:00:0e'
LLDP_DST = '\x01\x80\xc2\x00\x00\x0e'
_PAD = b'\x00'
_PAD2 = _PAD*2
_PAD3 = _PAD*3
_PAD4 = _PAD*4
_PAD6 = _PAD*6

class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception, e:
            print e
            return False

class TheServer:
    input_list = []
    channel = {}
    sockaddr = {}
    addrsock = {}
    portVlanMapping= {}
    vlanPortMapping= {}
    vlanCustomerMapping={}
    customerControllerMapping = {}
    customerVlanList = {}
    ethVlanMapping = {}#this is for loop prevention, every eth only comes from one vlan
                       #the ethVlanmapping might need expiry time, in case a link breaks   
   
    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(1000)

    def configure_port_mapping(self,port,vlan):
        self.portVlanMapping[port]=vlan

    def configure_vlan_mapping(self,vlan,port):
        self.vlanPortMapping[vlan]=port

    def configure_vlan_customer_mapping(self,vlan, customer):
        self.vlanCustomerMapping[vlan] = customer

    def configure_customer_controller_mapping(self,customer,controller):
        self.customerControllerMapping[customer]=controller

    def configure_customer_vlan_list(self, customer, vlan):
        if customer in self.customerVlanList:

           vlanlist = self.customerVlanList[customer]
           vlanlist.append(vlan)
           self.customerVlanList[customer] = vlanlist
        else:
           self.customerVlanList[customer] = []
           self.customerVlanList[customer].append(vlan)

    def main_loop(self):
        #the proxy itself
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])

            for self.s in inputready:
                 if self.s == self.server:#the connection request that came to proxy
                     self.on_accept()
                     break
                 try:
                  self.data = self.s.recv(buffer_size)
                  if len(self.data) == 0:
                    self.on_close()
                  else:
                    self.on_recv()
                 except Exception, e:
                  print "an Exteption occured", e

    def on_accept(self):
        forward = Forward().start(controller1, controller_port)
        forward2 = Forward().start(controller2, controller_port)
        clientsock, clientaddr = self.server.accept()
        if forward:
            print clientaddr, "has connected to controller"
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.input_list.append(forward2)

            self.channel[forward] = clientsock
            self.channel[forward2] = clientsock

            self.sockaddr[clientsock]= clientaddr
            self.sockaddr[forward]= controller1
            self.sockaddr[forward2]= controller2
            self.addrsock[controller1]= forward
            self.addrsock[controller2]= forward2
        else:
            print "Can't establish connection with remote server ", controller1
            print "Closing connection with client side", clientaddr
            clientsock.close()
        if forward2:
            print clientaddr, "has connected to controller2"
        else:
            print "Can't establish connection with remote server ", controller2

    def on_close(self):
        print self.s.getpeername(), "has disconnected"
        #remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.channel[self.s].close()
        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]
 
    def on_recv(self):
        data = self.data
        # here we can parse and/or modify the data before send forward
        try:
            index, outp = self.parse_message()
            if outp != None:
               for outData in outp:
                   if self.s in self.channel:
                      self.channel[self.s].send(outData)
                   else:
                      if index != '0.0.0.0':
                         self.addrsock[index].send(outData)
                      else:
                         #replicate the packet to all controllers
                         for server in self.addrsock:
                              self.addrsock[server].send(outData)
            else:
               print "outData is none"
        except Exception, e:
            print "outData exception ",e
            return

    def parse_message(self):
        outPackets = [] 
        origin = self.sockaddr[self.s]
        index = '0.0.0.0'
          
        p = self.data
        t = ord(p[1])
        packet_length = ord(p[2]) << 8 | ord(p[3])
        print origin," The received packet type is ",t 
        
        message_length, xid = struct.unpack_from('!HL', p, 2)
        datapath = ProtocolDesc(version=ord(p[0]))#of13.OFP_VERSION)
        version = of13.OFP_VERSION
        msg_type = t
        msg_len = len(p)
        if t == of13.OFPT_PACKET_IN:
          try:
             msg = of.OFPPacketIn.parser(datapath, ord(p[0]), msg_type, msg_len, xid, p)
             print xid," IN msg ", msg
          except Exception, e:
             print e
             outPackets.append(p)
             return index, outPackets
          # we need to drop the looped packets
           
           
          dst, src, eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)
          in_port = msg.match.fields[0].value
       
          arp_check = 0
          lldph_check = 0
          fake_lldp_check = 0
          ipv4_check = 0 
        # Ensure it's an ethernet frame.
          try: 
            pkt = packet.Packet(msg.data)
            i =iter (pkt)
            eth= i.next()
            next_pkt = i.next()
          except:
            print "A none ethernet packet got has been received"
            return index, None    
          if eth_type == ether.ETH_TYPE_8021Q:
              src_vlan = 0
              nx_next_pkt = i.next()
           
              #loop prevention
              print " in loop checking ", haddr_to_str(src)
              if  haddr_to_str(src) in self.ethVlanMapping:
                for proto in pkt.protocols:
                   if isinstance(proto, vlan.vlan):
                      if proto.vid != self.ethVlanMapping[ haddr_to_str(src)]:
                         return index,None
                      break
              else:
                for proto in pkt.protocols:
                   if isinstance(proto, vlan.vlan):
                      self.ethVlanMapping[ haddr_to_str(src)] = proto.vid
                      break #break after the first vid 
                  
              for proto in pkt.protocols:
                   
                   if isinstance(proto, vlan.vlan):
                      src_vlan = proto.vid
                      customerid = self.vlanCustomerMapping[src_vlan]
                      controllerSocketid = self.customerControllerMapping[customerid]
                      index = controllerSocketid
                      print "index is ", index
                      break
              if src_vlan in self.vlanPortMapping:
                   match = of.OFPMatch(in_port= self.vlanPortMapping[src_vlan])
                   print " dl_vid ",src_vlan, " self.vlanPortMapping[src_vlan] ",self.vlanPortMapping[src_vlan]
              packed = b""
              if isinstance(nx_next_pkt,lldp.lldp):
                 packed += struct.pack('!6s6sH', LLDP_DST,src,ether.ETH_TYPE_LLDP)
                 #return index, None #only for testing
              elif isinstance(nx_next_pkt,arp.arp):
                 packed += struct.pack('!6s6sH', dst,src,ether.ETH_TYPE_ARP)
              else:#we assume everything else is IPv4
                 packed += struct.pack('!6s6sH', dst,src,ether.ETH_TYPE_IP)

              #removing the vlan header
              newPayload = b""
              newPayload += p[0:2]
              newPayload += struct.pack("!HL", message_length - 4, xid)
              newPayload += struct.pack("!IH", msg.buffer_id, msg.total_len - 4) 
              newPayload += p[14:24]
              buf = bytearray()
              new_packedmatch= match.pack(buf,0)
              newPayload += new_packedmatch
              newPayload += p[24 + len(buf):of13.OFP_HEADER_SIZE+of13.OFP_PACKET_IN_SIZE + 2]
              newPayload +=packed
              newPayload +=p[of13.OFP_HEADER_SIZE+of13.OFP_PACKET_IN_SIZE + 20:]
              
              outPackets.append(newPayload)
              return index,outPackets 
          elif eth_type != ether.ETH_TYPE_8021Q:
             print eth.ethertype," is NO vlan packet (this should not happen) "
             return index, None  
        elif t == of13.OFPT_PACKET_OUT:
             try:
                msg = of.OFPPacketOut.parser(datapath, ord(p[0]), msg_type, msg_len, xid, p)
                print "OUT msg ", msg
             except Exception, e:
                print e
                outPackets.append(p)
                return index, outPackets
            
             flood_action = 1
             end1 =0 
             ends = [] 
             updated_actions = []
               
             for a in msg.actions:
                 if a.type == 65535 :#Flood
                    flood_action = 1
                 else:
                    print "non flood action" 
             dl_vid = [] 
             lldp_check = 0
             arp_check = 0
             ip_check = 0
             try:
                dst, src, eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0) 
                pkt = packet.Packet(msg.data) 
                i = iter(pkt)
                eth_pkt = i.next()
                next_pkt = i.next()
                sec_pkt = None 
             except:
                #the packet out message does not contain an ethernet packet
                return index, None
             eth = pkt.get_protocols(ethernet.ethernet)[0]
             if eth.ethertype == ether.ETH_TYPE_LLDP: 
                packed = b""
                packed += struct.pack('!6s6sH', BROADCAST,src,ether.ETH_TYPE_LLDP)
                lldp_check = 1
                if msg.in_port != of13.OFPP_CONTROLLER:
                   return index, None # there could not be an out message from anyone except the controller
             elif eth.ethertype == ether.ETH_TYPE_ARP:
                packed = b""
                packed += struct.pack('!6s6sH', dst,src,ether.ETH_TYPE_ARP)
                arp_check = 1
                print "Arp packet from the controller"  
             elif eth.ethertype == ether.ETH_TYPE_IP:
                packed = b""
                packed += struct.pack('!6s6sH', BROADCAST,src,ether.ETH_TYPE_IP)
                ip_check = 1 
                print "IP packet from the controller"
                if icmp.icmp in pkt:
                   print "ICMP packet"

             if lldp_check == 1:#this lldp packet has originated from the controller
                 print "lldp check 1 ", len(dl_vid)
                 spliter =  msg.data[0:6]#this is LLDP_DST
                 payloads = msg.data.split(spliter)
                 updated_actions = []
                 paycount = 0
                 for pay in payloads:
                  if paycount == 0:
                     paycount += 1
                  else: 
                     updated_actions = []  
                     dl_vid = []
                     packed = b""
                     packed += struct.pack('!6s6sH', BROADCAST,src,ether.ETH_TYPE_LLDP)
                     new_pay = b""
                     new_pay += packed
                     new_pay += pay[8:]
                     pktt = packet.Packet(new_pay)
                     i = iter(pktt)
                     eth_pkt = i.next()
                     next_pkt = i.next()    
                     tlv_port_id = next_pkt.tlvs[1].port_id
                     print "tlv_port_id: ", tlv_port_id
                     try:
                        outport = int(tlv_port_id)
                     except :
                        outport = 0
                     if outport in self.portVlanMapping:
                        dl_vid.append(self.portVlanMapping[outport])
                     if eth.ethertype != ether.ETH_TYPE_8021Q:
                        c = of.OFPActionPushVlan(ether.ETH_TYPE_8021Q)
                        c.len = of13.OFP_ACTION_PUSH_SIZE
                        c.type = of13.OFPAT_PUSH_VLAN
                        updated_actions.append(c)

             
                     for vid in dl_vid:
                         f = of.OFPMatchField.make(of13.OXM_OF_VLAN_VID, vid)
                         updated_actions.append(of.OFPActionSetField(f))
                         if msg.in_port == 1:
                            updated_actions.append(of.OFPActionOutput(of13.OFPP_IN_PORT))
                         else:
                            updated_actions.append(of.OFPActionOutput(1))
                     if outport != 0 and outport != 1:
                        t_msg= of.OFPPacketOut(
                datapath= datapath, in_port=of13.OFPP_CONTROLLER,
                buffer_id= msg.buffer_id,#of13.OFP_NO_BUFFER,
                actions=updated_actions,
                data=new_pay)
                        print "OUT dl_vid ", self.portVlanMapping[outport]
                        t_msg.serialize()
                        outPackets.append(t_msg.buf)
                 if len(outPackets) == 0:
                    return index,None
                 
                 return index,outPackets
             elif flood_action == 1:# for the pacets that are not in lldp_check we check if the action is flood 
                if msg.in_port in self.portVlanMapping:
                  #this probably is not going to happen
                  originVlan = self.portVlanMapping[msg.in_port]
                  originCustomer = self.vlanCustomerMapping[originVlan]
                  for vlanId in self.customerVlanList[originCustomer] :
                    if vlanId != originVlan:
                       dl_vid.append(vlanId)
                else:#this packet has originated from the controller
                  for port in self.portVlanMapping:
                    dl_vid.append(self.portVlanMapping[port]) 

             if arp_check == 1 or ip_check == 1:
                if flood_action != 1: #currently we only handle the flooding case from the controller  
                     print "no flood in arp check ip check"
                else: 
                     print "arp check ip check"
                     updated_actions = []
                     
                     c = of.OFPActionPushVlan(ether.ETH_TYPE_8021Q)
                     c.len = of13.OFP_ACTION_PUSH_SIZE
                     c.type = of13.OFPAT_PUSH_VLAN
                     updated_actions.append(c)


                     for vid in dl_vid:
                         f = of.OFPMatchField.make(of13.OXM_OF_VLAN_VID, vid)
                         updated_actions.append(of.OFPActionSetField(f))
                         if msg.in_port == 1:
                            updated_actions.append(of.OFPActionOutput(of13.OFPP_IN_PORT))
                         else:
                            updated_actions.append(of.OFPActionOutput(1))
                     
                     t_msg= of.OFPPacketOut(
                datapath=datapath, in_port=of13.OFPP_CONTROLLER,
                buffer_id=msg.buffer_id,#of13.OFP_NO_BUFFER,
                actions=updated_actions,
                data=msg.data)
                     t_msg.serialize()
                     outPackets.append(t_msg.buf)
                     if len(outPackets) == 0:
                        return index,None
                     else:
                        print "sending out arp packet"
                        return index,outPackets
             elif eth.ethertype == ether.ETH_TYPE_8021Q:#if lldp_check == 1 
                   return index,None  
             else:
               print "The controller packet either has a type that is not handled yet or sending a non-flood action!"
               return index, None#outPackets
             
             print "Ultimately the code should never come here" 
             return index,None    
        elif t == of13.OFPT_FLOW_MOD:
          try: 
             msg = of.OFPFlowMod.parser( datapath, version, msg_type, msg_len, xid, p)
             print "OFPT_FLOW_MOD msg ", msg
          except Exception, e:
             print e
             outPackets.append(new_msg.buf)
             return index, outPackets 
          dl_vid = []
          actions =[]
          new_inst = [] 
          for a in msg.instructions:
           if isinstance(a, of.OFPInstructionActions):
            for ac in a.actions:
              if isinstance(ac,of.OFPActionOutput):
                 dl_vid.append(self.portVlanMapping[ac.port])
                 f = of.OFPMatchField.make(of13.OXM_OF_VLAN_VID, dl_vid[0])
                 actions.append(of.OFPActionSetField(f))
                 actions.append(of.OFPActionOutput(of13.OFPP_IN_PORT))
              else:
                 actions.append(ac)
            a.actions = actions
            new_inst.append(a)
           else:
            new_inst.append(a)   
         
          new_msg = of.OFPFlowMod(
            datapath=datapath, cookie=msg.cookie, cookie_mask=msg.cookie_mask, table_id=msg.table_id,command=msg.command, idle_timeout=msg.idle_timeout, hard_timeout=msg.hard_timeout,priority=msg.priority, buffer_id=msg.buffer_id,out_port=msg.out_port,out_group=msg.out_group,flags=msg.flags, match=msg.match, instructions=new_inst)
          new_msg.xid = xid
          new_msg.serialize()
          outPackets.append(new_msg.buf)
          return index, outPackets 

        elif t == of13.OFPT_ERROR:
          try: 
                msg = of.OFPErrorMsg.parser( datapath, version, msg_type, msg_len, xid, p)
                print "msg ", msg
          except Exception, e:
                print e
                outPackets.append(p)
                return index, outPackets
        elif t == of13.OFPT_MULTIPART_REQUEST:
          print "OFPT_MULTIPART_REQUEST"
         
        elif t == of13.OFPT_MULTIPART_REPLY:
          try:
                msg = of.OFPMultipartReply.parser( datapath, version, msg_type, msg_len, xid, p)
                print "OFPT_MULTIPART_REPLY ",msg 
          except Exception, e:
                print e
                outPackets.append(p)
                return index, outPackets
          outPackets.append(p)
          return index, outPackets
          #right now we return before this because the rest is not desirable  
          if msg.type == of13.OFPMP_PORT_DESC:
             print "PortDesc might need to be updated"
             for port in msg.body: 
                 if port.port_no == 1:
                    config = port.config
                    state = port.state
                    curr = port.curr
                    advertised = port.advertised
                    supported = port.supported
                    peer = port.peer
                    curr_speed = port.curr_speed
                    max_speed = port.max_speed
             fakePorts = []
             port_no = 2
             hw_addr = 'c0:26:53:c4:29:e2'
             name = 'etp2'
             i = of.OFPPort(port_no, hw_addr, name, config, state, curr,
                    advertised, supported, peer, curr_speed, max_speed)
             fakePorts.append(i)
             
             port_no = 3
             hw_addr = 'c2:16:a3:c4:26:13'
             name = 'etp3'
             i = of.OFPPort(port_no, hw_addr, name, config, state, curr,
                    advertised, supported, peer, curr_speed, max_speed)
             fakePorts.append(i)

             port_no = 4
             hw_addr = 'c0:33:73:48:00:24'
             name = 'etp4'
             i = of.OFPPort(port_no, hw_addr, name, config, state, curr,
                    advertised, supported, peer, curr_speed, max_speed)
             fakePorts.append(i) 

             msg.body = fakePorts

             for port in msg.body:
                 print "body ", port

             msg.serialize()
             outPackets.append(msg.buf)
             return index, outPackets 
       
          if msg.type == of13.OFPMP_PORT_STATS:
             print "PortStat might need to be updated"

             outPackets.append(p)
             return index, outPackets 

             for port in msg.body:
                 if port.port_no == 1:
                    rx_packets = port.rx_packets
                    tx_packets = port.tx_packets
                    rx_bytes = port.rx_bytes
                    tx_bytes = port.tx_bytes
                    rx_dropped = port.rx_dropped
                    tx_dropped = port.tx_dropped
                    rx_errors = port.rx_errors
                    tx_errors = port.tx_errors
                    rx_frame_err = port.rx_frame_err
                    rx_over_err = port.rx_over_err
                    rx_crc_err = port.rx_crc_err
                    collisions = port.collisions
                    duration_sec = port.duration_sec
                    duration_nsec = port.duration_nsec

             fakeStats = []
              
             port_no = 2 
             i = of.OFPPortStats(port_no, rx_packets, tx_packets,
                           rx_bytes, tx_bytes, rx_dropped, tx_dropped,
                           rx_errors, tx_errors, rx_frame_err,
                           rx_over_err, rx_crc_err, collisions, duration_sec, duration_nsec)   
             fakeStats.append(i)

             msg.body = fakeStats


             msg.serialize()
             outPackets.append(msg.buf)
             return index, outPackets 

        elif t == of13.OFPT_FEATURES_REPLY:
          try:
                msg = of.OFPSwitchFeatures.parser(datapath, version, msg_type, msg_len, xid, p)
                print "features reply might need to be updated", msg
          except Exception, e:
                print e
                outPackets.append(p)
                return index, outPackets  
        elif t == of13.OFPT_HELLO:
          try:
                msg = of.OFPHello.parser(datapath, version, msg_type, msg_len, xid, p)
          except Exception, e:
                print e
                outPackets.append(p)
                return index, outPackets
        outPackets.append(p)
        return index, outPackets
 
if __name__ == '__main__':
        server = TheServer('', 9050)
        LLDP_TEST = 0
        PING_TEST =1
        try:
           if PING_TEST == 1 :
           #for this to work it is important that only one ovs switch is active per each physical switch 
            for x in range(2, 5):
                print x
                server.configure_port_mapping(x, x+3)
                server.configure_vlan_mapping( x+3,x)
                server.configure_vlan_customer_mapping( x+3,4002)
                server.configure_customer_vlan_list( 4002, x+3) #this is a list unlike others 
            server.configure_customer_controller_mapping(4002, controller1)
           elif LLDP_TEST == 1:
            for x in range(2, 4):
                print x
                server.configure_port_mapping(x, x+3)
                server.configure_vlan_mapping( x+3,x)
                server.configure_vlan_customer_mapping( x+3,x+4000)
                server.configure_customer_vlan_list( x+4000, x+3)

            x = 4
            server.configure_port_mapping(x, x+3)
            server.configure_vlan_mapping( x+3,x)
            server.configure_vlan_customer_mapping( x+3,4003)
            server.configure_customer_vlan_list( 4003, x+3)

            server.configure_customer_controller_mapping(4002, controller1)

            server.configure_customer_controller_mapping(4003, controller2)     
           else:
            for x in range(2, 4):
                print x
                server.configure_port_mapping(x, x+3)
                server.configure_vlan_mapping( x+3,x)
                server.configure_vlan_customer_mapping( x+3,4002)
                server.configure_customer_vlan_list( 4002, x+3)
            server.configure_customer_controller_mapping(4002, controller1)     
            server.configure_customer_controller_mapping(4003, controller2)
            x = 4
            server.configure_port_mapping(x, x+3)
            server.configure_vlan_mapping( x+3,x)
            server.configure_vlan_customer_mapping( x+3,4003)
            server.configure_customer_vlan_list( 4003, x+3)

           server.main_loop()

        except KeyboardInterrupt:
            print "Ctrl C - Stopping server"
            sys.exit(1)
