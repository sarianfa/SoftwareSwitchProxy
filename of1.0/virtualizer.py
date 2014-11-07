#!/usr/bin/python
# This is a simple port-forward / proxy, written using only the default python
import socket
import select
import time
import sys
import struct
import libopenflow_01 as of
import ethernet as ether
from vlan import vlan as vlan
from packet_base import packet_base as pkt 
from lldp import lldp as lldp
from copy import deepcopy
# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can breake things
buffer_size = 32384#16192
delay = 0.0001
forward_to = ('192.168.1.40', 6633)
controller1 = '192.168.1.40'
controller2 = '192.168.1.50'
controller_port = 6633
 
OFPXMC_OPENFLOW_BASIC= 0x8000
OFPXMT_OFB_VLAN_VID= 6
VLAN_TYPE = 0x8100
FAKE_TYPE  = 0x0FED
#ETHER_BROADCAST      = EthAddr(b"\xff\xff\xff\xff\xff\xff")
HW_ADDR  = ether.EthAddr(b"\x54\x7f\xee\xa9\x5c\xee")
#HW_ADDR  = ether.EthAddr(b"\x90\xe2\xba\x45\xa1\x85")
#90:e2:ba:45:a1:85
#HW_ADDR  = ether.EthAddr(b"\x54\x7f\xee\xa9\x5d\x06")
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
 
    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)
    
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
           print "added vlan to existing list ", vlan 
        else:    
           self.customerVlanList[customer] = []
           self.customerVlanList[customer].append(vlan)
           print "Inserted vlan to new list ", vlan
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
        #it normally comes here everytime a client tries to open a connection
        #appends first the client connection then the server connection to the input list, the proxy itself was already appended
        #ToDo: I have to somehow make the channel[clientsock] to map to more than one server socket, not just to forward but to forward2,.. 
        #or may be instead of channel[clientsock] it should be channel of something else, like channel of vlan, or no channel, or something
        #the things that get added to the channel should be done before coming to this point, just with the definition of a new server
        #lets do it this way that thechannel[] information only shows the next one is in server direction or the client direction, and does not return the actual socket itself, in the server direction then it also needs to retun an index  
        forward = Forward().start(forward_to[0], forward_to[1])
        forward2 = Forward().start(controller2, controller_port)
        clientsock, clientaddr = self.server.accept()
        if forward:
            print clientaddr, "has connected to controller"
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.input_list.append(forward2)
           #forward directin is 1, backward direction is 2, but how you say which one in forward direction??
           #self.channel[clientsock] could be either foward or forward1, how to decide?
            #self.channel[clientsock] = forward
            
            self.channel[forward] = clientsock
            self.channel[forward2] = clientsock
            
            self.sockaddr[clientsock]= clientaddr
            self.sockaddr[forward]= forward_to[0]
            self.sockaddr[forward2]= controller2 
            
            #self.addrsock['0.0.0.0']= forward
            #self.addrsock[clientaddr]= clientsock
            self.addrsock[forward_to[0]]= forward
            self.addrsock[controller2]= forward2 
        else:
            print "Can't establish connection with remote server ", forward_to[0]
            print "Closing connection with client side", clientaddr
            clientsock.close()
        if forward2:
            print clientaddr, "has connected to controller2"
        else:
            print "Can't establish connection with remote server ", controller2 
    def on_close(self):
      try:
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
      except:
        #pass
         return
    def on_recv(self):
        data = self.data
        # here we can parse and/or modify the data before send forward
        try: 
            index, p = self.parse_message()
            if p != None:
           #t = ord(p[1])
               i = 0 
               for outData in p:
                   i = i + 1
                   if i > 10:
                      print "outPackets index ", i
               #here somehow in the choice of channel it is embedded which one is the other end: if this came from the client, then it should get forwarded to the server and vise versa
              # we hav ethe problem because the addition of the new pair is triggered by a new connection from the client, and not by the number of servers    
                   if self.s in self.channel:
                      self.channel[self.s].send(outData)
                   else:
                      if index != '0.0.0.0':
                         print "Sending the previous packet to: ",index
                         self.addrsock[index].send(outData)
                      else:
                         #replicate the packet to all controllers
                         for server in self.addrsock:
                             self.addrsock[server].send(outData)
                   
        except Exception, e:
            #print e
            #pass
            return  

    def parse_message(self):
        outPackets = []
        p = self.data
        origin = self.sockaddr[self.s]
        index = '0.0.0.0'
        if(len(p) < 4):
          return index, None 
        t = ord(p[1])
        if ord(p[0]) != of.OFP_VERSION:
           print "Bad OpenFlow version while trying to capture messages", ord(p[0]), " vs. ", of.OFP_VERSION
           return index, None
        

        packet_length = ord(p[2]) << 8 | ord(p[3])
        #if packet_length < 8:
        #   return None
        #this is assuming the message size is never bigger than the buffer size
        if packet_length != len(p) and 2*packet_length != len(p):
           print "packet length is: ",packet_length,"real length ",len(p)," for ",t," version ", ord(p[0]), " ord(p[2]) ", ord(p[2])," ord(p[3]) ", ord(p[3]), " self.s ", self.s  
              #ToDo "this logic needs to be changed"
              #return None 
        #if packet_length > len(p) and t != 0:
           #return index, None
       #the next 2 lines are for not changing the message format
        #outPackets.append(p)
        #return index, outPackets 

        message_length, xid = struct.unpack_from('!HL', p, 2) 
        if t == of.OFPT_PACKET_IN:
          if 4*packet_length < len(p):
             print "packet length is: ",packet_length,"real length ",len(p)," for ",t 
             return index,None
          try:
           l,p = of.ofp_packet_in.unpack_new(p)
           if l == 0 and p == 0:
             #print "something wrong during unpacking"
             return index,None
          except Exception, e:
             return index, None  
          #print "Switch packet early on"
          #print p.show()
          #print "p.toatal len ", p.total_len
          #print p._validate()
          #print "Switch packet before change"
          #print p.show()
          in_port = p.in_port
          eth = of.ethernet(p.data)
          lldp_check = 0  
          vlan_check =0
          ip_check = 0
          arp_check = 0
          lldphh = of.ethernet(type=of.ethernet.LLDP_TYPE)
          lldphh.src = eth.src
          lldphh.dst = eth.dst
          headersize = len(lldphh)
          vlanhdr = headersize + 2
          llPayload = lldphh.pack()
          #llPayload += p.data[vlanhdr+2:]
          lldph = of.ethernet(llPayload)  
          lldph.payload =  p.data[vlanhdr+2:]
          if eth.type == FAKE_TYPE:
             print "print fake_type"
             eth.dst = ether.LLDP_MULTICAST
             eth.type = of.ethernet.LLDP_TYPE
             lldph.type = eth.type
             lldph.dst = eth.dst 
             lldp_check = 1
          elif eth.type == VLAN_TYPE:
              lldph.type = eth.effective_ethertype
              vlan_check = 1
              
              #ToDo: depending on the labels, these values might be different
              customerid = self.vlanCustomerMapping[eth.payload.id]
              controllerSocketid = self.customerControllerMapping[customerid]
              index = controllerSocketid
              #print "Switch packet before change"
              #print p.show()
              #print eth.payload
              #if str(eth.src) == str(HW_ADDR):
              #   print str(eth.src)
              #   return index,None
              #print "vlan id is ", eth.payload.id
              #print "Controller id is ",index  
              if vlan_check: #ToDo: this is a lldp packet, what if it is a data packet
                 if lldph.type == FAKE_TYPE:
                    lldph.type = of.ethernet.LLDP_TYPE 
                    lldph.dst = ether.LLDP_MULTICAST
                    lldp_check = 1
                 elif eth.effective_ethertype == of.ethernet.IP_TYPE:
                    ip_check = 1
                    print "Setting ip check" 
                 elif eth.effective_ethertype == of.ethernet.ARP_TYPE:
                    print "Setting arp check"
                    arp_check = 1
                 else:
                    print "Setting no check"
          else:
             return index,None         
          #if lldp_check == 0:
          #   outPackets.append(p.pack())
             
          #   return index, outPackets
          if lldp_check == 1 or arp_check == 1:# isinstance(lldph, of.ethernet):
             po = of.ofp_packet_in()
             po.xid = xid
             po.buffer_id = p.buffer_id
             po.reason = p.reason
             po.total_len = len(po) + len(lldph) #ToDo: this should be p_total_len -vlanheader.size
             try:
                if vlan_check ==1 or lldp_check == 1: 
                   po.data = lldph
                   
             except Exception as e:
                print "an error inserting lldphd" 
                
                return index, None
             if eth.type == VLAN_TYPE and p.in_port != 65534:
                #this is where the real thing happens 
                #assume it is always vlan tagged, and the inport was 1
                #the actual vlan tag is in eth.payload.id 
                po.in_port = self.vlanPortMapping[eth.payload.id]
                print "real inport not 65534, while fake one is ", po.in_port

             else: 
                print "inport is 65534"
                po.in_port = p.in_port
             #if lldp_check == 0: 
                #print "Switch packet after change"
                #print po.show()
                #print eth.payload
             outPackets.append(po.pack())
             #here it should identify which server is supposed to receive this  
             return index, outPackets
          elif lldp_check == 0 and arp_check == 0:# isinstance(lldph, of.ethernet):
             po = of.ofp_packet_in()
             po.xid = xid
             po.buffer_id = p.buffer_id
             po.reason = p.reason
             po.total_len = len(p.data) - 2 #ToDo: this should be p_total_len -vlanheader.size
             try:
                if ip_check ==1 :
                   iphh = of.ethernet(type=of.ethernet.IP_TYPE)
                   iphh.src = eth.src
                   iphh.dst = eth.dst
                   headersize = len(iphh)
                   vlanhdr = headersize + 2
                   iPayload = iphh.pack()
          #llPayload += p.data[vlanhdr+2:]
                   iph = of.ethernet(iPayload)
                   iph.payload =  p.data[vlanhdr+2:]
                   po.total_len = len(po) + len(iph)
                   po.data = iph#the icmp/arp packet but without the vlan
                   print "in ip-check 1"
                   ipp = of.ipv4(iph.payload)
                   print ipp
                if arp_check == 1 :
                   
                   iphh = of.ethernet(type=of.ethernet.ARP_TYPE)
                   iphh.src = eth.src
                   iphh.dst = eth.dst
                   headersize = len(iphh)
                   vlanhdr = headersize + 2
                   iPayload = iphh.pack()
          #llPayload += p.data[vlanhdr+2:]
                   iph = of.ethernet(iPayload)
                   iph.payload =  p.data[vlanhdr+2:]
                   po.total_len = len(po) + len(iph)
                   po.data = iph
                   print "in arp-check 1"
                   print iph.payload
             except Exception as e:
                print "an error inserting lldphd"

                return index, None
             if eth.type == VLAN_TYPE and p.in_port != 65534:
                #this is where the real thing happens 
                #assume it is always vlan tagged, and the inport was 1
                #the actual vlan tag is in eth.payload.id 
                po.in_port = self.vlanPortMapping[eth.payload.id]
                print "real inport not 65534, while fake one is ", po.in_port

             else:
                print "inport is 65534"
                po.in_port = p.in_port
             if lldp_check == 0:
                print "Switch packet non-lldp after change"
                print po.show()
                print eth.payload
             outPackets.append(po.pack())
             #here it should identify which server is supposed to receive this  
             return index, outPackets
          else:
             return index, None
          outPackets.append(p.pack()) 
          return index, outPackets
        elif t == of.OFPT_PACKET_OUT:
          try:
           l,p = of.ofp_packet_out.unpack_new(p)
           if l ==0 and p ==0 :
             print "something wrong during unpacking"
             return index,None
          except Exception, e:
             return index, None 
          eth = of.ethernet.unpack(p.data)
          #print "Controller packet before change"
          #print p.show()
          if eth.type == of.ethernet.LLDP_TYPE:
             eth.type = FAKE_TYPE
             eth.dst = ether.ETHER_BROADCAST
          #here we assume the first action is always output
          #ToDo: we might need to change this when things get more complex
             if p.actions[0].port != 65534:
                #print "Controller packet before change"
                #print p.show()
                #ToDo: if it is port 65531 it means flood on all ports except the one that came in, now we do not have that port here
                vlanId = self.portVlanMapping[p.actions[0].port] 
                #for vlanId in (p.actions[0].port + 3, p.actions[0].port + 4): 
                if vlanId > 0 : 
                   po = of.ofp_packet_out()
                   po.xid = xid
                   po.buffer_id = p.buffer_id
                   po.in_port =p.in_port
                   po.data = eth#p.data
                   vlanAction = of.ofp_action_vlan_vid()
                   vlanAction.vlan_vid = vlanId
                   po.actions.append(vlanAction)
                   p.actions[0].port = 1 #it is always this one port, only the vlan differs
                   po.actions.append(p.actions[0])
                   #print "Controller packet after change"
                   #print po.show()
                   outPackets.append(po.pack())
                return index, outPackets
          if eth.type == of.ethernet.IP_TYPE or eth.type == of.ethernet.ARP_TYPE :
             #eth.type = FAKE_TYPE
             #eth.dst = ether.ETHER_BROADCAST
          #here we assume the first action is always output
          #ToDo: we might need to change this when things get more complex
             if p.actions[0].port != 65534 and p.actions[0].port != 65531:
                #print "Controller packet other case before change"
                #print p.show()
                #ToDo: if it is port 65531 it means flood on all ports except the one that came in, now we do not have that port here
                vlanId = self.portVlanMapping[p.actions[0].port]
                #for vlanId in (p.actions[0].port + 3, p.actions[0].port + 4): 
                if vlanId > 0 :
                   po = of.ofp_packet_out()
                   po.xid = xid
                   po.buffer_id = p.buffer_id
                   po.in_port =p.in_port
                   po.data = eth 
                   vlanAction = of.ofp_action_vlan_vid()
                   vlanAction.vlan_vid = vlanId
                   po.actions.append(vlanAction)
                   p.actions[0].port = 1 #it is always this one port, only the vlan differs
                   po.actions.append(p.actions[0])
                   print "Controller packet other case after change ",eth.type
                   print eth.dst 
                   print po.show()
                   outPackets.append(po.pack())
                return index, outPackets
             if p.actions[0].port == 65531:
                #print "Controller packet flooding case before change"
                originVlan = self.portVlanMapping[p.in_port] 
                originCustomer = self.vlanCustomerMapping[originVlan]
                for vlanId in self.customerVlanList[originCustomer] :
                    if vlanId != originVlan:
                       po = of.ofp_packet_out()
                       po.xid = xid
                       po.buffer_id = p.buffer_id
                       po.in_port =p.in_port
                       po.data = p.data 
                       vlanAction = of.ofp_action_vlan_vid()
                       vlanAction.vlan_vid = vlanId
                       po.actions.append(vlanAction)
                       p.actions[0].port = 1 #it is always this one port, only the vlan differs
                       po.actions.append(p.actions[0])
                       print "Controller packet flooding case after change ",eth.type
                       print eth.dst
                       print po.show()
                       print str(po.data)
                       print eth.payload
                       outPackets.append(po.pack())
                return index, outPackets
             outPackets.append(p.pack())
             return index, outPackets
        
        elif t == of.OFPT_FEATURES_REPLY:
          try:
           l,inp = of.ofp_features_reply.unpack_new(p)
          except Exception, e:
             return index, None
          config = 0
          state = 0
          curr = 0
          advertised = 0
          supported = 0
          peer = 0
          for port in inp.ports:
             #print "here is the feature reply" 
             #print port.show()
             if port.port_no == 1:
                config = port.config
                state = port.state
                curr = port.curr
                advertised = port.advertised
                supported = port.supported
                peer = port.peer
          #print inp.show() 
        
          fakePorts = []
          i = of.ofp_phy_port()
          i.port_no = 2
          i.hw_addr = ether.EthAddr(b"\x50\x77\x12\x44\x38\x52")
          i.name = "etp2"
          i.config= config
          i.state=state
          i.curr= curr
          i.advertised= advertised
          i.supported= supported
          i.peer= peer
          fakePorts.append(i)
          

          i = of.ofp_phy_port()
          i.port_no = 3
          i.hw_addr = ether.EthAddr(b"\x98\x70\x12\x14\x09\x53")
          i.name = "etp3"
          i.config= config
          i.state=state
          i.curr= curr
          i.advertised= advertised
          i.supported= supported
          i.peer= peer
          fakePorts.append(i)
 
          i = of.ofp_phy_port()
          i.port_no = 4
          i.hw_addr = ether.EthAddr(b"\xA8\xA0\xA2\xA4\xA9\x54")
          i.name = "etp4"
          i.config= config
          i.state=state
          i.curr= curr
          i.advertised= advertised
          i.supported= supported
          i.peer= peer
          fakePorts.append(i)  

          inp.ports = fakePorts
          outPackets.append(inp.pack())
          #print inp.show()
          #ToDo: this message should be sent to both controllers  
          return index, outPackets
          return index, None
          #return p
        elif t == of.OFPT_STATS_REQUEST:
             try:
              l,inp = of.ofp_stats_request.unpack_new(p) 
             except Exception, e:
              return index, None
             #print "stats request message"
             #print inp.show()
             outPackets.append(p)
             return index, outPackets
        elif t == of.OFPT_STATS_REPLY:
             try:
              l,inp = of.ofp_stats_reply.unpack_new(p) 
             except Exception, e:
              return index, None
             #print "stats reply message"
             #print inp.show()
             outPackets.append(p)
             return index, outPackets
        elif t == of.OFPT_ECHO_REQUEST:
             try: 
              l,inp = of.ofp_echo_request.unpack_new(p)
             except Exception, e:
              return index, None 
             #print "echo request message"
             #print inp.show()
             outPackets.append(p)
             return index, outPackets
        elif t == of.OFPT_ECHO_REPLY:
             try:
              l,inp = of.ofp_echo_reply.unpack_new(p)
             except Exception, e:
              return index, None   
             #print "echo reply message"
             #print inp.show()
             outPackets.append(p)
             return index, outPackets
        elif t == of.OFPT_FLOW_MOD:
             try:
              l,inp = of.ofp_flow_mod.unpack_new(p)
             except Exception, e:
              return index, None
             print "flow mod message"
             print inp.show()
             clonedActions = []
             for action in inp.actions: 
              if action.type == of.OFPAT_OUTPUT:
                print "output action port is ", action.port
                print "it vlan mapping is ", self.portVlanMapping[action.port] 
                clonedActions.append(of.ofp_action_vlan_vid(vlan_vid = self.portVlanMapping[action.port]))            
                clonedActions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
              else:
                clonedActions.append(action)
             actions = []
             actions.append(of.ofp_action_vlan_vid(vlan_vid = 120))
             print "middle 1"
             
             actions.append(of.ofp_action_output(port = 1))
             print "middle 2"
             
             clonedMatch = inp.match.clone()
             #this should be added if there is any info regarding input port in the match 
             #clonedMatch.dl_vlan = 50
             
             print "cloned match is "  
             msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            actions=clonedActions,
                            match=clonedMatch)

             print "new match is " 

             msg.match.show()
             outPackets.append(msg.pack())
             return index, outPackets
        elif t == of.OFPT_PORT_MOD:
             try:
              l,inp = of.ofp_port_mod.unpack_new(p)
             except Exception, e:
              return index, None
             print "port mod message"
             print inp.show()
             outPackets.append(p)
             return index, outPackets
        elif t == of.OFPT_SET_CONFIG:
             try:
              l,inp = of.ofp_set_config.unpack_new(p)
             except Exception, e:
              return index, None
             print "set config mod message"
             print inp.show()
             outPackets.append(p)
             return index, outPackets 
        elif t == of.OFPT_QUEUE_GET_CONFIG_REQUEST or t == of.OFPT_QUEUE_GET_CONFIG_REPLY or t == of.OFPT_BARRIER_REPLY or t == of.OFPT_BARRIER_REQUEST or t == of.OFPT_FLOW_REMOVED or t == of.OFPT_PORT_STATUS or t == of.OFPT_ERROR or t == of.OFPT_HELLO or t == of.OFPT_VENDOR or t == of.OFPT_FEATURES_REQUEST or t == of.OFPT_GET_CONFIG_REQUEST or t == of.OFPT_GET_CONFIG_REPLY :
          print "Openflow message type: ", t
          outPackets.append(p)
          return index, outPackets
        else:
          return index, None   
        #assert l == len(p)


if __name__ == '__main__':
        server = TheServer('', 9050)
        LLDP_TEST = 1
        PING_TEST =0
        try:
           if PING_TEST == 1:
           #for this to work it is important that only one ovs switch is active per each physical switch 
            for x in range(2, 5):
                print x
                server.configure_port_mapping(x, x+3)  
                server.configure_vlan_mapping( x+3,x)       
                #server.configure_vlan_customer_mapping( x+3,x+4000)
                server.configure_vlan_customer_mapping( x+3,4002)
                server.configure_customer_vlan_list( 4002, x+3) #this is list unlike others 
            server.configure_customer_controller_mapping(4002, controller1) 
            #for multiple customers and controllers the following should go to different controller
            #server.configure_customer_controller_mapping(4002, controller2)     
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
                #server.configure_vlan_customer_mapping( x+3,x+4000)
            server.configure_vlan_customer_mapping( x+3,4003)
            server.configure_customer_vlan_list( 4003, x+3)

            server.configure_customer_controller_mapping(4002, controller1)

            server.configure_customer_controller_mapping(4003, controller2)       
           else:
            #this shoulrk but ovs's must be on different switches to prevent loops, or may be not? anyways there will be a loop?
            for x in range(2, 4):
                print x
                server.configure_port_mapping(x, x+3)
                server.configure_vlan_mapping( x+3,x)
                server.configure_vlan_customer_mapping( x+3,4002)
                server.configure_customer_vlan_list( 4002, x+3)
            server.configure_customer_controller_mapping(4002, controller1)            
            server.configure_customer_controller_mapping(4003, controller2)
            #for x= 4 just add this to one of existing customers
            x = 4
            server.configure_port_mapping(x, x+3)
            server.configure_vlan_mapping( x+3,x)
                #server.configure_vlan_customer_mapping( x+3,x+4000)
            server.configure_vlan_customer_mapping( x+3,4003)
            server.configure_customer_vlan_list( 4003, x+3) 

           server.main_loop()

        except KeyboardInterrupt:
            print "Ctrl C - Stopping server"
            sys.exit(1)
