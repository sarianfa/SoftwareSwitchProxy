#!/usr/bin/python
# This is a simple port-forward / proxy, written using only the default python
import socket
import select
import time
import sys
import struct 
# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 8096
delay = 0.0001
forward_to = ('192.168.1.40', 6633)
_PAD = b'\x00'
_PAD2 = _PAD*2
_PAD3 = _PAD*3
_PAD4 = _PAD*4
_PAD6 = _PAD*6 
OFPXMC_OPENFLOW_BASIC= 0x8000
OFPXMT_OFB_VLAN_VID= 6
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
 
    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)
 
    def main_loop(self):
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break
 
                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                else:
                    self.on_recv()
 
    def on_accept(self):
        forward = Forward().start(forward_to[0], forward_to[1])
        clientsock, clientaddr = self.server.accept()
        if forward:
            print clientaddr, "has connected"
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            print "Can't establish connection with remote server.",
            print "Closing connection with client side", clientaddr
            clientsock.close()
 
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
        ofp_version = ord(data[0])
        ofp_type = ord(data[1])
        data_length = ord(data[2]) << 8 | ord(data[3])
        #message_length, xid = struct.unpack_from('!HL', data, 2)
        #print "xid ", xid
        print ofp_type
       
        #h = self.ofp_handlers.get(ofp_type)
        #xid =4,5,6,7
        offset =8;
        if(ofp_type == 13):
           
           buffer_id = struct.unpack_from('!L', data,offset)[0]
           print "buffer_id ", buffer_id
           offset = offset +4
           inPort = struct.unpack_from('!L', data, offset)[0]
           print "inPort ", inPort 
           offset = offset +4
           copied = data[:offset]
           
           actsLen = struct.unpack_from('!H', data, offset)[0] 
           print "actsLen ", actsLen
           offset = offset +2

           ''' 
           cacttype= 0x0011
           cactlen = 0x0008
           cactethertype= 0x8100 
           pushVlanAction = ""
           pushVlanAction+= struct.pack("!H",cacttype) 
           pushVlanAction+= struct.pack("!H",cactlen)
           pushVlanAction+= struct.pack("!H",cactethertype)
           pushVlanAction+= _PAD2
           
           cacttype= 0x0019
          
           setfieldAction = ""
           setfieldAction+= struct.pack("!H",cacttype)
          
           oxm_class= struct.pack("!H",OFPXMC_OPENFLOW_BASIC)
           oxm_fieldh = OFPXMT_OFB_VLAN_VID << 1 & 1
           oxm_field = struct.pack("!B",oxm_fieldh)
          
           #oxm_field = oxm_field << 1 & oxm_hasmask
           oxm_length= struct.pack("!B",8)
           oxm_vid = struct.pack("!H",0x0005)
           oxm_vid_mask = struct.pack("!H",0x0fff)
           oxmTLV = ""
           oxmTLV += oxm_class 
           oxmTLV += oxm_field 
           oxmTLV += oxm_length 
           oxmTLV += oxm_vid 
           oxmTLV += oxm_vid_mask    
           setfieldlen = len (oxmTLV) + 8
           print "length of oxmTLV ", len(oxmTLV) 
           setfieldAction+= struct.pack("!H",setfieldlen)
           setfieldAction+=oxmTLV  
          
           cact = actsLen + len (pushVlanAction)+ len (setfieldAction)
           copied+= struct.pack("!H",cact)
           copied+= _PAD6
           copied+=pushVlanAction
           copied+=setfieldAction
           cactsLen = struct.unpack_from('!H', copied, offset+8)[0]
           print "cactlength ", cactsLen
           ''' 
           #the nextone is a pad
           offset = offset + 6;
           actsend = offset + actsLen
           print "acts end at ", actsend
           acttype = struct.unpack_from('!H', data, offset)[0]
           print "acttype ", acttype
           offset = offset +2
           actLen = struct.unpack_from('!H', data, offset)[0]
           print "actLen ", actLen
           offset = offset +2
           
           if (acttype == 0):#this is an output act
              outPort = struct.unpack_from('!L', data, offset)[0]
              print "outPort ", outPort
              offset = offset +4 
              maxlen = struct.unpack_from('!H', data, offset)[0]
              print "maxlen ", maxlen
              offset = offset +2
              #pad
              offset= offset +6
              print "offset at ", offset, " data length ",data_length
              if(offset < data_length):
                print data[offset:] 
                
              
           #while (offset < acts_end) {
         #offset = dissect_openflow_action_v4(tvb, pinfo, tree, offset, length);
           #after this the data part starts, openflow_packet_out_v4
            
               
           #act0 = struct.unpack_from('!L', data, 24)[0]
           #print "act0 ", act0      
           #      elif (start == 24):
           #         print "type, ", data[start:start+2]
           #         print "length, ", data[start+2:start+4]
           #print data[40:]
        self.channel[self.s].send(data)
 
if __name__ == '__main__':
        server = TheServer('', 9090)
        try:
            server.main_loop()
        except KeyboardInterrupt:
            print "Ctrl C - Stopping server"
            sys.exit(1)
