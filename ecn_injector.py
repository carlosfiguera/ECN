import socket
import struct
import threading
import time
import sys
from optparse import OptionParser

ETH_P_IP = 0x0800 # Internet Protocol Packet

def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+= ord(data[i]) + (ord(data[i+1]) << 8)
    if n:
        s+= ord(data[i+1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s

def send(network, transport, payload="Payload for ECN usage in TUCAN3G", iface=None, retry=3, timeout=1):
    if timeout<=0:
        # Avoid entering an infinite waiting loop
        timeout = 0.1
    response = []
    event = threading.Event()
    sock = socket.socket(socket.AF_INET,
                         socket.SOCK_RAW,
                         socket.IPPROTO_RAW)
    # Extracting identifiers
    # ip
    src = network.source
    dst = network.destination
    # port
    srcp = struct.pack("!H", transport.srcp)
    dstp = struct.pack("!H", transport.dstp)
    
    transport.payload = payload
    packet = network.pack() + transport.pack(network.source, network.destination) + payload
    
    sock.sendto(packet, (socket.inet_ntoa(dst), 0))


class layer():
    pass

class IP(object):
    def __init__(self, source, destination,ecn):
                self.version = 4
                self.ihl = 5 # Internet Header Length
                if ecn == 0:
			self.tos = 0x02 # Type of Service  ##assuming DSCP=0 ECN=0
		else:
			self.tos = 0x03 # Type of Service  ##assuming DSCP=0 ECN=1
		#here it would be interesting add a funcionality with dynamic DSCP
		
                self.tl = 0 # total length will be filled by kernel
                self.id = 54321
                self.flags = 0
                self.offset = 0
                self.ttl = 65
		#self.protocol = socket.IPPROTO_TCP ##para TCP
                self.protocol = socket.IPPROTO_UDP
                self.checksum = 0 # will be filled by kernel
                self.source = socket.inet_aton(source)
                self.destination = socket.inet_aton(destination)
    def pack(self):
        ver_ihl = (self.version << 4) + self.ihl
        flags_offset = (self.flags << 13) + self.offset
        ip_header = struct.pack("!BBHHHBBH4s4s",
                    ver_ihl,
                    self.tos,
                    self.tl,
                    self.id,
                    flags_offset,
                    self.ttl,
                    self.protocol,
                    self.checksum,
                    self.source,
                    self.destination)
        return ip_header
    def unpack(self, packet):
            _ip = layer()
            _ip.ihl = (ord(packet[0]) & 0xf) * 4
            iph = struct.unpack("!BBHHHBBH4s4s", packet[:_ip.ihl])
            _ip.ver = iph[0] >> 4
            _ip.tos = iph[1]
            _ip.length = iph[2]
            _ip.ids = iph[3]
            _ip.flags = iph[4] >> 13
            _ip.offset = iph[4] & 0x1FFF
            _ip.ttl = iph[5]
            _ip.protocol = iph[6]
            _ip.checksum = hex(iph[7])
            _ip.src = socket.inet_ntoa(iph[8])
            _ip.dst = socket.inet_ntoa(iph[9])
            _ip.list = [
                _ip.ihl,
                _ip.ver,
                _ip.tos,
                _ip.length,
                _ip.ids,
                _ip.flags,
                _ip.offset,
                _ip.ttl,
                _ip.protocol,
                _ip.src,
                _ip.dst]
            return _ip

class UDP(object):
    def __init__(self, srcp, dstp):
        self.srcp = srcp
        self.dstp = dstp 
        self.length = 0
        self.checksum = 0
        self.payload = ""


    def pack(self, source, destination):
        udp_hdr = struct.pack('!HHHH', self.srcp, self.dstp,
        self.length,
        self.checksum)
       #Pseudo header
        psip = source
        pdip = destination
        reserved = 0
        proto = socket.IPPROTO_UDP
        tlen = len(udp_hdr) + len(self.payload)
        pshdr = struct.pack('!4s4sBBH',
                psip,
                pdip,
                reserved,
                proto,
                tlen)
        pshdr = pshdr + udp_hdr+ self.payload
        udp_checksum = checksum(pshdr)
        udp_hdr = struct.pack('!HHH',
                  self.srcp,self.dstp,
                  tlen)
             

        udp_checksum = struct.pack('H',udp_checksum)
        udp_hdr = udp_hdr + udp_checksum + self.payload
        return udp_hdr

    def unpack(self, packet):
        cflags = { # Control flags
            32:"U",
            16:"A",
            8:"P",
            4:"R",
            2:"S",
            1:"F"}
        _tcp = layer()
        _tcp.thl = (ord(packet[12])>>4) * 4
        _tcp.options = packet[20:_tcp.thl]
        _tcp.payload = packet[_tcp.thl:]
        tcph = struct.unpack("!HHLLBBHHH", packet[:20])
        _tcp.srcp = tcph[0] # source port
        _tcp.dstp = tcph[1] # destination port
        _tcp.seq = tcph[2] # sequence number
        _tcp.ack = hex(tcph[3]) # acknowledgment number
        _tcp.flags = ""
        for f in cflags:
            if tcph[5] & f:
                _tcp.flags+=cflags[f]
        _tcp.window = tcph[6] # window
        _tcp.checksum = hex(tcph[7]) # checksum
        _tcp.urg = tcph[8] # urgent pointer
        _tcp.list = [
            _tcp.srcp,
            _tcp.dstp,
            _tcp.seq,
            _tcp.ack,
            _tcp.thl,
            _tcp.flags,
            _tcp.window,
            _tcp.checksum,
            _tcp.urg,
            _tcp.options,
            _tcp.payload]
        return _tcp

    
def main():
    parser = OptionParser()
    parser.add_option("-s", "--src", dest="src", type="string",
                      help="Source IP address", metavar="IP")
    parser.add_option("-d", "--dst", dest="dst", type="string",
                      help="Destination IP address", metavar="IP")
    parser.add_option("-q", "--load", dest="q", type="string",
                      help="Load level from 0-100", metavar="Load-level")
    options, args = parser.parse_args()
    
    if options.dst == None:
        parser.print_help()
        sys.exit()
    else:
        dst_host = socket.gethostbyname(options.dst)
    if options.src == None:
        # Get the current Network Interface
        src_host = socket.gethostbyname(socket.gethostname())
    else:
        src_host = options.src
    if options.q == None:
        parser.print_help()
        sys.exit()
    else:
        load = options.q

    #quality=0	#manually set
    ratio=float(0.5)
    total_sent=float(0)
    ecn1_sent=float(0)  
    while 1:
	pkt_obj=float(load)/100
	if pkt_obj >= ratio:
		#print "1"
		ipobj = IP(src_host, dst_host,1)
		udpobj = UDP(1234, 80)
		send(ipobj, udpobj, iface="eth0", retry=1, timeout=0.3)
		ecn1_sent=ecn1_sent+1
	else:
		#print "0"
		ipobj = IP(src_host, dst_host,0)
		udpobj = UDP(1234, 80)
		send(ipobj, udpobj, iface="eth0", retry=1, timeout=0.3)	
	total_sent=total_sent+1
	ratio=float(ecn1_sent/total_sent)
	time.sleep(0.1)
	
if __name__=="__main__":
    main()
	


