import sys ; sys.path.insert(0, '../..')
#from sys import stdout
import ip, icmp, udp
import socket
import select
import time
import os
import getopt
import string
from optparse import OptionParser

#UDP Packet sniffer in python for Linux. 
# the output can be obtained in stdout
# a specific window size must be set

 
import socket, sys
from struct import *
 
def calcQoS(x):
	total=len(x)
	ones=0
	q=float(0)
	n=0
	
	for n in range(total):
		if x[n] == 1:
			ones=ones+1
	q=float(ones)/float(total)

	return q
def main():
    	parser = OptionParser()
	parser.add_option("-w", "--window", dest="win", type="int",
                      help="Window Size", metavar="WinSize")
	options, args = parser.parse_args()
	if options.win == None:
       		parser.print_help()
        	sys.exit()
   	else:
       		winSize = options.win
	
	#create an INET, STREAMing socket
	try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
	except socket.error , msg:
	    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	    sys.exit()
	i=0
	x = [0 for z in xrange(winSize)]
	# receive a packet
	while True:
	    packet = s.recvfrom(65565)
	     
	    #packet string from tuple
	    packet = packet[0]
	    
	     
	    #take first 20 characters for the ip header
	    ip_header = packet[0:20]
	     
	    #now unpack them :)
	    iph = unpack('!BBHHHBBH4s4s' , ip_header)

	    version_ihl = iph[0]
	    version = version_ihl >> 4
	    ihl = version_ihl & 0xF
	     
	    iph_length = ihl * 4

	    tos = iph[1]
	    ttl = iph[5]
	    protocol = iph[6]
	    s_addr = socket.inet_ntoa(iph[8]);
	    d_addr = socket.inet_ntoa(iph[9]);
	     
	    if i < winSize:
		    if tos == 2:
		    	#print 0
			x[i]=0
		    else:
			#print 1
			x[i]=1
	            i=i+1
	    else:
		i=0
		
		state= str(calcQoS(x)) # return % of QoS

		qvalue= float(state)
		qvalue=qvalue*100
		
		print str(qvalue)

		x = [0 for z in xrange(winSize)]

if __name__=="__main__":
    main()
     
