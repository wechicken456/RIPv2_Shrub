from scapy.all import *
import netifaces

import json
import signal
import argparse
import socket
from ipaddress import IPv4Interface
import ipaddress

import sys

import threading

# conf.use_pcap = True
conf.L3socket = L3RawSocket

## super slow and bulky...
def sniff_iface(stop_threads, capfile, network):
	capwriter = PcapWriter(capfile, append=True, sync=True) ## add endianness, snaplen, bufsize etc. 

	## sniff pkts
	## only operate on IPv4 packets whose destination is inside the pcap's network.

	sniff(iface=args.iface, prn=lambda x: write_packetlist(capwriter, x), stop_filter=lambda _: stop_threads.is_set(), filter=f"( udp or tcp or icmp ) and net { str(network.network).split('/')[0] } mask { network.netmask }" )
	
def write_packetlist(capwriter, pkt):
	capwriter.write(raw(pkt))#, linktype=1, ifname=args.iface) # apparently doesnt work for scapy 2.5.0  ¯\_(ツ)_/¯
	capwriter.flush()

## super slow and bulky...
def sniff_pcap(stop_threads, capfile, network):
	capreader = PcapReader(capfile)
	while(not stop_threads.is_set()):
		try:
			## sniff a pkt from the capture file
			pkt = capreader.recv()
			if IP in pkt and ipaddress.ip_address(pkt[IP].src) in network.network:
				## if from this network and to this network, dont move it outside the pcap.
				if ipaddress.ip_address(pkt[IP].src) in network.network and ipaddress.ip_address(pkt[IP].dst) in network.network:
					continue
				if(args.debug >0):
					print("sending pkt", pkt.summary())

				## write pkt out. specifying interface doesnt do anything.
				# send(pkt.getlayer(IP), verbose=1, iface=args.iface)
				send(pkt.getlayer(IP), verbose=args.debug)

		except:
			# sleep for 10ms to prevent thrashing.
			time.sleep(0.01)
			pass


def sighandler(signum, frame):
	print("caught signal, closing nicely.")
	stop_threads.set()
	t1.join()
	t2.join()
	exit(0)

if __name__ == '__main__':
	parser = argparse.ArgumentParser("pyshim")

	## get network address as argument
	parser.add_argument("-n", "--network", "--net", dest="network", help="Name of the network the pcap file represents. In the format abc.def.ghi.jkl_mn (e.g. 127.0.0.0_16 for 127.0.0.0/16)", type=ascii, required=True)

	## get network interface as argument
	parser.add_argument("-i", "--iface", dest="iface", help="Name of the external network interface to interact with. Most often named something like `eth0` or `ens1`.", type=ascii, required=True)

	## add debug support
	parser.add_argument("-d","--debug", dest="debug", help="Enable debug. specify multiple times for more verbose output.", action='count', default=0)

	args = parser.parse_args()

	## remove the single quotes that argparse adds to the arguments for some reason...
	args.network = args.network.replace("'", "")
	args.iface = args.iface.replace("'", "")

	## check format of network argument and parse it.
	netparts = args.network.split("_")
	assert(len(netparts) == 2)
	try:
		network = IPv4Interface(args.network.replace("_", "/"))
	except socket.error:
		parser.print_help(sys.stderr)
		sys.exit(-1)

	if(args.debug >0):
		print("network address validated, operating on network with name ", network.network)

	## create capture file name from network string.
	capname = str(network.network).replace("/", "_") + ".dmp" ## fix

	print("using file ", capname, " as pcap file for network.")

	## add signal handlers for terminate and interrupt to clean up nicely.
	signal.signal(signal.SIGTERM, sighandler)
	signal.signal(signal.SIGINT, sighandler)

	## init stop threads event, used to signal a stop to threads when finished.
	stop_threads = threading.Event()

	while not os.path.exists(capname):
		pass

	print("capfile exists, starting interface sniffing...")

	global t1
	global t2

	t1 = threading.Thread(target=sniff_pcap, args=(stop_threads, capname,network,) )#db, lock, ))
	t1.start()


	capfilew = open(capname, "ab")
	
	t2 = threading.Thread(target=sniff_iface, args=(stop_threads, capfilew, network,) )# db, lock, ))
	t2.start()


	print("press ctrl+d to stop ")
	## read until ctrl+d (or signal handler catches a signal)
	instr = sys.stdin.read()

	print("ctrl+d seen, closing nicely.")

	stop_threads.set()
	t1.join()
	t2.join()

	exit(0)

## TODO
##
## add snaplen, endianness, and buffersize to the read and write sniffers to ensure they 
## 	dont choke on oversized pkts
##
## add usage instructions and installation instructions
##	particularly mention that `pip install scapy` may be insufficient since the
##	script will be run with sudo, so you may need to use a virtual environemnt 
##	(or `sudo pip install scapy` as a janky solution...)
##
