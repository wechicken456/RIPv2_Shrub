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
# conf.L3socket = L3RawSocket # changed

def dec_ttl(pkt):
	if IP not in pkt:
		return pkt

	if args.debug > 1:
		print(f"ttl: {pkt[IP].ttl} -> {pkt[IP].ttl-1}")
	pkt[IP].ttl -= 1
	if pkt[IP].ttl <= 0:	
		## packet expired on interface, ignore
		return None
	del pkt[IP].chksum ## delete old checksum so it gets recalculated.
	return pkt


## super slow and bulky...
def sniff_iface(stop_threads, capfile, network):
	capwriter = PcapWriter(capfile, append=True, sync=True) ## add endianness, snaplen, bufsize etc. 
	iface_mac = netifaces.ifaddresses(args.iface)[netifaces.AF_LINK][0]['addr']
	if (args.debug > 0):
		print("interface in use has mac:", iface_mac)
	## sniff pkts
	## only operate on IPv4 packets whose destination is inside the pcap's network.

	# sniff(iface=args.iface, prn=lambda x: write_packetlist(capwriter, iface_mac, x), stop_filter=lambda _: stop_threads.is_set(), filter=f"arp or (( udp or tcp or icmp ) and net { str(network.network).split('/')[0] } mask { network.netmask })" )
	sniff(iface=args.iface, prn=lambda x: write_packetlist(capwriter, iface_mac, x), stop_filter=lambda _: stop_threads.is_set(), filter=f"( arp or ( ( udp or tcp or icmp ) and dst net 172.31.0.0 mask 255.255.0.0 ) ) and ( ether dst {iface_mac} or ether dst ff:ff:ff:ff:ff:ff ) " )
	
def write_packetlist(capwriter, iface_mac, pkt):

	pkt = dec_ttl(pkt)

	## if the packet expired on the interface, dont forward it.
	if(pkt == None):
		return

	if Ether not in pkt:
		if args.debug:
			print("non-ethernet packet ignored.")
		return

	## reject incoming arp requests to prevent loops...
	if ARP in pkt and pkt[ARP].op == 1:
		return

	if pkt[Ether].src.startswith("fe:"):
		## dont forward packets from the inside of the network back into it
		return

	
	pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"

	# print(pkt.summary())
	capwriter.write(raw(pkt))#, linktype=1, ifname=args.iface) # apparently doesnt work for scapy 2.5.0  ¯\_(ツ)_/¯
	capwriter.flush()

## super slow and bulky...
def sniff_pcap(stop_threads, capfile, network):
	capreader = PcapReader(capfile)
	iface_mac = netifaces.ifaddresses(args.iface)[netifaces.AF_LINK][0]['addr']
	# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	while(not stop_threads.is_set()):
		try:
			## sniff a pkt from the capture file

			pkt = dec_ttl(capreader.recv())
			# pkt = capreader.recv()

			## if the packet expired on the interface, dont forward it.
			if(pkt == None):
				continue
			
			if Ether not in pkt:
				if args.debug:
					print("non-ethernet packet ignored.")
				continue

			print(pkt.summary())
			# if IP in pkt and ipaddress.ip_address(pkt[IP].src) in network.network:
				## if from this network and to this network, dont move it outside the pcap.
			if IP in pkt and ipaddress.ip_address(pkt[IP].src) in network.network and ipaddress.ip_address(pkt[IP].dst) in network.network:
				print("didnt send packet internal to this network")
				continue
			if IP in pkt and ipaddress.ip_address(pkt[IP].dst) == ipaddress.ip_address("255.255.255.255"):
				## temporary - prevent IP limited broadcast from going out from the pcap and looping. this is only an issue currently due to my messed up RIPv1 implementation from last year.
				continue
			if ARP in pkt and pkt[ARP].op == 2:
				continue

			## do NOT forward packets from the outside interface back to it, and do not forward MAC broadcast packets out of our pcap network.
			## also do NOT forward packets which do not have fe:... as their source adress. all packets sent from shrubs will have fe:... as sources.
			if not pkt[Ether].src.startswith("5e:fe:") : ## iface_mac == pkt[Ether].src or pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff' or 
				if(args.debug > 2):
					print("packet not for me, mac doesnt match...")
				continue


			if(args.debug  == 1 and IP in pkt):
				print("sending pkt to", pkt[IP].dst)
			elif(args.debug >1):
				print("sending pkt", pkt.summary())

			## write pkt out. specifying interface doesnt do anything.
			send(pkt.getlayer(IP), verbose=args.debug)
			# pkt[Ether].src = iface_mac
			# sendp(pkt, verbose=args.debug, iface=args.iface) # if using arp

		except socket.error as e:
			print(f"socket error: {e}")
			pass
		except EOFError:
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

	if (args.debug > 0):
		print(f"debug enabled: lvl {args.debug}")

	## remove the single quotes that argparse adds to the arguments for some reason...
	args.network = args.network.replace("'", "")
	args.iface = args.iface.replace("'", "")

	conf.iface = args.iface

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
