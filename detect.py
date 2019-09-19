from scapy.all import *
import argparse
import re


parser = argparse.ArgumentParser()
parser.add_argument("-i", help="network interface to sniff for online mode")
parser.add_argument("-r", help="pcap file for offline mode")
parser.add_argument("-e", help="expression for scapy to filter packets")
terminalArgs = parser.parse_args()



interface = terminalArgs.i
pcappath = terminalArgs.r
expression = terminalArgs.e


MAX_SIZE = 50
packetLenWithoutLoad = 32
previousPackets = [ ]


def isAForgedPacket(pkt):
	if hasattr(pkt.getlayer('TCP'), 'load'):
		for prevPkt in previousPackets:
			if prevPkt[IP].dst == pkt[IP].dst and prevPkt[IP].src == pkt[IP].src and\
			prevPkt[TCP].sport == pkt[TCP].sport and prevPkt[TCP].dport == pkt[TCP].dport and\
			prevPkt[TCP].seq == pkt[TCP].seq and prevPkt[TCP].ack == pkt[TCP].ack and\
			len(prevPkt[TCP]) > packetLenWithoutLoad and len(pkt[TCP]) > packetLenWithoutLoad and\
			prevPkt[TCP].payload != pkt[TCP].payload:
				print "________________________________________________"
				print "aho el attackk "
				print "here is our forged packet "
				prevPkt.show()
				print "this is the original packet"
				pkt.show()
		previousPackets.append(pkt)




terminalArgs = parser.parse_args()


if not pcappath and not interface:
    interface = "eth0"
    print "we used this interface: ", interface
    packets = sniff (count = MAX_SIZE, iface = interface, filter = expression, prn = lambda pkt: isAForgedPacket(pkt))
elif interface and pcappath:
	print "You can't be online and offline at the same time"
elif interface:
	print "using interface: ", interface
	packets = sniff (count = MAX_SIZE, iface = interface, filter = expression, prn = lambda pkt: isAForgedPacket(pkt))
else:
	print "using pcap: ", pcappath
	packets = sniff(offline = pcappath, filter = expression, prn = lambda pkt: isAForgedPacket(pkt) )


