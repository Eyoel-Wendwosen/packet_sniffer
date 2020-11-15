#!/usr/bin/env python

import scapy.all as scapy
import argparse
from scapy.layers import http
def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(interface):
	print("Sniffing...")
	scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		print("\n\n ---------packet found---------")
		print("host: ", packet[http.HTTPRequest].Host.decode("utf-8"))
		print("Path: ", packet[http.HTTPRequest].Path.decode("utf-8"))
		if packet.haslayer(scapy.Raw):
			load = packet[scapy.Raw].load
			print("packet load", load.decode("utf-8"))
		print("-------------//-------------")
        

interface = get_interface()
sniff(interface)