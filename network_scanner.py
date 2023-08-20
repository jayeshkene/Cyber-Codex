#!/usr/bin/python 

import scapy.all as scapy
import argparse

def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
	options = parser.parse_args()
	return options 

def scan(ip):
	#scrapy.arping(ip) 
	arp_request = scapy.ARP(pdst = ip) 
	#print(arp_request.summary()) 
	#scapy.ls(scapy.ARP()) 

	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
	#scapy.ls(scapy.Ether())
	#print(broadcast.summary())

	arp_request_broadcast = broadcast/arp_request
	#print(arp_request_broadcast.summary())

	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False) [0]
	#print(answered_list.summary())

	client_list = []
	for element in answered_list:
		client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
		client_list.append(client_dict)
	return client_list

def print_results(results_list):
	print("IP\t\t\tMAC Address\n-----------------------------------------")
	for client in results_list:
		print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_results = scan(options.target)
print_results(scan_results)




