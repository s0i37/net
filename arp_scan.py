#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from sys import argv
from time import sleep
from scapy.all import sr1, IP, ARP, ICMP, conf
from netaddr import IPNetwork
from colorama import Fore

iface = argv[1]
net = argv[2]
conf.verb = 0

for ip in IPNetwork(net):
	if sr1(IP(dst=str(ip))/ICMP(), iface=iface, timeout=0.1):
		print(Fore.GREEN + str(ip) + Fore.RESET)
	elif sr1(ARP(op=1, pdst=str(ip)), iface=iface, timeout=0.1):
		print(Fore.RED + str(ip) + Fore.RESET)
	else:
		print(Fore.LIGHTBLACK_EX + str(ip) + Fore.RESET)
