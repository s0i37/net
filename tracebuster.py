#!/usr/bin/python3
from scapy.all import *
from sys import argv, stdout
from time import sleep
from threading import Thread
from netaddr import IPNetwork


conf.verb = False
max_hops = int(argv[1])
proto = argv[2].lower()
targets = argv[3]
port = int(argv[4]) if proto != "icmp" else 0
if proto == "icmp":
	packet = ICMP()
elif proto == "udp":
	packet = UDP(dport=port)
elif proto == "tcp":
	packet = TCP(dport=port)

class Hop:
	def __init__(self, recv, send):
		self.ip = recv[IP].src
		self.id = recv[IP].id
		self.ttl = recv[IP].ttl
		self.time = 0
		self.recv = recv
		self.send = send
		self.msg = ""

paths = []
def probe(ip):
	hops = {}
	for hop in traceroute(ip, l4=packet, maxttl=max_hops, timeout=0.1)[0]:
		req,res = hop
		hops[req[IP].ttl] = Hop(res,req)
		if res[IP].src == ip:
			break

	path = ''
	for hop in hops:
		path += hops[hop].recv[IP].src + '->'

	#stdout.write(f"[*] {ip}: {path}\r"); stdout.flush()
	if not path in paths:
		print(f"[+] {ip}: {path}" + " "*30)
		paths.append(path)

for network in IPNetwork(targets).subnet(24):
	probe(str(network[1]))
	#sleep(0.1)
