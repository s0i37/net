#!/usr/bin/python3
from scapy.all import *
import sys


targets = []
if len(sys.argv) == 2:
	with open( sys.argv[1] ) as f:
		for target in f:
			(host,port,proto) = target.split()
			targets.append( (host, int(port), proto) )
else:
	while True:
		try:
			line = input()
			ip,port,proto = line.split()[:3]
			targets.append( (ip, int(port), proto) )
		except:
			break


paths = TracerouteResult()

for target in targets:
	(host,port,proto) = target
	if proto == 'udp':
		paths += traceroute(host,l4=UDP(dport=port))[0]
	elif proto == 'tcp':
		paths += traceroute(host,dport=port)[0]

paths.graph(type="png", target=">out.png")
print('see out.png')
