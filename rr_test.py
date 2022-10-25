#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys

if len(sys.argv) != 2:
	print( "%s host" % sys.argv[0] )
	exit()

host = sys.argv[1]
conf.verb = False

p = IP( dst=host, options=IPOption_RR(pointer=4, routers=["0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0"]) )/ICMP()
print(p.summary())
a = sr1(p)
if a[IP].options:
	for router in a[IP].options[0].routers:
		print(router)
