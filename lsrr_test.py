#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from netaddr import IPNetwork
import sys

if len(sys.argv) != 3:
	print( "%s host targets" % sys.argv[0] )
	exit()

host = sys.argv[1]
targets = IPNetwork( sys.argv[2] )
conf.verb = False

for target in targets:
	p = IP( dst=host, options=IPOption_LSRR(pointer=4, routers=[str(target)]) )/ICMP()
	print(p.summary())
	send(p)
