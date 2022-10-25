#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from sys import argv
from threading import Thread
from time import sleep
from scapy.all import sr1, ARP, sniff, conf
import pydot

conf.verb = 0
iface = argv[1]
graph = pydot.Dot(graph_type='digraph')
RED = '\x1b[31m'
GREEN = '\x1b[32m'
RESET = '\x1b[39m'
INTERVAL_UPDATE = 5
ip_own = [route[4] for route in conf.route.routes if route[3] == iface][0]

def analyze(packet):
	if ARP in packet:
		src = packet[ARP].psrc
		dst = packet[ARP].pdst
		if src == ip_own:
			return
		host_alive = is_alive(dst)
		graph.add_node( pydot.Node(src) )
		graph.add_node( pydot.Node(dst, style="filled", fillcolor='green' if host_alive else 'red') )
		graph.add_edge( pydot.Edge(src, dst) )
		print("%s -> %s" % (src, (GREEN if host_alive else RED) + dst + RESET))

alived_ips = []
def is_alive(ip):
	if ip == ip_own or ip in alived_ips or sr1(ARP(op=1, pdst=ip), iface=iface, timeout=1):
		alived_ips.append(ip)
		return True
	else:
		return False

def update(graph, interval):
	while True:
		graph.write_png('out.png')
		sleep(interval)

#print("eog out.png")
thread = Thread( target=update, args=(graph, INTERVAL_UPDATE) )
thread.start()
sniff(iface=iface, filter='arp', prn=analyze)
thread.join()
