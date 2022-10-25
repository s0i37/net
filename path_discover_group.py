#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
import datetime
import time
import pydot
from random import random

conf.verb = 0
TIMEOUT = 5

def get_sport():
	return int( 50000 + random()*(65535-50000) )

def build_packet(target):
	(ip,port,proto) = target
	if proto == 'tcp':
		packet = IP(dst=ip)/TCP(dport=port, sport=get_sport())
	elif proto == 'udp':
		packet = IP(dst=ip)/UDP(dport=port, sport=get_sport())
	return packet

def _traceroute(target):
	max_hops = 30
	packet = build_packet(target)
	packet[IP].ttl = 1
	hops = []
	while True:
		if packet[IP].ttl >= max_hops:
			break
		try:
			hop = sr1(packet, timeout=TIMEOUT)[IP].src
		except Exception as e:
			#print(str(e))
			hop = 'unk_%d' % packet[IP].ttl
		hops.append(hop)
		print(" %s"%hop)
		packet[IP].ttl += 1
		if hop == packet[IP].dst:
			break
	return hops

def get_uptime(packet):
	max_attempts = 5
	while True:
		answer = sr1(packet, timeout=TIMEOUT)
		try:
			boot_timestamp = answer[TCP].options[3][1][0] / 100
			boot_time = datetime.datetime.utcfromtimestamp( time.time() - boot_timestamp ).strftime('%Y-%m-%d_%H-%M')
			break
		except Exception as e:
			#print(str(e))
			boot_time = "?"
		max_attempts -= 1
		if max_attempts <= 0:
			break
	return boot_time


targets = []
if len(sys.argv) == 2:
	with open( sys.argv[1] ) as f:
		for target in f:
			(host,port,proto) = target.split()
			targets.append( (host, int(port), proto.lower()) )
else:
	while True:
		try:
			line = input()
			ip,port,proto = line.split()[:3]
			targets.append( (ip, int(port), proto.lower()) )
		except:
			break

graph = pydot.Dot(graph_type='digraph')
uptimes = {}
for target in targets:
	packet = build_packet(target)
	packet[TCP].options=[('Timestamp',(0,0))]
	packet[TCP].flags="S"
	uptime = get_uptime(packet)
	print("[*] %s:%d %s" % (packet[IP].dst, packet.dport, uptime))
	hops = _traceroute(target)
	_hop = None
	for hop in hops:
		label = hop
		fillcolor = 'grey'
		if hop == packet[IP].dst:
			hop = uptime
			if not uptime in uptimes.keys():
				uptimes[uptime] = [uptime]
			uptimes[uptime].append( "%s:%d" % (packet[IP].dst, packet[TCP].dport) )
			label = "\n".join(uptimes[uptime])
			fillcolor = 'green'

		graph.add_node( pydot.Node(hop, label=label, style="filled", fillcolor=fillcolor, fontcolor='black') )
		if _hop:
			graph.add_edge( pydot.Edge(_hop, hop) )
		_hop = hop

graph.write_dot('out.dot')
