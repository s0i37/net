#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sr1, IP, TCP, conf
from netaddr import IPNetwork
from random import random
from sys import argv
import datetime
import time

MAX_PROBES = 10
TIMEOUT = 2

conf.verb = 0
targets = []

def get_sport():
	return int( 50000 + random()*(65535-50000) )

def probe(ip,port):
	try:
		answer = sr1( IP(dst=ip)/TCP(sport=get_sport(), dport=port, flags="S", options=[('Timestamp',(0,0))]), timeout=TIMEOUT )
		time.sleep(1)
		delta_id = sr1( IP(dst=ip)/TCP(sport=get_sport(), dport=port, flags="S"), timeout=TIMEOUT )[IP].id - answer[IP].id
		ttl = answer[IP].ttl
		flags = answer.sprintf('%TCP.flags%')
		try:
			boot_timestamp = answer[TCP].options[3][1][0] / 100
			boot_time = datetime.datetime.utcfromtimestamp( time.time() - boot_timestamp ).strftime('%Y-%m-%d %H:%M:%S')
		except:
			boot_time = None
			delta_id = 0
			ttl = 0
	except:
		boot_time = None
		delta_id = 0
		ttl = 0
	return (boot_time, ttl, abs(delta_id))

if len( argv ) == 3:
	net = argv[1]
	port = argv[2]
	for ip in IPNetwork(net):
		targets.append( [str(ip), int(port)] )
else:
	while True:
		try:
			line = input()
			ip,port = line.split()[:2]
			if not [ip, int(port)] in targets:
				targets.append( [ip, int(port)] )
		except:
			break

ports = {}
machines = {}
for ip,port in targets:
	prev = ''
	probe_no = 0
	while True:
		uptime,ttl,delta_id = probe(ip,port)
		print("[*]",ip,port,uptime,ttl,delta_id)
		_uptime = ':'.join(uptime.split(':')[0:2])if uptime else ''
		if not uptime:
			break
		if prev and (prev == _uptime or probe_no > MAX_PROBES):
			break
		prev = _uptime
		probe_no += 1
		try:
			ports["%s:%d"%(ip,port)].append((uptime,ttl,delta_id))
		except:
			ports["%s:%d"%(ip,port)] = [(uptime,ttl,delta_id)]
		try:
			machines[_uptime+":xx"].append("%s:%d"%(ip,port))
		except:
			machines[_uptime+":xx"] = ["%s:%d"%(ip,port)]

print("==========targets==========")
for target in ports.keys():
	print(target)
	for machine in ports[target]:
		print('\tuptime="' + machine[0] + '" ttl=' + str(machine[1]) + " delta_id=+" + str(machine[2]))

print("==========machines==========")
for machine in machines.keys():
	print(machine)
	for target in machines[machine]:
		print("\t" + target)
