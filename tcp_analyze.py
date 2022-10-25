#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sr1, IP, TCP, conf
from netaddr import IPNetwork
from tabulate import tabulate
from threading import Thread
from random import random
from sys import argv
import datetime
import time

TIMEOUT = 10
DELTA_ID_TIMEOUT = 0.5
INTERVAL = 1
SCREEN_UP_TO = '\033[%dA'

conf.verb = 0
targets = []
results = []
is_stop = False

def get_sport():
	return int( 50000 + random()*(65535-50000) )

def probe(ip,port,probe_id):
	global results
	while True:
		try:
			answer = sr1( IP(dst=ip)/TCP(sport=get_sport(), dport=port, flags="S", options=[('Timestamp',(0,0))]), timeout=TIMEOUT )
			time.sleep(DELTA_ID_TIMEOUT)
			delta_id = sr1( IP(dst=ip)/TCP(sport=get_sport(), dport=port, flags="S"), timeout=TIMEOUT )[IP].id - answer[IP].id
			ttl = answer[IP].ttl
			flags = answer.sprintf('%TCP.flags%')
			try:
				boot_timestamp = answer[TCP].options[3][1][0] / 100
				boot_time = datetime.datetime.utcfromtimestamp( time.time() - boot_timestamp ).strftime('%Y-%m-%d %H:%M:%S')
			except:
				boot_time = "?                 ?"
			results[probe_id] = [ "%s:%d" % (ip, port), flags, "+%d" % abs(delta_id), str(ttl), boot_time ]
		except:
			#results[probe_id] = [ "%s:%d" % (ip, port), "xx", "x    x", "x x", "x                 x" ]
			pass
		if is_stop:
			break
		time.sleep(INTERVAL)

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
			targets.append( [ip, int(port)] )
		except:
			break

threads = []
i = 0
for ip,port in targets:
	results.append( ['%s:%d' % (ip,port), '*', '*', '*', '*'] )
	threads.append( Thread( target=probe, args=(ip,port,i) ) )
	i += 1

for thread in threads:
	thread.start()

while True:
	try:
		output = []
		if len(results) == 1:
			print( " | ".join( results[0] ) )
		else:
			for result in results:
				output.append(result)
			print( tabulate(output, headers=["ip","flags","delta","ttl","uptime"]) )
			print( SCREEN_UP_TO % ( len(results) + 3 ) )
		time.sleep(INTERVAL)
	except KeyboardInterrupt:
		is_stop = True
		break

for thread in threads:
	thread.join()