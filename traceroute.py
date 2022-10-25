#!/usr/bin/python3
from scapy.all import *
from sys import argv
from time import sleep
from threading import Thread
from netaddr import IPNetwork
from geolite2 import geolite2 #pip3 install maxminddb-geolite2
from ipwhois import IPWhois #pip3 install ipwhois
from tabulate import tabulate
from time import time


INTERVAL = 0.1
conf.verb = False
geoip = geolite2.reader()
grey_A = IPNetwork("10.0.0.0/8")
grey_B = IPNetwork("172.16.0.0/12")
grey_C = IPNetwork("192.168.0.0/16")
SCREEN_UP_TO = '\033[%dA'

def check_port(ip, port):
	res = sr1( IP( dst=ip )/TCP( dport=port, flags="S" ), timeout=0.5 )
	if not res:
		return False
	return res[TCP].flags == TCP(flags="SA").flags

class Hop:
	def __init__(self, recv, send):
		self.ip = recv[IP].src
		self.id = recv[IP].id
		self.ttl = recv[IP].ttl
		self.time = 0
		self.recv = recv
		self.send = send
		self.msg = ""

def monitor_id(hop):
	while True:
		before = time()
		ans = sr1(hop.send, timeout=INTERVAL)
		after = time()
		if ans:
			hop.id = abs(ans[IP].id - hop.id)
			hop.time = "%.03f" % (after - before)
			hop.msg = "[ok]"
		sleep(INTERVAL)

def geoiplookup(ip):
	result = geoip.get(ip)
	country = result['country']['names']['en'] if "country" in result else "UNKN"
	city = result["city"]["names"]["en"] if "city" in result else "UNKN"
	return f"{country}, {city}"

def whoislookup(ip):
	result = IPWhois(ip).lookup_whois()
	netname = result['nets'][0]['name']
	descr = result['nets'][0]['description']
	return f"{netname}"


proto = argv[1].lower()
ip = argv[2]
port = int(argv[3]) if proto != "icmp" else 0
if proto == "icmp":
	packet = ICMP()
elif proto == "udp":
	packet = UDP(dport=port)
elif proto == "tcp":
	packet = TCP(dport=port)

hops = {}
for hop in traceroute(ip, l4=packet)[0]:
	req,res = hop
	hops[req[IP].ttl] = Hop(res,req)
	if res[IP].src == ip:
		break

output = []
for n in range(1,len(hops)+1):
	hop = hops[n]
	if hop:
		if not hop.ip in grey_A and not hop.ip in grey_B and not hop.ip in grey_C:
			hop.geo = geoiplookup(hop.ip)
			hop.netname = whoislookup(hop.ip)
		else:
			hop.geo = ""
			hop.netname = "intranet"
		output.append(["[ok]", n, hop.ip, hop.ttl, hop.time, hop.id, hop.geo, hop.netname])
	else:
		output.append(["[un]", n, "*", "*", "*", "*", "*", "*"])
print(tabulate(output, headers=["sta","n","ip","ttl","rtt","delta","geo","whois"]))

threads = []
for n in range(1,len(hops)+1):
	hop = hops[n]
	if hop:
		thread = Thread(target=monitor_id, args=(hop,))
		thread.start()
		threads.append(thread)

while True:
	print(SCREEN_UP_TO % (len(hops)+3))
	output = []
	for n in range(1,len(hops)+1):
		hop = hops[n]
		if hop:
			output.append([hop.msg, n, hop.ip, hop.ttl, hop.time, "+"+str(hop.id), hop.geo, hop.netname])
			hop.msg = "[to]"
		else:
			output.append(["[un]", n, "*", "*", "*", "*", "*", "*"])
	print(tabulate(output, headers=["sta","n","ip","ttl","rtt","delta","geo","whois"]))
	sleep(1)

for thread in threads:
	thread.join()
