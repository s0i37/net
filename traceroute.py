#!/usr/bin/python3
from scapy.all import *
from sys import argv
from time import sleep, time
from threading import Thread, Lock
from netaddr import IPNetwork
from geolite2 import geolite2 #pip3 install maxminddb-geolite2
from ipwhois import IPWhois #pip3 install ipwhois
import matplotlib.pyplot as plt
from tabulate import tabulate


TTL_MIN = 1
TTL_MAX = 30
TIMEOUT = 1
DELTAS = [0.1, 0.25, 0.5]
conf.verb = False
geoip = geolite2.reader()
grey_A = IPNetwork("10.0.0.0/8")
grey_B = IPNetwork("172.16.0.0/12")
grey_C = IPNetwork("192.168.0.0/16")
SCREEN_UP_TO = '\033[%dA'

class Hop:
	def __init__(self, recv, send):
		self.ip = recv[IP].src
		self.ttl = recv[IP].ttl
		self.delta_id = 0
		self.rtt = recv.time - send.sent_time
		self.rtts = []
		self.recv = recv
		self.send = send
		self.msg = ""

mutex = Lock()
def monitor_id(hop, fix):
	def measurement(measurements, packet, timeout):
		ans = sr1(packet, timeout=TIMEOUT)
		if ans:
			measurements[timeout].append(ans[IP].id)
		else:
			measurements[timeout].append(0)
	while True:
		mutex.acquire()
		before = time()
		ans = sr1(hop.send, timeout=TIMEOUT)
		after = time()
		if ans:
			hop.msg = "[+]" if hop.ip == ans[IP].src else "[!]"
			hop.ip = ans[IP].src
			hop.ttl = ans[IP].ttl
			hop.rtt = after - before
			hop.rtts.append(hop.rtt)
			measurements = {}
			for timeout in DELTAS:
				measurements[timeout] = []
				Thread(target=measurement, args=(measurements, hop.send, timeout)).start()
				sleep(timeout)
				Thread(target=measurement, args=(measurements, hop.send, timeout)).start()
			sleep(0.1)
			ids = []
			for delta in measurements:
				if len(measurements[delta]) == 2 and not 0 in measurements[delta]:
					id1,id2 = measurements[delta]
					ids.append(abs(id2-id1-1)/delta)
			delta_id = int(sum(ids)/len(measurements)) - fix
			hop.delta_id = delta_id if delta_id > 0 else 0
		else:
			hop.ip = None
			hop.rtts.append(0)
		mutex.release()
		sleep(0.1)

geoip_cache = {}
def geoiplookup(ip):
	if ip in geoip_cache:
		return geoip_cache[ip]
	result = geoip.get(ip) or {}
	country = result['country']['names']['en'] if "country" in result else "UNKN"
	city = result["city"]["names"]["en"] if "city" in result else "UNKN"
	geoip_cache[ip] = f"{country}, {city}"
	return f"{country}, {city}"

whois_cache = {}
def whoislookup(ip):
	if ip in whois_cache:
		return whois_cache[ip]
	result = IPWhois(ip).lookup_whois()
	netname = result['nets'][0]['name']
	descr = result['nets'][0]['description']
	whois_cache[ip] = f"{netname}"
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

def _traceroute(dst, l4, minttl, maxttl, timeout):
	results = {}
	def _send(results, packet, timeout):
		packet.sent_time = time()
		ans = sr1(packet, timeout=timeout)
		results[packet[IP].ttl] = [packet, ans]

	for ttl in range(minttl, maxttl):
		Thread(target=_send, args=(results, IP(dst=dst, ttl=ttl)/l4, timeout)).start()
		sleep(0.1)
	sleep(timeout)
	return [[results.get(ttl) for ttl in range(minttl, maxttl)],0]

hops = {}
for hop in _traceroute(ip, l4=packet, minttl=TTL_MIN, maxttl=TTL_MAX, timeout=TIMEOUT)[0]:
	req,res = hop
	hops[req[IP].ttl] = Hop(res,req) if res else None
	if res and res[IP].src == ip:
		break

threads = []
for n in range(1,len(hops)+1):
	hop = hops[n]
	if hop:
		thread = Thread(target=monitor_id, args=(hop, (n-1)*(len(DELTAS)+2) ))
		thread.start()
		threads.append(thread)

plt.draw()
while True:
	output = []
	rtt_delta = 0
	prev = []
	for n in range(1,len(hops)+1):
		hop = hops[n]
		if hop and hop.ip:
			if not hop.ip in grey_A and not hop.ip in grey_B and not hop.ip in grey_C:
				hop.geo = geoiplookup(hop.ip)
				hop.netname = whoislookup(hop.ip)
			else:
				hop.geo = ""
				hop.netname = "intranet"
			rtt = "%.03f(+%.03f)"%(hop.rtt,abs(hop.rtt-rtt_delta)) if rtt_delta else "%.03f"%hop.rtt
			delta_id = "+"+str(hop.delta_id) if hop.delta_id else 0
			output.append([hop.msg, n, hop.ip, hop.ttl, rtt, delta_id, hop.geo, hop.netname])
			hop.msg = "[*]"
			rtt_delta = hop.rtt

			try:
				plt.plot(range(len(hop.rtts)), list(map(lambda ms:ms[0]+ms[1], zip(prev,hop.rtts))) if prev else hop.rtts, label=hop.ip)
				prev = hop.rtts[:]
				plt.legend()
			except:
				pass
		else:
			output.append(["[?]", n, "*", "*", "*", "*", "*", "*"])
	print(tabulate(output, headers=["status","n","ip","ttl","rtt","id","geo","whois"]))
	sleep(0.1)
	print(SCREEN_UP_TO % (len(hops)+3))
	plt.pause(0.1)
	plt.clf()

for thread in threads:
	thread.join()
