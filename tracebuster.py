#!/usr/bin/python3
from scapy.all import *
import argparse
from sys import argv, stdout
from time import sleep
from threading import Thread
from netaddr import IPNetwork


arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("nets", nargs="*", default=["192.168.0.0/16","172.16.0.0/12","10.0.0.0/8"], metavar="network", help="targets (10.0.0.0/8)")
arg_parser.add_argument('-m','--max-ttl', dest="ttl", type=int, default=4, metavar='ttl', help='max TTL (10)')
arg_parser.add_argument('-t','--timeout', dest="timeout", type=float, default=1, metavar='sec', help='timeout (1)')
arg_parser.add_argument('-s','--step', dest="step", type=int, default=24, metavar='cidr mask', help='step (24 - means /24, 255.255.255.0)')
arg_parser.add_argument('-T','--threads', dest="threads", type=int, default=10, metavar='threads', help='threads of tracing (10)')
arg_parser.add_argument('-i','--interval', dest="interval", type=float, default=0, metavar='sec', help='sleep between steps (0)')
arg_parser_tcp = arg_parser.add_argument_group("TCP")
arg_parser_tcp.add_argument('--tcp', dest="tcp", action="store_true", default=False, help='enable TCP mode')
arg_parser_tcp.add_argument('--tcp-port', dest="port", type=int, default=80, metavar='port', help='TCP port (80)')
arg_parser_udp = arg_parser.add_argument_group("UDP")
arg_parser_udp.add_argument('--udp', dest="udp", action="store_true", default=False, help='enable UDP mode')
arg_parser_udp.add_argument('--udp-port', dest="port", type=int, default=53, metavar='port', help='UDP port (53)')
arg_parser_icmp = arg_parser.add_argument_group("ICMP")
arg_parser_icmp.add_argument('--icmp', dest="icmp", action="store_true", default=True, help='enable ICMP mode')
arg_parser.add_argument('--out-txt', dest="out_txt", type=str, default="out.txt", metavar='outfile', help='text file subnets report')
arg_parser.add_argument('--out-dot', dest="out_dot", type=str, default="out.dot", metavar='outfile', help='dot file graph report')
args = arg_parser.parse_args(argv[1:])

conf.verb = False
if args.tcp:
	packet = TCP(dport=args.port)
elif args.udp:
	packet = UDP(dport=args.port)
elif args.icmp:
	packet = ICMP()

def _traceroute(dst, l4, minttl, maxttl, timeout):
	results = {}
	def _send(results, packet, timeout):
		ans = sr1(packet, timeout=timeout)
		results[packet[IP].ttl] = [packet, ans]

	for ttl in range(minttl, maxttl):
		Thread(target=_send, args=(results, IP(dst=dst, ttl=ttl)/l4, timeout)).start()
		sleep(0.1)
	sleep(timeout)
	return [[results.get(ttl) for ttl in range(minttl, maxttl)],0]

hops = set()
paths = []
size = 0
def probe(ip):
	global hops,paths,size
	path = ''
	for hop in _traceroute(ip, l4=packet, minttl=1, maxttl=args.ttl, timeout=args.timeout)[0]: # L3 interfaces supports
		if hop:
			req,res = hop
			if res:
				path += res[IP].src + '->'
				hops.add(res[IP].src)
				if res[IP].src == ip:
					break

	delta = 0 if len(f"[*] {ip}: {path}") > size else len(f"[*] {ip}: {path}") - size
	size = len(f"[*] {ip}: {path}")

	stdout.write(f"[*] {ip}: {path}\r"); stdout.flush()
	if not path in paths:
		print(f"[+] {ip}: {path}" + " "*delta)
		paths.append(path)

try:
	threads = []
	for net in args.nets:
		for network in IPNetwork(net).subnet(args.step):
			if len(threads) < args.threads:
				thread = Thread(target=probe, args=(str(network[1] if len(network)>1 else network[0]),))
				threads.append(thread)
				thread.start()
				sleep(args.interval)
			for thread in threads:
				thread.join(0.1)
				if thread.is_alive():
					threads.remove(thread)
			#probe(str(network[1]))
			#sleep(0.1)
except KeyboardInterrupt:
	print("interrupted")
except Exception as e:
	print(str(e))

[thr.join() for thr in threads]

if args.out_txt:
	with open(args.out_txt, "w") as o:
		for hop in hops:
			o.write(str(IPNetwork('{ip}/{mask}'.format(ip=hop, mask=args.step)).cidr) + "\n")

if args.out_dot:
	from pydot import *
	graph = Dot(graph_type='digraph', rankdir="LR")
	edges = []
	for path in paths:
		prev = "attacker"
		for node in path.split("->"):
			if node and not (prev, node) in edges:
				graph.add_edge(Edge(prev, node))
				edges.append((prev, node))
				prev = node
	graph.write_dot(args.out_dot)
