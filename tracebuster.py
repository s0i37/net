#!/usr/bin/python3
from scapy.all import *
from sys import argv, stdout
from time import sleep
from threading import Thread
from netaddr import IPNetwork
from pydot import *
import time

conf.verb = False
max_hops = int(argv[1])
proto = argv[2].lower()
targets = argv[3]
port = int(argv[4]) if proto != "icmp" else 0
if proto == "icmp":
    packet = ICMP()
elif proto == "udp":
    packet = UDP(dport=port)
elif proto == "tcp":
    packet = TCP(dport=port)


class Hop:
    def __init__(self, recv, send):
        self.ip = recv[IP].src
        self.id = recv[IP].id
        self.ttl = recv[IP].ttl
        self.time = 0
        self.recv = recv
        self.send = send
        self.msg = ""


set_ips = set()
paths = []
size = 0
time_now=time.time()
file=open("ip_list_{}_{}_{}.txt".format(proto,port,time_now),"w")
def probe(ip):
    global size
    hops = {}
    for hop in traceroute(ip, l4=packet, maxttl=max_hops, timeout=0.1)[0]:
        req, res = hop
        hops[req[IP].ttl] = Hop(res, req)
        if res[IP].src == ip:
            break

    path = ""
    for hop in hops:
        set_ips.add(hops[hop].recv[IP].src)
        path += hops[hop].recv[IP].src + "->"

    delta = 0 if len(f"[*] {ip}: {path}") > size else len(f"[*] {ip}: {path}") - size
    size = len(f"[*] {ip}: {path}")

    stdout.write(f"[*] {ip}: {path}\r")
    stdout.flush()
    if not path in paths:
        print(f"[+] {ip}: {path}" + " " * delta)
        paths.append(path)


try:
    for network in IPNetwork(targets).subnet(24):
        probe(str(network[1]))
        # sleep(0.1)
except:
    pass

for element in set_ips:
    file.write(element+"\n")
file.close()

graph = Dot(graph_type="digraph", rankdir="LR")
for path in paths:
    prev = "attacker"
    for node in path.split("->"):
        if node:
            graph.add_edge(Edge(prev, node))
            prev = node

graph.write_dot("graph_{}_{}_{}.dot".format(proto,port,time_now))
