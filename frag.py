#!/usr/bin/python2
from netfilterqueue import NetfilterQueue
from scapy.all import *
import logging; logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
from sys import argv

iface = argv[1]
fragsize = int(argv[2])
conf.iface = iface
ip_own = [route[4] for route in conf.route.routes if route[3] == iface][0]

def fragment(pkt, fragsize=8):
    fragsize = (fragsize + 7) // 8 * 8
    lst = []
    for p in pkt:
        s = raw(p[IP].payload)
        nb = (len(s) + fragsize - 1) // fragsize
        for i in range(nb):
            q = p.copy()
            del(q[IP].payload)
            del(q[IP].chksum)
            del(q[IP].len)
            if i != nb - 1:
                q[IP].flags |= 1
            q[IP].frag += i * fragsize // 8          # <---- CHANGE THIS
            r = conf.raw_layer(load=s[i * fragsize:(i + 1) * fragsize])
            r.overload_fields = p[IP].payload.overload_fields.copy()
            q.add_payload(r)
            lst.append(q)
    return lst

def callback(packet):
    p = IP( packet.get_payload() )
    if p[IP].src != ip_own:
        return
    print p.summary() + " -> ",
    for p in fragment(p, fragsize=fragsize):
        send(p, verbose=0)
        print ".",
    print ""

queue = NetfilterQueue()
queue.bind(1, callback)
#os.system("/sbin/iptables -A FORWARD -j NFQUEUE --queue-num 1")
os.system("/sbin/iptables -A OUTPUT -j NFQUEUE --queue-num 1")
try:
    queue.run()
except KeyboardInterrupt:
    queue.unbind()
    #os.system("/sbin/iptables -D FORWARD -j NFQUEUE --queue-num 1")
    os.system("/sbin/iptables -D OUTPUT -j NFQUEUE --queue-num 1")
