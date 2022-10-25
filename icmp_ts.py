#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sr1, IP, ICMP, conf
from sys import argv
import datetime
import time
from netaddr import IPNetwork
from socket import ntohl

TIMEOUT = 2
targets = argv[1]
conf.verb = 0

def get_delta_time(target):
	answer = sr1( IP(dst=target)/ICMP(type=13, code=0), timeout=TIMEOUT )
	if not answer or not ICMP in answer:
		return
	ts_ori = answer[ICMP].ts_ori
	ts_rx = answer[ICMP].ts_rx
	ts_tx = answer[ICMP].ts_tx
	time_ori_fmt = (datetime.datetime(1,1,1)+datetime.timedelta(milliseconds=ts_ori)).strftime('%H:%M:%S')
	if 128 < answer[IP].ttl <= 255:
		ts_tx = ts_tx # Cisco unsupported
	elif 64 < answer[IP].ttl <= 128:
		ts_tx = ntohl(ts_tx)
	elif answer[IP].ttl <= 64:
		ts_tx = ts_tx
	ts_tx_fmt = (datetime.datetime(1,1,1)+datetime.timedelta(milliseconds=ts_tx)).strftime('%H:%M:%S')
	sign = "+" if ts_tx >= ts_ori else "-"
	delta = (datetime.datetime(1,1,1)+datetime.timedelta(milliseconds=abs(ts_tx - ts_ori))).strftime('%H:%M:%S')
	print("%s: local UTC=%s, remote UTC=%s, delta=%s%s (ttl=%d)"%(target, time_ori_fmt, ts_tx_fmt, sign, delta, answer[IP].ttl))
	time.sleep(1)

for ip in IPNetwork(targets):
	get_delta_time(str(ip))
