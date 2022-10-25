#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sr1, IP, ICMP, conf
from sys import argv
import datetime
import time

TIMEOUT = 10
target = argv[1]
conf.verb = 0

answer = sr1( IP(dst=target)/ICMP(type=13, code=0), timeout=TIMEOUT )
answer[ICMP].ts_ori
answer[ICMP].ts_rx
answer[ICMP].ts_tx
time_ori = (datetime.datetime(1,1,1)+datetime.timedelta(milliseconds=answer[ICMP].ts_ori)).strftime('%H:%M:%S')
print("remote_time=%s, local_time=%s"%(time_ori, datetime.datetime.now().strftime('%H:%M:%S')))

#https://www.rfc-editor.org/rfc/rfc792.html