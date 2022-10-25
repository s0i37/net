#!/usr/bin/python3
import pyshark
from sys import argv


iface = argv[1]
_filter = argv[2] if len(argv) > 2 else None

packets_type = {}
capture = pyshark.LiveCapture(interface=iface, bpf_filter=_filter)
for i,packet in enumerate(capture.sniff_continuously()):
    layers = "/".join(list(map(lambda l:l.layer_name, packet.layers)))
    if layers in packets_type:
        packets_type[layers] += 1
    else:
        packets_type[layers] = 1
        print(f"[+] {layers}")
    #bytes.fromhex(packet[2].payload.raw_value)
