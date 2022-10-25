#!/usr/bin/python3
from scapy.all import *
from sys import argv

GW_IP = '11.0.0.1'
BROADCAST = '11.0.0.255'
NETMASK = '255.255.255.0'
DNS_IP = '8.8.8.8'
#DOMAIN = 'test.local'
NBN_IP = '11.0.0.1'
DHCP_POOL = ['11.0.0.11', '11.0.0.12', '11.0.0.13']
IFACE = argv[1]

def send_offer(client_ip, client_mac, transaction=0):
	p = Ether(dst='ff:ff:ff:ff:ff:ff')/IP(dst='255.255.255.255', src=GW_IP)/\
		UDP(sport=67, dport=68)/\
		BOOTP(op=2, yiaddr=client_ip, siaddr='0.0.0.0', giaddr='0.0.0.0', chaddr=mac2str(client_mac), xid=transaction)/\
		DHCP(options=[("message-type", "offer"), ("server_id", GW_IP), ("broadcast_address", BROADCAST), ("router", GW_IP), ("subnet_mask", NETMASK), ('name_server', DNS_IP), ('NetBIOS_server', NBN_IP), 'end'])
	sendp(p)

def send_ack(client_ip, client_mac, transaction=0):
	p = Ether(dst='ff:ff:ff:ff:ff:ff')/IP(dst='255.255.255.255', src=GW_IP)/\
		UDP(sport=67, dport=68)/\
		BOOTP(op=2, yiaddr=client_ip, siaddr='0.0.0.0', giaddr='0.0.0.0', chaddr=mac2str(client_mac), xid=transaction)/\
		DHCP(options=[("message-type", "ack"), ("server_id", GW_IP), ("broadcast_address", BROADCAST), ("router", GW_IP), ("subnet_mask", NETMASK), ('name_server', DNS_IP), ('NetBIOS_server', NBN_IP), 'end'])
	sendp(p)

ip = DHCP_POOL.pop(0)
def parse(p):
	global ip
	if BOOTP in p:
		if p[BOOTP].op == 1: # DISCOVER/REQUEST
			client_mac = p[Ether].src
			vendor_class_id = ''
			hostname = ''
			requested_addr = ''
			transaction = p[BOOTP].xid
			for option in p[DHCP].options:
				if 'vendor_class_id' in option:
					vendor_class_id = option[1]
				elif 'hostname' in option:
					hostname = option[1]
				elif 'requested_addr' in option:
					requested_addr = option[1]
			if not requested_addr:
				print("[*] DHCP discover {vendor} {hostname}".format(vendor=vendor_class_id, hostname=hostname))
				send_offer(ip, client_mac, transaction)
				print("[+] DHCP offer {ip} {gw} {mask} {dns}".format(ip=ip, gw=GW_IP, mask=NETMASK, dns=DNS_IP))
			else:
				print("[*] DHCP request {vendor} {hostname} {ip}".format(vendor=vendor_class_id, hostname=hostname, ip=requested_addr))
				send_ack(requested_addr, client_mac, transaction)
				print("[+] DHCP ack {ip} {gw} {mask} {dns}".format(ip=requested_addr, gw=GW_IP, mask=NETMASK, dns=DNS_IP))
				ip = DHCP_POOL.pop(0)

conf.verb = 0
conf.iface = IFACE
sniff(iface=IFACE, prn=parse)
