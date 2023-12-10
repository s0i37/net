#!/usr/bin/python3
from scapy.all import *
from geolite2 import geolite2 #pip3 install maxminddb-geolite2
from ipwhois import IPWhois #pip3 install ipwhois
import json
import sys


TIMEOUT = 5
geoip = geolite2.reader()
targets = []
if len(sys.argv) == 2:
	with open( sys.argv[1] ) as f:
		for target in f:
			(host,port,proto) = target.split()
			targets.append( (host, int(port), proto) )
else:
	while True:
		try:
			line = input()
			(host,port,proto) = line.split()[:3]
			targets.append( (host, int(port), proto) )
		except:
			break

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

def is_grey(ip):
	parts = list(map(int, ip.split(".")))
	if parts[0] == 10:
		return True
	elif parts[0] == 172 and 16 <= parts[1] <= 24:
		return True
	elif parts[0] == 192 and parts[1] == 168:
		return True
	return False

def get_color(ip):
	if is_grey(ip):
		return "#0000ff"
	else:
		return "#00ff00"

nodes = []
links = []

def add_node(ip):
	global nodes
	nodes.append({
		"id": ip,
		"ip": ip,
		"size": 5,
		"netname": whoislookup(ip) if not is_grey(ip) else "local",
		"geo": geoiplookup(ip) if not is_grey(ip) else "local",
		"color": get_color(ip)
	})

def get_node(name):
	global nodes
	for node in nodes:
		if node["id"] == name:
			return node

def add_link(source, target):
	global links
	links.append({
		"source": source,
		"target": target,
		"color": "#ff0000",
		"label": "hop",
		"distance": 100,
		"width": 5,
		"count": 1,
		"speed": 0.01,
		"particle": 2
	})

def get_link(source, target):
	global links
	for link in links:
		if link["source"] == source and link["target"] == target:
			return link

paths = TracerouteResult()

add_node(conf.iface.ip)
for target in targets:
	(host,port,proto) = target
	if proto == 'tcp':
		l4 = TCP(dport=port)
	elif proto == 'udp':
		l4 = UDP(dport=port)
	elif proto == 'icmp':
		l4 = ICMP()
	node_prev = get_node(conf.iface.ip)
	for hop in traceroute(host,l4=l4,timeout=TIMEOUT)[0]:
		hop = hop[1]
		if not get_node(hop[IP].src):
			add_node(hop[IP].src)
		node = get_node(hop[IP].src)
		if node_prev:
			add_link(node_prev["id"], node["id"])
		node_prev = node

WWW = '''
<html>
<head>
  <style> body { margin: 0; } </style>
  <title>traceroute</title>
  <script type="importmap">{ "imports": { "three": "https://unpkg.com/three/build/three.module.js" }}</script>
  <script src="https://unpkg.com/three"></script>
  <script src="https://unpkg.com/three-spritetext@1.8.1/dist/three-spritetext.min.js"></script>
  <script src="https://unpkg.com/3d-force-graph"></script>
</head>

<body>

  <div id="3d-graph"></div>
  <style>
    body { margin: 0; }
    .node-label {
      font-size: 12px;
      padding: 1px 4px;
      border-radius: 4px;
      background-color: rgba(0,0,0,0.5);
      user-select: none;
    }
  </style>
  
  <script type="module">
  import { CSS2DRenderer, CSS2DObject } from 'https://unpkg.com/three@0.152.2/examples/jsm/renderers/CSS2DRenderer.js';
  import { UnrealBloomPass } from 'https://unpkg.com/three/examples/jsm/postprocessing/UnrealBloomPass.js';
	var dataset = %s

    const elem = document.getElementById('3d-graph');

    const Graph = ForceGraph3D({extraRenderers: [new CSS2DRenderer()]})(elem)
      .graphData(dataset)
      .backgroundColor('#101020')
      .nodeAutoColorBy('group')
      .linkAutoColorBy('color')
      .nodeVal(node => node.size)
      .nodeResolution(16)
      .nodeThreeObject(node => {
        const nodeEl = document.createElement('div');
        nodeEl.textContent = `${node.ip} ${node.geo}`;
        nodeEl.style.color = node.color;
        nodeEl.className = 'node-label';
        return new CSS2DObject(nodeEl);
      })
      .nodeThreeObjectExtend(true)
      .linkWidth("width")
      .linkDirectionalArrowLength(3.5)
      .linkDirectionalArrowRelPos(1)
      .linkDirectionalParticles("count")
      .linkDirectionalParticleSpeed("speed")
      .linkDirectionalParticleWidth("particle")
      //.linkDirectionalParticleColor(() => 'white')
      .nodeLabel(node => `${node.ip}`)
      .linkLabel(link => link.label)
      .onNodeDragEnd(node => {
        node.fx = node.x;
        node.fy = node.y;
        node.fz = node.z;
      })
      .onNodeClick(function(node){
        console.log(`selected ${node.ip}: ${node.netname}`)
        zoom(node)
      })
      .onLinkClick(link => console.log(link))
      Graph.d3Force('link').distance(link => link.distance)

    
    function zoom(node)
    {
      const distance = 40;
      const distRatio = 1 + distance/Math.hypot(node.x, node.y, node.z);

      const newPos = node.x || node.y || node.z
        ? { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio }
        : { x: 0, y: 0, z: distance }; // special case if node is in (0,0,0)

      Graph.cameraPosition(
        newPos, // new position
        node, // lookAt ({ x, y, z })
        3000  // ms transition duration
      );
    }
  </script>
</body>
</html>
'''
with open("out.html", "w") as o:
	o.write(WWW % json.dumps({"nodes": nodes, "links": links}))
