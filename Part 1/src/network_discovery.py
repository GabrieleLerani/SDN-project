import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr

from pox.lib.util import dpidToStr
import networkx as nx
import numpy as np

class Link():

	def __init__(self, sid1, sid2, dpid1, port1, dpid2, port2):
		self.name = str(sid1) + "_" + str(sid2)
		self.sid1 = sid1
		self.sid2 = sid2
		self.dpid1 = dpidToStr(dpid1)
		self.dpid2 = dpidToStr(dpid2)
		self.port1 = int(port1)
		self.port2 = int(port2)

class linkDiscovery():

	def __init__(self):
		self.switches = {}
		self.gateway = {}
		self.links = {}
		self.switch_id = {}
		self.id = 0
		core.openflow.addListeners(self)
		Timer(5, self.sendProbes, recurring=True)

	def find_gw(self,dpid,ports):
		for port in ports:
			# find gateway address and store its position
			if port.hw_addr == core.GatewayAccess.gw_mac:
				self.gateway[dpid] = ports
				print("Gateway is", dpid)


	def _handle_ConnectionUp(self, event):
		self.switch_id[self.id] = event.dpid
		self.switches[event.dpid] = event.ofp.ports
		self.install_flow_rule(event.dpid)
		print("Connection Up: " + dpidToStr(event.dpid) + ", " + str(self.id)) 
		self.id += 1


	def _handle_PacketIn(self, event):
		eth_frame = event.parsed
		if eth_frame.src == EthAddr("00:11:22:33:44:55"):
			eth_dst = eth_frame.dst.toStr().split(':')
			sid1 = int(eth_dst[4])
			dpid1 = self.switch_id[sid1]
			port1 = int(eth_dst[5])
			dpid2 = event.dpid
			sid2 = list(self.switch_id.keys())[list(self.switch_id.values()).index(dpid2)]
			port2 = event.ofp.in_port
			link = Link(sid1, sid2, dpid1, port1, dpid2, port2)
			if link.name not in self.links:
				self.links[link.name] = link
				print("discovered new link: " + link.name)
				print(link.__dict__)

	def sendProbes(self):
		"""
		Send packet with fake mac address to discover switches
		"""
		for sid in self.switch_id:
			dpid = self.switch_id[sid]
			for port in self.switches[dpid]:
				if port.port_no != 65534:
					mac_src = EthAddr("00:11:22:33:44:55")
					mac_dst = EthAddr("00:00:00:00:" + str(sid) + ":" + str(port.port_no))
					ether = ethernet()
					ether.type = ethernet.ARP_TYPE
					ether.src = mac_src
					ether.dst = mac_dst
					ether.payload = arp()
					msg = of.ofp_packet_out()
					msg.data = ether.pack()
					msg.actions.append(of.ofp_action_output(port = port.port_no))
					core.openflow.sendToDPID(dpid, msg)
	
	

	def install_flow_rule(self, dpid):
		
		"""
		Flow rule for network discovery 
		"""

		msg = of.ofp_flow_mod()
		msg.priority = 50000
		match = of.ofp_match(dl_src = EthAddr("00:11:22:33:44:55"))
		msg.match = match
		msg.actions = [of.ofp_action_output(port = of.OFPP_CONTROLLER)]
		core.openflow.sendToDPID(dpid, msg)

	
	def getGraph(self):
		N = len(self.switches)
		adj = np.zeros((N, N))
		for link in self.links:
			adj[self.links[link].sid1, self.links[link].sid2] = 1
		graph = nx.from_numpy_matrix(np.where(adj > 0, 1, 0))
		return graph


class HostSwtichLink():

	def __init__(self, dpid, host_ip, port1, port2):
		self.dpid = dpid
		self.host_ip = host_ip
		self.sw_port = port1
		self.host_port = port2



class hostDiscovery():

	def __init__(self):
		core.openflow.addListeners(self)
		self.hosts = {}
		self.max_hosts = 5 # assumption
		self.fake_mac_gw = EthAddr("00:00:00:00:11:11")
		self.fake_ip_gw = IPAddr("10.0.0.200")

	def _handle_ConnectionUp(self, event):
		self.hostDiscovery(event.connection)

	def hostDiscovery(self, connection):
		for h in range(self.max_hosts):
			arp_req = arp()
			arp_req.hwsrc = self.fake_mac_gw
			arp_req.opcode = arp.REQUEST
			arp_req.protosrc = self.fake_ip_gw
			arp_req.protodst = IPAddr(f"10.0.0.10{h}")
			ether = ethernet()
			ether.type = ethernet.ARP_TYPE
			ether.dst = EthAddr.BROADCAST

			# mac src address of the fake gateway
			ether.src = self.fake_mac_gw
			ether.payload = arp_req
			msg = of.ofp_packet_out()
			msg.data = ether.pack()
			
			# The arp message should be flooded to all because
			# there is no assumption of the port
			# output all openflow ports except the in port.
			msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL)) 
			connection.send(msg)
		
	def _handle_PacketIn(self, event):
		eth_frame = event.parsed
		
		# handle the ARP reply
		if eth_frame.type == ethernet.ARP_TYPE and eth_frame.dst == self.fake_mac_gw:
			arp_msg = eth_frame.payload
			if arp_msg.opcode == arp.REPLY:
				ip_host = arp_msg.protosrc
				mac_host = arp_msg.hwsrc

				if ip_host not in self.hosts:
					self.hosts[ip_host] = {
						"switch": event.dpid,
						"port": event.port,
						"mac": mac_host
					}

					print("Host:", ip_host)
					print("Switch:", self.hosts[ip_host]["switch"])
					print("Port:", self.hosts[ip_host]["port"])
					print("MAC:", self.hosts[ip_host]["mac"])
					print()

			


def launch():
	core.registerNew(linkDiscovery)
	core.registerNew(hostDiscovery)
