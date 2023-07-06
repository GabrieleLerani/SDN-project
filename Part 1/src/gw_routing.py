import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_dpid
import numpy as np
import networkx as nx

class Routing():

	def __init__(self):
		core.openflow.addListeners(self)
		self.host_location = {}
		self.host_ip_mac = {}
		self.max_hosts = 5

	
	def _handle_PacketIn(self, event):
		eth_frame = event.parsed

		# we have to find the switch position using the MAC address
		if eth_frame.type == ethernet.IP_TYPE and eth_frame.dst == core.GatewayAccess.gw_mac:
			
			self.handle_ip_traffic(event)

	# TODO debug	
	def handle_ip_traffic(self,event):
		
		# get gateway pdid
		gw_dpid = core.GatewayAccess.get_dpid_gw()
			
		# get dpid of the current switch
		switch_src_dpid = event.dpid
	
		S = D = sw_dst = 0
		
		# the packet comes from the gateway
		if gw_dpid == switch_src_dpid:
			
			# extract the IP payload
			ip_pkt = event.parsed.payload 
			print(ip_pkt.__dict__)
			
			# get the IP of the host that has sent the IP message
			src_host_ip = ip_pkt.srcip

			# get the switch dpid the host is connected with
			sw_dst = core.hostDiscovery.hosts[src_host_ip]["switch"]

			# get the id of the source switch
			S = self.get_key_from_value(core.linkDiscovery.switch_id,gw_dpid)

			# get the id of the destination switch
			D = self.get_key_from_value(core.linkDiscovery.switch_id,sw_dst)

		# packet comes from another switch
		else:
			# get the id of the source switch
			S = self.get_key_from_value(core.linkDiscovery.switch_id,switch_src_dpid)

			# get the id of the destination switch
			D = self.get_key_from_value(core.linkDiscovery.switch_id,gw_dpid)



		# get network graph
		graph = core.linkDiscovery.getGraph()
			
		# compute the shortest path between S and D
		path = list(nx.shortest_path(graph, S, D))
			
		# get path links as a list of tuple: [(1,2),(2,3)...]
		path_links = self.get_links_pair(path)			
			
		print("found path towards the gw",path_links)

		for sw in path_links:
				src_dpid = core.linkDiscovery.switch_id[sw[0]]
				link_name = f"{sw[0]}_{sw[1]}"
				out_port = core.linkDiscovery.links[link_name].port1

				# flow rule for traffic towards the gateway
				msg = of.ofp_flow_mod()
				msg.match = of.ofp_match(
						dl_type = ethernet.IP_TYPE,
						dl_dst = core.GatewayAccess.gw_mac            
				)
				
				msg.actions = [of.ofp_action_output(port = out_port)]
				core.openflow.sendToDPID(src_dpid, msg)

				# instruct the gw to drop packet, in a real scenario it should forward
				# the packet towards the external ip network
				# TODO it may be different and handle icmp request
				if sw[1] == D and gw_dpid != switch_src_dpid:	
					msg = of.ofp_flow_mod()
					msg.match = of.ofp_match(
							dl_type = ethernet.IP_TYPE,
							dl_dst = core.GatewayAccess.gw_mac            
					)
					
					#msg.actions = [] # empty actions is equal to dropping packet
					msg.actions = [of.ofp_action_output(port = of.OFPP_CONTROLLER)]
					core.openflow.sendToDPID(gw_dpid, msg)

				elif sw[1] == D and gw_dpid == switch_src_dpid:
					# get the MAC of the host
					host_mac = core.hostDiscovery.hosts[src_host_ip]["mac"]

					# get the port of the host
					sw_to_host_port = core.hostDiscovery.hosts[src_host_ip]["port"]

					
					msg = of.ofp_flow_mod()
					msg.match = of.ofp_match(
							dl_type = ethernet.IP_TYPE,
							dl_dst = host_mac           
					)
					
					
					msg.actions = [of.ofp_action_output(port = sw_to_host_port)]
					core.openflow.sendToDPID(sw_dst, msg)
					




	def get_links_pair(self,link_ids):
		result_list = [(link_ids[i],link_ids[i+1]) for i in range(len(link_ids) - 1)]
		return result_list

	def get_key_from_value(self, my_dict, target):
		for key, value in my_dict.items():
			if value == target:
				return key


def launch():
	Routing()
