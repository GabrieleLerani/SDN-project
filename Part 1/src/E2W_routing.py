import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.packet.ipv4 import ipv4
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpidToStr
import networkx as nx


TCP_IDLE_TIMEOUT = 180

class E2WRouting:
    def __init__(self):
        core.openflow.addListeners(self)
        self.flow_map = {}  # Map to store flow information TODO remove

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if packet.type == packet.IP_TYPE:
            ip_packet = packet.payload
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip
            
            if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
                tcp_packet = ip_packet.payload
                src_port = tcp_packet.srcport
                dst_port = tcp_packet.dstport
                self.route_traffic_flows(src_ip,dst_ip)
    
    # TODO create also the reverted method for handling TCP connections    
    def route_traffic_flows(self,src_host_ip,dst_host_ip):
            
        # get the switch dpid the host is connected with
        sw_src = core.hostDiscovery.hosts[src_host_ip]["switch"]

        # get the switch dpid the host is connected with
        sw_dst = core.hostDiscovery.hosts[dst_host_ip]["switch"]

        # get the port of the swtich where the host is connected with
        sw_to_host_port = core.hostDiscovery.hosts[src_host_ip]["port"] 
 

        # TODO make get_key_from_value in a separated util module 
        # get the id of the source switch
        S = core.Routing.get_key_from_value(core.linkDiscovery.switch_id, sw_src)

        # get the id of the destination switch
        D = core.Routing.get_key_from_value(core.linkDiscovery.switch_id, sw_dst)     

        # get network graph
        graph = core.linkDiscovery.getGraph()

        # Draw graph
        #core.linkDiscovery.drawGraph(graph)

        # compute the shortest path between S and D according to the path weight
        path = list(nx.shortest_path(graph, S, D, weight="weight"))

        # get path links as a list of tuple: [(1,2),(2,3)...]
        path_links = core.Routing.get_links_pair(path)

        print(f"found path for TCP traffics between {src_host_ip} and {dst_host_ip}: {path}")

        for sw in path_links:
            src_dpid = core.linkDiscovery.switch_id[sw[0]]
            link_name = f"{sw[0]}_{sw[1]}"
            out_port = core.linkDiscovery.links[link_name].port1

            # increment flow on that edge
            core.linkDiscovery.links[link_name].flow += 1

            # flow rule for TCP traffic towards the receiving host
            # to handle flows from the same source I have to insert also the destination port
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match(
                dl_type=ethernet.IP_TYPE, 
                nw_src = src_host_ip,
                nw_dst = dst_host_ip,
                nw_proto = ipv4.TCP_PROTOCOL
            )
            msg.idle_timeout = TCP_IDLE_TIMEOUT
            msg.actions = [of.ofp_action_output(port=out_port if sw[1] != D else sw_to_host_port)]
            core.openflow.sendToDPID(src_dpid if sw[1] != D else sw_dst, msg)
            
            
        

def launch():
    core.registerNew(E2WRouting)