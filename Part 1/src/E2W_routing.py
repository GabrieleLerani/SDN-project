import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpidToStr
from util import get_links_pair
from util import get_key_from_value
from util import reverse_string
from pox.lib.addresses import IPAddr
import networkx as nx


E2W_IDLE_TIMEOUT = 10

class E2WRouting:
    def __init__(self):
        core.openflow.addListeners(self)
        self.flows = {}
         

    def _handle_PacketIn(self, event):
        packet = event.parsed
        
        # discard all icmp replay from the gateway, consider only internal traffic
        if (packet.find('ipv4') and
            packet.src != core.GatewayAccess.gw_mac and
            packet.dst != core.GatewayAccess.gw_mac):
                
            ip_packet = packet.payload
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip
            self.route_traffic_flows(src_ip,dst_ip)
    
        
    def _handle_FlowRemoved(self, event):
        if event.idleTimeout:
            flow_match = event.ofp.match
            print("FLOW REMOVED from:", dpidToStr(event.dpid))
            print("MATCH: ",event.ofp.match)

            flow_id = (
                    flow_match.nw_src,
                    flow_match.nw_dst,
                    flow_match.dl_type
            )

            if flow_id in self.flows.keys():

                graph = core.Graph.graph_without_gw

                # decrease flow counter for every link used by the flow
                for link in self.flows[flow_id]:
                    link_name = f"{link[0]}_{link[1]}"
                    reversed_link = reverse_string(link_name)
                    # core.linkDiscovery.links[link_name].flow -= 1
                    # core.linkDiscovery.links[reversed_link].flow -= 1
                    core.Graph.update_weight(graph,link[0],link[1],1,decrement=True)

                # remove flow 
                del self.flows[flow_id]

     
    def route_traffic_flows(self,src_host_ip,dst_host_ip):
            
        # get the switch dpid of the src
        sw_src = core.hostDiscovery.hosts[src_host_ip]["switch"]

        # get the switch dpid of the dst
        sw_dst = core.hostDiscovery.hosts[dst_host_ip]["switch"]

        # get the port of the switch where the host is connected with
        sw_to_host_port = core.hostDiscovery.hosts[dst_host_ip]["port"] 
 
        # get the id of the source switch
        S = get_key_from_value(core.linkDiscovery.switch_id, sw_src)

        # get the id of the destination switch
        D = get_key_from_value(core.linkDiscovery.switch_id, sw_dst)     

        # get network graph
        graph = core.Graph.graph_without_gw

        # compute the shortest path between S and D according to the path weight
        path = list(nx.shortest_path(graph, S, D, weight="weight"))

        # get path links as a list of tuple: [(1,2),(2,3)...]
        path_links = get_links_pair(path)


        flow_sum = 0
        # TODO remove
        for node in path_links:
            flow_sum += graph[node[0]][node[1]]["weight"]
            
        print(f"found path for traffics between {src_host_ip} and {dst_host_ip}: {path} with {flow_sum} flows")

        # a flow is identified by src ip and dst ip, it should be changed to consider 
        # different flows from the same host to the same machine
        flow_id = (src_host_ip, dst_host_ip, ethernet.IP_TYPE)
        
        # store the path associated to a flow
        self.flows[flow_id] = path_links

        # define the flow rule
        msg = of.ofp_flow_mod()
        msg.idle_timeout = E2W_IDLE_TIMEOUT            
        
        # Send flow removed message when rule expire
        msg.flags = of.OFPFF_SEND_FLOW_REM
        msg.match = of.ofp_match(
            dl_type=ethernet.IP_TYPE, 
            nw_src = src_host_ip,
            nw_dst = dst_host_ip,
        )

        if len(path) == 1:
            msg.actions = [of.ofp_action_output(port=sw_to_host_port)]  
            core.openflow.sendToDPID(sw_dst, msg)
                
        else:

            for sw in path_links:
                
                src_dpid = core.linkDiscovery.switch_id[sw[0]]
                link_name = f"{sw[0]}_{sw[1]}"
                #reversed_link = reverse_string(link_name)
                out_port = core.linkDiscovery.links[link_name].port1

                # # increment flow on that edge
                # core.linkDiscovery.links[link_name].flow += 1
                # core.linkDiscovery.links[reversed_link].flow += 1
                core.Graph.update_weight(graph,sw[0],sw[1],1)

                flow = graph[sw[0]][sw[1]]["weight"]

                print(f"Link {link_name} has {flow} flow")

                msg.actions = [of.ofp_action_output(port=out_port)]  
                core.openflow.sendToDPID(src_dpid, msg)
                print("E2W flow rule sent to ",dpidToStr(src_dpid))
                if sw[1] == D:
                    msg.actions = [of.ofp_action_output(port=sw_to_host_port)]  
                    core.openflow.sendToDPID(sw_dst, msg)
                    print("E2W flow rule sent to ",dpidToStr(sw_dst))
        
        

def launch():
    core.registerNew(E2WRouting)