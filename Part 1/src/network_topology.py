import networkx as nx
from pox.core import core
from util import get_key_from_value

class Graph:
    
    def __init__(self,componentLinkDiscovery):
        componentLinkDiscovery.addListeners(self)
        core.openflow.addListeners(self)
        self.graph_with_gw_node = None
        self.graph_without_gw = None


    def _handle_linkDiscovered(self,event):
        print("All links have been discovered, starting graph computation...\n")
        self.graph_with_gw_node = self.get_graph(route_to_gw=True)
        self.graph_without_gw = self.get_graph()

    def get_graph(self,route_to_gw = False):
        
        G = nx.Graph()
        gw_dpid = core.GatewayAccess.get_dpid_gw()
        gw_id = get_key_from_value(core.linkDiscovery.switch_id, gw_dpid)

        nodes = list()
        if route_to_gw:
            nodes = list(core.linkDiscovery.switch_id.keys())

        else:
            for sw_id in list(core.linkDiscovery.switch_id.keys()):
                if gw_id != sw_id:
                    nodes.append(sw_id)

        G.add_nodes_from(nodes)
        for link in core.linkDiscovery.links:
            sid1 = core.linkDiscovery.links[link].sid1 
            sid2 = core.linkDiscovery.links[link].sid2
            weight = core.linkDiscovery.links[link].flow  # Get flows of the link
            if route_to_gw:
                G.add_edge(sid1,sid2,weight=weight)
            else: 
                if not core.linkDiscovery.links[link].gw_link:
                    G.add_edge(sid1,sid2,weight=weight)
        print(G)
        print(G.edges.data())
        return G

    

def launch():
    core.register(Graph(core.linkDiscovery))