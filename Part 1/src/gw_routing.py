import pox.openflow.libopenflow_01 as of
from pox.core import core
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpidToStr
from util import get_links_pair
from util import get_key_from_value
import networkx as nx


class Routing:
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_PacketIn(self, event):
        eth_frame = event.parsed
        switch_src_dpid = event.dpid
        gw_dpid = core.GatewayAccess.get_dpid_gw()

        
        if eth_frame.find("icmp") and eth_frame.dst == core.GatewayAccess.gw_mac:
            
            if gw_dpid != switch_src_dpid:
                self.ip_traffic_to_gw(event)
            else:
                self.ip_traffic_to_host(event)


    def ip_traffic_to_host(self,event):
                
        gw_dpid = core.GatewayAccess.get_dpid_gw()

        # extract the IP payload
        ip_pkt = event.parsed.payload
            
        # get the IP of the host that has sent the IP message
        src_host_ip = ip_pkt.srcip

        # get the switch dpid the host is connected with
        sw_dst = core.hostDiscovery.hosts[src_host_ip]["switch"]

        # get the MAC of the host
        host_mac = core.hostDiscovery.hosts[src_host_ip]["mac"]

        # get the port of the swtich where the host is connected with
        sw_to_host_port = core.hostDiscovery.hosts[src_host_ip]["port"] 
 
        # get the id of the source switch
        S = get_key_from_value(core.linkDiscovery.switch_id, gw_dpid)

        # get the id of the destination switch
        D = get_key_from_value(core.linkDiscovery.switch_id, sw_dst)     

        # get network graph
        graph = core.Graph.graph_with_gw_node

        # compute the shortest path between S and D
        path = list(nx.shortest_path(graph, S, D))

        # get path links as a list of tuple: [(1,2),(2,3)...]
        path_links = get_links_pair(path)

        print(f"found path towards the host {src_host_ip}: {path_links}")


        # flow rule for traffic towards the gateway
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(
            dl_type=ethernet.IP_TYPE, dl_dst=host_mac
        )
        msg.flags=of.OFPFF_CHECK_OVERLAP


        for sw in path_links:
            src_dpid = core.linkDiscovery.switch_id[sw[0]]
            link_name = f"{sw[0]}_{sw[1]}"
            out_port = core.linkDiscovery.links[link_name].port1

            msg.actions = [of.ofp_action_output(port=out_port)]
            core.openflow.sendToDPID(src_dpid, msg)
            
            if sw[1] == D:
                               
                msg.actions = [of.ofp_action_output(port=sw_to_host_port)]
                core.openflow.sendToDPID(sw_dst, msg)

        # create the ICMP reply message and send it back to the gw
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.data = self.create_ICMP_REPLY(packet=event.parsed)
        msg.in_port = event.port
        core.openflow.sendToDPID(gw_dpid, msg)
        print("Sending back ICMP REPLY to gw", dpidToStr(gw_dpid))        
                

    def ip_traffic_to_gw(self,event):
        
        # get gateway pdid
        gw_dpid = core.GatewayAccess.get_dpid_gw()

        # get dpid of the current switch
        switch_src_dpid = event.dpid

        # get the id of the source switch
        S = get_key_from_value(core.linkDiscovery.switch_id, switch_src_dpid)

        # get the id of the destination switch
        D = get_key_from_value(core.linkDiscovery.switch_id, gw_dpid)

        # get network graph
        graph = core.Graph.graph_with_gw_node

        # compute the shortest path between S and D
        path = list(nx.shortest_path(graph, S, D))

        # get path links as a list of tuple: [(1,2),(2,3)...]
        path_links = get_links_pair(path)

        print(f"found path towards the gw: {path_links}")


        for sw in path_links:
            src_dpid = core.linkDiscovery.switch_id[sw[0]]
            link_name = f"{sw[0]}_{sw[1]}"
            out_port = core.linkDiscovery.links[link_name].port1

            # flow rule for traffic towards the gateway
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match(
                dl_type=ethernet.IP_TYPE, dl_dst=core.GatewayAccess.gw_mac
            )
            msg.flags=of.OFPFF_CHECK_OVERLAP
            msg.actions = [of.ofp_action_output(port=out_port)]
            core.openflow.sendToDPID(src_dpid, msg)

            if sw[1] == D:
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match(
                    dl_type=ethernet.IP_TYPE, dl_dst=core.GatewayAccess.gw_mac
                )
                msg.flags=of.OFPFF_CHECK_OVERLAP
                # msg.actions = [] # empty actions is equal to dropping packet
                msg.actions = [of.ofp_action_output(port=of.OFPP_CONTROLLER)]
                core.openflow.sendToDPID(gw_dpid, msg)



    def create_ICMP_REPLY(self, packet):
        # Make the ping reply
        icmp = pkt.icmp()
        icmp.type = pkt.TYPE_ECHO_REPLY
        icmp.payload = packet.find("icmp").payload

        # Make the IP packet around it
        ipp = pkt.ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = packet.find("ipv4").dstip
        ipp.dstip = packet.find("ipv4").srcip

        # Ethernet around that...
        e = pkt.ethernet()
        e.src = packet.dst
        e.dst = packet.src
        e.type = e.IP_TYPE

        # Hook them up...
        ipp.payload = icmp
        e.payload = ipp
        return e.pack()
    


def launch():
    core.registerNew(Routing)
