import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpidToStr
from util import get_key_from_value
import networkx as nx
import numpy as np
from pox.lib.revent.revent import EventMixin
from pox.lib.revent.revent import Event

# To use event handler you should know a priori what are the number
# of links between switches
#LINKS = 48
LINKS = 12
MAX_HOSTS = 5

class linkDiscovered(Event):
    def __init__(self):
        Event.__init__(self)


class Link:
    def __init__(self, sid1, sid2, dpid1, port1, dpid2, port2, gw_link):
        self.name = str(sid1) + "_" + str(sid2)
        self.sid1 = sid1
        self.sid2 = sid2
        self.dpid1 = dpidToStr(dpid1)
        self.dpid2 = dpidToStr(dpid2)
        self.port1 = int(port1)
        self.port2 = int(port2)
        self.gw_link = gw_link
        self.flow = 0
        
class linkDiscovery(EventMixin):
    _eventMixin_events = set([linkDiscovered,])

    def __init__(self):
        core.openflow.addListeners(self)
        self.switches = {}
        self.links = {}
        self.switch_id = {}
        self.id = 1
        Timer(5, self.sendProbes, recurring=True)

    def _handle_ConnectionUp(self, event):
        self.switch_id[self.id] = event.dpid
        self.switches[event.dpid] = event.ofp.ports
        self.install_flow_rule(event.dpid)
        print("Connection Up: " + dpidToStr(event.dpid) + ", " + str(self.id))
        self.id += 1

        # when the gw is connected install the flow rule to discard
        # host discovery packet
        if core.GatewayAccess.get_dpid_gw() == event.dpid:
            self.install_gw_rule()
        
    
    def _handle_PacketIn(self, event):
        eth_frame = event.parsed
        if eth_frame.src == EthAddr("00:11:22:33:44:55"):
            eth_dst = eth_frame.dst.toStr().split(":")
            sid1 = int(eth_dst[4])
            dpid1 = self.switch_id[sid1]
            port1 = int(eth_dst[5])
            dpid2 = event.dpid
            sid2 = list(self.switch_id.keys())[
                list(self.switch_id.values()).index(dpid2)
            ]
            port2 = event.ofp.in_port
            gw_link = dpid1 == core.GatewayAccess.get_dpid_gw() or dpid2 == core.GatewayAccess.get_dpid_gw() 
            link = Link(sid1, sid2, dpid1, port1, dpid2, port2, gw_link)
            
            if link.name not in self.links:

                self.links[link.name] = link
                print("discovered new link: " + link.name)
                print(link.__dict__)

                if len(self.links) == LINKS:
                    self.raiseEvent(linkDiscovered)


    def sendProbes(self):
        """
        Send packet with fake mac address to discover switches
        """
        for sid in self.switch_id:
            dpid = self.switch_id[sid]
            for port in self.switches[dpid]:
                if port.port_no != 65534:
                    mac_src = EthAddr("00:11:22:33:44:55")
                    mac_dst = EthAddr(
                        "00:00:00:00:" + str(sid) + ":" + str(port.port_no)
                    )
                    ether = ethernet()
                    ether.type = ethernet.ARP_TYPE
                    ether.src = mac_src
                    ether.dst = mac_dst
                    ether.payload = arp()
                    msg = of.ofp_packet_out()
                    msg.data = ether.pack()
                    msg.actions.append(of.ofp_action_output(port=port.port_no))
                    core.openflow.sendToDPID(dpid, msg)

    def install_gw_rule(self):
        """
        The gw is not intended to use for host discovery so we proactively install a rule
        to drop all host discovery packets that come from leaves and spines 
        """
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(
            dl_type=ethernet.ARP_TYPE, dl_dst=core.hostDiscovery.fake_mac_gw
        )

        msg.actions = [] # empty actions is equal to dropping packet
        core.openflow.sendToDPID(core.GatewayAccess.get_dpid_gw(), msg)



    def install_flow_rule(self, dpid):
        """
        Flow rule for network discovery
        """

        msg = of.ofp_flow_mod()
        msg.priority = 50000
        match = of.ofp_match(dl_src=EthAddr("00:11:22:33:44:55"))
        msg.match = match
        msg.actions = [of.ofp_action_output(port=of.OFPP_CONTROLLER)]
        core.openflow.sendToDPID(dpid, msg)


class hostDiscovery:
    def __init__(self,componentLinkDiscovery):
        componentLinkDiscovery.addListeners(self)
        core.openflow.addListeners(self)
        self.hosts = {}
        self.max_hosts = MAX_HOSTS  # assumption
        self.fake_mac_gw = EthAddr("00:00:00:00:11:11")
        self.fake_ip_gw = IPAddr("10.0.0.200") # fake gateway used for host discovery
        self.connections = list()

    def _handle_linkDiscovered(self,event):

        print(f"All {len(core.linkDiscovery.links)} links have been discovered, starting host discovering...\n")
        
        for conn in self.connections:
            self.hostDiscovery(conn)

    def _handle_ConnectionUp(self, event):
        self.connections.append(event.connection)

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
            # there is no assumption about the output port
            msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
            connection.send(msg)

    def _handle_PacketIn(self, event):
        eth_frame = event.parsed

        # handle the ARP reply to store host location
        if eth_frame.type == ethernet.ARP_TYPE and eth_frame.dst == self.fake_mac_gw:
            arp_msg = eth_frame.payload
            if arp_msg.opcode == arp.REPLY:
                ip_host = arp_msg.protosrc
                mac_host = arp_msg.hwsrc

                if ip_host not in self.hosts:
                    self.hosts[ip_host] = {
                        "switch": event.dpid,
                        "port": event.port,
                        "mac": mac_host,
                    }

                    sw_id = get_key_from_value(core.linkDiscovery.switch_id,event.dpid)
                    sw_dpid = dpidToStr(self.hosts[ip_host]["switch"])
                    print("Host:", ip_host)
                    print("Switch:",sw_id,",",sw_dpid)
                    print("Port:", self.hosts[ip_host]["port"])
                    print("MAC:", self.hosts[ip_host]["mac"])
                    print()


def launch():
    core.registerNew(linkDiscovery)
    core.register(hostDiscovery(core.linkDiscovery))
