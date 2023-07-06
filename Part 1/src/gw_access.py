import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_dpid

class GatewayAccess():
    def __init__(self) -> None:
        core.openflow.addListeners(self)
        self.gw_ip = IPAddr("10.0.0.1")
        self.gw_mac = EthAddr("00:00:01:01:01:01")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if packet.type == packet.ARP_TYPE and packet.src != core.hostDiscovery.fake_mac_gw:
            if packet.payload.opcode == arp.REQUEST:
                arp_packet = packet.payload
                print(packet.payload.__dict__)
                self.install_gw_rule(event, arp_packet)
                self._handle_ARPRequest(event, arp_packet)
         
            
    def install_gw_rule(self,event, arp_packet):
        """
        Send the rule to handle ARP REPLY message of the gateway
        """
        
        msg = of.ofp_flow_mod()
        
        msg.match = of.ofp_match(
                dl_type = ethernet.ARP_TYPE,
                dl_src = self.gw_mac,
                dl_dst = arp_packet.hwsrc            
        )
        # Rule will expire after 5 seconds because it useful only to
        # send back to the host the ARP reply
        msg.hard_timeout = 5

        msg.actions.append(of.ofp_action_output(port = event.ofp.in_port))
        event.connection.send(msg)
        
        
    
    def _handle_ARPRequest(self, event, arp_packet):
        if arp_packet.protodst == self.gw_ip:
            
            # Create ARP reply message
            arp_reply = arp()
            arp_reply.opcode = arp.REPLY
            
            # As if the reply comes from the GW and not from the controller
            arp_reply.hwsrc = self.gw_mac   
            arp_reply.hwdst = arp_packet.hwsrc
            arp_reply.protosrc = arp_packet.protodst
            arp_reply.protodst = arp_packet.protosrc

            # Create ethernet frame
            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = arp_packet.hwsrc
            ether.src = self.gw_mac  
            ether.payload = arp_reply
            
            # Create openflow msg and send with a packet out
            msg = of.ofp_packet_out()
            msg.data = ether.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(msg)     
    
    def get_dpid_gw(self):
        """
        It returns the dpid of the gw since it is the same of the MAC address of interface
        eth0
        """    
        str_gw_mac = self.gw_mac.toStr()
        str_gw_dpid = str_gw_mac.replace(":","-")
        gw_dpid = str_to_dpid(str_gw_dpid)
        return gw_dpid
    
			

def launch():
    core.registerNew(GatewayAccess)
