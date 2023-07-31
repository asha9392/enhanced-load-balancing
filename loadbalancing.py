                                                     SOURCE CODE 

Random Selection :

from pox.core import core
import pox
log = core.getLogger("iqlb")

from pox.lib.packet.ethernet import ethernet,ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr,EthAddr
from pox.lib.util import str_to_bool,dpid_to_str,str_to_dpid

import pox.openflow.libopenflow_01 as of
import time
import random

FLOW_IDLE_TIMEOUT = 10
FLOW_MEMORY_TIMEOUT = 60*5

class MemoryEntry(object):

    def __init__(self,server,first_packet,client_port):
        self.server = server
        self.first_packet = first_packet
        self.client_port = client_port
        self.refresh()

    def refresh(self):
        self.timeout = time.time() + FLOW_MEMORY_TIMEOUT

    @property
    def is_expired(self):
        return time.time()>self.timeout
    @property
    def key1(self):
        ethp = self.first_packet
        ipp = ethp.find('ipv4')
        tcpp = ethp.find('tcp')
        return ipp.scrip,ipp.dstip,ipp.srcport,tcpp.dstport
    @property
    def key2(self):
        ethp = self.first_packet
        ipp = ethp.find('ipv4')
        tcpp = ethp.find('tcp')
        return self.server,ipp.scrip,tcpp.dstport,ipp.srcport
class iplb(object):
    def __init__(self,connection,service_ip,servers=[]):
        self.service_ip = IPAddr(service_ip)
        self.servers = [IPAddr(a) for a in servers]
        self.con = connection
        self.mac = self.con.eth_addr
        self.live_servers ={} #IP -> MAC,port


        try:
            self.log = log.getCHild(dpid_to_str(self.con.dpid))
        except:
            self.log =log
            self.outstanding_probes = {}#IP -> expire_time
            self.probe_cycle_time = 5
                  self.arp_timeout = 3
            # approach: hashing.
            self.memory = {} # (srcip,dstip,srcport,dstport) -> MemoryEntry
            self._do_probe() # Kick off the probing
          

    def _do_expire(self):
        
        t = time.time()

        #expire probes
        for ip,expire_at in list(self.outstanding_probes.items()):
            if t>expire_at:
                self.outstanding_probes.pop(ip,None)
                if ip in self.live_servers:
                    self.log.warn("server %s down",ip)
                    del self.live_servers[ip]

        
        # Expire old flows
        c = len(self.memory)
        self.memory = {k:v for k,v in self.memory.items()
                       if not v.is_expired}
        if len(self.memory) != c:
            self.log.debug("Expired %i flows", c-len(self.memory))

    def _do_probe(self):
        """
             send an ARP to a server to see if its still up
        """
        self._do_expire()

        server=self.servers.pop(0)
        self.servers.append(server)

        r=arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = server
        r.hwsrc = self.mac
        r.protosrc = self.service_ip
        e = ethernet(type=ethernet.ARP_TYPE, src=self.mac,
            dst=ETHER_BROADCAST)
        e.set_payload(r)
     
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = of.OFPP_NONE
        self.con.send(msg)
        self.outstanding_probes[server] = time.time()+self.arp_timeout

        core.callDelayed(self._probe_wait_time,self._do_probe)

    @property
    def _probe_wait_time(self):
        """
        Time to wait between probes
        """
        r = self.probe_cycle_time/float(len(self.servers))
        r = max(.25,r)#Cap it at four per second
        return r
    def _pick_server(self,key,inport):
        """
        pick a server for a (hopefully) new connection
        """
        return random.choice(list(self.live_servers.keys()))
    def _handle_Packets(self,event):
        inport = event.port
        packet = event.parsed

        def drop():
            if event.ofp.buffer_id is not None:
                #Kill the buffer
                msg = of.ofp_packet_out(data = event.ofp)
                self.con.send(msg)
            return None
        tcpp = packet.find('tcp')
        if not tcpp:
            arpp = packet.find('arp')
            if arpp:
                #Handle replies to our server liveness probes
                if arpp.opcode == arpp.REPLY:
                    if arpp.protosrc in self.outstandning_probes:
                                                del self.outstanding_probes[arpp.protosrc]
                        if (self.live_servers.get(arpp.protosrc, (None,None)) == (arpp.hwsrc,inport)):
                        #ah,nothing new here
                            pass
                        else:
                            #new server
                            self.live_servers[arpp.protosrc] = arpp.hwsrc,inport
                            self.log.info("server %s up",arpp.protosrc)
                return
           
            return drop()
        #its TCP

        ipp = packet.find('ipv4')

        if ipp.srcip in self.servers:
            

            key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
            entry = self.memory.get(key)

            if entry is None :
                
                self.log.debug("No client for %s", key)
                return drop()
                        entry.refresh()
            #self.log.debug("Install reverse flow for %s", key)

            # Install reverse table entry
            mac,port = self.live_servers[entry.server]
            actions = []
            actions.append(of.ofp_action_dl_addr.set_src(self.mac))
            actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
            actions.append(of.ofp_action_output(port=entry.client_port))
            match=of.ofp_match.from_packet(packet,inport)

            msg= of.ofp_flow_mod(command=of.OFPFC_ADD,idle_timeout=FLOW_IDLE_TIMEOUT,hard_timeout=of.OFP_FLOW_PERMANENT,data=event.ofp,actions=actions,match=match)
            self.con.send(msg)
        elif ipp.dstip == self.service_ip:
            #Ah, it's for our service IP and needs to be load balanced

            # Do we already know this flow?
            key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
            entry = self.memory.get(key)
            if entry is None or entry.server not in self.live_servers:
                # Don't know it (hopefully it's new!)
                if len(self.live_servers) == 0:
                    self.log.warn("No servers!")
                    return drop()

                # Pick a server for this flow
                server = self._pick_server(key, inport)
                self.log.debug("Directing traffic to %s", server)
                entry = MemoryEntry(server, packet, inport)
                self.memory[entry.key1] = entry
                self.memory[entry.key2] = entry

            # Update timestamp
            entry.refresh()
            # Set up table entry towards selected server
            mac,port = self.live_servers[entry.server]
            actions = []
            actions.append(of.ofp_action_dl_addr.set_dst(mac))
            actions.append(of.ofp_action_nw_addr.set_dst(entry.server))
            actions.append(of.ofp_action_output(port = port))
            match = of.ofp_match.from_packet(packet, inport)

            msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                  idle_timeout=FLOW_IDLE_TIMEOUT,
                                  hard_timeout=of.OFP_FLOW_PERMANENT,
                                  data=event.ofp,
                                  actions=actions,
                                  match=match)
            self.con.send(msg)

    
    _dpid = None

    def launch (ip, servers, dpid = None):
        global _dpid

        if dpid is not None:
            _dpid = str_to_dpid(dpid)
        servers = servers.replace('',''," ").split()
        servers = [IPAddr(x) for x in servers]
        ip = IPAddr(ip)

        from proto.arp_responder import ARPResponder
        old_pi = ARPResponder._handle_PacketIn
        def new_pi (self, event):
            if event.dpid == _dpid:
                # Yes, the packet-in is on the right switch
                return old_pi(self, event)
        ARPResponder._handle_PacketIn = new_pi
        # Hackery done. Now start it.
        from proto.arp_responder import launch as arp_launch
        arp_launch(eat_packets=False,**{str(ip):True})
        import logging
        logging.getLogger("proto.arp_responder").setLevel(logging.WARN)



        def _handle_ConnectionUp(event):
            global _dpid
            if _dpid is None:
                _dpid = event.dpid

            if _dpid != event.dpid:
                log.warn("ignoring switch %s",event.connection)
            else:
                if not core.hasComponent('iplb'):
                    #Need to Initialize first....
                    core.registerNew(iplb,event.connection,IPAddr(ip),servers)
                    log.info(("IP Load Balancer Ready."))
                log.info("Load Balancing on %s", event.connection)

                               core.iplb.con = event.connection
                event.connection.addListeners(core.ip)
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)


Round Robin Code :




from pox.core import core
import pox
log = core.getLogger("iplb")

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str,str_to_dpid

import pox.openflow.libopenflow_01 as of

import time
import random

FLOW_IDLE_TIMEOUT = 10
FLOW_MEMORY_TIMEOUT = 60 * 5
selected_server=0


class MemoryEntry (object):

  def __init__ (self, server, first_packet, client_port):
    self.server = server
    self.first_packet = first_packet
    self.client_port = client_port
    self.refresh()

  def refresh (self):
    self.timeout = time.time() + FLOW_MEMORY_TIMEOUT

  @property
  def is_expired (self):
    return time.time() > self.timeout

  @property
  def key1 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport

  @property
  def key2 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return self.server,ipp.srcip,tcpp.dstport,tcpp.srcport


class iplb (object):
  
  def __init__ (self, connection, service_ip, servers = []):
    self.service_ip = IPAddr(service_ip)
    self.servers = [IPAddr(a) for a in servers]
    self.con = connection
    self.selected_server=selected_server
    #self.mac = self.con.eth_addr
    self.mac=EthAddr("00:00:00:11:22:33")
    self.live_servers = {} # IP -> MAC,port

    try:
      self.log = log.getChild(dpid_to_str(self.con.dpid))
    except:
    
      self.log = log

    self.outstanding_probes = {} # IP -> expire_time

   
    self.probe_cycle_time = 5

   
    self.arp_timeout = 3

    self.memory = {} 

    self._do_probe() 

  
  def _do_expire (self):
   
    t = time.time()

    # Expire probes
    for ip,expire_at in self.outstanding_probes.items():
      if t > expire_at:
        self.outstanding_probes.pop(ip, None)
        if ip in self.live_servers:
          self.log.warn("Server %s down", ip)
          del self.live_servers[ip]

    # Expire old flows
    c = len(self.memory)
    self.memory = {k:v for k,v in self.memory.items()
                   if not v.is_expired}
    if len(self.memory) != c:
      self.log.debug("Expired %i flows", c-len(self.memory))

  def _do_probe (self):
    
    self._do_expire()

    server = self.servers.pop(0)
    self.servers.append(server)

    r = arp()
    r.hwtype = r.HW_TYPE_ETHERNET
    r.prototype = r.PROTO_TYPE_IP
    r.opcode = r.REQUEST
    r.hwdst = ETHER_BROADCAST
    r.protodst = server
    r.hwsrc = self.mac
    r.protosrc = self.service_ip
    e = ethernet(type=ethernet.ARP_TYPE, src=self.mac,
                 dst=ETHER_BROADCAST)
    e.set_payload(r)
    #self.log.debug("ARPing for %s", server)
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = of.OFPP_NONE
    self.con.send(msg)

    self.outstanding_probes[server] = time.time() + self.arp_timeout

    core.callDelayed(self._probe_wait_time, self._do_probe)

  @property
  def _probe_wait_time (self):
    """
    Time to wait between probes
    """
    r = self.probe_cycle_time / float(len(self.servers))
    r = max(.25, r) # Cap it at four per second
    return r


  def _pick_server (self, key, inport):
    global selected_server
    a=list(self.live_servers.keys())
    
    b=a[self.selected_server-1]
    self.selected_server+=1
    if self.selected_server==len(list(self.live_servers)):
      self.selected_server=0
    return b
    

  def _handle_PacketIn (self, event):
    inport = event.port
    packet = event.parsed

    def drop ():
      if event.ofp.buffer_id is not None:
        # Kill the buffer
        msg = of.ofp_packet_out(data = event.ofp)
        self.con.send(msg)
      return None

    tcpp = packet.find('tcp')
    if not tcpp:
      arpp = packet.find('arp')
      if arpp:
        # Handle replies to our server-liveness probes
        if arpp.opcode == arpp.REPLY:
          if arpp.protosrc in self.outstanding_probes:
            # A server is (still?) up; cool.
            del self.outstanding_probes[arpp.protosrc]
            if (self.live_servers.get(arpp.protosrc, (None,None))
                == (arpp.hwsrc,inport)):
            
              pass
            else:
              
              self.live_servers[arpp.protosrc] = arpp.hwsrc,inport
              self.log.info("Server %s up", arpp.protosrc)
        return

      return drop()

    
    
    ipp = packet.find('ipv4')

    if ipp.srcip in self.servers:
      

      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)

      if entry is None:
        
        self.log.debug("No client for %s", key)
        return drop()

      
      entry.refresh()

     
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_src(self.mac))
      actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
      actions.append(of.ofp_action_output(port = entry.client_port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      self.con.send(msg)

    elif ipp.dstip == self.service_ip:
      
      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)
      if entry is None or entry.server not in self.live_servers:
        
        if len(self.live_servers) == 0:
          self.log.warn("No servers!")
          return drop()

        
        for i in range(0,2):
        
          server = self._pick_server(key, inport)
        self.log.debug("Directing traffic to %s", server)
        entry = MemoryEntry(server, packet, inport)
        self.memory[entry.key1] = entry
        self.memory[entry.key2] = entry
   
      
      entry.refresh()

      
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_dst(mac))
      actions.append(of.ofp_action_nw_addr.set_dst(entry.server))
      actions.append(of.ofp_action_output(port = port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      self.con.send(msg)


_dpid = None

def launch (ip, servers, dpid = None):
  global _dpid
  if dpid is not None:
    _dpid = str_to_dpid(dpid)
    
  servers = servers.replace(","," ").split()
  servers = [IPAddr(x) for x in servers]
  ip = IPAddr(ip)
  
  from proto.arp_responder import ARPResponder
  old_pi = ARPResponder._handle_PacketIn
  def new_pi (self, event):
    if event.dpid == _dpid:
      # Yes, the packet-in is on the right switch
      return old_pi(self, event)
  ARPResponder._handle_PacketIn = new_pi

  
  from proto.arp_responder import launch as arp_launch
  arp_launch(eat_packets=False,**{str(ip):True})
  import logging
  logging.getLogger("proto.arp_responder").setLevel(logging.WARN)

  def _handle_ConnectionUp (event):
    global _dpid
    if _dpid is None:
      _dpid = event.dpid

    if _dpid != event.dpid:
      log.warn("Ignoring switch %s", event.connection)
    else:
      if not core.hasComponent('iplb'):
        # Need to initialize first...
        core.registerNew(iplb, event.connection, IPAddr(ip), servers)
        log.info("IP Load Balancer Ready.")
      log.info("Load Balancing on %s", event.connection)

      # Gross hack
      core.iplb.con = event.connection
      event.connection.addListeners(core.iplb)


  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
