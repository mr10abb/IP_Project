""" CSC 573 IP Project"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import Timer
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str, str_to_dpid
import time
import calendar
from time import gmtime
from pox.lib.packet import *
import pox.lib.packet as pkt
import math
from pox.openflow.of_json import * 

log = core.getLogger()

# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda:defaultdict(lambda:None))

# Switches we know of.  [dpid] -> Switch
switches = {}

# ethaddr -> (switch, port)
mac_map = {}

# [sw1][sw2] -> (distance, intermediate)
path_map = defaultdict(lambda:defaultdict(lambda:(None,None,None)))
port_statistics = {}

# Waiting path.  (dpid,xid)->WaitingPath
waiting_paths = {}
bwTable = {}
# Time to not flood in seconds
FLOOD_HOLDDOWN = 5

# Flow timeouts
FLOW_IDLE_TIMEOUT = 10
FLOW_HARD_TIMEOUT = 0

# How long is allowable to set up a path?
PATH_SETUP_TIME = 4

latency_to_dpid = {}
dpid_depTime = {}

def _cost (switch, p):
  m = 1
  for i,j in switches.iteritems():
    if j == switch:
      dpid = i
  #link_cost = 0.5*bwTable[dpid][p][7]   
  link_cost = round((m/float(bwTable[dpid][p][6]) + 0.5*bwTable[dpid][p][7]),3)
  print "Switch:",switch," Port:",p," Available Bandwidth is:",round(bwTable[dpid][p][6],3)," Latency:",round(bwTable[dpid][p][7],3)," Cost:", link_cost
  #print "link latency",bwTable[dpid][p][7]
  port_statistics[dpid][p][3] = link_cost
  #print port_statistics[dpid]
  return link_cost

def _calc_paths_data ():
  #print "in data"
  b=125000/100000
  m=1
  sws = switches.values()
  path_map.clear()
  for k in sws:
    for j,port in adjacency[k].iteritems():
      if port is None: continue
      path_map[k][j] = (m/b,None,None)  
    path_map[k][k] = (0,None,None) # distance, intermediate

  #dump()

  for k in sws:
    for i in sws:
      for j in sws:
        if path_map[i][k][0] is not None:
          if path_map[k][j][0] is not None:
            # i -> k -> j exists
            ikj_dist = path_map[i][k][0]+path_map[k][j][0]
            if path_map[i][j][0] is None or ikj_dist < path_map[i][j][0]:
              # i -> k -> j is better than existing
              path_map[i][j] = (ikj_dist, k)

def _calc_paths_video ():  
  """
  Essentially Floyd-Warshall algorithm
  """
  print "Calculating path for High Priority traffic:"
  sws = switches.values()
  path_map.clear()
  for k in sws:
    for j,port in adjacency[k].iteritems():
      if port is None: continue
      v = _cost(k,port)
      path_map[k][j] = (10,None,v) 
    path_map[k][k] = (0,None,0) # distance, intermediate

  #dump()

  for k in sws:
    for i in sws:
      for j in sws:
        if path_map[i][k][2] is not None:
          if path_map[k][j][2] is not None:
            # i -> k -> j exists
            ikj_dist = path_map[i][k][2]+path_map[k][j][2]
            if path_map[i][j][2] is None or ikj_dist < path_map[i][j][2]:
              # i -> k -> j is better than existing
              path_map[i][j] = (10, k, ikj_dist)

  #print "--------------------"
  #dump()


def _get_raw_path (src, dst, x):
  """
  Get a raw path (just a list of nodes to traverse)
  """
  #if len(path_map) == 0:
  if(x == 1):
    _calc_paths_video()
  else:
    #if len(path_map) == 0:
     _calc_paths_data()

  if src is dst:
    # We're here!
    return []
  if path_map[src][dst][0] is None:
    return None
  intermediate = path_map[src][dst][1]
  if intermediate is None:
    # Directly connected
    return []
  return _get_raw_path(src, intermediate, x) + [intermediate] + \
         _get_raw_path(intermediate, dst, x)


def _check_path (p):
  """
  Make sure that a path is actually a string of nodes with connected ports

  returns True if path is valid
  """
  for a,b in zip(p[:-1],p[1:]):
    if adjacency[a[0]][b[0]] != a[2]:
      return False
    if adjacency[b[0]][a[0]] != b[1]:
      return False
  return True


def _get_path (src, dst, first_port, final_port, x):
  """
  Gets a cooked path -- a list of (node,in_port,out_port)
  """
  # Start with a raw path...
  if src == dst:
    path = [src]
  else:
    path = _get_raw_path(src, dst, x)
    if path is None: return None
    path = [src] + path + [dst]
    print "Traffic is taking the path: ",path
  # Now add the ports
  r = []
  in_port = first_port
  for s1,s2 in zip(path[:-1],path[1:]):
    out_port = adjacency[s1][s2]
    r.append((s1,in_port,out_port))
    in_port = adjacency[s2][s1]
  r.append((dst,in_port,final_port))

  assert _check_path(r), "Illegal path!"

  return r


class WaitingPath (object):
  """
  A path which is waiting for its path to be established
  """
  def __init__ (self, path, packet):
    """
    xids is a sequence of (dpid,xid)
    first_switch is the DPID where the packet came from
    packet is something that can be sent in a packet_out
    """
    self.expires_at = time.time() + PATH_SETUP_TIME
    self.path = path
    self.first_switch = path[0][0].dpid
    self.xids = set()
    self.packet = packet

    if len(waiting_paths) > 1000:
      WaitingPath.expire_waiting_paths()

  def add_xid (self, dpid, xid):
    self.xids.add((dpid,xid))
    waiting_paths[(dpid,xid)] = self

  @property
  def is_expired (self):
    return time.time() >= self.expires_at

  def notify (self, event):
    """
    Called when a barrier has been received
    """
    self.xids.discard((event.dpid,event.xid))
    if len(self.xids) == 0:
      # Done!
      if self.packet:
        log.debug("Sending delayed packet out %s"
                  % (dpid_to_str(self.first_switch),))
        msg = of.ofp_packet_out(data=self.packet,
            action=of.ofp_action_output(port=of.OFPP_TABLE))
        core.openflow.sendToDPID(self.first_switch, msg)

      core.l2_multi.raiseEvent(PathInstalled(self.path))


  @staticmethod
  def expire_waiting_paths ():
    packets = set(waiting_paths.values())
    killed = 0
    for p in packets:
      if p.is_expired:
        killed += 1
        for entry in p.xids:
          waiting_paths.pop(entry, None)
    if killed:
      log.error("%i paths failed to install" % (killed,))


class PathInstalled (Event):
  """
  Fired when a path is installed
  """
  def __init__ (self, path):
    self.path = path


class Switch (EventMixin):
  def __init__ (self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None

  def __repr__ (self):
    return dpid_to_str(self.dpid)

  """ Path Installation modules"""  
  def _install (self, switch, in_port, out_port, match, buf = None):
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.match.in_port = in_port
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.actions.append(of.ofp_action_output(port = out_port))
    msg.buffer_id = buf
    switch.connection.send(msg)
 
    
  def _install_path (self, p, match, packet_in=None):
    wp = WaitingPath(p, packet_in)
    for sw,in_port,out_port in p:
      self._install(sw, in_port, out_port, match)
      msg = of.ofp_barrier_request()
      sw.connection.send(msg)
      wp.add_xid(sw.dpid,msg.xid)

  def install_path (self, dst_sw, last_port, match, event, x):
    """
    Attempts to install a path between this switch and some destination
    """
    p = _get_path(self, dst_sw, event.port, last_port, x)
    if p is None:
      log.warning("Can't get from %s to %s", match.dl_src, match.dl_dst)

      import pox.lib.packet as pkt

      if (match.dl_type == pkt.ethernet.IP_TYPE and
          event.parsed.find('ipv4')):
        # It's IP -- let's send a destination unreachable
        log.debug("Dest unreachable (%s -> %s)",
                  match.dl_src, match.dl_dst)

        from pox.lib.addresses import EthAddr
        e = pkt.ethernet()
        e.src = EthAddr(dpid_to_str(self.dpid)) #FIXME: Hmm...
        e.dst = match.dl_src
        e.type = e.IP_TYPE
        ipp = pkt.ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = match.nw_dst #FIXME: Ridiculous
        ipp.dstip = match.nw_src
        icmp = pkt.icmp()
        icmp.type = pkt.ICMP.TYPE_DEST_UNREACH
        icmp.code = pkt.ICMP.CODE_UNREACH_HOST
        orig_ip = event.parsed.find('ipv4')
        
        d = orig_ip.pack()
        d = d[:orig_ip.hl * 4 + 8]
        import struct
        d = struct.pack("!HH", 0,0) + d #FIXME: MTU
        icmp.payload = d
        ipp.payload = icmp
        e.payload = ipp
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = event.port))
        msg.data = e.pack()
        self.connection.send(msg)

      return

    log.debug("Installing path for %s -> %s %04x (%i hops)",
        match.dl_src, match.dl_dst, match.dl_type, len(p))

    # We have a path -- install it
    self._install_path(p, match, event.ofp)

    # Now reverse it and install it backwards
    # (we'll just assume that will work)
    p = [(sw,out_port,in_port) for sw,in_port,out_port in p]
    self._install_path(p, match.flip())


  def _handle_PacketIn (self, event):
    #og.debug("No flow entry")
    def flood ():
      """ Floods the packet """
      if self.is_holding_down:
        log.warning("Not flooding -- holddown active")
      msg = of.ofp_packet_out()
      # OFPP_FLOOD is optional; some switches may need OFPP_ALL
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop ():
      # Kill the buffer
      if event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        event.ofp.buffer_id = None # Mark is dead
        msg.in_port = event.port
        self.connection.send(msg)

    packet = event.parsed

    """ Matching Latency Packets """  
    if (packet.type == 0x9999):
      present = time.clock() 

      data = packet.payload

      [src_time, sdpid, ddpid, sport] = data.split(',')

      if ddpid == dpid_to_str(event.dpid):

        final_latency = round((present - float(src_time))*1000 - (latency_to_dpid[str_to_dpid(sdpid)])*1000 - (latency_to_dpid[str_to_dpid(ddpid)])*1000, 4 )

        if(final_latency >= 0):

          port_statistics[str_to_dpid(sdpid)][int(sport)][1] = final_latency
          bwTable[str_to_dpid(sdpid)][int(sport)][7] = final_latency
        else:
          port_statistics[str_to_dpid(sdpid)][int(sport)][1] = 0

      return
    

    loc = (self, event.port) # Place we saw this ethaddr
    oldloc = mac_map.get(packet.src) # Place we last saw this ethaddr


    """ Matching LLDP Packets """
    if packet.effective_ethertype == packet.LLDP_TYPE:
      drop()
      return

    if oldloc is None:
      if packet.src.is_multicast == False:
        mac_map[packet.src] = loc # Learn position for ethaddr
        log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
    elif oldloc != loc:
    
      # ethaddr seen at different place!
      if core.openflow_discovery.is_edge_port(loc[0].dpid, loc[1]):
        # New place is another "plain" port (probably)
        log.debug("%s moved from %s.%i to %s.%i?", packet.src,
                  dpid_to_str(oldloc[0].dpid), oldloc[1],
                  dpid_to_str(   loc[0].dpid),    loc[1])
        if packet.src.is_multicast == False:
          mac_map[packet.src] = loc # Learn position for ethaddr
          log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
      #elif packet.dst.is_multicast == False:
        # New place is a switch-to-switch port!
        # Hopefully, this is a packet we're flooding because we didn't
        # know the destination, and not because it's somehow not on a
        # path that we expect it to be on.
        # If spanning_tree is running, we might check that this port is
        # on the spanning tree (it should be).
        #if packet.dst in mac_map:
          # Unfortunately, we know the destination.  It's possible that
          # we learned it while it was in flight, but it's also possible
          # that something has gone wrong.
          #log.warning("Packet from %s to known destination %s arrived "
                      #"at %s.%i without flow", packet.src, packet.dst,
                      #dpid_to_str(self.dpid), event.port)

    """ Matching Multicast Packets """
    if packet.dst.is_multicast:
      log.debug("Flood multicast from %s", packet.src)
      flood()
    else:
      if packet.dst not in mac_map:
        log.debug("%s unknown -- flooding" % (packet.dst,))
        flood()
      elif packet.dst in mac_map:
        if (packet.effective_ethertype == packet.IP_TYPE and packet.find('ipv4').tos == 32):
          print "High priority traffic. TOS bits are set to 32. Statistics are as below:"
          
          dest = mac_map[packet.dst]
          match = of.ofp_match.from_packet(packet)
          self.install_path(dest[0], dest[1], match, event, 1)
        elif packet.effective_ethertype == packet.ARP_TYPE:
          print "This is an ARP Packet"
          #flood()
          dest = mac_map[packet.dst]
          match = of.ofp_match.from_packet(packet)
          self.install_path(dest[0], dest[1], match, event, 0)
        else:
        
          print "Data Traffic received. Printing the Path :"
          
          dest = mac_map[packet.dst]
          match = of.ofp_match.from_packet(packet)
          self.install_path(dest[0], dest[1], match, event, 0)
          

  def disconnect (self):
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None

  def connect (self, connection):
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    log.debug("Connect %s" % (connection,))
    self.connection = connection
    self._listeners = self.listenTo(connection)
    self._connected_at = time.time()

  @property
  def is_holding_down (self):
    if self._connected_at is None: return True
    if time.time() - self._connected_at > FLOOD_HOLDDOWN:
      return False
    return True

  def _handle_ConnectionDown (self, event):
    self.disconnect()


class l2_multi (EventMixin):

  _eventMixin_events = set([
    PathInstalled,
  ])

  def __init__ (self):
    # Listen to dependencies (specifying priority 0 for openflow)
    core.listen_to_dependencies(self, listen_args={'openflow':{'priority':0}})

  """ Handling Link Events """  
  def _handle_openflow_discovery_LinkEvent (self, event):
    def flip (link):
      return Discovery.Link(link[2],link[3], link[0],link[1])

    l = event.link
    sw1 = switches[l.dpid1]
    sw2 = switches[l.dpid2]

    # Invalidate all flows and path info.
    # For link adds, this makes sure that if a new link leads to an
    # improved path, we use it.
    # For link removals, this makes sure that we don't use a
    # path that may have been broken.
    #NOTE: This could be radically improved! (e.g., not *ALL* paths break)
    clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    for sw in switches.itervalues():
      if sw.connection is None: continue
      sw.connection.send(clear)
    path_map.clear()

    if event.removed:
      # This link no longer okay
      if sw2 in adjacency[sw1]: del adjacency[sw1][sw2]
      if sw1 in adjacency[sw2]: del adjacency[sw2][sw1]

      # But maybe there's another way to connect these...
      for ll in core.openflow_discovery.adjacency:
        if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:
          if flip(ll) in core.openflow_discovery.adjacency:
            # Yup, link goes both ways
            adjacency[sw1][sw2] = ll.port1
            adjacency[sw2][sw1] = ll.port2
            # Fixed -- new link chosen to connect these
            break
    else:
      # If we already consider these nodes connected, we can
      # ignore this link up.
      # Otherwise, we might be interested...
      if adjacency[sw1][sw2] is None:
        # These previously weren't connected.  If the link
        # exists in both directions, we consider them connected now.
        if flip(l) in core.openflow_discovery.adjacency:
          # Yup, link goes both ways -- connected!
          adjacency[sw1][sw2] = l.port1
          adjacency[sw2][sw1] = l.port2

      # If we have learned a MAC on this port which we now know to
      # be connected to a switch, unlearn it.
      bad_macs = set()
      for mac,(sw,port) in mac_map.iteritems():
        if sw is sw1 and port == l.port1: bad_macs.add(mac)
        if sw is sw2 and port == l.port2: bad_macs.add(mac)
      for mac in bad_macs:
        log.debug("Unlearned %s", mac)
        del mac_map[mac]

        
  def _handle_openflow_ConnectionUp (self, event):
    sw = switches.get(event.dpid)
    if sw is None:
      # New switch
      sw = Switch()
      switches[event.dpid] = sw
      sw.connect(event.connection)
    else:
      sw.connect(event.connection)

    
    latency_to_dpid[event.dpid] = 0.0
    bwTable[event.dpid] = {}
    dpid_depTime[event.dpid] = 0.0
    port_statistics[event.dpid] = {}
    for p in event.ofp.ports:
      bwTable[event.dpid][p.port_no] = [0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0] # [new_rx, old_rx, new_tx, old_tx, new_used_bw, old_used_bw, available_bw, latency]
      port_statistics[event.dpid][p.port_no] = [p.hw_addr,0.0,0.0,0.0]

  def _handle_openflow_BarrierIn (self, event):
    wp = waiting_paths.pop((event.dpid,event.xid), None)
    if not wp:
      #log.info("No waiting packet %s,%s", event.dpid, event.xid)
      return
    #log.debug("Notify waiting packet %s,%s", event.dpid, event.xid)
    wp.notify(event)

""" Calculating Latency """
def calculate_latency ():


  for sobj in core.openflow_discovery.adjacency:
    src_mac = port_statistics[sobj.dpid1][sobj.port1][0]
    dst_mac = port_statistics[sobj.dpid2][sobj.port2][0]
    packet = pkt.ethernet(type = 0x9999)
    packet.src = src_mac
    packet.dst = dst_mac
    packet.payload = str(time.clock()) + ',' + dpid_to_str(sobj.dpid1) + ',' + dpid_to_str(sobj.dpid2) + ',' + str(sobj.port1)
    msg = of.ofp_packet_out(action = of.ofp_action_output(port = sobj.port1))
    msg.data = packet.pack()
    core.openflow.sendToDPID(sobj.dpid1, msg)


""" Calculating Latency to DPID """
def calculate_dpid_latency (dpid, arrival_time):

  delay = round((arrival_time - dpid_depTime[dpid]), 5)
  latency_to_dpid[dpid] = delay/2 ## two-way latency

def _handle_switchdesc_received (event): 

  arrival_time = time.clock()
  calculate_dpid_latency (event.connection.dpid, arrival_time) 

""" Calling Latency calculation modules """
def _timer_func_latency ():  
  
  #print " Latest Latency Values"

  #for sobj in core.openflow_discovery.adjacency:
    #for p in port_statistics[sobj.dpid1].keys():
      #print  sobj.dpid1, sobj.port1, port_statistics[sobj.dpid1][sobj.port1][1] 

  for connection in core.openflow._connections.values():
    dpid_depTime[connection.dpid] = time.clock()
    connection.send(of.ofp_stats_request(body=of.ofp_desc_stats_request()))

  calculate_latency()


""" Calling Available Bandwidth calculation modules """
def _timer_func_bw ():
  for connection in core.openflow._connections.values():
    #connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
    connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
  #print "Sent ", len(core.openflow._connections),  " flow/port stats request(s)"


def _handle_portstats_received (event):  

  for p in event.stats:
    #if p.port_no == 65534:
      #continue
    bwTable [event.connection.dpid][p.port_no][0] = p.rx_bytes
    bwTable [event.connection.dpid][p.port_no][2] = p.tx_bytes

  #for i in switches.keys():
  i = event.connection.dpid
  for port in bwTable[i].keys():
    if bwTable[i][port][5] == 0:
      bwTable[i][port][5] = bwTable[i][port][4] = (bwTable[i][port][2] - bwTable[i][port][3]) /5.0 # if old avg is 0, set the old avg = new avg
      
      if (bwTable[i][port][4]/125000) > 0.8:
        bwTable[i][port][6] = 0.1
      else:
        bwTable[i][port][6] = (125000 - bwTable[i][port][4])/100000
      
      bwTable[i][port][1] = bwTable[i][port][0]
      bwTable[i][port][3] = bwTable[i][port][2]

    else:

      new_used_bw = (bwTable[i][port][2] - bwTable[i][port][3] )/5.0
      new_tx = (bwTable[i][port][2] - bwTable[i][port][3])/5.0
      new_avg_used_bw = ((bwTable[i][port][5] + new_used_bw)/2.0)
      bwTable[i][port][5] = bwTable[i][port][4] # Setting old_used_bw
      bwTable[i][port][4] = math.ceil(new_avg_used_bw) # setting new_used_bw
      #bwTable[i][port][6] = (125000 - new_used_bw)/1000000  #Subtracting the used bw from static bw of 10 Mbps = 1250000 bytes/sec to give available bw
      bwTable[i][port][1] = bwTable[i][port][0]
      bwTable[i][port][3] = bwTable[i][port][2]
      if (new_used_bw/125000) > 0.8:
        bwTable[i][port][6] = 0.1
      else:  
        bwTable[i][port][6] = (125000 - new_used_bw)/100000

""" Program Launch """
def launch ():
  core.registerNew(l2_multi)
  import pox.openflow.discovery
  pox.openflow.discovery.launch()
  import pox.openflow.spanning_tree
  pox.openflow.spanning_tree.launch()
  timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)

  core.openflow.addListenerByName("PortStatsReceived",_handle_portstats_received)
  core.openflow.addListenerByName("SwitchDescReceived",_handle_switchdesc_received)  
  
  Timer( 6, _timer_func_latency, recurring=True)
  Timer( 5, _timer_func_bw, recurring=True)


