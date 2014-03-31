############################################################################
##
## Copyright (c) 2000-2014 BalaBit IT Ltd, Budapest, Hungary
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
##
############################################################################
"""
<module maturity="stable">
  <summary>The Dispatch module defines the classes that accept incoming connections.</summary>
   <description>
    <para>
      Dispatchers bind to a specific IP address and port of the Zorp firewall and wait for incoming connection requests.
      For each accepted connection, the Dispatcher creates a new service instance to handle the traffic arriving in
      the connection.
        </para>
        <note><para>Earlier Zorp versions used different classes to handle TCP and
        UDP connections (Listeners and Receivers, respectively).
         These classes have been merged into the Dispatcher module.</para></note>
         <para>For each accepted connection, the Dispatcher creates a new service
         instance to handle the traffic arriving in the connection. The service
         started by the dispatcher depends on the type of the dispatcher:
    </para>
        <itemizedlist>
                <listitem>
                        <para>
                        <link linkend="python.Dispatch.Dispatcher">Dispatchers</link>
                        start the same service for every connection.
                        </para>
                </listitem>
                <listitem>
                        <para>
                        <link linkend="python.Dispatch.CSZoneDispatcher">CSZoneDispatchers</link>
                        start different services based on the zones the client
                        and the destination server belong to.
                        </para>
                </listitem>
        </itemizedlist>
        <note>
        <para>
        Only one dispatcher can bind to an IP address/port pair.
        </para>
        </note>
        <section id="dispatcher_service_selection">
        <title>Zone-based service selection</title>
              <para>
              Dispatchers can start only a predefined service. Use
              CSZonedDispatchers to start different services for different connections.
              CSZoneDispatchers assign different services to different client-server zone pairs.
              Define the zones and the related services in the
              <parameter>services</parameter> parameter.
                The <parameter>*</parameter> wildcard matches all client or server zones.
            </para>
            <note>
              <para>
                The server zone may be modified by the proxy, the router, the
                chainer, or the NAT policy used in the service. To select the
                service, CSZoneDispatcher determines the server zone from the
                original destination IP address of the incoming client request.
                Similarly, the client zone is determined from the source IP
                   address of the original client request.
              </para>
            </note>
            <para>
              To accept connections from the child zones of the selected client
              zones, set the <parameter>follow_parent</parameter> attribute
              to <parameter>TRUE</parameter>. Otherwise, the dispatcher accepts
              traffic only from the client zones explicitly listed in the
              <parameter>services</parameter> attribute of the dispatcher.
            </para>
            </section>
        </description>
  <metainfo>
    <enums>
      <enum maturity="stable" id="enum.zd.pri">
        <description/>
        <item>
          <name>ZD_PRI_LISTEN</name>
        </item>
        <item>
          <name>ZD_PRI_NORMAL</name>
        </item>
        <item>
          <name>ZD_PRI_RELATED</name>
        </item>
      </enum>
    </enums>
  </metainfo>
</module>
"""
from Zorp import *
from Zone import Zone
from Session import MasterSession, ClientInfo
from Cache import ShiftCache
from SockAddr import SockAddrInet, SockAddrInet6
from Subnet import Subnet
from Util import *
from Exceptions import *

from traceback import print_exc
import Zorp, SockAddr
import collections, sys

import kzorp.messages as kzorp
import socket

listen_hook = None
unlisten_hook = None
dispatch_id = 0

ZD_PRI_LISTEN = 100
ZD_PRI_NORMAL = 0
ZD_PRI_RELATED = -100

"""
<module maturity="stable">
  <summary>
  </summary>
  <description/>
</module>
"""
def convertSockAddrToDB(sa, protocol):
    """
    <function internal="yes">
    </function>
    """
    if isinstance(sa, collections.Sequence):
        return map(lambda x: convertSockAddrToDB(x), sa)

    if isinstance(sa, Zorp.SockAddrType):
        if protocol == ZD_PROTO_AUTO:
            raise ValueError, "No preferred protocol specified"
        return DBSockAddr(sa, protocol=protocol)
    else:
        if sa.protocol:
            if sa.protocol != protocol:
                raise ValueError, "Protocol number mismatch (%d != %d)" % (sa.protocol, protocol)
        else:
            sa.protocol = protocol
        return sa

def convertDBProtoToIPProto(dbproto):
    """<function internal="yes">
    </function>
    """
    if dbproto == ZD_PROTO_TCP:
        return socket.IPPROTO_TCP
    elif dbproto == ZD_PROTO_UDP:
        return socket.IPPROTO_UDP
    raise ValueError, "Unknown dispatch bind protocol"

def convertIPProtoToDBProto(ipproto):
    """
    <function internal="yes"/>
    """
    if ipproto == socket.IPPROTO_TCP:
        return ZD_PROTO_TCP
    elif ipproto == socket.IPPROTO_UDP:
        return ZD_PROTO_UDP
    raise ValueError, "IP protocol not representable in DBProto; protocol='%d'" % (ipproto,)

class BaseDispatch(object):
    """
    <class maturity="stable" abstract="yes" internal="yes">
    <summary>Class encapsulating the abstract Dispatch interface.</summary>
      <description>
        <para>
        </para>
      </description>
    </class>
    """
    def __init__(self, session_id, bindto=None, **kw):
        """
        <method internal="yes">
        </method>
        """
        global dispatch_id

        if not isSequence(bindto):
            raise ValueError, "bindto is required argument and must be a sequence"

        self.session_id = '%s/dsp/dispatch:%d' % (session_id, dispatch_id)
        dispatch_id = dispatch_id + 1
        self.dispatches = []
        prio = kw.pop('prio', ZD_PRI_LISTEN)
        self.transparent = kw.setdefault('transparent', FALSE)
        self.rule_port = self._parsePortString(kw.pop('rule_port', ""))

        if kw == None:
            kw = {}

        for b in bindto:
            self.dispatches.append(Dispatch(self.session_id, b, prio, self.accepted, kw))

        Globals.dispatches.append(self)

    @staticmethod
    def _parsePortString(s):
        """<function internal="yes">
        </function>
        """
        if not s:
            return []
        if type(s) == int:
            return [(s, s)]
        ranges = []
        for p in s.split(","):
            c = p.count(":")
            if c == 0:
                ranges.append((int(p), int(p)))
            elif c == 1:
                (start, end) = p.split(":")[:2]
                ranges.append((int(start), int(end)))
            else:
                raise ValueError, "Invalid port range: '%s'" % (p)
        return ranges

    @staticmethod
    def _startInstance(client_info, service):
        try:
            session = MasterSession(protocol=client_info.client_listen.protocol, service=service, client_info=client_info, instance_id=getInstanceId(service.name))

            client_info.client_stream.name = session.session_id

            ## LOG ##
            # This message reports that the given service is started, because of a new connection.
            ##
            #log(self.session_id, CORE_SESSION, 5, "Starting service; name='%s'", service.name)
            log(session.session_id, CORE_SESSION, 5, "Starting service; name='%s'", service.name)

            if service.startInstance(session):
                return TRUE

        except ZoneException, s:
            ## LOG ##
            # This message indicates that no appropriate zone was found for the client address.
            # @see: Zone
            ##
            log(session.session_id, CORE_POLICY, 1, "Zone not found; info='%s'", (s,))
        except DACException, s:
            ## LOG ##
            # This message indicates that an DAC policy violation occurred.
            # It is likely that the new connection was not permitted as an outbound_service in the given zone.
            # @see: Zone
            ##
            log(session.session_id, CORE_POLICY, 1, "DAC policy violation; info='%s'", (s,))
        except MACException, s:
            ## LOG ##
            # This message indicates that a MAC policy violation occurred.
            ##
            log(session.session_id, CORE_POLICY, 1, "MAC policy violation; info='%s'", (s,))
        except AAException, s:
            ## LOG ##
            # This message indicates that an authentication failure occurred.
            # @see: Auth
            ##
            log(session.session_id, CORE_POLICY, 1, "Authentication failure; info='%s'", (s,))
        except LimitException, s:
            ## LOG ##
            # This message indicates that the maximum number of concurrent instance number is reached.
            # Try increase the Service "max_instances" attribute.
            # @see: Service.Service
            ##
            log(session.session_id, CORE_POLICY, 1, "Connection over permitted limits; info='%s'", (s,))
        except LicenseException, s:
            ## LOG ##
            # This message indicates that the licensed number of IP address limit is reached, and no new IP address is allowed or an unlicensed component is used.
            # Check your license's "Licensed-Hosts" and "Licensed-Options" options.
            ##
            log(session.session_id, CORE_POLICY, 1, "Attempt to use an unlicensed component, or number of licensed hosts exceeded; info='%s'", (s,))
        except RuntimeError, s:
            log(session.session_id, CORE_POLICY, 1, "Unexpected runtime error occured; info='%s'", (s,))
        except:
            print_exc()

        if session != None:
            session.destroy()

        return None


    def accepted(self, stream, client_address, client_local, client_listen):
        """
        <method internal="yes">
          <summary>Callback to inform the python layer about incoming connections.</summary>
          <description>
            <para>
              This callback is called by the core when a connection is
              accepted. Its primary function is to check access control
              (whether the client is permitted to connect to this port),
              and to spawn a new session to handle the connection.
            </para>
            <para>
              Exceptions raised due to policy violations are handled here.
              Returns TRUE if the connection is accepted
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>stream</name>
                <type></type>
                <description>the stream of the connection to the client</description>
              </argument>
              <argument maturity="stable">
                <name>client_address</name>
                <type></type>
                <description>the address of the client</description>
              </argument>
              <argument maturity="stable">
                <name>client_local</name>
                <type></type>
                <description>client local address (contains the original destination if transparent)</description>
              </argument>
              <argument maturity="stable">
                <name>client_listen</name>
                <type></type>
                <description>the address where the listener was bound to</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        if stream == None:
            return None
        session = None
        client_info = ClientInfo(client_stream=stream,
                                 client_local=client_local,
                                 client_listen=client_listen,
                                 client_address=client_address)

        service = self.getService(client_info)
        if not service:
            raise DACException, "No applicable service found"

        ## LOG ##
        # This message indicates that a new connection is accepted.
        ##
        #log(session.session_id, CORE_DEBUG, 8, "Connection accepted; client_address='%s'", (client_address,))
        log(None, CORE_DEBUG, 8, "Connection accepted; client_address='%s'", (client_address,))

        return self._startInstance(client_info, service)

    def getService(self, session):
        """
        <method internal="yes">
          <summary>Get the service associated with the session</summary>
          <description>
            <para>
              Returns the service to start.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>session</name>
                <type></type>
                <description>session reference</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        return None

    def destroy(self):
        """
        <method internal="yes">
          <summary>Stops the listener on the given port</summary>
          <description>
            <para>
              Calls the destroy method of the low-level object
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        for d in self.dispatches:
            d.destroy()

    def buildKZorpMessage(self):
        """<method internal="yes">
        </method>
        """
        return []

    def buildKZorpBindMessage(self):
        """<method internal="yes">
        </method>
        """
        return []

class RuleDispatcher(BaseDispatch):
    """
    <class maturity="stable" internal="yes">
      <summary></summary>
      <description>
      </description>
      <metainfo>
        <attributes>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, **kw):
        """<method internal="yes">
        </method>
        """
        self.bindto = []
        self.bindto.append(DBSockAddr(SockAddrInet("127.0.0.1", 0), ZD_PROTO_TCP))
        self.bindto.append(DBSockAddr(SockAddrInet("127.0.0.1", 0), ZD_PROTO_UDP))
        self.bindto.append(DBSockAddr(SockAddrInet6("::1", 0), ZD_PROTO_TCP))
        self.bindto.append(DBSockAddr(SockAddrInet6("::1", 0), ZD_PROTO_UDP))
        kw['transparent'] = TRUE
        super(RuleDispatcher, self).__init__(Globals.instance_name, self.bindto, **kw)

    def getService(self, session):
        """<method internal="yes">
        </method>
        """
        # query the KZorp result for the client fd of this session
        fd = session.client_stream.fd
        result = getKZorpResult(session.client_address.family, fd)
        if (result):
            (client_zone_name, server_zone_name, dispatcher_name, service_name) = result

            return Globals.services.get(service_name)
        else:
            ## LOG ##
            # This message indicates that the KZorp result
            # lookup has failed for this session.
            ##
            log(None, CORE_POLICY, 0, "Unable to determine service, KZorp service lookup failed; bindto='%s'", (self.bindto[0], ))
            return None

    def buildKZorpMessage(self):
        """<method internal="yes">
        </method>
        """
        messages = []

        messages.append(kzorp.KZorpAddDispatcherMessage(self.session_id, Globals.rules.length))

        for rule in Globals.rules:
            messages.extend(rule.buildKZorpMessage(self.session_id))

        return messages

    def buildKZorpBindMessage(self):
        """<method internal="yes">
        </method>
        """
        messages = []
        for bind in self.bindto:
            messages.append(kzorp.KZorpAddBindMessage(bind.sa.family, Globals.instance_name,
                                                     bind.sa.pack(), bind.sa.port,
                                                     convertDBProtoToIPProto(bind.protocol)))
        return messages

    @classmethod
    def createOneInstance(cls):
        """<method internal="yes">
        </method>
        """
        def deinit():
          cls._singletonRuleDispatcher = None

        if not hasattr(cls, "_singletonRuleDispatcher"):
            cls._singletonRuleDispatcher = RuleDispatcher()

            #This is need to break the circular reference on RuleDispatcher
            Globals.deinit_callbacks.append(deinit)

class Dispatcher(BaseDispatch):
    """
    <class maturity="stable">
      <summary>Class encapsulating the Dispatcher which starts a service by the client and server zone.</summary>
      <description>
        <para>
          This class is the starting point of Zorp services. It listens on the
          given port, and when a connection is accepted it starts a session
          and the given service.
        </para>
        <example>
            <title>Dispatcher example</title>
            <para>The following example defines a transparent dispatcher that
            starts the service called <parameter>demo_http_service</parameter>
            for connections received on the <parameter>192.168.2.1</parameter>
             IP address.</para>
            <synopsis>Dispatcher(bindto=SockAddrInet('192.168.2.1', 50080), service="demo_http_service", transparent=TRUE, backlog=255, threaded=FALSE)</synopsis>
        </example>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>service</name>
                    <type>
                      <service/>
                    </type>
            <description>Name of the service to start.</description>
          </attribute>
          <attribute maturity="stable">
            <name>bindto</name>
                    <type>
                      <sockaddr existing="yes"/>
                    </type>
                    <description>An existing <link linkend="python.SockAddr">socket address</link> containing the IP address and port number where the Dispatcher accepts connections.</description>
          </attribute>
          <attribute maturity="stable">
            <name>protocol</name>
            <type></type>
            <description>the protocol we were bound to</description>
          </attribute>
          <attribute>
            <name>backlog</name>
            <type>
            <integer/>
            </type>
            <description><emphasis>Applies only to TCP connections.</emphasis>
            This parameter sets the queue size (maximum number)
            of TCP connections that are established by the kernel, but not
            yet accepted by Zorp. This queue stores the connections that
            successfully performed the three-way TCP handshake with the Zorp
            host, until the dispatcher sends the <emphasis>Accept</emphasis>
            package.</description>
            </attribute>
            <attribute>
            <name>threaded</name>
            <type>
            <boolean/>
            </type>
            <description>Set this parameter to <parameter>TRUE</parameter>
            to start a new thread for every client request. The proxy threads
            started by the dispatcher will start from the dispatcher's thread
            instead of the main Zorp thread. Zorp accepts incoming connections
            faster and optimizes queuing if this option is enabled. This
            improves user experience, but significantly increases the memory
            consumption of Zorp. Use it only if Zorp has to transfer a very
            high number of concurrent connections.
            </description>
            </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, bindto=None, service=None, **kw):
        """
        <method maturity="stable">
          <summary>Constructor to initialize a Dispatcher instance.</summary>
          <description>
            <para>
              This constructor creates a new Dispatcher instance which can be
              associated with a <link linkend="python.Service.Service">Service</link>.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>bindto</name>
                <type>
                  <sockaddr existing="yes"/>
                </type>
                <description>An existing <link linkend="python.SockAddr">socket address</link> containing the IP address and port number where the Dispatcher accepts connections.</description>
              </argument>
              <argument maturity="stable">
                <name>service</name>
                <type>
                  <service/>
                </type>
                <description>Name of the service to start.</description>
              </argument>
              <argument maturity="stable">
                <name>transparent</name>
                <type>
                  <boolean/>
                </type>
                <description>Set this parameter to <parameter>TRUE</parameter> if the
                dispatcher starts a transparent service.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        try:
            if service != None:
                self.service = Globals.services[service]
            else:
                self.service = None
        except KeyError:
            raise ServiceException, "Service %s not found" % (service,)

        bindto = makeSequence(bindto)

        # make sure that bind addresses are consistent wrt. the protocol
        self.protocol = ZD_PROTO_AUTO
        for b in bindto:
            if b.protocol == ZD_PROTO_AUTO:
                raise ValueError, "No preferred protocol is specified"
            if b.protocol != self.protocol:
                if self.protocol == ZD_PROTO_AUTO:
                    self.protocol = b.protocol
                else:
                    raise ValueError, "Inconsistent protocol specified in dispatch addresses"

        self.bindto = bindto
        super(Dispatcher, self).__init__(Globals.instance_name, bindto, **kw)

    def getService(self, client_info):
        """
        <method internal="yes">
          <summary>Returns the service associated with the listener</summary>
          <description>
            <para>
              Returns the service to start.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>client_info</name>
                <type></type>
                <description>client_info reference</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        return self.service

class ZoneDispatcher(Dispatcher):
    """
    <class maturity="stable" internal="yes">
      <summary>Class encapsulating the Dispatcher which starts a service by the client zone.</summary>
      <description>
        <para>
          This class is similar to a simple Dispatcher, but instead of
          starting a fixed service, it chooses one based on the client
          zone.
        </para>
        <para>
          It takes a mapping of services indexed by a zone name, with
          an exception of the '*' service, which matches anything.
        </para>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>services</name>
                <type>
                      <hash>
                        <key>
                            <zone/>
                        </key>
                        <value>
                            <service/>
                        </value>
                      </hash>
                    </type>
            <description>services mapping indexed by zone name</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, bindto=None, services=None, **kw):
        """
        <method maturity="stable">
          <summary>Constructor to initialize a ZoneDispatcher instance.</summary>
          <description>
            <para>
              This constructor initializes a ZoneDispatcher instance and sets
              its initial attributes based on arguments.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>bindto</name>
                <type></type>
                <description>bind to this address</description>
              </argument>
              <argument maturity="stable">
                <name>services</name>
                <type></type>
                <description>a mapping between zone names and services</description>
              </argument>
              <argument maturity="stable">
                <name>follow_parent</name>
                <type></type>
                <description>whether to follow the administrative hieararchy when finding the correct service</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.follow_parent = kw.pop('follow_parent', FALSE)
        super(ZoneDispatcher, self).__init__(bindto, None, **kw)
        self.services = services
        self.cache = ShiftCache('sdispatch(%s)' % str(bindto), config.options.zone_dispatcher_shift_threshold)

    def getService(self, client_info):
        """
        <method internal="yes">
          <summary>Virtual function which returns the service to be ran</summary>
          <description>
            <para>
              This function is called by our base class to find out the
              service to be used. It uses the client zone name to decide
              which service to use.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>client_info</name>
                <type></type>
                <description>Client connection info</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """

        cache_ndx = client_info.client_zone.getName()

        cached = self.cache.lookup(cache_ndx)
        if cached == 0:
            ## LOG ##
            # This message indicates that no applicable service was found for this client zone in the services cache.
            # It is likely that there is no applicable service configured in this ZoneListener/Receiver at all.
            # Check your ZoneListener/Receiver service configuration.
            # @see: Listener.ZoneListener
            # @see: Receiver.ZoneReceiver
            ##
            log(None, CORE_POLICY, 2, "No applicable service found for this client zone (cached); bindto='%s', client_zone='%s'", (self.bindto, client_info.client_zone))
        elif cached:
            return cached

        src_hierarchy = {}
        if self.follow_parent:
            z = client_info.client_zone
            level = 0
            while z:
                src_hierarchy[z.getName()] = level
                z = z.admin_parent
                level = level + 1
            src_hierarchy['*'] = level
            max_level = level + 1
        else:
            src_hierarchy[client_info.client_zone.getName()] = 0
            src_hierarchy['*'] = 1
            max_level = 10

        best = None
        for spec in self.services.keys():
            try:
                src_level = src_hierarchy[spec]
            except KeyError:
                src_level = max_level

            if not best or                                                  \
               (best_src_level > src_level):
                best = self.services[spec]
                best_src_level = src_level

        s = None
        if best_src_level < max_level:
            try:
                s = Globals.services[best]
            except KeyError:
                log(None, CORE_POLICY, 2, "No such service; service='%s'", (best))

        else:
            ## LOG ##
            # This message indicates that no applicable service was found for this client zone.
            # Check your ZoneListener/Receiver service configuration.
            # @see: Listener.ZoneListener
            # @see: Receiver.ZoneReceiver
            ##
            log(None, CORE_POLICY, 2, "No applicable service found for this client zone; bindto='%s', client_zone='%s'", (self.bindto, client_info.client_zone))

        self.cache.store(cache_ndx, s)
        return s

class CSZoneDispatcher(Dispatcher):
    """
    <class maturity="stable">
      <summary>Class encapsulating the Dispatcher which starts a service by the client and server zone.</summary>
      <description>
        <para>
          This class is similar to a simple Dispatcher, but instead of
          starting a fixed service, it chooses one based on the client
          and the destined server zone.
        </para>
        <para>
          It takes a mapping of services indexed by a client and the server
          zone name, with an exception of the '*' zone, which matches
          anything.
        </para>
        <para>
          NOTE: the server zone might change during proxy and NAT processing,
          therefore the server zone used here only matches the real
          destination if those phases leave the server address intact.
        </para>
        <example>
            <title>CSZoneDispatcher example</title>
            <para>The following example defines a CSZoneDispatcher that
            starts the service called <parameter>internet_HTTP_DMZ</parameter>
            for connections received on the <parameter>192.168.2.1</parameter>
             IP address, but only if the connection comes from the
             <parameter>internet</parameter> zone and the destination is
             in the <parameter>DMZ</parameter> zone.</para>
            <synopsis>CSZoneDispatcher(bindto=SockAddrInet('192.168.2.1', 50080), services={("internet", "DMZ"):"internet_HTTP_DMZ"}, transparent=TRUE, backlog=255, threaded=FALSE, follow_parent=FALSE)</synopsis>
        </example>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>services</name>
            <type></type>
            <description>services mapping indexed by zone names</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, bindto=None, services=None, **kw):
        """
        <method maturity="stable">
          <summary>Constructor to initialize a CSZoneDispatcher instance.</summary>
          <description>
            <para>
              This constructor initializes a CSZoneDispatcher instance and sets
              its initial attributes based on arguments.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>bindto</name>
                <type>
                  <sockaddr existing="yes"/>
                </type>
               <description>An existing <link linkend="python.SockAddr">socket address</link> containing the IP address and port number where the Dispatcher accepts connections.</description>
               </argument>
              <argument maturity="stable">
                <name>services</name>
                <type>
                  <hash>
                    <key>
                      <tuple>
                        <zone/>
                        <zone/>
                      </tuple>
                    </key>
                    <value>
                        <service/>
                    </value>
                  </hash>
                </type>
                <guitype>HASH;STRING_zone,STRING_zone;STRING_service</guitype>
                <description>Client zone - server zone - service name pairs
                using the <parameter>(("client_zone","server_zone"):"service")</parameter>
                format; specifying the service to start when the dispatcher
                accepts a connection from the given
                client zone that targets the server zone.</description>
              </argument>
              <argument maturity="stable">
                <name>follow_parent</name>
                <type>
                  <boolean/>
                </type>
                <description>Set this parameter to <parameter>TRUE</parameter>
                if the dispatcher handles also the connections coming from
                the child zones of the selected client zones. Otherwise,
                the dispatcher accepts traffic only from the explicitly
                listed client zones.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.follow_parent = kw.pop('follow_parent', FALSE)
        super(CSZoneDispatcher, self).__init__(bindto, None, **kw)
        self.services = services
        self.cache = ShiftCache('csdispatch(%s)' % str(self.bindto), config.options.zone_dispatcher_shift_threshold)

    def getService(self, client_info):
        """
        <method internal="yes">
          <summary>Virtual function which returns the service to be ran</summary>
          <description>
            <para>
              This function is called by our base class to find out the
              service to be used for the current client_info. It uses the
              client and the server zone name to decide which service to
              use.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>client_info</name>
                <type></type>
                <description>Client connection info</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        dest_zone = Zone.lookup(client_info.client_local)

        cache_ndx = (client_info.client_zone.getName(), dest_zone.getName())

        cached = self.cache.lookup(cache_ndx)
        if cached == 0:
            ## LOG ##
            # This message indicates that no applicable service was found for this client zone in the services cache.
            # It is likely that there is no applicable service configured in this CSZoneListener/Receiver at all.
            # Check your CSZoneListener/Receiver service configuration.
            # @see: Listener.CSZoneListener
            # @see: Receiver.CSZoneReceiver
            ##
            log(None, CORE_POLICY, 2, "No applicable service found for this client & server zone (cached); bindto='%s', client_zone='%s', server_zone='%s'", (self.bindto, client_info.client_zone, dest_zone))
        elif cached:
            return cached

        src_hierarchy = {}
        dst_hierarchy = {}
        if self.follow_parent:
            z = client_info.client_zone
            level = 0
            while z:
                src_hierarchy[z.getName()] = level
                z = z.admin_parent
                level = level + 1
            src_hierarchy['*'] = level
            max_level = level + 1
            z = dest_zone
            level = 0
            while z:
                dst_hierarchy[z.getName()] = level
                z = z.admin_parent
                level = level + 1
            dst_hierarchy['*'] = level
            max_level = max(max_level, level + 1)
        else:
            src_hierarchy[client_info.client_zone.getName()] = 0
            src_hierarchy['*'] = 1
            dst_hierarchy[dest_zone.getName()] = 0
            dst_hierarchy['*'] = 1
            max_level = 10

        best = None
        for spec in self.services.keys():
            try:
                src_level = src_hierarchy[spec[0]]
                dst_level = dst_hierarchy[spec[1]]
            except KeyError:
                src_level = max_level
                dst_level = max_level

            if not best or                                                  \
               (best_src_level > src_level) or                              \
               (best_src_level == src_level and best_dst_level > dst_level):
                best = self.services[spec]
                best_src_level = src_level
                best_dst_level = dst_level

        s = None
        if best_src_level < max_level and best_dst_level < max_level:
            try:
                s = Globals.services[best]
            except KeyError:
                log(None, CORE_POLICY, 2, "No such service; service='%s'", (best))
        else:
            ## LOG ##
            # This message indicates that no applicable service was found for this client zone.
            # Check your CSZoneListener/Receiver service configuration.
            # @see: Listener.CSZoneListener
            # @see: Receiver.CSZoneReceiver
            ##
            log(None, CORE_POLICY, 2, "No applicable service found for this client & server zone; bindto='%s', client_zone='%s', server_zone='%s'", (self.bindto, session.client_zone, dest_zone))
        self.cache.store(cache_ndx, s)
        return s


def purgeDispatches():
    """
    <function internal="yes">
    </function>
    """
    for i in Globals.dispatches:
        i.destroy()
    del Globals.dispatches

Globals.deinit_callbacks.append(purgeDispatches)

