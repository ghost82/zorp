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
  <summary>
    The Service module defines the classes used to create service definitions.
  </summary>
  <description>
    <para>
      This module defines classes encapsulating service descriptions. Zorp
      services define how incoming connection requests are handled.
      When a connection is accepted by a <link
      linkend="python.Rule">Rule</link>, the service specified in the
      Rule creates an instance of itself.
      This instance handles the connection and
      proxies the traffic between the client and the server.
      The instance of the selected service is created using the <link
      linkend="python.Service.Service.startInstance">'startInstance()'</link>
      method.
    </para>
    <para>
    A service does not perform useful activity on its own, it needs
    a <link linkend="python.Rule">Rule</link> to bind the
    service to a network interface of the firewall. New instances of the
    service are started as the Rule accepts new connections.
    </para>
    <section>
    <title>Naming services</title>
    <para>
      The name of the service must be a unique identifier; rules refer to this unique ID.
    </para>
    <para>Use clear, informative, and consistent service names. Include the following information in
            the service name:</para>
          <itemizedlist>
            <listitem>
              <para>Source zones, indicating which clients may use the service (e.g.,
                  <parameter>intranet</parameter>).</para>
            </listitem>
          </itemizedlist>
          <itemizedlist>
            <listitem>
              <para>The protocol permitted in the traffic (e.g.,
              <parameter>HTTP</parameter>).</para>
            </listitem>
          </itemizedlist>
          <itemizedlist>
            <listitem>
              <para>Destination zones, indicating which servers may be accessed using the service
                (e.g., <parameter>Internet</parameter>).</para>
            </listitem>
          </itemizedlist>
          <tip>
            <para>Name the service that allows internal users to browse the Web
                <parameter>intra_HTTP_internet</parameter>. Use dots to indicate child zones, e.g.,
                <parameter> intra.marketing_HTTP_inter</parameter>.</para>
          </tip>
    </section>
  </description>
</module>
"""

from Stream import Stream
from Session import StackedSession
from Zorp import *
from Chainer import ConnectChainer
from Router import TransparentRouter, DirectedRouter
from Auth import AuthPolicy, getAuthPolicyObsolete, getAuthenticationPolicy
from Resolver import DNSResolver, getResolverPolicy, ResolverPolicy
from NAT import getNATPolicy, NATPolicy, NAT_SNAT, NAT_DNAT
from Encryption import getEncryptionPolicy
from Exceptions import LimitException
from Util import enum

import types, thread, time, socket

import kzorp.messages

Z_SESSION_LIMIT_NOT_REACHED        = 0
Z_SESSION_LIMIT_GRACEFULLY_REACHED = 1
Z_SESSION_LIMIT_REACHED            = 2

default_snat = None
default_dnat = None
default_auth = None
default_router = None
default_chainer = None

class AbstractService(object):
    """
    <class maturity="stable" abstract="yes">
      <summary>
        Class encapsulating the abstract Service properties.
      </summary>
      <description>
        <para>
            AbstractService implements an abstract service. Service
            definitions should be based on a customized class derived from
            AbstractService, or on the predefined
            <link linkend="python.Service.Service">Service</link> class.
        </para>
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>name</name>
            <type><string/></type>
            <description>The name of the service.</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, name):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize an instance of the AbstractService class.
          </summary>
          <description>
            <para>
              This constructor creates an AbstractService instance and sets the attributes of the instance
               according to the received arguments. It also registers the Service to the
               <parameter>services</parameter> hash so that rules can find the service instance.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>name</name>
                <type>
                  <string/>
                </type>
                <description>The name of the service.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        if Globals.services.has_key(name):
            raise ValueError, "Duplicate service: %s" % name
        Globals.services[name] = self
        self.name = name

    def startInstance(self, session):
        """
        <method internal="yes">
          <summary>
            Function to start an instance of this service.
          </summary>
          <description>
            <para>
              Abstract method to be implemented in derived classes.
              Should start an instance of the given service. A service
              instance takes care of the client connection, connects
              to the server and supervises the traffic going in either
              direction.
            </para>
            <para>
              Tasks of a service instance are implemented by classes
              derived from <link linkend="python.Proxy.Proxy">Proxy</link>.
            </para>
            <para>
              This method unconditionally raises a NotImplementedError
              exception to indicate that it must be overridden by
              descendant classes like 'Service'.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>session</name>
                <type></type>
                <description>start service within this session</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        raise NotImplementedError

    def stopInstance(self, session):
        """
        <method internal="yes">
          <summary>
            Function called when an instance of this service is ended
          </summary>
          <description>
            <para>
              This function is called by Session.__del__ and indicates
              that a given session (instance) of this service is ended.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>session</name>
                <type></type>
                <description>ending session</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        raise NotImplementedError

    def __str__(self):
        """
        <method internal="yes">
          <summary>
            Function to represent this object as a string
          </summary>
          <description>
            <para>
              This function is called by the Python core when this object
              is used as-, or casted to a string. It simply returns
              the service name.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        return self.name

class Service(AbstractService):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating a service definition.
      </summary>
      <description>
        <para>
          A service is one of the fundamental objects in Zorp. It
          stores the names of proxy related parameters, and is also
          used for access control purposes to decide what kind
          of traffic is permitted.
        </para>
        <note><para>The Service class transfers application-level (proxy)
         services. To transfer connections on the application-level,
         use the <link linkend="python.Service.Service">Service</link>
         class.</para></note>
       <example>
       <title>Service example</title>
       <para>The following service transfers HTTP connections. Every
       parameter is left at its default.
       </para>
       <synopsis>Service(name="demo_http, proxy_class=HttpProxy, router=TransparentRouter())</synopsis>
       <para>The following service handles HTTP connections. This service
       uses authentication and authorization, and network address translation
       on the client addresses (SNAT).
       </para>
       <synopsis>Service(name="demo_http", proxy_class=HttpProxy, authentication_policy="demo_authentication_policy", authorization_policy="demo_permituser", snat_policy="demo_natpolicy", router=TransparentRouter())</synopsis>
       <para>The following example defines a few Zorp classes:
       the client and server zones, a simple services, and a rule that starts the service.
       </para>
       <synopsis>Zone('internet', ['0.0.0.0/0'])
Zone('office', ['192.168.1.0/32', '192.168.2.0/32'])

def demo_instance() :
Service(name="office_http_inter", proxy_class=HttpProxy, router=TransparentRouter())
Rule(src_zone='office',
    proto=6,
    dst_zone='internet',
    service='office_http_inter'
    )</synopsis>
       </example>
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>router</name>
            <!--<type>AbstractRouter instance</type>-->
            <type><class/></type>
            <description>A router instance used to determine the
            destination address of the server.
            See <xref linkend="python.Router"/> for details.</description>
          </attribute>
          <attribute>
            <name>chainer</name>
            <!--<type>AbstractChainer instance</type>-->
            <type><class/></type>
            <description>A chainer instance used to connect to
            the destination server.
            See <xref linkend="python.Chainer"/> for details.</description>
          </attribute>
          <attribute>
            <name>snat_policy</name>
            <!--<type>NATPolicy instance</type>-->
            <type><class/></type>
            <description>Name of the NAT policy instance used to translate
            the source addresses of the sessions.
            See <xref linkend="python.NAT"/> for details.</description>
          </attribute>
          <attribute>
            <name>dnat_policy</name>
            <!--<type>NATPolicy instance</type>-->
            <type><class/></type>
            <description>Name of the NAT policy instance used to translate
            the destination addresses of the sessions.
            See <xref linkend="python.NAT"/> for details.</description>
          </attribute>
          <attribute>
            <name>proxy_class</name>
            <!--<type>Proxy instance</type>-->
            <type><class/></type>
            <description>Name of the proxy class instance used to analyze
            the traffic transferred in the session.
            See <xref linkend="python.Proxy"/> for details.</description>
          </attribute>

          <attribute>
            <name>authentication_policy</name>
            <!--<type>AuthenticationPolicy name</type>-->
            <type><class/></type>
            <description>Name of the AuthenticationPolicy instance used to
            authenticate the clients.
            See <xref linkend="python.Auth"/> for details.</description>
          </attribute>
          <attribute>
            <name>authorization_policy</name>
            <!--<type>AuthorizationPolicy name</type>-->
            <type><class/></type>
            <description>Name of the AuthorizationPolicy instance used to
            authorize the clients.
            See <xref linkend="python.Auth"/> for details.</description>
          </attribute>

          <attribute>
            <name>auth_name</name>
            <type><string/></type>
            <description>
              Authentication name of the service. This string informs the
              users of the Zorp Authentication Agent about which
              service they are authenticating for.
              Default value: the name of the service.
            </description>
          </attribute>
          <attribute>
            <name>resolver_policy</name>
            <!--<type>ResolvePolicy instance</type>-->
            <type></type>
            <description>Name of the ResolvePolicy instance used to resolve
            the destination domain names.
            See <xref linkend="python.Resolver"/> for details.
            Default value: <parameter>DNSResolver</parameter>
            </description>
          </attribute>
          <attribute>
            <name>max_instances</name>
            <type><integer/></type>
            <description>
              Permitted number of concurrent instances of this service.
              Usually each service instance handles
              one connection. The default value is <parameter>0</parameter>,
              which allows unlimited number of instances.
            </description>
          </attribute>
          <attribute>
            <name>max_sessions</name>
            <type><integer/></type>
            <description>
              Maximum number of concurrent sessions handled by one thread.
            </description>
          </attribute>
          <attribute>
            <name>num_instances</name>
            <type><integer/></type>
            <description>
              The current number of running instances of this service.
            </description>
          </attribute>
          <attribute>
            <name>instance_id</name>
            <type><integer/></type>
            <description>The sequence number of the last session started</description>
          </attribute>
          <attribute>
            <name>keepalive</name>
            <type><integer/></type>
            <default>Z_KEEPALIVE_NONE</default>
            <description>
              The TCP keepalive option, one of the Z_KEEPALIVE_NONE,
              Z_KEEPALIVE_CLIENT, Z_KEEPALIVE_SERVER,
              Z_KEEPALIVE_BOTH values.
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    keepalive = Z_KEEPALIVE_NONE

    def __init__(self, name, proxy_class, router=None, chainer=None, snat_policy=None, snat=None,
                    dnat_policy=None, dnat=None, authentication_policy=None, authorization_policy=None,
                    max_instances=0, max_sessions=0, auth_name=None, resolver_policy=None, auth=None,
                    auth_policy=None, keepalive=None,
                    encryption_policy=None, limit_target_zones_to=None, detector_config=None,
                    ):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize a Service instance.
          </summary>
          <description>
            <para>
              This contructor defines a Service with the specified parameters.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>name</name>
                <type>
                  <string/>
                </type>
                <description>The name identifying the service.</description>
              </argument>
              <argument maturity="stable">
                <name>router</name>
                <type>
                  <class filter="router" instance="yes"/>
                </type>
                <default>None</default>
                <description>Name of the router instance used to determine
                the destination address of the server.
                Defaults to <link linkend="python.Router.TransparentRouter">TransparentRouter</link>
                if no other router is specified.
                </description>
              </argument>
              <argument maturity="stable">
                <name>chainer</name>
                <type>
                  <class filter="chainer" instance="yes"/>
                </type>
                <default>None</default>
                <description>Name of the chainer instance used to connect to
                the destination server.
                Defaults to <link linkend="python.Chainer.ConnectChainer">ConnectChainer</link>
                if no other chainer is specified.</description>
              </argument>
              <argument>
                <name>snat_policy</name>
                <type>
                  <class filter="natpolicy" existing="yes"/>
                </type>
                <default>None</default>
                <description>Name of the NAT policy instance used to
                translate the source addresses of
                the sessions. See <xref linkend="python.NAT"/> for details.</description>
              </argument>
              <argument maturity="obsolete">
                <name>snat</name>
                <type>
                  <class filter="nat"/>
                </type>
                <default>None</default>
                <description>Obsolete parameter, use <parameter>snat_policy</parameter> instead.
                </description>
              </argument>
              <argument>
                <name>dnat_policy</name>
                <type>
                  <class filter="natpolicy" existing="yes"/>
                </type>
                <default>None</default>
                <description>Name of the NAT policy instance used to
                translate the destination addresses of
                the sessions. See <xref linkend="python.NAT"/> for details.</description>
              </argument>
              <argument maturity="obsolete">
                <name>dnat</name>
                <type>
                  <class filter="nat"/>
                </type>
                <default>None</default>
                <description>Obsolete parameter,
                use <parameter>dnat_policy</parameter> instead.</description>
              </argument>
              <argument maturity="stable">
                <name>proxy_class</name>
                <type>
                  <class filter="proxy"/>
                </type>
                <description>Name of the proxy class instance used to analyze the traffic transferred in
                the session. See <xref linkend="python.Proxy"/> for details.</description>
              </argument>
              <argument>
                <name>authentication_policy</name>
                <type>
                  <class filter="authpolicy" existing="yes"/>
                </type>
                <default>None</default>
                <description>Name of the AuthenticationPolicy instance used to authenticate the clients.
                See <xref linkend="python.Auth"/> for details.</description>
              </argument>
              <argument>
                <name>authorization_policy</name>
                <type>
                  <class filter="authorizationpolicy" existing="yes"/>
                </type>
                <default>None</default>
                <description>Name of the AuthorizationPolicy instance used to authorize the clients.
                See <xref linkend="python.Auth"/> for details.</description>
              </argument>
              <argument maturity="obsolete">
                <name>auth</name>
                <type>
                  <class filter="auth" instance="yes"/>
                </type>
                <default>None</default>
                <description>Obsolete parameter, use <parameter>authentication_policy</parameter> instead.
                </description>
              </argument>
              <argument maturity="obsolete">
                <name>auth_policy</name>
                <type>
                  <class filter="authpolicy" existing="yes"/>
                </type>
                <default>None</default>
                <description>Obsolete parameter, use <parameter>authorization_policy</parameter> instead.
                </description>
              </argument>
              <argument>
                <name>auth_name</name>
                <type>
                  <string/>
                </type>
                <default>None</default>
                <description>
                 Authentication name of the service. This string informs the
                 users of the Zorp Authentication Agent about which
                 service they are authenticating for. Default value: the name of the service.
                </description>
              </argument>
              <argument maturity="stable">
                <name>max_instances</name>
                <type>
                  <integer/>
                </type>
                <default>0</default>
                <description>Permitted number of concurrent instances of this service. Usually each
                service instance handles one connection. Default value: <parameter>0</parameter> (unlimited).
                </description>
              </argument>
              <argument>
                <name>max_sessions</name>
                <type><integer/></type>
                <default>0</default>
                <description>
                  Maximum number of concurrent sessions handled by one thread.
                </description>
              </argument>
              <argument>
                <name>resolver_policy</name>
                <type>
                  <class filter="resolverpolicy" existing="yes"/>
                </type>
                <default>None</default>
                <description>Name of the ResolvePolicy instance used to resolve the destination domain names.
                See <xref linkend="python.Resolver"/> for details.
                Default value: <parameter>DNSResolver</parameter>.
                </description>
              </argument>
              <argument>
                <name>keepalive</name>
                <type><integer/></type>
                <default>Z_KEEPALIVE_NONE</default>
                <description>
                  The TCP keepalive option, one of the Z_KEEPALIVE_NONE,
                  Z_KEEPALIVE_CLIENT, Z_KEEPALIVE_SERVER,
                  Z_KEEPALIVE_BOTH values.
                </description>
              </argument>
              <argument>
                <name>limit_target_zones_to</name>
                <type><list><string/></list></type>
                <default>None</default>
                <description>
                  A comma-separated list of zone names permitted as the target of the service. No restrictions
                  are applied if the list is empty. Use this parameter to replace the obsolete <parameter>inbound_services</parameter> parameter of the Zone class.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        super(Service, self).__init__(name)
        self.proxy_class = proxy_class
        self.router = router or default_router or TransparentRouter()
        self.chainer = chainer or default_chainer or ConnectChainer()
        if (snat or default_snat) and snat_policy:
            raise ValueError, "Cannot set both snat and snat_policy"
        if (dnat or default_dnat) and dnat_policy:
            raise ValueError, "Cannot set both dnat and dnat_policy"
        if (auth or default_auth or auth_policy) and authentication_policy:
            raise ValueError, "Cannot set authentication_policy and auth or auth_policy"

        if snat or default_snat:
            self.snat_policy = NATPolicy('__%s-snat' % name, snat or default_snat)
        else:
            self.snat_policy = getNATPolicy(snat_policy)
        if dnat or default_dnat:
            self.dnat_policy = NATPolicy('__%s-dnat' % name, dnat or default_dnat)
        else:
            self.dnat_policy = getNATPolicy(dnat_policy)

        if type(auth) == types.StringType:
            auth_policy = auth
            auth = None
        if keepalive:
            self.keepalive = keepalive

        if auth_policy:
            # one older auth_policy implementation (up to Zorp 3.0)
            auth_policy = getAuthPolicyObsolete(auth_policy)

            self.authentication_policy = auth_policy.getAuthenticationPolicy()
        elif auth or default_auth:
            # even older auth implementation (up to Zorp 2.1)
            auth_policy = AuthPolicy(None, auth or default_auth)
            self.authentication_policy = auth_policy.getAuthenticationPolicy()
        else:
            # current Authentication support
            self.authentication_policy = getAuthenticationPolicy(authentication_policy)


        self.auth_name = auth_name or name

        if resolver_policy:
            self.resolver_policy = getResolverPolicy(resolver_policy)
        else:
            self.resolver_policy = ResolverPolicy(None, DNSResolver())

        if encryption_policy:
            self.encryption_policy = getEncryptionPolicy(encryption_policy)
        else:
            self.encryption_policy = None

        self.limit_target_zones_to = limit_target_zones_to
        self.detector_config = detector_config

        self.max_instances = max_instances
        self.max_sessions = max_sessions
        self.num_instances = 0
        self.proxy_group = ProxyGroup(self.max_sessions)
        self.lock = thread.allocate_lock()

    def startInstance(self, session):
        """
        <method maturity="stable">
          <summary>
            Start a service instance.
          </summary>
          <description>
            <para>
              Called by the Rule to create an instance of this
              service.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>session</name>
                <type></type>
                <description>The session object</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        if self.max_instances != 0 and self.num_instances >= self.max_instances:
            raise LimitException, "Instance limit reached"

        sys.exc_clear()
        session.client_stream.keepalive = self.keepalive & Z_KEEPALIVE_CLIENT;


        self.lock.acquire()
        self.num_instances = self.num_instances + 1
        self.lock.release()

        session.started = 1


        ## LOG ##
        # This message reports that a new proxy instance is started.
        ##
        log(session.session_id, CORE_SESSION, 3, "Starting proxy instance; client_fd='%d', client_address='%s', client_zone='%s', client_local='%s', client_protocol='%s'", (session.client_stream.fd, session.client_address, session.client_zone, session.client_local, session.protocol_name))
        ss = StackedSession(session, self.chainer)

        # set up proxy stream
        ss.client_stream = session.client_stream
        ss.client_stream.name = session.session_id + '/' + self.proxy_class.name + '/client'

        # route session
        self.router.routeConnection(ss)

        timestamp = str(time.time())

        szigEvent(Z_SZIG_SERVICE_COUNT,
                    (Z_SZIG_TYPE_PROPS,
                       (self.name, {
                         'session_number': session.instance_id + 1,
                         'sessions_running': self.num_instances,
                         'last_started': timestamp,
                         }
                 )))

        # start up proxy
        proxy = self.proxy_class(ss)
        ss.registerStart(timestamp)
        if not self.proxy_group.start(proxy):
            self.proxy_group = ProxyGroup(self.max_sessions)
            if not self.proxy_group.start(proxy):
                raise RuntimeError, "Error starting proxy in group"
        return TRUE

    def stopInstance(self, session):
        """
        <method internal="yes">
          <summary>
            Function called when a session terminates.
          </summary>
          <description>
            <para>
              This function is called when a session terminates. It
              decrements concurrent session count.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>session</name>
                <type></type>
                <description>session we belong to</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """

        if session.started:
            self.lock.acquire()
            self.num_instances = self.num_instances - 1
            self.lock.release()

            szigEvent(Z_SZIG_SERVICE_COUNT,
                       (Z_SZIG_TYPE_PROPS,
                        (self.name, {
                          'sessions_running': self.num_instances,
                          }
                     )))

        ## LOG ##
        # This message reports that a new proxy instance is stopped.
        ##
        log(session.session_id, CORE_SESSION, 4, "Ending proxy instance;")

    def buildKZorpMessage(self):
        """<method internal="yes">
        </method>
        """
        return [kzorp.messages.KZorpAddProxyServiceMessage(self.name), ];


class PFService(AbstractService):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating a packet-filter service definition.
      </summary>
      <description>
       <para>PFServices allow you to replace the FORWARD rules of iptables, and configure application-level and packet-filter rules from Zorp.</para>
       <note><para>The PFService class transfers packet-filter level
         services. To transfer connections on the packet-filter level,
         use the <link linkend="python.Service.PFService">PFService</link>
         class.</para></note>
       <example>
       <title>PFService example</title>
       <para>The following packet-filtering service transfers TCP connections
       that arrive to port <parameter>5555</parameter>.
       </para>
       <synopsis>PFService(name="intranet_PF5555_internet", router=TransparentRouter())</synopsis>
       <para>The following example defines a few Zorp classes:
       the client and server zones, a simple services, and a rule that starts the service.
       </para>
       <synopsis>Zone('internet', ['0.0.0.0/0'])
Zone('intranet', ['192.168.0.0/16'])

def demo() :
PFService(name="intranet_PF5555_internet", router=TransparentRouter())
Rule(dst_port=5555,
    src_zone='intranet',
    dst_zone='internet',
    service='PFService'
    )</synopsis>
       </example>
      </description>
      <!-- FIXME link to the kzorp chapter -->
      <metainfo>
        <attributes>
          <attribute>
            <name>router</name>
            <!--<type>AbstractRouter instance</type>-->
            <type><class/></type>
            <description>A router instance used to determine the
            destination address of the server.
            See <xref linkend="python.Router"/> for details.</description>
          </attribute>
          <attribute>
            <name>snat_policy</name>
            <!--<type>NATPolicy instance</type>-->
            <type><class/></type>
            <description>Name of the NAT policy instance used to translate
            the source addresses of the sessions.
            See <xref linkend="python.NAT"/> for details.</description>
          </attribute>
          <attribute>
            <name>dnat_policy</name>
            <!--<type>NATPolicy instance</type>-->
            <type><class/></type>
            <description>Name of the NAT policy instance used to translate
            the destination addresses of the sessions.
            See <xref linkend="python.NAT"/> for details.</description>
          </attribute>
         </attributes>
      </metainfo>
    </class>

    """
    def __init__(self, name, router=None, snat_policy=None, dnat_policy=None):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize a PFService instance.
          </summary>
          <description>
            <para>
              This constructor defines a packetfilter-service with the specified parameters.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
          </method>
          """
        super(PFService, self).__init__(name)
        self.router = router or default_router or TransparentRouter()
        self.snat_policy = getNATPolicy(snat_policy)
        self.dnat_policy = getNATPolicy(dnat_policy)

    def buildKZorpMessage(self):
        """<method internal="yes">
        </method>
        """
        def addNATMappings(messages, nat_type, nat_policy):
            if nat_type == NAT_SNAT:
                msg_class = kzorp.messages.KZorpAddServiceSourceNATMappingMessage
            else:
                msg_class = kzorp.messages.KZorpAddServiceDestinationNATMappingMessage
            if nat_policy:
                nat_mappings = nat_policy.getKZorpMapping()
                for src_tuple, dst_tuple, map_tuple in nat_mappings:
                    messages.append(msg_class(self.name, src_tuple, map_tuple, dst_tuple))

        flags = kzorp.messages.KZF_SVC_LOGGING
        if isinstance(self.router, TransparentRouter):
            flags = flags | kzorp.messages.KZF_SVC_TRANSPARENT
            router_target_family = None
            router_target_ip = None
            router_target_port = None
        elif isinstance(self.router, DirectedRouter):
            if len(self.router.dest_addr) > 1:
                raise ValueError, "DirectedRouter with more than one destination address not supported by KZorp"
            router_target_family = self.router.dest_addr[0].family
            router_target_ip = self.router.dest_addr[0].pack()
            router_target_port = self.router.dest_addr[0].port
        else:
            raise ValueError, "Invalid router type specified for port forwarded service"

        if self.router.forge_addr:
            flags = flags | kzorp.messages.KZF_SVC_FORGE_ADDR

        messages = []
        messages.append(kzorp.messages.KZorpAddForwardServiceMessage(self.name, \
                        flags, 0, router_target_family, router_target_ip, router_target_port))
        if self.snat_policy:
            addNATMappings(messages, NAT_SNAT, self.snat_policy)
        if self.dnat_policy:
            addNATMappings(messages, NAT_DNAT, self.dnat_policy)
        return messages

DenyIPv4 = enum(DROP=0,
                TCP_RESET=1,
                ICMP_NET_UNREACHABLE=2,
                ICMP_HOST_UNREACHABLE=3,
                ICMP_PROTO_UNREACHABLE=4,
                ICMP_PORT_UNREACHABLE=5,
                ICMP_NET_PROHIBITED=6,
                ICMP_HOST_PROHIBITED=7,
                ICMP_ADMIN_PROHIBITED=8)

DenyIPv6 = enum(DROP=0,
                TCP_RESET=1,
                ICMP_NO_ROUTE=2,
                ICMP_ADMIN_PROHIBITED=3,
                ICMP_ADDR_UNREACHABLE=4,
                ICMP_PORT_UNREACHABLE=5)

class DenyService(AbstractService):
    """
    <class maturity="stable">
        <summary>DenyService prohibits access to certain services</summary>
        <description>
            <para>The DenyService class is a type of service that rejects connections with a predefined error code. DenyServices can be specified in the <parameter>service</parameter> parameter of <link linkend="python.Rule">Rules</link>. If the rule referencing the DenyService matches a connection request, Zorp rejects the connection. DenyService is a replacement for the obsolete Umbrella zone concept.</para>
            <example>
                <title>A simple DenyService</title>
                <para>The following defines a DenyService and a rule to reject all traffic that targets port 5555.</para>
                <synopsis>def demo() :
    DenyService(name='DenyService', ipv4_setting=DenyIPv4.DROP, ipv6_setting=DenyIPv6.DROP)
    Rule(dst_port=5555,
    service='DenyService'
    )</synopsis>
            </example>
        </description>
        <metainfo>
            <enums>
                <enum maturity="stable" id="enum.denyservice.ipv4">
                  <description/>
                  <item><name>DenyIPv4.DROP</name></item>
                  <item><name>DenyIPv4.TCP_RESET</name></item>
                  <item><name>DenyIPv4.ICMP_NET_UNREACHABLE</name></item>
                  <item><name>DenyIPv4.ICMP_HOST_UNREACHABLE</name></item>
                  <item><name>DenyIPv4.ICMP_PROTO_UNREACHABLE</name></item>
                  <item><name>DenyIPv4.ICMP_PORT_UNREACHABLE</name></item>
                  <item><name>DenyIPv4.ICMP_NET_PROHIBITED</name></item>
                  <item><name>DenyIPv4.ICMP_HOST_PROHIBITED</name></item>
                  <item><name>DenyIPv4.ICMP_ADMIN_PROHIBITED</name></item>
                </enum>
            </enums>
            <enums>
                <enum maturity="stable" id="enum.denyservice.ipv6">
                  <description/>
                  <item><name>DenyIPv6.DROP</name></item>
                  <item><name>DenyIPv6.TCP_RESET</name></item>
                  <item><name>DenyIPv6.ICMP_NO_ROUTE</name></item>
                  <item><name>DenyIPv6.ICMP_ADMIN_PROHIBITED</name></item>
                  <item><name>DenyIPv6.ICMP_ADDR_UNREACHABLE</name></item>
                  <item><name>DenyIPv6.ICMP_PORT_UNREACHABLE</name></item>
                </enum>
            </enums>
            <attributes>
                <attribute>
                    <name>name</name>
                    <type>
                        <string/>
                    </type>
                    <description>The name of the service.</description>
                </attribute>
                <attribute>
                    <name>ipv4_setting</name>
                    <type>
                        <hash>
                            <key>
                                <string display_name="IPV4 deny action"/>
                            </key>
                            <value>
                                <link id="enum.denyservice.ipv4"/>
                            </value>
                        </hash>
                    </type>
                    <description>Specifies how to reject IPv4 traffic. By default, Zorp simply drops the traffic without notifying the client (<parameter>DenyIPv4.DROP</parameter>). The following values are available: <parameter>DenyIPv4.DROP</parameter>, <parameter>DenyIPv4.TCP_RESET</parameter>, <parameter>DenyIPv4.ICMP_NET_UNREACHABLE</parameter>, <parameter>DenyIPv4.ICMP_HOST_UNREACHABLE</parameter>, <parameter>DenyIPv4.ICMP_PROTO_UNREACHABLE</parameter>, <parameter>DenyIPv4.ICMP_PORT_UNREACHABLE</parameter>, <parameter>DenyIPv4.ICMP_NET_PROHIBITED</parameter>, <parameter>DenyIPv4.ICMP_HOST_PROHIBITED</parameter>, <parameter>DenyIPv4.ICMP_ADMIN_PROHIBITED</parameter>
                    <note>
                        <para>When the <parameter>DenyIPv4.TCP_RESET</parameter> option is used, Zorp sends the TCP RESET packet as if it was sent by the target server.</para>
                        <para>When using an ICMP option, Zorp sends the appropriate ICMP packet, just like a router would.</para>
                    </note>
                    </description>
                </attribute>
                <attribute>
                    <name>ipv6_setting</name>
                    <type>
                        <hash>
                            <key>
                                <string display_name="IPV6 deny action"/>
                            </key>
                            <value>
                                <link id="enum.denyservice.ipv6"/>
                            </value>
                        </hash>
                    </type>
                    <description>Specifies how to reject IPv6 traffic. By default, Zorp simply drops the traffic without notifying the client (<parameter>DenyIPv6.DROP</parameter>). The following values are available: <parameter>DenyIPv6.DROP</parameter>, <parameter>DenyIPv6.TCP_RESET</parameter>, <parameter>DenyIPv6.ICMP_NO_ROUTE</parameter>, <parameter>DenyIPv6.ICMP_ADMIN_PROHIBITED</parameter>, <parameter>DenyIPv6.ICMP_ADDR_UNREACHABLE</parameter>, <parameter>DenyIPv6.ICMP_PORT_UNREACHABLE</parameter></description>
                </attribute>
            </attributes>
      </metainfo>
    </class>

    """

    def __init__(self, name, logging=True, ipv4_setting=DenyIPv4.DROP, ipv6_setting=DenyIPv6.DROP):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize a DenyService instance.
          </summary>
          <description>
            <para>
              This constructor defines a DenyService with the specified parameters.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
          </method>
          """
        super(DenyService, self).__init__(name)
        self.name = name
        self.logging = logging
        self.ipv4_setting = ipv4_setting
        self.ipv6_setting = ipv6_setting

    def buildKZorpMessage(self):
        """
        <method maturity="stable" internal="yes"></method>
        """
        return [kzorp.messages.KZorpAddDenyServiceMessage(self.name, \
                self.logging, 0, self.ipv4_setting, self.ipv6_setting), ]
