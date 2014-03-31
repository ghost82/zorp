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
    Module defining interface to the session related classes.
  </summary>
  <description>
    <para>
      This module defines the abstract session interface in a class named
      <parameter>AbstractSession</parameter>, and two descendants <parameter>MasterSession</parameter>
      and <parameter>StackedSession</parameter>.
    </para>
    <para>
      Sessions are hierarchically stacked into each other just like proxies.
      All sessions except the master session have a parent session from which child sessions inherit variables.
      Child sessions are stacked into their master sessions, so stacked sessions can inherit data from the encapsulating
      proxy instances.
      (Inheritance is implemented using a simple <function>getattr</function> wrapper.)
    </para>
    <para>
        Instances of the Session classes store the parameters
         of the client-side and server-side connections in a session object
         (for example, the IP addresses and zone of the server and the client,
        and the username and group memberships of the user when authentication is used).
        Other components of Zorp refer to this data
          when making various policy-based decisions.
    </para>
  </description>
  <metainfo/>
</module>
"""

import Zorp
from Zorp import *
from Zone import Zone
from Exceptions import *

import inspect

class AbstractSession(object):
    """
    <class maturity="stable" abstract="yes" internal="yes">
      <summary>
        Class encapsulating an abstract session for different types (master, or stacked).
      </summary>
      <description>
        <para>
          Abstract base class for different session types (master, or stacked),
          both MasterSession and StackedSession are derived from this class.
        </para>
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>client_stream</name>
            <type><class filter="stream" instance="yes"/></type>
            <description>Client-side stream.</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self):
        """<method internal="yes">"""
        self.client_stream = None

    def destroy(self):
        """
        <method internal="yes">
          <summary>
            Method called at session destruction time.
          </summary>
          <description>
            <para>
              This method is called when the session is being destroyed.
              We close filedescriptors here in case no proxy module
              could be started (because of policy violations, or because
              the module cannot be found).
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        if self.client_stream:
            self.client_stream.close()


class ClientInfo(object):
    """
    <class maturity="stable" internal="yes"/>
    """
    def __init__(self, client_stream, client_local, client_listen, client_address):
        """<method internal="yes">"""
        self.client_stream = client_stream
        self.client_local = client_local
        self.client_listen = client_listen
        self.client_address = client_address

        if client_address is not None:
            try:
                self.client_zone = Zone.lookup(client_address)
            except ZoneException:
                self.client_zone = None
        else:
            self.client_zone = None


def get_protocol_name(protocol):
    """<function internal="yes"/>"""
    try:
        return ZD_PROTO_NAME[protocol]
    except KeyError:
        return "Unknown(%d)" % (protocol)


class MasterSession(AbstractSession):
    """
    <class maturity="stable" internal="yes">
      <summary>
        Class encapsulating a master session.
      </summary>
      <description>
        <para>
          This class encapsulates a master session that is on the top of the
          session hierarchy. MasterSession instances store properties that
          are shared by all sub-sessions and proxies started for a client
          connection.
        </para>
        <section>
          <title>Referencing attributes exported by parent proxies</title>
          <para>
            When a stacked proxy needs some information exported by its parent,
            it can simply use the by-name references in the
            session structure. For example a proxy named 'pssl' will export an
            attribute named 'pssl' in its session which is inherited in the
            session hierarchy, so a stacked proxy can refer to any pssl
            attributes through this reference:
          </para>
            <example>
              <title>Referencing parent proxy attributes by type</title>
              <synopsis>class MyPsslProxy(PsslProxy):
    class EmbeddedHttpProxy(HttpProxy):
            def config(self):
                    super(MyPsslProxy, self).config()
                    peer = self.session.pssl.server_peer_certificate.subject

    def config(self):
            super(MyPsslProxy, self).config()
            self.stack_proxy = self.EmbeddedHttpProxy</synopsis>
            </example>
        </section>
      </description>
      <metainfo>
        <attributes>
          <attribute>
            <name>client_address</name>
            <type><class filter="sockaddr" instance="yes"/></type>
            <description>IP address of the client.</description>
          </attribute>
          <attribute>
            <name>client_local</name>
            <type><class filter="sockaddr" instance="yes"/></type>
            <description>The IP address of the server targeted by the client. </description>
          </attribute>
          <attribute>
            <name>client_zone</name>
            <type><class filter="zone" instance="yes"/></type>
            <description>Zone of the client.</description>
          </attribute>
          <attribute>
            <name>target_address_inband</name>
            <type><boolean/></type>
            <description>destination address is determined by the proxy</description>
          </attribute>
          <attribute>
            <name>target_local_loose</name>
            <type>BOOLEAN</type>
            <description>
              Allow loosely allocated source ports. (e.g.
              it is not absoletely necessary to allocate
              the same port as specified in <parameter>server_local</parameter>parameter>,
              it is enough if it matches its category.)
            </description>
          </attribute>
          <attribute>
            <name>target_local_random</name>
            <type>BOOLEAN</type>
            <description>
              Allocate source ports randomly using a cryptographically secure algorithm.
              <parameter>target_local_loose</parameter> should also be enabled for this.
            </description>
          </attribute>
          <attribute>
            <name>service</name>
            <type><string/></type>
            <description>The name of the service which started this session.</description>
          </attribute>
          <attribute>
            <name>session_id</name>
            <type><string/></type>
            <description>A unique identifier for this session using the
             following format: <parameter>(Zorp_hostname/service:instance id/proxy)</parameter>.
            </description>
          </attribute>
          <attribute>
            <name>instance_id</name>
            <type><integer/></type>
            <description>The instance identifier of the service (sequence number).</description>
          </attribute>
          <attribute internal="yes">
            <name>started</name>
            <type><boolean/></type>
            <description>Indicates that the instance has been started.</description>
          </attribute>
          <attribute>
            <name>auth_user</name>
            <type><string/></type>
            <description>The username of the authenticated user.</description>
          </attribute>
          <attribute>
            <name>auth_groups</name>
            <type><list><string/></list></type>
            <description>List of groups the authenticated user is member of.</description>
          </attribute>
          <attribute>
            <name>authorized</name>
            <type><boolean/></type>
            <description>Stores whether the session was authorized.</description>
          </attribute>
          <attribute>
            <name>protocol</name>
            <type><integer/></type>
            <description>The protocol used in the client-side connection,
            represented as an integer.</description>
          </attribute>
          <attribute internal="yes">
            <name>protocol_name</name>
            <type><string/></type>
            <description>The name of the protocol used in the client-side
            connection.</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, protocol, service, client_info, instance_id):
        """
        <method internal="yes">
          <summary>
            Constructor to initialize a MasterSession instance.
          </summary>
          <description>
            <para>
              This constructor initializes a new MasterSession instance
              based on its arguments.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        super(MasterSession, self).__init__()

        self.base_session_id = 'svc'

        for method in ['client_stream', 'client_local', 'client_listen', 'client_address', 'client_zone']:
            setattr(self, method, getattr(client_info, method))

        # these are set by the router to indicate how target address
        # selection should work based on the type of the router used
        self.target_address_inband = FALSE
        self.target_local_loose = TRUE
        self.target_local_random = FALSE

        self.auth_user = ""
        self.auth_groups = ()
        self.authorized = FALSE

        self.started = 0
        self.service = service
        self.instance_id = 0

        self.protocol = protocol
        self.protocol_name = get_protocol_name(protocol)
        self.proxy = None

        self.instance_id = instance_id

        self.session_id = "%s/%s:%d" % (self.base_session_id, self.service.name, instance_id)
        self.master_session_id = self.session_id

    def __del__(self):
        """
        <method internal="yes">
          <summary>
            Function called when the master session is freed.
          </summary>
          <description>
            <para>
              This function is called when the master session is freed,
              thus the session ended. We inform our spawner service
              about this event.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        if self.service:
            self.service.stopInstance(self)

class StackedSession(AbstractSession):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating a subsession.
      </summary>
      <description>
        <para>
          This class represents a stacked session, e.g., a session within the
          session hierarchy. Every subsession inherits session-wide
          parameters from its parent.
        </para>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>owner</name>
            <type>
              <class filter="AbstractSession" instance="yes"/>
            </type>
            <description>The parent session of the current session.</description>
          </attribute>
          <attribute maturity="stable">
            <name>chainer</name>
            <type>
              <class filter="chainer" instance="yes"/>
            </type>
            <description>
              The chainer used to connect to the parent proxy. If unset, the
              <parameter>server_stream</parameter> parameter must be set.
            </description>
          </attribute>
          <attribute>
            <name>server_stream</name>
            <type><class filter="stream" instance="yes"/></type>
            <description>Server-side stream.</description>
          </attribute>
          <attribute>
            <name>server_address</name>
            <type><class filter="sockaddr" instance="yes"/></type>
            <description>The IP address Zorp connects to. Most often this is
            the IP address requested by the client, but Zorp can redirect the
            client requests to different IPs.</description>
          </attribute>
          <attribute>
            <name>server_local</name>
            <type><class filter="sockaddr" instance="yes"/></type>
            <description>Zorp connects the server from this IP address. This
            is either the IP address of Zorp's external interface, or the
            IP address of the client (if Forge Port is enabled). The
            client's original IP address may be modified if SNAT policies
            are used.</description>
          </attribute>
          <attribute>
            <name>server_zone</name>
            <type><class filter="zone" instance="yes"/></type>
            <description>Zone of the server.</description>
          </attribute>
          <attribute>
            <name>target_address</name>
            <type><class filter="sockaddr" instance="yes"/></type>
            <description>The IP address Zorp connects to. Most often this is
            the IP address requested by the client, but Zorp can redirect the
            client requests to different IPs.</description>
          </attribute>
          <attribute>
            <name>target_local</name>
            <type><class filter="sockaddr" instance="yes"/></type>
            <description>Zorp connects the server from this IP address. This
            is either the IP address of Zorp's external interface, or the
            IP address of the client (if Forge Port is enabled). The
            client's original IP address may be modified if SNAT policies
            are used.</description>
          </attribute>
          <attribute>
            <name>target_zone</name>
            <type><class filter="zone" instance="yes"/></type>
            <description>Zone of the server.</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, owner, chainer=None):
        """
        <method internal="yes">
          <summary>
            Constructor to initialize a StackedSession instance.
          </summary>
          <description>
            <para>
              This constructor initializes a new StackedSession instance
              based on parameters.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>owner</name>
                <type>
                  <class filter="AbstractSession" instance="yes"/>
                </type>
                <description>Parent session</description>
              </argument>
              <argument maturity="stable">
                <name>chainer</name>
                <type>
                  <class filter="chainer" instance="yes"/>
                </type>
                <description>Chainer used to chain up to parent.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        super(StackedSession, self).__init__()
        self.server_stream = None
        self.owner = owner
        self.chainer = chainer

        # we might inherit a target and server address from our owner
        self.server_address = getattr(owner, "server_address", None)
        self.server_local = getattr(owner, "server_local", None)
        self.server_zone = getattr(owner, "server_zone", None)

        self.target_address = getattr(owner, "target_address", ())
        self.target_local = getattr(owner, "target_local", None)
        self.target_zone = getattr(owner, "target_zone", ())

        self.registered_in_szig = False

    def destroy(self):
        """<method internal="yes"/>"""
        super(StackedSession, self).destroy()
        if self.server_stream:
            self.server_stream.close()

    def __del__(self):
        """<method internal="yes"/>"""
        if self.registered_in_szig:
            self.registerStop()

    def __getattr__(self, name):
        """
        <method internal="yes">
          <summary>
            Function to perform attribute inheritance.
          </summary>
          <description>
            <para>
              This function is called by the Python core when an attribute
              is referenced. It returns variables from the parent session, if
              not overriden here.
              Returns The value of the given attribute.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>name</name>
                <type></type>
                <description>Name of the attribute to get.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        try:
            if name != '__dict__':
                return self.__dict__[name]
            else:
                raise KeyError
        except KeyError:
            owner_attr = getattr(self.owner, name)
            if inspect.ismethod(owner_attr):
                raise

            return owner_attr

    def setProxy(self, proxy):
        """
        <method internal="yes">
          <summary>
            Set the proxy name used in this subsession.
          </summary>
          <description>
            <para>
              Stores a reference to the proxy class, and modifies
              the session_id to include the proxy name. This is
              called by the Listener after the proxy module to
              use is determined.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>proxy</name>
                <type></type>
                <description>Proxy class instance</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.proxy = proxy
        setattr(self, proxy.name, proxy)

        secondary_part = ""
        if self._get_secondary_connection() != 0:
            secondary_part = ":%d" % self._get_secondary_connection()

        self.session_id = "%s%s/%s" % (self.master_session_id, secondary_part, proxy.name)

    def setServerAddress(self, addr):
        """
        <method internal="yes">
          <summary>
            Sets the server address and looks up the server zone and sets the server_zone property.
          </summary>
        </method>
        """
        self.server_address = addr
        self.server_zone = Zone.lookup(addr)

    def isServerPermitted(self):
        """
        <method internal="yes">
          <summary>
            Function to actually check access control.
          </summary>
          <description>
            <para>
              This function is called when a connection is to be
              established with the server. It performs access control
              checks whether the connection to the server is permitted by
              the policy.  Its return value specifies the result of the
              check.
              Returns ZV_ACCEPT for success, and ZV_REJECT for failure.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        zone_name_list = self.service.limit_target_zones_to

        if zone_name_list:
            zone = self.server_zone

            while zone:
                if zone.getName() in zone_name_list:
                    return ZV_ACCEPT
                else:
                    zone = zone.admin_parent

            ## LOG ##
            # This message indicates that a service trying to enter to the given
            # zone was denied by the policy. Check that the destination zone is included in
            # the target zone list of the service.
            ##
            log(self.session_id, CORE_POLICY, 1,
                "Outbound connection not permitted; service='%s', client_zone='%s', client='%s', server_zone='%s', server='%s'" %
                (self.service, self.client_zone, self.client_address, self.server_zone, self.server_address))
            return ZV_REJECT

        return ZV_ACCEPT

    def setTargetAddressByHostname(self, host, port):
        """<method internal="yes"/>"""
        # resolve host, port and store it in session.server_address
        # may raise an exception
        if self.target_address_inband:
            target = self.service.resolver_policy.resolve(host, port)
            if not target:
                ## LOG ##
                # This message indicates that the given hostname
                # could not be resolved.  It could happen if the
                # hostname is invalid or nonexistent, or it if your
                # resolve setting are not well configured.  Check
                # your "/etc/resolv.conf"
                ##
                log(self.session_id, CORE_ERROR, 3, "Error resolving hostname; host='%s'", (host,))
                return FALSE

            self.setTargetAddress(target)

        return TRUE

    def setTargetAddress(self, addr):
        """
        <method internal="yes">
          <summary>
            Set the target server address.
          </summary>
          <description>
            <para>
              This is a compatibility function for proxies that
              override the routed target.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>addr</name>
                <type></type>
                <description>Server address</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        # NOTE: handling SockAddr types is a compatibility hack, as
        # proxies might call setServer with a SockAddr instance
        # instead of a tuple of SockAddrs

        if isinstance(addr, SockAddrType):
            self.target_address = (addr,)
        else:
            self.target_address = addr

        self.target_zone = [Zone.lookup(a) for a in self.target_address]

    setServer = setTargetAddress

    def _get_secondary_connection(self):
        """<method internal="yes"/>"""
        return getattr(self, "secondary_connection_id", 0)

    def _get_trimmed_session_id(self):
        """<method internal="yes"/>"""
        return self.session_id.rsplit("/", 1)[0]

    def registerStart(self, timestamp=None):
        """<method internal="yes"/>"""
        if timestamp is None:
            import time
            timestamp = str(time.time())

        self.updateSzigConns(Z_SZIG_CONNECTION_PROPS, {
                        'started': timestamp,
                        'session_id': self._get_trimmed_session_id(),
                        'proxy_module': self.proxy.name,
                        'proxy_class': self.proxy.__class__.__name__,
                        'client_address': str(self.client_address),
                        'client_local': str(self.client_local),
                        'client_zone': self.client_zone.getName(),
                        })

        szigEvent(Z_SZIG_CONNECTION_START,
                    (Z_SZIG_TYPE_PROPS,
                       (self.service.name, {}
                 )))

        self.registered_in_szig = True

    def registerStop(self):
        """<method internal="yes"/>"""
        self.updateSzigConns(Z_SZIG_CONNECTION_STOP, {})

    def registerServerAddress(self):
        """<method internal="yes"/>"""
        self.updateSzigConns(Z_SZIG_CONNECTION_PROPS, {
                'server_address': str(self.server_address),
                'server_local': str(self.server_local),
                'server_zone': self.server_zone.getName(),
                })

    def updateSzigConns(self, event, data):
        """<method internal="yes"/>"""
        szigEvent(event,
                  (Z_SZIG_TYPE_CONNECTION_PROPS,
                   (self.service.name, self.instance_id, self._get_secondary_connection(), 0, data)))
