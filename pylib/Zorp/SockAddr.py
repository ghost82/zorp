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
  Module defining interface to the SockAddr.
</summary>
<description>
  <para>
  This module implements <parameter>inet_ntoa</parameter> and <parameter>inet_aton</parameter>. The module also provides an interface
  to the SockAddr services of the Zorp core. SockAddr is used for example to define the address of the ZAS server in
  <link linkend="python.AuthDB.AuthenticationProvider">AuthenticationProvider</link> policies.
  </para>
</description>
</module>
"""

class SockAddrInet(object):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating an IPv4 address:port pair.
      </summary>
      <description>
        <para>
          This class encapsulates an IPv4 address:port pair, similarly to
          the <parameter>sockaddr_in</parameter> struct in C. The class is implemented and exported by
          the Zorp core. The <parameter>SockAddrInet</parameter> Python class serves only
          documentation purposes, and has no real connection to the
          behavior implemented in C.
        </para>
        <example>
            <title>SockAddrInet example</title>
            <para>
            The following example defines an IPv4 address:port pair.</para>
            <synopsis>SockAddrInet('192.168.10.10', 80)</synopsis>
            <para>
            The following example uses SockAddrInet in a dispatcher.
            </para>
            <synopsis>Dispatcher(transparent=TRUE, bindto=DBSockAddr(protocol=ZD_PROTO_TCP, sa=SockAddrInet('192.168.11.11', 50080)), service="intra_HTTP_inter", backlog=255, rule_port="50080")</synopsis>
        </example>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>type</name>
            <type><string/></type>
            <description>The <parameter>inet</parameter> value that indicates an address in the AF_INET domain.</description>
          </attribute>
          <attribute maturity="stable">
            <name>ip</name>
            <type></type>
            <description>IP address (network byte order).</description>
          </attribute>
          <attribute maturity="stable">
            <name>ip_s</name>
            <type></type>
            <description>IP address in string representation.</description>
          </attribute>
          <attribute maturity="stable">
            <name>port</name>
            <type></type>
            <description>Port number (network byte order).</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, ip_addr, port):
        pass

class SockAddrInet6(object):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating an IPv6 address:port pair.
      </summary>
      <description>
        <para>
          This class encapsulates an IPv6 address:port pair, similarly to
          the <parameter>sockaddr_in</parameter> struct in C. The class is implemented and exported by
          the Zorp core. The <parameter>SockAddrInet</parameter> Python class serves only
          documentation purposes, and has no real connection to the
          behavior implemented in C.
        </para>
        <example>
            <title>SockAddrInet example</title>
            <para>
            The following example defines an IPv6 address:port pair.</para>
            <synopsis>SockAddrInet('fec0::1', 80)</synopsis>
            <para>
            The following example uses SockAddrInet in a dispatcher.
            </para>
            <synopsis>Dispatcher(transparent=TRUE, bindto=DBSockAddr(protocol=ZD_PROTO_TCP, sa=SockAddrInet('fec0::1', 50080)), service="intra_HTTP_inter", backlog=255, rule_port="50080")</synopsis>
        </example>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>type</name>
            <type><string/></type>
            <description>The <parameter>inet</parameter> value that indicates an address in the AF_INET domain.</description>
          </attribute>
          <attribute maturity="stable">
            <name>ip</name>
            <type></type>
            <description>IP address (network byte order).</description>
          </attribute>
          <attribute maturity="stable">
            <name>ip_s</name>
            <type></type>
            <description>IP address in string representation.</description>
          </attribute>
          <attribute maturity="stable">
            <name>port</name>
            <type></type>
            <description>Port number (network byte order).</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self, ip_addr, port):
        pass

class SockAddrInetRange(object):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating an IPv4 address and a port range.
      </summary>
      <description>
        <para>
          A specialized SockAddrInet class which allocates a new port
          within the given range of ports when a dispatcher bounds to it.
          The class is implemented and exported by
          the Zorp core. The <parameter>SockAddrInetRange</parameter> Python class serves only
          documentation purposes, and has no real connection to the
          behavior implemented in C.
        </para>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>type</name>
            <type><string/></type>
            <description>The <parameter>inet</parameter> value that indicates an address in the AF_INET domain.</description>
          </attribute>
          <attribute maturity="stable">
            <name>ip</name>
            <type></type>
            <description>IP address (network byte order).</description>
          </attribute>
          <attribute maturity="stable">
            <name>ip_s</name>
            <type></type>
            <description>IP address in string representation.</description>
          </attribute>
          <attribute maturity="stable">
            <name>port</name>
            <type></type>
            <description>Port number (network byte order).</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>

    """
    def __init__(self, ip_addr, port_min, port_max):
        pass

class SockAddrUnix(object):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating a UNIX domain socket.
      </summary>
      <description>
        <para>
          This class encapsulates a UNIX domain socket endpoint.
          The socket is represented by a filename. The <parameter>SockAddrUnix</parameter>
          Python class serves only
          documentation purposes, and has no real connection to the
          behavior implemented in C.
        </para>
        <example>
            <title>SockAddrUnix example</title>
            <para>
            The following example defines a Unix domain socket.</para>
            <synopsis>SockAddrUnix('/var/sample.socket')</synopsis>
            <para>
            The following example uses SockAddrUnix in a DirectedRouter.
            </para>
            <synopsis>Service(name="demo_service", proxy_class=HttpProxy, router=DirectedRouter(dest_addr=SockAddrUnix('/var/sample.socket'), overrideable=FALSE, forge_addr=FALSE))</synopsis>
        </example>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>type</name>
            <type><string/></type>
            <description>The <parameter>unix</parameter> value that indicates an address in the UNIX domain.</description>
          </attribute>
        </attributes>
      </metainfo>
    </class>

    """
    def __init__(self, socket_path):
        pass

class SockAddrInetHostname(object):
    def __init__(self, hostname, port):
        pass
