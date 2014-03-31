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
    Module defining interface to the Zones.
  </summary>
  <description>
    <para>
      This module defines the <parameter>Zone</parameter> class.
    </para>
    <para>
              Zones are the basis of access control in Zorp. A zone consists of a
              set of IP addresses, address ranges, or subnet. For example, a zone can
              contain an IPv4 or IPv6 subnet.
            </para>
            <para>
              Zones are organized into a hierarchy created by the
              Zorp administrator. Child zones inherit the
              security attributes (set of permitted services etc.) from their
              parents. The administrative hierarchy often reflects the organization of
              the company, with zones assigned to the different departments.</para>
              <para>
              When Zorp has to determine which zone a client belongs to,
              it selects the most specific zone containing the searched IP address.
              If an IP address belongs to two different zones, the most specific zone is selected.
              </para>
              <note>
                <para>In earlier Zorp versions, zones had an option to stop child zones from inheriting parameters (umbrella zones). Starting from Zorp 3 F5, use <link linkend="python.Service.DenyService">DenyServices</link> to achieve similar functionality.</para>
              </note>
        <example>
        <title>Finding IP networks</title>
        <para>Suppose there are three zones configured: <parameter>Zone_A</parameter> containing the
            <parameter>10.0.0.0/8</parameter> network, <parameter>Zone_B</parameter> containing the
            <parameter>10.0.0.0/16</parameter> network, and <parameter>Zone_C</parameter> containing
          the <parameter>10.0.0.25</parameter> IP address. Searching for the
          <parameter>10.0.44.0</parameter> network returns <parameter>Zone_B</parameter>, because
          that is the most specific zone matching the searched IP address. Similarly, searching for
            <parameter>10.0.0.25</parameter> returns only <parameter>Zone_C</parameter>.</para>
        <para>This approach is used in the service definitions as well: when a client sends a
          connection request, Zorp looks for the most specific zone containing the IP address of the
          client. Suppose that the clients in <parameter>Zone_A</parameter> are allowed to use HTTP.
          If a client with IP <parameter>10.0.0.50</parameter> (thus belonging to
          <parameter>Zone_B</parameter>) can only use HTTP if <parameter>Zone_B</parameter> is the
          child of <parameter>Zone_A</parameter>, or if a service definition explicitly permits
            <parameter>Zone_B</parameter> to use HTTP.</para>
      </example>
     <example id="inetzone_example">
     <title>Zone examples</title>
     <para>The following example defines a simple zone hierarchy. The following
     zones are defined:</para>
     <itemizedlist>
     <listitem>
     <para><emphasis>internet</emphasis>: This zone contains every possible IP
     addresses, if an IP address does not belong to another zone, than it belongs
     to the <emphasis>internet</emphasis> zone.</para>
     </listitem>
     <listitem>
     <para><emphasis>office</emphasis>: This zone contains the <parameter>192.168.1.0/32
     </parameter> and <parameter>192.168.2.0/32
     </parameter> networks.</para>
     </listitem>
     <listitem>
     <para><emphasis>management</emphasis>: This zone is separated from the
     <emphasis>office</emphasis> zone, because it contans an independent subnet <parameter>192.168.3.0/32
     </parameter>. But from the Zorp administrator's view, it is the child zone of
     the <emphasis>office</emphasis> zone, meaning that it can use (and accept)
      the same services as the <emphasis>office</emphasis> zone.</para>
     </listitem>
     <listitem>
     <para><emphasis>DMZ</emphasis>: This is a separate zone.</para>
     </listitem>
     </itemizedlist>
     <synopsis>Zone('internet', ['0.0.0.0/0', '::0/0'])
Zone('office', ['192.168.1.0/32', '192.168.2.0/32'])
Zone('management', ['192.168.3.0/32'])
Zone('DMZ', ['10.50.0.0/32'])</synopsis>
     </example>
  </description>
</module>
"""

from Base import BaseZone
from Subnet import Subnet, InetSubnet, Inet6Subnet
from socket import htonl, ntohl
from traceback import print_exc
from Exceptions import ZoneException
import types
import radix
import struct

class Zone(BaseZone):
    """
          <class maturity="stable">
            <summary>
              Class encapsulating IP zones.
            </summary>
            <description>
              <para>
                This class encapsulates IPv4 and IPv6 zones.
              </para>
        <example>
      <title>Determining the zone of an IP address</title>
      <para>
      An IP address always belongs to the most specific zone.
      Suppose that <parameter>Zone A</parameter> includes the IP network <parameter>10.0.0.0/8</parameter>
      and <parameter>Zone B</parameter> includes the network <parameter>10.0.1.0/24</parameter>.
      In this case, a client machine with the <parameter>10.0.1.100/32</parameter> IP address
      belongs to both zones from an IP addressing point of view. But <parameter>Zone B</parameter> is more
      specific (in CIDR terms), so the client machine belongs to <parameter>Zone B</parameter> in Zorp.
      </para>
        </example>
            </description>
            <metainfo>
              <attributes/>
            </metainfo>
          </class>
    """
    zone_subnet_tree = radix.Radix()
    has_dynamic_subnet = False

    def __init__(self, name, addrs=(), hostnames=(), admin_parent=None, inbound_services=None, outbound_services=None):
        """
                    <method maturity="stable">
                      <summary>
                        Constructor to initialize a Zone instance
                      </summary>
                      <description>
                        <para>
                          This constructor initializes a Zone object.
                        </para>
                      </description>
                      <metainfo>
                        <arguments>
                          <argument maturity="stable">
                            <name>name</name>
                            <type><string/></type>
                            <description>Name of the zone.</description>
                          </argument>
                          <argument maturity="stable">
                            <name>addr</name>
                            <type><list><string/></list></type>
                            <description>
                              A string representing an address range interpreted
                              by the domain class (last argument), *or* a list of
                              strings representing multiple address ranges. <!--FIXME-->
                            </description>
                          </argument>
                          <argument maturity="stable">
                            <name>hostnames</name>
                            <type><list><string/></list></type>
                            <description>
                              A string representing a domain name, the addresses of its
                              A and AAAA records are placed into the zone hierarchy
                              *or* a list of domain names representing multiple domain names
                            </description>
                          </argument>
                          <argument maturity="stable">
                            <name>admin_parent</name>
                            <type><string/></type>
                            <description>Name of the administrative parent zone. If set, the current zone
                             inherits the lists of permitted inbound and outbound
                             services from its administrative parent zone.</description>
                          </argument>
                        </arguments>
                      </metainfo>
                    </method>
        """
        if (inbound_services or outbound_services) is not None:
            raise Exception, "Inbound and outbound services are not supported as of Zorp 3.5"

        super(Zone, self).__init__(name, addrs, hostnames, admin_parent)

        zone = reduce(lambda res, subnet: res or self.zone_subnet_tree.search_exact(packed=subnet.addr_packed()), self.subnets, None)
        if zone:
            raise ZoneException, "Zone with duplicate IP range; zone=%s" % zone.data["zone"]
        for subnet in self.subnets:
            self.zone_subnet_tree.add(packed=subnet.addr_packed(), masklen=subnet.netmask_bits()).data["zone"] = self
        if hostnames:
            Zone.has_dynamic_subnet = True

    @staticmethod
    def __lookupFromKZorp(addr):
        from kzorp.communication import Adapter
        from kzorp.netlink import NetlinkException
        from kzorp.messages import KZorpLookupZoneMessage
        import socket

        family = addr.family
        addr_str = addr.ip_s
        try:
            with Adapter() as adapter:
                add_zone_message = adapter.send_message(KZorpLookupZoneMessage(family, socket.inet_pton(family, addr.ip_s)))
                return Zone.lookupByName(add_zone_message.name)
        except NetlinkException as e:
            return None

    @staticmethod
    def __lookupFromZone(addr):
        rnode = Zone.zone_subnet_tree.search_best(packed = addr)
        if rnode:
            return rnode.data["zone"]
        else:
            return None

    @staticmethod
    def __createPackedAddr(addr):
        if isinstance(addr, InetSubnet):
            addr_packed = addr.addr_packed()
        elif isinstance(addr, Inet6Subnet):
            addr_packed = addr.addr_packed()
        else:
            addr_packed = addr.pack()

        return addr_packed

    @staticmethod
    def lookup(addr):
        """
        <method internal="yes"/>
        """

        addr_packed = Zone.__createPackedAddr(addr)
        if Zone.has_dynamic_subnet:
            return Zone.__lookupFromKZorp(addr)
        else:
            return Zone.__lookupFromZone(addr_packed)

    @staticmethod
    def lookupByStaticAddressExactly(addr):
        """
        <method internal="yes"/>
        """
        addr_packed = Zone.__createPackedAddr(addr)
        rnode = Zone.zone_subnet_tree.search_exact(packed = addr_packed)
        if rnode:
            return rnode.data["zone"]
        else:
            return None

    @staticmethod
    def lookupByStaticAddress(addr):
        """
        <method internal="yes"/>
        """
        addr_packed = Zone.__createPackedAddr(addr)
        return Zone.__lookupFromZone(addr_packed)

    @staticmethod
    def lookupByName(name):
        """
        <method internal="yes"/>
        """
        if name in Zone.zones:
            return Zone.zones[name]

        return None

    @staticmethod
    def lookupByHostname(hostname):
        """
        <method internal="yes"/>
        """
        zones = filter(lambda zone: hostname in zone.hostnames, Zone.zones.values())
        if len(zones) > 1: raise ValueError
        elif len(zones) == 1: return zones[0]
        else: return None

InetZone = Zone
