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
    <summary>Module defining firewall rules</summary>
    <description>
        <para>The Rule module defines the classes needed to create Zorp firewall rules.</para>
        <xi:include href="../../zorp-admin-guide/chapters/zorp-firewall-rules.xml" xmlns:xi="http://www.w3.org/2001/XInclude" xpointer="element(zorp-firewall-rules-evaluation)"><xi:fallback><xi:include href="../zorp-admin-guide/chapters/zorp-firewall-rules.xml" xmlns:xi="http://www.w3.org/2001/XInclude" xpointer="element(zorp-firewall-rules-evaluation)"/></xi:fallback></xi:include>
        <section xml:id="sample-rules">
            <title>Sample rules</title>
            <example xml:id="example-rules">
                <title>Sample rule definitions</title>
                <para>The following rule starts the service called <parameter>MyPFService</parameter> for every incoming TCP connection (<parameter>proto=6</parameter>).</para>
                <synopsis>Rule(proto=6,
    service='MyPFService'
    )</synopsis>
                <para>The following rule starts a service for TCP or UDP connections from the <parameter>office</parameter> zone.</para>
                <synopsis>Rule(proto=(6,17),
    src_zone='office',
    service='MyService'
    )</synopsis>
            <para>The following rule permits connections from the <parameter>192.168.0.0/16</parameter> IPv4 and the <parameter>2001:db8:c001:ba80::/58</parameter> IPv6 subnets. Note that since the <parameter>src_subnet</parameter> parameter has two values, they are specified as a Python tuple: <parameter>('value1','value2')</parameter>.</para>
            <synopsis>Rule(proto=6,
    src_subnet=('192.168.0.0/16', '2001:db8:c001:ba80::/58'),
    service='MyService'
    )</synopsis>
            <para>The following rule has almost every parameter set:</para>
            <synopsis>Rule(src_iface=('eth0', ),
    proto=6,
    dst_port=443,
    src_subnet=('192.168.10.0/24', ),
    src_zone=('office', ),
    dst_subnet=('192.168.50.50/32', ),
    dst_zone=('finance', ),
    service='MyHttpsService'
    )</synopsis>
            </example>
        </section>
        <section xml:id="rules-metadata">
            <title>Adding metadata to rules: tags and description</title>
            <para>To make the configuration file more readable and informative, you can add descriptions and tags to the rules. Descriptions can be longer texts, while tags are simple labels, for example, to identify rules that belong to the same type of traffic. Adding metadata to rules is not necessary, but can be a great help when maintaining large configurations.</para>
            <itemizedlist>
                <listitem>
                    <para>To add a description to a rule, add the text of the description before the rule, enclosed between three double-quotes:</para>
                    <synopsis>&quot;&quot;&quot;This rule is ...&quot;&quot;&quot;</synopsis>
                </listitem>
                <listitem>
                    <para>To tag a rule, add a comment line before the rule that contains the list of tags applicable to the rule, separated with commas.</para>
                    <synopsis>#Tags: tag1, tag2</synopsis>
                </listitem>
            </itemizedlist>
            <example>
                <title>Tagging rules</title>
                <para>The following rule has two tags, marking the traffic type and the source zone: <parameter>http</parameter> and <parameter>office</parameter>.</para>
                <synopsis>#Tags: http, office
    &quot;&quot;&quot;Description&quot;&quot;&quot;
    Rule(proto=(6),
    src_zone='office',
    service='MyHttpService'
    )</synopsis>
            </example>
        </section>
    </description>
</module>
"""

from Util import makeSequence
from Util import parseIfaceGroupAliases
from Subnet import Subnet
from Zone import Zone
import kzorp.messages as kzorp
import Globals
import Dispatch

class RuleSet(object):
    """
    <class maturity="stable" internal="yes">
      <summary>
      </summary>
      <description>
        <para>
        </para>
      </description>
    </class>
    """
    def __init__(self):
        """
        <method internal="yes">
        </method>
        """
        self._rules = []
        self._rule_id_index = 1
        self._rule_id_set = set()

    def _getNextId(self):
        """
        <method internal="yes">
        </method>
        """
        while (self._rule_id_index in self._rule_id_set):
            self._rule_id_index += 1

        return self._rule_id_index

    def add(self, rule):
        """
        <method internal="yes">
        </method>
        """
        rule_id = rule.getId()
        if not rule_id:
            # generate a unique id
            rule_id = self._getNextId()
            rule.setId(rule_id)
        elif rule_id in self._rule_id_set:
            # the specified id is not unique
            raise ValueError, "Duplicate rule id found; id='%d'" % (rule_id,)

        self._rule_id_set.add(rule_id)
        self._rules.append(rule)

    def _sortRules(self):
        """
        <method internal="yes">
        </method>
        """
        self._rules.sort(lambda a, b: cmp(a.getId(), b.getId()))

    def __iter__(self):
        """
        <method internal="yes">
        </method>
        """
        self._sortRules()
        return iter(self._rules)

    @property
    def length(self):
        """
        <method internal="yes">
        </method>
        """
        return len(self._rules)

class PortRange(object):
    """
    <class maturity="stable">
        <summary>Specifies a port range for a rule</summary>
        <description>
            <para>This class specifies a port range for a firewall rule. It can be used in the <parameter>src_port</parameter> and <parameter>dst_port</parameter> parameters of a rule. For example: <parameter>src_port=PortRange(2000, 2100)</parameter>, or <parameter>src_port=(PortRange(2000, 2100), PortRange(2500, 2600))</parameter>. When listing multiple elements, ports and port ranges can be mixed, for example: <parameter>src_port=(4433, PortRange(2000, 2100), PortRange(2500, 2600))</parameter></para>
        </description>
        <metainfo>
            <attributes>
                <attribute>
                    <name>low</name>
                    <type><integer/></type>
                    <description>The lower value of the port range.</description>
                </attribute>
                <attribute>
                    <name>high</name>
                    <type><integer/></type>
                    <description>The higher value of the port range.</description>
                </attribute>
            </attributes>
        </metainfo>
    </class>
    """
    def __init__(self, low, high):
        """
        <method internal="yes">
        </method>
        """
        self._low = low
        self._high = high

    def getTuple(self):
        """
        <method internal="yes">
        </method>
        """
        return (self._low, self._high)

class Rule(object):
    """
    <class maturity="stable">
        <summary>This class implements firewall rules</summary>
        <description>
            <para>This class implements Zorp firewall rules. For details, see <xref linkend="python.Rule"/>.</para>
        </description>
        <metainfo>
          <attributes/>
        </metainfo>
    </class>
    """
    valid_dimensions = { 'reqid'         : kzorp.KZNL_ATTR_N_DIMENSION_REQID,
                         'iface'         : kzorp.KZNL_ATTR_N_DIMENSION_IFACE,
                         'ifgroup'       : kzorp.KZNL_ATTR_N_DIMENSION_IFGROUP,
                         'proto'         : kzorp.KZNL_ATTR_N_DIMENSION_PROTO,
                         'proto_type'    : kzorp.KZNL_ATTR_N_DIMENSION_PROTO_TYPE,
                         'proto_subtype' : kzorp.KZNL_ATTR_N_DIMENSION_PROTO_SUBTYPE,
                         'src_port'      : kzorp.KZNL_ATTR_N_DIMENSION_SRC_PORT,
                         'dst_port'      : kzorp.KZNL_ATTR_N_DIMENSION_DST_PORT,
                         'src_subnet'    : kzorp.KZNL_ATTR_N_DIMENSION_SRC_IP,
                         'src_subnet6'   : kzorp.KZNL_ATTR_N_DIMENSION_SRC_IP6,
                         'src_zone'      : kzorp.KZNL_ATTR_N_DIMENSION_SRC_ZONE,
                         'dst_subnet'    : kzorp.KZNL_ATTR_N_DIMENSION_DST_IP,
                         'dst_subnet6'   : kzorp.KZNL_ATTR_N_DIMENSION_DST_IP6,
                         'dst_iface'     : kzorp.KZNL_ATTR_N_DIMENSION_DST_IFACE,
                         'dst_ifgroup'   : kzorp.KZNL_ATTR_N_DIMENSION_DST_IFGROUP,
                         'dst_zone'      : kzorp.KZNL_ATTR_N_DIMENSION_DST_ZONE,
                       }

    dimension_aliases = {
                          'src_iface'    : 'iface',
                          'src_ifgroup'  : 'ifgroup',
                          'icmp_type'    : 'proto_type',
                          'icmp_code'    : 'proto_subtype',
                        }

    try:
        iface_group_aliases = parseIfaceGroupAliases()
    except IOError as e:
        iface_group_aliases = {}

    def __init__(self, **kw):
        """
        <method>
            <summary>Initializes a rule</summary>
            <description>Initializes a rule</description>
            <metainfo>
                <arguments>
                    <argument>
                        <name>dst_iface</name>
                        <type><interface/></type>
                        <description>Permit traffic only for connections that target a configured IP address of the listed interfaces. This parameter can be used to provide nontransparent service on an interface that received its IP address dynamically. For example, <parameter>dst_iface='eth0',</parameter> or <parameter>dst_iface=('eth0', 'tun1'),</parameter>.</description>
                    </argument>
                    <argument>
                        <name>dst_ifgroup</name>
                        <type><integer/></type>
                        <description>Permit traffic only for connections that target a configured IP address of the listed interface group. This parameter can be used to provide nontransparent service on an interface that received its IP address dynamically. For example, <parameter>dst_ifgroup=1</parameter>.</description>
                    </argument>
                    <argument>
                        <name>dst_port</name>
                        <type><integer/></type>
                        <description>Permit traffic only if the client targets the listed port. For example, <parameter>dst_port=80</parameter>, or <parameter>dst_port=(80, 443)</parameter>. To specify port ranges, use the <link linkend="python.Rule.PortRange">PortRange</link> class, for example, <parameter>dst_port=PortRange(2000, 2100)</parameter>.</description>
                    </argument>
                    <argument>
                        <name>dst_subnet</name>
                        <type><subnet/></type>
                        <description>Permit traffic only for connections targeting a listed IP address, or an address belonging to the listed subnet. The subnet can be IPv4 or IPv6 subnet. When listing multiple subnets, you can list both IPv4 and IPv6 subnets. IP addresses are treated as subnets with a /32 (IPv4) or /128 (IPv6) netmask. If no netmask is set for a subnet, it is treated as a specific IP address. For example, <parameter>dst_subnet='192.168.10.16'</parameter> or <parameter>dst_subnet=('192.168.0.0/16', '2001:db8:c001:ba80::/58')</parameter>.</description>
                    </argument>
                    <argument>
                        <name>dst_zone</name>
                        <type><zone/></type>
                        <description>Permit traffic only for connections targeting an address belonging to the listed zones. For example, <parameter>dst_zone='office'</parameter> or <parameter>dst_zone=('office', 'finance')</parameter>. Note that this applies to destination address of the client-side connection request: the actual address of the server-side connection can be different (for example, if a DirectedRouter is used in the service).</description>
                    </argument>
                    <argument>
                        <name>proto</name>
                        <type><integer/></type>
                        <description>Permit only connections using the specified transport protocol. This is the transport layer (Layer 4) protocol of the OSI model, for example, TCP, UDP, ICMP, and so on. The protocol must be specified using a number: the decimal value of the "protocol" field of the IP header. This value is 6 for the TCP and 17 for the UDP protocol. For a list of protocol numbers, see the <ulink url="http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml">Assigned Internet Protocol Numbers page of IANA</ulink>. For example: <parameter>proto=(6,17)</parameter>.
                        <para>To permit any protocol, do not add the <parameter>proto</parameter> parameter to the rule.</para></description>
                    </argument>
                    <argument>
                        <name>rule_id</name>
                        <type><integer/></type>
                        <description>A unique ID number for the rule. This parameter is optional, Zorp automatically generates an ID number for the rule during startup.</description>
                    </argument>
                    <argument>
                        <name>service</name>
                        <type><service/></type>
                        <description>The name of the service to start for matching connections. This is the only required parameter for the rule, everything else is optional. For example, <parameter>service='MyService'</parameter></description>
                    </argument>
                    <argument>
                        <name>src_iface</name>
                        <type><interface/></type>
                        <description>Permit traffic only for connections received on the listed interface. For example, <parameter>src_iface='eth0',</parameter> or <parameter>src_iface=('eth0', 'tun1'),</parameter>.</description>
                    </argument>
                    <argument>
                        <name>src_ifgroup</name>
                        <type><integer/></type>
                        <description>Permit traffic only for connections received on the listed interfacegroup. For example, <parameter>src_iface=1</parameter>. Interface groups can be defined in the <filename>/etc/network/interfaces</filename> file, for example:
                        <synopsis>iface eth0 inet dhcp
            group 1
        iface eth1 inet dhcp
            group 1</synopsis></description>
                    </argument>
                    <argument>
                        <name>src_port</name>
                        <type><integer/></type>
                        <description>Permit traffic only if the client sends the connection request from the listed port. For example, <parameter>src_port=4455</parameter>. To specify port ranges, use the <link linkend="python.Rule.PortRange">PortRange</link> class, for example, <parameter>src_port=PortRange(2000, 2100)</parameter>.</description>
                    </argument>
                    <argument>
                        <name>src_subnet</name>
                        <type><subnet/></type>
                        <description>Permit traffic only for the clients of the listed subnet or IP addresses. The subnet can be IPv4 or IPv6 subnet. When listing multiple subnets, you can list both IPv4 and IPv6 subnets. IP addresses are treated as subnets with a /32 (IPv4) or /128 (IPv6) netmask. If no netmask is set for a subnet, it is treated as a specific IP address. For example, <parameter>src_subnet='192.168.10.16'</parameter> or <parameter>src_subnet=('192.168.0.0/16', '2001:db8:c001:ba80::/58')</parameter>.</description>
                    </argument>
                    <argument>
                        <name>src_zone</name>
                        <type><zone/></type>
                        <description>Permit traffic only for the clients of the listed zones. For example, <parameter>src_zone='office'</parameter> or <parameter>src_zone=('office', 'finance')</parameter>.</description>
                    </argument>
                </arguments>
            </metainfo>
        </method>
        """

        def parseSubnets(subnet_list):
            """
            <method internal="yes">
            Helper function to convert a string-based
            subnet list to two tuples consisting of
            InetSubnet and InetSubnet6 instances.
            </method>
            """
            import socket
            subnets = { socket.AF_INET: [], socket.AF_INET6: [] }

            subnet_list = makeSequence(subnet_list)

            for item in subnet_list:
                if isinstance(item, basestring):
                    subnet = Subnet.create(item)
                elif isinstance(item, Subnet):
                    subnet = item
                else:
                    raise ValueError, "Invalid subnet specification: value='%s'" % (item,)

                subnets[subnet.get_family()].append((subnet.addr_packed(), subnet.netmask_packed()))

            return (tuple(subnets[socket.AF_INET]), tuple(subnets[socket.AF_INET6]))

        def resolveZones(name_list):
            """
            <method internal="yes">
            Helper function to convert a list of zone
            names to a list of Zone instnaces
            </method>
            """
            name_list = makeSequence(name_list)

            for name in name_list:
                if Zone.lookupByName(name) == None:
                    raise ValueError, "No zone was defined with that name; zone='%s'" % (name,)

        def parsePorts(port_list):
            """
            <method internal="yes">
            Helper function to convert a port or port
            range list to a list of port ranges. Accepted
            input formats are:

            (port1, port2, port3) - list of ports
            (port1, (begin, end), port3) - list of ports mixed with ranges
            </method>
            """
            ports = []
            port_list = makeSequence(port_list)

            for item in port_list:
                if isinstance(item, PortRange):
                    ports.append(item.getTuple())
                else:
                    if isinstance(item, basestring):
                        item = int(item)

                    if not isinstance(item, int):
                        raise ValueError, "Integer port value expected; value='%s'" % (item,)

                    ports.append((item, item))

            return ports

        def parseGroups(group_list):
            groups = []
            group_list = makeSequence(group_list)

            for item in group_list:
                if isinstance(item, int):
                    groups.append(item)
                elif isinstance(item, basestring):
                    try:
                        item = int(item)
                    except ValueError:
                        if item not in self.iface_group_aliases:
                            raise ValueError, "Valid group name expected; value='%s' %s" % (item, str(self.iface_group_aliases))
                        item = self.iface_group_aliases[item]

                    groups.append(item)

            return groups

        def CreateRealRule(parameters):
            """
            <method internal="yes">
            Helper function to create rules
            </method>
            """

            # store service
            service_name = parameters.pop('service', None)
            self._service = Globals.services.get(service_name, None)
            if not self._service:
                raise ValueError, "No valid service was specified for the rule; service='%s'" % (service_name,)

            # convert and check special dimensions: subnets, ports and zones at the moment

            for ip_keyword in ['src_subnet', 'dst_subnet']:
                ipv6_keyword = ip_keyword + '6'
                # forbid usage of ipv6 related keywords:
                if ipv6_keyword in parameters:
                    raise ValueError, "Invalid dimension specification '%s'" % ipv6_keyword
                (parameters[ip_keyword], parameters[ipv6_keyword]) = parseSubnets(parameters.get(ip_keyword, []))

            parameters['src_ifgroup'] = parseGroups(parameters.get('src_ifgroup', []))
            parameters['dst_ifgroup'] = parseGroups(parameters.get('dst_ifgroup', []))
            parameters['src_port'] = parsePorts(parameters.get('src_port', []))
            parameters['dst_port'] = parsePorts(parameters.get('dst_port', []))
            resolveZones(parameters.get('src_zone', []))
            resolveZones(parameters.get('dst_zone', []))

            # store values specified
            self._dimensions = {}
            for key, value in parameters.items():
                if key not in self.valid_dimensions:
                    if key in self.dimension_aliases:
                        key = self.dimension_aliases[key]
                    else:
                        raise ValueError, "Unknown dimension '%s'" % (key,)

                self._dimensions.setdefault(key, []).extend(makeSequence(value))

            Dispatch.RuleDispatcher.createOneInstance()

        parameters = kw
        # store id
        self._id = parameters.pop('rule_id', None)

        Globals.rules.add(self)

        protocol_detect_dict = parameters.pop('detect', None)
        if protocol_detect_dict:
          from APR import DetectorProxy
          from Service import Service
          for detector_name, service_name in protocol_detect_dict.iteritems():
            if not Globals.detectors.get(detector_name, None):
              raise ValueError, "No such detector defined; detector='%s'" % (detector_name,)

            if not Globals.services.get(service_name, None):
              raise ValueError, "No such service defined; service='%s'" % (service_name,)

          rule_service_name = "detector_service_for_rule_%s" % (self.getId(),)
          Service(rule_service_name, proxy_class=DetectorProxy, detector_config=protocol_detect_dict)
          parameters['service'] = rule_service_name

        CreateRealRule(parameters)

    def getId(self):
        """
        <method internal="yes">
        </method>
        """
        return self._id

    def setId(self, rule_id):
        """
        <method internal="yes">
        </method>
        """
        self._id = rule_id

    def buildKZorpMessage(self, dispatcher_name):
        """
        <method internal="yes">
        </method>
        """
        messages = []

        # determine maximum dimension length

        kzorp_dimensions = {}
        for (key, value) in self._dimensions.items():
            kzorp_dimensions[self.valid_dimensions[key]] = value

        kzorp_dimension_sizes = dict(map(lambda (key, value): (key, len(value)), kzorp_dimensions.items()))
        max_dimension_length = max(kzorp_dimension_sizes.values()) if len(kzorp_dimension_sizes) > 0 else 0

        messages.append(kzorp.KZorpAddRuleMessage(dispatcher_name,
                                                 self.getId(),
                                                 self._service.name,
                                                 kzorp_dimension_sizes))

        for i in xrange(max_dimension_length):
            data = {}

            for dimension, values in kzorp_dimensions.items():
                if len(values) > i:
                    data[dimension] = values[i]

            messages.append(kzorp.KZorpAddRuleEntryMessage(dispatcher_name, self.getId(), data))
        return messages
