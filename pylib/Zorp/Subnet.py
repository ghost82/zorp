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
    Module defining interface to address domains.
  </summary>
  <description>
    <para>
      This module implements the Subnet classes, which encapsulate a set of physical addresses.
    </para>
  </description>
</module>
"""

from Zorp import *
from string import split, atoi
from socket import htonl, ntohl, inet_ntoa, inet_aton, inet_pton, inet_ntop, ntohs
import socket
import struct

def packed_1operand(a, f):
    """<function internal="yes">apply second argument to each character of the packed string 'a', converted to int</function>"""
    return map(lambda x: chr(f(ord(x)) & 0xff), a)

def packed_2operand(a, b, f):
    """<function internal="yes">apply the third argument to each character in both first and second arguments</function>"""
    return "".join(map(lambda t: chr(f(ord(t[0]), ord(t[1]))), zip(a, b)))

def packed_mask(addr, mask):
    """
    <function internal="yes"/>
    """
    return packed_2operand(addr, mask, lambda a, b: a & b)

class Subnet(object):
    """
    <class internal="yes"/>
    """
    def __init__(self):
        """
        <method internal="yes"/>
        """
        pass

    @staticmethod
    def create(addr):
        """
        <method internal="yes">
        Factory function for InetSubnet and Inet6Subnet instances -- guess
        based on the string whether or not the subnet is IPv6 or IPv4.
        </method>
        """
        if '.' in addr:
            return InetSubnet(addr)
        elif ':' in addr:
            return Inet6Subnet(addr)

class InetSubnet(Subnet):
    """
          <class>
            <summary>Class representing IPv4 address ranges.</summary>
          </class>
    """
    def __init__(self, addr):
        """
               <method>
                 <summary>Constructor to initialize an InetSubnet instance</summary>
                 <description>
                   <para>
                     A class representing Internet (IPv4) addresses, and IP segments.
                     The address is represented in the <parameter>XXX.XXX.XXX.XXX/M</parameter> format, where <parameter>XXX.XXX.XXX.XXX</parameter>
                     is the network address, and <parameter>M</parameter> specifies the number of ones (1) in the netmask.
                   </para>
                 </description>
                 <metainfo>
                   <arguments>
                     <argument maturity="stable">
                       <name>addr</name>
                       <type> <string/> </type>
                       <description>
                         The string representation of an address, optionally with a subnet prefix length.
                       </description>
                     </argument>
                   </arguments>
                 </metainfo>
               </method>
        """
        super(InetSubnet, self).__init__()
        parts = split(addr,'/')
        try:
            self.mask_bits = atoi(parts[1])
        except IndexError:
            self.mask_bits = 32
        self.mask = struct.pack(">I", ((1 << self.mask_bits) - 1) << (32 - self.mask_bits))
        self.ip = inet_aton(parts[0])

    def __str__(self):
        """
        <method internal="yes">
          <summary>Function returning the string representation of this instance.</summary>
        </method>
        """
        return "%s/%u" % (inet_ntoa(self.ip), self.mask_bits)

    def contains(self, other):
        """
        <method internal="yes">
          <summary>Checks if an address or subnet is contained within the subnet</summary>
          <description><parameter>other</parameter> may be an InetSubnet or a SockAddrInet.</description>
        </method>
        """
        if isinstance(other, InetSubnet):
            return (other.mask_bits >= self.mask_bits) and (packed_mask(other.addr_packed(), self.netmask_packed()) == self.addr_packed())
        else:
            try:
                return ((other.ip & self.netmask_int()) == self.addr_int())
            except:
                return False

    def getHostAddr(self, addr):
        """
        <method internal="yes">
          <summary>Masks out the subnet part of <parameter>addr</parameter>.</summary>
        </method>
        """
        return addr.ip & ~self.netmask_int()

    def mapHostAddr(self, addr):
        """
        <method internal="yes">
          <summary>Maps an <parameter>address</parameter> to the subnet.</summary>
          <description><parameter>address</parameter> is a 'host address', containing only the host specific part of the address, without the subnet part. This address will be mapped to this InetSubnet.</description>
        </method>
        """
        return self.addr_int() | (addr & ~self.netmask_int())

    def addr_packed(self):
        """
        <method internal="yes">
          <summary>Function returning the address packed into a string of 4 characters.</summary>
          <description> Uses the same representation as Python's socket.inet_pton. </description>
        </method>
        """
        return self.ip

    def addr_str(self):
        """
        <method internal="yes">
          <summary>Function returning the address as a string.</summary>
          <description> Uses the same family specific representation as Python's socket.inet_ntop. </description>
        </method>
        """
        return inet_ntop(socket.AF_INET, self.ip)

    def addr_int(self):
        """
        <method internal="yes">
          <summary>Function returning the address as a 32-bit integer.</summary>
        </method>
        """
        return struct.unpack("I", self.ip)[0]

    def broadcast(self):
        """
        <method internal="yes"/>
        """
        if self.mask_bits == 0:
            return self.addr_int()

        return htonl(ntohl(self.addr_int()) | (0x7fffffff >> (self.mask_bits - 1)))

    def network(self):
        """
        <method internal="yes"/>
        """
        return self.addr_int() & self.netmask_int()

    def netmask_int(self):
        """
        <method internal="yes"/>
        """
        return struct.unpack("I", self.mask)[0]

    def netmask_bits(self):
        """
        <method internal="yes"/>
        """
        return self.mask_bits

    def netmask_packed(self):
        """
        <method internal="yes">
          <summary>Function returning the netmask packed into a string of 4 characters.</summary>
          <description> Uses the same representation as Python's socket.inet_pton. </description>
        </method>
        """
        return self.mask

    def get_family(self):
        """
        <method internal="yes"/>
        """
        return socket.AF_INET

class Inet6Subnet(Subnet):
    """
          <class>
            <summary>Class representing IPv6 address ranges.</summary>
          </class>
    """
    def __init__(self, addr):
        """
                <method>
                  <summary>Constructor to initialize an InetSubnet instance</summary>
                  <description>
                    <para>
                      A class representing Internet (IPv4) addresses, and IP segments.
                      The address is represented in the <parameter>XXX.XXX.XXX.XXX/M</parameter> format, where <parameter>XXX.XXX.XXX.XXX</parameter>
                      is the network address, and <parameter>M</parameter> specifies the number of ones (1) in the netmask.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>addr</name>
                        <type> <string/> </type>
                        <description>
                          The string representation of an address, optionally with a subnet prefix length.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
        """
        def calculate_mask(bits):
            ret = ""
            while bits > 0:
                n = min(bits, 8)
                v = chr(((1 << n) - 1) << (8 - n))
                ret += v
                bits = bits - n

            return ret.ljust(16, chr(0))

        super(Inet6Subnet, self).__init__()

        parts = split(addr, '/')

        if len(parts) == 2:
            self.mask_bits = atoi(parts[1])
        else:
            self.mask_bits = 128

        self.mask = calculate_mask(self.mask_bits)
        self.ip = packed_mask(inet_pton(socket.AF_INET6, parts[0]), self.mask)

    def __str__(self):
        """
        <method internal="yes">
          <summary>Function returning the string representation of this instance.</summary>
        </method>
        """
        return "%s/%u" % (inet_ntop(socket.AF_INET6, self.ip), self.mask_bits)

    def getHostAddr(self, addr):
        """
        <method internal="yes">
          <summary>Masks out the subnet part of <parameter>addr</parameter>.</summary>
        </method>
        """
        return packed_mask(addr.pack(), packed_1operand(self.netmask_packed(), lambda x: ~x))

    def mapHostAddr(self, addr):
        """
        <method internal="yes">
          <summary>Maps an <parameter>address</parameter> to the subnet.</summary>
          <description><parameter>address</parameter> is a 'host address', containing only the host specific part of the address, without the subnet part. This address will be mapped to this Inet6Subnet.</description>
        </method>
        """
        return struct.unpack("8H", packed_2operand(self.addr_packed(), packed_2operand(addr, packed_1operand(self.netmask_packed(), lambda x: ~x), lambda a, b: a & b), lambda a, b: a | b))

    def addr_int(self):
        """
        <method internal="yes">
          <summary>Function returning the address as a tuple of 8 16-bit integers.</summary>
        </method>
        """
        return struct.unpack("8H", self.ip)

    def addr_str(self):
        """
        <method internal="yes">
          <summary>Function returning the address as a string.</summary>
          <description> Uses the same family specific representation as Python's socket.inet_ntop. </description>
        </method>
        """
        return inet_ntop(socket.AF_INET6, self.ip)

    def addr_packed(self):
        """
        <method internal="yes">
          <summary>Function returning the address packed into a string of 16 characters.</summary>
          <description> Uses the same representation as Python's socket.inet_pton. </description>
        </method>
        """
        return self.ip

    def netmask_packed(self):
        """
        <method internal="yes">
          <summary>Function returning the netmask packed into a string of 16 characters.</summary>
          <description> Uses the same representation as Python's socket.inet_pton. </description>
        </method>
        """
        return self.mask

    def netmask_bits(self):
        """
        <method internal="yes">
          <summary>Return the subnet prefix length in bits.</summary>
          <description>Equals to the number of 1s in the base-2 representation of the netmask.</description>
        </method>
        """
        return self.mask_bits

    def netmask_int(self):
        """
        <method internal="yes">
          <summary>Function returning the netmask as a tuple of 8 16-bit integers.</summary>
        </method>
        """
        return struct.unpack("8H", self.mask)

    def contains(self, other):
        """
        <method internal="yes">
          <summary>Checks if an address or subnet is contained within the subnet</summary>
          <description><parameter>other</parameter> may be an Inet6Subnet or a SockAddrInet6.</description>
        </method>
        """
        if isinstance(other, Inet6Subnet):
            return ((other.mask_bits >= self.mask_bits) & (packed_mask(other.ip, self.mask_bits) == self.ip))
        else:
            try:
                return (packed_mask(other.pack(), self.netmask_packed()) == self.ip)
            except:
                return False

    def get_family(self):
        """
        <method internal="yes"/>
        """
        return socket.AF_INET6

class InetDomain(InetSubnet):
    """
    <class internal="yes"/>
    """
    deprecated_warning = True
    def __init__(self, addr):
        """ <method internal="yes"/> """
        if (InetDomain.deprecated_warning):

            InetDomain.deprecated_warning = False
            log(None, CORE_DEBUG, 3, "Use of InetDomain class is deprecated, InetSubnet should be used instead.")

        super(InetDomain, self).__init__(addr)
