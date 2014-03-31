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

"""<module internal="yes" />
"""

from Subnet import Subnet, InetSubnet, Inet6Subnet

class BuiltinProxy():
  """<class internal="yes"/>
  """
  def __init__():
    pass

class BaseZone(object):
    """
    <class internal="yes"/>
    """
    zones = {}

    def __init__(self, name, addrs=(), hostnames=(), admin_parent=None):
        """
        <method internal="yes"/>
        """
        self.name = name
        self.admin_children = []

        if admin_parent is not None:
            self.admin_parent = self.zones[admin_parent]
        else:
            self.admin_parent = None

        self.zones[name] = self

        if isinstance(addrs, basestring):
            addrs = (addrs, )

        if hostnames == "":
            hostnames = None

        if isinstance(hostnames, basestring):
            hostnames = (hostnames, )

        self.hostnames = hostnames
        self.subnets = map(Subnet.create, addrs)

    def __str__(self):
        """
        <method internal="yes"/>
        """
        return "Zone(%s)" % self.name

    def getName(self):
        """
        <method internal="yes"/>
        """
        return self.name

    def getDepth(self):
        """
        <method internal="yes"/>
        """
        if self.admin_parent:
            return 1 + self.admin_parent.getDepth()
        else:
            return 0
