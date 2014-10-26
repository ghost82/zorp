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
  <summary>Module defining interface to the Core.</summary>
  <description>
    <para>
      This module imports all public Zorp interfaces and makes it easy to use
      those from the user policy file by simply importing all symbols from
      Zorp.Core.
    </para>
  </description>
</module>
"""

import new
import socket

from Zorp import *
import Zorp
from Zone import Zone, InetZone
from Service import Service, PFService, DenyService, DenyIPv4, DenyIPv6
from SockAddr import SockAddrInet, SockAddrInetHostname, SockAddrInetRange, SockAddrInet6, SockAddrUnix
from Router import TransparentRouter, DirectedRouter, InbandRouter
from Chainer import ConnectChainer, MultiTargetChainer, StateBasedChainer, RoundRobinChainer, FailoverChainer, SideStackChainer
from Subnet import InetSubnet, InetDomain, Inet6Subnet
from Dispatch import Dispatcher, RuleDispatcher
from Rule import PortRange, Rule
from NAT import NATPolicy, ForgeClientSourceNAT, StaticNAT, OneToOneNAT, OneToOneMultiNAT, RandomNAT, HashNAT, GeneralNAT
from NAT import NAT64, NAT46
from Proxy import proxyLog
from Auth import InbandAuthentication, AuthCache, AuthPolicy, AuthenticationPolicy
from Stack import StackingProvider, RemoteStackingBackend
from Matcher import MatcherPolicy, AbstractMatcher, RegexpMatcher, RegexpFileMatcher, CombineMatcher, DNSMatcher, WindowsUpdateMatcher, SmtpInvalidRecipientMatcher
from Resolver import DNSResolver, HashResolver, ResolverPolicy
from Encryption import EncryptionPolicy, TLSEncryption
from Detector import DetectorPolicy, AbstractDetector, HttpDetector, CertDetector, SshDetector
