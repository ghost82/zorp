# vim: ts=8 sts=4 expandtab autoindent
from Zorp.Core import *
from Zorp.Plug import *
from Zorp.Session import MasterSession, ClientInfo
from Zorp.NAT import getNATPolicy, NAT_SNAT, NAT_DNAT
import unittest

config.options.kzorp_enabled = FALSE

class TestGeneralNAT(unittest.TestCase):

    def tearDown(self):
        """Clean up global state."""
        del self.session

        import Zorp.Globals
        Zorp.Globals.services.clear()
        Zorp.Globals.nat_policies.clear()

    def setUp(self):
        """Construct a fake session object."""
        self.session = MasterSession(0, Service("service1", PlugProxy), ClientInfo(None, None, None, None), instance_id=1)

    def performTranslation(self, nat_policy_name, addresses, nat_type):
        nat = getNATPolicy(nat_policy_name)
        return nat.performTranslation(self.session, addresses, nat_type)

    def checkDNAT(self, nat_policy_name, addresses, expected_result):
        return self.assertEqual(str(self.performTranslation(nat_policy_name, addresses, NAT_DNAT)), str(expected_result))

    def test_simple_dnat(self):
        """Test if DNAT works at all."""
        NATPolicy('test', GeneralNAT(
                        [(InetDomain('0.0.0.0/32'), InetDomain('10.0.0.0/8'), InetDomain('20.0.0.0/8')),
                        ]))
        self.checkDNAT("test", (None, SockAddrInet('9.255.255.255', 8888)), None)
        self.checkDNAT("test", (None, SockAddrInet('10.0.0.0', 8888)), SockAddrInet('20.0.0.0', 8888))
        self.checkDNAT("test", (None, SockAddrInet('10.0.0.1', 8888)), SockAddrInet('20.0.0.1', 8888))
        self.checkDNAT("test", (None, SockAddrInet('10.255.255.255', 8888)), SockAddrInet('20.255.255.255', 8888))
        self.checkDNAT("test", (None, SockAddrInet('11.0.0.0', 8888)), None)

    def test_ipv6_dnat(self):
        """Test if DNAT works for IPv6 addresses"""
        NATPolicy('test', GeneralNAT(
                        [(Inet6Subnet('::/128'), Inet6Subnet('1200::/8'), Inet6Subnet('2300::/8'))
                        ]))
        self.checkDNAT("test", (None, SockAddrInet6('1234::', 8888)), SockAddrInet6('2334::', 8888))
        self.checkDNAT("test", (None, SockAddrInet6('1300::', 8888)), None)

    def test_multiple_ranges_dnat(self):
        """Test if DNAT works with multiple ranges."""
        NATPolicy('test', GeneralNAT(
                        [(InetDomain('0.0.0.0/32'), InetDomain('10.0.0.0/8'), InetDomain('20.0.0.0/8')),
                         (InetDomain('0.0.0.0/32'), InetDomain('11.0.0.0/8'), InetDomain('192.168.0.0/24')),
                        ]))

        self.checkDNAT("test", (None, SockAddrInet('10.0.0.1', 8888)), SockAddrInet('20.0.0.1', 8888))
        self.checkDNAT("test", (None, SockAddrInet('11.0.0.1', 8888)), SockAddrInet('192.168.0.1', 8888))

    def test_overlapping_ranges_ordering(self):
        """Test what happens if there were overlapping ranges specified."""
        NATPolicy('large_first', GeneralNAT(
                        [(InetDomain('0.0.0.0/32'), InetDomain('10.0.0.0/8'), InetDomain('20.0.0.0/8')),
                         (InetDomain('0.0.0.0/32'), InetDomain('10.128.0.0/9'), InetDomain('21.0.0.0/9')),
                        ]))
        self.checkDNAT("large_first", (None, SockAddrInet('10.127.255.255', 8888)), SockAddrInet('20.127.255.255', 8888))
        self.checkDNAT("large_first", (None, SockAddrInet('10.128.0.0', 8888)), SockAddrInet('20.128.0.0', 8888))

        NATPolicy('small_first', GeneralNAT(
                        [(InetDomain('0.0.0.0/32'), InetDomain('10.128.0.0/9'), InetDomain('21.0.0.0/9')),
                         (InetDomain('0.0.0.0/32'), InetDomain('10.0.0.0/8'), InetDomain('20.0.0.0/8')),
                        ]))
        self.checkDNAT("small_first", (None, SockAddrInet('10.127.255.255', 8888)), SockAddrInet('20.127.255.255', 8888))
        self.checkDNAT("small_first", (None, SockAddrInet('10.128.0.0', 8888)), SockAddrInet('21.0.0.0', 8888))

    def test_destination_out_of_range(self):
        """Test if the result is properly capped."""
        NATPolicy('test', GeneralNAT(
                        [(InetDomain('0.0.0.0/32'), InetDomain('11.0.0.0/8'), InetDomain('192.168.0.0/24')),
                        ]))

        self.checkDNAT("test", (None, SockAddrInet('11.255.255.255', 8888)), SockAddrInet('192.168.0.255', 8888))


class TestNAT6446(unittest.TestCase):

    def tearDown(self):
        """Clean up global state."""
        del self.session

        import Zorp.Globals
        Zorp.Globals.services.clear()
        Zorp.Globals.nat_policies.clear()

    def setUp(self):
        """Construct a fake session object."""
        self.session = MasterSession(0, Service("service1", PlugProxy), ClientInfo(None, None, None, None), instance_id=1)

    def performTranslation(self, nat_policy_name, addresses, nat_type):
        nat = getNATPolicy(nat_policy_name)
        return nat.performTranslation(self.session, addresses, nat_type)

    def checkDNAT(self, nat_policy_name, addresses, expected_result):
        return self.assertEqual(str(self.performTranslation(nat_policy_name, addresses, NAT_DNAT)), str(expected_result))

    def test_nat64(self):
        """Test if DNAT64 works."""
        NATPolicy('test32', NAT64(prefix_mask=32))
        NATPolicy('test40', NAT64(prefix_mask=40))
        NATPolicy('test48', NAT64(prefix_mask=48))
        NATPolicy('test56', NAT64(prefix_mask=56))
        NATPolicy('test64', NAT64(prefix_mask=64))
        NATPolicy('test96', NAT64(prefix_mask=96))
        self.checkDNAT("test32", (None, SockAddrInet6('2001:db8:c000:221::', 8888)), SockAddrInet('192.0.2.33', 8888))
        self.checkDNAT("test40", (None, SockAddrInet6('2001:db8:1c0:2:21::', 8888)), SockAddrInet('192.0.2.33', 8888))
        self.checkDNAT("test48", (None, SockAddrInet6('2001:db8:122:c000:2:2100::', 8888)), SockAddrInet('192.0.2.33', 8888))
        self.checkDNAT("test56", (None, SockAddrInet6('2001:db8:122:3c0:0:221::', 8888)), SockAddrInet('192.0.2.33', 8888))
        self.checkDNAT("test64", (None, SockAddrInet6('2001:db8:122:344:c0:2:2100::', 8888)), SockAddrInet('192.0.2.33', 8888))
        self.checkDNAT("test96", (None, SockAddrInet6('2001:db8:122:344::192.0.2.33', 8888)), SockAddrInet('192.0.2.33', 8888))

    def test_nat46(self):
        """Test if DNAT64 works."""
        NATPolicy('test32', NAT46(prefix="2001:db8:122:344::", prefix_mask=32))
        NATPolicy('test40', NAT46(prefix="2001:db8:122:344::", prefix_mask=40))
        NATPolicy('test48', NAT46(prefix="2001:db8:122:344::", prefix_mask=48))
        NATPolicy('test56', NAT46(prefix="2001:db8:122:344::", prefix_mask=56))
        NATPolicy('test64', NAT46(prefix="2001:db8:122:344::", prefix_mask=64))
        NATPolicy('test96', NAT46(prefix="2001:db8:122:344::", prefix_mask=96))
        self.checkDNAT("test32", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:c000:221::', 8888))
        self.checkDNAT("test40", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:1c0:2:21::', 8888))
        self.checkDNAT("test48", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:c000:2:2100::', 8888))
        self.checkDNAT("test56", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:3c0:0:221::', 8888))
        self.checkDNAT("test64", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:344:c0:2:2100::', 8888))
        self.checkDNAT("test96", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:344::192.0.2.33', 8888))


def zorp():
    unittest.main(argv=('/',))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
