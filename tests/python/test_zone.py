# vim: ts=8 sts=4 expandtab autoindent
from Zorp.Core import *
from Zorp.Zorp import quit
from Zorp.Zone import Zone
from Zorp.Subnet import Subnet
from Zorp.Session import MasterSession, StackedSession, ClientInfo
from time import time
from socket import htonl
from Zorp.Exceptions import ZoneException
import unittest
import radix

config.options.kzorp_enabled = FALSE

class FakeProxy(object):
    def __init__(self, name):
        self.name = name

class MyResolverCache():
    def __init__(self, hosts, server=None):
       self.hostnames = { "blog.balabit" : set(['10.10.40.1']),
                          "intraweb.balabit" : set(['10.10.40.1']),
                          "intra.balabit" : set(['10.10.40.1']),
                          "core.balabit" : set(['10.10.0.1', 'fec0:0:0:b000::ffff']) }
       self.addresses = { "10.10.0.1" : "core.balabit", "10.10.40.1": "blog.balabit"}

    def addHost(self, hostname):
        pass

    def removeHost(self, hostname):
        pass

    def shouldUpdate(self):
        return True

    def lookupAddress(self, hostname):
        """<method internal="yes"/>
        """
        if self.addresses.has_key(hostname):
            return self.addresses[hostname]
        else:
            return None

    def lookupHostname(self, hostname):
        """<method internal="yes"/>
        """
        if self.hostnames.has_key(hostname):
            return self.hostnames[hostname]
        else:
            return None

class TestZone(unittest.TestCase):

    def setUp(self):
        Zone.dnscache = MyResolverCache(None)

    def tearDown(self):
        Zone.zone_subnet_tree = radix.Radix()
        Zone.zones = {}

    def doLookup(self, address):
        zone = Zone.lookup(Subnet.create(address))
        if zone is None:
            raise ZoneException(address)
        return zone

    def test_lookup_no_zones_defined(self):
        self.assertRaises(ZoneException, self.doLookup, '1.2.3.4')

    def test_lookup_internet_zone(self):
        inet = InetZone("internet", "0.0.0.0/0")
        self.assertEqual(self.doLookup('0.0.0.0'), inet)
        self.assertEqual(self.doLookup('127.0.0.1'), inet)
        self.assertEqual(self.doLookup('255.255.255.255'), inet)

    def test_lookup_single_zone(self):
        t1 = InetZone("zone1", "10.0.0.0/8")
        self.assertRaises(ZoneException, self.doLookup, '1.2.3.4')
        self.assertRaises(ZoneException, self.doLookup, '9.255.255.255')
        self.assertEqual(self.doLookup('10.0.0.0'), t1)
        self.assertEqual(self.doLookup('10.255.255.255'), t1)
        self.assertRaises(ZoneException, self.doLookup, '11.0.0.0')

    def test_lookup(self):
        t1 = Zone("test1", "192.168.0.0/24")
        t2 = Zone("test2", "192.168.0.32/27")
        t3 = Zone("test3", "192.168.0.0/26")
        t4 = Zone("test4", "192.168.0.64/27")
        t5 = Zone("test5", "192.168.0.96/27")
        t6 = Zone("test6", "192.168.0.0/25")
        t7 = Zone("test7", "192.168.0.0/16")
        t8 = Zone("test8", "192.168.1.1/32")
        t9 = Zone("test9", "192.168.1.2/32")
        t10 = Zone("test10", "192.168.1.3/32")
        t11 = Zone("test11", "192.168.1.4/32")
        t12 = Zone("test12", "192.168.1.5/32")
        t13 = Zone("test13", "192.168.1.6/32")
        t14 = Zone("test14", "192.168.0.184")
        t15 = Zone("test15", "dead:beef:baad:c0ff:ee00:1122:3344:5566/127")


        self.assertEqual(Zone.lookup(SockAddrInet('192.168.0.1', 10)), t3)
        self.assertEqual(self.doLookup('192.168.0.1'), t3)
        self.assertEqual(self.doLookup('192.168.0.33'), t2)
        self.assertEqual(self.doLookup('192.168.0.65'), t4)
        self.assertEqual(self.doLookup('192.168.0.97'), t5)
        self.assertEqual(self.doLookup('192.168.0.129'), t1)
        self.assertEqual(self.doLookup('192.168.1.129'), t7)
        self.assertEqual(self.doLookup('192.168.0.184'), t14)
        self.assertEqual(self.doLookup('dead:beef:baad:c0ff:ee00:1122:3344:5567'), t15)

def init(name, virtual_name, is_master):
    unittest.main(argv=('/',))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
