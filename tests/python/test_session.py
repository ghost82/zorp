# vim: ts=8 sts=4 expandtab autoindent
from Zorp.Core import *
from Zorp.Zorp import quit
from Zorp.Proxy import Proxy
from Zorp.Http import HttpProxy
from Zorp.Session import MasterSession, StackedSession, ClientInfo
import Zorp.Globals
import Zorp.Resolver
import socket
import unittest

config.options.kzorp_enabled = FALSE

InetZone("internet", "0.0.0.0/0")


class DummyResolver(Zorp.Resolver.AbstractResolver):

    def resolve(self, host, port):
        return SockAddrInet("127.0.0.1", port)

ResolverPolicy("test_resolver", DummyResolver())


class TestSessionBase(unittest.TestCase):

    def setUp(self):
        self.service = Service("testservice", HttpProxy, resolver_policy="test_resolver")
        self.address = SockAddrInet("127.0.0.1", 80)
        client_info = ClientInfo(client_stream=None, client_local=None, client_listen=None, client_address=self.address)
        self.mastersession = MasterSession(ZD_PROTO_TCP, self.service, client_info, instance_id=1)
        self.session = StackedSession(self.mastersession)

    def tearDown(self):
        del self.session
        del self.mastersession
        del self.service
        del self.address
        Zorp.Globals.services.clear()


class TestTopLevelProxySession(TestSessionBase):

    def test_construction(self):
        self.assertTrue(isinstance(self.mastersession, MasterSession))
        self.assertTrue(isinstance(self.session, StackedSession))

    def test_construction_initializes_protocol(self):
        master = MasterSession(ZD_PROTO_TCP, self.service, ClientInfo(None,None,None,None), 1)
        self.assertEqual(master.protocol, ZD_PROTO_TCP)
        self.assertEqual(master.protocol_name, "TCP")

    def test_client_zone_lookup(self):
        self.assertEqual(self.session.client_address, self.address)
        self.assertEqual(self.session.client_zone.name, "internet")

    def test_setServerAddress(self):
        self.session.setServerAddress(self.address)
        self.assertEqual(self.session.server_address, self.address)
        self.assertEqual(self.session.server_zone.name, "internet")

    def test_setTargetAddress(self):
        self.session.setTargetAddress(self.address)
        self.assertEqual(self.session.target_address, (self.address, ))
        self.assertEqual(len(self.session.target_zone), 1)
        self.assertEqual(self.session.target_zone[0].name, "internet")

    def test_setProxy(self):
        """Check the final session ID constructed when an associated proxy was created and the proxy is properly set in the session"""
        (client_stream, server_stream) = streamPair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.session.client_stream = client_stream
        proxy = HttpProxy(self.session)
        self.assertEqual(self.session.session_id, "svc/" + self.service.name + ":1" + "/http")
        self.assertEqual(self.session.proxy, proxy)
        self.assertEqual(self.session.http, proxy)
        self.assertEqual(proxy.session, self.session)


class TestStackedProxySession(TestSessionBase):

    def test_stacking_inherit_target_address(self):
        """Stacked proxies should inherit the target address of their parent"""
        self.session.setTargetAddress(self.address)
        ss = StackedSession(self.session)
        self.assertEqual(ss.target_address, (self.address, ))

    def test_stacking_override_target_address(self):
        """Stacked proxies can override their target own address without affecting their parent session"""
        self.session.setTargetAddress(self.address)
        ss = StackedSession(self.session)
        address2 = SockAddrInet("10.0.0.1", 90)
        ss.setTargetAddress(address2)
        self.assertEqual(ss.target_address, (address2, ))
        self.assertEqual(self.session.target_address, (self.address, ))


def init(name, virtual_name, is_master):
    unittest.main(argv=('/',))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
