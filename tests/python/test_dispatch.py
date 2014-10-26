# vim: ts=8 sts=4 expandtab autoindent
from Zorp.Core import *
from Zorp.Plug import *
from Zorp.Zorp import quit

import unittest

config.options.kzorp_enabled = FALSE

class TestDispatcher(unittest.TestCase):

    def setUp(self):
        Service('test', PlugProxy)

    def tearDown(self):
        import Zorp.Globals
        Zorp.Globals.services.clear()

    def test_keyword_args(self):
        """Test keyword argument that is processed by the C code."""
        Dispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)
        Dispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)
        Dispatcher(DBIfaceGroup(100, 1999, protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)

        ZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)
        ZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)
        ZoneDispatcher(DBIfaceGroup(100, 1999, protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)

    def test_constructors(self):
        """No keyword arguments."""
        Dispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), 'test')
        Dispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), 'test')

        ZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {'all': 'test'})
        ZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {'all': 'test'})

def zorp():
    unittest.main(argv=('/'))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
