#!/usr/bin/env python

import os
import sys
import glob

import socket
socket.IP_TRANSPARENT = 19
socket.SO_KZORP_RESULT = 1678333

import test_kzorp
import kzorp.messages
import kzorp.communication


class KZorpSockoptTest(test_kzorp.KZorpComm):
    def __init__(self, *args):
        super(KZorpSockoptTest, self).__init__(*args)
        self.handle = kzorp.communication.Handle()

    __setup_messages = \
        (
          kzorp.messages.KZorpAddProxyServiceMessage("service"),
          kzorp.messages.KZorpAddZoneMessage("internet"),
          kzorp.messages.KZorpAddDispatcherMessage("dispatcher", 1),
          kzorp.messages.KZorpAddRuleMessage("dispatcher", 1, "service", {}),
        )

    def setUp(self):
        self.start_transaction()
        self.flush_all()
        [self.handle.talk(m) for m in self.__setup_messages]
        self.end_transaction()

    def tearDown(self):
        self.flush_all()

if __name__ == "__main__":

    if os.getenv("USER") != "root":
        print "ERROR: You need to be root to run the unit test"
        sys.exit(1)

    if glob.glob('/var/run/zorp/*.pid'):
        print "ERROR: pidfile(s) exist in /var/run/zorp directory. Zorp is running?"
        print "       You should stop Zorp and/or delete pid files from /var/run/zorp"
        print "       in order to run this test."
        sys.exit(1)

    test = KZorpSockoptTest()
    test.setUp()

    print "*" * 70
    print "KZorp configuration set up, start get_kzorp_result, then connect to"
    print "any TCP port of the test host with netcat. get_kzorp_result should"
    print "then print the following following:\n"
    print "Cookie: 123456789, client zone: 'internet', server zone: 'internet',"
    print "dispatcher: 'dispatcher', service: 'service'\n"
    print "Then press Enter to flush the KZorp configuration"
    print "*" * 70

    sys.stdin.readline()
    test.tearDown()
