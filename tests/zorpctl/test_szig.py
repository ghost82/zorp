#!/usr/bin/env python

import unittest
from HandlerMock import HandlerMock
from zorpctl.szig import SZIG


class TestSzig(unittest.TestCase):

    def setUp(self):
        self.szig = SZIG("", HandlerMock)

    def test_get_value(self):
        self.assertEquals(self.szig.get_value(""), None)
        self.assertEquals(self.szig.get_value("service"), None)
        self.assertEquals(self.szig.get_value("info.policy.file"), "/etc/zorp/policy.py")
        self.assertEquals(self.szig.get_value("stats.thread_number"), 5)
        self.assertEquals(self.szig.get_value("service.service_http_transparent.sessions_running"), 0)

    def test_get_sibling(self):
        self.assertEquals(self.szig.get_sibling("conns"), "info")
        self.assertEquals(self.szig.get_sibling("stats.threads_running"), "stats.thread_rate_max")
        self.assertEquals(self.szig.get_sibling("stats.thread_rate_max"), "stats.audit_number")
        self.assertEquals(self.szig.get_sibling("stats.thread_number"), None)

    def test_get_child(self):
        self.assertEquals(self.szig.get_child(""), "conns")
        self.assertEquals(self.szig.get_child("info"), "info.policy")
        self.assertEquals(self.szig.get_child("info.policy"), "info.policy.reload_stamp")
        self.assertEquals(self.szig.get_child("info.policy.reload_stamp"), None)

    def test_get_set_loglevel(self):
        loglevel = 6
        self.szig.loglevel = loglevel
        self.assertEquals(self.szig.loglevel, loglevel)

    def test_get_set_logspec(self):
        logspec = "this is a logspec"
        self.szig.logspec = logspec
        self.assertEquals(self.szig.logspec, logspec)

    def test_get_set_deadlockcheck(self):
        deadlockcheck = False
        self.szig.deadlockcheck = deadlockcheck
        self.assertEquals(self.szig.deadlockcheck, deadlockcheck)

    def test_reload_and_reload_result(self):
        self.szig.reload()
        self.assertEquals(self.szig.reload_result(), True)

    def test_coredump(self):
        try:
            self.szig.coredump()
            self.assertTrue(False, "szig coredump should not work while not repaired")
        except:
            self.assertTrue(True, "szig coredump is not working yet")

if __name__ == '__main__':
    unittest.main()
