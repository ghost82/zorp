#!/usr/bin/env python

import unittest
from HandlerMock import HandlerMock
from zorpctl.szig import SZIG
from zorpctl.ProcessAlgorithms import LogLevelAlgorithm

class TestLogLevelAlgorithm(unittest.TestCase):

    def setUp(self):
        handler_mock = HandlerMock
        szig = SZIG("", handler_mock)
        self.algorithm = LogLevelAlgorithm()
        self.algorithm.szig = szig

    def test_get_loglevel(self):
        self.assertTrue(self.algorithm.getloglevel())

    def test_set_loglevel(self):
        self.algorithm.modifyloglevel(6)
        self.assertEquals(self.algorithm.getloglevel().value, 6)


if __name__ == '__main__':
    unittest.main()
