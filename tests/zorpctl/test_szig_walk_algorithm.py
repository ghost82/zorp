#!/usr/bin/env python

import unittest
from HandlerMock import HandlerMock
from zorpctl.szig import SZIG
from zorpctl.ProcessAlgorithms import SzigWalkAlgorithm

class TestSzigWalkAlgorithm(unittest.TestCase):

    def test_szig_walk(self):
        handler_mock = HandlerMock
        szig = SZIG("", handler_mock)
        algorithm = SzigWalkAlgorithm()
        algorithm.szig = szig
        self.assertEquals(algorithm.walk(""), handler_mock().data)
        self.assertEquals(algorithm.walk("stats"), handler_mock().data["stats"])

if __name__ == '__main__':
    unittest.main()
