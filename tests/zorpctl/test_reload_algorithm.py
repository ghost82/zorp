#!/usr/bin/env python

import unittest
from HandlerMock import HandlerMock
from zorpctl.szig import SZIG
from zorpctl.ProcessAlgorithms import ReloadAlgorithm

class TestReloadAlgorithm(unittest.TestCase):

    def test_reload(self):
        handler_mock = HandlerMock
        szig = SZIG("", handler_mock)
        algorithm = ReloadAlgorithm()
        algorithm.szig = szig
        self.assertTrue(algorithm.reload())

if __name__ == '__main__':
    unittest.main()
