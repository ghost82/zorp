#!/usr/bin/env python

import unittest
from HandlerMock import HandlerMock
from zorpctl.szig import SZIG
from zorpctl.ProcessAlgorithms import DeadlockCheckAlgorithm

class TestDeadLockCheckAlgorithm(unittest.TestCase):

    def setUp(self):
        handler_mock = HandlerMock
        szig = SZIG("", handler_mock)
        self.algorithm = DeadlockCheckAlgorithm()
        self.algorithm.szig = szig

    def test_get_deadlock_check(self):
        self.assertTrue(self.algorithm.getDeadlockcheck())

    def test_set_deadlock_check(self):
        self.assertTrue(self.algorithm.setDeadlockcheck(True))
        self.assertEquals(str(self.algorithm.getDeadlockcheck()), "deadlockcheck=True")
        self.assertTrue(self.algorithm.setDeadlockcheck(False))
        self.assertEquals(str(self.algorithm.getDeadlockcheck()), "deadlockcheck=False")

if __name__ == '__main__':
    unittest.main()
