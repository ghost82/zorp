#!/usr/bin/env python

import unittest
from Zorp.Instance import Instance
from zorpctl.ProcessAlgorithms import StartAlgorithm

class TestStartAlgorithm(unittest.TestCase):
    def setUp(self):
        self.params = {
                       "name" : "default",
                       "zorp_argv" : "-p policy.py",
                       "auto_restart" : True,
                       "number_of_processes" : 4,
                       "enable_core" : True
                      }

    def test_assemble_start_command(self):
        algorithm = StartAlgorithm()
        algorithm.setInstance(Instance(**self.params))
        algorithm.instance.process_num = 0
        self.assertEquals(" ".join(algorithm.assembleStartCommand()[1:]),
                          '--as default -p policy.py --master default#0 --enable-core --process-mode background')
        algorithm.instance.process_num = 1
        self.assertEquals(" ".join(algorithm.assembleStartCommand()[1:]),
                          '--as default -p policy.py --slave default#1 --enable-core --process-mode background')

    def test_invalid_instance_for_start(self):
        instance = Instance(**self.params)
        wrong_number = instance.number_of_processes
        algorithm = StartAlgorithm()
        algorithm.setInstance(instance)
        algorithm.instance.process_num = wrong_number
        self.assertEquals(str(algorithm.isValidInstanceForStart()),
                          "number %d must be between [0..%d)" %
                          (wrong_number, instance.number_of_processes))

        algorithm.instance.process_num = 0
        algorithm.instance.auto_start = False
        self.assertEquals(str(algorithm.isValidInstanceForStart()),
                          "not started, because no-auto-start is set")

        algorithm.force = True
        self.assertTrue(algorithm.isValidInstanceForStart())

if __name__ == '__main__':
    unittest.main()
