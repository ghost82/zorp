#!/usr/bin/env python

import unittest, os
from Zorp.InstancesConf import InstancesConf

class TestInstancesConf(unittest.TestCase):

    def setUp(self):
        self.instance_name = 'default'
        self.zorp_argv = ''
        self.zorpctl_argv = {
                             "num_of_processes" : 4,
                             "auto_restart" : False,
                             "auto_start" : False,
                             "enable_core" : True
                            }

        zorpctl_argv = "--num-of-processes 4"
        if not self.zorpctl_argv["auto_restart"]:
            zorpctl_argv += " --no-auto-restart"
        if not self.zorpctl_argv["auto_start"]:
            zorpctl_argv += " --no-auto-start"
        if self.zorpctl_argv["enable_core"]:
            zorpctl_argv += " --enable-core"

        self.filename = 'testfile_instances.conf'
        testfile = open(self.filename, 'w')
        testfile.write("%s %s -- %s" % (self.instance_name, self.zorp_argv, zorpctl_argv))
        testfile.close()

    def __del__(self):
        os.remove(self.filename)

    def test_instance_generation(self):
        try:
             instancesconf = InstancesConf()
             instancesconf.instances_conf_path = self.filename
             for instance in instancesconf:
                 self.assertEquals(instance.name, self.instance_name)
                 self.assertEquals(instance.number_of_processes, self.zorpctl_argv["num_of_processes"])
                 self.assertEquals(instance.auto_restart, self.zorpctl_argv["auto_restart"])
                 self.assertEquals(instance.auto_start, self.zorpctl_argv["auto_start"])
                 self.assertEquals(instance.enable_core, self.zorpctl_argv["enable_core"])
        except IOError as e:
             self.assertFalse("Something went wrong while initializing InstancesConf object: %s" % e.message)

if __name__ == '__main__':
    unittest.main()
