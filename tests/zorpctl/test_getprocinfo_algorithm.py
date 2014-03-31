#!/usr/bin/env python

import unittest, os
from zorpctl.ProcessAlgorithms import GetProcInfoAlgorithm

class TestGetProcInfoAlgorithm(unittest.TestCase):

    def setUp(self):
        self.algorithm = GetProcInfoAlgorithm()
        proc_info_file_values = ['1572', '(zorp)', 'S', '1571', '1572',
                                 '1572', '0', '-1', '4202816', '3288',
                                 '0', '22', '0', '46', '32', '0', '0',
                                 '20', '0', '4', '0', '2466', '295555072',
                                 '3120', '18446744073709551615', '1',
                                 '1', '0', '0', '0', '0', '0',
                                 '16777216', '89659',
                                 '18446744073709551615', '0', '0', '17', '3']

        self.test_procinfo_file = open('test_procinfo_file', 'w')
        self.test_procinfo_file.write(proc_info_file_values[0])
        for value in proc_info_file_values[1:]:
            self.test_procinfo_file.write(" " + value)
        self.test_procinfo_file.close()

        self.algorithm.procinfo_file = open('test_procinfo_file', 'r')
        self.proc_info_file_data = {
            "majflt": "22",
            "cutime": "0",
            "endcode": "1",
            "vsize": "295555072",
            "wchan": "18446744073709551615",
            "tpgid": "-1",
            "sigcatch": "89659",
            "cstime": "0",
            "pid": "1572",
            "_dummyzero": "4",
            "cminflt": "0",
            "session": "1572",
            "comm": "(zorp)",
            "stime": "32",
            "startstack": "0",
            "sigignore": "16777216",
            "startcode": "1",
            "processor": "3",
            "tty_nr": "0",
            "cmajflt": "0",
            "rss": "3120",
            "priority": "20",
            "ppid": "1571",
            "minflt": "3288",
            "itrealvalue": "0",
            "kstkesp": "0",
            "rlim": "18446744073709551615",
            "nswap": "0",
            "utime": "46",
            "exit_signal": "17",
            "pgrp": "1572",
            "state": "S",
            "flags": "4202816",
            "starttime": "2466",
            "kstkeip": "0",
            "blocked": "0",
            "cnswap": "0",
            "signal": "0",
            "nice": "0"
        }

    def __del__(self):
        pass
        os.remove('test_procinfo_file')

    def test_get_proc_info(self):
        self.maxDiff = None
        self.assertEquals(self.algorithm.getProcInfo(), self.proc_info_file_data)


if __name__ == '__main__':
    unittest.main()
