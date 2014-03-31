#!/usr/bin/env python

import unittest, os
from zorpctl.ProcessAlgorithms import DetailedStatusAlgorithm, ProcessStatus

class TestDetailedStatusAlgorithm(unittest.TestCase):

    def setUp(self):
        self.algorithm = DetailedStatusAlgorithm()
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

        self.test_uptime_filename = 'test_proc_uptime_file'
        test_uptime_file = open(self.test_uptime_filename, 'w')
        test_uptime_file.write('19534.16 66241.85')
        test_uptime_file.close()

        self.test_stat_filename = 'test_proc_stat_file'
        test_stat_file = open(self.test_stat_filename, 'w')
        test_stat_file.write("cpu  677042 37221 447831 6575990 23683 4 1743 0 0 0 \
                              cpu0 198740 7613 139162 1584199 4778 3 729 0 0 0 \
                              cpu1 166518 10310 106719 1651103 6142 0 334 0 0 0 \
                              cpu2 157808 9493 102157 1668239 4922 0 347 0 0 0 \
                              cpu3 153976 9804 99791 1672447 7840 0 332 0 0 0 \
                              intr 97534152 43 11472 0 0 0 0 0 2 1 0 0 0 0 0 0 0 88194 2 304 285 0 0 128079 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 405590 %s\
                              ctxt 194770779 \
                              btime 1367748435 \
                              processes 32903 \
                              procs_running 2 \
                              procs_blocked 0 \
                              softirq 17765007 0 3342173 3318 444082 127922 0 9080 3165220 1741954 8931258')" % (701 * "0 "))
        test_stat_file.close()

        self.algorithm.uptime_filename = self.test_uptime_filename
        self.algorithm.stat_file = open(self.test_stat_filename, 'r')

        self.procinfo = self.proc_info_file_data = {
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
        os.remove(self.test_uptime_filename)
        os.remove(self.test_stat_filename)
        os.remove('test_procinfo_file')

    def test_detailed_status(self):
        import datetime
        status = ProcessStatus("test")
        status.reload_timestamp = 1367664125
        status.policy_file = "/etc/zorp/policy.py"
        expected_result =('policy: file=/etc/zorp/policy.py, loaded=%s' % (datetime.datetime.fromtimestamp(status.reload_timestamp)) +
                 '\ncpu: real=0:0.780000, user=0:0.460000, sys=0:0.320000\n' +
                 'memory: vsz=288628kB, rss=12480kB'
        )
        chop_len = len('started at: yyyy-mm-dd xx:xx:xx.xxxxxx\n')
        #must chop started at part because of now and uptime calculations
        #no better solution yet
        result = self.algorithm.assembleDetails(status, self.procinfo, self.algorithm.getJiffiesPerSec())
        self.assertEquals(result[chop_len:], expected_result)


if __name__ == '__main__':
    unittest.main()
