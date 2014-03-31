############################################################################
##
## Copyright (c) 2000-2014 BalaBit IT Ltd, Budapest, Hungary
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
##
############################################################################

import argparse

from Zorp.InstancesConf import InstancesConf

from zorpctl.szig import SZIG, SZIGError
from zorpctl.ProcessAlgorithms import ProcessAlgorithm, GetProcInfoAlgorithm
from zorpctl.CommandResults import CommandResultFailure, CommandResultSuccess

class RunningInstances(object):

    def __init__(self):
        self.instancesconf = InstancesConf()

    def __iter__(self):
        return self

    def next(self):
        instance = self.instancesconf.next()
        instance.process_num = 0
        algorithm = ProcessAlgorithm()
        algorithm.setInstance(instance)
        if algorithm.isRunning(instance.process_name):
            return instance
        else:
            return self.next()

class GetAlgorithm(ProcessAlgorithm):

    def __init__(self):
        super(GetAlgorithm, self).__init__()

    def get(self):
        raise NotImplementedError()

    def execute(self):
        try:
            self.szig = SZIG(self.instance.process_name)
        except IOError as e:
            return CommandResultFailure(e.message)
        return CommandResultSuccess("", self.get())

class GetSessionsRunningAlgorithm(GetAlgorithm):

    def get(self):
        result = self.szig.get_value('stats.sessions_running')
        return int(result) if result else 0

class GetThreadRateAlgorithm(GetAlgorithm):

    def get(self):
        """
        Minus one value shows some error happened.
        """
        result = {}
        _max = self.szig.get_value('stats.thread_rate_max')
        result["max"] = int(_max) if _max != None else -1
        _avg15 = self.szig.get_value('stats.thread_rate_avg15')
        result["avg15"] = int(_avg15) if _avg15 != None else -1
        _avg5 = self.szig.get_value('stats.thread_rate_avg5')
        result["avg5"] = int(_avg5) if _avg5 != None else -1
        _avg1 = self.szig.get_value('stats.thread_rate_avg1')
        result["avg1"] = int(_avg1) if _avg1 != None else -1

        return result

class GetThreadsRunningAlgorithm(GetAlgorithm):

    def get(self):
        result = self.szig.get_value('stats.threads_running')
        return int(result) if result else 0

class GetMemoryRSSAlgorithm(ProcessAlgorithm):

    def __init__(self):
        super(GetMemoryRSSAlgorithm, self).__init__()

    def get(self):
        algorithm = GetProcInfoAlgorithm()
        algorithm.setInstance(self.instance)
        proc_info = algorithm.run()
        if not proc_info:
            return proc_info
        return CommandResultSuccess("", int(proc_info["rss"])*4)

    def execute(self):
        return self.get()

class GetMemoryVSZAlgorithm(ProcessAlgorithm):

    def __init__(self):
        super(GetMemoryVSZAlgorithm, self).__init__()

    def get(self):
        algorithm = GetProcInfoAlgorithm()
        algorithm.setInstance(self.instance)
        proc_info = algorithm.run()
        if not proc_info:
            return proc_info
        return CommandResultSuccess("", int(proc_info["vsize"])/1024)

    def execute(self):
        return self.get()

class GetServicesAlgorithm(ProcessAlgorithm):

    def __init__(self):
        super(GetServicesAlgorithm, self).__init__()

    def services(self):
        services = []
        service = self.szig.get_child("service")
        while service:
            services.append(service[len("service."):])
            service = self.szig.get_sibling(service)
        return CommandResultSuccess("", services)

    def execute(self):
        try:
            self.szig = SZIG(self.instance.process_name)
        except IOError as e:
            return CommandResultFailure(e.message)
        try:
            return self.services()
        except SZIGError as e:
            return CommandResultFailure("error while communicating through szig: %s" % e.msg)

class GetServiceRateAlgorithm(GetAlgorithm):

    def __init__(self):
        super(GetServiceRateAlgorithm, self).__init__()

    def getServiceRate(self, services):
        avg = {}
        for service in services.value:
            avg1 = int(self.szig.get_value("service." + service + ".rate_avg1"))
            avg5 = int(self.szig.get_value("service." + service + ".rate_avg5"))
            avg15 = int(self.szig.get_value("service." + service + ".rate_avg15"))
            avg[service] = {"avg1" : avg1, "avg5" : avg5, "avg15" : avg15}
        return avg

    def get(self):
        algorithm = GetServicesAlgorithm()
        algorithm.setInstance(self.instance)
        services = algorithm.run()
        if not services:
            return services

        return self.getServiceRate(services)

class ParseZorpArgumentsAlgorithm(ProcessAlgorithm):

    def __init__(self):
        super(ParseZorpArgumentsAlgorithm, self).__init__()

        self.parser = argparse.ArgumentParser(
                                        prog="Zorp specific instance argument parser")
        self.parser.add_argument('--threads', type=int)
        self.parser.add_argument('--stack-size', type=int)
        self.parser.add_argument('--process-mode', type=str)
        self.parser.add_argument('--verbose', type=int)
        self.parser.add_argument('--uid', type=str)
        self.parser.add_argument('--gid', type=str)
        self.parser.add_argument('--fd-limit-min', type=int)
        self.parser.add_argument('--policy', type=str)

    def execute(self):
        return vars(self.parser.parse_args(self.instance.zorp_argument_list))

class GetThreadLimitAlgorithm(ProcessAlgorithm):

    def __init__(self):
        super(GetThreadLimitAlgorithm, self).__init__()

        self.parse_algorithm = ParseZorpArgumentsAlgorithm()

    def errorHandling(self):
        self.parse_algorithm.run()

    def execute(self):
        self.parse_algorithm.setInstance(self.instance)
        self.errorHandling()
        zorp_arguments = self.parse_algorithm.run()
        return CommandResultSuccess("", zorp_arguments['threads'])
