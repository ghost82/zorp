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

from Zorp.InstancesConf import InstancesConf
from zorpctl.ProcessAlgorithms import (StartAlgorithm, StopAlgorithm,
                                LogLevelAlgorithm , DeadlockCheckAlgorithm,
                                GUIStatusAlgorithm, StatusAlgorithm,
                                ReloadAlgorithm, SzigWalkAlgorithm,
                                DetailedStatusAlgorithm, AuthorizeAlgorithm)
from zorpctl.CommandResults import CommandResultFailure

class ZorpHandler(object):

    @staticmethod
    def start():
        return ZorpHandler.callAlgorithmToAllInstances(StartAlgorithm())

    @staticmethod
    def force_start():
        algorithm = StartAlgorithm()
        algorithm.force = True
        return ZorpHandler.callAlgorithmToAllInstances(algorithm)

    @staticmethod
    def stop():
        return ZorpHandler.callAlgorithmToAllInstances(StopAlgorithm())

    @staticmethod
    def force_stop():
        algorithm = StopAlgorithm()
        algorithm.force = True
        return ZorpHandler.callAlgorithmToAllInstances(algorithm)

    @staticmethod
    def reload():
        return ZorpHandler.callAlgorithmToAllInstances(ReloadAlgorithm())

    @staticmethod
    def status():
        return ZorpHandler.callAlgorithmToAllInstances(StatusAlgorithm())

    @staticmethod
    def gui_status():
        return ZorpHandler.callAlgorithmToAllInstances(GUIStatusAlgorithm())

    @staticmethod
    def detailedStatus():
        return ZorpHandler.callAlgorithmToAllInstances(DetailedStatusAlgorithm())

    @staticmethod
    def authorize(behaviour, session_id, description):
        return ZorpHandler.callAlgorithmToAllInstances(AuthorizeAlgorithm(behaviour, session_id, description))

    @staticmethod
    def inclog():
        return ZorpHandler.callAlgorithmToAllInstances(LogLevelAlgorithm(LogLevelAlgorithm.INCREMENT))

    @staticmethod
    def declog():
        return ZorpHandler.callAlgorithmToAllInstances(LogLevelAlgorithm(LogLevelAlgorithm.DECREASE))

    @staticmethod
    def getlog():
        return ZorpHandler.callAlgorithmToAllInstances(LogLevelAlgorithm())

    @staticmethod
    def deadlockcheck(value=None):
        return ZorpHandler.callAlgorithmToAllInstances(DeadlockCheckAlgorithm(value))

    @staticmethod
    def szig_walk(root):
        return ZorpHandler.callAlgorithmToAllInstances(SzigWalkAlgorithm(root))

    @staticmethod
    def callAlgorithmToAllInstances(algorithm):
        result = []
        try:
            for instance in InstancesConf():
                result += InstanceHandler.executeAlgorithmOnInstanceProcesses(instance, algorithm)
            return result
        except BaseException as e:
            return CommandResultFailure(e.message)

class InstanceHandler(object):

    @staticmethod
    def executeAlgorithmOnInstanceProcesses(instance, algorithm):
        results = []
        for i in range(0, instance.number_of_processes):
            instance.process_num = i
            algorithm.setInstance(instance)
            result = algorithm.run()
            result.msg = "%s: %s" % (instance.process_name, result.msg)
            results.append(result)

        return results

    @staticmethod
    def searchInstance(instance_name):
        try:
            for instance in InstancesConf():
                if instance.name == instance_name:
                    return instance
            return CommandResultFailure("instance %s not found!" % instance_name)
        except IOError as e:
            return CommandResultFailure(e.message)
