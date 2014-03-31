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

"""<module internal="yes" />
"""
import argparse

class ZorpProcess(object):
    """<class internal="yes" />
    """
    def __init__(self, zorp_argv):
        """<method internal="yes" />
        """
        parser = argparse.ArgumentParser(prog="Zorp specific instance argument parser")

        parser.add_argument('--log-tags', action='store_true')
        parser.add_argument('--log-spec', type=str)
        parser.add_argument('--threads', type=int)
        parser.add_argument('--stack-size', type=int)
        parser.add_argument('--process-mode', type=str)
        parser.add_argument('--verbose', type=int)
        parser.add_argument('--uid', type=str)
        parser.add_argument('--gid', type=str)
        parser.add_argument('--fd-limit-min', type=int)
        parser.add_argument('-p', '--policy', type=str,
                            dest='policy', default='/etc/zorp/policy.py',
                            )
        self.args = parser.parse_args(zorp_argv)

class Instance(object):
    """<class internal="yes" />
    """
    def __init__(self, **kwargs):
        """<method internal="yes" />
        """
        self.name = kwargs.pop('name')
        self.process_name = kwargs.pop('process_name', None)
        self.process_num = kwargs.pop('process_num', None)

        self.auto_restart = kwargs.pop('auto_restart', True)
        self.auto_start = kwargs.pop('auto_start', True)
        self.number_of_processes = kwargs.pop('number_of_processes', 1)
        self.enable_core = kwargs.pop('enable_core', False)

        self.zorp_argument_list = kwargs.pop('zorp_argv', "").split()
        self.zorp_process = ZorpProcess(zorp_argv=self.zorp_argument_list)

    @staticmethod
    def splitInstanceName(instance_name):
        """<method internal="yes" />
        """
        #"""
        #Splits the instance name from the process number.
        #example: 'default#0' -> ('default', 0)
        #         'default'   -> ('default', None)
        #"""
        splitted = instance_name.split('#')
        return splitted[0], int(splitted[1]) if len(splitted) > 1 else None

    @property
    def process_name(self):
        """<method internal="yes" />
        """
        self._process_name = self.name + '#' + str(self.process_num)
        return self._process_name

    @process_name.setter
    def process_name(self, value):
        """<method internal="yes" />
        """
        self._process_name = value
