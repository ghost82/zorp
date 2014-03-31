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

"""<module internal="yes"/>
"""

import argparse, sys
from Instance import Instance
from zorpctl.ZorpctlConf import ZorpctlConfig

class InstancesConf(object):
    """<class internal="yes"/>
    """
    def __init__(self):
        """<method internal="yes"/>
        """
        self.ZORPCTLCONF = ZorpctlConfig.Instance()
        self.ZORPCTLCONF.parse()
        self.instances_conf_path = self.ZORPCTLCONF['ZORP_SYSCONFDIR'] + "/instances.conf"
        self.instances_conf_file = None

    def __del__(self):
        """<method internal="yes"/>
        """
        if self.instances_conf_file:
            self.instances_conf_file.close()

    def __iter__(self):
        """<method internal="yes"/>
        """
        try:
            self.instances_conf_file = open(self.instances_conf_path, 'r')
        except IOError as e:
            e.message = "%s %s" % (e.strerror, self.instances_conf_path)
            raise e
        return self

    def next(self):
        """<method internal="yes"/>
        """
        line = self._read()
        if line:
            return self._createInstance(line)
        else:
            raise StopIteration

    def _read(self):
        """<method internal="yes"/>
        """
        line = self.instances_conf_file.readline().lstrip()
        while line.startswith('#') or line == '\n':
            line = self.instances_conf_file.readline()
        return line[:-1] if line[-1:] == '\n' else line

    def _parseZorpctlArgs(self, zorpctl_argv):
        """<method internal="yes"/>
        """
        parser = argparse.ArgumentParser()
        parser.add_argument('--num-of-processes', type=int,
                            dest='number_of_processes', default=1
                            )
        try:
            autorestart_default = self.ZORPCTLCONF['AUTO_RESTART']
        except AttributeError:
            autorestart_default = None

        parser.add_argument('--auto-restart', dest='auto_restart',
                            action='store_true', default=autorestart_default
                            )
        parser.add_argument('--no-auto-restart', dest='auto_restart',
                            action='store_false', default=None
                            )
        parser.add_argument('--no-auto-start', dest='auto_start',
                            action='store_false'
                            )
        parser.add_argument('--enable-core', dest='enable_core',
                            action='store_true'
                            )

        return vars(parser.parse_args(zorpctl_argv.split()))

    def _createInstance(self, line):
        """<method internal="yes"/>
        """
        params = {}
        splitted_line = line.split(' -- ')
        zorp_argv = splitted_line[0]

        try:
            arg = self.ZORPCTLCONF['ZORP_APPEND_ARGS']
            if arg:
                zorp_argv += " %s" % arg
        except KeyError:
            pass

        params['name'] = zorp_argv.split()[0]
        params['zorp_argv'] = " ".join(zorp_argv.split()[1:])

        zorpctl_argv = splitted_line[1] if len(splitted_line) > 1 else ""

        try:
            arg = self.ZORPCTLCONF['ZORPCTL_APPEND_ARGS']
            if arg:
                zorpctl_argv += " %s" % arg
        except KeyError:
            pass

        if zorpctl_argv:
            params.update(self._parseZorpctlArgs(zorpctl_argv))

        return Instance(**params)
