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

import ConfigParser

import Zorp.Config

class Singleton(object):
    """
    A non-thread-safe helper class to ease implementing singletons.
    This should be used as a decorator -- not a metaclass -- to the
    class that should be a singleton.

    The decorated class can define one `__init__` function that
    takes only the `self` argument. Other than that, there are
    no restrictions that apply to the decorated class.

    To get the singleton instance, use the `Instance` method. Trying
    to use `__call__` will result in a `TypeError` being raised.

    Limitations: The decorated class cannot be inherited from.

    """

    def __init__(self, decorated):
        self._decorated = decorated

    def Instance(self):
        """
        Returns the singleton instance. Upon its first call, it creates a
        new instance of the decorated class and calls its `__init__` method.
        On all subsequent calls, the already created instance is returned.

        """
        try:
            return self._instance
        except AttributeError:
            self._instance = self._decorated()
            return self._instance

    def __call__(self):
        raise TypeError('Singletons must be accessed through `Instance()`.')

    def __instancecheck__(self, inst):
        return isinstance(inst, self._decorated)


@Singleton
class ZorpctlConfig(object):

    def __init__(self):
        defaults = {
# specifies whether --auto-restart is default
'AUTO_RESTART' : 1,

# wait a starting process to report back for this amount of time, assume the
# startup failed if it exceeds this time.
'START_WAIT_TIMEOUT' : 10,

# The interval (in seconds) to check a stopping Zorp instance at, second
# fractions are allowed.
'STOP_CHECK_DELAY' : 0.1,

# The number of seconds to wait for a stopping Zorp instance
'STOP_CHECK_TIMEOUT' : 5,

# automatically append this string to each Zorp command line, this was
# renamed in Zorp 3.0.3, but the original APPEND_ARGS option still works.
'ZORP_APPEND_ARGS' : '',

# arguments appended to the zorpctl instance specific options, such as
# --enable-core
'ZORPCTL_APPEND_ARGS' : '',

# whether to check /etc/zorp permissions
'CHECK_PERMS' : 1,
'CONFIG_DIR' : '/etc/zorp',
'CONFIG_DIR_OWNER' : 'root',
'CONFIG_DIR_GROUP' : 'zorp',
'CONFIG_DIR_MODE' : 0750,

# directory where Zorp stores its pidfiles
'PIDFILE_DIR' : '/var/run/zorp',

# set pidfile directory ownership according to the settings below (umask is
# applied).
# DO not modify this, unless you know what you are doing.
'PIDFILE_DIR_OWNER' : 'zorp',
'PIDFILE_DIR_GROUP' : 'zorp',
'PIDFILE_DIR_MODE' : 0770,
                   }

        self.config = ConfigParser.RawConfigParser(defaults)
        self.path = Zorp.Config.config.dirs.sysconfdir

    def __getitem__(self, key):
        if key == "ZORP_PRODUCT_NAME":
           return Zorp.Config.config.options.product_name
        if key == 'ZORP_LIBDIR':
            return Zorp.Config.config.dirs.libdir
        if key == 'ZORP_SYSCONFDIR':
            return Zorp.Config.config.dirs.sysconfdir
        if key == 'ZORP_PIDFILEDIR':
            return Zorp.Config.config.dirs.pidfiledir

        try:
            value = self.config.get('zorpctl', key)
            return value
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            try:
                value = self.config.get('DEFAULT', key)
            except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
                raise KeyError(key)

        try:
             value = float(value)
             if round(value - int(value), 6) == 0:
                 value = int(value)
        except ValueError:
             pass

        return value

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value
        self.parse()

    def parse(self):
        if not self.config.read(self.path + '/zorpctl.conf'):
            self.config.read(self.path)
