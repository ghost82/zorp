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

class CommandResult(object):
    def __init__(self, msg = None, value = None):
        self.msg = msg
        self.value = value

    def __str__(self):
        return self.msg

class CommandResultSuccess(CommandResult):
    def __init__(self, msg = None, value = None):
        super(CommandResultSuccess, self).__init__(msg, value)

    def __nonzero__(self):
        return True

class CommandResultFailure(CommandResult):
    def __init__(self, msg = None, value = None):
        super(CommandResultFailure, self).__init__(msg, value)

    def __nonzero__(self):
        return False
