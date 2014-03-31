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

import zorpctl.utils as utils

class Message(object):
    def __init__(self, params = None):
        self.params = params

    def _strParams(self):
        return " ".join(self.params) if utils.isSequence(self.params) else self.params

    def __str__(self):
        return "%s%s\n" % (self.command, " " + self._strParams() if self.params else "")

class MessageGetValue(Message):
    command = "GETVALUE"
    param_name = ""

    def __init__(self, key):
        if not key:
            self.command = "GETVALUE "
        super(MessageGetValue, self).__init__(key)

class MessageGetSibling(Message):
    command = "GETSBLNG"
    param_name = ""

    def __init__(self, node):
        if not node:
            self.command = "GETSBLNG "
        super(MessageGetSibling, self).__init__(node)

class MessageGetChild(Message):
    command = "GETCHILD"
    param_name = ""

    def __init__(self, node):
        if not node:
            self.command = "GETCHILD "
        super(MessageGetChild, self).__init__(node)

class MessageGetLogLevel(Message):
    command = "LOGGING"
    param_name = "VGET"

    def __init__(self):
        super(MessageGetLogLevel, self).__init__(self.param_name)

class MessageSetLogLevel(Message):
    command = "LOGGING"
    param_name = "VSET"

    def __init__(self, level):
        super(MessageSetLogLevel, self).__init__([self.param_name, str(level)])

class MessageGetLogSpec(Message):
    command = "LOGGING"
    param_name = "GETSPEC"

    def __init__(self):
        super(MessageGetLogSpec, self).__init__(self.param_name)

class MessageSetLogSpec(Message):
    command = "LOGGING"
    param_name = "SETSPEC"

    def __init__(self, value):
        super(MessageSetLogSpec, self).__init__([self.param_name, value])

class MessageGetDeadLockCheck(Message):
    command = "DEADLOCKCHECK"
    param_name = "GET"

    def __init__(self):
        super(MessageGetDeadLockCheck, self).__init__(self.param_name)

class MessageSetDeadLockCheck(Message):
    command = "DEADLOCKCHECK"
    param_name = ""

    def __init__(self, value):
        self.param_name = "ENABLE" if value else "DISABLE"
        super(MessageSetDeadLockCheck, self).__init__(self.param_name)

class MessageReload(Message):
    command = "RELOAD"
    param_name = ""

    def __init__(self):
        super(MessageReload, self).__init__()

class MessageReloadResult(Message):
    command = "RELOAD"
    param_name = "RESULT"

    def __init__(self):
        super(MessageReloadResult, self).__init__(self.param_name)

class MessageStopSession(Message):
    command = "STOPSESSION"
    param_name = ""

    def __init__(self, param):
        super(MessageStopSession, self).__init__(param)

class MessageAuthorizeAbstract(Message):
    command = "AUTHORIZE"

    def __init__(self):
        super(MessageAuthorizeAbstract, self).__init__([self.param_name, self.session_id, self.description])

class MessageAuthorizeAccept(MessageAuthorizeAbstract):
    param_name = "ACCEPT"

    def __init__(self, session_id, description):
        self.session_id = session_id
        self.description = description
        super(MessageAuthorizeAccept, self).__init__()

class MessageAuthorizeReject(MessageAuthorizeAbstract):
    param_name = "REJECT"

    def __init__(self, session_id, description):
        self.session_id = session_id
        self.description = description
        super(MessageAuthorizeReject, self).__init__()

