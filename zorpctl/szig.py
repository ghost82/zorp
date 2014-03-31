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

import socket
from zorpctl.SZIGMessages import (
        MessageAuthorizeAccept, MessageAuthorizeReject,
        MessageGetChild, MessageGetDeadLockCheck,
        MessageGetLogLevel, MessageGetLogSpec,
        MessageGetSibling, MessageGetValue,
        MessageReload, MessageReloadResult,
        MessageSetDeadLockCheck, MessageSetLogLevel,
        MessageSetLogSpec, MessageStopSession
    )
from zorpctl.ZorpctlConf import ZorpctlConfig


class Response(object):
    def __init__(self, succeeded, value = None):
        self.is_succeeded = succeeded
        self.value = value

class ResponseDeadlockCheck(Response):

    def isSet(self):
        return self.value == "1"

class Handler(object):
    """
    Class created for handling messages sent by Szig to Zorp
    and receiving answer from Zorp
    """

    _success_prefix = "OK "
    _fail_prefix = "FAIL "

    def __init__(self, server_address):
        self.max_command_length = 4096
        self.response_length = 4096
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_address = server_address
        try:
            self.socket.connect(self.server_address)
        except IOError as e:
            e.message = "Socket not found, %s" % server_address
            raise e

    def talk(self, message):
        """
        Sends an instance of Message and
        returns the response as Response class
        """
        self.send(message)
        return self.recv()

    def send(self, message):
        """
        Sending a message to Zorp.
        Messages can be derived from abstract Message class.
        """
        self._write_request(str(message))

    def recv(self):
        """
        Returns an instance of Response class.
        """
        resp = self._read_response()
        return Response(self._isSucceeded(resp), self._cutPrefix(resp))

    def _write_request(self, request):
        """
        Writing a command message to a Unix Domain Socket
        to communicate with Zorp.

        Raises SZIGError if not all the data has been sent.
        SZIGError value is a tuple of sent/all
        """

        request_length = len(request)
        if request_length > self.max_command_length:
            raise SZIGError("Given request is longer than %s" % self.max_command_length)

        sent_data_length = self.socket.send(request)
        if sent_data_length < request_length:
            msg = "There was an error while sending the request (%s/%s)!" % (sent_data_length, request_length)
            raise SZIGError(msg, (sent_data_length, request_length))

    def _read_response(self, resp_len = None):
        """
        Reading from a Unix Domain Socket
        to communicate with Zorp.
        """
        if not resp_len:
            resp_len = self.response_length
        if resp_len < 1:
            raise SZIGError("Response length should be greater than 0")

        response = self.socket.recv(resp_len)
        if not response:
            raise SZIGError("There was an error while receiving the answer!")

        return response[:-1] if response[-1:] == '\n' else response

    def _isSucceeded(self, response):
        """
        Method for checking if Zorp understood
        the given request by inspecting the response.
        """
        return response[:len(self._success_prefix)] == self._success_prefix

    def _cutPrefix(self, string):
        """
        Cuts the defined prefix from a string.
        """
        if string[:len(self._success_prefix)] == self._success_prefix:
            string =  string[len(self._success_prefix):]
        else:
            if string[:len(self._fail_prefix)] == self._fail_prefix:
                string = string[len(self._fail_prefix):]

        return string

class SZIG(object):

    def __init__(self, process_name, handler=None):
        ZORPCTLCONF = ZorpctlConfig.Instance()
        self.pidfile_dir = ZORPCTLCONF['ZORP_PIDFILEDIR']
        if not handler:
            handler = Handler
        self.handler = handler(self.pidfile_dir + '/zorpctl.' + process_name)

    def get_value(self, key):
        response = self.handler.talk(MessageGetValue(key))
        return None if response.value == "None" else response.value

    def get_sibling(self, node):
        response =  self.handler.talk(MessageGetSibling(node))
        return None if response.value == "None" else response.value

    def get_child(self, node):
        response =  self.handler.talk(MessageGetChild(node))
        return None if response.value == "None" else response.value

    @property
    def loglevel(self):
        self.handler.send(MessageGetLogLevel())
        return int(self.handler.recv().value)

    @loglevel.setter
    def loglevel(self, value):
        self.handler.send(MessageSetLogLevel(value))
        if not self.handler.recv().is_succeeded:
            raise SZIGError("Log level has not been set.")

    @property
    def logspec(self):
        self.handler.send(MessageGetLogSpec())
        return self.handler.recv().value

    @logspec.setter
    def logspec(self, value):
        """
        Setting LOGSPEC expecting a log specification
        string as value
        """
        self.handler.send(MessageSetLogSpec(value))
        if not self.handler.recv().is_succeeded:
            raise SZIGError("Log specification has not been set.")

    @property
    def deadlockcheck(self):
        self.handler.send(MessageGetDeadLockCheck())
        dlc = self.handler.recv()
        dlc.__class__ = ResponseDeadlockCheck

        return dlc.isSet()

    @deadlockcheck.setter
    def deadlockcheck(self, value):
        """
        Sets Deadlock Check, expects a boolean as value.
        """
        self.handler.talk(MessageSetDeadLockCheck(value))

    def reload(self):
        self.handler.talk(MessageReload())

    def reload_result(self):
        result = self.handler.talk(MessageReloadResult())
        return result.is_succeeded

    def stop_session(self, instance):
        response = self.handler.talk(MessageStopSession(instance))
        if not response.is_succeeded:
            raise SZIGError("Session stop failed! Response was: %s" % response.value)

    def authorize_accept(self, session_id, description):
        response = self.handler.talk(MessageAuthorizeAccept(session_id, description))
        if not response.is_succeeded:
            raise SZIGError(response.value)
        return response.value

    def authorize_reject(self, session_id, description):
        response = self.handler.talk(MessageAuthorizeReject(session_id, description))
        if not response.is_succeeded:
            raise SZIGError(response.value)
        return response.value

class SZIGError(Exception):
    """
    Exception Class created for Szig specific errors.
    """
    def __init__(self, msg, value = None):
        self.msg = msg
        self.value = value

    def __str__(self):
        return self.msg + repr(self.value)
