from zorpctl.SZIGMessages import *
from zorpctl.szig import Response

class HandlerMock(object):

    def __init__(self, server_address=None):
        self.loglevel = 4
        self.deadlockcheck = True
        self.siblings = {}
        self.logspec = ''
        self.data = {
            "conns": {
                "service_http_transparent": {
                    "outbound_zones": "clients(1)",
                    "inbound_zones": "servers(1)"
                }
            },
            "info": {
                "policy": {
                    "reload_stamp": 1367664125,
                    "file_stamp": 1322391262,
                    "file": "/etc/zorp/policy.py"
                }
            },
            "stats": {
                "threads_running": 4,
                "thread_rate_max": 0,
                "thread_number": 5,
                "audit_number": None,
                "audit_running": None,
                "thread_rate_avg1": 0,
                "sessions_running": 0,
                "thread_rate_avg5": 0,
                "threads_max": 5,
                "thread_rate_avg15": 0
            },
            "service": {
                "service_http_transparent": {
                    "rate_max": 0,
                    "session_number": 1,
                    "sessions_max": 1,
                    "sessions_running": 0,
                    "rate_avg1": 0,
                    "rate_avg5": 0,
                    "last_started": 1367675872.63,
                    "rate_avg15": 0
                }
            }
        }

    def _get(self, key):
        result = self.data
        if not key:
            return result
        parts = key.split('.')
        for part in parts:
            result = result[part]
        return result

    def getvalue(self, key):
        if key == "":
            return None
        result = self._get(key)
        if type(result) == dict:
            return None
        return result

    def _getmembers(self, key):
        last_dot_position = key.rfind('.')
        if last_dot_position == -1:
            members = self.data.keys()
        else:
            members = self._get(key[:last_dot_position]).keys()
        return members

    def getsibling(self, key):
        members = self._getmembers(key)

        position = members.index(key.split('.')[-1])
        try:
            sibling = members[position + 1]
        except IndexError:
            return None
        last_dot_position = key.rfind('.')
        return ((key[:last_dot_position] + ".") if last_dot_position != -1 else "") + sibling

    def getchild(self, key):
        value = self._get(key)
        if type(value) != dict:
            return None
        childs = value.keys()
        return (key + "." if key else "") + childs[0]

    def talk(self, message):
        if type(message) == MessageGetValue:
            return Response(True, self.getvalue(message.params))
        if type(message) == MessageGetSibling:
            return Response(True, self.getsibling(message.params))
        if type(message) == MessageGetChild:
            return Response(True, self.getchild(message.params))
        if type(message) == MessageGetLogLevel:
            return Response(True, self.loglevel)
        if type(message) == MessageSetLogLevel:
            self.loglevel = int(message.params[1])
            return Response(True)
        if type(message) == MessageGetDeadLockCheck:
            return Response(True, "1" if self.deadlockcheck else "0")
        if type(message) == MessageSetDeadLockCheck:
            self.deadlockcheck = message.params == 'ENABLE'
        if type(message) == MessageReloadResult:
            return Response(True)
        if type(message) == MessageGetLogSpec:
            return Response(True, self.logspec)
        if type(message) == MessageSetLogSpec:
            self.logspec = message.params[1]
            return Response(True)

    def send(self, message):
        self.sent_message = message

    def recv(self):
        return self.talk(self.sent_message)
