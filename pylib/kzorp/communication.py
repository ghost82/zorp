import netlink
import random, time
import messages as kzorp_messages
import Zorp.Common

class Handle(netlink.Handle):
    def __init__(self):
        super(Handle, self).__init__('kzorp')

    def dump(self, message, factory=kzorp_messages.KZorpMessageFactory):
        return super(Handle, self).talk(message, True, factory)

    def exchange(self, message, factory=kzorp_messages.KZorpMessageFactory):
        replies = []
        for reply in self.talk(message, False, factory):
            replies.append(reply)
        reply_num = len(replies)
        if reply_num == 0:
            return None
        elif reply_num == 1:
            return replies[0]
        else:
            raise netlink.NetlinkException, "Netlink message has more than one reply: command='%d'" % (msg.command)

def exchangeMessage(h, payload):
    try:
        for reply in h.talk(payload):
            pass
    except netlink.NetlinkException as e:
        raise netlink.NetlinkException, "Error while talking to kernel; result='%s'" % (e.what)

def exchangeMessages(h, messages):
    for payload in messages:
        exchangeMessage(h, payload)

def startTransaction(h, instance_name):
    tries = 7
    wait = 0.1
    while tries > 0:
        try:
            exchangeMessage(h, kzorp_messages.KZorpStartTransactionMessage(instance_name))
        except:
            tries = tries - 1
            if tries == 0:
                raise
            wait = 2 * wait
            time.sleep(wait * random.random())
            continue

        break

def commitTransaction(h):
    exchangeMessage(h, kzorp_messages.KZorpCommitTransactionMessage())


class Adapter(object):
    def __init__(self):
        self.kzorp_handle = Handle()

    def __enter__(self):
        self.__acquire_caps()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.__drop_caps()

    def __acquire_caps(self):
        """ aquire the CAP_NET_ADMIN capability """
        import prctl

        try:
            prctl.set_caps((prctl.CAP_NET_ADMIN, prctl.CAP_EFFECTIVE, True))
        except OSError, e:
            Zorp.Common.log(None, Zorp.Common.CORE_ERROR, 1, "Unable to acquire NET_ADMIN capability; error='%s'" % (e))
            raise e

    def __drop_caps(self):
        """ drop the CAP_NET_ADMIN capability """
        import prctl

        try:
            prctl.set_caps((prctl.CAP_NET_ADMIN, prctl.CAP_EFFECTIVE, False))
        except OSError, e:
            Zorp.Common.log(None, Zorp.Common.CORE_ERROR, 1, "Unable to drop NET_ADMIN capability; error='%s'" % (e))
            raise e

    def send_message(self, message):
        return self.kzorp_handle.exchange(message)

    def send_messages_in_transaction(self, messages):
        try:
            startTransaction(self.kzorp_handle, kzorp_messages.KZ_INSTANCE_GLOBAL)

            for message in messages:
                self.kzorp_handle.exchange(message)

            commitTransaction(self.kzorp_handle)
        except netlink.NetlinkException as e:
            Zorp.Common.log(None, Zorp.Common.CORE_ERROR, 6,
                       "Error occured while downloading zones to kernel; error='%s'" % (e.detail))
            raise e
