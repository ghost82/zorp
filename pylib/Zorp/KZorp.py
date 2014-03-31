############################################################################
##
##
############################################################################

import Globals
import random
import kzorp.messages
import kzorp.communication
from Zorp import *

def downloadServices(h):
    # download services
    kzorp.communication.exchangeMessage(h, kzorp.messages.KZorpFlushServicesMessage())

    for service in Globals.services.values():
        messages = service.buildKZorpMessage()
        kzorp.communication.exchangeMessages(h, messages)

def downloadDispatchers(h):
    kzorp.communication.exchangeMessage(h, kzorp.messages.KZorpFlushDispatchersMessage())

    for dispatch in Globals.dispatches:
        try:
            messages = dispatch.buildKZorpMessage()
            kzorp.communication.exchangeMessages(h, messages)
        except:
            log(None, CORE_ERROR, 0, "Error occured during Dispatcher upload to KZorp; dispatcher='%s', error='%s'" % (dispatch.bindto[0].format(), sys.exc_value))
            raise


def downloadBindAddresses(h):
    for dispatch in Globals.dispatches:
        try:
            messages = dispatch.buildKZorpBindMessage()
            kzorp.communication.exchangeMessages(h, messages)
        except:
            log(None, CORE_ERROR, 0, "Error occured during bind address upload to KZorp; dispatcher='%s', error='%s'" % (dispatch.bindto[0].format(), sys.exc_value))
            raise

def createAddZoneMessageFromZone(zone):
    subnet_num = len(zone.subnets) + len(zone.hostnames)
    pname = zone.admin_parent.name if zone.admin_parent else None
    return kzorp.messages.KZorpAddZoneMessage(zone.name, pname, subnet_num = subnet_num)

def createAddZoneSubnetMessagesFromZoneAddresses(zone):
    add_zone_subnet_messages = []
    for subnet in zone.subnets:
        add_zone_subnet_message = kzorp.messages.KZorpAddZoneSubnetMessage(zone.name,
                                                                                subnet.get_family(),
                                                                                subnet.addr_packed(),
                                                                                subnet.netmask_packed())
        add_zone_subnet_messages.append(add_zone_subnet_message)
    return add_zone_subnet_messages

def downloadStaticZones(zones):
    h = kzorp.communication.Handle()
    kzorp.communication.startTransaction(h, kzorp.messages.KZ_INSTANCE_GLOBAL)
    try:
        for zone in sorted(zones, cmp=lambda z1, z2: cmp(z1.getDepth(), z2.getDepth())):
            kzorp.communication.exchangeMessages(h, (createAddZoneMessageFromZone(zone), ))
            kzorp.communication.exchangeMessages(h, createAddZoneSubnetMessagesFromZoneAddresses(zone))

        kzorp.communication.commitTransaction(h)
    except:
        h.close()
        raise

def downloadKZorpConfig(instance_name, is_master):

    random.seed()
    h = kzorp.communication.Handle()

    # start transaction
    kzorp.communication.startTransaction(h, instance_name)

    try:
        if is_master:
            downloadServices(h)
            downloadDispatchers(h)
        downloadBindAddresses(h)
        kzorp.communication.commitTransaction(h)
    except:
        h.close()
        raise

    Globals.kzorp_netlink_handle = h

def flushKZorpConfig(instance_name):

    random.seed()

    h = getattr(Globals, "kzorp_netlink_handle", None)
    if not h:
        h = kzorp.communication.Handle()

    # flush dispatchers and services
    kzorp.communication.startTransaction(h, instance_name)
    try:
        kzorp.communication.exchangeMessage(h, kzorp.messages.KZorpFlushDispatchersMessage())
        kzorp.communication.exchangeMessage(h, kzorp.messages.KZorpFlushServicesMessage())
        kzorp.communication.commitTransaction(h)
    except:
        h.close()
        raise

    h.close()

def closeKZorpHandle():
    h = getattr(Globals, "kzorp_netlink_handle", None)
    if h:
        Globals.kzorp_netlink_handle = None
        h.close()

Globals.deinit_callbacks.append(closeKZorpHandle)
