#!/usr/bin/env python

import os
import errno

import string
import struct
import socket
import glob

import optparse
import sys
import types
from functools import partial
import kzorp.netlink as netlink
from kzorp.messages import *
from kzorp.communication import *
from Zorp.Service import DenyIPv4, DenyIPv6

import unittest

from Zorp.Zone import InetZone, Zone
from Zorp.Subnet import InetDomain, Inet6Subnet, InetSubnet
FALSE = 0
TRUE = 1

def inet_ntoa(a):
    return "%s.%s.%s.%s" % ((a >> 24) & 0xff, (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff)

def inet_aton(a):
    r = 0L
    for n in a.split("."):
        r = (r << 8) + int(n)
    return r

def size_to_mask(family, size):
    if family == socket.AF_INET:
        max_size = 32
    elif family == socket.AF_INET6:
        max_size = 128
    else:
        raise ValueError, "address family not supported; family='%d'" % family

    if size > max_size:
        raise ValueError, "network size is greater than the maximal size; size='%d', max_size='%d'" % (size, max_size)

    packed_mask = ''
    actual_size = 0
    while actual_size + 8 < size:
        packed_mask += '\xff'
        actual_size = actual_size + 8

    if actual_size <= size:
        packed_mask += chr((0xff << (8 - (size - actual_size))) & 0xff)
        actual_size = actual_size + 8

    while actual_size < max_size:
        packed_mask += '\x00'
        actual_size = actual_size + 8

    return socket.inet_ntop(family, packed_mask)

class KZorpComm(unittest.TestCase):
    handle = None
    _flushables = [
                    KZorpFlushZonesMessage,
                    KZorpFlushServicesMessage,
                    KZorpFlushDispatchersMessage,
                    KZorpFlushBindsMessage
                  ]

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)
        self.create_handle()
        self._in_transaction = False

    def __del__(self):
        self.close_handle()

    def create_handle(self):
        if self.handle == None:
            self.handle = Handle()
            self.assertNotEqual(self.handle, None)

    def close_handle(self):
        if self.handle:
            self.handle.close()
            self.handle = None

    def reopen_handle(self):
        self.close_handle()
        self.create_handle()

    def send_message(self, message, assert_on_error = True, message_handler = None, dump = False, error_handler=None):
        self.assertNotEqual(message, None)
        self.assertNotEqual(self.handle, None)

        try:
            res = 0
            for reply_message in self.handle.talk(message, dump, factory=KZorpMessageFactory):
                if message_handler is not None:
                    message_handler(reply_message)
                else:
                    pass
        except NetlinkException as e:
            res = e.detail
            if assert_on_error:
                if error_handler:
                    error_handler(e.detail)
                else:
                    raise

        return res

    def start_transaction(self, instance_name = KZ_INSTANCE_GLOBAL, cookie = 0L):
        self.send_message(KZorpStartTransactionMessage(instance_name))
        self._in_transaction = True

    def end_transaction(self, instance_name = KZ_INSTANCE_GLOBAL):
        self.send_message(KZorpCommitTransactionMessage())
        self._in_transaction = False

    def flush_all(self):
        if self._in_transaction:
            self.reopen_handle()
            self._in_transaction = False

        for message_class in self._flushables:
            self.start_transaction()
            self.send_message(message_class())
            self.end_transaction()

class KZorpBaseTestCaseZones(KZorpComm):
    _dumped_zones = []

    def _dump_zone_handler(self, message):
        if message.command is not KZNL_MSG_ADD_ZONE:
            return

        self._dumped_zones.append(message)

    def check_zone_num(self, num_zones = 0, in_transaction = True):
        self._dumped_zones = []

        if in_transaction == True:
            self.start_transaction()

        self.send_message(KZorpGetZoneMessage(None), message_handler = self._dump_zone_handler, dump = True)

        if in_transaction == True:
            self.end_transaction()

        self.assertEqual(num_zones, len(self._dumped_zones))

    def get_zone_attrs(self, message):
        self.assertEqual(message.command, KZNL_MSG_ADD_ZONE)

        attrs = message.get_attributes()

        return attrs

    def send_add_zone_message(self, inet_zone):
        for m in inet_zone.buildKZorpMessage():
            self.send_message(m)

    def _check_zone_params(self, add_zone_message, zone_data):
        self.assertEqual(add_zone_message.name, zone_data['name'])
        self.assertEqual(add_zone_message.pname, zone_data['pname'])
        subnet_num = 1 if zone_data.has_key('address') else 0
        self.assertEqual(add_zone_message.subnet_num, subnet_num)

class KZorpTestCaseZones(KZorpBaseTestCaseZones):
    _zones = [
               {'name' : 'root', 'pname' : None,   'address' : '10.0.100.1',     'mask' : 32, 'family' : socket.AF_INET},
               {'name' :    'b', 'pname' : 'root', 'address' : '10.0.102.1',     'mask' : 31, 'family' : socket.AF_INET},
               {'name' :    'c', 'pname' :    'b', 'address' : '10.0.103.1',     'mask' : 30, 'family' : socket.AF_INET},
               {'name' :    'd', 'pname' :    'b', 'address' : '10.0.104.1',     'mask' : 29, 'family' : socket.AF_INET},
               {'name' :    'e', 'pname' :    'b', 'address' : '10.0.105.1',     'mask' : 28, 'family' : socket.AF_INET},
               {'name' :    'f', 'pname' :    'b', 'address' : '10.0.106.1',     'mask' : 27, 'family' : socket.AF_INET},
               {'name' :    'g', 'pname' :    'f', 'address' : '10.0.107.1',     'mask' : 26, 'family' : socket.AF_INET},
               {'name' :    'h', 'pname' :    'g', 'address' : '10.0.108.1',     'mask' : 25, 'family' : socket.AF_INET},
               {'name' :    'i', 'pname' :    'g', 'address' : '10.0.109.1',     'mask' : 24, 'family' : socket.AF_INET},
               {'name' :    'j', 'pname' :    'g', 'address' : '10.0.110.1',     'mask' : 23, 'family' : socket.AF_INET},
             ]

    def newSetUp(self):
        self.start_transaction()

        for zone in self._zones:
            add_zone_message = KZorpAddZoneMessage(zone['name'], pname = zone['pname'], subnet_num = 1)
            self.send_message(add_zone_message)

            family = zone['family']
            add_zone_subnet_message = KZorpAddZoneSubnetMessage(zone['name'],
                                                                family = family,
                                                                address = socket.inet_pton(family, zone['address']),
                                                                mask = socket.inet_pton(family, size_to_mask(family, zone['mask'])))
            self.send_message(add_zone_subnet_message)

        self.end_transaction()
        self._index = -1
        self._add_zone_message = None
        self._add_zone_messages = []

    def setUp(self):
        self.internet_zone_name = 'internet'
        self.internet_subnet_family = socket.AF_INET
        self.internet_subnet_addr = socket.inet_pton(self.internet_subnet_family, '0.0.0.0')
        self.internet_subnet_mask = self.internet_subnet_addr

    def tearDown(self):
        self.flush_all()

    def test_add_zone(self):
        self.newSetUp()
        #set up and ter down test the zone addition
        self.check_zone_num(len(self._zones))

    def test_add_zone_errors(self):
        zones = [
                  {'desc' : 'nonexistent parent', 'name' :   'x1',  'pname' :  'x', 'error' : -errno.ENOENT},
                  {'desc' : 'no parent',          'name' :    'a',  'pname' : None, 'error' : 0},
                  {'desc' : 'existing name',      'name' :    'a',  'pname' : None, 'error' : -errno.EEXIST},
                  {'desc' : 'nonexistent name',   'name' :   'x2',  'pname' : None, 'error' : 0},
                  {'desc' : 'empty name',         'name' :     '',  'pname' : None, 'error' : -errno.EINVAL},
                  {'desc' : 'empty parent',       'name' : 'fake',  'pname' :   '', 'error' : -errno.EINVAL},
                ]

        add_zone_message = KZorpAddZoneMessage('a');
        res = self.send_message(add_zone_message, assert_on_error = False)
        self.assertEqual(res, -errno.ENOENT)

        self.start_transaction()
        for zone in zones:
            add_zone_message = KZorpAddZoneMessage(zone['name'], pname = zone['pname'])

            res = self.send_message(add_zone_message, assert_on_error = False)
            self.assertEqual(res, zone['error'])
        self.end_transaction()

    def test_zero_subnet_is_valid(self):
        self.start_transaction()
        self.send_message(KZorpAddZoneMessage('name', None, subnet_num = 0))
        self.end_transaction()

    def _add_zone_subnet_handler(self, msg):
        if msg.command is KZNL_MSG_ADD_ZONE_SUBNET:
            self._add_zone_subnet_msg = msg

    def _create_add_zone_subnet_internet(self, name):
        return KZorpAddZoneSubnetMessage(name,
                                         self.internet_subnet_family,
                                         self.internet_subnet_addr,
                                         self.internet_subnet_mask)

    def _add_zone_with_internet_subnet(self):
        self.start_transaction()
        self.send_message(KZorpAddZoneMessage(self.internet_zone_name, None, subnet_num = 1))
        add_zone_subnet_msg = self._create_add_zone_subnet_internet(self.internet_zone_name)
        self.send_message(add_zone_subnet_msg)
        self.end_transaction()

        self._check_add_zone_subnet_internet(add_zone_subnet_msg)

    def _check_add_zone_subnet_internet(self, msg):
        self.send_message(KZorpGetZoneMessage(msg.zone_name),
                          message_handler = self._add_zone_subnet_handler)
        self.assertEqual(self._add_zone_subnet_msg, msg)

    def test_add_zone_subnet_in_same_transaction(self):
        self._add_zone_with_internet_subnet()


    def __test_add_zone_subnet_different_transaction(self):
        self.start_transaction()
        self.send_message(KZorpAddZoneMessage(self.internet_zone_name, None, subnet_num = 0))
        self.end_transaction()

        self.start_transaction()
        add_zone_subnet_msg = self._create_add_zone_subnet_internet(self.internet_zone_name)
        self.send_message(add_zone_subnet_msg)
        self.end_transaction()

        self._check_add_zone_subnet_internet(add_zone_subnet_msg)

    def test_add_subnet_to_zone_with_zero_subnet_num(self):
        self.start_transaction()

        self.send_message(KZorpAddZoneMessage('name', None, subnet_num = 0))

        res = self.send_message(self._create_add_zone_subnet_internet('name'),
                                assert_on_error = False)
        self.assertEqual(res, -errno.ENOMEM)

        self.end_transaction()

    def _get_zone_message_handler(self, msg):
        self._add_zone_message = msg
        if msg.command is not KZNL_MSG_ADD_ZONE:
            return

        self._index += 1

        self._check_zone_params(msg, self._zones[self._index])

    def test_get_zone_by_name(self):
        self.newSetUp()
        #get each created zone
        for zone in self._zones:
            zone_name = zone['name']
            self.send_message(KZorpGetZoneMessage(zone_name), message_handler = self._get_zone_message_handler)
        self.assertNotEqual(self._index, len(self._zones))

        #get a not existent zone
        self.assertNotEqual(self._zones[0]['name'], 'nonexistent zone name')
        res = self.send_message(KZorpGetZoneMessage('nonexistent zone name'), assert_on_error = False)
        self.assertEqual(res, -errno.ENOENT)

    def _get_zones_message_handler(self, msg):
        if msg.command is not KZNL_MSG_ADD_ZONE:
            return

        self._add_zone_messages.append(msg)

    def test_get_zone_with_dump(self):
        self.newSetUp()
        #get the dump of zones
        self.send_message(KZorpGetZoneMessage(None), message_handler = self._get_zones_message_handler, dump = True)
        self.assertEqual(len(self._add_zone_messages), len(self._zones))
        for add_zone_message in self._add_zone_messages:
            for i in range(len(self._zones)):
                if add_zone_message.name == self._zones[i]['name']:
                    self._check_zone_params(add_zone_message, self._zones[i])
                    break
            else:
                self.assert_(True, "zone with name %s could not find in the dump" % self.get_zone_uname(add_zone_message))

attrmap = {
            KZNL_ATTR_SVC_NAME: (create_name_attr, parse_name_attr),
            KZNL_ATTR_SVC_PARAMS: (create_service_params_attr, parse_service_params_attr),
            KZNL_ATTR_SVC_ROUTER_DST_ADDR: (create_inet_addr_attr, parse_inet_addr_attr),
            KZNL_ATTR_SVC_ROUTER_DST_PORT: (create_port_attr, parse_port_attr),
            KZNL_ATTR_SVC_NAT_SRC: (create_nat_range_attr, parse_nat_range_attr),
            KZNL_ATTR_SVC_NAT_DST: (create_nat_range_attr, parse_nat_range_attr),
            KZNL_ATTR_SVC_NAT_MAP: (create_nat_range_attr, parse_nat_range_attr),
            KZNL_ATTR_SVC_SESSION_COUNT: (NetlinkAttribute.create_be32, NetlinkAttribute.parse_be32),
          }

def create_attr(type, *attr):
    return attrmap[type][0](type, *attr)

def parse_attr(type, attr):
    if not attr.has_key(type):
        return None
    return attrmap[type][1](attr[type])

def service_get_flags(transparent, forge_addr):
    flags = 0
    if (transparent): flags |= KZF_SVC_TRANSPARENT
    if (forge_addr): flags |= KZF_SVC_FORGE_ADDR
    return flags


class KZorpTestCaseServices(KZorpComm):

    services = [
        (KZorpAddProxyServiceMessage,
         { 'name': "test-proxy" }),

        (KZorpAddForwardServiceMessage,
         { 'name': "test3", 'dst_family': socket.AF_INET, 'dst_ip': socket.inet_pton(socket.AF_INET, '1.2.3.4'), 'dst_port': 1 }),

        (KZorpAddForwardServiceMessage,
         { 'name': "test6", 'dst_family': socket.AF_INET, 'dst_ip': socket.inet_pton(socket.AF_INET, '1.2.3.4'), 'dst_port': 1 }),

        (KZorpAddProxyServiceMessage,
         {'name': 'test5', 'count': 303}),

        (KZorpAddDenyServiceMessage,
         {'name': 'test-deny', 'logging': True, 'count': 33, 'ipv4_settings': DenyIPv4.DROP, 'ipv6_settings': DenyIPv6.DROP}),
        ]

    def check_svc_num(self, num_svc):
        _dumped_zones = []
        self.send_message(KZorpGetServiceMessage(None), message_handler = _dumped_zones.append, dump = True)
        self.assertEqual(num_svc, len(_dumped_zones))

    def check_send(self, message, return_value):
        self.start_transaction()
        r = self.send_message(message, assert_on_error=False)
        self.end_transaction()
        self.assertEqual(return_value, r)

    def newSetUp(self):
        self.start_transaction()
        for service in self.services:
            self.send_message(service[0](**service[1]))
        self.end_transaction()

    def tearDown(self):
        self.flush_all();

    def test_get_service(self):
        def check_get_reply(self, service, reply):
            for (name, value) in service[1].items():
                self.assertEqual(getattr(reply, name), value)

        self.newSetUp()
        self.check_svc_num(len(self.services))
        self.assertEqual(-2, self.send_message(KZorpGetServiceMessage("nonexistent"), assert_on_error=False))

        for service in self.services:
            self.send_message(KZorpGetServiceMessage(service[1].get('name')), message_handler = partial(check_get_reply, self, service))

    def test_add_service_duplicated(self):
        self.newSetUp()
        service_cnt = len(self.services)
        #duplicated entry check: the matching service was in the same transaction
        self.start_transaction()
        self.send_message(KZorpAddProxyServiceMessage("dupe1"))
        res = self.send_message(KZorpAddProxyServiceMessage("dupe1"), assert_on_error=False)
        self.end_transaction()
        self.assertEqual(-errno.EEXIST, res)
        service_cnt += 1
        self.check_svc_num(service_cnt)

        #duplicated entry check: the matching service was already existing
        self.check_send(KZorpAddProxyServiceMessage("dupe1"), -errno.EEXIST)
        self.check_svc_num(service_cnt)

    def test_add_service_invalid(self):

        class KZorpAddInvalidServiceMessage(KZorpAddServiceMessage):
            type_string = "Invalid"

            def __init__(self, name):
                super(KZorpAddInvalidServiceMessage, self).__init__(name, KZ_SVC_PROXY + 100, 0, 0)

                self._build_payload()

        self.newSetUp()
        service_cnt = len(self.services)
        #invalid service type
        self.check_send(KZorpAddInvalidServiceMessage("invalid_service_type"), -errno.EINVAL)
        self.check_svc_num(service_cnt)

    def test_add_service(self):

        self.newSetUp()
        service_cnt = len(self.services)

        #outside of transaction
        self.assertEqual(-errno.ENOENT, self.send_message(self.services[0][0](**self.services[0][1]), assert_on_error=False))
        self.check_svc_num(service_cnt)

    def test_add_service_flags(self):
        self.newSetUp()
        service_cnt = len(self.services)

        for i in range(2 * KZF_SVC_LOGGING):
            self.check_send(KZorpAddProxyServiceMessage("flag-%d" % i, i), 0)

        service_cnt += 2 * KZF_SVC_LOGGING
        self.check_svc_num(service_cnt)

        # using undefined flags
        self.start_transaction()
        res = self.send_message(KZorpAddProxyServiceMessage("flag-invalid", flags=0xfffffffc), assert_on_error=False)
        self.end_transaction()
        self.assertNotEqual(0, res)

    def test_add_service_nontransparent(self):
        self.newSetUp()
        service_cnt = len(self.services)
        self.check_send(KZorpAddForwardServiceMessage("test-nontransparent-router", flags=0, count=0, dst_family=socket.AF_INET, dst_ip=socket.inet_pton(socket.AF_INET, '1.2.3.4'), dst_port=10010), 0)
        service_cnt += 1
        self.check_svc_num(service_cnt)

        self.check_send(KZorpAddForwardServiceMessage("test-nontransparent-norouter", flags=0, count=0), -errno.EINVAL)
        self.check_svc_num(service_cnt)

    def _test_add_service_nat(self, nat_message_class):
        service_cnt = len(self.services)

        #adding a nat rule to a service added in the same transaction
        self.start_transaction()
        self.send_message(KZorpAddForwardServiceMessage('test-nat', flags=KZF_SVC_TRANSPARENT))
        self.send_message(nat_message_class('test-nat',
                                            nat_src=(KZ_SVC_NAT_MAP_IPS + KZ_SVC_NAT_MAP_PROTO_SPECIFIC, 12345688, 12345689, 1024, 1025),
                                            nat_map=(KZ_SVC_NAT_MAP_IPS + KZ_SVC_NAT_MAP_PROTO_SPECIFIC, 12345688, 12345689, 1024, 1025)))
        self.end_transaction()
        service_cnt += 2

        self.check_svc_num(service_cnt)

    def test_add_service_nat_dst(self):
        self.newSetUp()
        self._test_add_service_nat(KZorpAddServiceDestinationNATMappingMessage)

    def test_add_service_nat_src(self):
        self.newSetUp()
        self._test_add_service_nat(KZorpAddServiceSourceNATMappingMessage)

    def test_add_deny_service(self):
        response = []
        m = KZorpAddDenyServiceMessage("denyservice", False, 0, DenyIPv4.DROP, DenyIPv6.DROP)
        self.start_transaction()
        self.send_message(m)
        self.end_transaction()
        self.start_transaction()
        self.send_message(KZorpGetServiceMessage("denyservice"), message_handler = response.append, dump = True)
        self.end_transaction()

        self.assertEqual(1, len(response))


class KZorpTestCaseFlush(KZorpComm):

    def __init__(self, *args):
        KZorpComm.__init__(self, *args)

    def setUp(self):
        self._response_message_num = 0
        self.start_transaction()
        message_add_dispatcher = KZorpAddDispatcherMessage('dispatcher_name', 0)
        self.send_message(message_add_dispatcher)
        self.end_transaction()

        self.start_transaction()
        self.send_message(KZorpAddProxyServiceMessage('proxyservice'))
        self.send_message(KZorpAddForwardServiceMessage('pfservice', KZF_SVC_TRANSPARENT))
        self.end_transaction()

        self.start_transaction()
        self.send_message(KZorpAddZoneMessage('zone'))
        self.end_transaction()

    def tearDown(self):
        self.flush_all()

    def message_handler(self, message):
        self._response_message_num += 1

    def test_flush_zones(self):
        self.start_transaction()
        self.send_message(KZorpFlushZonesMessage(), message_handler = self.message_handler)
        self.end_transaction()

        self.send_message(KZorpGetZoneMessage(None), message_handler = self.message_handler, dump = True)
        self.assertEqual(self._response_message_num, 0)

    def test_flush_services(self):
        self.start_transaction()
        self.send_message(KZorpFlushServicesMessage(), message_handler = self.message_handler)
        self.end_transaction()

        self.send_message(KZorpGetServiceMessage(None), message_handler = self.message_handler, dump = True)
        self.assertEqual(self._response_message_num, 0)

    def test_flush_dispatchers(self):
        self.start_transaction()
        self.send_message(KZorpFlushDispatchersMessage(), message_handler = self.message_handler)
        self.end_transaction()

        self.send_message(KZorpGetDispatcherMessage(None), message_handler = self.message_handler, dump = True)
        self.assertEqual(self._response_message_num, 0)

class KZorpTestCaseTransaction(KZorpBaseTestCaseZones):
    def tearDown(self):
        self.flush_all()

    def test_transactions(self):
        # Start a transaction
        self.start_transaction(KZ_INSTANCE_GLOBAL, 123456789L)

        # Start the transaction again without end transaction
        message = KZorpStartTransactionMessage(KZ_INSTANCE_GLOBAL, 987654321L)
        res = self.send_message(message, False)
        self.assertEqual(res, -errno.EINVAL)

        # Commit the transaction without any change
        self.end_transaction()

        # Commit the transaction again out of the transaction
        res = self.send_message(KZorpCommitTransactionMessage(), False)
        self.assertEqual(res, -errno.ENOENT)

    def test_transaction_collision(self):
        self.start_transaction()

        message = KZorpStartTransactionMessage(KZ_INSTANCE_GLOBAL)
        res = self.send_message(message, False)
        self.assertEqual(res, -errno.EINVAL)

        self.end_transaction()

    def test_transaction_abort(self):
        self.start_transaction()
        self.send_message(KZorpAddZoneMessage('zone'))
        self.end_transaction()
        self.check_zone_num(1)

        # Start a transaction
        self.start_transaction()

        self.send_message(KZorpAddZoneMessage('a'))
        self.check_zone_num(1, False)

        # Abort the transaction
        self.reopen_handle()

        self.check_zone_num(1, False)


class KZorpBaseTestCaseDispatchers(KZorpComm):
    _dumped_dispatchers = []
    _zones = [
               InetZone('internet', ['0.0.0.0/0']),
               InetZone('A',        ['10.99.101.0/25',   '10.99.201.0/25']),
               InetZone('AA',       ['10.99.101.0/28',   '10.99.201.0/28'],                  admin_parent='A'),
               InetZone('AAA',      ['10.99.101.0/30',   '10.99.201.0/30'],                  admin_parent='AA'),
               InetZone('AAZ',      ['10.99.101.4/30',   '10.99.201.4/30'],                 admin_parent='AA'),
               InetZone('AB',       ['10.99.101.64/28',  '10.99.201.64/28'],                 admin_parent='A'),
               InetZone('ABA',      ['10.99.101.64/30',  '10.99.201.64/30'],                  admin_parent='AB'),
               InetZone('ABZ',      ['10.99.101.68/30',  '10.99.201.68/30'],                 admin_parent='AB'),
               InetZone('AY',       ['10.99.101.80/28',  '10.99.201.80/28'],                 admin_parent='A'),
               InetZone('AYA',      ['10.99.101.80/30',  '10.99.201.80/30'],                  admin_parent='AY'),
               InetZone('AYZ',      ['10.99.101.84/30',  '10.99.201.84/30'],                 admin_parent='AY'),
               InetZone('AZ',       ['10.99.101.16/28',  '10.99.201.16/28'],                 admin_parent='A'),
               InetZone('AZA',      ['10.99.101.16/30',  '10.99.201.16/30'],                  admin_parent='AZ'),
               InetZone('AZZ',      ['10.99.101.20/30',  '10.99.201.20/30'],                 admin_parent='AZ'),
               InetZone('Z',        ['10.99.101.128/25', '10.99.201.128/25']),
               InetZone('ZA',       ['10.99.101.128/28', '10.99.201.128/28'],                  admin_parent='Z'),
               InetZone('ZAA',      ['10.99.101.128/30', '10.99.201.128/30'],                  admin_parent='ZA'),
               InetZone('ZAZ',      ['10.99.101.132/30', '10.99.201.132/30'],                 admin_parent='ZA'),
               InetZone('ZB',       ['10.99.101.192/28', '10.99.201.192/28'],                    admin_parent='Z'),
               InetZone('ZBA',      ['10.99.101.192/30', '10.99.201.192/30'],                  admin_parent='ZB'),
               InetZone('ZBZ',      ['10.99.101.196/30', '10.99.201.196/30'],                 admin_parent='ZB'),
               InetZone('ZY',       ['10.99.101.208/28', '10.99.201.208/28'],                admin_parent='Z'),
               InetZone('ZYA',      ['10.99.101.208/30', '10.99.201.208/30'],                  admin_parent='ZY'),
               InetZone('ZYZ',      ['10.99.101.212/30', '10.99.201.212/30'],                 admin_parent='ZY'),
               InetZone('ZZ',       ['10.99.101.144/28', '10.99.201.144/28'],                 admin_parent='Z'),
               InetZone('ZZA',      ['10.99.101.144/30', '10.99.201.144/30'],                  admin_parent='ZZ'),
               InetZone('ZZZ',      ['10.99.101.148/30', '10.99.201.148/30'],                 admin_parent='ZZ'),

               # imported Zone from Zorp.Zone
               Zone('IPv6_Zone_80',  ['fd00:bb:1030:1100:cc::/80']),
               Zone('IPv6_Zone_96',  ['fd00:bb:1030:1100:cc:aa::/96']),
               Zone('IPv6_Zone_96_2',  ['fd00:bb:1030:1100:cc:22::/96']),
               Zone('IPv6_Zone_128',  ['fd00:bb:1030:1100:cc:aa:bb:dd/128']),

             ]

    def _dump_dispatcher_handler(self, message):
        self._dumped_dispatchers.append(message)

    def check_dispatcher_num(self, num_dispatchers = 0, in_transaction = True):
        self._dumped_dispatchers = []

        if in_transaction == True:
            self.start_transaction()
        self.send_message(KZorpGetDispatcherMessage(None), message_handler = self._dump_dispatcher_handler, dump = True)
        if in_transaction == True:
            self.end_transaction()

        self.assertEqual(num_dispatchers, len(self._dumped_dispatchers))

    def get_dispatcher_attrs(self, message):
        attrs = message.get_attributes()

        return attrs

    def get_dispatcher_name(self, message):
        attrs = self.get_dispatcher_attrs(message)
        if attrs.has_key(KZNL_ATTR_DPT_NAME) == True:
            return parse_name_attr(attrs[KZNL_ATTR_DPT_NAME])

        return None

    def _check_dispatcher_params(self, add_dispatcher_message, dispatcher_data):
        self.assertEqual(self.get_dispatcher_name(add_dispatcher_message), dispatcher_data['name'])

        attrs = self.get_dispatcher_attrs(add_dispatcher_message)

        num_rules = parse_n_dimension_attr(attrs[KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS])
        self.assertEqual(dispatcher_data['num_rules'], num_rules)

    def _check_add_rule_params(self, add_dispatcher_message, rule_data):

        attrs = add_dispatcher_message.get_attributes()
        dpt_name, rule_id, service, rules = parse_rule_attrs(attrs)

        self.assertEqual(rule_data['rule_id'], rule_id)
        self.assertEqual(rule_data['service'], service)

        self.assertEqual(len(rule_data['entry_nums']), len(rules))

        for k, v in rule_data['entry_nums'].items():
            self.assertEqual(k in rules, True)
            self.assertEqual((rule_data['entry_nums'][k],), (rules[k],))

    def _check_add_rule_entry_params(self, add_dispatcher_message, rule_entry_data, rule_entry_index):

        attrs = add_dispatcher_message.get_attributes()
        dpt_name, rule_id, rule_entries = parse_rule_entry_attrs(attrs)
        self.assertEqual(rule_entry_data['rule_id'], rule_id)

        for k, v in rule_entry_data['entry_values'].items():
            if rule_entry_data['entry_nums'][k] > rule_entry_index:
                self.assertEqual(k in rule_entries, True)
                if k in [KZNL_ATTR_N_DIMENSION_SRC_IP, KZNL_ATTR_N_DIMENSION_DST_IP, KZNL_ATTR_N_DIMENSION_SRC_IP6, KZNL_ATTR_N_DIMENSION_DST_IP6]:
                    (addr, mask) = rule_entries[k]
                    self.assertEqual(rule_entry_data['entry_values'][k][rule_entry_index].addr_packed(), addr)
                    self.assertEqual(rule_entry_data['entry_values'][k][rule_entry_index].netmask_packed(), mask)
                elif k == KZNL_ATTR_N_DIMENSION_SRC_PORT or k == KZNL_ATTR_N_DIMENSION_DST_PORT:
                    self.assertEqual(rule_entry_data['entry_values'][k][rule_entry_index], rule_entries[k])
                else:
                    self.assertEqual(rule_entry_data['entry_values'][k][rule_entry_index], rule_entries[k])

    def setup_service_dispatcher(self, services, dispatchers, add_zone = True, add_service = True):
        self._dumped_diszpancsers = []

        self.start_transaction()

        if add_zone:
            for zone in self._zones:
                self.send_add_zone_message(zone)

        if add_service:
            for service in services:
                if type(service) == types.DictType:
                    service = service['name']
                self.send_message(KZorpAddProxyServiceMessage(service))

        for dispatcher in dispatchers:
            message_add_dispatcher = KZorpAddDispatcherMessage(dispatcher['name'],
                                                               dispatcher['num_rules']
                                                              )

            self.send_message(message_add_dispatcher, error_handler=lambda res: os.strerror(res)+" "+str(message_add_dispatcher))

            for rule in dispatcher['rules']:
                _max = 0
                for name, value in rule['entry_nums'].items():
                    if _max < value:
                        _max = value

                message_add_rule = KZorpAddRuleMessage(dispatcher['name'],
                                                       rule['rule_id'],
                                                       rule['service'],
                                                       rule['entry_nums']
                                                       )
                self.send_message(message_add_rule)

                for i in range(_max):
                    data = {}
                    for dim_type in N_DIMENSION_ATTRS:
                        if dim_type in rule['entry_nums'] and rule['entry_nums'][dim_type] > i:
                            if dim_type in [KZNL_ATTR_N_DIMENSION_SRC_IP, KZNL_ATTR_N_DIMENSION_DST_IP, KZNL_ATTR_N_DIMENSION_SRC_IP6, KZNL_ATTR_N_DIMENSION_DST_IP6]:
                                subnet = rule['entry_values'][dim_type][i]
                                data[dim_type] = (subnet.addr_packed(), subnet.netmask_packed())
                            else:
                                data[dim_type] = rule['entry_values'][dim_type][i]
                    message_add_rule_entry = KZorpAddRuleEntryMessage(dispatcher['name'], rule['rule_id'], data)

                    self.send_message(message_add_rule_entry)

        self.end_transaction()

class KZorpTestCaseDispatchers(KZorpBaseTestCaseDispatchers, KZorpBaseTestCaseZones):
    _dispatchers = [
                     { 'name' : 'n_dimension', 'num_rules' : 1,
                       'rules' : [
                                   { 'rule_id' : 1, 'service' : 'A_A',
                                     'entry_nums' :
                                                 {
                                                   KZNL_ATTR_N_DIMENSION_DST_PORT : 2,
                                                   KZNL_ATTR_N_DIMENSION_SRC_ZONE : 2

                                                 },
                                     'entry_values' :
                                                 {
                                                   KZNL_ATTR_N_DIMENSION_DST_PORT : [(12,12), (23, 44)],
                                                   KZNL_ATTR_N_DIMENSION_SRC_ZONE : ["AAA", "ZZZ"]
                                                 }
                                   }
                                 ]
                     },
                     { 'name' : 'n_dimension_with_rules', 'num_rules' : 3,
                       'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                     'entry_nums'   : { KZNL_ATTR_N_DIMENSION_DST_PORT : 1 },
                                     'entry_values' : { KZNL_ATTR_N_DIMENSION_DST_PORT : [(5,6)] }
                                   },
                                   { 'rule_id'      : 2, 'service' : 'A_A',
                                     'entry_nums'   : { KZNL_ATTR_N_DIMENSION_IFACE : 2, KZNL_ATTR_N_DIMENSION_DST_PORT : 3 },
                                     'entry_values' : { KZNL_ATTR_N_DIMENSION_IFACE : ['eth0', 'eth1'], KZNL_ATTR_N_DIMENSION_DST_PORT : [(3,3), (4,4), (50000,65534)]}
                                   },
                                   { 'rule_id'      : 3, 'service' : 'A_A',
                                     'entry_nums'   : { KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, KZNL_ATTR_N_DIMENSION_SRC_ZONE : 4, KZNL_ATTR_N_DIMENSION_DST_PORT : 2 },
                                     'entry_values' : { KZNL_ATTR_N_DIMENSION_SRC_PORT : [(1,2)], KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['AAA', 'AZA', 'AA', 'A'], KZNL_ATTR_N_DIMENSION_DST_PORT : [(10000,10000), (20000, 30000)] }
                                   }
                                 ]
                     },
                     { 'name' : 'n_dimension_with_ALL_rules', 'num_rules' : 2,
                       'rules' : [ { 'rule_id'      : 1, 'service' : 'Z_Z',
                                     'entry_nums'   : { KZNL_ATTR_N_DIMENSION_IFACE : 2, KZNL_ATTR_N_DIMENSION_PROTO : 1, KZNL_ATTR_N_DIMENSION_SRC_PORT : 2, KZNL_ATTR_N_DIMENSION_DST_PORT : 1, KZNL_ATTR_N_DIMENSION_SRC_IP : 2, KZNL_ATTR_N_DIMENSION_SRC_ZONE : 3, KZNL_ATTR_N_DIMENSION_DST_IP : 2, KZNL_ATTR_N_DIMENSION_DST_ZONE : 1, KZNL_ATTR_N_DIMENSION_IFGROUP : 1},
                                     'entry_values' : { KZNL_ATTR_N_DIMENSION_IFACE : ['eth4', 'eth2'], KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], KZNL_ATTR_N_DIMENSION_SRC_PORT : [(2,3), (4,5)], KZNL_ATTR_N_DIMENSION_DST_PORT : [(5,6)], KZNL_ATTR_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.4'), InetDomain('2.3.4.5/24')], KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['ZZZ', 'ZZ', 'Z'], KZNL_ATTR_N_DIMENSION_DST_IP : [InetDomain('3.4.5.6/16'), InetDomain('4.5.6.7/8')], KZNL_ATTR_N_DIMENSION_DST_ZONE : 'AAA', KZNL_ATTR_N_DIMENSION_IFGROUP : [1]},
                                   },
                                   { 'rule_id'      : 2, 'service' : 'Z_Z',
                                     'entry_nums'   : { KZNL_ATTR_N_DIMENSION_DST_ZONE : 2, KZNL_ATTR_N_DIMENSION_DST_IP : 3, KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1, KZNL_ATTR_N_DIMENSION_SRC_IP : 2, KZNL_ATTR_N_DIMENSION_DST_PORT : 2, KZNL_ATTR_N_DIMENSION_SRC_PORT : 2, KZNL_ATTR_N_DIMENSION_PROTO : 1, KZNL_ATTR_N_DIMENSION_IFACE : 3 },
                                     'entry_values' : { KZNL_ATTR_N_DIMENSION_DST_ZONE : ['AZA', 'ZAZ'], KZNL_ATTR_N_DIMENSION_DST_IP : [InetDomain('8.7.6.5'), InetDomain('7.6.5.4/31'), InetDomain('9.8.7.6/25')], KZNL_ATTR_N_DIMENSION_SRC_ZONE : 'ZZ', KZNL_ATTR_N_DIMENSION_SRC_IP : [InetDomain('5.4.3.2/32'), InetDomain('6.5.4.3/30')], KZNL_ATTR_N_DIMENSION_DST_PORT : [(66,66),(100,200)], KZNL_ATTR_N_DIMENSION_SRC_PORT : [(23,24), (30, 40)], KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], KZNL_ATTR_N_DIMENSION_IFACE : ['eth0', 'eth1', 'eth2'] }
                                   }
                                 ]
                     }

                   ]

    _services_tmp = [
                      {'dispatcher_name' : 'n_dimension',   'name' : 'A_A', 'czone' : 'A', 'szone' : 'A'},
                      {'dispatcher_name' : 'n_dimension_2', 'name' : 'Z_Z', 'czone' : 'Z', 'szone' : 'Z'}
                    ]

    def __init__(self, *args):
        KZorpBaseTestCaseDispatchers.__init__(self, *args)
        KZorpBaseTestCaseZones.__init__(self, *args)

        self._add_dispatcher_messages = []
        self._add_dispatcher_message = None
        self._index = -1

    def setUp(self):
        self.setup_service_dispatcher(self._services_tmp, self._dispatchers)

    def tearDown(self):
        self.flush_all()
        pass

    def test_get_4k_dispatcher(self):
        services = ['A_A']
        _iface_num = 300
        _iface_list = []
        _iface_string = "abcdefghijklmno"
        for i in range(_iface_num):
            _iface_list.append(_iface_string)

        dispatchers = [{ 'name' : 'n_dimension_4k', 'num_rules' : 1,
                         'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { KZNL_ATTR_N_DIMENSION_IFACE : _iface_num, KZNL_ATTR_N_DIMENSION_PROTO : 1, KZNL_ATTR_N_DIMENSION_SRC_PORT : 2, KZNL_ATTR_N_DIMENSION_DST_PORT : 1, KZNL_ATTR_N_DIMENSION_SRC_IP : 2, KZNL_ATTR_N_DIMENSION_SRC_ZONE : 3, KZNL_ATTR_N_DIMENSION_DST_IP : 2, KZNL_ATTR_N_DIMENSION_DST_ZONE : 1, KZNL_ATTR_N_DIMENSION_IFGROUP : 1},
                                       'entry_values' : { KZNL_ATTR_N_DIMENSION_IFACE : _iface_list, KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], KZNL_ATTR_N_DIMENSION_SRC_PORT : [(2,3), (4,5)], KZNL_ATTR_N_DIMENSION_DST_PORT : [(5,6)], KZNL_ATTR_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.4'), InetDomain('2.3.4.5/24')], KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['ZZZ', 'ZZ', 'Z'], KZNL_ATTR_N_DIMENSION_DST_IP : [InetDomain('3.4.5.6/16'), InetDomain('4.5.6.7/8')], KZNL_ATTR_N_DIMENSION_DST_ZONE : 'AAA', KZNL_ATTR_N_DIMENSION_IFGROUP : [1]},
                                     }
                                   ]
                     }]

        self.setup_service_dispatcher(services, dispatchers, False, False);
        self.send_message(KZorpGetDispatcherMessage("n_dimension_4k"), message_handler = self._get_dispatchers_message_handler)
        self._check_dispatcher_params(self._add_dispatcher_messages[0], dispatchers[0])
        self._check_ndim_params(dispatchers)

    def test_n_dimension_errors(self):
        error_dup_dispatchers=[
                            { 'name' : 'n_dimension_error', 'num_rules' : 0,
                            },

                            { 'name' : 'n_dimension_error2', 'num_rules' : 2,
                              'rules' : [{ 'rule_id' : 1, 'service' : 'A_A',
                                           'entry_nums' : { KZNL_ATTR_N_DIMENSION_IFACE : 2},
                                           'errno' : 0
                                         }
                                        ]
                            }
                          ]
        error_num_rules_dispatchers=[
                            { 'name' : 'n_dimension_error3', 'num_rules' : 1,
                              'rules' : [{ 'rule_id' : 2, 'service' : 'A_A',
                                           'entry_nums' : { KZNL_ATTR_N_DIMENSION_IFACE : 2},
                                           'errno' : 0
                                         },
                                         { 'rule_id' : 3, 'service' : 'A_A',
                                           'entry_nums' : { KZNL_ATTR_N_DIMENSION_IFACE : 2},
                                           'errno' : -errno.EINVAL
                                         }
                                        ]
                            },
                            { 'name' : 'n_dimension_error4', 'num_rules' : 1,
                              'rules' : [{ 'rule_id' : 3, 'service' : 'A_A',
                                           'entry_nums' : { KZNL_ATTR_N_DIMENSION_IFACE : 2},
                                           #FIXME: this shouldbe: -errno.EEXIST
                                           'errno' : 0
                                         }
                                        ]
                            }
                          ]
        error_num_rule_entries=[
                            { 'name' : 'n_dimension_error5', 'num_rules' : 8,
                              'rules' : [{ 'rule_id' : 4, 'service' : 'A_A',
                                           'entry_nums'   : { KZNL_ATTR_N_DIMENSION_IFACE : 1 },
                                           'entry_values' : { KZNL_ATTR_N_DIMENSION_IFACE : ['eth4', 'eth2'] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 5, 'service' : 'A_A',
                                           'entry_nums'   : { KZNL_ATTR_N_DIMENSION_PROTO : 1 },
                                           'entry_values' : { KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP, socket.IPPROTO_UDP] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 6, 'service' : 'A_A',
                                           'entry_nums'   : { KZNL_ATTR_N_DIMENSION_SRC_PORT : 1 },
                                           'entry_values' : { KZNL_ATTR_N_DIMENSION_SRC_PORT : [(1,1), (2,2)] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 7, 'service' : 'A_A',
                                           'entry_nums'   : { KZNL_ATTR_N_DIMENSION_DST_PORT : 1 },
                                           'entry_values' : { KZNL_ATTR_N_DIMENSION_DST_PORT : [(3,3),(4,5)] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 8, 'service' : 'A_A',
                                           'entry_nums'   : { KZNL_ATTR_N_DIMENSION_SRC_IP : 1 },
                                           'entry_values' : { KZNL_ATTR_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.4'), InetDomain('2.3.4.5')] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 9, 'service' : 'A_A',
                                           'entry_nums'   : { KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1 },
                                           'entry_values' : { KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['ZZZ', 'ZZ'] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 10, 'service' : 'A_A',
                                           'entry_nums'   : { KZNL_ATTR_N_DIMENSION_DST_IP : 1 },
                                           'entry_values' : { KZNL_ATTR_N_DIMENSION_DST_IP : [InetDomain('3.4.5.6'), InetDomain('4.5.6.7')] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 11, 'service' : 'A_A',
                                           'entry_nums'   : { KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                           'entry_values' : { KZNL_ATTR_N_DIMENSION_DST_ZONE : ['AAA', 'AA']},
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         }
                                        ]
                            }
                           ]

        error_zones_exist=[
                            { 'name' : 'n_dimension_error6', 'num_rules' : 2,
                              'rules' : [{ 'rule_id' : 12, 'service' : 'A_A',
                                           'entry_nums'   : { KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1 },
                                           'entry_values' : { KZNL_ATTR_N_DIMENSION_SRC_ZONE : 'BBB' },
                                           'rule_entry_errnos' : [-errno.ENOENT]
                                         },
                                         { 'rule_id' : 13, 'service' : 'A_A',
                                           'entry_nums'   : { KZNL_ATTR_N_DIMENSION_DST_ZONE : 1 },
                                           'entry_values' : { KZNL_ATTR_N_DIMENSION_DST_ZONE : 'CCC' },
                                           'rule_entry_errnos' : [-errno.ENOENT]
                                         }
                                        ]
                            }
                          ]

        #Check add_dispatcher without starting a transaction
        dispatcher = error_dup_dispatchers[0]
        message_add_dispatcher = KZorpAddDispatcherMessage(dispatcher['name'],
                                                           dispatcher['num_rules']
                                                          )

        res = self.send_message(message_add_dispatcher, assert_on_error = False)
        self.assertEqual(res, -errno.ENOENT)

        #check duplicated add_dispatcher
        self.start_transaction()
        message_add_dispatcher = KZorpAddDispatcherMessage(dispatcher['name'],
                                                           dispatcher['num_rules']
                                                           )
        res = self.send_message(message_add_dispatcher, assert_on_error = False)
        self.assertEqual(res, 0)
        res = self.send_message(message_add_dispatcher, assert_on_error = False)
        self.assertEqual(res, -errno.EEXIST)
        self.end_transaction()

        #check if num_rules > number of rule_entries
        dispathcer = error_dup_dispatchers[1]
        self.start_transaction()
        message_add_dispatcher = KZorpAddDispatcherMessage(dispatcher['name'],
                                                           dispatcher['num_rules']
                                                           )
        res = self.send_message(message_add_dispatcher, assert_on_error = False)
        self.assertEqual(res, 0)
        self.end_transaction()

        #check if num_rules < number of rule entries, check adding existing rule_id
        self.start_transaction()

        for i in range(len(error_num_rules_dispatchers)):
            dispatcher = error_num_rules_dispatchers[i]
            message_add_dispatcher = KZorpAddDispatcherMessage(dispatcher['name'],
                                                               dispatcher['num_rules']
                                                              )
            res = self.send_message(message_add_dispatcher, assert_on_error = False)

            for rule in dispatcher['rules']:
                message_add_rule = KZorpAddRuleMessage(dispatcher['name'],
                                                       rule['rule_id'],
                                                       rule['service'],
                                                       rule['entry_nums']
                                                      )
                res = self.send_message(message_add_rule, assert_on_error = False)
                if 'errno' in rule:
                    self.assertEqual(res, rule['errno'])
        self.end_transaction()

        #check if entry_nums < number of entry_values
        self.start_transaction()

        for i in range(len(error_num_rule_entries)):
            dispatcher = error_num_rule_entries[i]
            message_add_dispatcher = KZorpAddDispatcherMessage(dispatcher['name'],
                                                               dispatcher['num_rules']
                                                              )
            res = self.send_message(message_add_dispatcher, assert_on_error = False)

            for rule in dispatcher['rules']:
                _max = 2
                message_add_rule = KZorpAddRuleMessage(dispatcher['name'],
                                                        rule['rule_id'],
                                                        rule['service'],
                                                        rule['entry_nums']
                                                       )
                res = self.send_message(message_add_rule, assert_on_error = False)
                if 'errno' in rule:
                    self.assertEqual(res, rule['errno'])
                for i in range(_max):
                    data = {}
                    for dim_type in N_DIMENSION_ATTRS:
                        if dim_type in rule['entry_nums']:
                            if dim_type in [KZNL_ATTR_N_DIMENSION_SRC_IP, KZNL_ATTR_N_DIMENSION_DST_IP, KZNL_ATTR_N_DIMENSION_SRC_IP6, KZNL_ATTR_N_DIMENSION_DST_IP6]:
                                data[dim_type] = (rule['entry_values'][dim_type][i].addr_packed(), rule['entry_values'][dim_type][i].netmask_packed())
                            else:
                                data[dim_type] = rule['entry_values'][dim_type][i]
                    message_add_rule_entry = KZorpAddRuleEntryMessage(dispatcher['name'], rule['rule_id'], data)
                    res = self.send_message(message_add_rule_entry, assert_on_error = False)
                    self.assertEqual(res, rule['rule_entry_errnos'][i])

        self.end_transaction()

        self.start_transaction()
        #check zones exist
        for i in range(len(error_zones_exist)):
            dispatcher = error_zones_exist[i]
            message_add_dispatcher = KZorpAddDispatcherMessage(dispatcher['name'],
                                                               dispatcher['num_rules']
                                                              )
            res = self.send_message(message_add_dispatcher, assert_on_error = False)

            for rule in dispatcher['rules']:
                _max = 1
                message_add_rule = KZorpAddRuleMessage(dispatcher['name'],
                                                        rule['rule_id'],
                                                        rule['service'],
                                                        rule['entry_nums']
                                                       )
                res = self.send_message(message_add_rule, assert_on_error = False)
                if 'errno' in rule:
                    self.assertEqual(res, rule['errno'])
                for i in range(_max):
                    data = {}
                    for dim_type in N_DIMENSION_ATTRS:
                        if dim_type in rule['entry_nums']:
                            if dim_type == KZNL_ATTR_N_DIMENSION_SRC_IP or dim_type == KZNL_ATTR_N_DIMENSION_DST_IP:
                                data[dim_type] = (struct.pack('I', rule['entry_values'][dim_type][i].ip), struct.pack('I', rule['entry_values'][dim_type][i].mask))
                            else:
                                data[dim_type] = rule['entry_values'][dim_type][i]
                    message_add_rule_entry = KZorpAddRuleEntryMessage(dispatcher['name'], rule['rule_id'], data)
                    res = self.send_message(message_add_rule_entry, assert_on_error = False)
                    self.assertEqual(res, rule['rule_entry_errnos'][i])

        self.end_transaction()

    def test_add_dispatcher(self):
        #set up and ter down test the dispatcher addition
        num_rules = 0
        num_rule_entries = 0
        for dispatcher in self._dispatchers:
            for rule in dispatcher['rules']:
                num_rules = num_rules + 1
                _max = 0
                for name, value in rule['entry_nums'].items():
                    if _max < value:
                        _max = value
                num_rule_entries = num_rule_entries + _max

        self.check_dispatcher_num(num_rules + num_rule_entries + len(self._dispatchers))

    def test_get_dispatcher_by_name(self):
        #get a not existent dispatcher
        res = self.send_message(KZorpGetDispatcherMessage('nonexistentdispatchername'), assert_on_error = False)
        self.assertEqual(res, -errno.ENOENT)

    def _get_dispatchers_message_handler(self, msg):
        self._add_dispatcher_messages.append(msg)

    def _check_ndim_params(self, dispatchers):
        rule_entry_dispatcher_name = ""
        for add_dispatcher_message in self._add_dispatcher_messages:
            attrs = add_dispatcher_message.get_attributes()

            command = add_dispatcher_message.command
            if (command == KZNL_MSG_ADD_DISPATCHER or command == KZNL_MSG_ADD_RULE):
                dispatcher_name = parse_name_attr(attrs[KZNL_ATTR_DPT_NAME])

            for i in range(len(dispatchers)):
                if command == KZNL_MSG_ADD_DISPATCHER and dispatcher_name == dispatchers[i]['name']:
                    rule_index = 0
                    self._check_dispatcher_params(add_dispatcher_message, dispatchers[i])
                    break
                elif command == KZNL_MSG_ADD_RULE and dispatcher_name == dispatchers[i]['name']:
                    self._check_add_rule_params(add_dispatcher_message, dispatchers[i]['rules'][rule_index])
                    rule_entry_dispatcher_name = dispatcher_name
                    rule_index = rule_index + 1
                    rule_entry_index = 0
                    break
                elif command == KZNL_MSG_ADD_RULE_ENTRY and dispatchers[i]['name'] == rule_entry_dispatcher_name:
                    self._check_add_rule_entry_params(add_dispatcher_message, dispatchers[i]['rules'][rule_index - 1], rule_entry_index)
                    rule_entry_index = rule_entry_index + 1
                    break
            else:
                self.assert_(True, "dispatcher with name %s could not find in the dump") #% self.get_dispatcher_name(add_dispatcher_message))


    def test_get_dispatcher_with_dump(self):
        #get the dump of dispatchers
        self.send_message(KZorpGetDispatcherMessage(None), message_handler = self._get_dispatchers_message_handler, dump = True)
        self._check_ndim_params(self._dispatchers)
        #self.assertEqual(len(self._add_dispatcher_messages), len(self._dispatchers))


class KZorpBaseTestCaseQuery(KZorpBaseTestCaseDispatchers, KZorpBaseTestCaseZones):

    _object_count = 0

    def __init__(self, *args):
        KZorpBaseTestCaseDispatchers.__init__(self, *args)
        KZorpBaseTestCaseZones.__init__(self, *args)

        self._initialized = False

        self._dumped_diszpancsers = []

        if (KZorpBaseTestCaseQuery._object_count == 0):
            self.initialize()
        KZorpBaseTestCaseQuery._object_count += 1

    def __del__(self):
        KZorpBaseTestCaseQuery._object_count -= 1
        if (KZorpBaseTestCaseQuery._object_count == 0):
            self.deinitialize()

    def initialize(self):
        os.system('modprobe dummy numdummies=6')
        os.system('ifconfig dummy0 10.99.201.1 netmask 255.255.255.0')
        os.system('ifconfig dummy1 10.99.202.2 netmask 255.255.255.0')
        os.system('ifconfig dummy2 10.99.203.3 netmask 255.255.255.0')
        os.system('ifconfig dummy3 10.99.204.4 netmask 255.255.255.0')
        os.system('ifconfig dummy4 10.99.205.5 netmask 255.255.255.0')
        os.system('ifconfig dummy5 10.99.205.6 netmask 255.255.255.0')
        os.system('echo 0x1 > /sys/class/net/dummy3/netdev_group')
        os.system('echo 0x1 > /sys/class/net/dummy4/netdev_group')
        os.system('echo 0x2 > /sys/class/net/dummy0/netdev_group')

    def deinitialize(self):
        os.system('rmmod dummy')

    def get_dispatcher_attrs(self, message):
        attrs = message.get_attributes()
        return attrs

    def get_service_name(self, message):
        return message.service

    def get_client_zone_name(self, message):
        attrs = message.get_attributes()
        client_zone = "not found"
        if attrs.has_key(KZNL_ATTR_QUERY_CLIENT_ZONE):
            client_zone = parse_name_attr(attrs[KZNL_ATTR_QUERY_CLIENT_ZONE])
        return client_zone

    def get_server_zone_name(self, message):
        attrs = message.get_attributes()
        server_zone = "not found"
        if attrs.has_key(KZNL_ATTR_QUERY_SERVER_ZONE):
            server_zone = parse_name_attr(attrs[KZNL_ATTR_QUERY_SERVER_ZONE])
        return server_zone

    def _query_message_handler(self, msg):
        self._dumped_diszpancsers.append(msg)


class KZorpTestCaseQueryNDim(KZorpBaseTestCaseQuery):

    def __init__(self, *args):
        KZorpBaseTestCaseQuery.__init__(self, *args)

    def tearDown(self):
        self.flush_all()

    def _run_query2(self, queries):
        for query in queries:
            family = query['family']
            message_query = KZorpQueryMessage(proto = query['proto'],
                                              family = family,
                                              saddr = socket.inet_pton(family, query['saddr']),
                                              sport = query['sport'],
                                              daddr = socket.inet_pton(family, query['daddr']),
                                              dport = query['dport'],
                                              iface = query['iface'])
            self.send_message(message_query, message_handler =
                            lambda msg: self.assertEqual(self.get_service_name(msg), query['service'], "Expected: %s, got %s for query %s" % (str(query['service']), str(self.get_service_name(msg)), str(query))))

    def _run_query(self, _queries, _answers):
        for query in _queries:
            family = query['family']
            message_query = KZorpQueryMessage(proto = query['proto'],
                                              family = query['family'],
                                              saddr = socket.inet_pton(family, query['saddr']),
                                              sport = query['sport'],
                                              daddr = socket.inet_pton(family, query['daddr']),
                                              dport = query['dport'],
                                              iface = query['iface'])
            self.send_message(message_query, message_handler = self._query_message_handler)

        for i in range(len(_answers)):
            self.assertEqual(self.get_service_name(self._dumped_diszpancsers[i]), _answers[i])

class KZorpBaseTestCaseBind(KZorpComm):

    _bind_addrs = [
                    { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.1'), 'port' : 50080, 'proto' : socket.IPPROTO_UDP },
                    { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.1'), 'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                    { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.2'), 'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                    { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET6, 'addr' : socket.inet_pton(socket.AF_INET6, 'fec0::1'),   'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                    { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET6, 'addr' : socket.inet_pton(socket.AF_INET6, 'fec0::2'),   'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                    { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.1'), 'port' : 50081, 'proto' : socket.IPPROTO_TCP },
                  ]
    _dumped_bind_addrs = []

    _dumped_binds = []

    def setUp(self):
        self.start_transaction()
        for bind_addr in self._bind_addrs:
            msg_add_bind = KZorpAddBindMessage(**bind_addr)
            self.send_message(msg_add_bind)
        self.end_transaction()

    def tearDown(self):
        self.flush_all()

    def test_unicity_check_at_transaction(self):
        self.flush_all()
        self.start_transaction()
        for bind_addr in self._bind_addrs:
            msg_add_bind = KZorpAddBindMessage(**bind_addr)
            self.send_message(msg_add_bind)

            try:
                msg_add_bind = KZorpAddBindMessage(**bind_addr)
                self.send_message(msg_add_bind)
            except NetlinkException as e:
                if e.detail != -error.EEXIST:
                    raise e

        self.end_transaction()

    def test_unicity_check_at_instance(self):
        self.flush_all()
        self.start_transaction()
        for bind_addr in self._bind_addrs:
            msg_add_bind = KZorpAddBindMessage(**bind_addr)
            self.send_message(msg_add_bind)

        for bind_addr in self._bind_addrs:
            try:
                msg_add_bind = KZorpAddBindMessage(**bind_addr)
                self.send_message(msg_add_bind)
            except NetlinkException as e:
                if e.detail != -error.EEXIST:
                    raise e

        self.end_transaction()

    def _dump_bind_handler(self, message):
        self._dumped_binds.append(message)

    def get_bind(self):
        msg_get_bind = KZorpGetBindMessage()
        self.send_message(msg_get_bind, message_handler = self._dump_bind_handler, dump = True)

    def test_flush(self):
        self.flush_all()

        self._dumped_binds = []
        self.get_bind()

        self.assertEqual(len(self._dumped_binds), 0, "bind list not empty after flush; bind_num='%d'" % len(self._dumped_binds))

    def test_add(self):
        self._dumped_binds = []
        self.get_bind()

        self.assertEqual(len(self._dumped_binds), len(self._bind_addrs))

        for i in range(len(self._bind_addrs)):
            msg_add_bind = KZorpAddBindMessage(**self._bind_addrs[i])
            self.assertEqual(vars(msg_add_bind), vars(self._dumped_binds[i]))

    def test_auto_flush(self):
        bind_addr_num = len(self._bind_addrs)
        self._dumped_binds = []
        self.get_bind()

        # check binds set up with the original handle
        self.assertEqual(len(self._dumped_binds), len(self._bind_addrs))
        for i in range(bind_addr_num):
            msg_add_bind = KZorpAddBindMessage(**self._bind_addrs[i])
            self.assertEqual(vars(msg_add_bind), vars(self._dumped_binds[i]))

        # set up a new set of binds with a new handle
        orig_handle = self.handle
        self.handle = None
        self.create_handle()

        for bind_addr in self._bind_addrs:
            bind_addr["port"] += 1000

        self.setUp()

        for bind_addr in self._bind_addrs:
            bind_addr["port"] -= 1000

        self._dumped_binds = []
        self.get_bind()

        self.assertEqual(len(self._dumped_binds), len(self._bind_addrs) * 2)

        # close new handle and check if only the binds of the original handle remain
        self.close_handle()
        self.handle = orig_handle

        self._dumped_binds = []
        self.get_bind()

        self.assertEqual(len(self._dumped_binds), len(self._bind_addrs))
        for i in range(bind_addr_num):
            msg_add_bind = KZorpAddBindMessage(**self._bind_addrs[i])
            self.assertEqual(vars(msg_add_bind), vars(self._dumped_binds[i]))

        self.reopen_handle()

        self._dumped_binds = []
        self.get_bind()
        self.assertEqual(len(self._dumped_binds), 0)

class KZorpTestCaseGetVersion(KZorpComm):
    def _get_version_message_handler(self, msg):
        self._major_version = msg.major
        self._compat_version = msg.compat

    def setUp(self):
        get_version_message = KZorpGetVersionMessage()
        self.send_message(get_version_message, message_handler = self._get_version_message_handler)

    def test_get_version():
        self.assertEqual(self._major_version, 4)
        self.assertEqual(self._compat_version, 5)

class KZorpTestCaseDeleteZone(KZorpBaseTestCaseZones):
        def setUp(self):
            self.test_parent_zone_name = 'parent'
            self.test_child_zone_name = 'child'

            self.start_transaction()
            add_zone_message = KZorpAddZoneMessage(self.test_parent_zone_name)
            self.send_message(add_zone_message)
            add_zone_message = KZorpAddZoneMessage(self.test_child_zone_name, pname = self.test_parent_zone_name)
            self.send_message(add_zone_message)
            self.end_transaction()

        def _check_rest_zones_after_child_zone_delete(self):
            self.check_zone_num(1)

            message_updated_zone = self._dumped_zones[0]
            self.assertEqual(message_updated_zone.name, self.test_parent_zone_name)

        def _check_rest_zones_after_parent_zone_delete(self):
            self.check_zone_num(0)

        def _delete_one_zone(self, name, check_rest_zones_after_delete = None):
            self.start_transaction()
            self.send_message(KZorpDeleteZoneMessage(name))
            self.end_transaction()

            if check_rest_zones_after_delete is not None:
                check_rest_zones_after_delete()

        def test_delete_in_right_order(self):
            self._delete_one_zone(self.test_child_zone_name, self._check_rest_zones_after_child_zone_delete)
            self._delete_one_zone(self.test_parent_zone_name, self._check_rest_zones_after_parent_zone_delete)

        def test_parent_delete_before_child(self):
            with self.assertRaises(NetlinkException) as cm:
                self._delete_one_zone(self.test_parent_zone_name)
            self.assertEqual(cm.exception.detail, -errno.EINVAL)

        def test_delete_nonexistant_zone(self):
            with self.assertRaises(NetlinkException) as cm:
                self._delete_one_zone('noneexistantzonename')
            self.assertEqual(cm.exception.detail, -errno.ENOENT)

        def test_delete_zone_twice(self):
            with self.assertRaises(NetlinkException) as cm:
                self.start_transaction()
                self.send_message(KZorpDeleteZoneMessage(self.test_child_zone_name))
                self.send_message(KZorpDeleteZoneMessage(self.test_child_zone_name))
                self.end_transaction()
            self.assertEqual(cm.exception.detail, -errno.EINVAL)

        def tearDown(self):
            self.flush_all()

if __name__ == "__main__":

    if os.getenv("USER") != "root":
        print "ERROR: You need to be root to run the unit test"
        sys.exit(1)

    if glob.glob('/var/run/zorp/*.pid'):
        print "ERROR: pidfile(s) exist in /var/run/zorp directory. Zorp is running?"
        print "       You should stop Zorp and/or delete pid files from /var/run/zorp"
        print "       in order to run this test."
        sys.exit(1)

    unittest.main()
