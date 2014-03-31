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

"""
<module maturity="stable">
  <summary>
    Module defining interface to the Zorp core entry points.
  </summary>
  <description>
    <para>
      This module defines global constants (e.g., <parameter>TRUE</parameter> and
      <parameter>FALSE</parameter>) used by other Zorp components, and interface
      entry points to the Zorp core.
    </para>
  </description>
  <metainfo>
    <enums>
      <enum maturity="stable" id="enum.zorp.z">
        <description>
          Values returned by event handlers.
        </description>
        <item><name>ZV_UNSPEC</name></item>
        <item><name>ZV_ACCEPT</name></item>
        <item><name>ZV_DENY</name></item>
        <item><name>ZV_REJECT</name></item>
        <item><name>ZV_ABORT</name></item>
        <item><name>ZV_DROP</name></item>
        <item><name>ZV_POLICY</name></item>
      </enum>
     <enum maturity="stable" id="zorp.proto.id">
        <description>
          The network protocol used in the server-side connection.
        </description>
        <item>
          <name>ZD_PROTO_AUTO</name>
          <description>
            Use the protocol that is used on the client side.
          </description>
        </item>
        <item>
          <name>ZD_PROTO_TCP</name>
          <description>
            Use the TCP protocol on the server side.
          </description>
        </item>
        <item>
          <name>ZD_PROTO_UDP</name>
          <description>
            Use the UDP protocol on the server side.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.zorp.forge_port">
      <description>
        Options defining the source port of the server-side connection.
      </description>
      <item>
        <name>Z_PORT_ANY</name>
        <description>
          Selected a random port between 1024
              and 65535. This is the default behavior of every router.
        </description>
      </item>
      <item>
        <name>Z_PORT_GROUP</name>
        <description>
          Select a random port in the same group as the port used by
          the client. The following groups are defined:
          <parameter>0-513</parameter>, <parameter>514-1024</parameter>,
          <parameter>1025-</parameter>.
        </description>
      </item>
      <item>
        <name>Z_PORT_EXACT</name>
        <description>
          Use the same port as the client.
        </description>
      </item>
      <item>
        <name>Z_PORT_RANDOM</name>
        <description>
          Select a random port using a cryptographically secure function.
        </description>
      </item>
      </enum>
      <enum maturity="stable" id="enum.zorp.bacl">
        <description>basic acl tags</description>
        <item><name>Z_BACL_REQUIRED</name></item>
        <item><name>Z_BACL_SUFFICIENT</name></item>
      </enum>
      <enum maturity="stable" id="enum.zorp.af">
        <description>address families</description>
        <item><name>AF_UNSPEC</name></item>
        <item><name>AF_INET</name></item>
        <item><name>AF_INET6</name></item>
      </enum>
      <enum maturity="stable" id="enum.zorp.stack">
        <description></description>
        <item><name>Z_STACK_PROXY</name></item>
        <item><name>Z_STACK_PROGRAM</name></item>
        <item><name>Z_STACK_REMOTE</name></item>
        <item><name>Z_STACK_PROVIDER</name></item>
        <item><name>Z_STACK_PROXY_IN_SESSION</name></item>
      </enum>
      <enum maturity="stable" id="enum.zorp.logical">
        <description>logical operators</description>
        <item><name>Z_NOT</name></item>
        <item><name>Z_AND</name></item>
        <item><name>Z_OR</name></item>
        <item><name>Z_XOR</name></item>
        <item><name>Z_EQ</name></item>
        <item><name>Z_NE</name></item>
      </enum>
    </enums>
    <actiontuples>
      <actiontuple maturity="stable" id="action.zorp.stack" action_enum="enum.zorp.stack">
        <description>
        Stacking options.
        </description>
        <tuple action="Z_STACK_PROXY">
          <args>
            <class filter="proxy"/>
          </args>
          <description>
          Stack a proxy.
          </description>
        </tuple>
        <tuple action="Z_STACK_PROGRAM">
          <args>
            <string/>
          </args>
          <description>
          Stack an external program.
          </description>
        </tuple>
        <tuple action="Z_STACK_REMOTE">
          <args>
            <tuple>
              <sockaddr/>
              <string/>
            </tuple>
          </args>
          <description>
          Stack a remote destination.
          </description>
        </tuple>
        <tuple action="Z_STACK_PROVIDER">
          <args>
            <tuple>
              <class filter="stackingprov" existing="yes"/>
              <string/>
            </tuple>
          </args>
          <description>
          Stack a Stacking Provider.
          </description>
        </tuple>
      </actiontuple>
    </actiontuples>
    <constants>
      <constantgroup maturity="stable" id="const.zorp.glob">
        <description>global variables</description>
        <item><name>firewall_name</name><value>"zorp"</value></item>
      </constantgroup>
      <constantgroup maturity="stable" id="const.zorp.core">
        <description>Core message tags</description>
        <item><name>CORE_SESSION</name><value>"core.session"</value></item>
        <item><name>CORE_DEBUG</name><value>"core.debug"</value></item>
        <item><name>CORE_ERROR</name><value>"core.error"</value></item>
        <item><name>CORE_POLICY</name><value>"core.policy"</value></item>
        <item><name>CORE_MESSAGE</name><value>"core.message"</value></item>
        <item><name>CORE_AUTH</name><value>"core.auth"</value></item>
      </constantgroup>
    </constants>
  </metainfo>
</module>
"""

firewall_name = "zorp" # obsolete, not used anymore

import traceback
import sys
import errno
import socket
import Config

config = Config

import Common

CORE_SESSION = Common.CORE_SESSION
CORE_DEBUG = Common.CORE_DEBUG
CORE_ERROR = Common.CORE_ERROR
CORE_POLICY = Common.CORE_POLICY
CORE_MESSAGE = Common.CORE_MESSAGE
CORE_AUTH = Common.CORE_AUTH
CORE_INFO = Common.CORE_INFO
CORE_ALERTING = Common.CORE_ALERTING

# return values returned by event handlers
ZV_UNSPEC         = 0
ZV_ACCEPT         = 1
ZV_DENY           = 2
ZV_REJECT         = 3
ZV_ABORT          = 4
ZV_DROP           = 5
ZV_POLICY         = 6
ZV_ERROR          = 7

# Legacy names
Z_UNSPEC         = ZV_UNSPEC
Z_ACCEPT         = ZV_ACCEPT
Z_DENY           = ZV_DENY
Z_REJECT         = ZV_REJECT
Z_ABORT          = ZV_ABORT
Z_DROP           = ZV_DROP
Z_POLICY         = ZV_POLICY
Z_ERROR          = ZV_ERROR

# dispatched protocols
ZD_PROTO_AUTO = 0
ZD_PROTO_TCP  = 1
ZD_PROTO_UDP  = 2

ZD_PROTO_NAME = (
   "AUTO",    # ZD_PROTO_AUTO
   "TCP",     # ZD_PROTO_TCP
   "UDP",     # ZD_PROTO_UDP
)

# port allocation values
Z_PORT_ANY = -1
Z_PORT_GROUP = -2
Z_PORT_EXACT = -3
Z_PORT_RANDOM = -4

# basic acl tags
Z_BACL_REQUIRED = 1
Z_BACL_SUFFICIENT = 2

# stack types
Z_STACK_PROXY = 1
Z_STACK_PROGRAM = 2
Z_STACK_REMOTE = 3
Z_STACK_PROVIDER = 4
Z_STACK_CUSTOM = 5
Z_STACK_PROXY_IN_SESSION = 6

# proxy priorities
Z_PROXY_PRI_LOW = 0
Z_PROXY_PRI_NORMAL = 1
Z_PROXY_PRI_HIGH = 2
Z_PROXY_PRI_URGENT = 3

# boolean values
FALSE = 0
TRUE = 1

# address families
AF_UNSPEC = socket.AF_UNSPEC
AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6

# logical operators
Z_NOT  = "Z_NOT"
Z_AND  = "Z_AND"
Z_OR   = "Z_OR"
Z_XOR  = "Z_XOR"
Z_EQ   = "Z_EQ"
Z_NE   = "Z_XOR"

Z_SZIG_TYPE_LONG = 1
Z_SZIG_TYPE_TIME = 2
Z_SZIG_TYPE_STRING = 3
Z_SZIG_TYPE_PROPS = 4
Z_SZIG_TYPE_CONNECTION_PROPS = 5

Z_SZIG_THREAD_START = 0
Z_SZIG_THREAD_STOP = 1
Z_SZIG_TICK = 2
Z_SZIG_COUNTED_IP = 3
Z_SZIG_CONNECTION_PROPS = 4
Z_SZIG_CONNECTION_STOP = 5
Z_SZIG_AUDIT_START = 6
Z_SZIG_AUDIT_STOP = 7
Z_SZIG_RELOAD = 8
Z_SZIG_AUTH_PENDING_BEGIN = 9
Z_SZIG_AUTH_PENDING_FINISH = 10
Z_SZIG_SERVICE_COUNT = 11
Z_SZIG_CONNECTION_START = 12

Z_KEEPALIVE_NONE   = 0
Z_KEEPALIVE_CLIENT = 1
Z_KEEPALIVE_SERVER = 2
Z_KEEPALIVE_BOTH   = 3

Z_SSL_VERIFY_NONE               = 0
Z_SSL_VERIFY_OPTIONAL_UNTRUSTED = 1
Z_SSL_VERIFY_OPTIONAL_TRUSTED   = 2
Z_SSL_VERIFY_REQUIRED_UNTRUSTED = 3
Z_SSL_VERIFY_REQUIRED_TRUSTED   = 4

import Globals

def init(names, virtual_name, is_master):
    """
    <function internal="yes">
      <summary>
        Default init() function provided by Zorp
      </summary>
      <description>
        This function is a default <function>init()</function> calling the init function
        identified by the <parameter>name</parameter> argument. This way several Zorp
        instances can use the same policy file.
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>names</name>
            <type></type>
            <description>Names (instance name and also-as names) of this instance.</description>
          </attribute>
          <attribute maturity="stable">
            <name>virtual_name</name>
            <type>string</type>
            <description>
              Virtual instance name of this process. If a Zorp instance is backed by multiple
              Zorp processes using the same configuration each process has a unique virtual
              instance name that is used for SZIG communication, PID file creation, etc.
            </description>
          </attribute>
          <attribute>
            <name>is_master</name>
            <type>int</type>
            <description>
              TRUE if Zorp is running in master mode, FALSE for slave processes. Each Zorp instance
              should have exactly one master process and an arbitrary number of slaves.
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </function>
    """
    import __main__
    import SockAddr, KZorp, Matcher, Rule
    import kzorp.netlink
    import kzorp.communication
    import errno

    # miscelanneous initialization
    if config.audit.encrypt_certificate_file:
        try:
            config.audit.encrypt_certificate = open(config.audit.encrypt_certificate_file, 'r').read()
        except IOError:
            log(None, CORE_ERROR, 1, "Error reading audit encryption certificate; file='%s'", (config.audit.encrypt_certificate_file))

    if config.audit.encrypt_certificate_list_file:
        try:
            config.audit.encrypt_certificate_list = [ ]
            for list in config.audit.encrypt_certificate_list_file:
                newlist = [ ]
                for file in list:
                    try:
                        newlist.append( open(file, 'r').read() )
                    except IOError:
                        log(None, CORE_ERROR, 1, "Error reading audit encryption certificate; file='%s'", (file))
                config.audit.encrypt_certificate_list.append( newlist )
        except TypeError:
            log(None, CORE_ERROR, 1, "Error iterating encryption certificate file list;")

    if config.audit.encrypt_certificate_list == None and config.audit.encrypt_certificate:
        config.audit.encrypt_certificate_list = [ [ config.audit.encrypt_certificate ] ]

    if config.audit.sign_private_key_file:
        try:
            config.audit.sign_private_key = open(config.audit.sign_private_key_file, 'r').read()
        except IOError:
            log(None, CORE_ERROR, 1, "Error reading audit signature's private key; file='%s'", (config.audit.sign_private_key_file))

    if config.audit.sign_certificate_file:
        try:
            config.audit.sign_certificate = open(config.audit.sign_certificate_file, 'r').read()
        except IOError:
            log(None, CORE_ERROR, 1, "Error reading audit signature's certificate; file='%s'", (config.audit.sign_certificate_file))

    Globals.rules = Rule.RuleSet()

    if config.options.kzorp_enabled:
        # ping kzorp to see if it's there
        try:
            h = kzorp.communication.Handle()
            Globals.kzorp_available = True
        except:
            Globals.kzorp_available = False
            log(None, CORE_ERROR, 0, "Error pinging KZorp, it is probably unavailable; exc_value='%s'" % (sys.exc_value))

    Globals.instance_name = names[0]
    for i in names:
        try:
            func = getattr(__main__, i)
        except AttributeError:
            ## LOG ##
            # This message indicates that the initialization function of
            # the given instance was not found in the policy file.
            ##
            log(None, CORE_ERROR, 0, "Instance definition not found in policy; instance='%s'", (names,))
            return FALSE
        func()

    Matcher.validateMatchers()

    if Globals.kzorp_available:
        try:
            KZorp.downloadKZorpConfig(names[0], is_master)
        except:
            ## LOG ##
            # This message indicates that downloading the necessary information to the
            # kernel-level KZorp subsystem has failed.
            ##
            log(None, CORE_ERROR, 0, "Error downloading KZorp configuration, Python traceback follows; error='%s'" % (sys.exc_value))
            for s in traceback.format_tb(sys.exc_traceback):
                for l in s.split("\n"):
                    if l:
                        log(None, CORE_ERROR, 0, "Traceback: %s" % (l))

            # if kzorp did respond to the ping, the configuration is erroneous -- we die here so the user finds out
            return FALSE

    return TRUE


def deinit(names, virtual_name):
    """
    <function internal="yes">
    </function>
    """
    ## LOG ##
    # This message reports that the given instance is stopping.
    ##
    log(None, CORE_DEBUG, 6, "Deinitialization requested for instance; name='%s'", (names[0],))
    for i in Globals.deinit_callbacks:
        i()

def purge():
    """
    <function internal="yes">
    </function>
    """
    pass

def cleanup(names, virtual_name, is_master):
    """
    <function internal="yes">
    </function>
    """
    import KZorp
    ## LOG ##
    # This message reports that the given instance is freeing its external
    # resources (for example its kernel-level policy objects).
    ##
    log(None, CORE_DEBUG, 6, "Cleaning up instance; name='%s'", (names,))

    if is_master and Globals.kzorp_available and config.options.kzorp_enabled:
        try:
            KZorp.flushKZorpConfig(names[0])
        except:
            ## LOG ##
            # This message indicates that flushing the instance-related information in the
            # kernel-level KZorp subsystem has failed.
            ##
            log(None, CORE_ERROR, 0, "Error flushing KZorp configuration; error='%s'" % (sys.exc_value))
            for s in traceback.format_tb(sys.exc_traceback):
                for l in s.split("\n"):
                    if l:
                        log(None, CORE_ERROR, 4, "Traceback: %s" % (l))

def notify(event, params):
    """<function internal="yes">
    </function>
    """
    if Globals.notification_policy:
        return Globals.notification_policy.notify(event, params)



## NOLOG ##

def log(sessionid, logclass, verbosity, msg, args=None):
    """
    <function maturity="stable">
      <summary>
        Function to send a message to the system log.
      </summary>
      <description>
        <para>
          This function can be used to send a message to the system log.
        </para>
      </description>
      <metainfo>
        <arguments>
          <argument>
           <name>sessionid</name>
           <type><string/></type>
           <description>The ID of the session the message belongs to.</description>
          </argument>
          <argument>
            <name>logclass</name>
            <type><string/></type>
            <description>Hierarchical log class as described in the <emphasis>zorp(8)</emphasis> manual page</description>
          </argument>
          <argument>
            <name>verbosity</name>
            <type><integer/></type>
            <description>Verbosity level of the message.</description>
          </argument>
          <argument>
            <name>msg</name>
            <type><string/></type>
            <description>The message text.</description>
          </argument>
          <argument>
            <name>args</name>
            <type><string/></type>
            <description>Optional printf-style argument tuple added to the message.</description>
          </argument>
        </arguments>
      </metainfo>
    </function>
    """
    Common.log(sessionid, logclass, verbosity, msg, args=None)
