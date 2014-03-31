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
## Author  : SaSa
## Auditor :
## Last audited version:
## Notes:
##
############################################################################

"""<module maturity="stable">
  <summary>
    Proxy for the Simple Mail Transport Protocol.
  </summary>
  <description>
    <para>
      Simple Mail Transport Protocol (SMTP) is a protocol for transferring electronic
      mail messages from Mail User Agents (MUAs) to Mail Transfer Agents (MTAs). It is
      also used for exchanging mails between MTAs.
    </para>
    <section>
      <title>The SMTP protocol</title>
      <para>
        The main goal of SMTP is to reliably transfer mail objects from the client to
        the server. A mail transaction involves exchanging the
        sender and recipient information and the mail body itself.
      </para>
      <section>
        <title>Protocol elements</title>
        <para>
          SMTP is a traditional command based Internet protocol; the client
          issues command verbs with one or more arguments, and the server
          responds with a 3 digit status code and additional information. The
          response can span one or multiple lines, the continuation is indicated
          by an '-' character between the status code and text.
        </para>
        <para>
          The communication itself is stateful, the client first specifies the
          sender via the "MAIL" command, then the recipients using
          multiple "RCPT" commands. Finally it sends the mail body using the
          "DATA" command. After a transaction finishes the client either
          closes the connection using the "QUIT" command, or starts a new
          transaction with another "MAIL" command.
        </para>
        <example>
          <title>SMTP protocol sample</title>
          <synopsis>220 mail.example.com ESMTP Postfix (Debian/GNU)
EHLO client.host.name
250-mail.example.com
250-PIPELINING
250-SIZE 50000000
250-VRFY
250-ETRN
250-XVERP
250 8BITMIME
MAIL From: &lt;sender@sender.com&gt;
250 Sender ok
RCPT To: &lt;account@recipient.com&gt;
250 Recipient ok
RCPT To: &lt;account2@recipient.com&gt;
250 Recipient ok
DATA
354 Send mail body
From: sender@sender.com
To: account@receiver.com
Subject: sample mail

This is a sample mail message. Lines beginning with
..are escaped, another '.' character is perpended which
is removed when the mail is stored by the client.
.
250 Ok: queued as BF47618170
QUIT
221 Farewell</synopsis>
        </example>
      </section>
      <section>
        <title>Extensions</title>
        <para>
          Originally SMTP had a very limited set of commands (HELO, MAIL,
          RCPT, DATA, RSET, QUIT, NOOP) but as of RFC 1869, an extension
          mechanism was introduced. The initial HELO command was replaced
          by an EHLO command and the response to an EHLO command contains all
          the extensions the server supports. These extensions are identified by an IANA assigned
          name.
        </para>
        <para>
          Extensions are used for example to implement inband authentication
          (AUTH), explicit message size limitation (SIZE) and explicit queue
          run initiation (ETRN). Each extension might add new command verbs,
          but might also add new arguments to various SMTP commands. The SMTP proxy
          has built in support for the most important SMTP extensions, further extensions can be added through customization.
        </para>
      </section>
      <section>
        <title>Bulk transfer</title>
        <para>
          The mail object is transferred as a series of lines, terminated by
          the character sequence "CRLF '.' CRLF". When the '.' character occurs
          as the first character of a line, an escaping '.' character is
          prepended to the line which is automatically removed by the peer.
        </para>
      </section>
    </section>
    <section>
      <title>Proxy behavior</title>
      <para>
        The Smtp module implements the SMTP protocol as specified in RFC 2821. The
        proxy supports the basic SMTP protocol plus five extensions, namely:
        PIPELINING, SIZE, ETRN, 8BITMIME, and STARTTLS. All other ESMTP extensions are
        filtered by dropping the associated token from the EHLO response.
        If no connection can be established to the server, the request is rejected with an error message. In this case the proxy tries to connect the next mail exchange server.
      </para>
      <section>
        <title>Default policy for commands</title>
        <para>
          The abstract SMTP proxy rejects all commands and responses by default.
          Less restrictive proxies are available as derived classes (e.g.:
          SmtpProxy), or can be customized as required.
        </para>
      </section>
      <section xml:id="smtp_policies">
         <title>Configuring policies for SMTP commands and responses</title>
          <para>
            Changing the default behavior of commands can be done by
            using the hash attribute <parameter>request</parameter>. These hashes are indexed by the command name (e.g.: MAIL or DATA). Policies for responses can be configured using the <parameter>response</parameter> attribute, which is indexed by the command name and the response code. The possible actions are shown in the tables below. See <xref linkend="proxy_policies"/> for details. When looking up entries of the <parameter>response</parameter> attribute hash, the lookup precedence described in <xref linkend="proxy_response_codes"/> is used.
        </para>
           <inline type="actiontuple" target="action.smtp.req"/>
           <inline type="actiontuple" target="action.smtp.rsp"/>
         <para>
         SMTP extensions can be controlled using the <parameter>extension</parameter> hash, which is indexed by the extension name. The supported extensions (SMTP_EXT_PIPELINING; SMTP_EXT_SIZE; SMTP_EXT_ETRN; SMTP_EXT_8BITMIME) can be accepted or dropped (SMTP_EXT_ACCEPT or SMTP_EXT_DROP) individually or all at once using the SMTP_EXT_ALL index value.
         </para>

      </section>
       <section xml:id="smtp_stacking">
      <title>Stacking</title>
      <para>
      The available stacking modes for this proxy module are listed in the following table. For additional information on stacking, see <xref linkend="proxy_stacking"/>.
      </para>
      <inline type="actiontuple" target="action.smtp.stk"/>
      </section>
    </section>
    <section>
      <title>Related standards</title>
      <para>
        <itemizedlist>
          <listitem>
            <para>
              Simple Mail Transfer Protocol is described in RFC 2821.
            </para>
          </listitem>
          <listitem>
            <para>
              SMTP Service Extensions are described in the obsoleted RFC 1869.
            </para>
          </listitem>
          <listitem>
            <para>
              The STARTTLS extension is described in RFC 3207.
            </para>
          </listitem>
        </itemizedlist>
      </para>
    </section>
  </description>
  <metainfo>
    <enums>
      <enum maturity="stable" id="enum.smtp.autodetect_domain">
        <description>
          Attempt to identify the domain automatically.
        </description>
        <item>
          <name>SMTP_GETDOMAIN_MAILNAME</name>
          <description>Read from /etc/mailname</description>
        </item>
        <item>
          <name>SMTP_GETDOMAIN_FQDN</name>
          <description>Get firewall's FQDN</description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.smtp.req">
        <description>
          Action codes for SMTP requests
        </description>
        <item>
          <name>SMTP_REQ_ACCEPT</name>
        </item>
        <item>
          <name>SMTP_REQ_REJECT</name>
        </item>
        <item>
          <name>SMTP_REQ_ABORT</name>
        </item>
        <item>
          <name>SMTP_REQ_POLICY</name>
        </item>
      </enum>
      <enum maturity="stable" id="enum.smtp.rsp">
        <description>
          Action codes for SMTP responses
        </description>
        <item>
          <name>SMTP_RSP_ACCEPT</name>
        </item>
        <item>
          <name>SMTP_RSP_REJECT</name>
        </item>
        <item>
          <name>SMTP_RSP_ABORT</name>
        </item>
        <item>
          <name>SMTP_RSP_POLICY</name>
        </item>
      </enum>
      <enum maturity="stable" id="enum.smtp.ext">
        <description>
          Action codes for SMTP extensions
        </description>
        <item>
          <name>SMTP_EXT_ACCEPT</name>
          <description>Accept</description>
        </item>
        <item>
          <name>SMTP_EXT_DROP</name>
          <description>Drop</description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.smtp.stk">
        <description>
          Smtp stack hashes
        </description>
        <item>
          <name>SMTP_STK_NONE</name>
        </item>
        <item>
          <name>SMTP_STK_MIME</name>
        </item>
      </enum>
    </enums>
    <constants>
      <constantgroup maturity="stable" id="const.smtp.log">
        <description>
          Logging levels of SMTP
        </description>
        <item>
          <name>SMTP_POLICY</name>
          <value>'smtp.policy'</value>
        </item>
        <item>
          <name>SMTP_DEBUG</name>
          <value>'smtp.debug'</value>
        </item>
        <item>
          <name>SMTP_INFO</name>
          <value>smtp.info</value>
        </item>
        <item>
          <name>SMTP_ERROR</name>
          <value>smtp.error</value>
        </item>
      </constantgroup>
    </constants>
    <actiontuples>
      <actiontuple maturity="stable" id="action.smtp.req" action_enum="enum.smtp.req">
        <description>
          Action codes for SMTP requests
        </description>
        <tuple action="SMTP_REQ_ACCEPT" display_name="Accept the request">
          <args></args>
          <description>
            Accept the request without any modification.
          </description>
        </tuple>
        <tuple action="SMTP_REQ_REJECT" display_name="Reject the request">
          <args>
            <string display_name="Error code"/>
            <string display_name="Error message"/>
          </args>
          <description>
            Reject the request. The second parameter contains an SMTP status code, the third one an associated parameter which will be sent back to the client.
          </description>
        </tuple>
        <!-- FIXME: METHOD currently unsupported by the GUI
        <tuple action="SMTP_REQ_POLICY" display_name="">
          <args>METHOD</args>
          <description>
            Call the function specified to make a decision about the event. The function receives three parameters: self, command, and the parameters of the command. See <xref linkend="proxy_policies"/> for details.
          </description>
        </tuple>
        -->
        <tuple action="SMTP_REQ_ABORT" display_name="Terminate the connection">
          <args></args>
          <description>
            Reject the request and terminate the connection.
          </description>
        </tuple>
      </actiontuple>
            <actiontuple maturity="stable" id="action.smtp.rsp" action_enum="enum.smtp.rsp">
        <description>
          Action codes for SMTP responses
        </description>
        <tuple action="SMTP_RSP_ACCEPT" display_name="Accept the response">
          <args></args>
          <description>
            Accept the response without any modification.
          </description>
        </tuple>
        <tuple action="SMTP_RSP_REJECT" display_name="Reject the response">
          <args>
            <string display_name="Error code"/>
            <string display_name="Error message"/>
          </args>
          <description>
            Reject the response. The second parameter contains an SMTP status code, the third one an associated parameter which will be sent back to the client.
          </description>
        </tuple>
        <!-- FIXME: METHOD currently unsupported by the GUI
        <tuple action="SMTP_RSP_POLICY" display_name="">
          <args>METHOD</args>
          <description>
            Call the function specified to make a decision about the event. The function receives three parameters: self, command, and the parameters of the command. See <xref linkend="proxy_policies"/> for details.
          </description>
        </tuple>
        -->
        <tuple action="SMTP_RSP_ABORT" display_name="Terminate the connection">
          <args></args>
          <description>
            Reject the response and terminate the connection.
          </description>
        </tuple>
      </actiontuple>
      <actiontuple internal="yes" id="action.smtp.stk" action_enum="enum.smtp.stk">
        <description>
          Stacking options for SMTP
        </description>
        <tuple action="SMTP_STK_NONE">
          <args></args>
          <description>
          No additional proxy is stacked into the SMTP proxy.
          </description>
        </tuple>
        <tuple action="SMTP_STK_MIME">
          <args>
            <link id="action.zorp.stack"/>
          </args>
          <description>
          The data part including header information of the traffic is passed to the specified stacked proxy.
          </description>
        </tuple>
      </actiontuple>
    </actiontuples>
  </metainfo>
</module>
"""

from Zorp import *
from Proxy import Proxy, proxyLog
from Matcher import AbstractMatcher, getMatcher
# for compatibility
from Matcher import SmtpInvalidRecipientMatcher

from string import split, find, lower, replace

from time import strftime

from socket import gethostbyaddr, getfqdn

import types

SMTP_POLICY     = 'smtp.policy'
SMTP_DEBUG      = 'smtp.debug'
SMTP_INFO       = 'smtp.info'
SMTP_ERROR      = 'smtp.error'

SMTP_GETDOMAIN_MAILNAME = 'mailname'
SMTP_GETDOMAIN_FQDN     = 'fqdn'

SMTP_REQ_ACCEPT         = 1
SMTP_REQ_REJECT         = 3
SMTP_REQ_ABORT          = 4
SMTP_REQ_POLICY         = 6

SMTP_RSP_ACCEPT         = 1
SMTP_RSP_REJECT         = 3
SMTP_RSP_ABORT          = 4
SMTP_RSP_POLICY         = 6

SMTP_EXT_PIPELINING = 0x0001
SMTP_EXT_SIZE       = 0x0002
SMTP_EXT_ETRN       = 0x0004
SMTP_EXT_8BITMIME   = 0x0008
SMTP_EXT_AUTH       = 0x0010
SMTP_EXT_STARTTLS   = 0x0020

SMTP_EXT_ALL            = 0x000F

SMTP_EXT_ACCEPT         = 1
SMTP_EXT_DROP           = 5

SMTP_STK_NONE           = 0
SMTP_STK_MIME           = 1

class AbstractSmtpProxy(Proxy):
    """
    <class maturity="stable" abstract="yes">
      <summary>
        Class encapsulating the abstract SMTP proxy.
      </summary>
      <description>
      <para>This class implements an abstract SMTP proxy - it serves as a starting point for customized proxy classes, but is itself not directly usable. Service definitions should refer to a customized class derived from AbstractSmtpProxy, or one of the predefined proxy classes.
      </para>
      <para>
      The following requests are permitted: HELO; MAIL; RCPT; DATA; RSET; QUIT; NOOP; EHLO; AUTH; ETRN.
      The following extensions are permitted: PIPELINING; SIZE; ETRN; 8BITMIME; STARTTLS.
      </para>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>timeout</name>
            <type>
              <integer/>
            </type>
            <default>600000</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Timeout in milliseconds. If no packet arrives within this in interval, the connection is dropped.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>add_received_header</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Add a Received: header into the email messages transferred by the proxy.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>resolve_host</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Resolve the client host from the IP address and add it to the Received line.
              Only takes effect if add_received_header is TRUE.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>domain_name</name>
            <type>
              <string/>
            </type>
            <default></default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              If you want to set a fix domain name into the added Receive line, set this.
              Only takes effect if add_received_header is TRUE.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>autodetect_domain_from</name>
            <type>
              <link id="enum.smtp.autodetect_domain"/>
            </type>
            <default></default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              If you want Zorp to autodetect the domain name of the firewall and
              write it to the Received line, then set this. This attribute either set
              the method how the Zorp detect the mailname.
              Only takes effect if add_received_header is TRUE.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>interval_transfer_noop</name>
            <type>
              <integer/>
            </type>
            <default>600000</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              The interval between two NOOP commands sent to the server while waiting for the results of stacked proxies.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>max_request_length</name>
            <type>
              <integer/>
            </type>
            <default>256</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Maximum allowed line length of client requests.
            </description>
          </attribute>
          <attribute>
            <name>max_auth_request_length</name>
            <type>
              <integer/>
            </type>
            <default>256</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Maximum allowed length of a request during SASL style authentication.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>max_response_length</name>
            <type>
              <integer/>
            </type>
            <default>512</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Maximum allowed line length of a server response.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>unconnected_response_code</name>
            <type>
              <integer/>
            </type>
            <default>451</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Error code sent to the client if connecting to the server fails.
            </description>
          </attribute>
          <attribute>
            <name>require_crlf</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies whether the proxy should enforce valid CRLF line terminations.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>request_command</name>
            <type>
              <string/>
            </type>
            <default>n/a</default>
            <conftime/>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              When a command is passed to the policy level, its value can be changed to this value.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>request_param</name>
            <type>
              <string/>
            </type>
            <default>n/a</default>
            <conftime/>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              When a command is passed to the policy level, the value of its parameter can be changed to this value.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>response_value</name>
            <type>
              <string/>
            </type>
            <default>n/a</default>
            <conftime/>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              When a response is passed to the policy level, its value can be changed to this value. (It has effect only when the return
              value is not SMTP_*_ACCEPT.)
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>response_param</name>
            <type>
              <string/>
            </type>
            <default>n/a</default>
            <conftime/>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              When a response is passed to the policy level, the value of its parameter can be changed to this value. (It has effect only when the return
              value is not SMTP_*_ACCEPT.)
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>request</name>
            <type>
              <hash>
                <key>
                  <string display_name="Command name"/>
                </key>
                <value>
                  <link id="action.smtp.req"/>
                </value>
              </hash>
            </type>
            <default/>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Normative policy hash for SMTP requests
            indexed by the command name (e.g.: "USER", "UIDL", etc.). See also <xref linkend="smtp_policies"/>.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>response</name>
            <type>
              <hash>
                <key>
                  <tuple>
                    <string display_name="Command name"/>
                    <string display_name="Response code"/>
                  </tuple>
                </key>
                <value>
                  <link id="action.smtp.rsp"/>
                </value>
              </hash>
            </type>
            <default/>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Normative policy hash for SMTP responses
            indexed by the command name and the response code. See also <xref linkend="smtp_policies"/>.
            </description>
          </attribute>
          <attribute>
            <name>extensions</name>
            <type>
              <hash>
                <key>
                  <string display_name="Extension name"/>
                </key>
                <value>
                  <link id="enum.smtp.ext"/>
                </value>
              </hash>
            </type>
            <default/>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Normative policy hash for ESMTP extension policy, indexed by
              the extension verb (e.g. ETRN). It contains an action tuple with the
              SMTP_EXT_* values as possible actions.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>permit_unknown_command</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Enable unknown commands.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>permit_long_responses</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Permit overly long responses, as some MTAs include variable parts in responses
              which might get very long. If enabled, responses longer than <parameter>max_response_length</parameter> are segmented into separate messages. If disabled, such responses are rejected.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>permit_omission_of_angle_brackets</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Permit MAIL From and RCPT To parameters without the normally required angle brackets around them. They will be added when the message leaves the proxy anyway.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>request_stack</name>
            <type>
              <hash>
                <key>
                  <string/>
                </key>
                <value>
                  <link id="action.smtp.stk"/>
                </value>
              </hash>
            </type>
            <default/>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
            Attribute containing the stacking policy for SMTP commands. See <xref linkend="smtp_stacking"/>.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>append_domain</name>
            <type>
              <string/>
            </type>
            <default/>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Domain to append to email addresses which do not specify domain name.
              An address is rejected if it does not contain a domain and append_domain is empty.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>active_extensions</name>
            <type>
              <integer/>
            </type>
            <default>n/a</default>
            <conftime/>
            <runtime>
              <read/>
            </runtime>
            <description>
              Active extension bitmask, contains bits defined by the constants 'SMTP_EXT_*'
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>tls_passthrough</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Change to passthrough mode after a successful STARTTLS request. Zorp does not process
              or change the encrypted traffic in any way, it is transported intact between the client
              and server.
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    name = "smtp"

    def __init__(self, session):
        """
        <method maturity="stable" internal="yes">
          <summary>
            Initialize a SmtpProxy instance.
          </summary>
          <description>
            <para>
              Create and set up a SmtpProxy instance.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>session</name>
                <type>SESSION</type>
                <description>
                  session this instance belongs to
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.request_stack = {}
        Proxy.__init__(self, session)

    def loadSMTP(self):
        """
        <method internal="yes">
        </method>
        """
        # greeting
        self.response["Null", "220"] = SMTP_RSP_ACCEPT
        self.response["Null", "554"] = SMTP_RSP_ACCEPT

        # permitted for all commands
        self.response["*", "421"] = SMTP_RSP_ACCEPT
        self.response["*", "500"] = SMTP_RSP_ACCEPT
        self.response["*", "501"] = SMTP_RSP_ACCEPT

        self.request["HELO"] = SMTP_REQ_ACCEPT
        self.response["HELO", "250"] = SMTP_RSP_ACCEPT
        self.response["HELO", "504"] = SMTP_RSP_ACCEPT
        self.response["HELO", "550"] = SMTP_RSP_ACCEPT


        self.request["MAIL"] = SMTP_REQ_ACCEPT
        self.response["MAIL", "250"] = SMTP_RSP_ACCEPT
        self.response["MAIL", "450"] = SMTP_RSP_ACCEPT
        self.response["MAIL", "451"] = SMTP_RSP_ACCEPT
        self.response["MAIL", "452"] = SMTP_RSP_ACCEPT
        self.response["MAIL", "503"] = SMTP_RSP_ACCEPT
        self.response["MAIL", "530"] = SMTP_RSP_ACCEPT
        self.response["MAIL", "550"] = SMTP_RSP_ACCEPT
        self.response["MAIL", "552"] = SMTP_RSP_ACCEPT
        self.response["MAIL", "553"] = SMTP_RSP_ACCEPT

        self.request["RCPT"] = SMTP_REQ_ACCEPT
        self.response["RCPT", "250"] = SMTP_RSP_ACCEPT
        self.response["RCPT", "251"] = SMTP_RSP_ACCEPT
        self.response["RCPT", "450"] = SMTP_RSP_ACCEPT
        self.response["RCPT", "451"] = SMTP_RSP_ACCEPT
        self.response["RCPT", "452"] = SMTP_RSP_ACCEPT
        self.response["RCPT", "503"] = SMTP_RSP_ACCEPT
        self.response["RCPT", "530"] = SMTP_RSP_ACCEPT
        self.response["RCPT", "550"] = SMTP_RSP_ACCEPT
        self.response["RCPT", "551"] = SMTP_RSP_ACCEPT
        self.response["RCPT", "552"] = SMTP_RSP_ACCEPT
        self.response["RCPT", "553"] = SMTP_RSP_ACCEPT
        self.response["RCPT", "554"] = SMTP_RSP_ACCEPT

        self.request["DATA"] = SMTP_REQ_ACCEPT
        self.response["DATA", "354"] = SMTP_RSP_ACCEPT
        # after data transmission
        self.response["DATA", "250"] = SMTP_RSP_ACCEPT
        self.response["DATA", "530"] = SMTP_RSP_ACCEPT
        self.response["DATA", "451"] = SMTP_RSP_ACCEPT
        self.response["DATA", "452"] = SMTP_RSP_ACCEPT
        self.response["DATA", "503"] = SMTP_RSP_ACCEPT
        # not allowed by RFC, but seems to be a common choice to reject mail
        self.response["DATA", "550"] = SMTP_RSP_ACCEPT
        self.response["DATA", "552"] = SMTP_RSP_ACCEPT
        self.response["DATA", "554"] = SMTP_RSP_ACCEPT

        self.request["RSET"] = SMTP_REQ_ACCEPT
        self.response["RSET", "250"] = SMTP_RSP_ACCEPT

        self.request["QUIT"] = SMTP_REQ_ACCEPT
        self.response["QUIT", "221"] = SMTP_RSP_ACCEPT

        self.request["NOOP"] = SMTP_REQ_ACCEPT
        self.response["NOOP", "250"] = SMTP_RSP_ACCEPT

    def loadESMTP(self):
        """<method internal="yes">
        </method>
        """
        self.loadSMTP()
        self.extensions["PIPELINING"] = (SMTP_EXT_ACCEPT)
        self.extensions["SIZE"] = (SMTP_EXT_ACCEPT)
        self.extensions["ETRN"] = (SMTP_EXT_ACCEPT)
        self.extensions["AUTH"] = (SMTP_EXT_ACCEPT)
        self.extensions["8BITMIME"] = (SMTP_EXT_ACCEPT)
        self.extensions["STARTTLS"] = (SMTP_EXT_ACCEPT)

        self.request["EHLO"] = SMTP_REQ_ACCEPT
        self.response["EHLO", "250"] = SMTP_RSP_ACCEPT
        self.response["EHLO", "504"] = SMTP_RSP_ACCEPT
        self.response["EHLO", "550"] = SMTP_RSP_ACCEPT

        self.request["AUTH"] = SMTP_REQ_ACCEPT
        self.response["AUTH", "235"] = SMTP_RSP_ACCEPT
        self.response["AUTH", "334"] = SMTP_RSP_ACCEPT
        self.response["AUTH", "432"] = SMTP_RSP_ACCEPT
        self.response["AUTH", "454"] = SMTP_RSP_ACCEPT
        self.response["AUTH", "501"] = SMTP_RSP_ACCEPT
        self.response["AUTH", "503"] = SMTP_RSP_ACCEPT
        self.response["AUTH", "504"] = SMTP_RSP_ACCEPT
        self.response["AUTH", "534"] = SMTP_RSP_ACCEPT
        self.response["AUTH", "535"] = SMTP_RSP_ACCEPT
        self.response["AUTH", "538"] = SMTP_RSP_ACCEPT

        self.request["ETRN"] = SMTP_REQ_ACCEPT
        self.response["ETRN", "250"] = SMTP_RSP_ACCEPT
        self.response["ETRN", "251"] = SMTP_RSP_ACCEPT
        self.response["ETRN", "252"] = SMTP_RSP_ACCEPT
        self.response["ETRN", "253"] = SMTP_RSP_ACCEPT
        self.response["ETRN", "458"] = SMTP_RSP_ACCEPT
        self.response["ETRN", "459"] = SMTP_RSP_ACCEPT
        self.response["ETRN", "500"] = SMTP_RSP_ACCEPT
        self.response["ETRN", "501"] = SMTP_RSP_ACCEPT
        self.response["ETRN", "530"] = SMTP_RSP_ACCEPT

        self.request["STARTTLS"] = SMTP_REQ_ACCEPT
        self.response["STARTTLS", "220"] = SMTP_RSP_ACCEPT
        self.response["STARTTLS", "454"] = SMTP_RSP_ACCEPT
        self.response["STARTTLS", "501"] = SMTP_RSP_ACCEPT

    def generateReceived(self):
        """<method internal="yes">
        </method>
        """

        if  hasattr(self, "resolve_host") and self.resolve_host:
            try:
                from_hostaddr = gethostbyaddr(self.session.client_address.ip_s)
                from_domain = "%s [%s]" % (from_hostaddr[0], self.session.client_address.ip_s)
            except:
                from_domain = "[%s]" % (self.session.client_address.ip_s,)
        else:
            from_domain = "[%s]" % (self.session.client_address.ip_s,)

        if hasattr(self, "domain_name"):
            my_domain = self.domain_name
        elif hasattr(self, "autodetect_domain_from") and self.autodetect_domain_from == SMTP_GETDOMAIN_MAILNAME:
            try:
                mailname_handler = open("/etc/mailname")
                my_domain = mailname_handler.readline().strip()
            except IOError, s:
                log(None, SMTP_ERROR, 3, "Error reading mailname; error='%s'", (s,))
                my_domain = "unknown"
        elif hasattr(self, "autodetect_domain_from") and self.autodetect_domain_from == SMTP_GETDOMAIN_FQDN:
            try:
                my_domain = getfqdn()
            except:
                my_domain = "unknown"
        else:
            my_domain = "unknown"

        cur_date = strftime("%a, %d %b %Y %H:%M:%S %z (%Z)")

        received_id = replace(self.session.owner.session_id, ":", ".")

        line = "Received: from %s (%s) by %s with %s id %s; %s\r\n" % (self.helo_string, from_domain, my_domain, self.protocol, received_id, cur_date)
        return line

    def requestStack(self):
        """<method internal="yes">
        </method>
        """
        try:
            stack_proxy = self.request_stack["DATA"]
        except KeyError:
            try:
                stack_proxy = self.request_stack["*"]
            except:
                return None

        if (type(stack_proxy) == type(()) and stack_proxy[0] != SMTP_STK_NONE):
            return stack_proxy[1]

        return None

class SmtpProxy(AbstractSmtpProxy):
    """<class maturity="stable">
      <summary>
        Default SMTP proxy based on AbstractSmtpProxy.
      </summary>
      <description>
        <para>
          SmtpProxy implements a basic SMTP Proxy based on AbstractSmtpProxy, with relay checking and sender/recipient check restrictions. (Exclamation marks and percent signs are not allowed in the e-mail addresses.)
        </para>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>relay_zones</name>
            <type>
              <list>
                <zone/>
              </list>
            </type>
            <default></default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Zorp zones that are relayed. The administrative hierarchy of the zone is also used.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>relay_check</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Enable/disable relay checking.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>relay_domains</name>
            <type>
              <list>
                <string/>
              </list>
            </type>
            <default/>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Domains mails are accepted for. Use Postfix style lists.
              (E.g.: '.example.com' allows every subdomain of example.com, but not example.com. To match example.com use 'example.com'.)
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>relay_domains_matcher</name>
            <type>
              <class filter="matcherpolicy" existing="yes"/>
            </type>
            <default/>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Domains mails are accepted for based on a matcher (e.g.: RegexpFileMatcher).
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>sender_matcher</name>
            <type>
              <class filter="matcherpolicy" existing="yes"/>
            </type>
            <default/>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Matcher class (e.g.: SmtpInvalidRecipientMatcher) used to check and filter sender e-mail addresses.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>recipient_matcher</name>
            <type>
              <class filter="matcherpolicy" existing="yes"/>
            </type>
            <default/>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Matcher class (e.g.: SmtpInvalidRecipientMatcher) used to check and filter recipient e-mail addresses.
            </description>
          </attribute>
          <attribute>
            <name>permit_percent_hack</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Allow the '%' sign in the local part of e-mail addresses.
            </description>
          </attribute>
          <attribute>
            <name>permit_exclamation_mark</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Allow the '!' sign in the local part of e-mail addresses.
            </description>
          </attribute>
          <attribute>
            <name>error_soft</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <type>BOOLEAN:FALSE:RW:RW</type>
            <description>
              Return a soft error condition when recipient filter does not match. If enabled, the proxy will try to re-validate the recipient and send the mail again. This option is useful when the server used for the recipient matching is down.
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    sender_matcher = None
    recipient_matcher = None
    relay_domains_matcher = None

    def __init__(self, session):
        """<method internal="yes">
        </method>
        """
        self.relay_domains = ()
        self.relay_zones = ()
        self.permit_percent_hack = FALSE
        self.permit_exclamation_mark = FALSE
        self.error_soft = FALSE
        AbstractSmtpProxy.__init__(self, session)

    def config(self):
        """<method maturity="stable" internal="yes">
          <summary>
            Default Smtp config
          </summary>
          <description>
            <para>
              Fill request hash with common ESMTP commands and allow all
              known SMTP extensions.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        self.loadESMTP()
        self.request["MAIL"] = (SMTP_REQ_POLICY, self.checkSender)
        self.request["RCPT"] = (SMTP_REQ_POLICY, self.checkRecipient)
        self.relay_check = TRUE

    def __post_config__(self):
        """<method internal="yes">
        </method>
        """
        AbstractSmtpProxy.__post_config__(self)

        self.relay_zones_orig = {}
        if type(self.relay_zones) == types.TupleType or type(self.relay_zones) == types.ListType:
            for zone in self.relay_zones:
                self.relay_zones_orig[zone] = 1
        else:
            if type(self.relay_zones) == types.StringType:
                self.relay_zones_orig[self.relay_zones] = 1

        if type(self.relay_domains) == types.StringType:
            self.relay_domains = (self.relay_domains,)

        if self.sender_matcher:
            self.sender_matcher = getMatcher(self.sender_matcher)
        if self.recipient_matcher:
            self.recipient_matcher = getMatcher(self.recipient_matcher)
        if self.relay_domains_matcher:
            self.relay_domains_matcher = getMatcher(self.relay_domains_matcher)

    def checkSender(self, cmd, param):
        """<method internal="yes">
        </method>
        """
        email = self.sanitizeAddress(param[5:])
        try:
            if self.sender_matcher and self.sender_matcher.checkMatch(email):
                ## LOG ##
                # This message indicates that the sender address was administratively prohibited
                # and Zorp rejects the request. Check the 'sender_matcher' attribute.
                ##
                proxyLog(self, SMTP_POLICY, 3, "Sender address administratively prohibited; email='%s'" % email)
                if not self.error_soft:
                    self.error_code = "550"
                    self.error_info = "Sender address refused."
                else:
                    self.error_code = "450"
                    self.error_info = "Cannot verify sender at this time, come back later."
                return SMTP_REQ_REJECT
        except MatcherException:
            self.error_code = "450"
            self.error_info = "Cannot verify sender at this time, come back later"
            return SMTP_REQ_REJECT
        ## LOG ##
        # This message reports that the sender address check was successful and
        # Zorp accepts the request.
        ##
        proxyLog(self, SMTP_DEBUG, 6, "Sender check successful; email='%s'" % email)
        return SMTP_REQ_ACCEPT

    def checkRecipient(self, cmd, param):
        """<method internal="yes">
        </method>
        """
        email = self.sanitizeAddress(param[3:])
        try:
            (local, domain) = split(email, '@', 2)
        except ValueError:
            local = email
            domain = ''

        if not self.permit_percent_hack and local.find('%') != -1:
            ## LOG ##
            # This message indicates that the email address local-part contains a percent sign and
            # it is not permitted by the policy and Zorp rejects the request. Check the 'permit_percent_hack'
            # attribute.
            ##
            proxyLog(self, SMTP_POLICY, 3, "Forbidden percent found in address local-part; email='%s'" % email)
            self.error_code = '501'
            self.error_info = 'Malformed address'
            return SMTP_REQ_REJECT

        if not self.permit_exclamation_mark and local.find('!') != -1:
            ## LOG ##
            # This message indicates that the email address local-part contains a exclamation mark and
            # it is not permitted by the policy and Zorp rejects the request. Check the 'permit_exclamation_mark'
            # attribute.
            ##
            proxyLog(self, SMTP_POLICY, 3, "Forbidden exclamation mark found in address local-part; email='%s'" % email)
            self.error_code = '501'
            self.error_info = 'Malformed address'
            return SMTP_REQ_REJECT

        if self.relay_check and not self.relayCheck(email):
            ## LOG ##
            # This message indicates that relaying the given address is not permitted by the
            # policy and Zorp rejects the request. Check the 'relay_check' attribute.
            ##
            proxyLog(self, SMTP_POLICY, 3, "Relaying denied; email='%s'" % email)
            self.error_code = "554"
            self.error_info = "Relaying denied."
            return SMTP_REQ_REJECT
        else:
            ## LOG ##
            # This message reports that the relay check was successful and Zorp accepts the request.
            ##
            proxyLog(self, SMTP_DEBUG, 6, "Relay check successful; email='%s'" % email)

        try:
            if self.recipient_matcher and self.recipient_matcher.checkMatch(email):
                ## LOG ##
                # This message indicates that the given recipient address is administratively prohibited
                # and Zorp rejects the request. Check the 'recipient_matcher' attribute.
                ##
                proxyLog(self, SMTP_POLICY, 3, "Recipient address administratively prohibited; email='%s'" % email)
                if not self.error_soft:
                    self.error_code = "554"
                    self.error_info = "Recipient address refused."
                else:
                    self.error_code = "450"
                    self.error_info = "Cannot verify recipient at this time, come back later."
                return SMTP_REQ_REJECT
        except MatcherException:
            self.error_code = "450"
            self.error_info = "Cannot verify recipient at this time, come back later."
            return SMTP_REQ_REJECT
        ## LOG ##
        # This message reports that the recipient check was successful and Zorp accepts the request.
        ##
        proxyLog(self, SMTP_DEBUG, 6, "Recipient check successful; email='%s'" % email)
        return SMTP_REQ_ACCEPT

    def relayCheck(self, email):
        """<method internal="yes">
        </method>
        """
        ## LOG ##
        # This message reports that Zorp checks the zone of the client.
        ##
        proxyLog(self, SMTP_DEBUG, 7, "Relay check, checking client_zone; client_zone='%s'" % self.session.client_zone.name)
        if self.relay_zones_orig.has_key("*"):
            return TRUE
        if self.zoneCheck(self.session.client_zone):
            return TRUE

        try:
            (local, domain) = split(email, '@', 2)
        except ValueError:
            local = email
            domain = ''
        ## LOG ##
        # This message reports that Zorp checks the domain name of the email.
        ##
        proxyLog(self, SMTP_DEBUG, 7, "Relay check, checking mail domain; local='%s', domain='%s'" % (local, domain))
        for dom in self.relay_domains:
            f = find(lower(domain), lower(dom))
            if dom[0] == '.':
                if (f != -1) and (f + len(dom) == len(domain)):
                    return TRUE
            else:
                if (f == 0) and (len(dom) == len(domain)):
                    return TRUE

        try:
            if self.relay_domains_matcher and self.relay_domains_matcher.checkMatch(domain):
                return TRUE
        except MatcherException:
            return FALSE
        return FALSE

    def zoneCheck(self, zone):
        """<method internal="yes">
        </method>
        """
        if self.relay_zones_orig.has_key(zone.name):
            return TRUE
        else:
            if zone.admin_parent:
                return self.zoneCheck(zone.admin_parent)
        return FALSE
