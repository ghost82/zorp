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
    Proxy for the Post Office Protocol version 3.
  </summary>
  <description>
    <para>
      The Pop3 module defines the classes constituting the proxy for the POP3 protocol.
    </para>
    <section>
      <title>The POP3 protocol</title>
      <para>
        Post Office Protocol version 3 (POP3) is usually used by mail
        user agents (MUAs) to download messages from a remote mailbox. POP3
        supports a single mailbox only, it does not support advanced multi-mailbox operations
        offered by alternatives such as IMAP.
      </para>
      <para>
        The POP3 protocol uses a single TCP connection to give access to a
        single mailbox. It uses a simple command/response based approach, the
        client issues a command and a server can respond either positively
        or negatively.
      </para>
      <section>
        <title>Protocol elements</title>
        <para>
          The basic protocol is the following: the client issues a request (also called
          command in POP3 terminology) and the server responds with the
          result. Both commands and responses are line based, each command is
          sent as a complete line, a response is either a single line or - in case of
          mail transfer commands - multiple lines.
        </para>
        <para>
          Commands begin with a case-insensitive keyword possibly followed
          by one or more arguments (such as RETR or DELE).
        </para>
        <para>
          Responses begin with a status indicator ("+OK" or "-ERR") and a
          possible explanation of the status code (e.g.: "-ERR
          Permission denied.").
        </para>
        <para>
          Responses to certain commands (usually mail transfer commands) also
          contain a data attachment, such as the mail body. See the <xref linkend="pop3_bulktransfer"/> for further details.
        </para>
      </section>
      <section>
        <title>POP3 states</title>
        <para>
          The protocol begins with the server displaying a greeting message,
          usually containing information about the server.
        </para>
        <para>
          After the greeting message the client takes control and the protocol
          enters the AUTHORIZATION state where the user has to pass credentials
          proving his/her identity.
        </para>
        <para>
          After successful authentication the protocol enters
          TRANSACTION state where mail access commands can be issued.
        </para>
        <para>
          When the client has finished processing, it issues a QUIT command
          and the connection is closed.
        </para>
      </section>
      <section xml:id="pop3_bulktransfer">
        <title>Bulk transfers</title>
        <para>
          Responses to certain commands (such as LIST or RETR) contain a long
          data stream. This is transferred as a series of lines, terminated by
          a "CRLF '.' CRLF" sequence, just like in SMTP.
        </para>
        <example>
          <title>POP3 protocol sample</title>
          <synopsis>+OK POP3 server ready
USER account
+OK User name is ok
PASS password
+OK Authentication successful
LIST
+OK Listing follows
1 5758
2 232323
3 3434
.
RETR 1
+OK Mail body follows
From: sender@sender.com
To: account@receiver.com
Subject: sample mail

This is a sample mail message. Lines beginning with
..are escaped, another '.' character is perpended which
is removed when the mail is stored by the client.
.
DELE 1
+OK Mail deleted
QUIT
+OK Good bye</synopsis>
        </example>
      </section>
    </section>
    <section>
      <title>Proxy behavior</title>
      <para>
        Pop3Proxy is a module built for parsing messages of the POP3 protocol. It reads and parses COMMANDs on the client side, and sends them to the server if the local security policy permits. Arriving RESPONSEs are parsed as well, and sent to the client if the local security policy permits. It is possible to manipulate both the requests and the responses.
      </para>
      <section>
        <title>Default policy for commands</title>
        <para>
          By default, the proxy accepts all commands recommended in RFC 1939. Additionally, the
          following optional commands are also accepted: USER, PASS, AUTH. The proxy understands all the commands specified in RFC 1939 and the AUTH command. These additional commands can be enabled manually.
        </para>
      </section>
      <section xml:id="pop3_policies">
        <title>Configuring policies for POP3 commands</title>
        <para>
          Changing the default behavior of commands can be done using the
          hash named <parameter>request</parameter>. The hash is indexed by the command name
          (e.g.: USER or AUTH). See <xref linkend="proxy_policies"/> for details.
        </para>
        <inline type="actiontuple" target="action.pop3.req"/>
        <example>
          <title>Example for allowing only APOP authentication in POP3</title>
          <para>
          This sample proxy class rejects the USER authentication requests, but allows APOP requests.
          </para>
            <synopsis>class APop3(Pop3Proxy):
        def config(self):
                Pop3Proxy.config(self)
                self.request["USER"] = (POP3_REQ_REJECT)
                self.request["APOP"] = (POP3_REQ_ACCEPT)</synopsis>
        </example>
        <example>
          <title>Example for converting simple USER/PASS authentication to APOP in POP3</title>
          <para>
          The above example simply rejected USER/PASS authentication, this one converts USER/PASS authentication to APOP authentication messages.
          </para>
          <synopsis>class UToAPop3(Pop3Proxy):
        def config(self):
                Pop3Proxy.config(self)
                self.request["USER"] = (POP3_REQ_POLICY,self.DropUSER)
                self.request["PASS"] = (POP3_REQ_POLICY,self.UToA)

        def DropUSER(self,command):
                self.response_value = "+OK"
                self.response_param = "User ok Send Password"
                return POP3_REQ_REJECT

        def UToA(self,command):
                # Username is stored in self->username,
                # password in self->request_param,
                # and the server timestamp in self->timestamp,
                # consequently the digest can be calculated.
                # NOTE: This is only an example, calcdigest must be
                # implemented separately
                digest = calcdigest(self->timestamp+self->request_param)
                self->request_command = "APOP"
                self->request_param = name + " " + digest
                return POP3_REQ_ACCEPT</synopsis>
        </example>
      </section>
      <section>
        <title>Rewriting the banner</title>
        <para>
          As in many other protocols, POP3 also starts with a server banner.
          This banner contains the protocol version the server uses, the
          possible protocol extensions that it supports and, in many situations,
          the vendor and exact version number of the POP3 server.
        </para>
        <para>
          This information is useful only if the clients connecting to the POP3
          server can be trusted, as it might make bug hunting somewhat easier.
          On the other hand, this information is also useful for attackers when
          targeting this service.
        </para>
        <para>
          To prevent this, the banner can be replaced with a neutral one.
          Use the <parameter>request</parameter> hash with the 'GREETING' keyword as shown in the following example.
        </para>
       <example>
          <title>Rewriting the banner in POP3</title>
          <synopsis>class NeutralPop3(Pop3Proxy):
        def config(self):
        Pop3Proxy.config(self)
        self.request["GREETING"] = (POP3_REQ_POLICY, None, self.rewriteBanner)

        def rewriteBanner(self, response)
                self.response_param = "Pop3 server ready"
                return POP3_RSP_ACCEPT</synopsis>
        </example>
        <note>
        <para>
          Some protocol extensions (most notably APOP) use
          random characters in the greeting message as salt in the authentication
          process, so changing the banner when APOP is used effectively prevents
          APOP from working properly.
        </para>
        </note>
      </section>
      <section xml:id="pop3_stacking">
      <title>Stacking</title>
      <para>
      The available stacking modes for this proxy module are listed in the following table. For additional information on stacking, see <xref linkend="proxy_stacking"/>.
      </para>
      <inline type="actiontuple" target="action.pop3.stk"/>
      </section>
      <section xml:id="pop3_rejectbymail">
      <title>Rejecting viruses and spam</title>
        <para>
         When filtering messages for viruses or spam, the content vectoring modules reject infected and spam e-mails.
         In such cases the POP3 proxy notifies the client about the rejected message in a special e-mail.</para>
         <para>To reject e-mail messages using the <parameter>ERR</parameter> protocol element, set the <parameter>reject_by_mail</parameter>
         attribute to <parameter>FALSE</parameter>. However, this is not recommended, because several client applications handle
         <parameter>ERR</parameter> responses incorrectly.
        </para>
        <note>
        <para>
        Infected e-mails are put into the quarantine and deleted from the server.
        </para>
        </note>
      </section>
    </section>
    <section>
      <title>Related standards</title>
      <itemizedlist>
          <listitem>
            <para>
              Post Office Protocol Version 3 is described in RFC 1939.
            </para>
          </listitem>
          <listitem>
            <para>
              The POP3 AUTHentication command is described in RFC 1734.
            </para>
          </listitem>
        </itemizedlist>
    </section>
  </description>
  <metainfo>
    <enums>
      <enum maturity="stable" id="enum.pop3.req">
        <description>
          These are in request hashes.
        </description>
        <item>
          <name>POP3_REQ_ACCEPT</name>
        </item>
        <item>
          <name>POP3_REQ_ACCEPT_MLINE</name>
        </item>
        <item>
          <name>POP3_REQ_REJECT</name>
        </item>
        <item>
          <name>POP3_REQ_ABORT</name>
        </item>
        <item>
          <name>POP3_REQ_POLICY</name>
        </item>
      </enum>
      <enum maturity="stable" id="enum.pop3.rsp">
        <description>
          These are the pop3 response hashes.
        </description>
        <item>
          <name>POP3_RSP_ACCEPT</name>
        </item>
        <item>
          <name>POP3_RSP_REJECT</name>
        </item>
        <item>
          <name>POP3_RSP_ABORT</name>
        </item>
      </enum>
      <enum maturity="stable" id="enum.pop3.stk">
        <description>
          These are the pop3 proxy stacking capabilities.
        </description>
        <item>
          <name>POP3_STK_NONE</name>
        </item>
        <item>
          <name>POP3_STK_DATA</name>
        </item>
        <item>
          <name>POP3_STK_MIME</name>
        </item>
        <item>
          <name>POP3_STK_POLICY</name>
        </item>
      </enum>
    </enums>
    <actiontuples>
      <actiontuple maturity="stable" id="action.pop3.req" action_enum="enum.pop3.req">
        <description>
          Action codes for POP3 requests
        </description>
        <tuple action="POP3_REQ_ACCEPT">
          <args/>
          <description>
            <para>
              Accept the request without any modification.
            </para>
          </description>
        </tuple>
        <tuple action="POP3_REQ_ACCEPT_MLINE">
          <args/>
          <description>
            <para>
              Accept multiline requests without modification. Use it only if unknown commands has to be enabled (i.e. commands not specified in RFC 1939 or RFC 1734).
            </para>
          </description>
        </tuple>
        <tuple action="POP3_REQ_REJECT">
          <args>
            <string/>
          </args>
          <description>
            <para>
              Reject the request. The second parameter contains a string that is sent back to the client.
            </para>
          </description>
        </tuple>
        <tuple action="POP3_REQ_POLICY">
          <args>METHOD,METHOD</args>
          <description>
            <para>
              Call the function specified to make a decision about the event. See <xref linkend="proxy_policies"/> for details.
              This action uses two additional
              tuple items, which must be callable Python functions. The first function receives
              two parameters: self and command.
            </para>
            <para>
              The second one is called with an answer, (if the answer is multiline, it is called with every line) and receives two parameters: self and response_param.
            </para>
          </description>
        </tuple>
        <tuple action="POP3_REQ_ABORT">
          <args/>
          <description>
            <para>
              Reject the request and terminate the connection.
            </para>
          </description>
        </tuple>
      </actiontuple>
      <actiontuple maturity="stable" id="action.pop3.rsp" action_enum="enum.pop3.rsp">
        <description>
          Action codes for POP3 responses
        </description>
        <tuple action="POP3_RSP_ACCEPT">
          <args></args>
          <description>
            <para>Accept the response without any modification.
            </para>
          </description>
         </tuple>
        <tuple action="POP3_RSP_REJECT">
          <args></args>
          <description>
            <para>Reject the response.
            </para>
          </description>
         </tuple>
        <tuple action="POP3_RSP_ABORT">
          <args></args>
          <description>
            <para>Reject the response and terminate the connection.</para>
          </description>
         </tuple>
      </actiontuple>
      <actiontuple maturity="stable" id="action.pop3.stk" action_enum="enum.pop3.stk">
        <description>
          Action codes for proxy stacking
        </description>
        <tuple action="POP3_STK_POLICY">
          <args></args>
          <description>
            <para>
            Call the function specified to decide which part (if any) of the traffic should be passed to the stacked proxy.
            </para>
          </description>
        </tuple>
        <tuple action="POP3_STK_NONE">
          <args></args>
          <description>
            <para>
            No additional proxy is stacked into the POP3 proxy.
            </para>
          </description>
         </tuple>
        <tuple action="POP3_STK_MIME">
          <args>
            <link id="action.zorp.stack"/>
          </args>
          <description>
            <para>The data part of the traffic including the MIME headers is passed to the specified stacked proxy.
            </para>
          </description>
         </tuple>
        <tuple action="POP3_STK_DATA">
          <args>
            <link id="action.zorp.stack"/>
          </args>
          <description>
            <para>Only the data part of the traffic is passed to the specified stacked proxy.
            </para>
          </description>
        </tuple>
      </actiontuple>
    </actiontuples>
  </metainfo>
</module>
"""
from Zorp import *
from Proxy import Proxy

POP3_REQ_ACCEPT         =   1
POP3_REQ_ACCEPT_MLINE   = 100
POP3_REQ_REJECT         =   3
POP3_REQ_ABORT          =   4
POP3_REQ_POLICY         =   6

POP3_RSP_ACCEPT         = 1
POP3_RSP_REJECT         = 3
POP3_RSP_ABORT          = 4

POP3_STK_NONE           = 1
POP3_STK_DATA           = 2
POP3_STK_MIME           = 3
POP3_STK_POLICY         = 6

class AbstractPop3Proxy(Proxy):
    """<class maturity="stable" abstract="yes">
      <summary>
        Class encapsulating the abstract POP3 proxy.
      </summary>
      <description>
      <para>
      This class implements an abstract POP3 proxy - it serves as a starting point for customized proxy classes, but is itself not directly usable. Service definitions should refer to a customized class derived from AbstractPop3Proxy, or a predefined Pop3Proxy proxy class. AbstractPop3Proxy denies all requests by default.
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
              Timeout in milliseconds. If no packet arrives within this interval,
              connection is dropped.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>username</name>
            <type>
              <string/>
            </type>
            <default>n/a</default>
            <conftime/>
            <runtime>
              <read/>
            </runtime>
            <description>
              Username as specified by the client.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>password</name>
            <type>
              <string/>
            </type>
            <default></default>
            <conftime/>
            <runtime>
              <read/>
            </runtime>
            <description>
              Password sent to the server (if any).
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>max_request_line_length</name>
            <type>
              <integer/>
            </type>
            <default>90</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Maximum allowed line length for client requests.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>max_response_line_length</name>
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
              Maximum allowed line length for server responses.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>max_username_length</name>
            <type>
              <integer/>
            </type>
            <default>8</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Maximum allowed length of usernames.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>max_password_length</name>
            <type>
              <integer/>
            </type>
            <default>16</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Maximum allowed length of passwords.
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
              When a command or response is passed to the policy level, its value can be changed to this value. (It has effect only if the return value is not POP3_*_ACCEPT).
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
              When a command or response is passed to the policy level, the value its parameters can be changed to this value. (It has effect only if the return value is not POP3_*_ACCEPT).
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>response_multiline</name>
            <type>
              <boolean/>
            </type>
            <default>n/a</default>
            <conftime/>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Enable multiline responses.
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
              When a command is passed to the policy level, the value of its parameters can be changed to this value.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>request</name>
            <type>
              <hash>
                <key>
                  <string/>
                </key>
                <value>
                  <link id="enum.pop3.req"/>
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
              Normative policy hash for POP3 requests
            indexed by the command name (e.g.: "USER", "UIDL", etc.). See also <xref linkend="pop3_policies"/>.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>response_stack</name>
            <type>
              <hash>
                <key>
                  <string/>
                </key>
                <value>
                  <link id="action.pop3.stk"/>
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
            Hash containing the stacking policy for multiline POP3 responses. The hash
            is indexed by the POP3 response. See also <xref
            linkend="pop3_stacking"/>.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>session_timestamp</name>
            <type>
              <string/>
            </type>
            <default>n/a</default>
            <conftime/>
            <runtime>
              <read/>
            </runtime>
            <description>
              If the POP3 server implements the APOP command, with the greeting message it sends a timestamp, which is stored in this parameter.
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
            <name>permit_longline</name>
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
              In multiline answer (especially in downloaded messages) sometimes very long lines can appear. Enabling this option allows the unlimited long lines in multiline answers.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>max_authline_count</name>
            <type>
              <integer/>
            </type>
            <default>4</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Maximum number of lines that can be sent during the authentication
              conversation. The default value is enough for password authentication, but might have to be increased for other types of authentication.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>reject_by_mail</name>
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
              If the stacked proxy or content vectoring module rejects an e-mail message, reply with a special e-mail message instead
              of an <parameter>ERR</parameter> response. See <xref linkend="pop3_rejectbymail"/> for details.
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    name = "pop3"

    def __init__(self, session):
        """<method maturity="stable" internal="yes">
          <summary>
            Initialize a Pop3Proxy instance.
          </summary>
          <description>
          <para>
            Create and set up a Pop3Proxy instance.
          </para>
          </description>
          <metainfo>
          <arguments>
            <argument>
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
        Proxy.__init__(self, session)

class Pop3Proxy(AbstractPop3Proxy):
    """<class maturity="stable">
      <summary>
        Default POP3 proxy based on AbstractPop3Proxy.
      </summary>
      <description>
        <para>
          Pop3Proxy is the default POP3 proxy based on AbstractPop3Proxy, allowing the most commonly used requests.
        </para>
        <para>The following requests are permitted: APOP; DELE; LIST; LAST; NOOP; PASS; QUIT; RETR; RSET; STAT; TOP; UIDL; USER; GREETING.
        All other requests (including CAPA) are rejected.
        </para>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """
    def config(self):
        """<method internal="yes">
          <summary>
            Default config event handler.
          </summary>
          <description>
            <para>
              Enables the most common POP3 methods so we have a
              useful default configuration.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """

        self.request["APOP"] = POP3_REQ_ACCEPT
        self.request["DELE"] = POP3_REQ_ACCEPT
        self.request["LIST"] = POP3_REQ_ACCEPT
        self.request["LAST"] = POP3_REQ_ACCEPT
        self.request["NOOP"] = POP3_REQ_ACCEPT
        self.request["PASS"] = POP3_REQ_ACCEPT
        self.request["QUIT"] = POP3_REQ_ACCEPT
        self.request["RETR"] = POP3_REQ_ACCEPT
        self.request["RSET"] = POP3_REQ_ACCEPT
        self.request["STAT"] = POP3_REQ_ACCEPT
        self.request["TOP"]  = POP3_REQ_ACCEPT
        self.request["UIDL"] = POP3_REQ_ACCEPT
        self.request["USER"] = POP3_REQ_ACCEPT
        self.request["CAPA"] = POP3_REQ_REJECT
        self.request["*"]    = POP3_REQ_REJECT

        self.request["GREETING"] = POP3_REQ_ACCEPT
