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
    The Encryption module defines encryption related policies.
  </summary>
  <description>
    <para>
      FIXME: fill here.
    </para>
    <para>
        Starting with Zorp 3.3FR1, the Proxy module provides a common SSL/TLS framework for the Zorp proxies as well. This SSL framework replaces and extends the functionality of the Pssl proxy, providing support for STARTTLS as well. The Pssl proxy has become obsolete, but still provides a compatibility layer for older configuration files, but you are recommended to update your configuration to use the new SSL framework as soon as possible. The SSL framework is described in <xref linkend="chapter_ssl"/>.
    </para>
    <note>
        <para>STARTTLS support is currently available only for the Ftp proxy to support FTPS sessions and for the SMTP proxy.</para>
    </note>
    <inline type="enum" target="enum.ssl.verify"/>
    <inline type="enum" target="enum.ssl.method"/>
    <inline type="enum" target="enum.ssl.ciphers"/>
    <inline type="enum" target="enum.ssl.hso"/>
    <inline type="enum" target="enum.ssl.client_connection_security"/>
    <inline type="enum" target="enum.ssl.server_connection_security"/>
    <inline type="const" target="const.ssl.log"/>
    <inline type="const" target="const.ssl.hs"/>
  </description>
  <metainfo>
    <enums>
      <enum maturity="stable" id="enum.ssl.verify">
        <description>
          Certificate verification settings
        </description>
        <item>
          <name>SSL_VERIFY_NONE</name>
          <description>Automatic certificate verification is disabled.</description>
        </item>
<!--        <item>
          <name>SSL_VERIFY_OPTIONAL</name>
          <description>Certificate is optional, all certificates are accepted.</description>
        </item>-->
        <item>
          <name>SSL_VERIFY_OPTIONAL_UNTRUSTED</name>
          <description>Certificate is optional, if present, both trusted and untrusted certificates are accepted.</description>
        </item>
        <item>
          <name>SSL_VERIFY_OPTIONAL_TRUSTED</name>
          <description>Certificate is optional, but if a certificate is present, only  certificates signed by a trusted CA are accepted.</description>
        </item>
        <item>
          <name>SSL_VERIFY_REQUIRED_UNTRUSTED</name>
          <description>Valid certificate is required, both trusted and untrusted certificates are accepted.</description>
        </item>
        <item>
          <name>SSL_VERIFY_REQUIRED_TRUSTED</name>
          <description>Certificate is required, only valid certificates signed by a trusted CA are accepted.</description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.method">
        <description>
          Constants for SSL/TLS protocol selection
        </description>
        <item maturity="obsolete">
          <name>SSL_METHOD_SSLV23</name>
          <description>
           Permit the use of SSLv2 and v3.
          </description>
        </item>
        <item>
          <name>SSL_METHOD_SSLV2</name>
          <description>
           Permit the use of SSLv2 exclusively.
          </description>
        </item>
        <item>
          <name>SSL_METHOD_SSLV3</name>
          <description>
                Permit the use of SSLv3 exclusively.
          </description>
        </item>
        <item>
          <name>SSL_METHOD_TLSV1</name>
          <description>
                Permit the use of TLSv1 exclusively.
          </description>
        </item>
        <item>
          <name>SSL_METHOD_ALL</name>
          <description>
           Permit the use of all the supported (SSLv2, SSLv3, and TLSv1) protocols.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.ciphers">
        <description>
          Constants for cipher selection
        </description>
        <item>
          <name>SSL_CIPHERS_ALL</name>
          <description>
           Permit the use of all supported ciphers, including the 40 and 56 bit exportable ciphers.
          </description>
        </item>
        <item>
          <name>SSL_CIPHERS_HIGH</name>
          <description>
                Permit only the use of ciphers which use at least 128 bit long keys.
          </description>
        </item>
        <item>
          <name>SSL_CIPHERS_MEDIUM</name>
          <description>
                Permit only the use of ciphers which use 128 bit long keys.
          </description>
        </item>
        <item>
          <name>SSL_CIPHERS_LOW</name>
          <description>
                Permit only the use of ciphers which use keys shorter then 128 bits.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.hso">
        <description>
          Handshake order.
        </description>
        <item>
          <name>SSL_HSO_CLIENT_SERVER</name>
          <description>
                Perform the SSL-handshake with the client first.
          </description>
        </item>
        <item>
          <name>SSL_HSO_SERVER_CLIENT</name>
          <description>
                Perform the SSL-handshake with the server first.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.client_connection_security">
        <description>
          Client connection security type.
        </description>
        <item>
          <name>SSL_NONE</name>
          <description>
                Disable encryption between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_FORCE_SSL</name>
          <description>
                Require encrypted communication between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_ACCEPT_STARTTLS</name>
          <description>
                Permit STARTTLS sessions. Currently supported only in the Ftp proxy.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.server_connection_security">
        <description>
          Server connection security type.
        </description>
        <item>
          <name>SSL_NONE</name>
          <description>
                Disable encryption between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_FORCE_SSL</name>
          <description>
                Require encrypted communication between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_FORWARD_STARTTLS</name>
          <description>
                Forward STARTTLS requests to the server. Currently supported only in the Ftp proxy.
          </description>
        </item>
      </enum>
    </enums>
    <constants>
      <constantgroup maturity="stable" id="const.ssl.log">
        <description>
          Verbosity level of the log messages
        </description>
        <item>
          <name>SSL_ERROR</name>
          <description>
                Log only errors of the SSL framework.
          </description>
        </item>
        <item>
          <name>SSL_DEBUG</name>
          <description>
                Enable verbose logging of the SSL framework.
          </description>
        </item>
      </constantgroup>
      <constantgroup maturity="stable" id="const.ssl.hs">
        <description>
          Handshake policy decisions
        </description>
        <item>
          <name>SSL_HS_ACCEPT</name>
          <value>0</value>
          <description>
                Accept the connection.
          </description>
        </item>
        <item>
          <name>SSL_HS_REJECT</name>
          <value>1</value>
          <description>
                Reject the connection.
          </description>
        </item>
        <item>
          <name>SSL_HS_POLICY</name>
          <value>6</value>
          <description>
                Use a policy to decide about the connection.
          </description>
        </item>
        <item>
          <name>SSL_HS_VERIFIED</name>
          <value>10</value>
          <description>
                <!--FIXME-->
          </description>
        </item>
      </constantgroup>
    </constants>
  </metainfo>
</module>
"""

import Globals
from Keybridge import X509KeyBridge
from Zorp import log, CORE_POLICY

class EncryptionPolicy(object):
    """
    <class maturity="stable" type="encryptionpolicy">
      <summary>Class encapsulating named encryption settings.</summary>
      <description>
        <para>
          This class encapsulates a name and an associated Encryption
          settings instance. Encryption policies provide a way to re-use
          encryption settings without having to define encryption settings
          for each service individually.
        </para>
      </description>
    </class>
    """

    def __init__(self, name, encryption):
        """
        <method maturity="stable">
          <summary>Constructor to create an encryption policy.</summary>
          <description>
            <para>
              This constructor initializes an encryption policy.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument>
                <name>name</name>
                <type>
                  <string/>
                </type>
                <description>Name identifying the encryption policy.</description>
              </argument>
              <argument>
                <name>encryption</name>
                <type>
                  <class filter="encryption" instance="yes"/>
                </type>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.name = name
        self.encryption = encryption

        if Globals.encryption_policies.has_key(name):
            raise ValueError, "Duplicate encryption policy name name: %s" % name
        Globals.encryption_policies[name] = self

    def apply(self, proxy):
        """
        <function internal="yes"/>
        """
        self.encryption.apply(proxy)

def getEncryptionPolicy(name):
    """
    <function internal="yes"/>
    """
    if name:
        if Globals.encryption_policies.has_key(name):
            return Globals.encryption_policies[name]
        else:
            log(None, CORE_POLICY, 3, "No such encryption policy; name='%s'", name)
    return None

class Encryption(object):
    """
    <class maturity="stable" abstract="yes">
      <summary>
        Class encapsulating the abstract encryption settings.
      </summary>
    </class>
    """
    def __init__(self):
        """<method internal="yes">
        </method>
        """
        super(Encryption, self).__setattr__('settings', {})

    def __setattr__(self, name, value):
        """<method internal="yes">
        </method>
        """
        self.settings[name] = value

    def __getattr__(self, name):
        """<method internal="yes">
        </method>
        """
        if self.settings.has_key(name):
            return self.settings[name]
        else:
            raise AttributeError, "No such attribute: %s" % name

    def config(self):
        """<method internal="yes">
        </method>
        """
        pass

    def __post_config__(self):
        """<method internal="yes">
        </method>
        """
        pass

    def apply(self, proxy):
        """<method internal="yes">
        </method>
        """
        self.config()
        self.__post_config__()

class TLSEncryption(Encryption):
    """
    <class maturity="stable" abstract="no">
      <summary>
        Class encapsulating TLS encryption settings.
      </summary>
      <description>
        FIXME
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>handshake_timeout</name>
            <type>
              <integer/>
            </type>
            <default>30000</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              SSL handshake timeout in milliseconds.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>permit_invalid_certificates</name>
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
              Accept any kind of verification failure when UNTRUSTED verify_type is set.
              E.g.: accept expired, self-signed, etc. certificates.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>permit_missing_crl</name>
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
              This option has effect only if the CRL directories are set, that is, the
              attributes relevant to the connection are set:
              <parameter>client_crl_directory</parameter>,
              <parameter>server_crl_directory</parameter>,
              <parameter>client_verify_crl_directory</parameter>,
              <parameter>server_verify_crl_directory</parameter>. If Zorp does not find
              a CRL in these directories that matches the CAs in the certificate chain and
              <parameter>permit_missing_crl</parameter> is set to FALSE, Zorp rejects the
              certificate. Otherwise, the certificate is accepted even if no matching CRL is
              found.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>handshake_seq</name>
            <type>
              <link id="enum.ssl.hso"/>
            </type>
            <default>SSL_HSO_CLIENT_SERVER</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Handshake order. SSL_HSO_CLIENT_SERVER performs the client side handshake first, SSL_HSO_SERVER_CLIENT the server side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_connection_security</name>
            <type>
              <link id="enum.ssl.client_connection_security"/>
            </type>
            <default>SSL_NONE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Enable SSL on the client side of the proxy.
              This requires setting up a client private key and a certificate.
            </description>
          </attribute>
          <attribute internal="yes">
            <name>client_handshake</name>
            <type>HASH:empty:RW:R</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies policy callbacks for various SSL handshake phases.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_verify_type</name>
            <type>
              <link id="enum.ssl.verify"/>
            </type>
            <default>SSL_VERIFY_REQUIRED_TRUSTED</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Verification setting of the peer certificate on the client side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_verify_depth</name>
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
              The longest accepted CA verification chain.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_local_privatekey</name>
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
              The private key of the firewall on the client side. Specified as a string in PEM format.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_local_privatekey_passphrase</name>
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
              Passphrase used to access <parameter>client_local_privatekey</parameter>.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>client_local_certificate</name>
            <type>X509:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              The certificate associated to <parameter>client_local_privatekey</parameter> to be used on the client side.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>client_peer_certificate</name>
            <type>X509:empty:R:R</type>
            <default>empty</default>
            <conftime>
              <read/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              The certificate returned by the peer on the client side.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>client_local_ca_list</name>
            <type>HASH;INTEGER;X509:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              A hash of trusted certificates. The items in this hash are used to verify client certificates.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>client_local_crl_list</name>
            <type>HASH;INTEGER;X509_CRL:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              A hash of Certificate Revocation Lists, associated to CA certificates in <parameter>client_local_ca_list</parameter>.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_ssl_method</name>
            <type>
              <link id="enum.ssl.method"/>
            </type>
            <default>SSL_METHOD_ALL</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies the allowed SSL/TLS protocols on the client side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_disable_proto_sslv2</name>
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
              Specifies that SSLv2 should be disabled even if the method selection would otherwise support SSLv2.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_disable_proto_sslv3</name>
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
              Specifies that SSLv3 should be disabled even if the method selection would otherwise support SSLv3.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_disable_proto_tlsv1</name>
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
              Specifies that TLSv1 should be disabled even if the method selection would otherwise support TLSv1.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_ssl_cipher</name>
            <type>
              <link id="enum.ssl.ciphers"/>
            </type>
            <default>SSL_CIPHERS_ALL</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies the allowed ciphers on the client side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_connection_security</name>
            <type>
              <link id="enum.ssl.server_connection_security"/>
            </type>
            <default>SSL_NONE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Enable SSL on the server side of the proxy.
              This requires setting up a private key and a certificate on Zorp.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>server_handshake</name>
            <type>HASH:empty:RW:R</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies policy callbacks for various SSL handshake phases.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_verify_type</name>
            <type>
              <link id="enum.ssl.verify"/>
            </type>
            <default>SSL_VERIFY_REQUIRED_TRUSTED</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Verification settings of the peer certificate on the server side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_verify_depth</name>
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
              The longest accepted CA verification chain.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_local_privatekey</name>
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
              The private key of the firewall on the server side, specified as a string in PEM format.
              Server side key and certificate are optional.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_local_privatekey_passphrase</name>
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
              Passphrase used to access <parameter>server_local_privatekey</parameter>.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>server_local_certificate</name>
            <type>X509:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              The certificate to be used on the server side, associated with <parameter>server_local_privatekey</parameter>.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>server_peer_certificate</name>
            <type>X509:empty:R:R</type>
            <default>empty</default>
            <conftime>
              <read/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              The certificate returned by the peer on the server side.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>server_local_ca_list</name>
            <type>HASH;INTEGER;X509:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Hash of trusted certificates. The items in this hash are used to verify server certificates.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>server_peer_ca_list</name>
            <type>HASH;INTEGER;X509:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Hash of names of trusted CAs as returned by the server to aid the selection of a local certificate.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>server_local_crl_list</name>
            <type>HASH;INTEGER;X509_CRL:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Hash of Certificate Revocation Lists, associated to CA certificates in <parameter>server_local_ca_list</parameter>.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_ssl_method</name>
            <type>
              <link id="enum.ssl.method"/>
            </type>
            <default>SSL_METHOD_ALL</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies the SSL/TLS protocols allowed on the server side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_disable_proto_sslv2</name>
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
              Specifies that SSLv2 should be disabled even if the method selection would otherwise support SSLv2.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_disable_proto_sslv3</name>
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
              Specifies that SSLv3 should be disabled even if the method selection would otherwise support SSLv3.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_disable_proto_tlsv1</name>
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
              Specifies that TLSv1 should be disabled even if the method selection would otherwise support TLSv1.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_ssl_cipher</name>
            <type>
              <link id="enum.ssl.ciphers"/>
            </type>
            <default>SSL_CIPHERS_ALL</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies the ciphers allowed on the server side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_check_subject</name>
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
              Specifies
              whether the Subject of the
              server side certificate is
              checked against application
              layer information
              (e.g.: whether it matches the
              hostname in the URL). See also <xref linkend="certificate_verification"/>.
            </description>
          </attribute>

          <!-- FIXME: SSL attributes -->

          <attribute maturity="stable">
            <name>client_cert_file</name>
            <type>
              <certificate key="no" cert="yes"/>
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
              File containing the client-side certificate.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_key_file</name>
            <type>
              <certificate key="yes" cert="no"/>
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
              File containing the client-side private key.
            </description>
          </attribute>
          <attribute state="stable">
            <name>client_keypair_files</name>
            <type>
              <certificate cert="yes" key="yes"/>
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
              A tuple of two file names containing the certificate and
              key files. Using <parameter>client_keypair_files</parameter> is an alternative to using
              the <parameter>client_cert_file</parameter> and <parameter>client_key_file</parameter> attributes.
            </description>
          </attribute>
          <attribute state="stable">
            <name>client_keypair_generate</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime/>
            <description>
              Enables keybridging towards the clients. (Specifies whether to generate new certificates.)
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_ca_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the trusted CA certificates are stored. Note that every certificate
              in this directory is loaded when the proxy is starting up. If
              <parameter>client_verify_type</parameter> is set to verify
              client certificates, Zorp sends the subject names of CA certificates
              stored in this directory to the client to request a certificate
              from these CAs.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_verify_ca_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the trusted CA certificates are stored. CA certificates are loaded
              on-demand from this directory when verifying the client certificate. Use this
              option instead of <parameter>client_ca_directory</parameter> if possible.
              Note that when using the <parameter>client_verify_ca_directory</parameter> option, Zorp
              does not send the list of accepted CAs to the client if the certificate of the client
              is verified.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_crl_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the CRLs associated with trusted CAs are stored. Note that every
              CRL in this directory is loaded when the proxy is starting up and this might
              require a huge amount of memory.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>client_verify_crl_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the CRLs associated with trusted CAs are stored. CRLs are loaded
              on-demand from this directory when verifying the client certificate. Use this
              option instead of <parameter>client_crl_directory</parameter>.
            </description>
          </attribute>
          <attribute state="stable">
            <name>client_cagroup_directories</name>
            <type>
              <cagroup/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A tuple of the trusted CA certificate directory and
              the corresponding CRL directory.
            </description>
          </attribute>
          <attribute state="stable">
            <name>client_verify_cagroup_directories</name>
            <type>
              <cagroup/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A tuple of the trusted CA certificate directory and
              the corresponding CRL directory. This option sets both
              <parameter>client_verify_ca_directory</parameter>
              and <parameter>client_verify_crl_directory</parameter>.
            </description>
          </attribute>
          <attribute state="stable">
            <name>client_trusted_certs_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A directory where trusted IP - certificate assignments are
              stored. When a specific IP address introduces itself with the
              certificate stored in this directory, it is accepted regardless of
              its expiration or issuer CA. Each file in the directory should
              contain a certificate in PEM format and have the name of the IP
              address.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_cert_file</name>
            <type>
              <certificate key="no" cert="yes"/>
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
              File containing the server-side certificate.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_key_file</name>
            <type>
              <certificate key="yes" cert="no"/>
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
              File containing the server-side private key.
            </description>
          </attribute>
          <attribute state="stable">
            <name>server_keypair_files</name>
            <type>
              <certificate cert="yes" key="yes"/>
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
              A tuple of two file names containing the certificate and key
              files. Using <parameter>server_keypair_files</parameter> is an alternative to using the
              <parameter>server_cert_file</parameter> and <parameter>server_key_file</parameter> attributes.
            </description>
          </attribute>
          <attribute state="stable">
            <name>server_keypair_generate</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime/>
            <description>
              Enables keybridging towards the server. (Specifies whether to generate new certificates.)
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_ca_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the trusted CA certificates are stored. Please note that all certificates
              in the directory are loaded when the proxy is starting up.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_verify_ca_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the trusted CA certificates are stored. CA certificates are loaded
              on-demand from this directory when verifying the server certificate. Use this
              option instead of <parameter>server_ca_directory</parameter>.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_crl_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the CRLs associated with the trusted CAs are stored. Please note that all
              CRLs in the directory are loaded when the proxy is starting up and this might
              require a huge amount of memory.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>server_verify_crl_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the CRLs associated with trusted CAs are stored. CRLs are loaded
              on-demand from this directory when verifying the server certificate. Use this
              option instead of <parameter>server_crl_directory</parameter>.
            </description>
          </attribute>
          <attribute state="stable">
            <name>server_cagroup_directories</name>
            <type>
              <cagroup/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A tuple of the trusted CA certificate directory and
              the corresponding CRL directory. This option sets both
              <parameter>server_ca_directory</parameter>
              and <parameter>server_crl_directory</parameter>.
            </description>
          </attribute>
          <attribute>
            <name>server_verify_cagroup_directories</name>
            <type>
              <cagroup/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A tuple of the trusted CA certificate directory and
              the corresponding CRL directory. This option sets both
              <parameter>server_verify_ca_directory</parameter>
              and <parameter>server_verify_crl_directory</parameter>.
            </description>
          </attribute>
          <attribute state="stable">
            <name>server_trusted_certs_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A directory where trusted IP:port - certificate assignments are
              stored. When a specific IP address introduces itself with the
              certificate stored in this directory, it is accepted regardless
              of its expiration or issuer CA. Each file in the directory should
              contain a certificate in PEM format and should be named as
              'IP:PORT'.
            </description>
          </attribute>
          <attribute state="stable">
            <name>key_generator</name>
            <type>
              <class filter="x509keymanager" instance="yes"/>
            </type>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime/>
            <description>
              An instance of a X509KeyManager or derived class to generate keys
              automatically based on the keys on one of the other peers. Use
              X509KeyBridge to generate certificates automatically with a
              firewall hosted local CA.
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self):
        """<method internal="yes">
        </method>
        """
        super(TLSEncryption, self).__init__()

    def config(self):
        """<method internal="yes">
        </method>
        """
        super(TLSEncryption, self).config()

    def apply(self, proxy):
        """<method internal="yes">
        </method>
        """
        super(TLSEncryption, self).apply(proxy)

        for (name, value) in self.settings.items():
            setattr(proxy.ssl, name, value)

class TLSKeyBridgeEncryption(TLSEncryption):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating the TLS keybridge encryption settings.
      </summary>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>keybridge_key_file</name>
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
            </runtime>
            <description>
              The private key to be used for the newly generated certificates
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>keybridge_key_passphrase</name>
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
            </runtime>
            <description>
              Passphrase required to access the private key
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>keybridge_cache_directory</name>
            <type>
              <string/>
            </type>
            <default>/var/lib/zorp/keybridge-cache</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              The directory where all automatically generated certificates are cached
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>keybridge_trusted_ca_files</name>
            <type>
              <certificate cert="yes" key="yes" ca="yes"/>
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
              FIXME_keybridge_trusted_ca_files
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>keybridge_trusted_ca_cert_file</name>
            <type>
              <certificate key="no" cert="yes" ca="yes"/>
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
              CA certificate used for keybridging trusted certificates
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>keybridge_trusted_ca_key_file</name>
            <type>
              <certificate key="yes" cert="no" ca="yes"/>
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
              Key file for CA certificate used for keybridging trusted certificates
              The key file must have no passphrase.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>keybridge_untrusted_ca_files</name>
            <type>
              <certificate cert="yes" key="yes" ca="yes"/>
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
              FIXME_keybridge_untrusted_ca_files
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>keybridge_untrusted_ca_cert_file</name>
            <type>
              <certificate key="no" cert="yes" ca="yes"/>
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
              CA certificate used for keybridging untrusted certificates.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>keybridge_untrusted_ca_key_file</name>
            <type>
              <certificate key="yes" cert="no" ca="yes"/>
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
              Key file for CA certificate used for keybridging untrusted certificates.
              The key file must have no passphrase.
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    def __init__(self):
        """<method internal="yes">
        </method>
        """
        super(TLSKeyBridgeEncryption, self).__init__()

    def config(self):
        """<method internal="yes">
        </method>
        """
        super(TLSKeyBridgeEncryption, self).config()

        self.keybridge_key_file = None
        self.keybridge_key_passphrase = None
        self.keybridge_cache_directory = None
        self.keybridge_trusted_ca_files = None
        self.keybridge_trusted_ca_cert_file = None
        self.keybridge_trusted_ca_key_file = None
        self.keybridge_untrusted_ca_files = None
        self.keybridge_untrusted_ca_cert_file = None
        self.keybridge_untrusted_ca_key_file = None

    def __post_config__(self):
        """<method internal="yes">
        </method>
        """
        super(TLSKeyBridgeEncryption, self).__post_config__()

        if not self.keybridge_trusted_ca_files:
            self.keybridge_trusted_ca_files = (self.keybridge_trusted_ca_cert_file, self.keybridge_trusted_ca_key_file)

        if not self.keybridge_untrusted_ca_files:
            self.keybridge_untrusted_ca_files = (self.keybridge_untrusted_ca_cert_file, self.keybridge_untrusted_ca_key_file)

        self.key_generator = X509KeyBridge(self.keybridge_key_file,
                                           self.keybridge_cache_directory,
                                           self.keybridge_trusted_ca_files,
                                           self.keybridge_untrusted_ca_files,
                                           self.keybridge_key_passphrase)

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 8
# End:
