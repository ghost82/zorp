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
## Author  : Bazsi
## Auditor : kisza
## Last audited version: 1.2
## Notes:
##
############################################################################

"""<module maturity="stable">
<!-- FIXME: reindent -->
<summary>
   Module defining interface to the AnyPy proxy.
</summary>
  <description>
    <para>
      This module defines an interface to the AnyPy proxy as implemented in Zorp.
      AnyPy is basically a Python proxy which means that the proxy behaviour is
      defined in Python by the administrator.
    </para>
  <section>
    <title>Related standards</title>
    <para>
    </para>
  </section>
  </description>
  <metainfo>
    <attributes/>
  </metainfo>
</module>"""

from Proxy import Proxy

# policy verdicts
ANYPY_UNSPEC     = 0 # policy doesn't specify it, do something sensible
ANYPY_ACCEPT     = 1
ANYPY_DENY       = 2
ANYPY_REJECT     = 3 # continue and tell the client that we didn't do it
ANYPY_ABORT      = 4 # abort the connection
ANYPY_DROP       = 5 # continue and don't do it
ANYPY_POLICY     = 6 # Policy level will decide what to do
ANYPY_ERROR      = 7 # Error occurred try to nice fail

class AbstractAnyPyProxy(Proxy):
    """<class maturity="stable" abstract="yes">
    <summary>
      Class encapsulating an AnyPy proxy.
    </summary>
      <description>
        <para>
          This class encapsulates AnyPy, a proxy module calling a Python
          function to do all of its work. It can be used for defining proxies
          for protocols not directly supported by Zorp.
        </para>
        <warning>
          <para>
            This proxy class is a basis for creating a custom
            proxy, and cannot be used on its own. Create a new proxy class
            using the AnyPyProxy as its parent, and implement the proxyThread
            method to handle the traffic.
          </para>
          <para>
            Your code will be running as the proxy to transmit protocol elements.
            When writing your code, take care and be security conscious: do not
            make security vulnerabilities.
          </para>
        </warning>
      </description>
    <metainfo>
      <attributes>
        <attribute maturity="stable">
          <name>client_max_line_length</name>
          <type>
            <integer/>
          </type>
          <default>4096</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
          </runtime>
          <description>
              Size of the line buffer in the client stream in bytes. Default value: 4096
          </description>
        </attribute>
        <attribute maturity="stable">
          <name>server_max_line_length</name>
          <type>
            <integer/>
          </type>
          <default>4096</default>
          <conftime>
            <read/>
            <write/>
          </conftime>
          <runtime>
            <read/>
          </runtime>
          <description>
              Size of the line buffer in the server stream in bytes. Default value: 4096
          </description>
        </attribute>
      </attributes>
    </metainfo>
    </class>
    """
    name = "anypy"
    def __init__(self, session):
        """<method maturity="stable">
        <summary>
          Constructor to initialize an AnyPy instance.
        </summary>
        <description>
          <para>
            This constructor initializes a new AnyPy instance
            based on its arguments, and calls the inherited constructor.
          </para>
        </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>session</name>
                <type>SESSION</type>
                <description>
                  The session to be inspected with the proxy instance.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        Proxy.__init__(self, session)

    def proxyThread(self):
        """<method maturity="stable">
        <summary>
          Function called by the low-level proxy core to transfer requests.
        </summary>
        <description>
          <para>
            This function is called by the proxy module to
            transfer requests. It can use the
            'self.session.client_stream' and
            'self.session.server_stream' streams to
            read data from and write data to.
          </para>
        </description>
        <metainfo>
          <arguments/>
        </metainfo>
        </method>
        """
        raise NotImplementedError

class AnyPyProxy(AbstractAnyPyProxy):
    """<class maturity="stable">
    <summary>
      Class encapsulating the default AnyPy proxy.
    </summary>
      <description>
        <para>
          This class encapsulates AnyPy, a proxy module calling a Python
          function to do all of its work. It can be used for defining proxies
          for protocols not directly supported by Zorp.
        </para>
        <section>
          <title>Note</title>
          <para>
            This proxy class can only be used as a basis for creating a custom
            proxy and cannot be used on its own. Please create a new proxy class
            with the AnyPyProxy as its parent and implement the proxyThread
            method for handling traffic.
          </para>
          <para>
            Your code will be running as the proxy to transmit protocol elements,
            you'll have to take care and be security conscious not to
            make security vulnerabilities.
          </para>
        </section>
      </description>
    <metainfo>
      <attributes/>
    </metainfo>
    </class>
    """
    pass
