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
  <summary>Module defining Zorp exception types.</summary>
  <description>
    <para>
    </para>
  </description>
  <metainfo>
    <constants>
      <constantgroup maturity="stable" id="cont.zorp.log_message">
        <description>Zorp exception types</description>
        <item><name>ZoneException</name><value>"Zone not found"</value></item>
        <item><name>ServiceException</name><value>"Service"</value></item>
        <item><name>DACException</name><value>"DAC policy violation"</value></item>
        <item><name>MACException</name><value>"MAC policy violation"</value></item>
        <item><name>AAException</name><value>"Authentication or authorization failed"</value></item>
        <item><name>LimitException</name><value>"Limit error"</value></item>
        <item><name>InternalException</name><value>"Internal error occurred"</value></item>
        <item><name>UserException</name><value>"Incorrect, or unspecified parameter"</value></item>
        <item><name>LicenseException</name><value>"Attempt to use unlicensed components"</value></item>
      </constantgroup>
    </constants>
  </metainfo>
</module>
"""

class ZorpException(Exception):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(ZorpException, self).__init__()
        self.what = ''
        self.detail = detail

    def __str__(self):
        """<method internal="yes">
        </method>"""
        return '%s: %s' % (self.what, self.detail)

class ZoneException(ZorpException):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(ZoneException, self).__init__(detail)
        self.what = 'Zone not found'

class ServiceException(ZorpException):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(ServiceException, self).__init__(detail)
        self.what = 'Service'

class DACException(ZorpException):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(DACException, self).__init__(detail)
        self.what = 'DAC policy violation'

class MACException(ZorpException):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(MACException, self).__init__(detail)
        self.what = 'MAC policy violation'

class AAException(ZorpException):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(AAException, self).__init__(detail)
        self.what = 'Authentication or authorization failed'

# for compatibility
AuthException = AAException

class LimitException(ZorpException):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(LimitException, self).__init__(detail)
        self.what = 'Limit error'

class InternalException(ZorpException):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(InternalException, self).__init__(detail)
        self.what = 'Internal error occured'

class UserException(ZorpException):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(UserException, self).__init__(detail)
        self.what = 'Incorrect, or unspecified parameter'

class LicenseException(ZorpException):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(LicenseException, self).__init__(detail)
        self.what = 'Attempt to use unlicensed components'

class MatcherException(ZorpException):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(MatcherException, self).__init__(detail)
        self.what = 'Matcher error'

class ConfigException(ZorpException):
    """
    <class internal="yes"/>
    """
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(ConfigException, self).__init__(detail)
        self.what = 'Configuration error'
