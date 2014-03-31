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

"""<module internal="yes" />

"""

CORE_SESSION = "core.session"
CORE_DEBUG = "core.debug"
CORE_ERROR = "core.error"
CORE_POLICY = "core.policy"
CORE_MESSAGE = "core.message"
CORE_AUTH = "core.auth"
CORE_INFO = "core.info"
CORE_ALERTING = "core.alerting"

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
    import syslog
    logmsg = "%s(%d): (%s): %s" % (logclass, verbosity, sessionid, msg)
    syslog.syslog(syslog.LOG_INFO, logmsg)
