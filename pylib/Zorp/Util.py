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
  <summary>Module containing utility functions used throughout Zorp.</summary>
  <description>
    <para>
    </para>
  </description>
</module>
"""

import collections

def isSequence(value):
    if isinstance(value, basestring):
        return False

    return isinstance(value, collections.Sequence)

def makeSequence(value):
    if not isSequence(value):
        return (value, )
    return value

def enum(*args, **kw):

    def reverse_enumerate(s):
        return zip(s, range(len(s)))

    def to_string_method(enums):
        rev_map=dict((v,k) for k, v in enums.iteritems())
        return staticmethod(lambda value: rev_map[value])

    enums = dict(reverse_enumerate(args), **kw)
    return type('Enum', (object,), dict(enums, to_string=to_string_method(enums)))

def parseIfaceGroupAliases(filename='/etc/iproute2/group'):
    group_aliases = { }
    group_file = open(filename, 'r')
    try:
        for group_line in group_file:
            if group_line == '' or group_line[0] == '#':
                continue

            (num, alias) = group_line.split()
            num = int(num, 10)
            if num < 0 or num > 255 or num in group_aliases:
                raise ValueError

            group_aliases[alias] = num
    except ValueError:
        group_aliases  = { }
    finally:
        group_file.close()

    return group_aliases
