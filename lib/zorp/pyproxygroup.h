/***************************************************************************
 *
 * Copyright (c) 2000-2014 BalaBit IT Ltd, Budapest, Hungary
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation.
 *
 * Note that this permission is granted for only version 2 of the GPL.
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ***************************************************************************/

#ifndef ZORP_PYPROXYGROUP_H_INCLUDED
#define ZORP_PYPROXYGROUP_H_INCLUDED

#include <zorp/pystruct.h>
#include <zorp/proxygroup.h>

ZPolicyObj *z_policy_proxy_group_new(gint max_secondary_sessions);
ZProxyGroup *z_policy_proxy_group_get_proxy_group(ZPolicyObj *s);

static inline gboolean
z_policy_proxy_group_check(ZPolicyObj *s)
{
  return z_policy_struct_check(s, Z_PST_PROXY_GROUP);
}

void z_policy_proxy_group_module_init(void);

#endif
