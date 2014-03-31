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

#ifndef AUTHORIZATION_H_INCLUDED
#define AUTHORIZATION_H_INCLUDED

#include <zorp/policy.h>
#include <zorp/proxy.h>

#define ZAuthProvider ZPolicyObj


gboolean
z_auth_provider_check_passwd(ZAuthProvider *self,
                                      gchar *session_id,
                                      gchar *username,
                                      gchar *passwd,
                                      gchar ***groups,
                                      ZProxy *proxy);
#endif
