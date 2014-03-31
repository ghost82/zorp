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
 * Author:  Attila SZALAY <sasa@balabit.hu>
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include "pop3misc.h"

#include <zorp/log.h>

void
pop3_get_timestamp(Pop3Proxy *self)
{
  gchar *left;
  gchar *right;

  z_proxy_enter(self);
  g_string_assign(self->timestamp, "");
  if ((left = strchr(self->response_param->str, '<')) == NULL)
    z_proxy_return(self);

  if ((right = strchr(self->response_param->str, '>')) == NULL)
    z_proxy_return(self);

  if (left >= right)
    z_proxy_return(self);

  g_string_append_len(self->timestamp, left, right - left + 1);
  z_proxy_return(self);
}
