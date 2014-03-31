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

#ifndef ZORP_SESSIONID_H_INCLUDED
#define ZORP_SESSIONID_H_INCLUDED

#include <glib.h>

typedef gint ZSessionId;

static inline ZSessionId
z_session_id_get_next(volatile ZSessionId *id)
{
#if GLIB_CHECK_VERSION(2, 30, 0)
  /* In glib >= 2.30 g_atomic_int_exchange_and_add() is deprecated, but
   * g_atomic_int_add() has been changed to return the old value. */
  return g_atomic_int_add(id, 1);
#else
  return g_atomic_int_exchange_and_add(id, 1);
#endif
}

#endif
