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
 * Author: Laszlo Attila Toth
 *
 ***************************************************************************/

#ifndef ZORP_PROXY_COMMON_H_INCLUDED
#define ZORP_PROXY_COMMON_H_INCLUDED

/* a two-way connection between streams */

/* endpoint indexes */
typedef enum _ZEndpoint
  {
    EP_CLIENT,
    EP_SERVER,
    EP_MAX
  } ZEndpoint;

inline ZEndpoint& operator++(ZEndpoint &side)
{
  side = ZEndpoint(side + 1);
  return side;
}

#define EP_OTHER(ep) (ZEndpoint(1-(ep)))
#define EP_STR(ep)   ((ep) == EP_CLIENT ? "client" : "server")

typedef enum _ZDirection
  {
    EP_DIR_IN,
    EP_DIR_OUT,
    EP_DIR_MAX
  } ZDirection;

#define EP_DIR_OTHER(ep) (1-(ep))
#define EP_DIR_STR(ep)   ((ep) == EP_DIR_IN ? "input" : "output")

struct ZProxy;

#endif
