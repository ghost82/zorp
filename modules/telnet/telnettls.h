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

#ifndef ZORP_MODULES_TELNET_TELNETTLS_H_INCLUDED
#define ZORP_MODULES_TELNET_TELNETTLS_H_INCLUDED

#include "telnet.h"

enum
  {
    TELNET_TLS_FOLLOWS_SUBOPTION = 1
  };

gboolean telnet_tls_is_negotiation_complete(TelnetProxy *self);
gboolean telnet_tls_is_negotiation_complete_on_side(TelnetProxy *self, ZEndpoint ep);
gboolean telnet_tls_start_negotiate(TelnetProxy *self);
gboolean telnet_tls_start_negotiate_on_side(TelnetProxy *self, ZEndpoint ep);
ZVerdict telnet_tls_handle_option(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option);
ZVerdict telnet_tls_handle_suboption(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption);

#endif /* ZORP_MODULES_TELNET_TELNETTLS_H_INCLUDED */
