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

#ifndef ZORP_MODULES_TELNET_TELNETSUBOPTION_H_INCLUDED
#define ZORP_MODULES_TELNET_TELNETSUBOPTION_H_INCLUDED

#include "telnet.h"

ZVerdict telnet_subopt_terminal_type(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption);
ZVerdict telnet_subopt_terminal_speed(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption);
ZVerdict telnet_subopt_x_display(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption);
ZVerdict telnet_subopt_new_env(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption);
ZVerdict telnet_subopt_naws(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption);
ZVerdict telnet_subopt_unknown(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption);

#endif
