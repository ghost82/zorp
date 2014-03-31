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

#ifndef ZORP_MODULES_TELNET_TELNETOPTION_H_INCLUDED
#define ZORP_MODULES_TELNET_TELNETOPTION_H_INCLUDED

#include "telnet.h"

gboolean telnet_option_do(TelnetProxy *self, const ZEndpoint ep, const guint8 option);
gboolean telnet_option_will(TelnetProxy *self, const ZEndpoint ep, const guint8 option);

gboolean telnet_option_do_in_progress(TelnetProxy *self, const ZEndpoint ep, const guint8 option);
gboolean telnet_option_will_in_progress(TelnetProxy *self, const ZEndpoint ep, const guint8 option);

void telnet_option_command_received(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option);
void telnet_option_command_sent(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option);

#endif
/*
# Local Variables:
# indent-tabs-mode: nil
# End:
*/
