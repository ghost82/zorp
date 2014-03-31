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

#ifndef ZORP_MODULES_TELNET_TELNETSTATE_H_INCLUDED
#define ZORP_MODULES_TELNET_TELNETSTATE_H_INCLUDED

void telnet_state_register_callbacks(TelnetProxy *self, ZEndpoint ep);

void telnet_event_start_opneg(TelnetProxy *self);
void telnet_state_nt_wait_opneg(TelnetProxy *self);
void telnet_state_nt_wait_environment(TelnetProxy *self);
void telnet_state_nt_prompt_server(TelnetProxy *self);
void telnet_state_nt_prompt_user(TelnetProxy *self);
void telnet_state_nt_prompt_password(TelnetProxy *self);
void telnet_event_print_banner(TelnetProxy *self);

#endif
