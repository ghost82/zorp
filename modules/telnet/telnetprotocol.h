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

#ifndef ZORP_MODULES_TELNET_TELNETPROTOCOL_H_INCLUDED
#define ZORP_MODULES_TELNET_TELNETPROTOCOL_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/packetbuf.h>

typedef enum _TelnetProtocolState
  {
    PROTO_STATE_DATA,
    PROTO_STATE_ESCAPED,
    PROTO_STATE_OPNEG,
    PROTO_STATE_SUBNEG,
    PROTO_STATE_SUBNEG_ESCAPED,
    PROTO_STATE_QUIT,
  } TelnetProtocolState;

typedef gboolean (*TelnetProtocolReceivedCallback)(ZPktBuf *data, gpointer user_data);
typedef gboolean (*TelnetProtocolCommandReceivedCallback)(guint8 command, gpointer user_data);
typedef gboolean (*TelnetProtocolOpnegReceivedCallback)(guint8 command, guint8 option, gpointer user_data);

typedef struct _TelnetProtocol
{
  gchar *session_id;
  TelnetProtocolState state;

  /* buffers */
  ZPktBuf *data_buffer;
  ZPktBuf *subneg_buffer;
  guint8 command;

  /* callbacks */
  TelnetProtocolReceivedCallback data_received;
  gpointer data_received_user_data;
  TelnetProtocolReceivedCallback subneg_received;
  gpointer subneg_received_user_data;
  TelnetProtocolCommandReceivedCallback command_received;
  gpointer command_received_user_data;
  TelnetProtocolOpnegReceivedCallback opneg_received;
  gpointer opneg_received_user_data;
} TelnetProtocol;

void telnet_protocol_init(TelnetProtocol *self, const gchar *session_id);
void telnet_protocol_destroy(TelnetProtocol *self);

void telnet_protocol_set_data_received(TelnetProtocol *self,
                                       TelnetProtocolReceivedCallback callback,
                                       gpointer user_data);
void telnet_protocol_set_subneg_received(TelnetProtocol *self,
                                         TelnetProtocolReceivedCallback callback,
                                         gpointer user_data);
void telnet_protocol_set_command_received(TelnetProtocol *self,
                                          TelnetProtocolCommandReceivedCallback callback,
                                          gpointer user_data);
void telnet_protocol_set_opneg_received(TelnetProtocol *self,
                                        TelnetProtocolOpnegReceivedCallback callback,
                                        gpointer user_data);

void telnet_protocol_process_data(TelnetProtocol *self, ZPktBuf *data);

gboolean telnet_protocol_is_running(TelnetProtocol *self);

void telnet_protocol_escape_data(ZPktBuf *data);

#endif

/*
  # Local Variables:
  # indent-tabs-mode: nil
  # End:
*/
