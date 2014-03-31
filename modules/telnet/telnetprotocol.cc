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

#include "telnetprotocol.h"
#include "telnet.h"

void
telnet_protocol_init(TelnetProtocol *self, const gchar *session_id)
{
  self->session_id = g_strdup(session_id);
  self->state = PROTO_STATE_DATA;
  self->data_buffer = z_pktbuf_new();
  self->subneg_buffer = z_pktbuf_new();
}

void
telnet_protocol_destroy(TelnetProtocol *self)
{
  g_free(self->session_id);
  self->session_id = NULL;

  z_pktbuf_unref(self->data_buffer);
  self->data_buffer = NULL;
  z_pktbuf_unref(self->subneg_buffer);
  self->data_buffer = NULL;
}

static inline void
change_state(TelnetProtocol *self,
             TelnetProtocolState new_state)
{
  z_log(self->session_id, TELNET_DEBUG, 6, "Protocol changing state; old='%d', new='%d'", self->state, new_state);

  self->state = new_state;
}

gboolean
telnet_protocol_is_running(TelnetProtocol *self)
{
  return self->state != PROTO_STATE_QUIT;
}

void
telnet_protocol_set_data_received(TelnetProtocol *self,
                                  TelnetProtocolReceivedCallback callback,
                                  gpointer user_data)
{
  self->data_received = callback;
  self->data_received_user_data = user_data;
}

void
telnet_protocol_set_subneg_received(TelnetProtocol *self,
                                    TelnetProtocolReceivedCallback callback,
                                    gpointer user_data)
{
  self->subneg_received = callback;
  self->subneg_received_user_data = user_data;
}

void
telnet_protocol_set_command_received(TelnetProtocol *self,
                                     TelnetProtocolCommandReceivedCallback callback,
                                     gpointer user_data)
{
  self->command_received = callback;
  self->command_received_user_data = user_data;
}

void
telnet_protocol_set_opneg_received(TelnetProtocol *self,
                                   TelnetProtocolOpnegReceivedCallback callback,
                                   gpointer user_data)
{
  self->opneg_received = callback;
  self->opneg_received_user_data = user_data;
}

static void
call_data_received(TelnetProtocol *self)
{
  if (!telnet_protocol_is_running(self))
    return;

  if (z_pktbuf_length(self->data_buffer) == 0)
    return;

  z_pktbuf_seek(self->data_buffer, G_SEEK_SET, 0);

  if (self->data_received)
    {
      gboolean res = self->data_received(self->data_buffer, self->data_received_user_data);

      if (!res)
        {
          z_log(self->session_id, TELNET_DEBUG, 5, "Data received callback returned error, aborting;");
          change_state(self, PROTO_STATE_QUIT);
        }
    }

  z_pktbuf_resize(self->data_buffer, 0);

}

static void
call_subneg_received(TelnetProtocol *self)
{
  if (!telnet_protocol_is_running(self))
    return;

  if (z_pktbuf_length(self->subneg_buffer) == 0)
    return;

  z_pktbuf_seek(self->subneg_buffer, G_SEEK_SET, 0);

  if (self->subneg_received)
    {
      gboolean res = self->subneg_received(self->subneg_buffer, self->subneg_received_user_data);

      if (!res)
        {
          z_log(self->session_id, TELNET_DEBUG, 5, "Suboption negotiation callback returned error, aborting;");
          change_state(self, PROTO_STATE_QUIT);
        }
    }

  z_pktbuf_resize(self->subneg_buffer, 0);
}

static void
call_opneg_received(TelnetProtocol *self, guint8 option)
{
  if (!telnet_protocol_is_running(self))
    return;

  if (self->opneg_received)
    {
      gboolean res = self->opneg_received(self->command, option, self->opneg_received_user_data);

      if (!res)
        {
          z_log(self->session_id, TELNET_DEBUG, 5, "Option negotiation callback returned error, aborting;");
          change_state(self, PROTO_STATE_QUIT);
        }
    }
}

static void
call_command_received(TelnetProtocol *self)
{
  if (!telnet_protocol_is_running(self))
    return;

  if (self->command_received)
    {
      gboolean res = self->command_received(self->command, self->command_received_user_data);

      if (!res)
        {
          z_log(self->session_id, TELNET_DEBUG, 5, "Command callback returned error, aborting;");
          change_state(self, PROTO_STATE_QUIT);
        }
    }
}

static inline void
append_byte(TelnetProtocol *self, ZPktBuf *buf, guint8 byte)
{
  /* stop on buffer overrun */
  if (z_pktbuf_length(buf) >= TELNET_BUFFER_SIZE)
    {
      /*LOG
        This message indicates that the Telnet protocol contained a sequence of
        protocol elements that would have needed an unreasonably large buffer to
        process. These structures are not commonly found in normal Telnet
        streams but could be used to mount a denial of service attack on a
        Telnet client or server by a malicious host.
       */
      z_log(self->session_id, TELNET_VIOLATION, 1, "Buffer overflow during protocol decoding, aborting session; buffer_length='%" G_GSIZE_FORMAT "'",
            z_pktbuf_length(buf));
      change_state(self, PROTO_STATE_QUIT);
    }
  else
    z_pktbuf_put_u8(buf, byte);
}

static void
handle_state_data(TelnetProtocol *self,
                  ZPktBuf *data)
{
  guint8 byte;

  g_assert(z_pktbuf_get_u8(data, &byte));

  if (byte == TELNET_IAC)
    change_state(self, PROTO_STATE_ESCAPED);
  else
    append_byte(self, self->data_buffer, byte);
}

static void
handle_state_escaped(TelnetProtocol *self,
                     ZPktBuf *data)
{
  guint8 byte;

  g_assert(z_pktbuf_get_u8(data, &byte));

  self->command = byte;

  switch (byte)
    {
    case TELNET_IAC:
      change_state(self, PROTO_STATE_DATA);
      append_byte(self, self->data_buffer, byte);
      call_data_received(self);
      break;

    case TELNET_CMD_SB:
      change_state(self, PROTO_STATE_SUBNEG);
      z_pktbuf_resize(self->subneg_buffer, 0);
      break;

    case TELNET_CMD_WILL:
    case TELNET_CMD_WONT:
    case TELNET_CMD_DO:
    case TELNET_CMD_DONT:
      change_state(self, PROTO_STATE_OPNEG);
      break;

    default:
      change_state(self, PROTO_STATE_DATA);
      call_data_received(self);
      call_command_received(self);
      break;
    }
}

static void
handle_state_opneg(TelnetProtocol *self,
                   ZPktBuf *data)
{
  guint8 option;

  g_assert(z_pktbuf_get_u8(data, &option));

  change_state(self, PROTO_STATE_DATA);

  call_data_received(self);
  call_opneg_received(self, option);
}

static void
handle_state_subneg(TelnetProtocol *self,
                    ZPktBuf *data)
{
  guint8 byte;

  g_assert(z_pktbuf_get_u8(data, &byte));

  if (byte == TELNET_IAC)
    change_state(self, PROTO_STATE_SUBNEG_ESCAPED);
  else
    append_byte(self, self->subneg_buffer, byte);
}

static void
handle_state_subneg_escaped(TelnetProtocol *self,
                            ZPktBuf *data)
{
  guint8 byte;

  g_assert(z_pktbuf_get_u8(data, &byte));

  if (byte == TELNET_CMD_SE)
    {
      change_state(self, PROTO_STATE_DATA);
      call_data_received(self);
      call_subneg_received(self);
    }
  else
    {
      change_state(self, PROTO_STATE_SUBNEG);
      append_byte(self, self->subneg_buffer, byte);
    }
}

void
telnet_protocol_process_data(TelnetProtocol *self,
                             ZPktBuf *data)
{
  while (telnet_protocol_is_running(self) &&
         z_pktbuf_available(data) > 0)
    {
      switch (self->state)
        {
        case PROTO_STATE_DATA:
          handle_state_data(self, data);
          break;
        case PROTO_STATE_ESCAPED:
          handle_state_escaped(self, data);
          break;
        case PROTO_STATE_OPNEG:
          handle_state_opneg(self, data);
          break;
        case PROTO_STATE_SUBNEG:
          handle_state_subneg(self, data);
          break;
        case PROTO_STATE_SUBNEG_ESCAPED:
          handle_state_subneg_escaped(self, data);
          break;
        case PROTO_STATE_QUIT:
          break;
        }
    }

  call_data_received(self);
}

void
telnet_protocol_escape_data(ZPktBuf *data)
{
  z_pktbuf_seek(data, G_SEEK_SET, 0);

  guint8 byte;
  while (z_pktbuf_available(data) > 0 &&
         z_pktbuf_get_u8(data, &byte))
    if (byte == TELNET_IAC)
      {
        z_pktbuf_insert(data, z_pktbuf_pos(data), &byte, sizeof(byte));
        z_pktbuf_seek(data, G_SEEK_CUR, 1);
      }
}

/*
  # Local Variables:
  # indent-tabs-mode: nil
  # End:
*/
