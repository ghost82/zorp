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

#include "telnetlineedit.h"

void
telnet_lineedit_init(TelnetLineEdit *self)
{
  self->data_buffer = z_pktbuf_new();
  self->do_echo = TRUE;
  self->eol = FALSE;
  self->echo_newline = TRUE;
}

void
telnet_lineedit_destroy(TelnetLineEdit *self)
{
  z_pktbuf_unref(self->data_buffer);
  self->data_buffer = NULL;
}

#define ECHO_DELETE_ONE_CHARACTER "\b \b"
#define ECHO_NEWLINE "\r\n"

ZPktBuf *
telnet_lineedit_compose_delete_n_chars(gsize n)
{
  ZPktBuf *ret = z_pktbuf_new();
  const char del_chars[] = {'\b', ' ', '\b'};

  for (gsize c = 0; c < sizeof(del_chars); ++c)
    for (gsize i = 0; i < n; ++i)
      z_pktbuf_put_c8(ret, del_chars[c]);

  return ret;
}

void
telnet_lineedit_clear(TelnetLineEdit *self)
{
  z_pktbuf_resize(self->data_buffer, 0);
  self->eol = FALSE;
}

ZPktBuf *
telnet_lineedit_process_data(TelnetLineEdit *self, ZPktBuf *data)
{
  guint8 byte;
  ZPktBuf *out = z_pktbuf_new();
  gboolean cr = FALSE;

  z_pktbuf_seek(data, G_SEEK_SET, 0);

  if (self->eol)
    telnet_lineedit_clear(self);

  while (z_pktbuf_available(data) > 0)
    {
      z_pktbuf_get_u8(data, &byte);

      if (cr && byte != '\n' && byte != '\0')
        {
          cr = FALSE;
          /* Skip the cr byte because it is not followed by \n or \0 */
        }

      switch (byte)
        {
        case LINEEDIT_BACKSPACE:
          if (z_pktbuf_length(self->data_buffer))
            {
              if (self->do_echo)
                z_pktbuf_put_string(out, ECHO_DELETE_ONE_CHARACTER);
              z_pktbuf_resize(self->data_buffer, z_pktbuf_length(self->data_buffer) - 1);
            }
          break;

        case LINEEDIT_LINEDEL:
          if (z_pktbuf_length(self->data_buffer))
            {
              if (self->do_echo)
                {
                  for(guint i = 0; i < z_pktbuf_length(self->data_buffer); i++)
                    z_pktbuf_put_string(out, ECHO_DELETE_ONE_CHARACTER);
                }
              z_pktbuf_resize(self->data_buffer, 0);
            }
          break;

        case '\r':
          cr = TRUE;
          break;

        case '\n':
        case '\0':
          if (cr)
            {
              cr = FALSE;
              self->eol = TRUE;

              if (self->echo_newline)
                z_pktbuf_put_string(out, ECHO_NEWLINE);
            }
          else
            {
              /* skip the \n or \0 because it is not allowed char if they'r not precedeed by \r */
            }
        break;

        default:
          if (self->do_echo)
            z_pktbuf_put_u8(out, byte);
          z_pktbuf_put_u8(self->data_buffer, byte);
        };
    }

  return out;
}
