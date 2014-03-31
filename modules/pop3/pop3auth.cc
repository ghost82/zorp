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
#include "pop3.h"

guint
pop3_auth_parse(Pop3Proxy *self, guint side)
{
  z_proxy_enter(self);
  self->auth_lines++;
  if (side == EP_CLIENT)
    {
      g_string_assign_len(self->command, self->request_line, self->request_length);
      g_string_assign(self->command_param, "");
      if (self->request_line[0] == '*' && self->request_length == 1)
        {
          self->pop3_state = POP3_STATE_AUTH_A_CANCEL;
          z_proxy_return(self, POP3_RSP_ACCEPT);
        }
    }
  else if (side == EP_SERVER)
    {
      g_string_assign_len(self->response, self->reply_line, self->reply_length);
      g_string_assign(self->response_param, "");
      if (strstr(self->response->str, "+OK ") == self->response->str && self->pop3_state != POP3_STATE_AUTH_A_CANCEL)
        {
          self->pop3_state = POP3_STATE_TRANS;
          z_proxy_return(self, POP3_RSP_ACCEPT);
        }
      else if (strstr(self->response->str, "-ERR ") == self->response->str)
        {
          self->pop3_state = POP3_STATE_AUTH;
          z_proxy_return(self, POP3_RSP_ACCEPT);
        }
      else if (self->response->len < 3 || self->response->str[0] != '+' || self->response->str[1] != ' ')
        {
          z_proxy_return(self, POP3_RSP_ABORT);
        }
      else if (self->pop3_state == POP3_STATE_AUTH_A_CANCEL)
        {
          z_proxy_log(self, POP3_VIOLATION, 2, "Auth cancellation must be followed with -ERR; line='%s'", self->response->str);
          g_string_assign(self->response, "-ERR Error in protocol");
          z_proxy_return(self, POP3_RSP_ABORT);
        }
    }

  if (self->auth_lines > self->max_authline_count)
    {
      self->pop3_state = POP3_STATE_AUTH;
      z_proxy_return(self, POP3_REQ_REJECT);
    }
  z_proxy_return(self, POP3_REQ_ACCEPT);
}
