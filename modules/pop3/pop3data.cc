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

#include "pop3data.h"
#include "pop3policy.h"

#include <zorp/proxy/dottransfer.h>

typedef struct _Pop3Transfer
{
  ZDotTransfer super;
  gint header_state;
  GString *actual_header;
} Pop3Transfer;

extern ZClass Pop3Transfer__class;

static gboolean
pop3_transfer_stack(ZTransfer2 *s, ZStackedProxy **stacked)
{
  Pop3Proxy *owner = Z_CAST(s->owner, Pop3Proxy);

  return pop3_policy_stack_hash_do(owner, stacked);
}

enum
{
  POP3_HEADER_NONE,
  POP3_HEADER_INSIDE,
  POP3_HEADER_END
};

#define FROM    "From: "
#define TO      "To: "
#define SUBJECT "Subject: "

static GIOStatus
pop3_transfer_src_read(ZTransfer2 *s, ZStream *stream, gchar *buf, gsize count, gsize *bytes_read, GError **err)
{
  GIOStatus ret;
  Pop3Transfer *self = Z_CAST(s, Pop3Transfer);
  Pop3Proxy *owner = Z_CAST(s->owner, Pop3Proxy);

  ret = Z_SUPER(s, ZTransfer2)->src_read(s, stream, buf, count, bytes_read, err);

  if (self->header_state < POP3_HEADER_END &&
       (ret == G_IO_STATUS_NORMAL || (ret == G_IO_STATUS_AGAIN && *bytes_read > 0)))
    {
      if (*bytes_read == 0)
        {
          self->header_state = POP3_HEADER_END;
        }
      else
        {
          gsize bytes_need = *bytes_read;
          if (buf[0] != ' ' && buf[0] != '\t')
            {
              self->header_state = POP3_HEADER_NONE;
              self->actual_header = NULL;
            }

          while (buf[bytes_need - 1] == '\n' || buf[bytes_need - 1] == '\r' || buf[bytes_need - 1] == ' ')
            bytes_need--;

          z_trace(NULL, "Read header line; line='%.*s'", (gint) bytes_need, buf);

          if (self->header_state == POP3_HEADER_NONE)
            {
              if (g_ascii_strncasecmp(buf, FROM, MIN(__builtin_strlen(FROM), bytes_need)) == 0)
                {
                  if (owner->from == NULL)
                    {
                      self->header_state = POP3_HEADER_INSIDE;
                      owner->from = g_string_new_len(buf + __builtin_strlen(FROM), bytes_need - __builtin_strlen(FROM));
                      self->actual_header = owner->from;
                    }
                  else
                    {
                      /* FIXME: Log */
                    }
                }
              else if (g_ascii_strncasecmp(buf, TO, MIN(__builtin_strlen(TO), bytes_need)) == 0)
                {
                  if (owner->to == NULL)
                    {
                      self->header_state = POP3_HEADER_INSIDE;
                      owner->to = g_string_new_len(buf + __builtin_strlen(TO), bytes_need - __builtin_strlen(TO));
                      self->actual_header = owner->to;
                    }
                  else
                    {
                      /* FIXME: Log */
                    }
                }
              else if (g_ascii_strncasecmp(buf, SUBJECT, MIN(__builtin_strlen(SUBJECT), bytes_need)) == 0)
                {
                  if (owner->subject == NULL)
                    {
                      self->header_state = POP3_HEADER_INSIDE;
                      owner->subject = g_string_new_len(buf + __builtin_strlen(SUBJECT), bytes_need - __builtin_strlen(SUBJECT));
                      self->actual_header = owner->subject;
                    }
                  else
                    {
                      /* FIXME: Log */
                    }
                }
            }
          else
            {
              g_string_append(self->actual_header, "\r\n");
              g_string_append_len(self->actual_header, buf, bytes_need);
            }
        }
    }
  return ret;
}

ZTransfer2Funcs pop3_transfer_funcs =
{
  {
    Z_FUNCS_COUNT(ZTransfer2),
    NULL,
  },
  /* .src_read = */ pop3_transfer_src_read,
  /* .dst_write = */ NULL,
  /* .src_shutdown = */ NULL,
  /* .dst_shutdown = */ NULL,
  /* .stack_proxy = */ pop3_transfer_stack,
  /* .setup = */ NULL, /* setup */
  /* .run = */ NULL,
  /* .progress = */ NULL  /* progress */
};

Z_CLASS_DEF(Pop3Transfer, ZDotTransfer, pop3_transfer_funcs);

gboolean
pop3_data_transfer(Pop3Proxy *owner)
{
  Pop3Transfer *t;
  GString *preamble;
  gboolean success;
  gchar buf[256];

  z_proxy_enter(owner);
  preamble = g_string_new(owner->response->str);
  if (owner->response_param->len)
    {
      g_string_append_c(preamble, ' ');
      g_string_append(preamble, owner->response_param->str);
    }
  g_string_append(preamble, "\r\n");
  t = Z_CAST(z_dot_transfer_new(Z_CLASS(Pop3Transfer),
                                &owner->super, owner->poll,
                                owner->super.endpoints[EP_SERVER], owner->super.endpoints[EP_CLIENT],
                                owner->buffer_length,
                                owner->timeout,
                                ZT2F_COMPLETE_COPY | ZT2F_PROXY_STREAMS_POLLED,
                                preamble),
             Pop3Transfer);
  z_transfer2_set_content_format(&t->super.super, "email");

  z_stream_line_set_nul_nonfatal(owner->super.endpoints[EP_SERVER], TRUE);
  if (owner->policy_enable_longline)
    z_stream_line_set_split(owner->super.endpoints[EP_SERVER], TRUE);

  success = z_transfer2_simple_run(&t->super.super);
  z_stream_line_set_split(owner->super.endpoints[EP_SERVER], FALSE);
  z_stream_line_set_nul_nonfatal(owner->super.endpoints[EP_SERVER], FALSE);
  if (t->super.dst_write_state == DOT_DW_PREAMBLE)
    {
      /* nothing was written to destination */
      switch (z_transfer2_get_stack_decision(&t->super.super))
        {
        case ZV_REJECT:
	  /*LOG
	    This message indicates that the stacked proxy rejected the content and Zorp
	    rejects the response.
	   */
          z_proxy_log(owner, POP3_ERROR, 2, "Stacked proxy rejected contents; info='%s'", z_transfer2_get_stack_info(&t->super.super));
          g_snprintf(buf, sizeof(buf), "Content rejected (%s)", z_transfer2_get_stack_info(&t->super.super));
          if (owner->reject_by_mail)
            pop3_error_msg(owner, buf);
          else
            pop3_response_reject(owner, buf);
          break;

        case ZV_ERROR:
          g_snprintf(buf, sizeof(buf), "Error occurred while transferring data (%s)", z_transfer2_get_stack_info(&t->super.super));
          pop3_response_reject(owner, buf);
          owner->pop3_state = POP3_STATE_QUIT;
          break;

        default:
          pop3_response_write(owner);
          pop3_write_client(owner, ".\r\n");
          break;
        }
    }
  else
    {
      pop3_write_client(owner, ".\r\n");
    }

  if (owner->from)
    {
      g_string_free(owner->from, TRUE);
      owner->from = NULL;
    }

  if (owner->to)
    {
      g_string_free(owner->to, TRUE);
      owner->to = NULL;
    }

  if (owner->subject)
    {
      g_string_free(owner->subject, TRUE);
      owner->subject = NULL;
    }

  z_object_unref(&t->super.super.super);
  z_proxy_return(owner, success);
}
