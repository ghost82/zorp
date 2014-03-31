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

#include "smtp.h"
#include <zorp/proxy/transfer2.h>
#include <zorp/log.h>

#define SMTP_SR_INITIAL      0
#define SMTP_SR_DATA         1

#define SMTP_DW_INITIAL      0
#define SMTP_DW_TRANSFER     3
#define SMTP_DW_TRANSFER_LF  4
#define SMTP_DW_TRANSFER_DOT 5
#define SMTP_DW_REJECTED     6

/**
 * SmtpTransfer:
 *
 * An SMTP specific transfer class.
 **/
struct _SmtpTransfer
{
  ZTransfer2 super;
  /* destination write state */
  gint dst_write_state;

  gint src_read_state;

  GString *received_line;
  guint received_line_pos;

  /* The previous line was too long, it must be concatenated with the current line */
  gboolean previous_line_split;
};

extern ZClass SmtpTransfer__class;

/**
 * smtp_transfer_src_read:
 * @s: ZTransfer instance
 * @stream: stream to read from
 * @buf: buffer to read into
 * @buf_len: size of the buffer
 * @bytes_read: the number of read bytes is returned here
 * @err: GLib error code
 *
 * Reads the incoming data stream, checks for EOF (a single '.' on its own),
 * removes '.' escaping and handles lines longer than the buffer size of ZStreamLine.
 *
 **/
static GIOStatus
smtp_transfer_src_read(ZTransfer2 *s G_GNUC_UNUSED, ZStream *stream, gchar *buf, gsize buf_len, gsize *bytes_read, GError **err)
{
  SmtpTransfer *self = Z_CAST(s, SmtpTransfer);
  SmtpProxy *owner = Z_CAST(self->super.owner, SmtpProxy);
  GIOStatus res;
  gsize line_len = buf_len - 2; /* to make space to closing CR LF */

  if (G_UNLIKELY(self->src_read_state == SMTP_SR_INITIAL))
    {
      if (owner->add_received_header)
        {
          if (self->received_line == NULL)
            {
              if (!smtp_generate_received(owner, &self->received_line))
                self->src_read_state = SMTP_SR_DATA;
            }

          if (self->received_line)
            {
              *bytes_read = MIN(buf_len, self->received_line->len - self->received_line_pos);
              memmove(buf, self->received_line->str + self->received_line_pos, *bytes_read);
              self->received_line_pos += *bytes_read;

              if (self->received_line_pos >= self->received_line->len)
                {
                  self->src_read_state = SMTP_SR_DATA;
                }
              return G_IO_STATUS_NORMAL;
            }
        }
      else
        {
          self->src_read_state = SMTP_SR_DATA;
        }
    }

  if (buf_len < 2)
    {
      return G_IO_STATUS_AGAIN;
    }

  res = z_stream_line_get_copy(stream, buf, &line_len, err);
  if (res == G_IO_STATUS_NORMAL)
    {
      if (!self->previous_line_split && line_len > 0 && buf[0] == '.')
        {
          if (line_len == 1)
            {
              return G_IO_STATUS_EOF;
            }
          else
            {
              /* strip off first dot */
              memmove(buf, &buf[1], line_len - 1);
              line_len = line_len - 1;
            }
        }
      buf[line_len] = '\r';
      buf[line_len+1] = '\n';
      *bytes_read = line_len + 2;
      self->previous_line_split = FALSE;
    }
  else if (res == G_IO_STATUS_AGAIN && line_len > 0)
    {
      /* streamline indicates that the line was too long, do not add EOL */
      *bytes_read = line_len;
      self->previous_line_split = TRUE;
      res = G_IO_STATUS_NORMAL;
    }
  return res;
}

/**
 * smtp_transfer_dst_write:
 * @s: ZTransfer instance
 * @stream: stream to write to
 * @buf: buffer to read into
 * @count: buffer size
 * @bytes_read: number of bytes returned
 * @err: GLib error
 *
 * This function handles the data stream as it comes out of the stacked
 * proxy. It takes care about prefixing the mail body with a "DATA" command,
 * and through complicated means also takes care about fetching the response
 * to it. When this is successful it takes care about sending the data
 * stream reescaping unescaped lines beginning with '.'.
 **/
static GIOStatus
smtp_transfer_dst_write(ZTransfer2 *s, ZStream *stream, const gchar *buf, gsize count, gsize *bytes_written, GError **err)
{
  SmtpTransfer *self = Z_CAST(s, SmtpTransfer);
  GIOStatus res;
  GError *local_error = NULL;
  gsize bw;
  gsize i;

  *bytes_written = 0;
  if (self->dst_write_state == SMTP_DW_INITIAL)
    {
      z_transfer2_suspend(s, SMTP_TRANSFER_SUSPEND_DATA);
      self->dst_write_state = SMTP_DW_TRANSFER;
      return G_IO_STATUS_AGAIN;
    }

 transfer_state:

  if (self->dst_write_state == SMTP_DW_TRANSFER || self->dst_write_state == SMTP_DW_TRANSFER_LF)
    {
      for (i = *bytes_written; i < count; i++)
        {
          if (self->dst_write_state == SMTP_DW_TRANSFER)
            {
              if (buf[i] == '\n')
                {
                  self->dst_write_state = SMTP_DW_TRANSFER_LF;
                }
            }
          else if (self->dst_write_state == SMTP_DW_TRANSFER_LF)
            {
              if (buf[i] == '.')
                {
                  /* we need to escape this '.' */

                  /* first, write buf up to this '.' */
                  res = z_stream_write(stream, buf + *bytes_written, i - *bytes_written, &bw, &local_error);
                  if (res == G_IO_STATUS_NORMAL && (i - *bytes_written) == bw)
                    {
                      *bytes_written += bw;
                      self->dst_write_state = SMTP_DW_TRANSFER_DOT;
                      break;
                    }
                  else
                    {
                      /* we wrote less bytes, go back to the original state */
                      self->dst_write_state = SMTP_DW_TRANSFER;
                      *bytes_written += bw;
                      if (local_error)
                        g_propagate_error(err, local_error);
                      return res;
                    }
                }
              self->dst_write_state = SMTP_DW_TRANSFER;
            }
        }
      if (i == count)
        {
          /* no need to escape */
          res = z_stream_write(stream, buf + *bytes_written, count - *bytes_written, &bw, err);
          *bytes_written += bw;
          return res;
        }
    }
  if (self->dst_write_state == SMTP_DW_TRANSFER_DOT)
    {
      res = z_stream_write(stream, ".", 1, &bw, &local_error);
      if (res == G_IO_STATUS_NORMAL && bw == 1)
        {
          self->dst_write_state = SMTP_DW_TRANSFER;
          goto transfer_state;
        }
      if (local_error)
        g_propagate_error(err, local_error);
      return res;
    }

  /* server responded non-354 to the DATA command */
  return G_IO_STATUS_ERROR;
}

/**
 * smtp_transfer_dst_shutdown:
 * @s: ZTransfer instance
 * @stream: stream to shut down
 * @shutdown_mode: shutdown mode
 * @err: GLib error
 *
 * This function is called when the server side stream is to be shut down. It takes care
 * about ending the mail body with a '.', or
 **/
static GIOStatus
smtp_transfer_dst_shutdown(ZTransfer2 *s G_GNUC_UNUSED, ZStream *stream, GError **err)
{
  gsize bytes_written;
  GError *local_error = NULL;
  GIOStatus res = G_IO_STATUS_NORMAL;
  SmtpTransfer *self = Z_CAST(s, SmtpTransfer);

  if (self->dst_write_state != SMTP_DW_INITIAL)
    {
      res = z_stream_write(stream, "\r\n.\r\n", 5, &bytes_written, &local_error);
    }
  if (local_error)
    g_propagate_error(err, local_error);
  return res;
}

static gboolean
smtp_transfer_stack_proxy(ZTransfer2 *s, ZStackedProxy **stacked)
{
  SmtpProxy *owner = Z_CAST(s->owner, SmtpProxy);
  ZPolicyObj *stacked_proxy;
  gboolean called;
  gboolean success = TRUE;

  z_policy_lock(owner->super.thread);
  stacked_proxy = z_policy_call(owner->super.handler,
                                "requestStack",
                                NULL,
                                &called,
                                owner->super.session_id);
  if (!stacked_proxy)
    success = FALSE;
  else if (stacked_proxy != z_policy_none)
    {
      success = z_proxy_stack_object(&owner->super, stacked_proxy, stacked, NULL);
    }

  z_policy_var_unref(stacked_proxy);
  z_policy_unlock(owner->super.thread);
  return success;

}

static gboolean
smtp_transfer_setup(ZTransfer2 *s)
{
  z_stream_line_set_split(s->endpoints[EP_CLIENT], TRUE);
  z_stream_line_set_truncate(s->endpoints[EP_CLIENT], FALSE);
  return TRUE;
}

static gboolean
smtp_transfer_progress(ZTransfer2 *s)
{
  SmtpTransfer *self = Z_CAST(s, SmtpTransfer);

  if (self->dst_write_state == SMTP_DW_INITIAL)
    z_transfer2_suspend(s, SMTP_TRANSFER_SUSPEND_NOOP);
  return TRUE;
}

static void
smtp_transfer_free_method(ZObject *s)
{
  SmtpTransfer *self = Z_CAST(s, SmtpTransfer);

  if (self->received_line)
    g_string_free(self->received_line, TRUE);
  z_transfer2_free_method(s);
}

ZTransfer2Funcs smtp_transfer_funcs =
{
  {
    Z_FUNCS_COUNT(ZTransfer2),
    smtp_transfer_free_method,
  },
  smtp_transfer_src_read,
  smtp_transfer_dst_write,
  NULL,
  smtp_transfer_dst_shutdown,
  smtp_transfer_stack_proxy,
  /* .setup = */ smtp_transfer_setup,
  /* .run = */ NULL,
  /* .progress = */ smtp_transfer_progress
};

Z_CLASS_DEF(SmtpTransfer, ZTransfer2, smtp_transfer_funcs);

/**
 * smtp_transfer_new:
 * @self: SmtpProxy instance
 *
 * This function is an Smtp specific constructor for the ZTransfer2 class.
 *
 * Returns: ZTransfer2 instance
 **/
ZTransfer2 *
smtp_transfer_new(SmtpProxy *owner)
{
  SmtpTransfer *self;

  self = Z_CAST(z_transfer2_new(Z_CLASS(SmtpTransfer), &owner->super, owner->poll,
                                owner->super.endpoints[EP_CLIENT], owner->super.endpoints[EP_SERVER],
                                owner->buffer_size, owner->timeout,
                                ZT2F_COMPLETE_COPY),
                SmtpTransfer);
  z_transfer2_set_content_format(&self->super, "email");
  z_transfer2_enable_progress(&self->super, owner->interval_transfer_noop);
  return &self->super;
}
