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
#include "pop3cmd.h"
#include "pop3misc.h"
#include "pop3policy.h"
#include "pop3data.h"

#include <zorp/proxy/errorloader.h>

#include <zorp/thread.h>
#include <zorp/registry.h>
#include <zorp/log.h>
#include <zorp/policy.h>

static void pop3_proxy_free(ZObject *s);

static struct _Pop3InternalCommands known_commands[] = {
  {"APOP", Pop3ParseAPOP,            FALSE, Pop3AnswerParseAPOP,    NULL, POP3_STATE_AUTH   },
  {"DELE", Pop3ParseNum_One,         FALSE, NULL,                   NULL, POP3_STATE_TRANS  },
  {"LIST", Pop3ParseNum_OneOptional, TRUE,  NULL,                   NULL, POP3_STATE_TRANS  },
  {"LAST", Pop3ParseNoarg,           FALSE, Pop3AnswerParseNum_One, NULL, POP3_STATE_TRANS  },
  {"NOOP", Pop3ParseNoarg,           FALSE, NULL,                   NULL, POP3_STATE_TRANS  },
  {"PASS", Pop3ParsePASS,            FALSE, Pop3AnswerParsePASS,    NULL, POP3_STATE_AUTH_U },
  {"QUIT", Pop3ParseNoarg,           FALSE, Pop3AnswerParseQUIT,    NULL, POP3_STATE_AUTH | POP3_STATE_AUTH_U | POP3_STATE_TRANS },
  {"RETR", Pop3ParseRETR,            TRUE,  NULL,                   NULL, POP3_STATE_TRANS  },
  {"RSET", Pop3ParseNoarg,           FALSE, NULL,                   NULL, POP3_STATE_TRANS  },
  {"STAT", Pop3ParseNoarg,           FALSE, Pop3AnswerParseNum_Two, NULL, POP3_STATE_TRANS  },
  {"TOP",  Pop3ParseNum_Two,         TRUE,  NULL,                   NULL, POP3_STATE_TRANS  },
  {"UIDL", Pop3ParseNum_OneOptional, TRUE,  NULL,                   NULL, POP3_STATE_TRANS  },
  {"USER", Pop3ParseUSER,            FALSE, Pop3AnswerParseUSER,    NULL, POP3_STATE_AUTH   },
  {"AUTH", Pop3ParseAUTH,            FALSE, NULL,                   NULL, POP3_STATE_AUTH   },
  {NULL,   NULL,                     FALSE, NULL,                   NULL, 0                 }
};

GIOStatus
pop3_write_client(Pop3Proxy *self, const char *msg)
{
  GIOStatus rc;
  gsize bytes_written;

  z_proxy_enter(self);
  rc = z_stream_write(self->super.endpoints[EP_CLIENT], msg, strlen(msg), &bytes_written, NULL);
  z_proxy_return(self, rc);
}

GIOStatus
pop3_write_server(Pop3Proxy *self, char *msg)
{
  GIOStatus rc;
  gsize bytes_written;

  z_proxy_enter(self);
  rc = z_stream_write(self->super.endpoints[EP_SERVER], msg, strlen(msg), &bytes_written, NULL);
  z_proxy_return(self, rc);
}

static gchar *
pop3_get_from(const gchar *header G_GNUC_UNUSED, gpointer user_data)
{
  Pop3Proxy *self = Z_CAST(user_data, Pop3Proxy);
  gchar *res;

  z_proxy_enter(self);
  res = self->from ? g_strdup(self->from->str) : NULL;
  z_proxy_return(self, res);
}

static gchar *
pop3_get_to(const gchar *header G_GNUC_UNUSED, gpointer user_data)
{
  Pop3Proxy *self = Z_CAST(user_data, Pop3Proxy);
  gchar *res;

  z_proxy_enter(self);
  res = self->to ? g_strdup(self->to->str) : NULL;
  z_proxy_return(self, res);
}

static gchar *
pop3_get_subject(const gchar *header G_GNUC_UNUSED, gpointer user_data)
{
  Pop3Proxy *self = Z_CAST(user_data, Pop3Proxy);
  gchar *res;

  z_proxy_enter(self);
  res = self->subject ? g_strdup(self->subject->str) : NULL;
  z_proxy_return(self, res);
}

static ZErrorLoaderVarInfo pop3_error_vars[] =
{
  {"FROM",    pop3_get_from},
  {"TO",      pop3_get_to},
  {"SUBJECT", pop3_get_subject},
  {NULL,      NULL}
};

void
pop3_error_msg(Pop3Proxy *self, gchar *additional_info)
{
  gchar *error_msg;
  gchar error_filename[256];
  guint error_len;
  gchar response[512];

  z_proxy_enter(self);
  g_snprintf(error_filename, sizeof(error_filename), ZORP_DATADIR "/pop3/%s/reject.msg", self->super.language->str);
  error_msg = z_error_loader_format_file(error_filename, additional_info, Z_EF_ESCAPE_NONE, pop3_error_vars, self);
  if (error_msg)
    {
      error_len = strlen(error_msg);
      g_snprintf(response, sizeof(response), "+OK %d octets\r\n", error_len);
      if (pop3_write_client(self, response) != G_IO_STATUS_NORMAL ||
          pop3_write_client(self, error_msg) != G_IO_STATUS_NORMAL)
        goto exit;

      if (error_msg[error_len -1] != '\n')
        {
          if (pop3_write_client(self, "\r\n") != G_IO_STATUS_NORMAL)
            goto exit;
        }
    }
  pop3_write_client(self, ".\r\n");

 exit:
  z_proxy_return(self);
}

GIOStatus
pop3_response_read(Pop3Proxy *self)
{
  GIOStatus res;

  z_proxy_enter(self);
  self->reply_length = self->max_reply_length;
  res = z_stream_line_get(self->super.endpoints[EP_SERVER], &self->reply_line, &self->reply_length, NULL);
  z_proxy_return(self, res);
}

guint
pop3_response_parse(Pop3Proxy *self)
{
  gchar response[5];
  guint i;

  z_proxy_enter(self);
  if (self->reply_length > self->max_reply_length)
    {
      /*LOG
        This message indicates that the response line is too long and Zorp
	aborts the connection. Check the 'max_reply_length' attribute.
       */
      z_proxy_log(self, POP3_VIOLATION, 3, "Response line too long; line='%.*s', length='%d', max_reply_length='%d'",
         (int)self->reply_length, self->reply_line, (int)self->reply_length, self->max_reply_length);
      z_proxy_return(self, POP3_RSP_ABORT);
    }

  for (i = 0; i < 4 && i < self->reply_length && self->reply_line[i] != ' '; i++)
    response[i] = self->reply_line[i];
  response[i++] = 0;

  if ((strcmp(response,"+OK") != 0) && (strcmp(response,"-ERR") != 0))
    {
      /*LOG
	This message indicates that the status of the response is invalid and Zorp
	rejects the response. The response should begin with '+OK' or with '-ERR'.
       */
      z_proxy_log(self, POP3_VIOLATION, 3, "Response status is invalid; rsp='%s'", response);
      z_proxy_return(self, POP3_RSP_REJECT);
    }

  if (strcmp(response, "+OK") != 0)
    self->response_multiline = FALSE;

  g_string_assign(self->response, response);
  if (self->reply_length > i)
    {
      g_string_assign_len(self->response_param,
                          self->reply_line + i,
                          self->reply_length - i);

      /*LOG
        This message reports that the fetched response contains a parameter.
       */
      z_proxy_log(self, POP3_RESPONSE, 7, "Response fetched with parameter; rsp='%s', rsp_prm='%s'", self->response->str, self->response_param->str);
    }
  else
    {
      /*LOG
        This message reports the fetched response.
      */
      z_proxy_log(self, POP3_RESPONSE, 7, "Response fetched; rsp='%s'", response);
      g_string_assign(self->response_param, "");
    }
  z_proxy_return(self, POP3_RSP_ACCEPT);
}

guint
pop3_response_process(Pop3Proxy *self)
{
  guint ret = POP3_RSP_ACCEPT;

  z_proxy_enter(self);
  if (self->pop3_state == POP3_STATE_LISTEN)
    {
      pop3_get_timestamp(self);
      self->pop3_state = POP3_STATE_AUTH;
    }

  ret = pop3_policy_response_hash_do(self);
  if (ret == POP3_RSP_ACCEPT)
    {
      if (self->command_desc &&
          self->command_desc->response_parse)
        ret = self->command_desc->response_parse(self);
    }
  z_proxy_return(self, ret);
}

void
pop3_response_write(Pop3Proxy *self)
{
  gchar newline[self->max_reply_length + 3];

  z_proxy_enter(self);
  if (self->response_param->len)
    g_snprintf(newline, sizeof(newline), "%s %s\r\n", self->response->str, self->response_param->str);
  else
    g_snprintf(newline, sizeof(newline), "%s\r\n", self->response->str);
  pop3_write_client(self, newline);
  z_proxy_return(self);
}

void
pop3_response_reject(Pop3Proxy *self, gchar *error_msg)
{
  gchar msg_buf[1024];

  z_proxy_enter(self);
  if (!error_msg)
    error_msg = "Error in protocol";
  g_snprintf(msg_buf, sizeof(msg_buf), "-ERR %s\r\n", error_msg);
  pop3_write_client(self, msg_buf);
  z_proxy_return(self);
}

gboolean
pop3_response_multiline(Pop3Proxy *self)
{
  gboolean res = TRUE;

  z_proxy_enter(self);
  res = pop3_data_transfer(self);
  if (!res)
    {
      /*LOG
        This message indicates that the multi-line data transfer failed and
	Zorp rejects the response.
       */
      z_proxy_log(self, POP3_ERROR, 2, "Data transfer failed;");
    }
  self->state = POP3_CLIENT;
  z_proxy_return(self, res);
}

gboolean
pop3_server_to_client(ZStream *stream G_GNUC_UNUSED,
                      GIOCondition  cond G_GNUC_UNUSED,
                      gpointer  user_data)
{
  Pop3Proxy *self = (Pop3Proxy *)user_data;
  guint resp;
  GIOStatus rc;

  z_proxy_enter(self);
  rc = pop3_response_read(self);
  if (rc != G_IO_STATUS_NORMAL)
    {
      if (rc != G_IO_STATUS_EOF)
        pop3_response_reject(self, NULL);
      self->pop3_state = POP3_STATE_QUIT;
      z_proxy_return(self, FALSE);
    }

  if (self->pop3_state != POP3_STATE_AUTH_A && self->pop3_state != POP3_STATE_AUTH_A_CANCEL)
    {
      resp = pop3_response_parse(self);
      if (resp == POP3_RSP_ACCEPT)
        resp = pop3_response_process(self);
    }
  else
    {
      resp = pop3_auth_parse(self, EP_SERVER);
    }

  switch (resp)
    {
    case POP3_RSP_ACCEPT:
      /* This is a dirty hack.
       * Because sources not recurses, we must leave
       * z_poll_iter_timeout before z_transfer_run called
       */
      if (self->response_multiline)
        {
          self->state = POP3_SERVER_MULTILINE;
          z_proxy_return(self, TRUE);
        }
      else
        {
          pop3_response_write(self);
        }
      break;

    case POP3_RSP_REJECT:
      pop3_response_reject(self, NULL);
      break;

    case POP3_RSP_ABORT:
      pop3_response_reject(self, NULL);
      self->pop3_state = POP3_STATE_QUIT;
      break;

    default:
      self->pop3_state = POP3_STATE_QUIT;
      break;
    }
  self->state = POP3_CLIENT;
  z_proxy_return(self, TRUE);
}

void pop3_command_reject(Pop3Proxy *self);

gboolean
pop3_command_read(Pop3Proxy *self)
{
  GIOStatus res;

  z_proxy_enter(self);
  self->response_multiline = FALSE;
  self->request_length = self->max_request_length;
  res = z_stream_line_get(self->super.endpoints[EP_CLIENT], &self->request_line, &self->request_length, NULL);
  if (res !=G_IO_STATUS_NORMAL)
    {
      /* FIXMEE
         Check if streamline return with error because of
         too long line, or connection broken.
       */
      if (res != G_IO_STATUS_EOF)
        pop3_command_reject(self);
      z_proxy_return(self, FALSE);
    }
  z_proxy_return(self, TRUE);
}

guint
pop3_command_parse(Pop3Proxy *self)
{
  gchar command[10];
  guint i;

  z_proxy_enter(self);
  if (self->request_length > self->max_request_length)
    {
      /*LOG
        This message indicates that the request line is too long and Zorp rejects
	the request. Check the 'max_request_length' attribute.
       */
      z_proxy_log(self, POP3_VIOLATION, 3, "Request line too long; line='%.*s', length='%d', max_request_length='%d'",
         (int)self->request_length, self->request_line, (int)self->request_length, self->max_request_length);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  for(i = 0; i < sizeof(command) - 1 && i < self->request_length && self->request_line[i] != ' '; i++)
    command[i] = self->request_line[i];
  command[i++] = 0;
  g_string_assign(self->command, command);
  g_string_ascii_up(self->command);

  if (self->request_length > i)
    {
      g_string_assign_len(self->command_param,
                          self->request_line + i,
                          self->request_length - i);

      /*LOG
        This message reports that the fetched request contains a parameter.
       */
      z_proxy_log(self, POP3_REQUEST, 7, "Request fetched with parameter; req='%s', req_prm='%s'", self->command->str, self->command_param->str);
    }
  else
    {
      /*LOG
        This message reports the fetched request.
       */
      z_proxy_log(self, POP3_REQUEST, 7, "Request fetched; req='%s'", self->command->str);
      g_string_assign(self->command_param, "");
    }

  self->command_desc = static_cast<Pop3InternalCommands *>(g_hash_table_lookup(self->pop3_commands, self->command->str));
  if (!self->command_desc && !self->permit_unknown_command && !pop3_policy_command_hash_search(self, self->command->str))
    {
      /*LOG
        This message indicates that the request was unknown and Zorp aborts the connection.
	Check the 'permit_unknown_command' and the 'request' attributes.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "Unknown request command; req='%s'", self->command->str);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  if (self->command_desc && !(self->command_desc->pop3_state & self->pop3_state))
    {
      /*LOG
        This message indicates that the request command is not allowed in this state of the protocol
	and Zorp rejects the request.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "Request command not allowed in this state; req='%s', state='%d'", self->command->str, self->pop3_state);
      z_proxy_return(self, POP3_REQ_REJECT);
    }
  z_proxy_return(self, POP3_REQ_ACCEPT);
}

guint
pop3_command_process(Pop3Proxy *self)
{
  guint res = POP3_REQ_ACCEPT;

  z_proxy_enter(self);
  res = pop3_policy_command_hash_do(self);
  if (res == POP3_REQ_ACCEPT)
    {
      if (self->command_desc)
        {
          self->response_multiline = self->command_desc->multi_line_response;
          if (self->command_desc->command_parse)
            res = self->command_desc->command_parse(self);
        }
    }
  z_proxy_return(self, res);
}

void
pop3_command_write(Pop3Proxy *self)
{
  gchar newline[self->max_request_length + 3];

  z_proxy_enter(self);
  if (self->command_param->len > 0)
    g_snprintf(newline, sizeof(newline), "%s %s\r\n", self->command->str, self->command_param->str);
  else
    g_snprintf(newline, sizeof(newline), "%s\r\n", self->command->str);
  pop3_write_server(self, newline);
  z_proxy_return(self);
}

void
pop3_command_reject(Pop3Proxy *self)
{
  gchar newline[self->max_reply_length + 1];

  z_proxy_enter(self);
  g_snprintf(newline, sizeof(newline), "%s %s\r\n", self->response->str, self->response_param->str);
  pop3_write_client(self, newline);
  z_proxy_return(self);
}

gboolean
pop3_client_to_server(ZStream *stream G_GNUC_UNUSED,
                 GIOCondition  cond G_GNUC_UNUSED,
                     gpointer user_data)
{
  Pop3Proxy *self = (Pop3Proxy *)user_data;
  guint resp;

  z_proxy_enter(self);
  g_string_assign(self->response, "-ERR");
  g_string_assign(self->response_param, "Invalid command.");
  resp = pop3_command_read(self);
  if (!resp)
    {
      self->pop3_state = POP3_STATE_QUIT;
      z_proxy_return(self, FALSE);
    }

  /* NOTE
   * POP3_STATE_AUTH_A_CANCEL state not needed because
   * it's could only be set after this and no other turn
   * available
   */
  if (self->pop3_state != POP3_STATE_AUTH_A)
    {
      resp = pop3_command_parse(self);
      if (resp == POP3_REQ_ACCEPT)
        resp = pop3_command_process(self);
    }
  else
    {
      resp = pop3_auth_parse(self, EP_CLIENT);
    }

  switch (resp)
    {
    case POP3_REQ_ACCEPT:
      pop3_command_write(self);
      self->state = POP3_SERVER;
      break;

    case POP3_REQ_REJECT:
      pop3_command_reject(self);
      break;

    case POP3_REQ_ABORT:
      pop3_command_reject(self); /* No break ! */

    default:
      self->pop3_state = POP3_STATE_QUIT;
      break;
    }
  z_proxy_return(self, TRUE);
}

void
pop3_set_defaults(Pop3Proxy *self)
{
  z_proxy_enter(self);
  self->max_username_length = 32;
  self->max_password_length = 32;

  self->username = g_string_new("");
  self->password = g_string_new("");

  self->command       = g_string_new("");
  self->command_param = g_string_new("");

  self->response       = g_string_new("");
  self->response_param = g_string_new("");

  self->timestamp = g_string_new("");
  self->timeout = 600000;
  self->max_request_length = 90;
  self->max_reply_length   = 512;
  self->pop3_commands = g_hash_table_new(g_str_hash, g_str_equal);
  self->commands_policy = g_hash_table_new(g_str_hash, g_str_equal);
  self->command_stack = g_hash_table_new(g_str_hash, g_str_equal);
  self->command_desc = NULL;
  self->policy_enable_longline = TRUE;
  self->buffer_length = 4096;
  self->max_authline_count = 4;
  self->reject_by_mail = TRUE;
  z_proxy_leave(self);
}

void
pop3_register_vars(Pop3Proxy *self)
{
  z_proxy_enter(self);
  z_proxy_var_new(&self->super, "timeout",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->timeout);

  z_proxy_var_new(&self->super, "max_request_line_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_request_length);

  z_proxy_var_new(&self->super, "max_response_line_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_reply_length);

  z_proxy_var_new(&self->super, "max_username_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_username_length);

  z_proxy_var_new(&self->super, "max_password_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_password_length);

  z_proxy_var_new(&self->super, "max_authline_count",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_authline_count);

  z_proxy_var_new(&self->super, "username",
                  Z_VAR_TYPE_STRING | Z_VAR_GET,
                  self->username);

  z_proxy_var_new(&self->super, "password",
                  Z_VAR_TYPE_STRING | Z_VAR_GET,
                  self->password);

  z_proxy_var_new(&self->super, "request_command",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->command);
  z_proxy_var_new(&self->super, "request_param",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->command_param);

  z_proxy_var_new(&self->super, "response_value",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->response);
  z_proxy_var_new(&self->super, "response_param",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->response_param);

  z_proxy_var_new(&self->super, "session_timestamp",
                  Z_VAR_TYPE_STRING | Z_VAR_GET,
                  self->timestamp);

  z_proxy_var_new(&self->super, "response_multiline",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET,
                  &self->response_multiline);

  z_proxy_var_new(&self->super, "permit_unknown_command",
                  Z_VAR_TYPE_INT | Z_VAR_SET_CONFIG | Z_VAR_GET,
                  &self->permit_unknown_command);

  z_proxy_var_new(&self->super, "request",
                  Z_VAR_TYPE_HASH | Z_VAR_GET_CONFIG | Z_VAR_GET,
                  self->commands_policy);

  z_proxy_var_new(&self->super, "response_stack",
                  Z_VAR_TYPE_HASH | Z_VAR_GET_CONFIG | Z_VAR_GET,
                  self->command_stack);

  z_proxy_var_new(&self->super, "permit_longline",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->policy_enable_longline);

  z_proxy_var_new(&self->super, "buffer_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->buffer_length);

  z_proxy_var_new(&self->super, "reject_by_mail",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->reject_by_mail);
  z_proxy_return(self);
}

guint
pop3_init_streams(Pop3Proxy *self)
{
  ZStream *tmpstream;

  z_proxy_enter(self);
  if (!self->super.endpoints[EP_SERVER] ||
      !self->super.endpoints[EP_CLIENT])
    z_proxy_return(self, FALSE);

  self->super.endpoints[EP_CLIENT]->timeout = self->timeout;
  self->super.endpoints[EP_SERVER]->timeout = self->timeout;

  tmpstream = self->super.endpoints[EP_CLIENT];
  self->super.endpoints[EP_CLIENT] = z_stream_line_new(tmpstream,
                                                       self->buffer_length,
                                                       ZRL_EOL_CRLF);
  z_stream_unref(tmpstream);

  tmpstream = self->super.endpoints[EP_SERVER];
  self->super.endpoints[EP_SERVER] = z_stream_line_new(tmpstream,
                                                       self->buffer_length,
                                                       ZRL_EOL_CRLF);
  z_stream_unref(tmpstream);

  z_stream_set_callback(self->super.endpoints[EP_CLIENT],
                        G_IO_IN,
                        pop3_client_to_server,
                        self,
                        NULL);

  z_stream_set_callback(self->super.endpoints[EP_SERVER],
                        G_IO_IN,
                        pop3_server_to_client,
                        self,
                        NULL);

  z_poll_add_stream(self->poll, self->super.endpoints[EP_CLIENT]);
  z_poll_add_stream(self->poll, self->super.endpoints[EP_SERVER]);
  z_proxy_return(self, TRUE);
}

static void
pop3_deinit_streams(Pop3Proxy *self)
{
  z_poll_remove_stream(self->poll, self->super.endpoints[EP_SERVER]);
  z_poll_remove_stream(self->poll, self->super.endpoints[EP_CLIENT]);
}

void
pop3_config_init(Pop3Proxy *self)
{
  int i;

  z_proxy_enter(self);
/* Load the command hash. */
  for (i = 0; known_commands[i].name != NULL; i++)
    g_hash_table_insert(self->pop3_commands, const_cast<gchar *>(known_commands[i].name),
                        const_cast<Pop3InternalCommands *>(&known_commands[i]));

  if (self->max_request_length + 1 > self->buffer_length)
    self->buffer_length = self->max_request_length + 1;

  if (self->max_reply_length + 1 > self->buffer_length)
    self->buffer_length = self->max_request_length + 1;

  self->poll = z_poll_new();
  z_proxy_return(self);
}

static gboolean
pop3_config(ZProxy *s)
{
  Pop3Proxy *self = Z_CAST(s, Pop3Proxy);

  z_proxy_enter(self);
  pop3_set_defaults(self);
  pop3_register_vars(self);
  if (Z_SUPER(s, ZProxy)->config(s))
    {
      pop3_config_init(self);
      z_proxy_return(self, TRUE);
    }
  z_proxy_return(self, FALSE);
}

/**
 * pop3_main:
 * s: Pop3Proxy instance
 *
 * Proxy main function.
 **/
static void
pop3_main(ZProxy *s)
{
  Pop3Proxy *self = (Pop3Proxy *) s;

  z_proxy_enter(self);
  if (!z_proxy_connect_server(&self->super, NULL, 0) || !pop3_init_streams(self))
    z_proxy_return(self);

  self->pop3_state = POP3_STATE_LISTEN;
  self->state = POP3_SERVER;

  z_stream_set_cond(self->super.endpoints[EP_CLIENT],
                    G_IO_IN,
                    FALSE);
  z_stream_set_cond(self->super.endpoints[EP_SERVER],
                    G_IO_IN,
                    TRUE);

  while (self->pop3_state != POP3_STATE_QUIT &&
         z_poll_is_running(self->poll))
    {
      if (!z_proxy_loop_iteration(s))
        {
          self->pop3_state = POP3_STATE_QUIT;
          break;
        }
      switch(self->state)
        {
        case POP3_CLIENT:
          z_stream_set_cond(self->super.endpoints[EP_CLIENT],
                            G_IO_IN,
                            TRUE);
          z_stream_set_cond(self->super.endpoints[EP_SERVER],
                            G_IO_IN,
                            FALSE);
          break;

        case POP3_SERVER:
          z_stream_set_cond(self->super.endpoints[EP_CLIENT],
                            G_IO_IN,
                            FALSE);
          z_stream_set_cond(self->super.endpoints[EP_SERVER],
                            G_IO_IN,
                            TRUE);
          break;

        case POP3_SERVER_MULTILINE:
          pop3_response_multiline(self);
          continue;

        default:
          self->pop3_state = POP3_STATE_QUIT;
          break;
        }

      if (!z_poll_iter_timeout(self->poll, self->timeout))
        self->pop3_state = POP3_STATE_QUIT;
    }
  pop3_deinit_streams(self);
  z_proxy_return(self);
}

ZProxyFuncs pop3_proxy_funcs =
{
  {
    Z_FUNCS_COUNT(ZProxy),
    pop3_proxy_free,
  },
  /* .config = */ pop3_config,
  /* .startup = */ NULL,
  /* .main = */ pop3_main,
  /* .shutdown = */ NULL,
  /* .destroy = */ NULL,
  /* .nonblocking_init = */ NULL,
  /* .nonblocking_deinit = */ NULL,
  /* .wakeup = */ NULL,
};

Z_CLASS_DEF(Pop3Proxy, ZProxy, pop3_proxy_funcs);

static ZProxy *
pop3_proxy_new(ZProxyParams *params)
{
  Pop3Proxy  *self;

  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(Pop3Proxy), params), Pop3Proxy);
  z_return((ZProxy *) self);
}

static void
pop3_proxy_free(ZObject *s)
{
  Pop3Proxy *self = (Pop3Proxy *) s;

  z_enter();
  g_hash_table_destroy(self->pop3_commands);
  z_poll_unref(self->poll);
  z_proxy_free_method(s);
  z_return();
}

static ZProxyModuleFuncs pop3_module_funcs =
  {
    /* .create_proxy = */ pop3_proxy_new,
    /* .module_py_init = */ NULL
  };

/*+

  Module initialization function. Registers a new proxy type.

+*/
gint
zorp_module_init(void)
{

  z_registry_add("pop3", ZR_PROXY, &pop3_module_funcs);
  return TRUE;
}
