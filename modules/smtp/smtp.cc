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

#include <zorp/thread.h>
#include <zorp/registry.h>
#include <zorp/log.h>
#include <zorp/policy.h>
#include <zorp/proxycommon.h>
#include <zorp/proxygroup.h>
#include <zorp/streamssl.h>

#define SMTP_DEBUG   "smtp.debug"
#define SMTP_REQUEST "smtp.request"
#define SMTP_REPLY   "smtp.reply"

/**
 * smtp_register_vars:
 * @self: SmtpProxy instance
 *
 * Registers python accessible variables.
 **/
static void
smtp_register_vars(SmtpProxy *self)
{
  z_proxy_enter(self);
  z_proxy_var_new(&self->super, "timeout",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->timeout);

  z_proxy_var_new(&self->super, "interval_transfer_noop",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->interval_transfer_noop);

  z_proxy_var_new(&self->super, "unconnected_response_code",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->unconnected_response_code);

  z_proxy_var_new(&self->super, "max_request_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_request_length);

  z_proxy_var_new(&self->super, "max_auth_request_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_auth_request_length);

  z_proxy_var_new(&self->super, "max_response_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_response_length);

  z_proxy_var_new(&self->super, "max_line_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_line_length);

  z_proxy_var_new(&self->super, "request_cmd",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->request);

  z_proxy_var_new(&self->super, "sender",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->sender);

  z_proxy_var_new(&self->super, "recipients",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->recipients);

  z_proxy_var_new(&self->super, "request_param",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->request_param);

  z_proxy_var_new(&self->super, "response_code",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->response);
  z_proxy_var_new(&self->super, "response_param",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->response_param);

  z_proxy_var_new(&self->super, "error_code",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->error_code);
  z_proxy_var_new(&self->super, "error_info",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->error_info);
  z_proxy_var_new(&self->super, "error_abort",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET,
                  &self->error_abort);

  z_proxy_var_new(&self->super, "append_domain",
                  Z_VAR_TYPE_STRING | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG | Z_VAR_GET | Z_VAR_SET,
                  self->append_domain);

  z_proxy_var_new(&self->super, "permit_unknown_command",
                  Z_VAR_TYPE_INT | Z_VAR_SET_CONFIG | Z_VAR_GET,
                  &self->permit_unknown_command);

  z_proxy_var_new(&self->super, "permit_long_responses",
                  Z_VAR_TYPE_INT | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG | Z_VAR_GET,
                  &self->permit_long_responses);

  z_proxy_var_new(&self->super, "permit_omission_of_angle_brackets",
                  Z_VAR_TYPE_INT | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG | Z_VAR_GET,
                  &self->permit_omission_of_angle_brackets);

  z_proxy_var_new(&self->super, "require_crlf",
                  Z_VAR_TYPE_INT | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG | Z_VAR_GET,
                  &self->require_crlf);

  z_proxy_var_new(&self->super, "permit_extensions",
                  Z_VAR_TYPE_INT | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG | Z_VAR_SET | Z_VAR_GET,
                  &self->permit_extensions);

  z_proxy_var_new(&self->super, "extensions",
                  Z_VAR_TYPE_HASH | Z_VAR_GET_CONFIG | Z_VAR_GET,
                  self->extensions);

  z_proxy_var_new(&self->super, "request",
                  Z_VAR_TYPE_HASH | Z_VAR_GET_CONFIG | Z_VAR_GET,
                  self->request_policy);

  z_proxy_var_new(&self->super, "response",
                  Z_VAR_TYPE_DIMHASH | Z_VAR_GET_CONFIG | Z_VAR_GET,
                  self->response_policy);

  z_proxy_var_new(&self->super, "active_extensions",
                  Z_VAR_TYPE_INT | Z_VAR_GET,
                  &self->active_extensions);

  z_proxy_var_new(&self->super, "add_received_header",
                  Z_VAR_TYPE_INT | Z_VAR_SET_CONFIG | Z_VAR_GET,
                  &self->add_received_header);

  z_proxy_var_new(&self->super, "helo_string",
                  Z_VAR_TYPE_STRING | Z_VAR_GET_CONFIG | Z_VAR_GET,
                  self->helo_string);

  z_proxy_var_new(&self->super, "protocol",
                  Z_VAR_TYPE_STRING | Z_VAR_GET_CONFIG | Z_VAR_GET,
                  self->protocol);

  z_proxy_var_new(&self->super, "tls_passthrough",
                  Z_VAR_TYPE_INT | Z_VAR_SET_CONFIG | Z_VAR_GET,
                  &self->tls_passthrough);

  z_proxy_var_new(&self->super, "sanitizeAddress",
                  Z_VAR_TYPE_METHOD | Z_VAR_GET,
                  self, smtp_policy_sanitize_address);

  z_proxy_return(self);
}

/**
 * smtp_set_defaults:
 * @self: SmtpProxy instance
 *
 * Set default values for various attributes in @self.
 **/
static void
smtp_set_defaults(SmtpProxy *self)
{
  z_proxy_enter(self);
  self->request       = g_string_sized_new(8);
  self->request_param = g_string_sized_new(128);

  self->response       = g_string_sized_new(4);
  self->response_param = g_string_sized_new(128);

  self->sender = g_string_sized_new(32);
  self->sanitized_recipient = g_string_sized_new(32);
  self->recipients = g_string_sized_new(32);

  self->error_code = g_string_sized_new(4);
  self->error_info = g_string_new("Invalid command");
  self->append_domain = g_string_sized_new(0);
  self->auth_request = g_string_sized_new(16);
  self->helo_string = g_string_sized_new(32);
  self->protocol = g_string_sized_new(6);

  self->timeout = 600000;
  self->interval_transfer_noop = 60000;
  self->buffer_size = 4096;

  self->active_extensions = static_cast<SmtpActionTypes>(0);

  self->max_request_length = 512;
  self->max_auth_request_length = 256;
  self->max_response_length = 512;
  self->max_line_length = 4096;
  self->require_crlf = TRUE;
  self->unconnected_response_code = 451;

  self->start_tls_ok[EP_CLIENT] = FALSE;
  self->start_tls_ok[EP_SERVER] = FALSE;

  self->tls_passthrough = FALSE;

  self->extensions = g_hash_table_new(g_str_hash, g_str_equal);
  self->request_policy = g_hash_table_new(g_str_hash, g_str_equal);
  self->response_policy = z_dim_hash_table_new(2, 2, DIMHASH_WILDCARD, DIMHASH_CONSUME);
  z_proxy_return(self);
}

/**
 * smtp_config_init:
 * @self: SmtpProxy instance
 *
 * Initialize a configuration after the config() method had been called. It
 * currently does nothing.
 **/
static gboolean
smtp_config_init(SmtpProxy *self G_GNUC_UNUSED)
{
  z_proxy_enter(self);
  z_proxy_return(self, TRUE);
}

/* request related functions */

/**
 * smtp_parse_request:
 * @self: SmtpProxy instance
 * @line: a complete line to parse as an SMTP request (non necessarily NULL terminated)
 * @line_len: length of @line
 *
 * This function parses an incoming line as an SMTP request and stores
 * various request parts in the @request and @request_param fields of @self.
 *
 * Returns: TRUE to indicate success
 **/
static gboolean
smtp_parse_request(SmtpProxy *self, gchar *line, gint line_len)
{
  gint i;

  z_proxy_enter(self);

  if (line_len <= 0)
    z_proxy_return(self, FALSE);

  g_string_truncate(self->request, 0);
  i = 0;
  while (i < line_len)
    {
      if (line[i] == ' ')
        break;
      else if (isalpha(line[i]))
        g_string_append_c(self->request, toupper(line[i])); /* NOTE we convert command to uppercase here so policy lookup works */
      i++;
    }

  if (self->request->len == 0
      || (i < line_len && line[i] != ' '))
    {
      /*LOG
        This message indicates that the request command verb is invalid and Zorp rejects the request.
       */
      z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid command verb in request; line='%.*s'", line_len, line);
      z_proxy_return(self, FALSE);
    }

  /* skip whitespace between verb and parameter */
  while (i < line_len && line[i] == ' ')
    i++;

  if (line_len > i)
    g_string_assign_len(self->request_param, line + i, line_len - i);
  else
    g_string_assign(self->request_param, "");
  /*LOG
    This message reports that the request was parsed successfully.
   */
  z_proxy_log(self, SMTP_REQUEST, 7, "Request parsed; request='%s', param='%s'", self->request->str, self->request_param->str);
  z_proxy_return(self, TRUE);
}

/**
 * smtp_fetch_request:
 * @self: SmtpProxy instance
 *
 * This function reads and parses an SMTP request from the client.
 *
 * Returns: TRUE for success
 **/
static gboolean
smtp_fetch_request(SmtpProxy *self)
{
  GIOStatus res;
  gchar *line;
  gsize line_len;

  z_proxy_enter(self);
  /*LOG
    This message reports that the request is going to be fetched.
   */
  z_proxy_log(self, SMTP_DEBUG, 6, "Fetching request;");
  res = z_stream_line_get(self->super.endpoints[EP_CLIENT], &line, &line_len, NULL);
  if (res != G_IO_STATUS_NORMAL)
    {
      if (res == G_IO_STATUS_ERROR || res == G_IO_STATUS_EOF)
        {
          g_string_assign(self->error_code, "421");
          g_string_assign(self->error_info, "Service not available, closing transmission channel.");
          self->error_abort = TRUE;
        }
      else if (res != G_IO_STATUS_AGAIN)
        {
          self->error_abort = TRUE;
        }
      z_proxy_return(self, FALSE);
    }
  if (line_len > self->max_request_length)
    {
      /*LOG
        This message indicates that the request line is too long and Zorp rejects the request. Check
	the 'max_request_length' attribute.
       */
      z_proxy_log(self, SMTP_VIOLATION, 2, "Request line too long; length='%zd', max='%d'", line_len, self->max_request_length);
      z_proxy_return(self, FALSE);
    }

  if (!smtp_parse_request(self, line, line_len))
    z_proxy_return(self, FALSE);

  self->request_cmd = static_cast<SmtpCommandDesc *>(g_hash_table_lookup(known_commands, self->request->str));
  z_proxy_return(self, TRUE);
}

/**
 * smtp_process_request:
 * @self: SmtpProxy instance
 *
 * Process a request read by @smtp_fetch_request.
 *
 * Returns: TRUE to indicate success.
 **/
static SmtpRequestTypes
smtp_process_request(SmtpProxy *self)
{
  SmtpRequestTypes res = SMTP_REQ_ACCEPT;

  z_proxy_enter(self);
  /*LOG
    This message reports that the request is going to be processed.
   */
  z_proxy_log(self, SMTP_DEBUG, 6, "Processing request;");
  if (self->request_cmd && !(self->request_cmd->smtp_state & self->smtp_state))
    {
      res = SMTP_REQ_REJECT;
      g_string_assign(self->error_code, "503");
      g_string_assign(self->error_info, "Invalid command in this state");
      /*LOG
        This message indicates that the given command is not permitted in this state of the communication and
	Zorp rejects the request.
       */
      z_proxy_log(self, SMTP_VIOLATION, 4, "Command not permitted in this state; request='%s', state='%d'", self->request->str, self->smtp_state);
      z_proxy_return(self, res);
    }

  if (self->request_cmd && self->request_cmd->command_parse)
    {
      res = self->request_cmd->command_parse(self);
      if (res != SMTP_REQ_ACCEPT)
        z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid SMTP command; request='%s', param='%s'", self->request->str, self->request_param->str);
    }

  if (res == SMTP_REQ_ACCEPT)
    {
      res = smtp_policy_check_request(self);
      if (res != SMTP_REQ_ACCEPT)
        z_proxy_log(self, SMTP_POLICY, 2, "Request not allowed by policy; request='%s', verdict='%d'", self->request->str, res);
    }

  if (!self->request_cmd && !self->permit_unknown_command && res != SMTP_REQ_ACCEPT)
    {
      /*LOG
        This message indicates that the given request is unknown and Zorp rejects it.
	Check the 'permit_unknown_command' and the 'request' attributes.
       */
      z_proxy_log(self, SMTP_VIOLATION, 2, "Unknown command; request='%s'", self->request->str);
      z_proxy_return(self, res);
    }

  if (res == SMTP_REQ_ABORT)
    {
      g_string_assign(self->error_code, "421");
      g_string_assign(self->error_info, "Service not available, closing transmission channel.");
      self->error_abort = TRUE;
    }

  if (res == SMTP_REQ_ACCEPT &&
      self->request_cmd && self->request_cmd->action_do)
    {
      res = self->request_cmd->action_do(self);
      if (res != SMTP_REQ_ACCEPT && res != SMTP_REQ_NOOP)
        z_proxy_log(self, SMTP_VIOLATION, 2, "Error processing SMTP request; request='%s', param='%s'", self->request->str, self->request_param->str);
    }

  z_proxy_return(self, res);
}

/**
 * smtp_copy_request:
 * @self: SmtpProxy instance
 *
 * Copy a request from the internal state to the stream representing the
 * server.
 *
 * Returns: TRUE to indicate success
 **/
static gboolean
smtp_copy_request(SmtpProxy *self)
{
  gchar newline[self->max_request_length + 3];
  gint len;
  gsize bytes_written;
  GIOStatus res;

  z_proxy_enter(self);
  /*LOG
    This message reports that the request is going to be copied to the server.
   */
  z_proxy_log(self, SMTP_DEBUG, 6, "Copying request to server; request='%s', param='%s'", self->request->str, self->request_param->str);
  if (self->request_param->len > 0)
    g_snprintf(newline, sizeof(newline), "%s %s\r\n", self->request->str, self->request_param->str);
  else
    g_snprintf(newline, sizeof(newline), "%s\r\n", self->request->str);
  len = strlen(newline);
  res = z_stream_write(self->super.endpoints[EP_SERVER], newline, len, &bytes_written, NULL);
  if (res != G_IO_STATUS_NORMAL)
    {
      /*LOG
        This message indicates that an error occurred during sending the request to the server.
       */
      z_proxy_log(self, SMTP_ERROR, 3, "Error sending request; request='%s', param='%s'", self->request->str, self->request_param->str);
      z_proxy_return(self, FALSE);
    }
  z_proxy_return(self, TRUE);
}

/* authentication requests */

static gboolean
smtp_fetch_auth_request(SmtpProxy *self)
{
  GIOStatus res;
  gchar *line;
  gsize line_len;

  z_proxy_enter(self);
  /*LOG
    This message reports that the authentication request is going to be fetched.
   */
  z_proxy_log(self, SMTP_DEBUG, 6, "Fetching authentication request;");
  res = z_stream_line_get(self->super.endpoints[EP_CLIENT], &line, &line_len, NULL);
  if (res != G_IO_STATUS_NORMAL)
    {
      if (res == G_IO_STATUS_ERROR)
        {
          g_string_assign(self->error_code, "421");
          g_string_assign(self->error_info, "Service not available, closing transmission channel.");
          self->error_abort = TRUE;
        }
      z_proxy_return(self, FALSE);
    }
  if (line_len > self->max_auth_request_length)
    {
      /*LOG
        This message indicates that the authentication request line is too long and Zorp rejects the request.
	Check the 'max_auth_request_length' attribute.
       */
      z_proxy_log(self, SMTP_VIOLATION, 2, "Auth request line too long; length='%zd', max='%d'", line_len, self->max_auth_request_length);
      z_proxy_return(self, FALSE);
    }
  /* FIXME: verify whether the line contains valid mime64 encoding */
  g_string_assign_len(self->auth_request, line, line_len);
  z_proxy_return(self, TRUE);
}

/**
 * smtp_copy_auth_request:
 * @self: SmtpProxy instance
 *
 * Copy an authentication request from the internal state to the stream
 * representing the server.
 *
 * Returns: TRUE to indicate success
 **/
static gboolean
smtp_copy_auth_request(SmtpProxy *self)
{
  gchar newline[self->max_auth_request_length + 3];
  gint len;
  gsize bytes_written;
  GIOStatus res;

  z_proxy_enter(self);
  /*LOG
    This message reports that the authentication request is going to be copied to the server.
   */
  z_proxy_log(self, SMTP_DEBUG, 6, "Copying authentication request to server;");
  g_snprintf(newline, sizeof(newline), "%s\r\n", self->auth_request->str);

  len = strlen(newline);
  res = z_stream_write(self->super.endpoints[EP_SERVER], newline, len, &bytes_written, NULL);
  if (res != G_IO_STATUS_NORMAL)
    {
      /*LOG
        This message indicates that an error occurred during sending the authentication request to the server.
       */
      z_proxy_log(self, SMTP_ERROR, 3, "Error sending authentication request;");
      z_proxy_return(self, FALSE);
    }
  z_proxy_return(self, TRUE);
}

/* response handling */

/**
 * smtp_clear_response:
 * @self: SmtpProxy instance
 *
 * Clear the currently stored response and free associated storage.
 **/
void
smtp_clear_response(SmtpProxy *self)
{
  GList *p, *pnext;

  g_string_truncate(self->response, 0);
  g_string_truncate(self->response_param, 0);
  for (p = self->response_lines, pnext = NULL; p; p = pnext)
    {
      g_string_free((GString *) p->data, TRUE);
      pnext = p->next;
      g_list_free_1(p);
    }
  self->response_lines = NULL;
}

/**
 * smtp_set_response:
 * @self: SmtpProxy instance
 * @code: SMTP reply code
 * @param: SMTP reply parameter
 *
 * Set the internal proxy state to contain the specified SMTP reply.
 * Primarily used to set an error response to be sent back to the client.
 **/
static void
smtp_set_response(SmtpProxy *self, const gchar *code, const gchar *param)
{
  z_proxy_enter(self);
  smtp_clear_response(self);
  g_string_assign(self->response, code);
  g_string_assign(self->response_param, param);
  z_proxy_return(self);
}

/**
 * smtp_parse_response:
 * @self: SmtpProxy instance
 * @line: the whole line as sent by the server
 * @line_len: the length of @line
 * @continuation: whether the response is to be continued
 * @code: the address of the reply code is returned here
 * @code_len: the length of the @code is returned here
 * @text: the address of textual parameter of the reply is returned here
 * @text_len: the length of @text is returned here
 *
 * Splits an incoming response line into parts, and returns them in
 * appropriate parameters. Returns TRUE to indicate success.
 **/
static gboolean
smtp_parse_response(SmtpProxy *self G_GNUC_UNUSED,
                    gchar *line, gint line_len,
                    gboolean *continuation,
                    gchar **code, gint *code_len,
                    gchar **text, gint *text_len)
{
  gint i;

  z_proxy_enter(self);
  if (line_len < 3)
    {
      z_proxy_log(self, SMTP_VIOLATION, 2, "Too small response; line='%.*s'", line_len, line);
      z_proxy_return(self, FALSE);
    }
  for (i = 0; i < 3; i++)
    {
      if (!isdigit(line[i]))
        {
	  /*LOG
	    This message indicates that the response contains non-numeric characters and Zorp
	    rejects the response.
	   */
          z_proxy_log(self, SMTP_VIOLATION, 2, "SMTP reply contains non-numeric characters; line='%.*s'", line_len, line);
          z_proxy_return(self, FALSE);
        }
    }
  *code = line;
  *code_len = 3;
  if (line_len > 3)
    {
      if (line[3] == '-')
        {
          /* continuation */
          *continuation = TRUE;
        }
      else if (line[3] == ' ')
        {
          *continuation = FALSE;
        }
      else
        {
	  /*LOG
	    This message indicates that the continuation character of the response contains an invalid
	    character and Zorp rejects the response. The response must contain ' ' or '-' after the response code.
	   */
          z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid continuation character; line='%.*s'", line_len, line);
          z_proxy_return(self, FALSE);
        }
      *text_len = line_len - 4;
      *text = line + 4;
    }
  else
    {
      *text_len = 0;
      *text = NULL;
    }
  z_proxy_return(self, TRUE);
}

/**
 * smtp_fetch_response:
 * @self: SmtpProxy instance
 *
 * This function reads and parses an incoming SMTP request and stores the
 * results in @self.
 **/
static gboolean
smtp_fetch_response(SmtpProxy *self)
{
  GIOStatus res;
  gchar *line, *code, *text;
  gsize line_len;
  gint code_len, text_len;
  gboolean continuation = TRUE, first = TRUE;
  gboolean success = FALSE;

  z_proxy_enter(self);
  /*LOG
    This message reports that the response is going to be fetched.
   */
  z_proxy_log(self, SMTP_DEBUG, 6, "Fetching response;");
  smtp_clear_response(self);
  while (continuation)
    {
      res = z_stream_line_get(self->super.endpoints[EP_SERVER], &line, &line_len, NULL);
      if (res != G_IO_STATUS_NORMAL)
        {
          if (res == G_IO_STATUS_ERROR)
            self->error_abort = TRUE;
          goto error_exit;
        }

      if ((guint) line_len > self->max_response_length)
        {
          if (!self->permit_long_responses)
            {
              /*LOG
                This message indicates that the response line is too long and Zorp rejects the response. Check
                the 'max_response_length' attribute.
               */
              z_proxy_log(self, SMTP_VIOLATION, 2, "Response line too long; line='%.*s', length='%" G_GSIZE_FORMAT "', max_response_length='%d'", (gint) line_len, line, line_len, self->max_response_length);
              goto error_exit;
            }
          else
            {
              line_len = self->max_response_length;
              z_proxy_log(self, SMTP_VIOLATION, 3, "Response line was too long, truncated; length='%" G_GSIZE_FORMAT "', max_response_length='%d'", line_len, self->max_response_length);
            }
        }

      if (!smtp_parse_response(self,
                               line, line_len,
                               &continuation,
                               &code, &code_len,
                               &text, &text_len))
        goto error_exit; /* the error is logged by parse_response */

      if (first)
        {
          g_string_assign_len(self->response, code, code_len);
          g_string_assign_len(self->response_param, text, text_len);
          first = FALSE;
        }
      else
        {
          if (strncmp(self->response->str, code, code_len) != 0)
            {
              /* hmm, return codes in continuation lines differs from the
               * first */
	      /*LOG
	        This message indicates that the reply code has changed in the continuation lines and Zorp rejects the response.
	       */
              z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid SMTP reply, reply code changed; response='%s', line='%.*s'", self->response->str, (gint) line_len, line);
              goto error_exit;
            }
          self->response_lines = g_list_prepend(self->response_lines, g_string_new_len(text, text_len));
        }
    }
  success = TRUE;

  /*LOG
    This message reports that the response is parsed successfully.
   */
  z_proxy_log(self, SMTP_RESPONSE, 7, "Response parsed; response='%s', param='%s'", self->response->str, self->response_param->str);

 error_exit:
  self->response_lines = g_list_reverse(self->response_lines);
  z_proxy_return(self, success);
}

/**
 * Check if the response is accepted according to the response type
 * @param res           the result to check
 *
 * @return TRUE if the response was accepted
 *         FALSE otherwise
 */
static inline gboolean
smtp_response_accepted(SmtpResponseTypes res)
{
  return (res == SMTP_RSP_ACCEPT || res == SMTP_RSP_NOOP);
}

/**
 * smtp_process_response:
 * @self: SmtpProxy instance
 *
 * Process a response by calling the appropriate command specific parsing
 * function.
 **/
static SmtpResponseTypes
smtp_process_response(SmtpProxy *self)
{
  SmtpResponseTypes res;

  /*LOG
    This message indicates that the response is going to be processed.
   */
  z_proxy_log(self, SMTP_DEBUG, 6, "Processing response;");
  res = smtp_policy_check_response(self);

  if (res == SMTP_RSP_ACCEPT)
    {
      if (self->request_cmd && self->request_cmd->response_parse)
        {
          res = self->request_cmd->response_parse(self);
          if (!smtp_response_accepted(res))
            {
              z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid SMTP response; request='%s', response='%s'", self->request->str, self->response->str);
            }
        }
    }
  else
    {
      z_proxy_log(self, SMTP_POLICY, 2, "Response not allowed by policy; request='%s', response='%s'", self->request->str, self->response->str);
    }

  if (res == SMTP_RSP_ABORT)
    {
      g_string_assign(self->error_code, "421");
      g_string_assign(self->error_info, "Service not available, closing transmission channel.");
      self->error_abort = TRUE;
    }

  return res;
}

/**
 * smtp_copy_response:
 * @self: SmtpProxy instance
 *
 * Copy the parsed response to the client by formatting the appropriate
 * protocol elements.
 **/
gboolean
smtp_copy_response(SmtpProxy *self)
{
  GList *p;
  GString *response;
  gsize bytes_written;
  gboolean success = TRUE;

  z_proxy_enter(self);
  /*LOG
    This message reports that the response is going to be copied to the client.
   */
  z_proxy_log(self, SMTP_DEBUG, 6, "Copying response to client;");
  response = g_string_sized_new(64);
  if (self->response_lines || self->response_param->len)
    g_string_sprintf(response, "%s%c%s\r\n", self->response->str, self->response_lines ? '-' : ' ', self->response_param->str);
  else
    g_string_sprintf(response, "%s\r\n", self->response->str);

  for (p = self->response_lines; p; p = p->next)
    g_string_sprintfa(response, "%s%c%s\r\n", self->response->str, p->next ? '-' : ' ', ((GString *) p->data)->str);

  if (z_stream_write(self->super.endpoints[EP_CLIENT], response->str, response->len, &bytes_written, NULL) != G_IO_STATUS_NORMAL)
    {
      /*LOG
        This message indicates that an error occurred during sending the response to the client.
       */
      z_proxy_log(self, SMTP_ERROR, 3, "Error sending SMTP reply;");
      success = FALSE;
    }
  g_string_free(response, TRUE);
  z_proxy_return(self, success);
}

/* general I/O entry points when the protocol is running */

/**
 * smtp_init_streams:
 * @self: SmtpProxy instance
 *
 * Initialize server and client side streams.
 *
 * Returns: TRUE to indicate success
 **/
static gboolean
smtp_init_streams(SmtpProxy *self)
{
  ZStream *tmpstream;

  z_proxy_enter(self);
  self->super.endpoints[EP_CLIENT]->timeout = self->timeout;
  tmpstream = self->super.endpoints[EP_CLIENT];
  self->super.endpoints[EP_CLIENT] = z_stream_line_new(tmpstream, self->max_line_length, ZRL_NUL_NONFATAL | ZRL_EOL_CRLF | (self->require_crlf ? ZRL_EOL_FATAL : 0));
  z_stream_unref(tmpstream);

  /**
   * When server side SSL handshake fails the proxy is in
   * SMTP_PROXY_UNCONNECTED_GREET state, but there is an
   * endpoint to the server
   */
  if (self->super.endpoints[EP_SERVER] && self->proxy_state != SMTP_PROXY_UNCONNECTED_GREET)
    {
      self->super.endpoints[EP_SERVER]->timeout = self->timeout;
      tmpstream = self->super.endpoints[EP_SERVER];
      self->super.endpoints[EP_SERVER] = z_stream_line_new(tmpstream, self->max_line_length,
                  ZRL_NUL_NONFATAL | ZRL_EOL_CRLF |
                  (self->require_crlf ? ZRL_EOL_FATAL : 0) |
                  (self->permit_long_responses ? ZRL_TRUNCATE : 0));
      z_stream_unref(tmpstream);
      self->proxy_state = SMTP_PROXY_RESPONSE;
    }
  else
    {
      self->proxy_state = SMTP_PROXY_UNCONNECTED_GREET;
    }
  z_proxy_return(self, TRUE);
}

static gboolean
smtp_generate_noop(SmtpProxy *self)
{
  gboolean policy_rejected;

  g_string_assign(self->request, "NOOP");
  g_string_assign(self->request_param, "");
  if (!smtp_copy_request(self) || !smtp_fetch_response(self))
    {
      return FALSE;
    }
  else
    {
      policy_rejected = !smtp_response_accepted(smtp_process_response(self));
      if (strcmp(self->response->str, "250") == 0 && policy_rejected)
        {
	  /*LOG
	    This message indicates that the response code 250 for the NOOP request is required and
	    Zorp ignores the invalid policy while generating NOOPs to the server.
	   */
          z_proxy_log(self, SMTP_POLICY, 3, "Invalid policy ignored, allowing 250 response to NOOP is required;");
        }
    }
  return TRUE;
}

gboolean
smtp_generate_received(SmtpProxy *self, GString **dst_string)
{
  gchar *received_line;
  ZPolicyObj *res;
  gboolean ret = FALSE;
  gboolean called;

  z_policy_lock(self->super.thread);

  res = z_policy_call(self->super.handler, "generateReceived", z_policy_var_build("()"),
                      &called, self->super.session_id);
  if (res)
    {
      if (!z_policy_var_parse(res, "s", &received_line))
        {
          z_proxy_log(self, SMTP_ERROR, 3, "Couldn't generate received line; error='wrong return value'");
        }
      else
        {
          *dst_string = g_string_new(received_line);
          ret = TRUE;
        }
      z_policy_var_unref(res);
    }
  else
    {
      z_proxy_log(self, SMTP_ERROR, 3, "Couldn't generate received line; error='exception occurred'");
    }

  z_policy_unlock(self->super.thread);
  return ret;
}

void
smtp_reset_state(SmtpProxy *self)
{
  self->smtp_state = SMTP_STATE_EHLO;
  g_string_truncate(self->sender, 0);
  g_string_truncate(self->recipients, 0);
}

/**
 * smtp_format_stack_info:
 * @self: SmtpProxy instance
 * @stack_info: Info sent by stacked proxy
 *
 * Set up a well-formed error string from the info
 * sent by stacked proxy. Check if the line has
 * character with have problem when sent as smtp response.
 *
 */
void
smtp_format_stack_info(SmtpProxy *self, const gchar *msg, const gchar *stack_info)
{
  const guchar *search;

  for (search = (const guchar *) stack_info; *search < 127 && !g_ascii_iscntrl(*search) && *search != 0; search++)
    ;

  g_string_printf(self->error_info, "%s (%.*s)", msg, (gint) ((gchar *)search - stack_info), stack_info);

  return;
}

static gboolean
smtp_process_transfer(SmtpProxy *self)
{
  ZTransfer2Result tr;
  gboolean policy_rejected;

  g_string_assign(self->error_code, "550");
  g_string_assign(self->error_info, "Error storing message");

  tr = ZT2_RESULT_FAILED;
  if (smtp_transfer_is_data_delayed(self->transfer))
    {
      gint suspend_reason = SMTP_TRANSFER_SUSPEND_DATA;

      /* make sure the server's timeout is extended (maybe the client waited
       * a lot before sending DATA) */
      if (!smtp_generate_noop(self))
        {
          goto error_reject_data;
        }

      /* we are entered here prior sending the DATA command */

      /* we respond in the name of the server to let our child proxy
       * have a chance to reject the contents (otherwise an empty
       * message would be sent) */
      g_string_assign(self->response, "354");
      g_string_assign(self->response_param, "Go on, send your message");
      if (!smtp_copy_response(self))
        {
          /* the client probably closed its connection, we should attempt to
           * write a 421 and close the session */
          goto error_before_transfer;

        }

      /* from this point the client sent a "DATA" and we responded to it
       * with 354, Thus the client is sending the mail body */

      do
        {
          tr = z_transfer2_run(self->transfer);

          if (tr == ZT2_RESULT_SUSPENDED)
            {
              suspend_reason = z_transfer2_get_suspend_reason(self->transfer);
              if (suspend_reason == SMTP_TRANSFER_SUSPEND_NOOP)
                {
                  if (!smtp_generate_noop(self))
                    {
                      goto error_in_transfer;
                    }
                }
            }
        }
      while (tr == ZT2_RESULT_SUSPENDED && suspend_reason != SMTP_TRANSFER_SUSPEND_DATA);

      /* still receiving the mail body */

      if (tr == ZT2_RESULT_SUSPENDED)
        {
          g_string_assign(self->request, "DATA");
          g_string_assign(self->request_param, "");
          if (!smtp_copy_request(self))
            {
              /* the server probably closed its connection */

              /* we need to fetch the end of the mail body, and return 550 to indicate failure and send RSET to server */
              goto error_reset;
            }
          if (!smtp_fetch_response(self))
            {
              /* we need to fetch the end of the mail body, and return 550 to indicate failure */
              goto error_reset;
            }
          policy_rejected = !smtp_response_accepted(smtp_process_response(self));
          if (strcmp(self->response->str, "354") != 0)
            {
              /* we need to fetch the end of the mail body, and return 550 to indicate failure */
              goto error_reset;
            }
          else if (policy_rejected)
            {
	      /*LOG
	        This message indicates that the response code 354 for the DATA request is required and
		Zorp ignores the invalid policy during data transfer to the server.
	       */
              z_proxy_log(self, SMTP_POLICY, 3, "Invalid policy ignored, allowing 354 response to DATA is required;");
            }

          do
            {
              tr = z_transfer2_run(self->transfer);
            }
          while (tr == ZT2_RESULT_SUSPENDED);

          /* ok, the transfer either succeeded or it failed but it is ended.
           * if it was a failure we return 550 and go on fetching the next
           * request, if it was a success we go on fetching the next
           * response from the server */

        }
      else if (tr == ZT2_RESULT_FINISHED)
        {
          /* empty message */
          if (z_transfer2_get_stack_decision(self->transfer) == ZV_REJECT)
            {
	      /*LOG
	        This message indicates that the content was declared invalid by the stacked proxy and Zorp
		rejects it.
	       */
              z_proxy_log(self, SMTP_POLICY, 3, "Invalid contents; stack_info='%s'", z_transfer2_get_stack_info(self->transfer));

              smtp_format_stack_info(self, "Error storing message", z_transfer2_get_stack_info(self->transfer));
            }
          else if (z_transfer2_get_stack_decision(self->transfer) == ZV_DROP)
            {
              z_proxy_log(self, SMTP_POLICY, 3, "Message dropped, invalid contents; stack_info='%s'", z_transfer2_get_stack_info(self->transfer));
              g_string_assign(self->error_code, "250");
              smtp_format_stack_info(self, "Message discarded", z_transfer2_get_stack_info(self->transfer));
            }
          else if (z_transfer2_get_stack_decision(self->transfer) == ZV_ERROR)
            {
              /*LOG
                This message inidicates that an error occurred during stacked proxy handle the contents and Zorp
                send back a temporary error message.
               */
              z_proxy_log(self, SMTP_POLICY, 3, "Error occurred while scanning contents; stack_info='%s'", z_transfer2_get_stack_info(self->transfer));
              g_string_assign(self->error_code, "421");
              g_string_assign(self->error_info, "Service not available, closing transmission channel.");
            }
          else
            {
	      /*LOG
	        This message indicates that an empty message is received from the stacked proxy and Zorp
		rejects it.
	       */
              z_proxy_log(self, SMTP_ERROR, 3, "Rejecting empty message;");
            }
          goto error_reset;
        }

    }
  else
    {
      /* the DATA command was sent and its response is received &
       * copied back to the client, check if we really need to
       * transfer data */

      if (strcmp(self->response->str, "354") == 0)
        {
          /* ok, our DATA command was accepted, go on sending the data stream */

          tr = z_transfer2_run(self->transfer);
          while (tr == ZT2_RESULT_SUSPENDED)
            tr = z_transfer2_run(self->transfer);

        }
    }

  if (tr == ZT2_RESULT_FINISHED)
    self->proxy_state = SMTP_PROXY_RESPONSE;
  else if (tr == ZT2_RESULT_ABORTED)
    goto error_abort;
  else if (tr == ZT2_RESULT_FAILED)
    goto error_in_transfer;

  return TRUE;

 error_reject_data:
  g_string_assign(self->response, "450");
  g_string_assign(self->response_param, "Mailbox unavailable, try again");
  z_proxy_log(self, SMTP_ERROR, 2, "Server closed the connection before transmission;");
  return FALSE;

 error_before_transfer:
  self->error_abort = TRUE;
  g_string_assign(self->error_code, "421");
  g_string_assign(self->error_info, "Service not available, closing transmission channel.");
  z_proxy_log(self, SMTP_ERROR, 2, "Client closed the connection before transmission;");
  return FALSE;

 error_abort:
  self->error_abort = TRUE;
  g_string_assign(self->error_code, "550");
  g_string_assign(self->error_info, "Mail body error (probably incorrect CRLF sequence)");
  z_proxy_log(self, SMTP_VIOLATION, 2, "Transaction aborted, some data may have been sent;");
  return FALSE;

 error_reset:
  g_string_assign(self->request, "RSET");
  g_string_assign(self->request_param, "");

  if (!smtp_copy_request(self) ||
      !smtp_fetch_response(self) ||
      !smtp_response_accepted(smtp_process_response(self)))
    {
      /*LOG
        This message indicates that Zorp was unable to send RSET command to the server.
       */
      z_proxy_log(self, SMTP_ERROR, 3, "Error sending RSET to the server;");
    }

 error_in_transfer:
  /* fetch the remaining mail body and return 550 */
  z_transfer2_rollback(self->transfer);
  z_proxy_log(self, SMTP_ERROR, 2, "Transaction failed, some data may have been sent;");
  return FALSE;
}

/**
 * smtp_config:
 * @s: SmtpProxy instance
 *
 * The config method for the SmtpProxy class.
 **/
static gboolean
smtp_config(ZProxy *s)
{
  SmtpProxy *self = (SmtpProxy *) s;
  gboolean success = FALSE;

  z_proxy_enter(self);
  self->poll = z_poll_new();
  smtp_set_defaults(self);
  smtp_register_vars(self);
  if (Z_SUPER(s, ZProxy)->config(s))
    success = smtp_config_init(self);
  z_proxy_return(self, success);
}

/**
 * Finish callback for our plug session
 * @param session       the session object (unused)
 * @param user_data     proxy owning the session
 *
 * Called by the plugsession callbacks when the channels have been
 * closed. We simply transition to SMTP_STATE_QUIT to exit the main
 * loop.
 */
static void
smtp_plug_finish(ZPlugSession *session G_GNUC_UNUSED, gpointer user_data)
{
  SmtpProxy *self = (SmtpProxy *) user_data;

  self->smtp_state = SMTP_STATE_QUIT;
}

/**
 * Timeout callback for our plug session
 * @param session       the session object (unused)
 * @param user_data     proxy owning the session
 *
 * Called by the plugsession callbacks when the channel timed out. We
 * go to SMTP_STATE_QUIT so that we exit our main loop in the next
 * iteration.
 */
static void
smtp_plug_timeout(ZPlugSession *session G_GNUC_UNUSED, gpointer user_data)
{
  SmtpProxy *self = (SmtpProxy *) user_data;

  self->smtp_state = SMTP_STATE_QUIT;
}

/**
 * Start a plug session with the streams of our proxy
 * @param self          our SmtpProxy instance
 *
 * Fall back to plug mode -- don't actually process anything, just get
 * data from client to server and back.  We set streams to
 * non-blocking, start a plug session and then iterate until the
 * session exits.
 *
 * On return, the streams of the proxy are in an inconsistent state
 * (might have been switched to non-blocking, for example).
 * @return              TRUE on success
 *                      FALSE if there was an error during the transfer
 */
static gboolean
smtp_plug_do_transfer(SmtpProxy *self)
{
  z_proxy_enter(self);

  /* set up plug session parameters */
  self->start_tls_fallback_data.copy_to_server = TRUE;
  self->start_tls_fallback_data.copy_to_client = TRUE;
  self->start_tls_fallback_data.timeout = self->timeout;
  self->start_tls_fallback_data.buffer_size = 2048;
  self->start_tls_fallback_data.packet_stats = NULL;
  self->start_tls_fallback_data.finish = smtp_plug_finish;
  self->start_tls_fallback_data.timeout_cb = smtp_plug_timeout;

  ZPlugSession *session = z_plug_session_new(&self->start_tls_fallback_data,
                                             self->super.endpoints[EP_CLIENT],
                                             self->super.endpoints[EP_SERVER],
                                             NULL, &self->super);
  if (session == NULL)
    z_proxy_return(self, FALSE);

  ZPoll *poll = z_poll_new();
  if (poll == NULL)
    {
      z_plug_session_destroy(session);
      z_proxy_return(self, FALSE);
    }

  z_stream_set_nonblock(self->super.endpoints[EP_CLIENT], TRUE);
  z_stream_set_nonblock(self->super.endpoints[EP_SERVER], TRUE);

  if (!z_plug_session_start(session, poll))
    {
      z_plug_session_destroy(session);
      z_proxy_return(self, FALSE);
    }

  while (z_poll_is_running(poll) &&
         self->smtp_state != SMTP_STATE_QUIT)
    {
      if (!z_proxy_loop_iteration(&self->super) ||
          !z_poll_iter_timeout(poll, -1))
        {
          self->smtp_state = SMTP_STATE_QUIT;
          break;
        }
    }

  z_plug_session_cancel(session);
  z_plug_session_destroy(session);

  z_poll_unref(poll);

  z_proxy_return(self, TRUE);
}

/**
 * smtp_main:
 * @self: SmtpProxy instance
 *
 * Main function of the SMTP proxy, implements the basic protocol by calling
 * various functions.
 **/
static void
smtp_main(ZProxy *s)
{
  SmtpProxy *self = Z_CAST(s, SmtpProxy);
  gboolean success, accepted;
  gboolean need_quit = FALSE;

  z_proxy_enter(self);
  if (!z_proxy_connect_server(&self->super, NULL, 0))
    self->proxy_state = SMTP_PROXY_UNCONNECTED_GREET;
  else
    self->proxy_state = SMTP_PROXY_RESPONSE;

  if (!smtp_init_streams(self))
    z_proxy_return(self);

  self->smtp_state = SMTP_STATE_INITIAL;

  while (self->smtp_state != SMTP_STATE_QUIT)
    {
      if (!z_proxy_loop_iteration(s))
        {
          self->smtp_state = SMTP_STATE_QUIT;
          break;
        }
      g_string_assign(self->error_code, "500");
      g_string_assign(self->error_info, "Invalid command");

      switch (self->proxy_state)
        {
        case SMTP_PROXY_UNCONNECTED_GREET:
          g_string_printf(self->error_code, "%d", self->unconnected_response_code);
          g_string_assign(self->error_info, "Server not available");
          self->proxy_state = SMTP_PROXY_UNCONNECTED_REJECT_ALL;
          goto error;

        case SMTP_PROXY_UNCONNECTED_REJECT_ALL:
          if (!smtp_fetch_request(self))
            goto error;

          switch (smtp_process_request(self))
            {
            case SMTP_REQ_ACCEPT:
              break;

            case SMTP_REQ_NOOP:
              continue;

            default:
              goto error;
            }

          if (strcasecmp(self->request->str, "QUIT") != 0)
            {
              g_string_assign(self->error_code, "503");
              g_string_assign(self->error_info, "Server not available");
            }
          else
            {
              g_string_assign(self->error_code, "221");
              g_string_assign(self->error_info, "Bye");
              self->smtp_state = SMTP_STATE_QUIT;
            }
          goto error;

        case SMTP_PROXY_TRANSFER:
          success = smtp_process_transfer(self);
          z_object_unref(&self->transfer->super);
          self->transfer = NULL;
          self->data_transfer = FALSE;
          accepted = FALSE;
          if (success)
            {
              if (!smtp_fetch_response(self))
                {
                  z_proxy_log(self, SMTP_ERROR, 3, "Error fetching acknowledgement response from server;");
                  success = FALSE;
                }
              else if (!smtp_response_accepted(smtp_process_response(self)))
                {
                  z_proxy_log(self, SMTP_ERROR, 3, "Error processing acknowledgement response from server;");
                  success = FALSE;
                }
              else if (!smtp_copy_response(self))
                {
                  z_proxy_log(self, SMTP_ERROR, 3, "Error sending acknowledgement to client, the message might be delivered multiple times;");
                  success = FALSE;
                }
              else if (self->response->str[0] == '2')
                {
                  accepted = TRUE;
                }

              if (!accepted && success)
                {
                  z_proxy_log(self, SMTP_RESPONSE, 4, "Server rejected our message; response='%s', response_param='%s'", self->response->str, self->response_param->str);
                }
              else if (!success)
                {
                  g_string_assign(self->error_code, "421");
                  g_string_assign(self->error_info, "Service not available, closing transmission channel.");
                  self->error_abort = TRUE;
                }
            }

	  /*LOG
	    This message reports the accounting information of the mail transfer.
	   */
          if (success)
            z_proxy_log(self, SMTP_ACCOUNTING, 4,
                        "Accounting; sender='%s', recipient='%s', response='%s', response_param='%s', result='%s'",
                        self->sender->str, self->recipients->str, self->response->str, self->response_param->str, accepted ? "success" : "failure");
          else
            z_proxy_log(self, SMTP_ACCOUNTING, 4,
                        "Accounting; sender='%s', recipient='%s', response='%s', response_param='%s', result='%s'",
                        self->sender->str, self->recipients->str, self->error_code->str, self->error_info->len ? self->error_info->str : "Invalid command", accepted ? "success" : "failure");

          smtp_reset_state(self);
          self->proxy_state = SMTP_PROXY_REQUEST;
          if (!success)
            goto error;
          break;

        case SMTP_PROXY_REQUEST:
          if (self->smtp_state != SMTP_STATE_AUTH)
            {
              if (!smtp_fetch_request(self))
                goto error;

              switch (smtp_process_request(self))
                {
                case SMTP_REQ_ACCEPT:
                  break;

                case SMTP_REQ_NOOP:
                  continue;

                default:
                  goto error;
                }

              if (self->data_transfer)
                {
                  self->transfer = smtp_transfer_new(self);
                  if (!z_transfer2_start(self->transfer))
                    {
                      z_object_unref(&self->transfer->super);
                      self->transfer = NULL;
                      self->data_transfer = FALSE;
                      g_string_assign(self->error_code, "421");
                      g_string_assign(self->error_info, "Service not available, closing transmission channel.");
                      need_quit = TRUE;
                      goto error;
                    }
                }
              if ((self->data_transfer && !smtp_transfer_is_data_delayed(self->transfer)) ||
                  !self->data_transfer)
                {
                  if (!smtp_copy_request(self))
                    {
                      g_string_assign(self->error_code, "421");
                      g_string_assign(self->error_info, "Service not available, closing transmission channel.");
                      self->error_abort = TRUE;
                      goto error;
                    }
                }
              if (self->data_transfer && smtp_transfer_is_data_delayed(self->transfer))
                self->proxy_state = SMTP_PROXY_TRANSFER;
              else
                self->proxy_state = SMTP_PROXY_RESPONSE;
            }
          else
            {
              if (!smtp_fetch_auth_request(self) ||
                  !smtp_copy_auth_request(self))
                goto error;
              self->proxy_state = SMTP_PROXY_RESPONSE;
            }
          break;

        case SMTP_PROXY_RESPONSE:
          if (!self->data_transfer)
            self->proxy_state = SMTP_PROXY_REQUEST;
          else
            self->proxy_state = SMTP_PROXY_TRANSFER;
          self->data_transfer = FALSE;
          if (!smtp_fetch_response(self))
            {
              g_string_assign(self->error_code, "421");
              g_string_assign(self->error_info, "Service not available, closing transmission channel.");
              self->error_abort = TRUE;
              goto error;
            }

          switch (smtp_process_response(self))
            {
            case SMTP_RSP_ACCEPT:
              if (!smtp_copy_response(self))
                goto error;
              break;
            case SMTP_RSP_NOOP:
              /* smtp_process_response() already did everything, so we
                 don't have to copy the response to the client */
              break;
            default:
              /* SMTP_RSP_REJECT or SMTP_RSP_ABORT: we go to the error branch,
               * since the response has been dropped */
              goto error;
            }

          break;

        case SMTP_PROXY_DATA:
          break;

        case SMTP_PROXY_PLUG:
          smtp_plug_do_transfer(self);
          self->smtp_state = SMTP_STATE_QUIT;
          break;
        }
      continue;

     error:
      if (self->proxy_state != SMTP_PROXY_UNCONNECTED_REJECT_ALL && !need_quit)
         self->proxy_state = SMTP_PROXY_REQUEST;
      if (need_quit)
         self->proxy_state = SMTP_PROXY_UNCONNECTED_REJECT_ALL;

      if (self->transfer)
        {
          z_transfer2_cancel(self->transfer);
          z_object_unref(&self->transfer->super);
          self->transfer = NULL;
          self->data_transfer = FALSE;
        }

      smtp_set_response(self, self->error_code->str, self->error_info->len ? self->error_info->str : "Invalid command");
      if (!smtp_copy_response(self) || self->error_abort)
        break;
      else
        continue;
    }
  /*LOG
    This message reports that Zorp is exiting from the SMTP proxy loop and closing connections on both side.
   */
  z_proxy_log(self, SMTP_DEBUG, 6, "Exiting SMTP loop;");
  smtp_clear_response(self);
  z_proxy_return(self);
}

/**
 * smtp_proxy_new:
 * @session_id: session id string
 * @client: client stream
 * @handler: policy handler
 * @parent: parent proxy if applicable
 *
 * This function is called by the Zorp core to create a new SMTP proxy
 * instance.
 *
 * Returns: a ZProxy reference which represents the new proxy
 **/
static ZProxy *
smtp_proxy_new(ZProxyParams *params)
{
  SmtpProxy  *self;

  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(SmtpProxy), params), SmtpProxy);
  z_return((ZProxy *) self);
}

/**
 * smtp_proxy_free:
 * @s: SmtpProxy instance
 *
 * This virtual function overrides z_proxy_free() to also free SMTP specific
 * fields in @s.
 **/
static void
smtp_proxy_free(ZObject *s)
{
  SmtpProxy *self = Z_CAST(s, SmtpProxy);

  z_enter();
  z_poll_unref(self->poll);
  g_string_free(self->auth_request, TRUE);
  g_string_free(self->sanitized_recipient, TRUE);
  z_proxy_free_method(s);
  z_return();
}

ZProxyFuncs smtp_proxy_funcs =
{
  {
    Z_FUNCS_COUNT(ZProxy),
    smtp_proxy_free,
  },
  /* .config = */ smtp_config,
  /* .startup = */ NULL,
  /* .main = */ smtp_main,
  /* .shutdown = */ NULL,
  /* .destroy = */ NULL,
  /* .nonblocking_init = */ NULL,
  /* .nonblocking_deinit = */ NULL,
  /* .wakeup = */ NULL,
};

Z_CLASS_DEF(SmtpProxy, ZProxy, smtp_proxy_funcs);

static ZProxyModuleFuncs smtp_module_funcs =
  {
    /* .create_proxy = */ smtp_proxy_new,
    /* .module_py_init = */ NULL
  };

/**
 * zorp_module_init:
 *
 * Zorp module initialization function.
 **/
gint
zorp_module_init(void)
{

  z_registry_add("smtp", ZR_PROXY, &smtp_module_funcs);
  smtp_init_cmd_hash();
  return TRUE;
}
