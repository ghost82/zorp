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
Pop3ParseNoarg(Pop3Proxy *self)
{
  z_proxy_enter(self);
  if (self->command_param->len > 0)
    /*LOG
      This message indicates that the request must not have any parameter and Zorp
      is going to drop the parameter.
     */
    z_proxy_log(self, POP3_REQUEST, 4, "Dropping request parameter, no parameter allowed; req='%s', req_prm='%s'",
	self->command->str, self->command_param->str);

  g_string_assign(self->command_param, "");
  z_proxy_return(self, POP3_REQ_ACCEPT);
}

guint
Pop3ParseNum_One(Pop3Proxy *self)
{
  long int arg;
  gchar *err;

  z_proxy_enter(self);
  arg = strtol(self->command_param->str, &err, 10);
  if (err == self->command_param->str)
    {
      /*LOG
        This message indicates that the numerical parameter of the request is missing and Zorp
	aborts the connection.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "The required numerical parameter of the request is missing; req='%s' req_prm='%s'",
	  self->command->str, self->command_param->str);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  if (errno == ERANGE)
    {
      /*LOG
        This message indicates that the numerical parameter of the request is not in the given range and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "The numerical parameter of the request is not in the given range; req='%s', req_prm='%s'",
	  self->command->str, self->command_param->str);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  if (arg < 0)
    {
      /*LOG
        This message indicates that the numerical parameter of the request is a negative number which is invalid and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "The numerical parameter of the request is negative; req='%s', req_prm='%s'",
	  self->command->str, self->command_param->str);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  if (arg == 0)
    {
      /*LOG
        This message indicates that the numerical parameter of the request is zero which is invalid and Zorp
	aborts the connection.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "The numerical parameter of the request is zero; req='%s', req_prm='%s'", self->command->str, self->command_param->str);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  if (*err != 0)
    {
      /*LOG
        This message indicates that the numerical parameter of the request contains junk characters after the number but
	Zorp ignores and truncates the junk.
       */
      z_proxy_log(self, POP3_REQUEST, 4, "The numerical parameter of the request contains junk after the number; req='%s', req_prm='%s'",
                  self->command->str, self->command_param->str);
    }

  g_string_printf(self->command_param, "%ld", arg);
  z_proxy_return(self, POP3_REQ_ACCEPT);
}

guint
Pop3ParseNum_OneOptional(Pop3Proxy *self)
{
  guint ret;

  z_proxy_enter(self);
  if (strlen(self->command_param->str) == 0)
    z_proxy_return(self, POP3_REQ_ACCEPT);

  self->response_multiline = FALSE;
  ret = Pop3ParseNum_One(self);
  z_proxy_return(self, ret);
}

guint
Pop3ParseNum_Two(Pop3Proxy *self)
{
  long int arg1, arg2;
  gchar *err = NULL;
  gchar *next;
  gchar newline[self->max_reply_length];

  z_proxy_enter(self);
  arg1 = strtol(self->command_param->str, &err, 10);
  if (errno == ERANGE)
    {
      /*LOG
        This message indicates that the first numerical parameter is not in the given range and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "The first numerical parameter of the request is not in the given range; req='%s', req_prm='%s'",
	  self->command->str, self->command_param->str);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  if (arg1 < 0)
    {
      /*LOG
        This message indicates that the first numerical parameter of the request is a negative number which is invalid and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "The first numerical parameter of the request is negative; req='%s', req_prm='%s'",
	  self->command->str, self->command_param->str);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  next = err;
  err = NULL;
  if (*next == 0)
    {
      /*LOG
        This message indicates that only one numerical parameter is present but two is required and Zorp
	rejects the request.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "Only one numerical argument in request; req='%s', req_prm='%s'",
	  self->command->str, self->command_param->str);
      z_proxy_return(self, POP3_REQ_REJECT);
    }

  arg2 = strtol(next, &err, 10);
  if (errno == ERANGE)
    {
      /*LOG
        This message indicates that the second numerical parameter is not in the given range and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "The second numerical parameter of the request is not in the given range; req='%s', req_prm='%s'",
	  self->command->str, self->command_param->str);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  if (arg2 < 0)
    {
      /*LOG
        This message indicates that the second numerical parameter of the request is a negative number which is invalid and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "The second numerical parameter of the request is a negative number; req='%s', req_prm='%s'",
	  self->command->str, self->command_param->str);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  if (*err != 0)
    {
      /*LOG
        This message indicates that the numerical parameters of the request contain junk characters after the numbers but
	Zorp ignores and truncates the junk.
       */
      z_proxy_log(self, POP3_REQUEST, 4, "The numerical parameter of the request contain junk after the number; req='%s', req_prm='%s'",
	self->command->str, self->command_param->str);
    }

  g_snprintf(newline, sizeof(newline), "%ld %ld", arg1, arg2);
  g_string_assign(self->command_param, newline);
  z_proxy_return(self, POP3_REQ_ACCEPT);
}

guint
Pop3ParseRETR(Pop3Proxy *self)
{
  guint ret;

  z_proxy_enter(self);
  ret = Pop3ParseNum_One(self);
  z_proxy_return(self, ret);
}

guint
Pop3ParseUSER(Pop3Proxy *self)
{
  gchar username[self->max_username_length + 1];

  z_proxy_enter(self);
  if (self->command_param->len <= self->max_username_length)
    {
      g_strlcpy(username, self->command_param->str, self->max_username_length + 1);
      g_string_assign(self->username, username);
      z_proxy_return(self, POP3_REQ_ACCEPT);
    }

  /*LOG
    This message indicates that the username parameter of the request is too long and Zorp
    rejects the request. Check the 'max_username_length' attribute.
   */
  z_proxy_log(self, POP3_POLICY, 2, "Username is too long; max_username_length='%d', username_length='%" G_GSIZE_FORMAT "', username='%s'",
              self->max_username_length, self->command_param->len, self->command_param->str);
  z_proxy_return(self, POP3_REQ_REJECT);
}

guint
Pop3ParsePASS(Pop3Proxy *self)
{
  gchar password[self->max_password_length + 1];

  z_proxy_enter(self);
  if (self->command_param->len <= self->max_password_length)
    {
      g_strlcpy(password, self->command_param->str, self->max_password_length + 1);
      g_string_assign(self->password, password);
      z_proxy_return(self, POP3_REQ_ACCEPT);
    }

  /*LOG
    This message indicates that the password parameter of the request is too long and Zorp
    rejects the request. Check the 'max_password_length' attribute.
   */
  z_proxy_log(self, POP3_POLICY, 2, "Password is too long; max_password_length='%d', password_length='%d'",
              self->max_password_length, (gint) self->command_param->len);
  z_proxy_return(self, POP3_REQ_REJECT);
}

guint
Pop3ParseAPOP(Pop3Proxy *self)
{
  gchar username[self->max_username_length + 1];
  guint i;
  gchar *buf = self->command_param->str;

  z_proxy_enter(self);
  for (i = 0; i < self->max_username_length && buf[i] != 0 && buf[i] != ' '; i++)
    username[i] = buf[i];
  username[i] = 0;

  if (buf[i] != ' ')
    {
      /*LOG
        This message indicates that the username parameter is too long or the digest missing after the
        username and Zorp rejects the request.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "The username parameter is too long or the digest parameter is missing; req='APOP', req_prm='%s'",
                  self->command_param->str);
      z_proxy_return(self, POP3_REQ_REJECT);
    }

  g_string_assign(self->username, username);
  while (buf[i] == 32)
    i++;
  buf = &buf[i];

  for (i = 0; i < 32 && buf[i] != 0 &&
       ((buf[i] >= '0' && buf[i] <= '9') ||
        (buf[i] >= 'a' && buf[i] <= 'f') ||
        (buf[i] >= 'A' && buf[i] <= 'F')); i++)
    ;

  if (i < 32)
    {
      /*LOG
        This message indicates that the MD5 digest parameter of the request is invalid and
        Zorp rejects the request.
       */
      z_proxy_log(self, POP3_REQUEST, 3, "Error parsing the MD5 digest; req='APOP', req_prm='%s'", self->command_param->str);
      z_proxy_return(self, POP3_REQ_REJECT);
    }
  z_proxy_return(self, POP3_REQ_ACCEPT);
}

guint
Pop3AnswerParseUSER(Pop3Proxy *self)
{
  z_proxy_enter(self);
  if (strcmp(self->response->str, "+OK") == 0)
    self->pop3_state = POP3_STATE_AUTH_U;
  z_proxy_return(self, POP3_RSP_ACCEPT);
}

guint
Pop3AnswerParsePASS(Pop3Proxy *self)
{
  z_proxy_enter(self);
  if (strcmp(self->response->str, "+OK") == 0)
    self->pop3_state = POP3_STATE_TRANS;
  else
    self->pop3_state = POP3_STATE_AUTH;
  z_proxy_return(self, POP3_RSP_ACCEPT);
}

guint
Pop3AnswerParseAPOP(Pop3Proxy *self)
{
  z_proxy_enter(self);
  if (strcmp(self->response->str, "+OK") == 0)
    self->pop3_state = POP3_STATE_TRANS;
  else
    self->pop3_state = POP3_STATE_AUTH;
  z_proxy_return(self, POP3_RSP_ACCEPT);
}

guint
Pop3AnswerParseQUIT(Pop3Proxy *self)
{
  z_proxy_enter(self);
  self->pop3_state = POP3_STATE_QUIT;
  z_proxy_return(self, POP3_RSP_ACCEPT);
}

guint
Pop3ParseAUTH(Pop3Proxy *self)
{
  z_proxy_enter(self);
  self->pop3_state = POP3_STATE_AUTH_A;
  self->auth_lines = 0;
  z_proxy_return(self, POP3_RSP_ACCEPT);
}

guint
Pop3AnswerParseNum_One(Pop3Proxy *self)
{
  long int arg;
  gchar *err;
  gchar newline[self->max_reply_length];

  z_proxy_enter(self);
  if (!strcmp(self->response->str, "-ERR"))
    z_proxy_return(self, POP3_RSP_ACCEPT);

  arg = strtol(self->response_param->str, &err, 10);
  if ( err == self->response_param->str )
    {
      /*LOG
        This message indicates that the numerical parameter of the response is missing and Zorp
	aborts the connection.
       */
      z_proxy_log(self, POP3_RESPONSE, 3, "The required numerical parameter of the response is missing; req='%s', rsp_prm='%s'",
	self->command->str, self->response_param->str);
      z_proxy_return(self, POP3_RSP_ABORT);
    }

  if (errno == ERANGE)
    {
      /*LOG
        This message indicates that the numerical parameter of the response is not in the given range and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_RESPONSE, 3, "The numerical parameter of the response is not in the given range; req='%s', rsp_prm='%s'",
	self->command->str, self->response_param->str);
      z_proxy_return(self, POP3_RSP_ABORT);
    }

  if (arg < 0)
    {
      /*LOG
        This message indicates that the numerical parameter of the response is a negative number which is invalid and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_RESPONSE, 3, "The numerical parameter of the response is a negative number; req='%s', rsp_prm='%s'",
	  self->command->str, self->response_param->str);
      z_proxy_return(self, POP3_RSP_ABORT);
    }

  if (*err != 0)
    {
      /*LOG
        This message indicates that the numerical parameter of the response contains junk characters after the number but
	Zorp ignores and truncates the junk.
       */
      z_proxy_log(self, POP3_RESPONSE, 4, "The numerical parameter of the response contains junk after the number; req='%s', rsp_prm='%s'",
	  self->command->str, self->response_param->str);
    }

  g_snprintf(newline, sizeof(newline), "%ld", arg);

  g_string_assign(self->response_param, newline);

  z_proxy_leave(self);
  return POP3_RSP_ACCEPT;
}

guint
Pop3AnswerParseNum_Two(Pop3Proxy *self)
{
  long int arg1, arg2;
  gchar *err = NULL;
  gchar *next;
  gchar newline[self->max_reply_length];

  z_proxy_enter(self);
  if (!strcmp(self->response->str, "-ERR"))
    z_proxy_return(self, POP3_RSP_ACCEPT);

  arg1 = strtol(self->response_param->str, &err, 10);
  if (errno == ERANGE)
    {
      /*LOG
        This message indicates that the numerical parameter of the response is not in the given range and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_RESPONSE, 3, "The numerical parameter of the response is not in the given range; req='%s', rsp_prm='%s'",
	  self->command->str, self->response_param->str);
      z_proxy_return(self, POP3_RSP_ABORT);
    }

  if (err == self->response_param->str)
    {
      /*LOG
        This message indicates that the numerical parameter of the response is missing and Zorp
	aborts the connection.
       */
      z_proxy_log(self, POP3_RESPONSE, 3, "The required numerical parameter of the response is missing; req='%s', rsp_prm='%s'",
	  self->command->str, self->response_param->str);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  if (arg1 < 0)
    {
      /*LOG
        This message indicates that the numerical parameter of the response is a negative number which is invalid and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_RESPONSE, 3, "The numerical parameter of the response is a negative number; req='%s', rsp_prm='%s'",
	  self->command->str, self->response_param->str);
      z_proxy_return(self, POP3_RSP_ABORT);
    }

  next = err;
  err = NULL;
  arg2 = strtol(next, &err, 10);
  if (errno == ERANGE)
    {
      /*LOG
        This message indicates that the second numerical parameter of the response is not in the given range and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_RESPONSE, 3, "The second numerical parameter of the response is not in the given range; req='%s', rsp_prm='%s'",
	  self->command->str, self->response_param->str);
      z_proxy_return(self, POP3_RSP_ABORT);
    }

  if (err == next)
    {
      /*LOG
        This message indicates that the second numerical parameter of the response is missing and Zorp
	aborts the connection.
       */
      z_proxy_log(self, POP3_RESPONSE, 3, "The required second numerical parameter of the response is missing; req='%s', rsp_prm='%s'",
	  self->command->str, self->response_param->str);
      z_proxy_return(self, POP3_REQ_ABORT);
    }

  if (arg2 < 0)
    {
      /*LOG
        This message indicates that the second numerical parameter of the response is a negative number which is invalid and
	Zorp aborts the connection.
       */
      z_proxy_log(self, POP3_RESPONSE, 3, "The second numerical parameter of the response is a negative number; req='%s', rsp_prm='%s'",
	  self->command->str, self->response_param->str);
      z_proxy_return(self, POP3_RSP_ABORT);
    }

  if (*err != 0)
    {
      /*LOG
        This message indicates that the second numerical parameter of the response contains junk characters after the number but
	Zorp ignores and truncates the junk.
       */
      z_proxy_log(self, POP3_REQUEST, 4, "The second numerical parameter of the response contains junk after the number; req='%s', rsp_prm='%s'",
                  self->command->str, self->response_param->str);
    }

  g_snprintf(newline, sizeof(newline), "%ld %ld", arg1, arg2);
  g_string_assign(self->response_param, newline);
  z_proxy_return(self, POP3_RSP_ACCEPT);
}
