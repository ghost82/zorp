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

#ifndef ZORP_MODULES_POP3_H_INCLUDED
#define ZORP_MODULES_POP3_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/streamline.h>
#include <zorp/proxy.h>
#include <zorp/proxystack.h>
#include <zorp/dimhash.h>
#include <zorp/poll.h>
#include <zorp/log.h>

#define POP3_DEBUG     "pop3.debug"
#define POP3_REQUEST   "pop3.request"
#define POP3_RESPONSE     "pop3.response"
#define POP3_ERROR     "pop3.error"
#define POP3_VIOLATION "pop3.violation"
#define POP3_POLICY    "pop3.policy"

#define POP3_STATE_LISTEN         0
#define POP3_STATE_AUTH           1
#define POP3_STATE_AUTH_U         2
#define POP3_STATE_AUTH_A         4
#define POP3_STATE_AUTH_A_CANCEL  8
#define POP3_STATE_TRANS         16
#define POP3_STATE_QUIT          32

#define POP3_SERVER                0
#define POP3_CLIENT                1
#define POP3_SERVER_MULTILINE      2
#define POP3_SERVER_MULTILINE_DOT  3
#define POP3_SERVER_MULTILINE_DROP 4

#define POP3_REQ_ACCEPT         1
#define POP3_REQ_REJECT         3
#define POP3_REQ_ABORT          4
#define POP3_REQ_POLICY         6
#define POP3_REQ_ACCEPT_MLINE 100

#define POP3_RSP_ACCEPT 1
#define POP3_RSP_REJECT 3
#define POP3_RSP_ABORT  4

#define POP3_STK_NONE   1
#define POP3_STK_DATA   2
#define POP3_STK_MIME   3
#define POP3_STK_POLICY 6

struct _Pop3Proxy;
struct _Pop3InternalCommands;

typedef guint (*Pop3CmdFunction)(struct _Pop3Proxy *);

typedef struct _Pop3InternalCommands
{
  const gchar *name;
  Pop3CmdFunction command_parse;
  gboolean multi_line_response;
  Pop3CmdFunction response_parse;
  Pop3CmdFunction response_multiline_parse;
  guint pop3_state;
} Pop3InternalCommands;

typedef struct _Pop3Proxy
{
  ZProxy super;

  gint timeout;                    /* Timeout value in milisec */

  gboolean policy_enable_longline; /* With this switch you may disable long line */

  guint max_username_length;       /* Max acceptable username length */
  guint max_password_length;       /* Max acceptable password length */

  GHashTable *commands_policy;     /* Command normative hash */

  GHashTable *command_stack;       /* What to stack for this command */

  guint max_request_length;        /* Max length of a client request */
  guint max_reply_length;          /* Max length of a server response */

  gboolean permit_unknown_command; /* Permit commands not known to proxy */

  guint buffer_length;             /* Length of read buffer */

  guint max_authline_count;        /* maximum number of auth lines */

  gboolean reject_by_mail;         /* If stacked proxy reject, reject it with error or a speical formatted mail */

  /* State of pop3 session */
  gint pop3_state;

  /* State of Pop3 Proxy */
  gint state;

  GString *username;
  GString *password;

  GString *command;
  GString *command_param;

  GString *response;
  GString *response_param;

  gboolean response_multiline;

  gchar *request_line;
  gchar *reply_line;

  gsize request_length;
  gsize reply_length;

  GHashTable *pop3_commands;
  Pop3InternalCommands *command_desc;

  GString *timestamp;

  ZStackedProxy *stacked;

  ZPoll *poll;

  /* This variable holds the number of arrived auth lines */
  guint auth_lines;

  GString *from;
  GString *to;
  GString *subject;

} Pop3Proxy;

extern ZClass Pop3Proxy__class;

/* pop3.c */
void pop3_response_reject(Pop3Proxy *self, gchar *error_msg);
void pop3_response_write(Pop3Proxy *self);
GIOStatus pop3_write_client(Pop3Proxy *self, const char *msg);

void pop3_error_msg(Pop3Proxy *self, gchar *additional_info);

/* pop3auth.c */
guint pop3_auth_parse(Pop3Proxy *self, guint side);

#endif
