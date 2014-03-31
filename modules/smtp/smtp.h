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

#ifndef ZORP_MODULES_SMTP_H_INCLUDED
#define ZORP_MODULES_SMTP_H_INCLUDED

#include "smtpmsg.h"

#include <zorp/zorp.h>
#include <zorp/streamline.h>
#include <zorp/proxy.h>
#include <zorp/dimhash.h>
#include <zorp/poll.h>
#include <zorp/misc.h>
#include <zorp/plugsession.h>
#include <zorp/proxy/transfer2.h>

/* smtp protocol states */
typedef enum
{
  SMTP_STATE_INITIAL    = 1 << 0,
  SMTP_STATE_EHLO       = 1 << 1,
  SMTP_STATE_AUTH       = 1 << 2,
  SMTP_STATE_MAIL_FROM  = 1 << 3,
  SMTP_STATE_RCPT_TO    = 1 << 4,
  SMTP_STATE_DATA       = 1 << 5,
  SMTP_STATE_QUIT       = 1 << 6
}SmtpStateTypes;

inline SmtpStateTypes operator|(SmtpStateTypes lhs, SmtpStateTypes rhs)
{
  return SmtpStateTypes(static_cast<int>(lhs) | static_cast<int>(rhs));
}

/* smtp proxy states */
typedef enum
{
  SMTP_PROXY_REQUEST                 = 1,
  SMTP_PROXY_RESPONSE,
  SMTP_PROXY_DATA,
  SMTP_PROXY_UNCONNECTED_GREET,
  SMTP_PROXY_UNCONNECTED_REJECT_ALL,
  SMTP_PROXY_TRANSFER,
  SMTP_PROXY_PLUG
}SmtpProxyStateTypes;

typedef enum
{
  SMTP_TRANSFER_SUSPEND_DATA = 100,
  SMTP_TRANSFER_SUSPEND_NOOP
}SmtpTransferTypes;

/* smtp extensions */
typedef enum
{
  SMTP_EM_PIPELINING = 1 << 0,
  SMTP_EM_SIZE       = 1 << 1,
  SMTP_EM_ETRN       = 1 << 2,
  SMTP_EM_8BITMIME   = 1 << 3,
  SMTP_EM_AUTH       = 1 << 4,
  SMTP_EM_STARTTLS   = 1 << 5
}SmtpExtensionTypes;

typedef enum
{
  SMTP_EXT_ACCEPT = 1,
  SMTP_EXT_DROP   = 5
}SmtpActionTypes;

inline SmtpActionTypes& operator|=(SmtpActionTypes &lhs, int rhs)
{
  lhs = static_cast<SmtpActionTypes>(lhs | rhs);
  return lhs;
}

inline SmtpActionTypes& operator&=(SmtpActionTypes &lhs, int rhs)
{
  lhs = static_cast<SmtpActionTypes>(lhs & rhs);
  return lhs;
}

typedef enum
{
  SMTP_REQ_ACCEPT = 1,
  SMTP_REQ_REJECT = 3,
  SMTP_REQ_ABORT  = 4,
  SMTP_REQ_POLICY = 6,
  SMTP_REQ_NOOP   = 101
}SmtpRequestTypes;

typedef enum
{
  SMTP_RSP_ACCEPT = 1,
  SMTP_RSP_REJECT = 3,
  SMTP_RSP_ABORT  = 4,
  SMTP_RSP_POLICY = 6,
  SMTP_RSP_NOOP   = 101,
}SmtpResponseTypes;

#define SMTP_VIOLATION  "smtp.violation"
#define SMTP_REQUEST    "smtp.request"
#define SMTP_RESPONSE   "smtp.response"
#define SMTP_POLICY     "smtp.policy"
#define SMTP_DEBUG      "smtp.debug"
#define SMTP_ERROR      "smtp.error"
#define SMTP_INFO       "smtp.info"
#define SMTP_ACCOUNTING "smtp.accounting"

typedef struct _SmtpProxy SmtpProxy;
typedef struct _SmtpTransfer SmtpTransfer;

typedef SmtpRequestTypes (*SmtpRequestFunction)(struct _SmtpProxy *);
typedef SmtpResponseTypes (*SmtpResponseFunction)(struct _SmtpProxy *);

typedef struct _SmtpCommandDesc
{
  const gchar *name;
  SmtpRequestFunction command_parse;
  SmtpResponseFunction response_parse;
  SmtpRequestFunction action_do;
  SmtpStateTypes smtp_state;
} SmtpCommandDesc;

typedef struct _SmtpExtensionDesc
{
  const gchar *name;
  SmtpExtensionTypes extension_mask;
} SmtpExtensionDesc;

struct _SmtpProxy
{
  ZProxy super;

  /* general I/O timeout */
  glong timeout;
  glong interval_transfer_noop;

  /* specifies which command is allowed, SMTP_STATE_* */
  SmtpStateTypes smtp_state;

  /* whether we should process requests/responses or data SMTP_PROXY_* */
  SmtpProxyStateTypes proxy_state;

  /* permitted SMTP extension */
  GHashTable *extensions;
  /* compatibility: permitted extension set via bitmask */
  SmtpActionTypes permit_extensions;
  /* negotiated SMTP extension set */
  SmtpActionTypes active_extensions;

  /* policy exported variables */
  GHashTable *request_policy;
  ZDimHashTable *response_policy;

  /* I/O buffer size for data transfer */
  gsize buffer_size;

  /* whether to permit commands not explicitly allowed */
  gboolean permit_unknown_command;
  gboolean permit_long_responses;

  /* whether to allow MAIL From and RCPT To addresses to appear without surrounding <>-s */
  gboolean permit_omission_of_angle_brackets;

  /* maximum line lengths */
  guint max_request_length;
  guint max_auth_request_length;
  guint max_response_length;
  guint max_line_length;
  gboolean require_crlf;
  gint unconnected_response_code;

  /* stores whether or not processing a STARTTLS request is allowed */
  gboolean start_tls_ok[EP_MAX];

  /* whether or not to fall back to a plugsession if a STARTTLS request is accepted */
  gboolean tls_passthrough;
  ZPlugSessionData start_tls_fallback_data;

  /* error information to be returned to the client */

  /* reply code */
  GString *error_code;
  /* whether to abort the connection */
  gboolean error_abort;
  /* string info appended to the error code */
  GString *error_info;
  GString *append_domain;

  /* proxy state */

  /* current request descriptor */
  SmtpCommandDesc *request_cmd;

  /* current request as string */
  GString *request;
  /* current request parameter */
  GString *request_param;

  /* sender/recipient logging */
  GString *sender;
  /* last, canonicalized recipient */
  GString *sanitized_recipient;
  GString *recipients;

  GString *auth_request;

  /* Add receive line */
  gboolean add_received_header;

  /* Received string as parameter or HELO/EHLO */
  GString *helo_string;

  /* Protocol in use (SMTP/ESMTP) */
  GString *protocol;

  /* current response as string */
  GString *response;
  /* current response parameter */
  GString *response_param;
  /* when an extended reply is received additional lines are stored here */
  GList *response_lines;

  ZTransfer2 *transfer;
  /* set to TRUE when a data transfer begins right after response processing */
  gboolean data_transfer;

  ZPoll *poll;

};

extern ZClass SmtpProxy__class;
extern SmtpMessage smtp_known_messages[SMTP_N_MSGS];

gboolean smtp_sanitize_address(SmtpProxy *self, GString *result, gchar *path, gboolean empty_path_ok, gchar **final_end);

gboolean smtp_sanitize_address(SmtpProxy *self, GString *result, gchar *path, gboolean empty_path_ok, gchar **final_end);

gboolean smtp_generate_received(SmtpProxy *self, GString **dst_string);

void smtp_reset_state(SmtpProxy *self);

SmtpRequestTypes smtp_policy_check_request(SmtpProxy *self);
SmtpResponseTypes smtp_policy_check_response(SmtpProxy *self);
gboolean smtp_policy_is_extension_permitted(SmtpProxy *self, gchar *extension);

ZTransfer2 *smtp_transfer_new(SmtpProxy *self);

static inline gboolean
smtp_transfer_is_data_delayed(ZTransfer2 *self)
{
  return !!self->stacked;
}

extern GHashTable *known_commands;
extern GHashTable *known_extensions;

void smtp_init_cmd_hash(void);

gboolean smtp_copy_response(SmtpProxy *self);
void smtp_clear_response(SmtpProxy *self);

ZPolicyObj *smtp_policy_sanitize_address(SmtpProxy *self, ZPolicyObj *args);

#define SMTP_SET_RESPONSE(smtp_msg_type) \
G_STMT_START{ \
  smtp_clear_response(self);\
  g_string_assign(self->response, smtp_known_messages[smtp_msg_type].code);\
  g_string_assign(self->response_param, smtp_known_messages[smtp_msg_type].long_desc);\
}G_STMT_END

#endif
