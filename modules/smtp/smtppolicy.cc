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

#include <zorp/zorp.h>
#include <zorp/stream.h>
#include <zorp/proxy.h>
#include <zorp/policy.h>
#include <zorp/thread.h>
#include <zorp/zpython.h>
#include <zorp/log.h>

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "smtp.h"

gboolean
smtp_hash_get_type(ZPolicyObj *tuple, guint *filter_type)
{
  ZPolicyObj *tmp;

  if (!z_policy_seq_check(tuple))
    {
      if (z_policy_var_parse(tuple, "i", filter_type))
        return TRUE;
      /* not a sequence */
      return FALSE;
    }

  tmp = z_policy_seq_getitem(tuple, 0);
  if (!z_policy_var_parse(tmp, "i", filter_type))
    {
      /* policy syntax error */
      z_policy_var_unref(tmp);
      return FALSE;
    }
  z_policy_var_unref(tmp);
  return TRUE;
}

SmtpRequestTypes
smtp_policy_check_request(SmtpProxy *self)
{
  ZPolicyObj *entry;
  ZPolicyObj *res;
  ZPolicyObj *process_cmd = NULL;
  SmtpRequestTypes action;
  gchar *response = NULL, *response_param = NULL;

  z_proxy_enter(self);
  entry = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->request_policy, self->request->str));
  if (!entry)
    entry = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->request_policy, "*"));
  if (!entry)
    z_proxy_return(self, SMTP_REQ_REJECT);

  z_policy_lock(self->super.thread);
  if (!smtp_hash_get_type(entry, reinterpret_cast<guint *>(&action)))
    {
      /*LOG
	This message indicates that the policy type is invalid for the given request and Zorp
	aborts the connection. Check the 'request' attribute.
       */
      z_proxy_log(self, SMTP_POLICY, 1, "Invalid request policy type; request='%s'", self->request->str);
      z_policy_unlock(self->super.thread);
      z_proxy_return(self, SMTP_REQ_ABORT);
    }
  z_policy_unlock(self->super.thread);

  z_cp();
  switch (action)
    {
    case SMTP_REQ_REJECT:
      z_policy_lock(self->super.thread);
      if (!z_policy_var_parse_tuple(entry, "i|ss", &action, &response, &response_param))
        {
	  /*LOG
	    This message indicates that the parameter of the request policy of the given request is invalid and Zorp aborts the connection.
	    Check the 'request' attribute.
	   */
          z_proxy_log(self, SMTP_POLICY, 1, "Error in request policy; request='%s'", self->request->str);
          action = SMTP_REQ_ABORT;
        }
      else
        {
          if (response)
            g_string_assign(self->error_code, response);
          if (response_param)
            g_string_assign(self->error_info, response_param);
        }
      z_policy_unlock(self->super.thread);
      break;

    case SMTP_REQ_ACCEPT:
      break;

    case SMTP_REQ_POLICY:
      z_policy_lock(self->super.thread);
      if (!z_policy_var_parse(entry, "(iO)", &action, &process_cmd))
        {
	  /*LOG
	    This message indicates that the parameter of the request policy of the given request is invalid and Zorp aborts the connection.
	    Check the 'request' attribute.
	   */
          z_proxy_log(self, SMTP_POLICY, 1, "Error in request policy; request='%s'", self->request->str);
          action = SMTP_REQ_ABORT;
        }
      else
        {
          res = z_policy_call_object(process_cmd, z_policy_var_build("(ss)", self->request->str, self->request_param->str), self->super.session_id);
          if (res)
            {
              if (!z_policy_var_parse(res, "i", &action))
                {
		  /*LOG
		    This message indicates that the returned value of the callback for the given request policy
		    is invalid and Zorp aborts the connection. Check the callback function.
		   */
                  z_proxy_log(self, SMTP_POLICY, 1, "The verdict returned by the policy is not an int; request='%s'", self->request->str);
                  action = SMTP_REQ_ABORT;
                }
              else
                {
                  switch (action)
                    {
                    case SMTP_REQ_ACCEPT:
                    case SMTP_REQ_REJECT:
                    case SMTP_REQ_ABORT:
                      break;

                    default:
                      action = SMTP_REQ_ABORT;
                      break;
                    }
                }
            }
          else
            {
              action = SMTP_REQ_ABORT;
            }
        }
      z_policy_unlock(self->super.thread);
      break;

    case SMTP_REQ_ABORT:
    default:
      action = SMTP_REQ_ABORT;
      break;
    }
  z_proxy_return(self, action);
}

SmtpResponseTypes
smtp_policy_check_response(SmtpProxy *self)
{
  ZPolicyObj *entry, *process_rsp, *res;
  gchar *key[2];
  gchar *response, *response_param;
  SmtpResponseTypes action;

  z_proxy_enter(self);
  if (self->request->len)
    key[0] = self->request->str;
  else
    key[0] = "Null";
  key[1] = self->response->str;
  entry = static_cast<ZPolicyObj *>(z_dim_hash_table_search(self->response_policy, 2, key));
  if (!entry)
    z_proxy_return(self, SMTP_RSP_REJECT);

  z_policy_lock(self->super.thread);
  if (!smtp_hash_get_type(entry, reinterpret_cast<guint *>(&action)))
    {
      /*LOG
	This message indicates that the policy type is invalid for the given response and Zorp
	aborts the connection. Check the 'response' attribute.
       */
      z_proxy_log(self, SMTP_POLICY, 1, "Invalid response policy; request='%s', response='%s'", self->request->str, self->response->str);
      z_proxy_return(self, SMTP_RSP_ABORT);
    }
  z_policy_unlock(self->super.thread);
  switch (action)
    {
    case SMTP_RSP_REJECT:
      z_policy_lock(self->super.thread);
      if (!z_policy_var_parse_tuple(entry, "i|ss", &action, &response, &response_param))
        {
	  /*LOG
	    This message indicates that the parameter of the response policy of the given request is invalid and Zorp aborts the connection.
	    Check the 'response' attribute.
	   */
          z_proxy_log(self, SMTP_POLICY, 1, "Error in response policy; request='%s', response='%s'", self->request->str, self->response->str);
          action = SMTP_RSP_ABORT;
        }
      else
        {
          if (response)
            g_string_assign(self->error_code, response);
          if (response_param)
            g_string_assign(self->error_info, response_param);
        }
      z_policy_unlock(self->super.thread);
      break;

    case SMTP_RSP_ACCEPT:
    case SMTP_RSP_ABORT:
      break;

    case SMTP_RSP_POLICY:
      z_policy_lock(self->super.thread);
      if (!z_policy_var_parse(entry, "(iO)", &action, &process_rsp))
        {
	  /*LOG
	    This message indicates that the parameter of the response policy of the given request is invalid and Zorp aborts the connection.
	    Check the 'response' attribute.
	   */
          z_proxy_log(self, SMTP_POLICY, 1, "Error in response policy; request='%s', response='%s'", self->request->str, self->response->str);
          action = SMTP_RSP_ABORT;
        }
      else
        {
          res = z_policy_call_object(process_rsp, z_policy_var_build("(ssss)", self->request->str, self->request_param->str, self->response->str, self->response_param->str), self->super.session_id);
          if (res)
            {
              if (!z_policy_var_parse(res, "i", &action))
                {
		  /*LOG
		    This message indicates that the returned value of the callback for the given response policy
		    is invalid and Zorp aborts the connection. Check the callback function.
		   */
                  z_proxy_log(self, SMTP_POLICY, 1, "The verdict returned by the policy is not an int; request='%s', response='%s'", self->request->str, self->response->str);
                  action = SMTP_RSP_ABORT;
                }
            }
          else
            {
              action = SMTP_RSP_ABORT;
            }
        }
      z_policy_unlock(self->super.thread);
      break;

    default:
      action = SMTP_RSP_ABORT;
      break;
    }
  z_proxy_return(self, action);
}

gboolean
smtp_policy_is_extension_permitted(SmtpProxy *self, gchar *extension)
{
  ZPolicyObj *e;
  SmtpExtensionDesc *ed;
  SmtpActionTypes verdict = SMTP_EXT_DROP;
  gboolean found;

  z_proxy_enter(self);

  /* compatibility, check permit_extensions first */
  ed = static_cast<SmtpExtensionDesc *>(g_hash_table_lookup(known_extensions, extension));
  if (ed && (self->permit_extensions & ed->extension_mask))
    z_proxy_return(self, TRUE);

  e = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->extensions, extension));
  if (!e)
    e = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->extensions, "*"));

  if (!e)
    z_proxy_return(self, FALSE);

  z_policy_lock(self->super.thread);
  found = smtp_hash_get_type(e, reinterpret_cast<guint *>(&verdict));
  z_policy_unlock(self->super.thread);

  z_proxy_return(self, found && (verdict == SMTP_EXT_ACCEPT));
}

ZPolicyObj *
smtp_policy_sanitize_address(SmtpProxy *self, ZPolicyObj *args)
{
  gchar *address;
  gchar *final_end;
  GString *sanitized_address;
  ZPolicyObj *res = NULL;

  z_proxy_enter(self);
  if (!z_policy_var_parse_tuple(args, "s", &address))
    {
      z_policy_raise_exception_obj(z_policy_exc_value_error, "Invalid arguments");
      z_proxy_leave(self);
      return NULL;
    }

  sanitized_address = g_string_new("");
  if (!smtp_sanitize_address(self, sanitized_address, address, TRUE, &final_end))
    {
      z_policy_raise_exception_obj(z_policy_exc_value_error, "Invalid address");
      goto exit;
    }

  res = z_policy_var_build("s", sanitized_address->str);

 exit:
  g_string_free(sanitized_address, TRUE);
  z_proxy_leave(self);
  return res;
}
