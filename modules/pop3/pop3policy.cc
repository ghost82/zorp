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

#include "pop3policy.h"

#define POP3_POLICY "pop3.policy"
#define POP3_DEBUG  "pop3.debug"
#define POP3_ERROR  "pop3.error"

guint
pop3_policy_command_hash_search(Pop3Proxy *self, gchar *command)
{
  void *tmp = g_hash_table_lookup(self->commands_policy, command);
  return tmp != NULL;
}

gboolean
pop3_hash_get_type(ZPolicyObj *tuple, guint *filter_type)
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

guint
pop3_policy_command_hash_do(Pop3Proxy *self)
{
  guint rc;
  ZPolicyObj *res;
  ZPolicyObj *tmp = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->commands_policy, self->command->str));
  ZPolicyObj *command_where = NULL;
  ZPolicyObj *answer_where = NULL;
  unsigned int command_do;

  z_proxy_enter(self);
  if (!tmp)
    {
      z_proxy_log(self, POP3_DEBUG, 6, "Policy does not contain this request, trying the default; request='%s'",
                  self->command->str);
      tmp = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->commands_policy, "*"));
    }

  if (!tmp)
    {
      /*LOG
        This message indicates that the policy does not contain any setting for the given
	request and Zorp rejects the request. Check the 'request' attribute.
       */
      z_proxy_log(self, POP3_DEBUG, 5, "Policy does not contain this request, using hard-coded default; request='%s'",
                  self->command->str);
      z_proxy_return(self, POP3_REQ_REJECT);
    }

  z_policy_lock(self->super.thread);
  if (!pop3_hash_get_type(tmp, &command_do))
    {
      /*LOG
        This message indicates that the policy type is invalid for the given request and Zorp
	aborts the connection. Check the 'request' attribute.
       */
      z_proxy_log(self, POP3_POLICY, 1, "Policy type is invalid; req='%s'", self->command->str);
      z_policy_unlock(self->super.thread);
      z_proxy_return(self, POP3_REQ_ABORT);
    }
  z_policy_unlock(self->super.thread);

  switch(command_do)
    {
    case POP3_REQ_ACCEPT_MLINE:
      self->response_multiline = TRUE;  /* No Break */
    case POP3_REQ_REJECT:
    case POP3_REQ_ACCEPT:
      rc = command_do;
      break;

    case POP3_REQ_POLICY:
      z_policy_lock(self->super.thread);
      if (!z_policy_var_parse(tmp, "(iOO)", &command_do, &command_where, &answer_where) &&
          !z_policy_var_parse(tmp, "(iO)", &command_do, &command_where))
        {
          /*LOG
            This message indicates that the policy for the given request is invalid
            and Zorp aborts the connection. Check the 'request' attribute. It is likely that the
            parameter for the POP3_REQ_POLICY is invalid.
           */
          z_proxy_log(self, POP3_POLICY, 1, "Cannot parse policy line; req='%s'",self->command->str);
          rc = POP3_REQ_ABORT;
        }
      else
        {
          res = z_policy_call_object(command_where, z_policy_var_build("(s)", self->command), self->super.session_id);
          if (res == NULL)
            {
              /*LOG
                This message indicates that the callback for the given request policy is invalid
                and Zorp aborts the connection. Check the 'request' attribute. It is likely that the
                parameter for the POP3_REQ_POLICY is invalid.
               */
              z_proxy_log(self, POP3_POLICY, 1, "Error in policy call; req='%s'", self->command->str);
              rc = POP3_REQ_ABORT;
            }
          else
            {
              if (!z_policy_var_parse(res, "i", &rc))
                {
                  /*LOG
                    This message indicates that the returned value of the callback for the given request policy
                    is invalid and Zorp aborts the connection. Check the callback function.
                   */
                  z_proxy_log(self, POP3_POLICY, 1, "Cannot parse the return code; req='%s'", self->command->str);
                  rc = POP3_REQ_ABORT;
                }
              else
                {
                  switch(rc)
                    {
                    case POP3_REQ_ACCEPT_MLINE:
                      self->response_multiline = TRUE; /* No Break */

                    case POP3_REQ_ACCEPT:
                      rc = POP3_REQ_ACCEPT;
                      break;

                    case ZV_UNSPEC:
                    case ZV_DROP:
                    case POP3_REQ_REJECT:
                      rc = POP3_REQ_REJECT;
                      break;

                    case POP3_REQ_ABORT:
                    default:
                      rc = POP3_REQ_ABORT;
                      break;
                    }
                }
            }
        }
      z_policy_unlock(self->super.thread);
      break;

    case POP3_REQ_ABORT:
    default:
      rc = POP3_REQ_ABORT;
      break;
    }
  z_proxy_return(self, rc);
}

guint
pop3_policy_response_hash_do(Pop3Proxy *self)
{
  guint rc;
  ZPolicyObj *res;
  ZPolicyObj *tmp;
  ZPolicyObj *command_where = NULL;
  ZPolicyObj *answer_where = NULL;
  unsigned int command_do;

  z_proxy_enter(self);
  if (self->command->len)
    tmp = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->commands_policy, self->command->str));
  else
    tmp = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->commands_policy, "GREETING"));

  if (!tmp)
    {
      z_proxy_log(self, POP3_DEBUG, 6, "Policy does not contain this request, trying the default; request='%s'", self->command->str);
      tmp = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->commands_policy, "*"));
    }
  if (!tmp)
    {
      /*LOG
	This message indicates that the policy does not contain any setting for the given
	response and Zorp rejects the response. Check the 'request' attribute.
       */
      z_proxy_log(self, POP3_DEBUG, 5, "Policy does not contain this request, using hard-coded default; request='%s'", self->command->str);
      z_proxy_return(self, POP3_RSP_REJECT);
    }
  z_policy_lock(self->super.thread);
  if (!pop3_hash_get_type(tmp, &command_do))
    {
      /*LOG
        This message indicates that the policy type is invalid for the given response and Zorp
	aborts the connection. Check the 'request' attribute.
       */
      z_proxy_log(self, POP3_POLICY, 1, "Policy type is invalid; req='%s'", self->command->str);
      z_policy_unlock(self->super.thread);
      z_proxy_return(self, POP3_RSP_ABORT);
    }
  z_policy_unlock(self->super.thread);
  switch(command_do)
    {
    case POP3_REQ_ACCEPT_MLINE:
    case POP3_REQ_ACCEPT:
      rc = POP3_RSP_ACCEPT;
      break;

    case POP3_REQ_POLICY:
      z_policy_lock(self->super.thread);
      if (!z_policy_var_parse(tmp, "(iOO)", &command_do, &command_where, &answer_where) &&
          !z_policy_var_parse(tmp, "(iO)", &command_do, &command_where))
        {
	  /*LOG
	    This message indicates that the policy for the given request/response is invalid
	    and Zorp aborts the connection. Check the 'request' attribute. It is likely that the
	    parameter for the POP3_REQ_POLICY is invalid.
	   */
          z_proxy_log(self, POP3_POLICY, 1, "Cannot parse policy line; req='%s'", self->command->str);
          rc = POP3_RSP_ABORT;
        }
      else
        {
          if (answer_where)
            {
              res = z_policy_call_object(answer_where, z_policy_var_build("(s)", self->response_param), self->super.session_id);
              if (res == NULL)
                {
	          /*LOG
		    This message indicates that the callback for the given request policy is invalid
		    and Zorp aborts the connection. Check the 'request' attribute. It is likely that the
		    parameter for the POP3_REQ_POLICY is invalid.
		  */
                  z_proxy_log(self, POP3_POLICY, 1, "Error in policy call; req='%s'", self->command->str);
                  rc = POP3_RSP_ABORT;
                }
              else
                {
                  if (!z_policy_var_parse(res, "i", &rc))
                    {
		      /*LOG
			This message indicates that the returned value of the callback for the given response policy
			is invalid and Zorp aborts the connection. Check the callback function.
		      */
                      z_proxy_log(self, POP3_POLICY, 1, "Cannot parse return code; req='%s'", self->command->str);
                      rc = POP3_RSP_ABORT;
                    }
                  else
                    {
                      switch(rc)
                        {
                        case POP3_RSP_ACCEPT:
                          break;

                        case ZV_UNSPEC:
                        case POP3_RSP_REJECT:
                          rc = POP3_RSP_REJECT;
                          break;

                        case POP3_RSP_ABORT:
                        default:
                          rc = POP3_RSP_ABORT;
                          break;
                        }
                    }
                }
            }
          else
            {
              rc = POP3_RSP_ACCEPT;
            }
        }
      z_policy_unlock(self->super.thread);
      break;

    case POP3_REQ_REJECT:
    case POP3_REQ_ABORT:
    default:
      rc = POP3_RSP_ABORT;
      break;
    }
  z_proxy_return(self, rc);
}

gboolean
pop3_policy_stack_hash_do(Pop3Proxy *self, ZStackedProxy **stacked)
{
  guint rc;
  ZPolicyObj *res = NULL;
  ZPolicyObj *tmp = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->command_stack, self->command->str));
  ZPolicyObj *command_where = NULL;
  ZPolicyObj *stack_proxy = NULL;
  unsigned int command_do;
  gboolean success = TRUE;

  z_proxy_enter(self);
  if (!tmp)
    tmp = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->command_stack, "*"));

  if (!tmp)
    z_proxy_return(self, TRUE);

  z_policy_lock(self->super.thread);
  if (!pop3_hash_get_type(tmp, &command_do))
    {
      /*LOG
        This message indicates that the stack policy type is invalid for the given response, so nothing will
	be stacked. Check the 'response_stack' attribute.
       */
      z_proxy_log(self, POP3_POLICY, 1, "Stack policy type is invalid; req='%s'", self->command->str);
      z_policy_unlock(self->super.thread);
      z_proxy_return(self, FALSE);
    }

  switch(command_do)
    {
    case POP3_STK_NONE:
      rc = command_do;
      break;

    case POP3_STK_DATA:
    case POP3_STK_MIME:
      if (!z_policy_var_parse(tmp, "(iO)", &rc, &stack_proxy))
        {
	  /*LOG
	    This message indicates that the stack policy for the given response is invalid
	    and Zorp stacks nothing. Check the 'response_stack' attribute. It is likely that the
	    parameter for the POP3_STK_MIME or POP3_STK_DATA is invalid.
	   */
          z_proxy_log(self, POP3_POLICY, 1, "Cannot parse stack policy line; req='%s'", self->command->str);
          success = FALSE;
        }
      break;

    case POP3_STK_POLICY:
      if (!z_policy_var_parse(tmp, "(iO)", &rc, &command_where))
        {
	  /*LOG
	    This message indicates that the stack policy for the given response is invalid
	    and Zorp stacks nothing. Check the 'response_stack' attribute. It is likely that the
	    parameter for the POP3_STK_POLICY is invalid.
	   */
          z_proxy_log(self, POP3_POLICY, 1, "Cannot parse stack policy line; req='%s'", self->command->str);
          success = FALSE;
        }
      else
        {
          res = z_policy_call_object(command_where, z_policy_var_build("(s)", self->command->str), self->super.session_id);
          if (res == NULL)
            {
	      /*LOG
		This message indicates that the callback for the given request policy is invalid
		and Zorp stacks nothing. Check the 'request' attribute. It is likely that the
		parameter for the POP3_STK_POLICY is invalid.
	       */
              z_proxy_log(self, POP3_POLICY, 1, "Error in policy call; req='%s'", self->command->str);
              success = FALSE;
            }
          else
            {
              if (!z_policy_var_parse(res, "i", &rc) &&
                  !z_policy_var_parse(res, "(iO)", &rc, &stack_proxy))
                {
		  /*LOG
		    This message indicates that the returned value of the callback for the given response policy
		    is invalid and Zorp stacks nothing. Check the callback function.
		   */
                  z_proxy_log(self, POP3_POLICY, 1, "Cannot parse return code; req='%s'", self->command->str);
                  success = FALSE;
                }
              z_policy_var_unref(res);
            }
        }
      break;
    }

  if (success && rc != POP3_STK_NONE && stack_proxy)
    success = z_proxy_stack_object(&self->super, stack_proxy, stacked, NULL);

  z_policy_unlock(self->super.thread);
  z_proxy_return(self, success);
}
