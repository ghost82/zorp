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

#include "telnet.h"
#include "telnetsuboption.h"
#include "telnetpolicy.h"
#include "telnetoption.h"
#include "telnetlineedit.h"
#include "telnettls.h"
#include <zorp/zorp.h>

static ZVerdict
process_suboption(TelnetProxy *self, ZEndpoint ep, ZPktBuf *suboption)
{
  ZVerdict res;
  TelnetSuboptionFunction check_func;

  z_proxy_enter(self);

  z_proxy_log(self, TELNET_DEBUG, 6, "Processing suboption; side='%s', length='%" G_GSIZE_FORMAT "'",
              EP_STR(ep), z_pktbuf_length(suboption));

  guint8 option;
  if (!z_pktbuf_get_u8(suboption, &option))
    {
      z_proxy_log(self, TELNET_VIOLATION, 1, "Suboption does not contain a command;");
      z_proxy_return(self, ZV_DROP);
    }

  z_proxy_log(self, TELNET_DEBUG, 6, "Suboption contains an option number; option='%hhu'", option);

  /* check if allowed in this session */
  if (!telnet_option_do(self, ep, option) && !telnet_option_will(self, ep, option))
    {
      z_proxy_log(self, TELNET_VIOLATION, 3, "Option not allowed in the session; option='%d'", option);
      z_proxy_return(self, ZV_DROP);
    }

  /* check if valid */
  if ((check_func = self->telnet_suboptions[option]) == NULL)
    {
      /* option has no suboption check function */
      check_func = telnet_subopt_unknown;
    }

  /* call check function, and check function calls policy */
  res = check_func(self, ep, option, suboption);

  if (res == ZV_ACCEPT)
    {
      if (telnet_state_is_connected(self))
        {
          /* forward if accepted */
          if (telnet_send_suboption(self, EP_OTHER(ep), suboption) != G_IO_STATUS_NORMAL)
            res = ZV_ABORT;
        }
    }

  z_proxy_return(self, res);
}

static gboolean
process_suboption_client_cb(ZPktBuf *suboption, gpointer user_data)
{
  TelnetProxy *self = Z_CAST(user_data, TelnetProxy);

  return (process_suboption(self, EP_CLIENT, suboption) != ZV_ABORT);
}

static gboolean
process_suboption_server_cb(ZPktBuf *suboption, gpointer user_data)
{
  TelnetProxy *self = Z_CAST(user_data, TelnetProxy);

  return (process_suboption(self, EP_SERVER, suboption) != ZV_ABORT);
}

static ZVerdict
process_opneg_ok(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option)
{
  ZVerdict res = ZV_ACCEPT;

  z_proxy_enter(self);

  /* update opneg state */
  telnet_option_command_received(self, ep, command, option);

  /* send command to peer */
  if (telnet_send_opneg(self, EP_OTHER(ep), command, option) != G_IO_STATUS_NORMAL)
    res = ZV_ABORT;

  z_proxy_return(self, res);
}

static ZVerdict
process_opneg_reject(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option)
{
  ZVerdict res = ZV_REJECT;
  guint8 reject = 0;

  z_proxy_enter(self);

  switch (command)
    {
    case TELNET_CMD_WILL:
    case TELNET_CMD_WONT:
      telnet_option_command_received(self, ep, TELNET_CMD_WONT, option);
      reject = TELNET_CMD_DONT;
      break;
    case TELNET_CMD_DO:
    case TELNET_CMD_DONT:
      telnet_option_command_received(self, ep, TELNET_CMD_DONT, option);
      reject = TELNET_CMD_WONT;
      break;
    }

  if (telnet_send_opneg(self, ep, reject, option) != G_IO_STATUS_NORMAL)
    res = ZV_ABORT;

  z_proxy_return(self, res);
}

static gchar telnet_nt_accepted_options[] =
  {
    TELNET_OPTION_SUPPRESS_GO_AHEAD,
    TELNET_OPTION_NAWS,
    TELNET_OPTION_TERMINAL_SPEED,
    TELNET_OPTION_TERMINAL_TYPE,
    TELNET_OPTION_X_DISPLAY_LOCATION,
    0,
  };

static gboolean
option_is_whitelisted(guint8 option)
{
  return strchr(telnet_nt_accepted_options, option) != NULL;
}

static gboolean
opneg_is_enable(guint8 command)
{
  return (command == TELNET_CMD_DO || command == TELNET_CMD_WILL);
}

static guint8
opneg_accept_response(guint8 request)
{
  if (request == TELNET_CMD_DO)
    return TELNET_CMD_WILL;
  else
    return TELNET_CMD_DO;
}

static guint8
opneg_deny_response(guint8 request)
{
  if (request == TELNET_CMD_DO || request == TELNET_CMD_DONT)
    return TELNET_CMD_WONT;
  else
    return TELNET_CMD_DONT;
}

static ZVerdict
process_opneg_non_transparent(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option)
{
  ZVerdict res = ZV_ACCEPT;

  z_proxy_enter(self);

  /* check if the opneg sequence is a reply */
  gboolean is_reply;
  if (command == TELNET_CMD_WILL || command == TELNET_CMD_WONT)
    {
      is_reply = self->do_dont_requested[option][ep] > 0;
      if (is_reply)
        self->do_dont_requested[option][ep]--;
    }
  else
    {
      is_reply = self->will_wont_requested[option][ep] > 0;
      if (is_reply)
        self->will_wont_requested[option][ep]--;
    }

  /* update opneg state */
  telnet_option_command_received(self, ep, command, option);

  if (!is_reply)
    {
      guint8 response;

      if (opneg_is_enable(command))
        {
          /* client wants to enable an option */
          if (option_is_whitelisted(option))
            {
              /* accept option */
              response = opneg_accept_response(command);
            }
          else
            {
              /* deny */
              response = opneg_deny_response(command);
            }
        }
      else
        response = opneg_deny_response(command);

      if (telnet_send_opneg(self, ep, response, option) != G_IO_STATUS_NORMAL)
        res = ZV_ABORT;
    }

  z_proxy_return(self, res);
}

/**
 * @brief Reply to server opneg request based on client side state
 * @param self Telnet proxy instance
 * @param command Command received from the server (DO/WILL/DONT/WONT)
 * @param option Option being negotiated
 *
 * In case the option has already been negotiated with the client and the
 * server requests the option to be enabled we have to reply on our own:
 * forwarding the request to the client might lead to the client not responding
 * since it's already in the requested state.
 *
 * @return ZV_UNSPEC if the option was not handled, a verdict otherwise
 */
static ZVerdict
replay_opneg_to_server(TelnetProxy *self, guint8 command, guint8 option)
{
  ZVerdict res = ZV_UNSPEC;

  z_proxy_enter(self);

  telnet_option_command_received(self, EP_SERVER, command, option);

  if (command == TELNET_CMD_DO &&
      option == TELNET_OPTION_NAWS &&
      telnet_option_do(self, EP_CLIENT, option) &&
      !telnet_option_will(self, EP_SERVER, option))
    {
      /* NAWS is special: when the server requests DO NAWS the client will
       * re-send the NAWS suboption even if the option has already been enabled.
       * We send the WILL to the server on our own but still forward the DO to the
       * client so that it triggers a suboption resend.
       */

      z_proxy_log(self, TELNET_DEBUG, 5, "Handling server-requested NAWS option specially;");

      if (telnet_send_opneg(self, EP_SERVER, TELNET_CMD_WILL, option) != G_IO_STATUS_NORMAL)
        z_proxy_return(self, ZV_ABORT);
      else
        z_proxy_return(self, ZV_UNSPEC);
    }

  guint8 response = 0;
  switch (command)
    {
      /* positive requests are replied if the option was enabled on the client side */
    case TELNET_CMD_DO:
      if (telnet_option_do(self, EP_CLIENT, option) &&
          !telnet_option_will(self, EP_SERVER, option))
        response = opneg_accept_response(command);
      break;
    case TELNET_CMD_WILL:
      if (telnet_option_will(self, EP_CLIENT, option) &&
          !telnet_option_do(self, EP_SERVER, option))
        response = opneg_accept_response(command);
      break;
      /* negative options are replied */
    case TELNET_CMD_DONT:
      if (!telnet_option_do_in_progress(self, EP_CLIENT, option) &&
          !telnet_option_do(self, EP_CLIENT, option))
        response = opneg_deny_response(command);
      break;
    case TELNET_CMD_WONT:
      if (!telnet_option_will_in_progress(self, EP_CLIENT, option) &&
          !telnet_option_will(self, EP_CLIENT, option))
        response = opneg_deny_response(command);
      break;
    }

  if (response != 0)
    {
      res = ZV_ACCEPT;

      z_proxy_log(self, TELNET_DEBUG, 5,
                  "Responding server-side request on behalf of the client; command='%hhu', option='%hhu', response='%hhu'",
                  command, option, response);

      if (telnet_send_opneg(self, EP_SERVER, response, option) != G_IO_STATUS_NORMAL)
        res = ZV_ABORT;
    }

  z_proxy_return(self, res);
}

static ZVerdict
process_opneg_transparent(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option)
{
  ZVerdict res;
  TelnetOptionFunction check_func;

  z_proxy_enter(self);

  if (ep == EP_SERVER && !telnet_proxy_is_transparent(self))
    {
      /* if we started in transparent mode it might be possible that the
       * option has already been negotiated with the client: check if the
       * client is already in the state now requested by the server and reply
       * instead of forwarding if that is the case
       */
      res = replay_opneg_to_server(self, command, option);

      if (res != ZV_UNSPEC)
        z_proxy_return(self, res);
    }

  /*
   * ask negotiation handler or policy if option is enabled
   */
  if ((check_func = self->telnet_option_negotiation_handlers[option]) == NULL)
    res = telnet_policy_option(self, ep, command, option);
  else
    res = check_func(self, ep, command, option);

  /* start TLS as neccessary. */
  if (!telnet_tls_is_negotiation_complete(self) &&
      !telnet_tls_start_negotiate(self))
    {
      z_proxy_log(self, TELNET_ERROR, 3, "TLS negotiation error;");
      z_proxy_return(self, ZV_UNSPEC);
    }

  switch (res)
    {
    case ZV_ACCEPT:
      res = process_opneg_ok(self, ep, command, option);
      break;

    case ZV_REJECT:
      res = process_opneg_reject(self, ep, command, option);
      break;

    case ZV_UNSPEC:
    case ZV_DENY:
    case ZV_POLICY:
    case ZV_ERROR:
    case ZV_DROP:
    case ZV_ABORT:
    case ZV_PROXY_SPECIFIC:
      /* do nothing, just return verdict */
      break;
    }

  z_proxy_return(self, res);
}

static ZVerdict
process_opneg(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option)
{
  ZVerdict res;

  z_proxy_enter(self);

  z_proxy_log(self, TELNET_DEBUG, 6, "Processing option negotiation; side='%s', command='%hhu', option='%hhu'",
              EP_STR(ep), command, option);

  if (telnet_state_is_connected(self))
    res = process_opneg_transparent(self, ep, command, option);
  else
    /* non-transparent mode, process and reply accordingly */
    res = process_opneg_non_transparent(self, ep, command, option);

  z_proxy_return(self, res);
}

static gboolean
process_opneg_client_cb(guint8 command, guint8 option, gpointer user_data)
{
  TelnetProxy *self = Z_CAST(user_data, TelnetProxy);

  return (process_opneg(self, EP_CLIENT, command, option) != ZV_ABORT);
}

static gboolean
process_opneg_server_cb(guint8 command, guint8 option, gpointer user_data)
{
  TelnetProxy *self = Z_CAST(user_data, TelnetProxy);

  return (process_opneg(self, EP_SERVER, command, option) != ZV_ABORT);
}

static ZVerdict
process_command_transparent(TelnetProxy *self, ZEndpoint ep, guint8 command)
{
  ZPolicyObj *res = NULL;
  guint option_needed;
  gchar cmd_str[5];
  ZVerdict ret_status;

  z_proxy_enter(self);

  /*
   * allow commands defined in RFC 854
   * these are important, and must be implemented
   */
  if (command >= 240)
    {
      z_proxy_log(self, TELNET_REQUEST, 6, "Accepting built-in Telnet command; command='%hhu'", command);
      z_proxy_return(self, ZV_ACCEPT);
    }

  /*
   * allow negotiated commands
   * these were allowed during a negotiation
   */
  g_snprintf(cmd_str, sizeof(cmd_str), "%hhu", command);

  z_policy_lock(self->super.thread);
  res = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->negotiation, cmd_str));
  if (res != NULL)
    {
      if (!z_policy_var_parse(res, "I", &option_needed))
        {
          z_proxy_log(self, TELNET_POLICY, 2, "Value in negotiation table bad; command='%s'", cmd_str);
          z_policy_unlock(self->super.thread);
          z_proxy_return(self, ZV_REJECT);
        }
      z_proxy_trace(self, "Changed required negotiated option; command='%s', option='%u'", cmd_str, option_needed);
    }
  else
    {
      option_needed = command;
    }
  z_policy_unlock(self->super.thread);

  ret_status = ZV_REJECT;
  if (option_needed == 255)
    {
      ret_status = ZV_ACCEPT;
    }
  else if (option_needed > 255)
    {
      z_proxy_log(self, TELNET_POLICY, 2, "Value in negotation table out of range; command='%hhu', value='%u'",
                  command, option_needed);
    }
  else
    {
      z_proxy_trace(self, "Option state check; option='%u', state='%d:%d'",
                    option_needed,
                    self->options[option_needed][ep],
                    self->options[option_needed][EP_OTHER(ep)]);

      if (telnet_option_do(self, ep, option_needed))
        ret_status = ZV_ACCEPT;
    } /* reject everything else */

  if (ret_status == ZV_ACCEPT)
    {
      if (telnet_send_command(self, EP_OTHER(ep), command) != G_IO_STATUS_NORMAL)
        ret_status = ZV_ABORT;
    }
  else
    {
      z_proxy_log(self, TELNET_VIOLATION, 2, "Illegal command; command='%hhu'", command);
    }

  z_proxy_return(self, ret_status);
}

static ZVerdict
process_command(TelnetProxy *self, ZEndpoint ep, guint8 command)
{
  ZVerdict res;

  z_proxy_enter(self);

  z_proxy_log(self, TELNET_DEBUG, 6, "Processing command; side='%s', command='%hhu'",
              EP_STR(ep), command);

  if (telnet_state_is_connected(self))
    res = process_command_transparent(self, ep, command);
  else
    /* just ignore the command in non-transparent mode */
    res = ZV_ACCEPT;

  z_proxy_return(self, res);
}

static gboolean
process_command_client_cb(guint8 command, gpointer user_data)
{
  TelnetProxy *self = Z_CAST(user_data, TelnetProxy);

  return (process_command(self, EP_CLIENT, command) != ZV_ABORT);
}

static gboolean
process_command_server_cb(guint8 command, gpointer user_data)
{
  TelnetProxy *self = Z_CAST(user_data, TelnetProxy);

  return (process_command(self, EP_SERVER, command) != ZV_ABORT);
}

static ZVerdict
process_data(TelnetProxy *self, ZEndpoint ep, ZPktBuf *data)
{
  ZVerdict res = ZV_ACCEPT;

  z_proxy_enter(self);

  z_proxy_log(self, TELNET_DEBUG, 6, "Processing data; side='%s', lenght='%" G_GSIZE_FORMAT "'",
              EP_STR(ep), z_pktbuf_length(data));

  ZPktBuf *out;
  ZEndpoint new_ep;

  if (self->state == TELNET_STATE_RELAYING)
    {
      /* copy data to the other endpoint */
      out = z_pktbuf_new();
      z_pktbuf_copy(out, z_pktbuf_data(data), z_pktbuf_length(data));
      new_ep = EP_OTHER(ep);
    }
  else if (telnet_state_is_lineedit(self) && ep == EP_CLIENT)
    {
      /* if we're editing a line feed the line editor */
      out = telnet_lineedit_process_data(&self->line_editor, data);
      new_ep = ep;
    }
  else
    {
      /* just ignore data otherwise */
      out = NULL;
      new_ep = ep;
    }

  if (out)
    {
      if (telnet_send_data(self, new_ep, out) != G_IO_STATUS_NORMAL)
        res = ZV_ABORT;

    }

  z_proxy_return(self, res);
}

static gboolean
process_data_client_cb(ZPktBuf *data, gpointer user_data)
{
  TelnetProxy *self = Z_CAST(user_data, TelnetProxy);

  return (process_data(self, EP_CLIENT, data) != ZV_ABORT);
}

static gboolean
process_data_server_cb(ZPktBuf *data, gpointer user_data)
{
  TelnetProxy *self = Z_CAST(user_data, TelnetProxy);

  return (process_data(self, EP_SERVER, data) != ZV_ABORT);
}

void
telnet_state_register_callbacks(TelnetProxy *self, ZEndpoint ep)
{
  z_proxy_enter(self);

  switch (ep)
    {
    case EP_CLIENT:
      {
        TelnetProtocol *p = &self->protocol[EP_CLIENT];

        GString *session_id = g_string_new(self->super.session_id);
        g_string_append(session_id, "/client_protocol");

        telnet_protocol_init(p, session_id->str);
        g_string_free(session_id, TRUE);

        telnet_lineedit_init(&self->line_editor);
        telnet_protocol_set_command_received(p, process_command_client_cb, self);
        telnet_protocol_set_opneg_received(p, process_opneg_client_cb, self);
        telnet_protocol_set_subneg_received(p, process_suboption_client_cb, self);
        telnet_protocol_set_data_received(p, process_data_client_cb, self);
      }
      break;

    case EP_SERVER:
      {
        TelnetProtocol *p = &self->protocol[EP_SERVER];

        GString *session_id = g_string_new(self->super.session_id);
        g_string_append(session_id, "/server_protocol");

        telnet_protocol_init(p, session_id->str);
        g_string_free(session_id, TRUE);

        telnet_protocol_set_command_received(p, process_command_server_cb, self);
        telnet_protocol_set_opneg_received(p, process_opneg_server_cb, self);
        telnet_protocol_set_subneg_received(p, process_suboption_server_cb, self);
        telnet_protocol_set_data_received(p, process_data_server_cb, self);
      }
      break;

    default:
      g_assert_not_reached();
    }

  z_proxy_leave(self);
}

static gboolean
send_will_option(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  z_proxy_enter(self);

  if (telnet_send_opneg(self, ep, TELNET_CMD_WILL, option) != G_IO_STATUS_NORMAL)
    z_proxy_return(self, FALSE);

  self->will_wont_requested[option][ep]++;

  z_proxy_return(self, TRUE);
}

static gboolean
send_do_option(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  z_proxy_enter(self);

  if (telnet_send_opneg(self, ep, TELNET_CMD_DO, option) != G_IO_STATUS_NORMAL)
    z_proxy_return(self, FALSE);

  self->do_dont_requested[option][ep]++;

  z_proxy_return(self, TRUE);
}

void
telnet_event_start_opneg(TelnetProxy *self)
{
  if (!send_will_option(self, EP_CLIENT, TELNET_OPTION_ECHO) ||
      !send_will_option(self, EP_CLIENT, TELNET_OPTION_SUPPRESS_GO_AHEAD) ||
      !send_do_option(self, EP_CLIENT, TELNET_OPTION_ENVIRONMENT))
    {
      z_proxy_log(self, TELNET_ERROR, 1, "Failed to send initial option negotiation sequence to client;");
      telnet_change_state(self, TELNET_STATE_QUIT);
      return;
    }

  telnet_change_state(self, TELNET_STATE_WAIT_OPNEG);
}

static gboolean
opneg_finished(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  return (self->will_wont_requested[option][ep] == 0 &&
          !telnet_option_will_in_progress(self, ep, option) &&
          !telnet_option_do_in_progress(self, ep, option));
}

static void
telnet_event_request_environment(TelnetProxy *self)
{
  ZPktBuf *buf = z_pktbuf_new();

  z_pktbuf_put_u8(buf, TELNET_OPTION_ENVIRONMENT);
  z_pktbuf_put_u8(buf, TELNET_SB_ENVIRONMENT_SEND);

  telnet_send_suboption(self, EP_CLIENT, buf);

  telnet_change_state(self, TELNET_STATE_WAIT_ENVIRONMENT);
}

static void start_non_transparent_session(TelnetProxy *self);

void
telnet_state_nt_wait_opneg(TelnetProxy *self)
{
  z_proxy_enter(self);

  if (opneg_finished(self, EP_CLIENT, TELNET_OPTION_ECHO) &&
      opneg_finished(self, EP_CLIENT, TELNET_OPTION_SUPPRESS_GO_AHEAD) &&
      opneg_finished(self, EP_CLIENT, TELNET_OPTION_ENVIRONMENT))
    {
      if (!telnet_option_will(self, EP_CLIENT, TELNET_OPTION_ECHO))
        {
          z_proxy_log(self, TELNET_ERROR, 3, "Failed to enable server echo, cannot proceed with this client in non-transparent mode;");
          telnet_change_state(self, TELNET_STATE_QUIT);
          z_proxy_leave(self);
          return;
        }

      /* start TLS on client side as neccessary. */
      if (!telnet_tls_is_negotiation_complete_on_side(self, EP_CLIENT) &&
          !telnet_tls_start_negotiate_on_side(self, EP_CLIENT))
        {
          z_proxy_log(self, TELNET_ERROR, 3, "TLS negotiation error;");
          telnet_change_state(self, TELNET_STATE_QUIT);

          z_proxy_leave(self);
          return;
        }

      if (telnet_option_do(self, EP_CLIENT, TELNET_OPTION_ENVIRONMENT))
        {
          z_proxy_log(self, TELNET_INFO, 5, "Requesting environment variables;");
          telnet_event_request_environment(self);
        }
      else
        {
          z_proxy_log(self, TELNET_INFO, 5, "Client does not support the NEW ENVIRONMENT option, will use interactive prompts if required;");
          start_non_transparent_session(self);
        }
    }

  z_proxy_leave(self);
}

static gboolean
telnet_do_gateway_auth(TelnetProxy *self)
{
  gchar **groups = NULL;

  z_proxy_enter(self);

  z_policy_lock(self->super.thread);
  gboolean res = z_auth_provider_check_passwd(self->auth, self->super.session_id,
                                              self->gateway_user->str, self->gateway_password->str,
                                              &groups, &self->super);
  z_policy_unlock(self->super.thread);

  if (res)
    {
      res = z_proxy_user_authenticated(&self->super, self->gateway_user->str,
                                       (gchar const **) groups,
                                       Z_PROXY_USER_AUTHENTICATED_GATEWAY);
    }

  g_strfreev(groups);

  z_proxy_return(self, res);
}

static void
telnet_event_prompt_user(TelnetProxy *self)
{
  ZPktBuf *pkt = z_pktbuf_new_from_gstring(self->gateway_user_prompt);

  self->line_editor.do_echo = TRUE;

  if (telnet_send_data(self, EP_CLIENT, pkt) != G_IO_STATUS_NORMAL)
    telnet_change_state(self, TELNET_STATE_QUIT);
  else
    telnet_change_state(self, TELNET_STATE_PROMPT_USER);
}

static void
telnet_event_prompt_password(TelnetProxy *self)
{
  ZPktBuf *pkt = z_pktbuf_new_from_gstring(self->gateway_password_prompt);

  self->line_editor.do_echo = FALSE;

  if (telnet_send_data(self, EP_CLIENT, pkt) != G_IO_STATUS_NORMAL)
    telnet_change_state(self, TELNET_STATE_QUIT);
  else
    telnet_change_state(self, TELNET_STATE_PROMPT_PASSWORD);
}

static void
telnet_event_prompt_server(TelnetProxy *self)
{
  ZPktBuf *pkt = z_pktbuf_new_from_gstring(self->server_name_prompt);

  self->line_editor.do_echo = TRUE;

  if (telnet_send_data(self, EP_CLIENT, pkt) != G_IO_STATUS_NORMAL)
    telnet_change_state(self, TELNET_STATE_QUIT);
  else
    telnet_change_state(self, TELNET_STATE_PROMPT_SERVER);
}

void
telnet_event_print_banner(TelnetProxy *self)
{
  ZPktBuf *pkt = telnet_user_string_to_pktbuf(self->banner);

  if (telnet_send_data(self, EP_CLIENT, pkt) != G_IO_STATUS_NORMAL)
    telnet_change_state(self, TELNET_STATE_QUIT);
}

static void
start_inband_server_selection(TelnetProxy *self)
{
  z_proxy_enter(self);

  if (self->server_hostname->len > 0)
    self->server_hostname_is_from_env = TRUE;

  if (self->transparent || self->server_hostname_is_from_env)
    telnet_event_connect_server(self);
  else
    telnet_event_prompt_server(self);

  z_proxy_leave(self);
}


static void
gateway_authentication_failed(TelnetProxy *self)
{
  ZPktBuf *failed_msg = z_pktbuf_new();

  z_proxy_enter(self);

  z_pktbuf_put_string(failed_msg, "\r\nGateway authentication failed.\r\n");
  if (telnet_send_data(self, EP_CLIENT, failed_msg) != G_IO_STATUS_NORMAL)
    {
      telnet_change_state(self, TELNET_STATE_QUIT);
      z_proxy_leave(self);
      return;
    }

  if (self->gateway_password_is_from_env)
    {
      /* no retry if the password came from the environment */
      z_proxy_log(self, TELNET_AUTH, 3, "Gateway authentication failed, will not retry non-interactive authentication;");
      telnet_change_state(self, TELNET_STATE_QUIT);
    }
  else
    {
      /* retry three times if an interactive password prompt was used */
      if (++self->gw_authentication_failures >= 3)
        {
          z_proxy_log(self, TELNET_AUTH, 3, "Gateway authentication failed, maximum number of failed attempts reached, exiting;");
          telnet_change_state(self, TELNET_STATE_QUIT);
        }
      else
        {
          z_proxy_log(self, TELNET_AUTH, 3, "Gateway authentication failed, requesting new password;");
          telnet_event_prompt_password(self);
        }
    }

  z_proxy_leave(self);
}

static void
start_inband_authentication(TelnetProxy *self)
{
  z_proxy_enter(self);

  if (self->gateway_user->len > 0)
    {
      /* we already have the user name, get password */
      if (self->gateway_password->len > 0)
        {
          /* have the password, too, check it */
          if (telnet_do_gateway_auth(self))
            {
              start_inband_server_selection(self);
            }
          else
            gateway_authentication_failed(self);
        }
      else
        telnet_event_prompt_password(self);
    }
  else
    telnet_event_prompt_user(self);

  z_proxy_leave(self);
}

static void
start_non_transparent_session(TelnetProxy *self)
{
  z_proxy_enter(self);

  telnet_event_print_banner(self);

  /* check if gateway auth is required */
  if (self->auth && self->gw_auth_required)
    start_inband_authentication(self);
  else
    /* otherwise we just do inband routing */
    start_inband_server_selection(self);

  z_proxy_leave(self);
}

void
telnet_state_nt_wait_environment(TelnetProxy *self)
{
  if (self->environment_is_received)
    {
      start_non_transparent_session(self);
    }
}

void
telnet_state_nt_prompt_server(TelnetProxy *self)
{
  if (self->line_editor.eol)
    {
      ZPktBuf *line = self->line_editor.data_buffer;
      GString *server = g_string_new_len(static_cast<gchar *>(z_pktbuf_data(line)), z_pktbuf_length(line));
      telnet_lineedit_clear(&self->line_editor);

      if (telnet_policy_parse_authinfo(self, "SERVER", server))
        telnet_event_connect_server(self);
      else
        telnet_event_prompt_server(self);

      g_string_free(server, TRUE);
    }
}

void
telnet_state_nt_prompt_user(TelnetProxy *self)
{
  if (self->line_editor.eol)
    {
      ZPktBuf *line = self->line_editor.data_buffer;
      g_string_assign_len(self->gateway_user, static_cast<gchar *>(z_pktbuf_data(line)), z_pktbuf_length(line));
      telnet_lineedit_clear(&self->line_editor);
      start_inband_authentication(self);
    }
}

void
telnet_state_nt_prompt_password(TelnetProxy *self)
{
  if (self->line_editor.eol)
    {
      ZPktBuf *line = self->line_editor.data_buffer;

      g_string_assign_len(self->gateway_password, static_cast<gchar *>(z_pktbuf_data(line)), z_pktbuf_length(line));
      telnet_lineedit_clear(&self->line_editor);

      gboolean res = telnet_do_gateway_auth(self);

      if (res)
        start_inband_server_selection(self);
      else
        start_inband_authentication(self);
    }
}
