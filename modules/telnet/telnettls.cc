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

#include "telnettls.h"
#include "telnetoption.h"

/**
 * Describes where the state machine was called from telnet proxy.
 *
 */
typedef enum _TlsStateMachineEntryPointType
  {
    SM_ENTRY_FROM_OPTION_ENFORCEMENT,
    SM_ENTRY_FROM_OPTION_NEG,
    SM_ENTRY_FROM_SUBOPTION_NEG
  } TlsStateMachineEntryPointType;

gboolean
telnet_tls_is_negotiation_complete_on_side(TelnetProxy *self, ZEndpoint ep)
{
  return !self->tls_required[ep] || (self->tls_required[ep] && self->tls_completed[ep]);
}

/**
 * Tells whether the TLS negotiation process is completed or not.
 *
 * @return TRUE when the negotiation is complete.
 */
gboolean
telnet_tls_is_negotiation_complete(TelnetProxy *self)
{
  return telnet_tls_is_negotiation_complete_on_side(self, EP_CLIENT) &&
    telnet_tls_is_negotiation_complete_on_side(self, EP_SERVER);
}

/**
 * Sends the Follows suboption of STARTTLS option to the endpoint.
 *
 * This helper method is used by both server and client state machine.
 *
 * @param self Proxy instance.
 * @param ep Endpoint (EP_CLIENT or EP_SERVER).
 * @return TRUE on success.
 */
static gboolean
telnet_tls_send_follows_suboption(TelnetProxy *self, ZEndpoint ep)
{
  ZPktBuf *buf = z_pktbuf_new();

  z_pktbuf_put_u8(buf, TELNET_OPTION_STARTTLS);
  z_pktbuf_put_u8(buf, TELNET_TLS_FOLLOWS_SUBOPTION);

  GIOStatus status = telnet_send_suboption(self, ep, buf);

  return (status == G_IO_STATUS_NORMAL);
}

/**
 * Sends error message to the client.
 *
 * @param self Proxy instance.
 * @param message Error message.
 */
static void
telnet_tls_send_error(TelnetProxy *self, const gchar *message)
{
  ZPktBuf *response = z_pktbuf_new();
  z_pktbuf_put_c8s(response, strlen(message), message);
  telnet_send_data(self, EP_CLIENT, response);
}

/**
 * Starts TLS option negotiation on client side.
 *
 * @param self Proxy instance.
 * @return TRUE when negotiation successfully started.
 */
static gboolean
telnet_tls_client_negotiation_start(TelnetProxy *self)
{
  telnet_option_command_received(self, EP_CLIENT, TELNET_CMD_WILL, TELNET_OPTION_STARTTLS);
  gboolean res = telnet_send_opneg(self, EP_CLIENT, TELNET_CMD_DO, TELNET_OPTION_STARTTLS);
  self->tls_status[EP_CLIENT] = TELNET_TLS_STATUS_SERVER_REQUESTED_TLS;

  z_proxy_log(self, TELNET_DEBUG, 7, "Starting TLS negotiation on client side;");
  return res;
}

static void
telnet_tls_complete_negotiation(TelnetProxy *self, ZEndpoint ep)
{
  self->tls_completed[ep] = TRUE;
  z_proxy_log(self, TELNET_INFO, 4, "Telnet STARTTLS completed, switched to SSL transport; side='%s'", EP_STR(ep));
}

/**
 * Adds SSL on top of the stream at given endpoint.
 *
 * @param self Proxy instance.
 * @param ep Endpoint (EP_CLIENT or EP_SERVER).
 * @return TRUE when SSL handshake was successful.
 */
static gboolean
telnet_tls_switch_stream_to_ssl(TelnetProxy *self, ZEndpoint ep)
{
  gboolean res = FALSE;

  z_proxy_log(self, TELNET_DEBUG, 5, "Switching to SSL transport; side='%s'", EP_STR(ep));
  z_stream_set_nonblock(self->super.endpoints[ep], FALSE);
  self->tls_status[ep] = TELNET_TLS_STATUS_HANDSHAKE_STARTED;
  res = z_proxy_ssl_request_handshake(&self->super, ep, FALSE);

  if (!res)
    {
      z_proxy_log(self, TELNET_ERROR, 1, "SSL handshake failed, terminating session; side='%s'", EP_STR(ep));
    }
  else
    {
      if (!self->super.ssl_opts.handshake_pending[ep]) /* SSL handshake is now completed on both sides */
        {
          telnet_tls_complete_negotiation(self, ep);

          if (!self->tls_completed[EP_OTHER(ep)] && self->tls_status[EP_OTHER(ep)] == TELNET_TLS_STATUS_HANDSHAKE_STARTED)
            telnet_tls_complete_negotiation(self, EP_OTHER(ep));
        }
    }

  z_stream_set_nonblock(self->super.endpoints[ep], TRUE);

  return res;
}

/**
 * @see telnet_tls_client_sm
 */
static gboolean
telnet_tls_client_sm_handle_client_starting_tls(TelnetProxy *self, guint8 command, TlsStateMachineEntryPointType entry)
{
  gboolean res = TRUE;

  switch (entry)
    {
    case SM_ENTRY_FROM_OPTION_NEG:
      if (command == TELNET_CMD_WILL)
        res = TRUE;
      else
        z_proxy_log(self, TELNET_ERROR, 1, "Invalid command received; side='client', status='%d'", self->tls_status[EP_CLIENT]);
      break;

    case SM_ENTRY_FROM_SUBOPTION_NEG:
      res = telnet_tls_send_follows_suboption(self, EP_CLIENT) &&
        telnet_tls_switch_stream_to_ssl(self, EP_CLIENT);
      break;

    default:
      z_proxy_log(self, TELNET_ERROR, 1, "client_starting_tls: Invalid entry point for TLS state; side='client', status='%d'", self->tls_status[EP_CLIENT]);
      res = FALSE;
      break;
    }

  return res;
}

/**
 * @see telnet_tls_client_sm
 */
static gboolean
telnet_tls_client_sm_handle_server_requested_tls(TelnetProxy *self, guint8 command, TlsStateMachineEntryPointType entry)
{
  gboolean res = FALSE;

  if (entry == SM_ENTRY_FROM_OPTION_NEG)
    {
      if (command == TELNET_CMD_WILL)
        {
          self->tls_status[EP_CLIENT] = TELNET_TLS_STATUS_CLIENT_STARTING_TLS;
          res = TRUE;
        }
      else
        {
          telnet_tls_send_error(self, "\r\nThis connection requires a STARTTLS capable telnet client.\r\n\r\n");
          z_proxy_log(self, TELNET_ERROR, 3, "TLS is required but client is not capable of TLS;");
        }
    }
  else
    {
      z_proxy_log(self, TELNET_ERROR, 1, "server_requested_tls: Invalid entry point for TLS state; side='client', status='%d', entry='%d'", self->tls_status[EP_CLIENT], entry);
    }

  return res;
}

/**
 * @see telnet_tls_client_sm
 */
static gboolean
telnet_tls_client_sm_handle_none_status(TelnetProxy *self, guint8 command, TlsStateMachineEntryPointType entry)
{
  gboolean res = FALSE;

  if (entry == SM_ENTRY_FROM_OPTION_ENFORCEMENT)
    {
      res = telnet_tls_client_negotiation_start(self);
    }
  else if (entry == SM_ENTRY_FROM_OPTION_NEG)
    {
      /* Client requested for STARTTLS */
      if (command == TELNET_CMD_WILL)
        {
          if (self->super.ssl_opts.security[EP_CLIENT] != PROXY_SSL_SEC_ACCEPT_STARTTLS)
            res = telnet_send_opneg(self, EP_CLIENT, TELNET_CMD_DONT, TELNET_OPTION_STARTTLS);
          else
            res = telnet_tls_client_negotiation_start(self);
        }
      else
        {
          z_proxy_log(self, TELNET_ERROR, 1, "Invalid command in STARTTLS option request; side='client', status='%d', command='%d'", self->tls_status[EP_CLIENT], command);
        }
    }
  else
    {
      z_proxy_log(self, TELNET_ERROR, 1, "TLS suboption received in invalid state; side='client', status='%d'", self->tls_status[EP_CLIENT]);
    }

  return res;
}

/**
 * State machine for client side TLS negotiation.
 *
 * @param self Proxy instance.
 * @param entry Tells where the state machine was called from.
 * @return TRUE when the state machine worked normally. FALSE on error.
 */
static ZVerdict
telnet_tls_client_sm(TelnetProxy *self, guint8 command, TlsStateMachineEntryPointType entry)
{
  gboolean res = FALSE;

  switch(self->tls_status[EP_CLIENT])
    {
    case TELNET_TLS_STATUS_NONE:
      res = telnet_tls_client_sm_handle_none_status(self, command, entry);
      break;

    case TELNET_TLS_STATUS_SERVER_REQUESTED_TLS:
      res = telnet_tls_client_sm_handle_server_requested_tls(self, command, entry);
      break;

    case TELNET_TLS_STATUS_CLIENT_STARTING_TLS:
      res = telnet_tls_client_sm_handle_client_starting_tls(self, command, entry);
      break;

    default:
      z_proxy_log(self, TELNET_ERROR, 1, "Invalid TLS state; side='client', status='%d'", self->tls_status[EP_CLIENT]);
      break;
    }

  return ZVerdict(res);
}

/**
 * @see telnet_tls_server_sm
 */
static gboolean
telnet_tls_server_sm_handle_client_starting_tls_follows(TelnetProxy *self, TlsStateMachineEntryPointType entry)
{
  gboolean res = FALSE;

  if (entry == SM_ENTRY_FROM_SUBOPTION_NEG)
    res = telnet_tls_switch_stream_to_ssl(self, EP_SERVER);
  else
    z_proxy_log(self, TELNET_ERROR, 1, "client_starting_tls_follows: Invalid entry point for TLS state; side='server', status='%d'", self->tls_status[EP_SERVER]);

  return res;
}

/**
 * @internal
 */
static gboolean
telnet_tls_server_sm_handle_server_not_tls_capable(TelnetProxy *self, gboolean tls_was_requested)
{
  gboolean res = FALSE;

  if (self->tls_required[EP_SERVER] || tls_was_requested)
    {
      telnet_tls_send_error(self, "\r\nThe required STARTTLS option is not supported by the server.\r\n\r\n");
      z_proxy_log(self, TELNET_ERROR, 1, "The required STARTTLS option is not supported by the server;");
    }
  else
    {
      res = TRUE;
    }

  return res;
}

/**
 * @internal
 */
static gboolean
telnet_tls_server_sm_negotiate_continue(TelnetProxy *self)
{
  gboolean res;

  telnet_option_command_received(self, EP_SERVER, TELNET_CMD_DO, TELNET_OPTION_STARTTLS);
  res = telnet_send_opneg(self, EP_SERVER, TELNET_CMD_WILL, TELNET_OPTION_STARTTLS) &&
    telnet_tls_send_follows_suboption(self, EP_SERVER);
  self->tls_status[EP_SERVER] = TELNET_TLS_STATUS_CLIENT_STARTING_TLS_FOLLOWS;

  return res;
}

/**
 * @internal
 */
static gboolean
telnet_tls_server_sm_negotiate_continue_if_possible(TelnetProxy *self)
{
  gboolean res;

  if (self->super.ssl_opts.security[EP_SERVER] != PROXY_SSL_SEC_FORWARD_STARTTLS)
    res = telnet_send_opneg(self, EP_SERVER, TELNET_CMD_WONT, TELNET_OPTION_STARTTLS);
  else
    res = telnet_tls_server_sm_negotiate_continue(self);

  return res;
}

/**
 * @see telnet_tls_server_sm
 */
static gboolean
telnet_tls_server_sm_handle_client_requested_tls(TelnetProxy *self, guint8 command, TlsStateMachineEntryPointType entry)
{
  gboolean res = FALSE;

  switch(entry)
    {
    case SM_ENTRY_FROM_OPTION_NEG:
      if (command == TELNET_CMD_DO)
        res = telnet_tls_server_sm_negotiate_continue(self);
      else
        res = telnet_tls_server_sm_handle_server_not_tls_capable(self, TRUE);
      break;

    default:
      z_proxy_log(self, TELNET_ERROR, 1, "server_handle_client_requested_tls: Invalid entry point for TLS state; side='server', status='%d'", self->tls_status[EP_SERVER]);
      break;
    }
  return res;
}

/**
 * @see telnet_tls_server_sm
 */
static gboolean
telnet_tls_server_sm_handle_none_status(TelnetProxy *self, guint8 command, TlsStateMachineEntryPointType entry)
{
  gboolean res = FALSE;

  z_proxy_log(self, TELNET_DEBUG, 7, "Starting TLS negotiation on server side;");
  switch (entry)
    {
    case SM_ENTRY_FROM_OPTION_ENFORCEMENT:
      telnet_option_command_received(self, EP_SERVER, TELNET_CMD_DO, TELNET_OPTION_STARTTLS);
      res = telnet_send_opneg(self, EP_SERVER, TELNET_CMD_WILL, TELNET_OPTION_STARTTLS);
      self->tls_status[EP_SERVER] = TELNET_TLS_STATUS_CLIENT_REQUESTED_TLS;
      break;

    case SM_ENTRY_FROM_OPTION_NEG:
      if (command == TELNET_CMD_DO) /* Server would like to switch to SSL. */
        res = telnet_tls_server_sm_negotiate_continue_if_possible(self);
      else
        res = telnet_tls_server_sm_handle_server_not_tls_capable(self, FALSE);
      break;

    default:
      z_proxy_log(self, TELNET_ERROR, 1, "server_handle_none_status: Invalid entry point for TLS state; side='server', status='%d'", self->tls_status[EP_SERVER]);
      break;
    }

  return res;
}

/**
 * State machine for server side TLS negotiation.
 *
 * @param self Proxy instance.
 * @param entry Tells where the state machine was called from.
 * @return TRUE when the state machine worked normally. FALSE on error.
 */
static gboolean
telnet_tls_server_sm(TelnetProxy *self, guint8 command, TlsStateMachineEntryPointType entry)
{
  gboolean res = FALSE;

  switch(self->tls_status[EP_SERVER])
    {
    case TELNET_TLS_STATUS_NONE:
      res = telnet_tls_server_sm_handle_none_status(self, command, entry);
      break;

    case TELNET_TLS_STATUS_CLIENT_REQUESTED_TLS:
      res = telnet_tls_server_sm_handle_client_requested_tls(self, command, entry);
      break;

    case TELNET_TLS_STATUS_CLIENT_STARTING_TLS_FOLLOWS:
      res = telnet_tls_server_sm_handle_client_starting_tls_follows(self, entry);
      break;

    default:
      z_proxy_log(self, TELNET_DEBUG, 7, "Unhandled tls state; side='server', status='%d'", self->tls_status[EP_SERVER]);
      break;
    }

  return res;
}

/**
 * @see telnet_tls_handle_option or telnet_tls_handle_suboption
 */
static inline ZVerdict
telnet_tls_handle_option_or_suboption(TelnetProxy *self, ZEndpoint ep, guint8 command, TlsStateMachineEntryPointType entry)
{
  ZVerdict res = ZV_ABORT;

  /* The packets should be dropped on success as TLS is handled separately on each side. */
  if (ep == EP_CLIENT)
    res = telnet_tls_client_sm(self, command, entry) ? ZV_DROP : ZV_ABORT;
  else if (ep == EP_SERVER)
    res = telnet_tls_server_sm(self, command, entry) ? ZV_DROP : ZV_ABORT;

  return res;
}

/**
 * This check function is called when a STARTTLS suboption is received.
 *
 * @param self Proxy instance.
 * @param ep Endpoint where the suboption was received.
 * @return Verdict about the suboption.
 */
ZVerdict
telnet_tls_handle_suboption(TelnetProxy *self, ZEndpoint ep, guint8 option G_GNUC_UNUSED, ZPktBuf *suboption_buffer G_GNUC_UNUSED)
{
  return telnet_tls_handle_option_or_suboption(self, ep, 0, SM_ENTRY_FROM_SUBOPTION_NEG);
}

/**
 * This check function is called when the STARTTLS option is received.
 *
 * @param self Proxy instance.
 * @param ep Endpoint where the option was received.
 * @return Verdict about the option.
 */
ZVerdict
telnet_tls_handle_option(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option G_GNUC_UNUSED)
{
  z_proxy_log(self, TELNET_DEBUG, 7, "TLS: Handle option; side='%s', command='%hhu', option='%hhu'", EP_STR(ep), command, option);
  return telnet_tls_handle_option_or_suboption(self, ep, command, SM_ENTRY_FROM_OPTION_NEG);
}

gboolean
telnet_tls_start_negotiate_on_side(TelnetProxy *self, ZEndpoint ep)
{
  gboolean res = TRUE;

  if (ep == EP_CLIENT && self->tls_status[EP_CLIENT] == TELNET_TLS_STATUS_NONE && self->tls_required[EP_CLIENT])
    res &= telnet_tls_client_sm(self, 0, SM_ENTRY_FROM_OPTION_ENFORCEMENT);
  else if (ep == EP_SERVER && self->tls_status[EP_SERVER] == TELNET_TLS_STATUS_NONE && self->tls_required[EP_SERVER])
    res &= telnet_tls_server_sm(self, 0, SM_ENTRY_FROM_OPTION_ENFORCEMENT);

  return res;
}

/**
 * Start negotiation of TLS protocol.
 *
 * @param self Proxy.
 * @param ep Negotiation will start on this endpoint.
 * @return TRUE on success.
 */
gboolean
telnet_tls_start_negotiate(TelnetProxy *self)
{
  return telnet_tls_start_negotiate_on_side(self, EP_CLIENT) &&
    telnet_tls_start_negotiate_on_side(self, EP_SERVER);
}
