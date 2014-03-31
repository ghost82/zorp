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
#include "telnetprotocol.h"
#include "telnetpolicy.h"
#include "telnetsuboption.h"
#include "telnetstate.h"
#include "telnettls.h"
#include "telnetoption.h"

#include <zorp/thread.h>
#include <zorp/registry.h>
#include <zorp/log.h>
#include <zorp/policy.h>
#include <zorp/io.h>
#include <zorp/stream.h>
#include <zorp/streambuf.h>
#include <zorp/pystruct.h>
#include <zorp/poll.h>
#include <zorp/packetbuf.h>
#include <zorp/source.h>

#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/types.h>
#include <sys/socket.h>

static TelnetSuboptions telnet_suboptions_table[] =
  {
    { TELNET_OPTION_TERMINAL_TYPE,      telnet_subopt_terminal_type },
    { TELNET_OPTION_TERMINAL_SPEED,     telnet_subopt_terminal_speed },
    { TELNET_OPTION_X_DISPLAY_LOCATION, telnet_subopt_x_display },
    { TELNET_OPTION_ENVIRONMENT,        telnet_subopt_new_env },
    { TELNET_OPTION_NAWS,               telnet_subopt_naws },
    { TELNET_OPTION_STARTTLS,           telnet_tls_handle_suboption },
    { 0,                                NULL }
  };

static TelnetOptions telnet_option_negotiation_table[] =
  {
    { TELNET_OPTION_STARTTLS,           telnet_tls_handle_option },
    { 0,                                NULL }
  };


/**
 * telnet_set_defaults:
 * @self:
 *
 *
 */
static void
telnet_set_defaults(TelnetProxy *self)
{
  z_proxy_enter(self);
  self->telnet_policy = z_dim_hash_table_new(1, 2, DIMHASH_WILDCARD, DIMHASH_WILDCARD);
  for (int i = 0; i < 256; i++)
    self->telnet_suboptions[i] = NULL;

  for (int i = 0; i < 256; i++)
    self->telnet_option_negotiation_handlers[i] = NULL;

  self->policy_name = g_string_new("");
  self->policy_value = g_string_new("");
  self->timeout = 600000;
  self->transparent = TRUE;
  self->gw_auth_required = FALSE;
  self->server_stream_initialized = FALSE;
  self->server_hostname = g_string_new("");
  self->username = g_string_new("");
  self->gateway_user = g_string_new("");
  self->gateway_password = g_string_new("");
  self->server_port = 23;
  self->banner = g_string_new("");
  self->server_name_prompt = g_string_new("Server: ");
  self->gateway_user_prompt = g_string_new("Gateway user name: ");
  self->gateway_password_prompt = g_string_new("Gateway password: ");
  self->negotiation = g_hash_table_new(g_str_hash, g_str_equal);
  z_proxy_return(self);
}

/**
 * telnet_register_vars:
 * @self:
 *
 *
 */
static void
telnet_register_vars(TelnetProxy *self)
{
  z_proxy_enter(self);

  z_proxy_var_new(&self->super, "auth",
                  Z_VAR_TYPE_OBJECT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->auth);

  z_proxy_var_new(&self->super, "auth_server",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->auth_server);

  z_proxy_var_new(&self->super, "option",
                  Z_VAR_TYPE_DIMHASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->telnet_policy);

  z_proxy_var_new(&self->super, "negotiation",
                  Z_VAR_TYPE_HASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->negotiation);

  z_proxy_var_new(&self->super, "client_tls_required",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG,
                  &self->tls_required[EP_CLIENT]);

  z_proxy_var_new(&self->super, "server_tls_required",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG,
                  &self->tls_required[EP_SERVER]);

  z_proxy_var_new(&self->super, "transparent_mode",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->transparent);

  z_proxy_var_new(&self->super, "gw_auth",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->gw_auth_required);

  z_proxy_var_new(&self->super, "current_var_name",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->policy_name);

  z_proxy_var_new(&self->super, "current_var_value",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->policy_value);

  z_proxy_var_new(&self->super, "timeout",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->timeout);

  z_proxy_var_new(&self->super, "server_name_prompt",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  self->server_name_prompt);

  z_proxy_var_new(&self->super, "gateway_user_prompt",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  self->gateway_user_prompt);

  z_proxy_var_new(&self->super, "gateway_password_prompt",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  self->gateway_password_prompt);

  z_proxy_var_new(&self->super, "banner",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  self->banner);

  z_proxy_var_new(&self->super, "username",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->username);

  z_proxy_var_new(&self->super, "gateway_user",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->gateway_user);

  z_proxy_var_new(&self->super, "server_hostname",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->server_hostname);

  z_proxy_var_new(&self->super, "server_port",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET,
                  &self->server_port);



  z_proxy_return(self);
}

/**
 * telnet_config_init:
 * @self:
 *
 *
 */
static void
telnet_config_init(TelnetProxy *self)
{
  int i;

  z_proxy_enter(self);
  for (i = 0; i < 256; i++)
    {
      self->options[i][EP_CLIENT] = 0;
      self->options[i][EP_SERVER] = 0;
    }

  for (i = 0; telnet_suboptions_table[i].suboption_check != NULL; i++)
    self->telnet_suboptions[telnet_suboptions_table[i].suboption] = telnet_suboptions_table[i].suboption_check;

  for (i = 0; telnet_option_negotiation_table[i].option_check != NULL; i++)
    self->telnet_option_negotiation_handlers[telnet_option_negotiation_table[i].option] = telnet_option_negotiation_table[i].option_check;

  z_proxy_return(self);
}

/**
 * This function sends a packet to one of the endpoints.
 *
 * @param[in]  self Telnet proxy instance
 * @param[in]  ep Endpoint index
 * @param[in]  pkt Packet to send (consumed)
 *
 * The function consumes the packet, so the caller must not unref it itself!
 *
 * @returns GIOStatus instance
 **/
GIOStatus
telnet_write_packet(TelnetProxy *self, ZEndpoint ep, ZPktBuf *pkt)
{
  GIOStatus res = G_IO_STATUS_ERROR;

  z_proxy_enter(self);

  if (self->super.ssl_opts.handshake_pending[ep]) /* do not send any data while SSL handshake is in progress. */
    {
      z_pktbuf_unref(pkt);
      z_proxy_return(self, G_IO_STATUS_NORMAL);
    }

    {
      res = z_stream_write_packet(self->super.endpoints[ep], pkt, NULL);
    }

  z_proxy_return(self, res);
}

GIOStatus
telnet_send_suboption(TelnetProxy *self, ZEndpoint ep, ZPktBuf *suboption)
{
  ZPktBuf *out = z_pktbuf_new();

  z_pktbuf_put_u8(out, TELNET_IAC);
  z_pktbuf_put_u8(out, TELNET_CMD_SB);
  telnet_protocol_escape_data(suboption);
  z_pktbuf_put_u8s(out, z_pktbuf_length(suboption), static_cast<guint8 *>(z_pktbuf_data(suboption)));
  z_pktbuf_put_u8(out, TELNET_IAC);
  z_pktbuf_put_u8(out, TELNET_CMD_SE);

  return telnet_write_packet(self, ep, out);
}

GIOStatus
telnet_send_command(TelnetProxy *self, ZEndpoint ep, guint8 command)
{
  ZPktBuf *out = z_pktbuf_new();

  z_pktbuf_put_u8(out, TELNET_IAC);
  z_pktbuf_put_u8(out, command);

  return telnet_write_packet(self, ep, out);
}

GIOStatus
telnet_send_opneg(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option)
{
  ZPktBuf *out = z_pktbuf_new();

  telnet_option_command_sent(self, ep, command, option);

  z_pktbuf_put_u8(out, TELNET_IAC);
  z_pktbuf_put_u8(out, command);
  z_pktbuf_put_u8(out, option);

  return telnet_write_packet(self, ep, out);
}

/**
 * @brief Send binary data to an endpoint
 *
 * @param self  Telnet proxy instance
 * @param ep  Endpoint to send to
 * @param data  Packet buffer containing the data to send (consumed!)
 * @return  I/O status of the operation
 *
 * The function consumes the packet buffer!
 */
GIOStatus
telnet_send_data(TelnetProxy *self, ZEndpoint ep, ZPktBuf *data)
{
  telnet_protocol_escape_data(data);

  return telnet_write_packet(self, ep, data);
}

static gboolean
telnet_read(TelnetProxy *self, ZStream *stream, ZEndpoint ep)
{
  gboolean res = FALSE;

  z_proxy_enter(self);

  ZPktBuf *buf = z_pktbuf_new();
  z_pktbuf_resize(buf, TELNET_BUFFER_SIZE);

  gsize bytes_read = 0;
  GIOStatus status = z_stream_read(stream, buf->data, buf->allocated, &bytes_read, NULL);

  if (status == G_IO_STATUS_ERROR || status == G_IO_STATUS_EOF)
    {
      /* error already logged */
      z_pktbuf_unref(buf);
      z_poll_quit(self->poll);
      return FALSE;
    }
  else if (status == G_IO_STATUS_AGAIN)
    {
      return TRUE;
    }
  buf->length += bytes_read;

  telnet_protocol_process_data(&self->protocol[ep], buf);

  z_pktbuf_unref(buf);

  res = telnet_protocol_is_running(&self->protocol[ep]);

  if (!res)
    z_poll_quit(self->poll);

  z_proxy_return(self, res);
}

static gboolean
telnet_client_read(ZStream *stream, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  TelnetProxy   *self = Z_CAST(user_data, TelnetProxy);
  gboolean      res;

  z_proxy_enter(self);

  res = telnet_read(self, stream, EP_CLIENT);

  z_proxy_return(self, res);
}

static gboolean
telnet_server_read(ZStream *stream G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  TelnetProxy   *self = Z_CAST(user_data, TelnetProxy);
  gboolean      res;

  z_proxy_enter(self);

  res = telnet_read(self, stream, EP_SERVER);

  z_proxy_return(self, res);
}

static void
telnet_init_stream(TelnetProxy *self, ZEndpoint ep, ZStreamCallback cb, gpointer user_data, GDestroyNotify data_notify)
{
  ZStream *stream = self->super.endpoints[ep] =
    z_stream_push(self->super.endpoints[ep], z_stream_buf_new(NULL, 256 * 1024, Z_SBF_IMMED_FLUSH));

  /* FIXME: provide a wrapper for this */
  int fd = z_stream_get_fd(stream);
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  z_stream_set_callback(stream, G_IO_IN, cb, user_data, data_notify);
  z_stream_set_timeout(stream, -2);

  z_poll_add_stream(self->poll, stream);
  z_stream_set_cond(stream, G_IO_IN, TRUE);
}

static gboolean
telnet_init_client_stream(TelnetProxy *self)
{
  z_proxy_enter(self);

  telnet_init_stream(self, EP_CLIENT, telnet_client_read, self, NULL);

  z_proxy_return(self, TRUE);
}

static gboolean
telnet_init_server_stream(TelnetProxy *self)
{
  gboolean ret = TRUE;

  z_proxy_enter(self);

  telnet_init_stream(self, EP_SERVER, telnet_server_read, self, NULL);

  self->server_stream_initialized = TRUE;


  z_proxy_return(self, ret);
}

static void
telnet_deinit_streams(TelnetProxy *self)
{
  if (self->server_stream_initialized)
    {
      z_poll_remove_stream(self->poll, self->super.endpoints[EP_SERVER]);
      z_stream_buf_flush(self->super.endpoints[EP_SERVER]);
    }

  z_poll_remove_stream(self->poll, self->super.endpoints[EP_CLIENT]);
  z_stream_buf_flush(self->super.endpoints[EP_CLIENT]);
}

/**
 * telnet_config:
 * @s:
 *
 *
 *
 * Returns:
 *
 */
static gboolean
telnet_config(ZProxy *s)
{
  TelnetProxy   *self = Z_CAST(s, TelnetProxy);
  gboolean      success = FALSE;

  z_proxy_enter(self);

  self->poll = z_poll_new();

  telnet_set_defaults(self);
  telnet_register_vars(self);

  telnet_state_register_callbacks(self, EP_CLIENT);
  telnet_state_register_callbacks(self, EP_SERVER);

  if (Z_SUPER(self, ZProxy)->config(s))
    {
      telnet_config_init(self);
      success = TRUE;
    }

  z_proxy_return(self, success);
}

/**
 * telnet_user_string_to_pktbuf:
 * @brief Convert a user string to ZPktBuf, while converting \n to \r\n
 * @param msg User string to be converted
 * @return ZPktBuf containing the \r\n-ified input string
 */
ZPktBuf*
telnet_user_string_to_pktbuf(GString *msg)
{
  ZPktBuf *ret = z_pktbuf_new();

  for (gsize i = 0; i < msg->len; ++i)
    {
      if (msg->str[i] == '\n')
        z_pktbuf_put_c8(ret, '\r');

      z_pktbuf_put_c8(ret, msg->str[i]);
    }

  return ret;
}


static const char *
telnet_state_str(TelnetState state)
{
  const char *state_strings[] = {
      "WAIT_OPNEG",
      "WAIT_ENVIRONMENT",
      "PROMPT_USER",
      "PROMPT_PASSWORD",
      "PROMPT_SERVER",
      "RELAYING",
      "QUIT"
  };

  switch (state)
    {
    case TELNET_STATE_WAIT_OPNEG: return state_strings[state];
    case TELNET_STATE_WAIT_ENVIRONMENT: return state_strings[state];
    case TELNET_STATE_PROMPT_USER: return state_strings[state];
    case TELNET_STATE_PROMPT_PASSWORD: return state_strings[state];
    case TELNET_STATE_PROMPT_SERVER: return state_strings[state];
    case TELNET_STATE_RELAYING: return state_strings[state];
    case TELNET_STATE_QUIT: return state_strings[state];
    }
  g_assert_not_reached();
}

/**
 * @brief Transition the main proxy state machine to a new state
 * @param self TelnetProxy instance
 * @param new_state new state to move to
 *
 * This function makes sure that we can log all transitions and later do extra
 * processing upon transitions, too.
 *
 */
void
telnet_change_state(TelnetProxy *self, TelnetState new_state)
{
  z_proxy_enter(self);

  z_proxy_log(self, TELNET_DEBUG, 6, "Telnet state machine transition; old='%s', new='%s'",
              telnet_state_str(self->state), telnet_state_str(new_state));
  self->state = new_state;


  z_proxy_leave(self);
}

void
telnet_change_state_to_connected(TelnetProxy *self)
{
  telnet_change_state(self, TELNET_STATE_RELAYING);
}

static inline gboolean
proxy_is_running(TelnetProxy *self)
{
  return self->state != TELNET_STATE_QUIT;
}

void
telnet_event_connect_server(TelnetProxy *self)
{
  z_proxy_enter(self);

  const gchar *server_hostname = self->transparent ? NULL : self->server_hostname->str;
  const gint server_port = self->transparent ? 0 : self->server_port;

  if (!z_proxy_connect_server(&self->super, server_hostname, server_port) ||
      !telnet_init_server_stream(self))
    {
      ZPktBuf *pkt = z_pktbuf_new();

      if (server_hostname != NULL)
        {
          gchar _numbuf[6];
          g_snprintf(_numbuf, sizeof(_numbuf), "%u", server_port);
          z_pktbuf_put_string(pkt, "\r\nConnection to server '");
          z_pktbuf_put_string(pkt, server_hostname);
          z_pktbuf_put_string(pkt, ":");
          z_pktbuf_put_string(pkt, _numbuf);
          z_pktbuf_put_string(pkt, "' failed.\r\n\r\n");
        }
      else
        {
          z_pktbuf_put_string(pkt, "\r\nConnection to server failed.\r\n\r\n");
        }

      telnet_send_data(self, EP_CLIENT, pkt);

      telnet_change_state(self, TELNET_STATE_QUIT);
    }
  else
    {
      ZPktBuf *pkt = z_pktbuf_new();

      if (server_hostname != NULL)
        {
          gchar _numbuf[6];
          g_snprintf(_numbuf, sizeof(_numbuf), "%u", self->server_port);
          z_pktbuf_put_string(pkt, "\r\nConnected to server '");
          z_pktbuf_put_string(pkt, self->server_hostname->str);
          z_pktbuf_put_string(pkt, ":");
          z_pktbuf_put_string(pkt, _numbuf);
          z_pktbuf_put_string(pkt, "'\r\n\r\n");
        }
      else
        {
          z_pktbuf_put_string(pkt, "\r\nConnected to server.\r\n\r\n");
        }

      if (telnet_send_data(self, EP_CLIENT, pkt) != G_IO_STATUS_NORMAL)
        {
          telnet_change_state(self, TELNET_STATE_QUIT);
          z_proxy_leave(self);
        }
      else
        telnet_change_state_to_connected(self);

      /* start TLS on server side as neccessary. */
      if (!telnet_tls_is_negotiation_complete_on_side(self, EP_SERVER) &&
          !telnet_tls_start_negotiate_on_side(self, EP_SERVER))
        {
          z_proxy_log(self, TELNET_ERROR, 3, "TLS negotiation error;");
          telnet_change_state(self, TELNET_STATE_QUIT);
        }
    }

  z_proxy_leave(self);
}

static gboolean
telnet_check_valid_config(TelnetProxy *self)
{
  z_proxy_enter(self);

  if (self->gw_auth_required && !self->auth)
    {
      z_proxy_log(self, TELNET_ERROR, 1, "Gateway authentication cannot be enabled without an authentication policy;");
      z_proxy_return(self, FALSE);
    }

  z_proxy_return(self, TRUE);
}

static void
telnet_stream_update_flow_control(TelnetProxy *self, ZEndpoint ep)
{
  ZStream *other_stream = self->super.endpoints[EP_OTHER(ep)];

  z_stream_set_cond(self->super.endpoints[EP_CLIENT],
                    G_IO_IN,
                    !other_stream || z_stream_buf_space_avail(other_stream));
}

/**
 * telnet_main:
 * @s:
 *
 *
 */
static void
telnet_main(ZProxy *s)
{
  TelnetProxy *self = Z_CAST(s, TelnetProxy);

  z_proxy_enter(self);

  if (!telnet_check_valid_config(self) || !telnet_init_client_stream(self))
    {
      z_proxy_leave(self);
      return;
    }

  if (telnet_proxy_is_transparent(self))
    {
      /* No inband routing and no gateway authentication: connect right away to the server */
      if (!z_proxy_connect_server(&self->super, NULL, 0) ||
          !telnet_init_server_stream(self))
        {
          telnet_change_state(self, TELNET_STATE_QUIT);
        }
      else
        {
          telnet_change_state_to_connected(self);
          /* start TLS as neccessary. */
          if (!telnet_tls_is_negotiation_complete(self) &&
              !telnet_tls_start_negotiate(self))
            {
              z_proxy_log(self, TELNET_ERROR, 3, "TLS negotiation error;");
              telnet_change_state(self, TELNET_STATE_QUIT);
            }

          telnet_event_print_banner(self);
        }
    }
  else
    {
      /* start option negotiation with client */
      telnet_event_start_opneg(self);
    }

  z_proxy_log(self, TELNET_DEBUG, 6, "Entering main loop;");

  while (proxy_is_running(self))
    {
      if (!z_proxy_loop_iteration(s) ||
          !z_poll_iter_timeout(self->poll, self->timeout) ||
          !telnet_protocol_is_running(&self->protocol[EP_CLIENT]) ||
          !telnet_protocol_is_running(&self->protocol[EP_SERVER]))
        {
          telnet_change_state(self, TELNET_STATE_QUIT);
          break;
        }

      switch (self->state)
        {
        case TELNET_STATE_WAIT_OPNEG:
          telnet_state_nt_wait_opneg(self);
          break;

        case TELNET_STATE_WAIT_ENVIRONMENT:
          telnet_state_nt_wait_environment(self);
          break;

        case TELNET_STATE_PROMPT_USER:
          telnet_state_nt_prompt_user(self);
          break;

        case TELNET_STATE_PROMPT_PASSWORD:
          telnet_state_nt_prompt_password(self);
          break;

        case TELNET_STATE_PROMPT_SERVER:
          telnet_state_nt_prompt_server(self);
          break;

        case TELNET_STATE_RELAYING:
          break;

        case TELNET_STATE_QUIT:
          break;
        };

      telnet_stream_update_flow_control(self, EP_CLIENT);
      telnet_stream_update_flow_control(self, EP_SERVER);
    }

  z_proxy_log(self, TELNET_DEBUG, 6, "Leaving main loop;");

  telnet_deinit_streams(self);
  z_proxy_leave(self);
}

/**
 * telnet_proxy_free:
 * @s:
 *
 *
 */
static void
telnet_proxy_free(ZObject *s)
{
  TelnetProxy *self = Z_CAST(s, TelnetProxy);

  z_enter();


  telnet_lineedit_destroy(&self->line_editor);
  telnet_protocol_destroy(&self->protocol[EP_CLIENT]);
  telnet_protocol_destroy(&self->protocol[EP_SERVER]);

  g_string_free(self->gateway_password, TRUE);

  z_poll_unref(self->poll);
  self->poll = NULL;

  z_proxy_free_method(s);
  z_return();
}

/**
 * telnet_proxy_new:
 * @params:
 *
 *
 *
 * Returns:
 *
 */
static ZProxy *
telnet_proxy_new(ZProxyParams *params)
{
  TelnetProxy *self;

  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(TelnetProxy), params), TelnetProxy);

  z_return((ZProxy *) self);
}

static void telnet_proxy_free(ZObject *s);

ZProxyFuncs telnet_proxy_funcs =
  {
    {
      Z_FUNCS_COUNT(ZProxy),
      telnet_proxy_free,
    },
    /* .config = */ telnet_config,
    /* .startup = */ NULL,
    /* .main = */ telnet_main,
    /* .shutdown = */ NULL,
    /* .destroy = */ NULL,
    /* .nonblocking_init = */ NULL,
    /* .nonblocking_deinit = */ NULL,
    /* .wakeup = */ NULL,
  };

Z_CLASS_DEF(TelnetProxy, ZProxy, telnet_proxy_funcs);

static ZProxyModuleFuncs telnet_module_funcs =
  {
    /* .create_proxy = */ telnet_proxy_new,
    /* .module_py_init = */ NULL
  };

/**
 * zorp_module_init:
 *
 * Returns:
 *
 */
gint
zorp_module_init(void)
{
  z_registry_add("telnet", ZR_PROXY, &telnet_module_funcs);
  return TRUE;
}
