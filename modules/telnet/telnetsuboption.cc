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
 * Author: Hidden
 *
 ***************************************************************************/

#include "telnet.h"
#include "telnetpolicy.h"
#include "telnetoption.h"

#include <zorp/log.h>

#include <string.h>
#include <ctype.h>

#define TELNET_POLICY                   "telnet.policy"
#define TELNET_DEBUG                    "telnet.debug"

/* virtual variable names */
#define TELNET_POLICY_TERMTYPE_NAME     "TERMINAL_TYPE"
#define TELNET_POLICY_TERMSPEED_NAME    "TERMINAL_SPEED"
#define TELNET_POLICY_XDISPLAY_NAME     "X_DISPLAY_LOCATION"
#define TELNET_POLICY_NAWS_NAME         "WINDOW_SIZE"

/* size of buffers used in suboption processing functions */
enum
  {
    TELNET_TERMINAL_TYPE_MAX_LENGTH = 128,
    TELNET_TERMINAL_SIZE_MAX_LENGTH = 64,
    TELNET_X_DISPLAY_LOCATION_MAX_LENGTH = 128,
    TELNET_TERMINAL_SPEED_MAX_LENGTH = 64,
    TELNET_NEW_ENVIRONMENT_MAX_LENGTH = 512,
  };

static inline void
update_suboption_value_in_buffer_from_str(ZPktBuf *buf, const GString *value)
{
  /* keep only the option and the subcommand byte in buffer */
  z_pktbuf_resize(buf, 2);
  /* replace the rest with the string contents */
  z_pktbuf_put_u8s(buf, value->len, reinterpret_cast<guchar *>(value->str));
}

static inline void
update_suboption_value_in_buffer(ZPktBuf *buf, ZPktBuf *value)
{
  /* keep only the option and the subcommand byte in buffer */
  z_pktbuf_resize(buf, 2);
  /* replace the rest with the string contents */
  z_pktbuf_put_u8s(buf, z_pktbuf_length(value), static_cast<unsigned char *>(z_pktbuf_data(value)));
}

static inline void
set_string_from_buffer_contents(GString *string, ZPktBuf *buf)
{
  gsize len = z_pktbuf_available(buf);

  g_string_truncate(string, len);
  g_string_overwrite_len(string, 0, reinterpret_cast<gchar *>(z_pktbuf_current(buf)), len);
}

static inline gboolean
terminal_type_value_validate(GString *terminal_type)
{
  for (guint i = 0; i < terminal_type->len; i++)
    {
      gchar c = terminal_type->str[i];
      if (!g_ascii_isalnum(c) && c != '-')
        return FALSE;
    }
  return TRUE;
}

/**
 * @brief Suboption filter function for TERMINAL TYPE.
 * @param self TelnetProxy instance
 * @param ep Endpoint we've received the suboption from
 * @param option Option code (should always be TELNET_OPTION_TERMINAL_TYPE)
 * @param[in,out] suboption_buffer The packet buffer containing the suboption value (including subcommands).
 *
 * The function may modify suboption_buffer: on successful return the contents
 * of suboption_buffer will be sent to the other endpoint.
 *
 * @return ZV_ACCEPT if the suboption has been accepted, ZV_DROP otherwise.
 */
ZVerdict
telnet_subopt_terminal_type(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption_buffer)
{
  ZVerdict res = ZV_ABORT;

  z_proxy_enter(self);

  guint8 subcommand;
  if (!z_pktbuf_get_u8(suboption_buffer, &subcommand))
    {
      z_proxy_log(self, TELNET_VIOLATION, 1, "TERMINAL TYPE suboption has invalid subcommand length;");
      z_proxy_return(self, ZV_DROP);
    }

  switch (subcommand)
    {
    case TELNET_SB_TERMINAL_TYPE_SEND:
      /* no extra data permitted for this subcommand */
      if (z_pktbuf_available(suboption_buffer) != 0)
        {
          z_proxy_log(self, TELNET_VIOLATION, 1, "TERMINAL TYPE SEND suboption has invalid subcommand length;");
          z_proxy_return(self, ZV_DROP);
        }

      /* SEND is sent by the Telnet server: check if this side sent DO and we've sent WILL */
      if (!telnet_option_will(self, ep, option))
        {
          z_proxy_log(self, TELNET_POLICY, 3, "TERMINAL TYPE SEND option not allowed from this side; side='%s'", EP_STR(ep));
          z_proxy_return(self, ZV_DROP);
        }

      g_string_assign(self->policy_name, TELNET_POLICY_TERMTYPE_NAME);
      g_string_assign(self->policy_value, "");
      res = telnet_policy_suboption(self, ep, option, subcommand, TELNET_POLICY_TERMTYPE_NAME, "");
      break;

    case TELNET_SB_TERMINAL_TYPE_IS:
      /* IS is sent by the Telnet client: check if this side sent WILL and we've acked it with a DO */
      if (!telnet_option_do(self, ep, option))
        {
          z_proxy_log(self, TELNET_POLICY, 3, "TERMINAL TYPE IS option not allowed from this side; side='%s'", EP_STR(ep));
          z_proxy_return(self, ZV_DROP);
        }

      if (z_pktbuf_available(suboption_buffer) > TELNET_TERMINAL_TYPE_MAX_LENGTH)
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "Invalid TERMINAL TYPE value, it is too long;");
          z_proxy_return(self, ZV_DROP);
        }

      set_string_from_buffer_contents(self->policy_value, suboption_buffer);
      if (!terminal_type_value_validate(self->policy_value))
        {
          /* FIXME: the value should be logged */
          z_proxy_log(self, TELNET_VIOLATION, 3, "Invalid TERMINAL TYPE value, it contains invalid characters;");
          z_proxy_return(self, ZV_DROP);
        }

      z_proxy_log(self, TELNET_DEBUG, 6, "TERMINAL TYPE option; value='%s'", self->policy_value->str);
      g_string_assign(self->policy_name, TELNET_POLICY_TERMTYPE_NAME);

      res = telnet_policy_suboption(self, ep, option, subcommand, TELNET_POLICY_TERMTYPE_NAME, self->policy_value->str);
      if (res == ZV_ACCEPT)
        {

          /* copy possibly changed value from policy_value back to the buffer */
          update_suboption_value_in_buffer_from_str(suboption_buffer, self->policy_value);
        }

      break;

    default:
      /* suboption code is  INVALID */
      z_proxy_log(self, TELNET_VIOLATION, 3, "TERMINAL TYPE option, invalid subcommand or invalid suboption length;");
      z_proxy_return(self, ZV_DROP);
    }

  z_proxy_return(self, res);
}

static inline gboolean
terminal_speed_value_validate(GString *terminal_type)
{
  for (guint i = 0; i < terminal_type->len; i++)
    {
      gchar c = terminal_type->str[i];
      if (!g_ascii_isdigit(c) && c != ',')
        return FALSE;
    }
  return TRUE;
}

/**
 * telnet_opt_terminal_speed:
 * @self:
 * @ep:
 *
 *
 *
 * Returns:
 *
 */
ZVerdict
telnet_subopt_terminal_speed(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption_buffer)
{
  ZVerdict res = ZV_ABORT;

  z_proxy_enter(self);

  guint8 subcommand;
  if (!z_pktbuf_get_u8(suboption_buffer, &subcommand))
    {
      z_proxy_log(self, TELNET_VIOLATION, 1, "TERMINAL SPEED IS suboption has invalid subcommand length;");
      z_proxy_return(self, ZV_DROP);
    }

  switch (subcommand)
    {
    case TELNET_SB_TERMINAL_SPEED_SEND:
      /* no extra data permitted for this subcommand */
      if (z_pktbuf_available(suboption_buffer) != 0)
        {
          z_proxy_log(self, TELNET_VIOLATION, 1, "TERMINAL SPEED SEND suboption has invalid subcommand length;");
          z_proxy_return(self, ZV_DROP);
        }

      /* SEND is normally sent by the side sending the DO: check if this side sent DO and we've sent WILL */
      if (!telnet_option_will(self, ep, option))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "TERMINAL SPEED SEND option not allowed from this side; side='%s'", EP_STR(ep));
          z_proxy_return(self, ZV_DROP);
        }

      g_string_assign(self->policy_name, TELNET_POLICY_TERMSPEED_NAME);
      g_string_assign(self->policy_value, "");
      res = telnet_policy_suboption(self, ep, option, subcommand, TELNET_POLICY_TERMSPEED_NAME, "");
      break;

    case TELNET_SB_TERMINAL_SPEED_IS:
      /* check if this side sent WILL and we've acked it with a DO */
      if (!telnet_option_do(self, ep, option))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "TERMINAL SPEED IS option not allowed from this side; side='%s'", EP_STR(ep));
          z_proxy_return(self, ZV_DROP);
        }

      if (z_pktbuf_available(suboption_buffer) > TELNET_TERMINAL_SPEED_MAX_LENGTH)
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "TERMINAL SPEED IS option, value too long");
          z_proxy_return(self, ZV_DROP);
        }

      set_string_from_buffer_contents(self->policy_value, suboption_buffer);
      if (!terminal_speed_value_validate(self->policy_value))
        {
          /* FIXME: the value should be logged */
          z_proxy_log(self, TELNET_VIOLATION, 3, "Invalid TERMINAL SPEED value, it contains invalid characters;");
          z_proxy_return(self, ZV_DROP);
        }

      z_proxy_log(self, TELNET_DEBUG, 6, "TERMINAL SPEED IS option; value='%s'", self->policy_value->str);
      g_string_assign(self->policy_name, TELNET_POLICY_TERMSPEED_NAME);
      res = telnet_policy_suboption(self, ep, option, subcommand, TELNET_POLICY_TERMSPEED_NAME, self->policy_value->str);
      if (res == ZV_ACCEPT)
        {
          /* copy possibly changed value from policy_value back to the buffer */
          update_suboption_value_in_buffer_from_str(suboption_buffer, self->policy_value);
        }
      break;

    default:
      z_proxy_log(self, TELNET_VIOLATION, 3, "TERMINAL SPEED option, invalid subcommand;");
      z_proxy_return(self, ZV_DROP);
    }

  z_proxy_return(self, res);
}

static inline gboolean
x_display_value_validate(GString *terminal_type)
{
  for (guint i = 0; i < terminal_type->len; i++)
    {
      gchar c = terminal_type->str[i];
      if (!g_ascii_isalnum(c) && c != '.' && c != ':' && c != '_' && c != '-')
        return FALSE;
    }
  return TRUE;
}

/**
 * telnet_opt_x_display:
 * @self:
 * @ep:
 *
 *
 *
 * Returns:
 *
 */
ZVerdict
telnet_subopt_x_display(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption_buffer)
{
  ZVerdict res = ZV_ABORT;

  z_proxy_enter(self);

  guint8 subcommand;
  if (!z_pktbuf_get_u8(suboption_buffer, &subcommand))
    {
      z_proxy_log(self, TELNET_VIOLATION, 1, "X DISPLAY LOCATION suboption has invalid subcommand length;");
      z_proxy_return(self, ZV_DROP);
    }

  switch (subcommand)
    {
    case TELNET_SB_X_DISPLAY_LOCATION_SEND:
      /* no extra data permitted for this subcommand */
      if (z_pktbuf_available(suboption_buffer) != 0)
        {
          z_proxy_log(self, TELNET_VIOLATION, 1, "X DISPLAY LOCATION SEND suboption has invalid subcommand length;");
          z_proxy_return(self, ZV_DROP);
        }

      /* check if this side sent DO and we've acked it with WILL */
      if (!telnet_option_will(self, ep, option))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "X DISPLAY LOCATION SEND option is not allowed from this side;");
          z_proxy_return(self, ZV_DROP);
        }

      g_string_assign(self->policy_name, TELNET_POLICY_XDISPLAY_NAME);
      g_string_assign(self->policy_value, "");
      res = telnet_policy_suboption(self, ep, option, subcommand, TELNET_POLICY_XDISPLAY_NAME, "");

      break;

    case TELNET_SB_X_DISPLAY_LOCATION_IS:
      /* check if this side sent WILL and we've acked it with a DO */
      if (!telnet_option_do(self, ep, option))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "X DISPLAY LOCATION IS option not allowed from this side; side='%s'", EP_STR(ep));
          z_proxy_return(self, ZV_DROP);
        }

      if (z_pktbuf_available(suboption_buffer) >= TELNET_X_DISPLAY_LOCATION_MAX_LENGTH)
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "X DISPLAY LOCATION IS option, value too long;");
          z_proxy_return(self, ZV_DROP);
        }

      set_string_from_buffer_contents(self->policy_value, suboption_buffer);
      if (!x_display_value_validate(self->policy_value))
        {
          /* FIXME: the value should be logged */
          z_proxy_log(self, TELNET_VIOLATION, 3, "Invalid X DISPLAY LOCATION value, it contains invalid characters;");
          z_proxy_return(self, ZV_DROP);
        }

      z_proxy_log(self, TELNET_DEBUG, 6, "X DISPLAY LOCATION IS option; value='%s'", self->policy_value->str);

      g_string_assign(self->policy_name, TELNET_POLICY_XDISPLAY_NAME);
      res = telnet_policy_suboption(self, ep, option, subcommand, TELNET_POLICY_XDISPLAY_NAME, self->policy_value->str);
      if (res == ZV_ACCEPT)
        update_suboption_value_in_buffer_from_str(suboption_buffer, self->policy_value);

      break;

    default:
      z_proxy_log(self, TELNET_VIOLATION, 3, "X DISPLAY LOCATION option, invalid subcommand or invalid suboption length;");
      z_proxy_return(self, ZV_DROP);

    }

  z_proxy_return(self, res);
}

static void
parse_environment_name_or_value(GString *string, ZPktBuf *buf)
{
  g_string_truncate(string, 0);

  guint8 byte;
  while (z_pktbuf_get_u8(buf, &byte))
    {
      if (byte == TELNET_OPTARG_ENVIRONMENT_VAR ||
          byte == TELNET_OPTARG_ENVIRONMENT_USERVAR ||
          byte == TELNET_OPTARG_ENVIRONMENT_VALUE)
        {
          /* end of name or value, rewind one byte */
          z_pktbuf_seek(buf, G_SEEK_CUR, -1);
          break;
        }

      if (byte == TELNET_OPTARG_ENVIRONMENT_ESC ||
          byte == TELNET_IAC)
        /* the next byte is escaped */
        if (!z_pktbuf_get_u8(buf, &byte))
          break;

      g_string_append_c(string, byte);
    }
}

static ZVerdict
filter_user_variable(TelnetProxy *self)
{
  ZVerdict res;
  if (!telnet_state_is_connected(self))
    {
      if (!telnet_policy_parse_authinfo(self, "USER", self->policy_value))
        {
          z_proxy_log(self, TELNET_REQUEST, 1, "Invalid USER value for inband routing or gateway authentication, aborting session;");
          res = ZV_ABORT;
        }
      else
        {
          z_proxy_log(self, TELNET_DEBUG, 6, "USER environment variable successfully parsed;");
          res = ZV_ACCEPT;
        }
    }
  else
    {
      /* if any part of the USER variable might have been used
       * make sure the USER variable only contains the user name to be used on the server */
      if (self->server_hostname_is_from_env || self->gateway_user_is_from_env)
        g_string_assign_len(self->policy_value, self->username->str, self->username->len);

      res = ZV_ACCEPT;
    }

  return res;
}

static ZVerdict
filter_special_variable(TelnetProxy *self)
{
  ZVerdict res = ZV_DROP;

  z_proxy_enter(self);

  /* might possibly be an inband routing / auth related variable, make sure we pre-process it */
  if (strcmp(self->policy_name->str, "SERVER") == 0)
    {
      if (!telnet_state_is_connected(self) &&
          !telnet_policy_parse_authinfo(self, "SERVER", self->policy_value))
        {
          z_proxy_log(self, TELNET_REQUEST, 1, "Invalid SERVER value for inband routing, aborting session;");
          res = ZV_ABORT;
        }
      else
        /* either the server name was parsed successfully or we have
         * already connected to the server: we have to make sure that the
         * SERVER variable will not get sent to the server */
        res = ZV_DROP;
    }
  else if (strcmp(self->policy_name->str, "USER") == 0)
    {
      res = filter_user_variable(self);
    }
  else if (strcmp(self->policy_name->str, "GW_USER") == 0 &&
           self->gw_auth_required)
    {
      if (!telnet_state_is_connected(self) &&
          self->gateway_user->len == 0)
        {
          g_string_assign(self->gateway_user, self->policy_value->str);
          self->gateway_user_is_from_env = TRUE;

          z_proxy_log(self, TELNET_DEBUG, 7, "Telnet suboption negotiation GW_USER variable; value='%s'",
                      self->policy_value->str);
        }

      /* drop this special variable */
      res = ZV_DROP;
    }
  else if (strcmp(self->policy_name->str, "GW_PASSWD") == 0 &&
           self->gw_auth_required)
    {
      if (!telnet_state_is_connected(self) &&
          self->gateway_password->len == 0)
        {
          g_string_assign(self->gateway_password, self->policy_value->str);
          self->gateway_password_is_from_env = TRUE;

          z_proxy_log(self, TELNET_DEBUG, 7, "Telnet suboption negotiation GW_PASS variable, value='%s'",
                      self->policy_value->str);
        }

      /* drop this special variable */
      res = ZV_DROP;
    }
  else
    /* not a special variable, handle as usual */
    res = ZV_ACCEPT;

  z_proxy_return(self, res);
}

/**
 * @brief Evaluate policy for a name/value pair and copy to filtered if it was accepted.
 * @param self TelnetProxy instance
 * @param ep proxy endpoint we've received the pair from
 * @param option Telnet option this belongs to
 * @param subcommand Telnet subcommand (eg. SEND, IS, etc.)
 * @param type Environment variable type
 * @param value_present TRUE if there was an explicit value set in self->policy_value
 * @param filtered Packet buffer collecting output
 *
 * The variable name is in self->policy_name and the value is in
 * self->policy_value.
 *
 * TELNET makes a distinction between a variable with an empty value and a
 * non-defined variable. Because of this, we cannot simpy check if
 * self->policy_value is non-empty to decide if a VALUE needs to be output. If
 * value_present is TRUE then we have to output a VALUE even for an empty
 * string.
 *
 * @return ZV_ACCEPT if the name/value pair has been accepted
 */
static ZVerdict
check_and_copy_environment_name_value_pair(TelnetProxy *self, ZEndpoint ep, guint8 option,
                                           guint8 subcommand, guint8 type, gboolean value_present,
                                           ZPktBuf *filtered)
{
  ZVerdict res = ZV_ACCEPT;

  z_proxy_log(self, TELNET_DEBUG, 6, "Evaluating NEW-ENVIRON environment variable; type='%hhu', name='%s', value='%s'",
              type, self->policy_name->str, self->policy_value->str);

  if (subcommand == TELNET_SB_ENVIRONMENT_IS &&
      (type == TELNET_OPTARG_ENVIRONMENT_VAR || type == TELNET_OPTARG_ENVIRONMENT_USERVAR))
    {
      if (!telnet_proxy_is_transparent(self))
        {
          res = filter_special_variable(self);
        }
    }

  if (res == ZV_ACCEPT)
    res = telnet_policy_suboption(self, ep, option, subcommand, self->policy_name->str, self->policy_value->str);

  switch (res)
    {
    case ZV_ACCEPT:
      /* copy both name and value (if a value was present or it is non-empty after policy evaluation) */
      z_pktbuf_put_u8(filtered, type);
      z_pktbuf_put_u8s(filtered, self->policy_name->len, reinterpret_cast<guchar *>(self->policy_name->str));

      if (value_present || self->policy_value->len > 0)
        {
          z_pktbuf_put_u8(filtered, TELNET_OPTARG_ENVIRONMENT_VALUE);
          z_pktbuf_put_u8s(filtered, self->policy_value->len, reinterpret_cast<guchar *>(self->policy_value->str));
        }
      break;

    case ZV_REJECT:
      /* REJECT means only the name gets copied without an associated VALUE.
       * According to RFC 1572 this means that the variable is not defined. */
      z_pktbuf_put_u8(filtered, type);
      z_pktbuf_put_u8s(filtered, self->policy_name->len, reinterpret_cast<guchar *>(self->policy_name->str));
      break;

    default:
      /* otherwise we don't copy anything */
      break;
    }

  return res;
}

static ZVerdict
process_environment_send(TelnetProxy *self, ZEndpoint ep, guint8 option, guint8 subcommand, ZPktBuf *suboption_buffer)
{
  ZVerdict res = ZV_DROP;

  /* check if this side sent DO and we've acked it with WILL */
  if (!telnet_option_will(self, ep, option))
    {
      z_proxy_log(self, TELNET_VIOLATION, 3, "NEW-ENVIRON SEND option not allowed from this side; side='%s'", EP_STR(ep));
      z_proxy_return(self, ZV_DROP);
    }

  gsize name_list_size = z_pktbuf_available(suboption_buffer);
  if (name_list_size > TELNET_NEW_ENVIRONMENT_MAX_LENGTH)
    {
      z_proxy_log(self, TELNET_VIOLATION, 3, "NEW-ENVIRON SEND option, name list too long;");
      z_proxy_return(self, ZV_DROP);
    }

  if (name_list_size > 0)
    {
      ZPktBuf *filtered = z_pktbuf_new(); /* contains list of accepted names */

      /* variable name list not empty, iterate while there are bytes in the buffer */
      while (res != ZV_ABORT &&
             z_pktbuf_available(suboption_buffer) > 0)
        {
          guint8 type;

          /* parse type and name */
          z_pktbuf_get_u8(suboption_buffer, &type);

          if (type == TELNET_OPTARG_ENVIRONMENT_VAR ||
              type == TELNET_OPTARG_ENVIRONMENT_USERVAR)
            {
              parse_environment_name_or_value(self->policy_name, suboption_buffer);
              g_string_assign(self->policy_value, "");

              res = check_and_copy_environment_name_value_pair(self, ep, option, subcommand, type, FALSE, filtered);
            }
          else
            {
              /* unexpected type */
              z_proxy_log(self, TELNET_VIOLATION, 3, "NEW-ENVIRON option, invalid SEND request;");
              res = ZV_DROP;
              break;
            }
        }

      if (res != ZV_ABORT)
        res = ZV_ACCEPT;

      update_suboption_value_in_buffer(suboption_buffer, filtered);
      z_pktbuf_unref(filtered);
    }
  else
    {
      /* empty variable list */
      g_string_assign(self->policy_name, "");
      g_string_assign(self->policy_value, "");
      res = telnet_policy_suboption(self, ep, option, subcommand, "", "");
    }

  return res;
}

static ZVerdict
process_environment_is(TelnetProxy *self, ZEndpoint ep, guint8 option, guint8 subcommand, ZPktBuf *suboption_buffer)
{
  ZVerdict res = ZV_DROP;

  /* check if this side sent WILL and we've acked it with a DO */
  if (!telnet_option_do(self, ep, option))
    {
      z_proxy_log(self, TELNET_VIOLATION, 3, "NEW ENVIRON IS or INFO option not allowed from this side; side='%s'", EP_STR(ep));
      z_proxy_return(self, ZV_DROP);
    }

  if (!telnet_state_is_connected(self))
    self->environment_is_received = TRUE;

  gsize name_value_list_size = z_pktbuf_available(suboption_buffer);
  if (name_value_list_size > 0)
    {
      /* parse name-value list */
      ZPktBuf *filtered = z_pktbuf_new(); /* contains list of accepted name-value pairs */

      /* iterate while buffer is not empty */
      gboolean variable_name_set = FALSE;
      guint8 variable_type = TELNET_OPTARG_ENVIRONMENT_VAR;

      while (res != ZV_ABORT &&
             z_pktbuf_available(suboption_buffer) > 0)
        {
          guint8 type;
          z_pktbuf_get_u8(suboption_buffer, &type);

          if (type == TELNET_OPTARG_ENVIRONMENT_VAR || type == TELNET_OPTARG_ENVIRONMENT_USERVAR)
            {
              if (variable_name_set)
                {
                  /* there was a variable name without a value, do policy check anyway with an empty value */
                  g_string_assign(self->policy_value, "");
                  res = check_and_copy_environment_name_value_pair(self, ep, option, subcommand, variable_type, FALSE, filtered);
                }
              parse_environment_name_or_value(self->policy_name, suboption_buffer);
              variable_name_set = TRUE;
              variable_type = type;
            }
          else if (type == TELNET_OPTARG_ENVIRONMENT_VALUE)
            {
              parse_environment_name_or_value(self->policy_value, suboption_buffer);

              if (variable_name_set)
                {
                  res = check_and_copy_environment_name_value_pair(self, ep, option, subcommand, variable_type, TRUE, filtered);
                  variable_name_set = FALSE;
                }
              else
                /* multiple values without a variable name */
                res = ZV_DROP;
            }
          else
            {
              z_proxy_log(self, TELNET_VIOLATION, 5, "NEW-ENVIRON IS or INFO option, invalid reply;");
              res = ZV_DROP;
              break;
            }
        }

      if (res != ZV_ABORT && variable_name_set)
        {
          /* there was a variable name without a value, do policy check anyway with an empty value */
          g_string_assign(self->policy_value, "");
          res = check_and_copy_environment_name_value_pair(self, ep, option, subcommand, variable_type, FALSE, filtered);
        }

      if (res != ZV_ABORT)
        res = ZV_ACCEPT;

      update_suboption_value_in_buffer(suboption_buffer, filtered);
      z_pktbuf_unref(filtered);
    }
  else
    {
      /* empty variable list */
      g_string_assign(self->policy_name, "");
      g_string_assign(self->policy_value, "");
      res = telnet_policy_suboption(self, ep, option, subcommand, "", "");
    }

  return res;
}

/**
 * @brief Suboption filter function for TELNET NEW ENVIRONMENT extension
 * @param self TelnetProxy instance
 * @param ep Endpoint we've received the suboption from
 * @param option Option this suboption belongs to (should be TELNET_OPTION_ENVIRONMENT)
 * @param suboption_buffer Packet buffer contatining suboption data
 *
 * Environment variable name/value pairs are parsed and processed one-by-one by this function.
 *
 * @return ZV_ACCEPT if the suboption was accepted, ZV_DROP if it was dropped,
 * ZV_ABORT if the proxy needs to be aborted
 */
ZVerdict
telnet_subopt_new_env(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption_buffer)
{
  ZVerdict res = ZV_ABORT;

  z_proxy_enter(self);

  guint8 subcommand;
  if (!z_pktbuf_get_u8(suboption_buffer, &subcommand))
    {
      z_proxy_log(self, TELNET_VIOLATION, 1, "NEW ENVIRON suboption has invalid subcommand length;");
      z_proxy_return(self, ZV_DROP);
    }

  switch (subcommand)
    {
    case TELNET_SB_ENVIRONMENT_SEND:
      res = process_environment_send(self, ep, option, subcommand, suboption_buffer);
      break;

    case TELNET_SB_ENVIRONMENT_IS:
    case TELNET_SB_ENVIRONMENT_INFO:
      res = process_environment_is(self, ep, option, subcommand, suboption_buffer);
      break;

    default:
      z_proxy_log(self, TELNET_VIOLATION, 3, "NEW-ENVIRON option, invalid subcommand;");
      res = ZV_DROP;
    }

  z_proxy_return(self, res);
}

/**
 * @brief Suboption filter function for TELNET Negotiate About Window Size extension
 * @param self TelnetProxy instance
 * @param ep Endpoint we've received the suboption from
 * @param option Option this suboption belongs to (should be TELNET_OPTION_NAWS)
 * @param suboption_buffer Packet buffer containing suboption data
 *
 * @return ZV_ACCEPT if the suboption has been accepted, ZV_DROP if it was
 * dropped, ZV_ABORT if an unrecoverable error has happened
 */
ZVerdict
telnet_subopt_naws(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption_buffer)
{
  ZVerdict res = ZV_DROP;

  z_proxy_enter(self);

  if (z_pktbuf_available(suboption_buffer) != 4)
    {
      z_proxy_log(self, TELNET_VIOLATION, 1, "NAWS suboption has invalid length;");
      z_proxy_return(self, ZV_DROP);
    }

  /* check if this side sent WILL and we've acked it with a DO */
  if (!telnet_option_do(self, ep, option))
    {
      z_proxy_log(self, TELNET_VIOLATION, 3, "NAWS option not allowed from this side; side='%s'", EP_STR(ep));
      z_proxy_return(self, ZV_DROP);
    }

  guint16 width, height;
  z_pktbuf_get_u16_be(suboption_buffer, &width);
  z_pktbuf_get_u16_be(suboption_buffer, &height);

  g_string_assign(self->policy_name, TELNET_POLICY_NAWS_NAME);
  g_string_sprintf(self->policy_value, "%hu,%hu", width, height);

  res = telnet_policy_suboption(self, ep, option, 0, TELNET_POLICY_NAWS_NAME, self->policy_value->str);


  z_proxy_return(self, res);
}

/**
 * @brief Generic suboption filter function.
 * @param self TelnetProxy instance
 * @param ep Endpoint we've received the suboption from
 * @param option Option this suboption belongs to
 * @param suboption_buffer Packet buffer containing the suboption data
 *
 * @return ZV_ACCEPT if the suboption has been accepted, ZV_DROP otherwise
 */
ZVerdict
telnet_subopt_unknown(TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption_buffer)
{
  ZVerdict res = ZV_DROP;

  z_proxy_enter(self);

  guint8 subcommand;
  if (!z_pktbuf_get_u8(suboption_buffer, &subcommand))
    {
      z_proxy_log(self, TELNET_VIOLATION, 1, "Suboption does not contain a command;");
      z_proxy_return(self, ZV_DROP);
    }

  g_string_assign(self->policy_name, "");
  set_string_from_buffer_contents(self->policy_value, suboption_buffer);
  res = telnet_policy_suboption(self, ep, option, subcommand, self->policy_name->str, self->policy_value->str);

  z_proxy_return(self, res);
}
