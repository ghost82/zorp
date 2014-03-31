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

#include "telnetoption.h"
#include "telnet.h"

/* option negotiation state */
enum
  {
    OPTION_DO        = 1,   /* our peer is using the option (peer sent WILL & we've replied DO or we sent DO & peer replied WILL) */
    OPTION_WILL      = 2,   /* we're using the option (we sent WILL & peer replied DO or peer sent DO & we sent WILL) */
    OPTION_WANT_DO   = 4,   /* we'd like our peer to use the option */
    OPTION_WANT_WILL = 8,   /* we'd like to use the option */
  };

typedef guint8 TelnetOptionState;

static inline TelnetOptionState *
telnet_option_state(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  return &self->options[option][ep];
}

static inline gboolean
state_will(TelnetOptionState state)
{
  return !!(state & OPTION_WILL);
}

static inline gboolean
state_do(TelnetOptionState state)
{
  return !!(state & OPTION_DO);
}

static inline gboolean
do_in_progress(const TelnetOptionState state)
{
  /* our want state isn't the same as our state */
  return !!(state & OPTION_DO) ^ !!(state & OPTION_WANT_DO);
}

static inline gboolean
will_in_progress(const TelnetOptionState state)
{
  /* our want state isn't the same as our state */
  return !!(state & OPTION_WILL) ^ !!(state & OPTION_WANT_WILL);
}

gboolean
telnet_option_do_in_progress(TelnetProxy *self, const ZEndpoint ep, const guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  return do_in_progress(*state);
}

gboolean
telnet_option_will_in_progress(TelnetProxy *self, const ZEndpoint ep, const guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  return will_in_progress(*state);
}

gboolean
telnet_option_do(TelnetProxy *self, const ZEndpoint ep, const guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  return !do_in_progress(*state) && state_do(*state);
}

gboolean
telnet_option_will(TelnetProxy *self, const ZEndpoint ep, const guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  return !will_in_progress(*state) && state_will(*state);
}

/* We'd like to use the option */
static void
request_will(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  *state |= OPTION_WANT_WILL;
}

/* We've received a will response for a do we've sent */
static void
response_will(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  *state |= OPTION_DO;
}

/* We'd like our peer to use the option */
static void
request_do(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  *state |= OPTION_WANT_DO;
}

/* We've received a do response for a will/won't we've sent */
static void
response_do(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  *state |= OPTION_WILL;
}

/* We wouldn't like to use the option */
static void
request_wont(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  *state &= ~OPTION_WANT_WILL;
}

/* We've received a won't response for a do/don't we've sent */
static void
response_wont(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  *state &= ~(OPTION_DO | OPTION_WANT_DO);
}

/* we'd like our peer not to use the option */
static void
request_dont(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  *state &= ~OPTION_WANT_DO;
}

/* we've received a don't response for a will/won't we've sent */
static void
response_dont(TelnetProxy *self, ZEndpoint ep, guint8 option)
{
  TelnetOptionState *state = telnet_option_state(self, ep, option);

  *state &= ~(OPTION_WILL | OPTION_WANT_WILL);
}

void
telnet_option_command_received(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option)
{
  switch (command)
    {
    case TELNET_CMD_WILL:
      response_will(self, ep, option);
      break;

    case TELNET_CMD_WONT:
      response_wont(self, ep, option);
      break;

    case TELNET_CMD_DO:
      response_do(self, ep, option);
      break;

    case TELNET_CMD_DONT:
      response_dont(self, ep, option);
      break;

    default:
      z_proxy_log(self, TELNET_VIOLATION, 1, "Unknown command; command='%hhu'", command);
      g_assert_not_reached();
      break;
    }
}

void
telnet_option_command_sent(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option)
{
  switch (command)
    {
    case TELNET_CMD_WILL:
      request_will(self, ep, option);
      break;

    case TELNET_CMD_WONT:
      request_wont(self, ep, option);
      break;

    case TELNET_CMD_DO:
      request_do(self, ep, option);
      break;

    case TELNET_CMD_DONT:
      request_dont(self, ep, option);
      break;

    default:
      z_proxy_log(self, TELNET_VIOLATION, 1, "Unknown command; command='%hhu'", command);
      g_assert_not_reached();
      break;
    }
}

/*
  # Local Variables:
  # indent-tabs-mode: nil
  # End:
*/
