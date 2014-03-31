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

#ifndef ZORP_MODULES_TELNET_TELNET_H_INCLUDED
#define ZORP_MODULES_TELNET_TELNET_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/proxy.h>
#include <zorp/poll.h>
#include <zorp/dimhash.h>
#include <zorp/authprovider.h>

#include "telnetprotocol.h"
#include "telnetlineedit.h"

/* Telnet command codes */

/* RFC 854 */
enum _TelnetCommands
  {
    TELNET_CMD_SE = 240,
    TELNET_CMD_NOP = 241,
    TELNET_CMD_DATAMARK = 242,
    TELNET_CMD_BRK = 243,
    TELNET_CMD_IP = 244,
    TELNET_CMD_AO = 245,
    TELNET_CMD_AYT = 246,
    TELNET_CMD_EC = 247,
    TELNET_CMD_EL = 248,
    TELNET_CMD_GA = 249,
    TELNET_CMD_SB = 250,
    TELNET_CMD_WILL = 251,
    TELNET_CMD_WONT = 252,
    TELNET_CMD_DO = 253,
    TELNET_CMD_DONT = 254,
    TELNET_IAC = 255,
  };

/* Telnet option codes */
enum _TelnetOptionCode
  {
    /* RFC 856 - TELNET binary transmission */
    TELNET_OPTION_BINARY = 0,
    /* RFC 857 - TELNET echo */
    TELNET_OPTION_ECHO = 1,
    /* RFC 858 - TELNET suppress go ahead */
    TELNET_OPTION_SUPPRESS_GO_AHEAD = 3,
    /* RFC 1091 - TELNET terminal-type */
    TELNET_OPTION_TERMINAL_TYPE = 24,
    /* RFC 885 - TELNET end of record */
    TELNET_OPTION_EOR = 25,
    /* RFC 1073 - TELNET windows size option */
    TELNET_OPTION_NAWS = 31,
    /* RFC 1079 - TELNET terminal speed */
    TELNET_OPTION_TERMINAL_SPEED = 32,
    /* RFC 1372 - TELNET remote flow control */
    TELNET_OPTION_TOGGLE_FLOW_CONTROL = 33,
    /* RFC 1184 - TELNET linemode */
    TELNET_OPTION_LINEMODE = 34,
    /* RFC 1096 - TELNET X display location */
    TELNET_OPTION_X_DISPLAY_LOCATION = 35,
    /* RFC 1572 - TELNET environment option */
    TELNET_OPTION_ENVIRONMENT = 39,
    /* INTERNET-DRAFT draft-altman-telnet-starttls-02.txt */
    TELNET_OPTION_STARTTLS = 46,
  };

/* RFC 1091 - TELNET terminal-type */
enum
  {
    TELNET_SB_TERMINAL_TYPE_IS = 0,
    TELNET_SB_TERMINAL_TYPE_SEND = 1,
  };

/* RFC 1079 - TELNET terminal speed */
enum
  {
    TELNET_SB_TERMINAL_SPEED_IS = 0,
    TELNET_SB_TERMINAL_SPEED_SEND = 1,
  };

/* RFC 1096 - TELNET X display location */
enum
  {
    TELNET_SB_X_DISPLAY_LOCATION_IS = 0,
    TELNET_SB_X_DISPLAY_LOCATION_SEND = 1,
  };

/* RFC 1572 - TELNET environment option */
enum
  {
    TELNET_SB_ENVIRONMENT_IS = 0,
    TELNET_SB_ENVIRONMENT_SEND = 1,
    TELNET_SB_ENVIRONMENT_INFO = 2,
  };

enum
  {
    TELNET_OPTARG_ENVIRONMENT_VAR = 0,
    TELNET_OPTARG_ENVIRONMENT_VALUE = 1,
    TELNET_OPTARG_ENVIRONMENT_ESC = 2,
    TELNET_OPTARG_ENVIRONMENT_USERVAR = 3,
  };

#define TELNET_BUFFER_SIZE      16384

#define TELNET_AUDIT_FORMAT_VERSION        "0.0"

struct _TelnetProxy;

typedef ZVerdict (*TelnetOptionFunction)(struct _TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option);
typedef ZVerdict (*TelnetSuboptionFunction)(struct _TelnetProxy *self, ZEndpoint ep, guint8 option, ZPktBuf *suboption);

typedef struct _TelnetOptions
{
  guint8                  option;
  TelnetOptionFunction    option_check;
} TelnetOptions;

typedef struct _TelnetSuboptions
{
  guint8                  suboption;
  TelnetSuboptionFunction suboption_check;
} TelnetSuboptions;

typedef enum _TelnetState
  {
    /* States preceding server connection */
    TELNET_STATE_WAIT_OPNEG,
    TELNET_STATE_WAIT_ENVIRONMENT,
    TELNET_STATE_PROMPT_USER,
    TELNET_STATE_PROMPT_PASSWORD,
    TELNET_STATE_PROMPT_SERVER,
    /* Proxy is relaying */
    TELNET_STATE_RELAYING,
    TELNET_STATE_QUIT,
  } TelnetState;

/**
 * See Telnet STARTTLS draft for details (http://tools.ietf.org/html/draft-altman-telnet-starttls-02).
 */
typedef enum _TelnetTlsStatus
  {
    TELNET_TLS_STATUS_NONE,
    TELNET_TLS_STATUS_CLIENT_REQUESTED_TLS, /* IAC WILL START_TLS */
    TELNET_TLS_STATUS_SERVER_REQUESTED_TLS, /* IAC DO START_TLS */
    TELNET_TLS_STATUS_CLIENT_STARTING_TLS, /* IAC WILL START_TLS */
    TELNET_TLS_STATUS_CLIENT_STARTING_TLS_FOLLOWS, /* IAC SB START_TLS FOLLOWS IAC SE */
    TELNET_TLS_STATUS_SERVER_CONFIRMED_STARTING_TLS, /* IAC SB START_TLS FOLLOWS IAC SE */
    TELNET_TLS_STATUS_HANDSHAKE_STARTED,
  } TelnetTlsStatus;

#define TELNET_REQUEST      "telnet.request"
#define TELNET_RESPONSE     "telnet.response"
#define TELNET_DEBUG        "telnet.debug"
#define TELNET_VIOLATION    "telnet.violation"

#define TELNET_ERROR        "telnet.error"
#define TELNET_POLICY       "telnet.policy"
#define TELNET_VIOLATION    "telnet.violation"
#define TELNET_INFO         "telnet.info"
#define TELNET_AUTH         "telnet.auth"

typedef struct _TelnetProxy
{
  ZProxy super;

  /* Policy level variables */

  /* timeout in milliseconds */
  gint                    timeout;

  /* policy hash */
  ZDimHashTable           *telnet_policy;

  /* options <-> commands link hash keyed by the command */
  GHashTable              *negotiation;

  /* variables for the policy callbacks to be able to make changes */
  GString                 *policy_name, *policy_value;

  ZAuthProvider *auth;          /**< inband authentication provider */

  gboolean auth_server;         /**< server user is authenticated in Zorp too */

  /* not zero for a transparent proxy */
  guint transparent;

  /* gateway authentication required */
  guint gw_auth_required;

  /* hostname we're connecting to (in case of inband routing) */
  GString *server_hostname;
  /* true if the host name came from either the SERVER or USER variable */
  gboolean server_hostname_is_from_env;
  /* port we're using to connect to the hostname (in case of inband routing) */
  guint server_port;
  /* username we're using to connect to the hostname (in case of inband routing) */
  GString *username;

  /* username we're using for gateway authentication */
  GString *gateway_user;
  /* true if the username came from the GW_USER environment variable */
  gboolean gateway_user_is_from_env;

  /* password to use for gateway authentication */
  GString *gateway_password;
  /* true if the password came from the GW_PASSWD environment variable */
  gboolean gateway_password_is_from_env;
  /* number of unsuccessful gateway authentication attempts */
  guint gw_authentication_failures;

  /* banner to print to client in non-transparent mode */
  GString *banner;

  /* server name prompt string sent to the client */
  GString *server_name_prompt;
  /* gateway user name prompt string sent to the client for inband auth */
  GString *gateway_user_prompt;
  /* gateway password prompt string */
  GString *gateway_password_prompt;

  /* Private variables */
  TelnetState             state;
  gboolean server_stream_initialized;
  gboolean environment_is_received;

  TelnetProtocol          protocol[EP_MAX];
  TelnetLineEdit          line_editor;

  /* option negotiation state */
  guint8                  options[256][EP_MAX];
  guint8                  do_dont_requested[256][EP_MAX];
  guint8                  will_wont_requested[256][EP_MAX];

  /* suboption check function lookup table */
  TelnetSuboptionFunction telnet_suboptions[256];

  /* option check function lookup table */
  TelnetOptionFunction    telnet_option_negotiation_handlers[256];


  /* Whether the connection requires STARTTLS before sending any data */
  gboolean                tls_required[EP_MAX];
  gboolean                tls_completed[EP_MAX];
  TelnetTlsStatus         tls_status[EP_MAX];


  ZPoll                   *poll;
} TelnetProxy;

extern ZClass TelnetProxy__class;


/* I/O */
GIOStatus telnet_send_suboption(TelnetProxy *self, ZEndpoint ep, ZPktBuf *suboption);
GIOStatus telnet_send_command(TelnetProxy *self, ZEndpoint ep, guint8 command);
GIOStatus telnet_send_opneg(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option);
GIOStatus telnet_send_data(TelnetProxy *self, ZEndpoint ep, ZPktBuf *data);

GIOStatus telnet_write_packet(TelnetProxy *self, ZEndpoint ep, ZPktBuf *pkt);

/* State machine helpers */
void telnet_change_state(TelnetProxy *self, TelnetState state);


static inline gboolean
telnet_state_is_lineedit(TelnetProxy *self)
{
  return (self->state == TELNET_STATE_PROMPT_SERVER
          || self->state == TELNET_STATE_PROMPT_USER
          || self->state == TELNET_STATE_PROMPT_PASSWORD
          );
}

static inline gboolean
telnet_state_is_pattern_matching(TelnetProxy *self)
{
  return self != self;
}

static inline gboolean
telnet_state_is_connected(TelnetProxy *self)
{
  return self->state == TELNET_STATE_RELAYING || telnet_state_is_pattern_matching(self);
}

static inline gboolean
telnet_proxy_is_transparent(TelnetProxy *self)
{
  return (self->transparent && !self->gw_auth_required);
}

void telnet_event_connect_server(TelnetProxy *self);

ZPktBuf *
telnet_user_string_to_pktbuf(GString *msg);

#endif
