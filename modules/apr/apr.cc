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
 * Author: Laszlo Attila Toth
 *
 ***************************************************************************/

#include <zorp/proxy.h>
#include <zorp/registry.h>
#include <zorp/streambuf.h>

#define APR_DUMP "apr.dump"
#define APR_DEBUG "apr.debug"
#define APR_ERROR "apr.error"

static const guint stream_buf_size = 65536;

typedef struct
{
  ZProxy super;
  ZPoll *poll;
  gint timeout;
  gboolean need_server_connect;
  gint copy_client_data;
  gboolean quit;
  ZPktBuf *data_buffer[EP_MAX];
  /**
   * Will pass stream to instance of this proxy class when set.
   */
  ZPolicyObj *service;
  gsize buffer_written_to_client;
} APRProxy;

static ZStream *
get_stream(APRProxy *self, gint side)
{
  return self->super.endpoints[side];
}

extern ZClass APRProxy__class;
static gboolean apr_read_callback(ZStream *stream, GIOCondition cond G_GNUC_UNUSED, gpointer user_data);

static void
apr_setup_stream(APRProxy *self, gint ep)
{
  self->super.endpoints[ep] = z_stream_push(self->super.endpoints[ep], z_stream_buf_new(NULL, stream_buf_size, Z_SBF_IMMED_FLUSH));
  z_poll_add_stream(self->poll, self->super.endpoints[ep]);
  z_stream_set_callback(get_stream(self, ep), G_IO_IN, apr_read_callback, self, NULL);
  z_stream_set_cond(get_stream(self, ep), G_IO_IN, TRUE);
}

static gboolean
apr_config_set_defaults(APRProxy *self)
{
  int i;
  for (i = 0; i < EP_MAX; ++i)
    self->data_buffer[i] = z_pktbuf_new();

  self->poll = z_poll_new();
  self->timeout = 600000;
  self->buffer_written_to_client = 0;

  return TRUE;
}

static gboolean
apr_continue_with_proxy(APRProxy *self)
{
  gint i;
  gboolean called;
  ZPolicyObj *pyres;

  for (i = EP_CLIENT; i < EP_MAX; i++)
    {
      if (self->super.endpoints[i])
        {
          /* NOTE: we flush out streams as some packets might be stucked */
          if (!z_stream_broken(self->super.endpoints[i]))
            {
              z_stream_buf_flush(self->super.endpoints[i]);
              z_stream_set_nonblock(self->super.endpoints[i], FALSE);
            }

          /* Prepare stream for passing to other proxy */
          z_stream_set_cond(self->super.endpoints[i], G_IO_IN, FALSE);
          z_poll_remove_stream(self->poll, self->super.endpoints[i]);

          self->super.endpoints[i] = z_stream_pop(self->super.endpoints[i]);

          gssize len = self->data_buffer[i]->length;
          if (i == EP_CLIENT && self->buffer_written_to_client)
            len = self->buffer_written_to_client;

          z_stream_unget(self->super.endpoints[i], self->data_buffer[i]->data, len, NULL);
        }
    }

  z_policy_lock(self->super.thread);
  pyres = z_policy_call(self->super.handler, "startService", z_policy_var_build("(O)", self->service), &called, self->super.session_id);
  z_policy_var_unref(pyres);
  z_policy_unlock(self->super.thread);

  /* release, but don't close fds on success */
  for (i = EP_CLIENT; i < EP_MAX; i++)
    {
      if (self->super.endpoints[i])
        {
          if (TRUE)
            z_stream_unref(self->super.endpoints[i]);
          else
            z_stream_close(self->super.endpoints[i], NULL);
          self->super.endpoints[i] = NULL;
        }
    }

  return TRUE;
}

static void
apr_register_vars(APRProxy *self)
{
  z_proxy_var_new(&self->super, "timeout",
                  Z_VAR_GET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG |
                  Z_VAR_TYPE_INT, &self->timeout);

  z_proxy_var_new(&self->super, "copy_client_data",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG |
                  Z_VAR_TYPE_INT, &self->copy_client_data);

  z_proxy_var_new(&self->super, "need_server_connect",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG |
                  Z_VAR_TYPE_INT, &self->need_server_connect);

  z_proxy_var_new(&self->super, "quit",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG |
                  Z_VAR_TYPE_INT, &self->quit);
}

static gboolean
apr_config(ZProxy *s)
{
  APRProxy *self = (APRProxy *) s;

  z_proxy_enter (self);
  apr_config_set_defaults(self);
  apr_register_vars(self);
  z_proxy_return(self, Z_SUPER(s, ZProxy)->config(s));
}

/**
 * Reads data into packet from stream.
 *
 * @internal
 */
static inline gboolean
apr_read(ZStream *stream, ZPktBuf *packet, gsize length)
{
  GIOStatus status;
  gsize br;

  if (packet->allocated < packet->length + length)
    z_pktbuf_resize(packet, packet->length + length);

  status = z_stream_read(stream, (gchar*) (z_pktbuf_end(packet)), length, &br, NULL);

  if (status == G_IO_STATUS_ERROR || status == G_IO_STATUS_EOF)
    {
      /* error already logged */
      return FALSE;
    }
  else if (status == G_IO_STATUS_NORMAL)
    {
      packet->length += br;
    }

  return TRUE;
}

static void
apr_detect(APRProxy *self, gint side)
{
  gboolean called;
  ZPolicyObj *pyres;
  ZPktBuf *buf = self->data_buffer[side];

  z_proxy_log_data_dump(self, APR_DUMP, 8, (gchar*) buf->data, buf->length);
  z_policy_lock(self->super.thread);
  PyObject *data = PyString_FromStringAndSize(reinterpret_cast<char *>(buf->data), buf->length);
  pyres = z_policy_call(self->super.handler, "detect", z_policy_var_build("(iO)", side, data), &called, self->super.session_id);
  Py_XDECREF(data);
  if (pyres && pyres != z_policy_none)
    {
      self->quit = TRUE;
      self->service = pyres;
    }
  else
    {
      z_policy_var_unref(pyres);
    }
  z_policy_unlock(self->super.thread);
}

static void
connect_server(APRProxy *self)
{
  if (get_stream(self, EP_SERVER))
    return;
  z_proxy_log(self, "APR.debug", 6, "connect server");
  if (z_proxy_connect_server(&self->super, NULL, 0))
    apr_setup_stream(self, EP_SERVER);
}

static gboolean
apr_read_callback(ZStream *stream, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  APRProxy *self = static_cast<APRProxy *>(user_data);
  gint side = (stream == get_stream(self, EP_CLIENT)) ? EP_CLIENT : EP_SERVER;
  ZPktBuf *incoming_packet = self->data_buffer[side];

  if (!apr_read(stream, incoming_packet, stream_buf_size))
    goto error;

  z_proxy_log(self, "APR.debug", 6, "Received data");
  apr_detect(self, side);
  if (self->need_server_connect)
    connect_server(self);
  if (self->copy_client_data && get_stream(self, EP_SERVER))
    {
      gsize written;
      gsize length = self->copy_client_data > self->data_buffer[EP_CLIENT]->length ? self->data_buffer[EP_CLIENT]->length : self->copy_client_data;
      self->copy_client_data = 0;
      z_stream_write(get_stream(self, EP_SERVER), self->data_buffer[EP_CLIENT]->data, length, &written, NULL);
      self->buffer_written_to_client = written;
    }
  return TRUE;

error:
  self->quit = TRUE;
  incoming_packet->length = 0;
  return FALSE;
}

static void
apr_wakeup(ZProxy *s)
{
  APRProxy *self = (APRProxy *) s;

  z_poll_wakeup(self->poll);
}

/*
 * Main proxy loop.
 *
 * @param[in] s APRProxy instance.
 */
static void
apr_main(ZProxy *s)
{
  APRProxy *self = Z_CAST(s, APRProxy);
  guint ep;

  /* construct and initialize */

  /* start */
  apr_setup_stream(self, EP_CLIENT);

  if (self->need_server_connect)
    connect_server(self);

  /* process packets */
  z_proxy_log(self, APR_DEBUG, 6, "Entering main-loop;");
  while (!self->quit && z_poll_iter_timeout(self->poll, self->timeout))
    {
      if (!z_proxy_loop_iteration(s))
        self->quit = TRUE;
    }

  /* pass streams as neccessary */
  if (self->service && !apr_continue_with_proxy(self))
    {
      //z_proxy_log(self, SOCKS_DEBUG, 6, "Unable to pass streams to stacked proxy;");
    }


  //z_proxy_log(self, SOCKS_DEBUG, 6, "Leaving main-loop;");

  for (ep = EP_CLIENT; ep < EP_MAX; ep++)
    {
      if (self->super.endpoints[ep])
        {
          /* NOTE: we flush out streams as some packets might be stucked */
          if (!z_stream_broken(self->super.endpoints[ep]))
            {
              z_stream_buf_flush(self->super.endpoints[ep]);
              z_stream_set_nonblock(self->super.endpoints[ep], FALSE);
            }

          z_poll_remove_stream(self->poll, self->super.endpoints[ep]);
        }
    }
}

/**
 * APRProxy constructor. Allocates and initializes a proxy instance,
 * starts proxy thread.
 */
static ZProxy *
apr_proxy_new(ZProxyParams *params)
{
  APRProxy *self;

  z_enter ();
  self = Z_CAST(z_proxy_new(Z_CLASS(APRProxy), params), APRProxy);
  z_return((ZProxy *) self);
}

/*
 * APRProxy free method.
 *
 * @param[in] s APRProxy instance.
 */
void
apr_proxy_free(ZObject *s)
{
  APRProxy *self = Z_CAST(s, APRProxy);

  z_enter();

  for (int i = 0; i < EP_MAX; ++i)
    z_pktbuf_unref(self->data_buffer[i]);

  z_poll_unref(self->poll);
  if (self->service)
    z_policy_var_unref(self->service);
  z_proxy_free_method(s);
  z_return();
}

ZProxyFuncs apr_proxy_funcs =
  {
    {
      Z_FUNCS_COUNT (ZProxy),
      apr_proxy_free,
    },
    apr_config,
    NULL,
    apr_main,
    NULL,
    NULL,
    NULL,
    NULL,
    apr_wakeup,
  };

Z_CLASS_DEF(APRProxy, ZProxy, apr_proxy_funcs);

static ZProxyModuleFuncs apr_module_funcs =
  {
    apr_proxy_new,
    NULL
  };

/**
 * Module initialization function. Registers the APR proxy type.
 *
 * @return TRUE if module usage is permitted by the licence.
 */
gint
zorp_module_init(void)
{
  z_registry_add("apr", ZR_PROXY, &apr_module_funcs);
  return TRUE;
}
