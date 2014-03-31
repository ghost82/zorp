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
 * Author: Bazsi
 * Auditor: Bazsi
 * Last audited version: 1.14
 * Notes:
 *
 ***************************************************************************/

#include <zorp/zorp.h>
#include <zorp/proxy.h>
#include <zorp/thread.h>
#include <zorp/policy.h>
#include <zorp/zpython.h>
#include <zorp/pystream.h>
#include <zorp/registry.h>
#include <zorp/log.h>
#include <zorp/streamline.h>
#include <zorp/proxystack.h>

#define ANYPY_ERROR "anypy.error"

/**
 * Proxy class for implementing proxies in Python.
 *
 * \extends Proxy
 */
typedef struct
{
  ZProxy super;
  guint max_line_length[EP_MAX];
  GList *stacked_proxies;
} AnyPyProxy;

extern ZClass AnyPyProxy__class;

/**
 * Initialize client and server-side streams.
 *
 * @private @memberof AnyPyProxy
 *
 * @param self AnyPyProxy instance
 *
 * This function is called upon startup to initialize our streams.
 **/
static gboolean
anypy_stream_init(AnyPyProxy *self)
{
  z_proxy_enter(self);
  if (!self->super.endpoints[EP_CLIENT] || !self->super.endpoints[EP_SERVER])
    {
      z_proxy_log(self, ANYPY_ERROR, 2, "Server side not yet connected, unable to init streams;");
      z_proxy_leave(self);
      return FALSE;
    }
  self->super.endpoints[EP_CLIENT] = z_stream_push(self->super.endpoints[EP_CLIENT], z_stream_line_new(NULL, self->max_line_length[EP_CLIENT], ZRL_EOL_CRLF));
  self->super.endpoints[EP_SERVER] = z_stream_push(self->super.endpoints[EP_SERVER], z_stream_line_new(NULL, self->max_line_length[EP_SERVER], ZRL_EOL_CRLF));

  z_proxy_leave(self);
  return TRUE;
}

/**
 * Set verdict for the parent proxy.
 *
 * @private @memberof AnyPyProxy
 *
 * @param self AnyPyProxy instance
 * @param args verdict as a (verdict, description) tuple
 *
 * Parses #args tuple and calls the set_verdict method of the stacking
 * interface of the parent proxy.
 **/
static ZPolicyObj *
anypy_set_verdict(AnyPyProxy * self, ZPolicyObj *args)
{
  ZVerdict verdict;
  gchar *description;

  z_proxy_enter(self);

  if (!z_policy_var_parse_tuple(args, "is", &verdict, &description))
    {
      z_policy_raise_exception_obj(z_policy_exc_value_error, "Invalid arguments.");
      z_proxy_return(self, NULL);
    }

  if (self->super.parent_proxy)
    {
      ZProxyStackIface *iface;
      iface = z_proxy_find_iface(self->super.parent_proxy, Z_CLASS(ZProxyStackIface));
      if (iface)
        {
          z_proxy_stack_iface_set_verdict(iface, verdict, description);
          z_object_unref(&iface->super);
        }
    }

  z_proxy_return(self, z_policy_none_ref());
}

/**
 * Set content hint for the parent proxy.
 *
 * @private @memberof AnyPyProxy
 *
 * @param self AnyPyProxy instance
 * @param args: Python long specifying the length of the content
 *
 * Notify our parent proxy of the length of the content we will
 * output. Must be called before writing anything to the server
 * stream.
 *
 **/
static ZPolicyObj *
anypy_set_content_hint(AnyPyProxy * self, ZPolicyObj *args)
{
  gint64 length;

  z_proxy_enter(self);

  if (!z_policy_var_parse_tuple(args, "L", &length))
    {
      z_policy_raise_exception_obj(z_policy_exc_value_error, "Invalid arguments.");
      z_proxy_leave(self);
      return NULL;
    }

  if (self->super.parent_proxy)
    {
      ZProxyStackIface *iface;
      iface = z_proxy_find_iface(self->super.parent_proxy, Z_CLASS(ZProxyStackIface));
      if (iface)
        {
          z_proxy_stack_iface_set_content_hint(iface, length);
          z_object_unref(&iface->super);
        }
    }

  z_proxy_return(self, z_policy_none_ref());
}

/**
 * Trigger stacking of an object.
 *
 * @private @memberof AnyPyProxy
 *
 * @param self AnyPyProxy instance
 * @param args: Python tuple describing method of stacking (eg. (Z_STACK_PROXY, ProxyClass))
 *
 * Triggers stacking a proxy instance of the specified stacking method. In case of using Z_STACK_PROXY class in the
 * passed-in session. Constructing the session (setting streams and
 * session id at least) is the responsibility of the caller.
 *
 **/
static ZPolicyObj *
anypy_stack(AnyPyProxy * self, ZPolicyObj *args)
{
  ZStackedProxy *stacked_proxy;

  z_proxy_enter(self);

  if (!z_proxy_stack_object(&self->super, args, &stacked_proxy, NULL))
    {
      z_policy_raise_exception_obj(z_policy_exc_runtime_error, "Stacking failed.");
      z_proxy_return(self, NULL);
    }

  self->stacked_proxies = g_list_prepend(self->stacked_proxies, stacked_proxy);

  z_proxy_return(self, z_policy_none_ref());
}

/**
 * Set default values of proxy attributes in the proxy structure.
 *
 * @private @memberof AnyPyProxy
 *
 * @param self AnyPyProxy instance
 *
 * This function initializes various attributes exported to the Python layer
 * for possible modification.
 **/
static void
anypy_config_set_defaults(AnyPyProxy *self)
{
  z_proxy_enter(self);

  self->max_line_length[EP_CLIENT] = 4096;
  self->max_line_length[EP_SERVER] = 4096;

  z_proxy_leave(self);
}

/**
 * Export proxy attributes to python.
 *
 * @private @memberof AnyPyProxy
 *
 * @param self AyPyProxy instance
 *
 * This function is called upon startup to export Python attributes.
 **/
static void
anypy_register_vars(AnyPyProxy *self)
{
  z_proxy_enter(self);
  /* method for setting the proxy verdict. It should be used before the first write */
  z_proxy_var_new(&self->super, "set_verdict",
	Z_VAR_TYPE_METHOD | Z_VAR_GET,
	self,anypy_set_verdict);
  /* method for setting the content hint. It should be used before the first write */
  z_proxy_var_new(&self->super, "set_content_hint",
        Z_VAR_TYPE_METHOD | Z_VAR_GET,
        self, anypy_set_content_hint);
  /* method for stacking a proxy in a custom session */
  z_proxy_var_new(&self->super, "stack",
        Z_VAR_TYPE_METHOD | Z_VAR_GET,
        self, anypy_stack);
  /* size of line buffer of the client stream */
  z_proxy_var_new(&self->super, "client_max_line_length",
	Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
	&self->max_line_length[EP_CLIENT]);
  /* size of line buffer of the server stream */
  z_proxy_var_new(&self->super, "server_max_line_length",
	Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
	&self->max_line_length[EP_SERVER]);
  z_proxy_leave(self);
}

/**
 * Configure proxy.
 *
 * @private @memberof AnyPyProxy
 *
 * @param s AnyPyProxy instance casted to ZProxy
 *
 * This function is called upon startup to configure the proxy.
 * This calls the the __pre_config__, config and __post_config__ events.
 **/
static gboolean
anypy_config(ZProxy *s)
{
  AnyPyProxy *self = Z_CAST(s, AnyPyProxy);

  anypy_config_set_defaults(self);
  anypy_register_vars(self);
  if (Z_SUPER(s, ZProxy)->config(s))
    {
      return TRUE;
    }
  return FALSE;
}

/**
 * Main method of proxy.
 *
 * @private @memberof AnyPyProxy
 *
 * @param s AnyPyProxy instance
 */
static void
anypy_main(ZProxy * s)
{
  AnyPyProxy *self = Z_CAST(s, AnyPyProxy);
  ZPolicyObj *res;
  gboolean called;

  z_proxy_enter(self);
  if (!z_proxy_connect_server(&self->super, NULL, 0) || !anypy_stream_init(self))
    {
      z_proxy_leave(self);
      return;
    }
  z_policy_lock(self->super.thread);
  res = z_policy_call(self->super.handler, "proxyThread", NULL, &called, self->super.session_id);
  z_policy_var_unref(res);
  z_policy_unlock(self->super.thread);

  for (GList *i = self->stacked_proxies; i; i = i->next)
    z_stacked_proxy_destroy((ZStackedProxy *) i->data);

  g_list_free(self->stacked_proxies);

  z_proxy_return(self);
}

/**
 * Create a new AnyPyProxy.
 *
 * @private @memberof AnyPyProxy
 *
 * @param params parameters for the AnyPyProxy class constructor
 *
 * This function is called upon startup to create a new AnyPy proxy.
 **/
ZProxy *
anypy_proxy_new(ZProxyParams *params)
{
  AnyPyProxy *self;

  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(AnyPyProxy), params), AnyPyProxy);
  z_return(&self->super);
}

ZProxyFuncs anypy_proxy_funcs =
{
  {
    Z_FUNCS_COUNT(ZProxy),
    NULL
  },            /* super */
  anypy_config, /* config */
  NULL,         /* startup */
  anypy_main,   /* main */
  NULL,         /* shutdown */
  NULL,         /* destroy */
  NULL,         /* nonblocking_init */
  NULL,         /* nonblocking_deinit */
  NULL,         /* wakeup */
};

Z_CLASS_DEF(AnyPyProxy, ZProxy, anypy_proxy_funcs);

static ZProxyModuleFuncs anypy_module_funcs =
  {
    /* .create_proxy = */ anypy_proxy_new,
    /* .module_py_init = */ NULL,
  };

/**
 * Initialize proxy module.
 *
 * Called after Zorp loads the dynamic module to register the proxy
 * implementation.
 */
gint
zorp_module_init(void)
{
  z_registry_add("anypy", ZR_PYPROXY, &anypy_module_funcs);
  return TRUE;
}
