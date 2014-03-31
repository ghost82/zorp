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
 * Author  : bazsi
 * Auditor : kisza
 * Last audited version: 1.4
 * Notes:
 *
 ***************************************************************************/

#include <zorp/pyproxygroup.h>
#include <zorp/pyproxy.h>

/**
 * @brief Bind C proxy implementation to policy object
 * @param python_proxy policy object to bind
 * @return TRUE if succeeded, FALSE otherwise
 *
 * @note Must be called with the policy lock held!
 *
 * @note In case this function returns FALSE a Python exception has been raised
 * and the caller must return an error.
 *
 */
static gboolean
bind_policy_object_to_lowlevel_implementation(ZPolicyObj *python_proxy)
{
  ZPolicyProxyBindImplementationResult res;

  res = z_policy_proxy_bind_implementation(python_proxy);
  switch (res)
    {
    case Z_POLICY_PROXY_BIND_IMPL_FAILED:
      PyErr_SetString(PyExc_RuntimeError, "Error binding proxy implementation");
      return FALSE;
      break;

    case Z_POLICY_PROXY_BIND_IMPL_LICENSE_ERROR:
      z_policy_raise_exception("LicenseException", "Number of licensed IPs exceeded");
      return FALSE;
      break;

    case Z_POLICY_PROXY_BIND_IMPL_OK:
      return TRUE;
      break;
    }

  g_assert_not_reached();
}

/**
 * z_policy_proxy_group_start:
 * @self this
 * @args Python params (proxy_class, session)
 *
 * Returns:
 */
static ZPolicyObj *
z_policy_proxy_group_start(gpointer user_data, ZPolicyObj *args, ZPolicyObj *kw G_GNUC_UNUSED)
{
  ZProxyGroup *proxy_group = (ZProxyGroup *) user_data;
  ZPolicyObj *proxy_instance;

  if (!z_policy_var_parse(args, "(O)", &proxy_instance))
    return NULL;

  if (!z_policy_proxy_check(proxy_instance))
    {
      PyErr_SetString(PyExc_ValueError, "Expecting Proxy instance as argument");
      return NULL;
    }

  if (!bind_policy_object_to_lowlevel_implementation(proxy_instance))
    {
      /* we already have a raised an exception */
      return NULL;
    }

  if (z_proxy_group_start_session(proxy_group, z_policy_proxy_get_proxy(proxy_instance)))
    {
      return PyInt_FromLong(1);
    }

  return z_policy_none_ref();
}

/**
 * z_policy_proxy_group_new_instance:
 * @o unused
 * @args Python arguments:
 *
 * Returns:
 * The new instance
 */
static ZPolicyObj *
z_policy_proxy_group_new_instance(PyObject *o G_GNUC_UNUSED, PyObject *args)
{
  gint max_sessions;
  ZProxyGroup *proxy_group;
  ZPolicyDict *dict;
  ZPolicyObj *res;

  if (!PyArg_Parse(args, "(i)", &max_sessions))
    return NULL;

  proxy_group = z_proxy_group_new(max_sessions);

  dict = z_policy_dict_new();

  /* NOTE: we need to add a reference to proxy_group here as our instance
   * might be freed earlier than the method reference, in a construct like
   * ProxyGroup(1).start(proxy).
   */

  z_policy_dict_register(dict, Z_VT_METHOD, "start", Z_VF_READ, z_policy_proxy_group_start, proxy_group, NULL);

  z_policy_dict_set_app_data(dict, proxy_group, (GDestroyNotify) z_proxy_group_orphan);
  res = z_policy_struct_new(dict, Z_PST_PROXY_GROUP);
  return res;
}

PyMethodDef z_policy_proxy_group_funcs[] =
{
  { "ProxyGroup", (PyCFunction) z_policy_proxy_group_new_instance, METH_VARARGS, NULL },
  { NULL,      NULL, 0, NULL }   /* sentinel*/
};

/**
 * z_policy_proxy_group_init:
 *
 * Module initialisation
 */
void
z_policy_proxy_group_module_init(void)
{
  Py_InitModule("Zorp.Zorp", z_policy_proxy_group_funcs);
}
