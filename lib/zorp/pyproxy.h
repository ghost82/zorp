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

#ifndef ZORP_PYPROXY_H_INCLUDED
#define ZORP_PYPROXY_H_INCLUDED

#include <zorp/zpython.h>
#include <zorp/thread.h>
#include <zorp/proxy.h>

typedef struct _ZPolicyProxy ZPolicyProxy;

extern PyTypeObject z_policy_proxy_type;

typedef enum
{
  Z_POLICY_PROXY_BIND_IMPL_FAILED,
  Z_POLICY_PROXY_BIND_IMPL_LICENSE_ERROR,
  Z_POLICY_PROXY_BIND_IMPL_OK
} ZPolicyProxyBindImplementationResult;

ZPolicyProxyBindImplementationResult z_policy_proxy_bind_implementation(PyObject *self);
ZProxy *z_policy_proxy_get_proxy(PyObject *obj);
void z_policy_proxy_set_proxy(PyObject *s, ZProxy *proxy);

void z_policy_proxy_module_init(void);
void z_policy_proxy_module_py_init(ZProxyModulePyInitFunc init_func, const gchar *module_name);

static inline gboolean
z_policy_proxy_check(ZPolicyObj *s)
{
  return PyObject_TypeCheck(s, &z_policy_proxy_type);
}

#endif
