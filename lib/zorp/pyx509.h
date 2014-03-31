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
 * Author: Panther
 *
 ***************************************************************************/

#ifndef ZORP_PYX509_H_INCLUDED
#define ZORP_PYX509_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/proxy.h>

ZPolicyObj *z_py_ssl_privkey_get(ZProxy *self, gchar *name, gpointer value);
int z_py_ssl_privkey_set(ZProxy *self, gchar *name, gpointer value, ZPolicyObj *new_);
void z_py_ssl_privkey_free(gpointer value);

ZPolicyObj *z_py_ssl_certificate_get(ZProxy *self, gchar *name, gpointer value);
void z_py_ssl_certificate_free(gpointer value);

ZPolicyObj *z_py_ssl_cert_list_get(ZProxy *self, gchar *name, gpointer value);
void z_py_ssl_cert_list_free(gpointer value);

ZPolicyObj *z_py_ssl_cert_name_list_get(ZProxy *self, gchar *name, gpointer value);
void z_py_ssl_cert_name_list_free(gpointer value);

ZPolicyObj *z_py_ssl_crl_list_get(ZProxy *self, gchar *name, gpointer value);
void z_py_ssl_crl_list_free(gpointer value);

#endif
