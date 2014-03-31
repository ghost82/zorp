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

#include <zorp/certchain.h>

ZCertificateChain *
z_certificate_chain_new(void)
{
  ZCertificateChain *self = Z_NEW_COMPAT(Z_CLASS(ZCertificateChain), ZCertificateChain);

  self->chain = sk_X509_new_null();

  return self;
}

void
z_certificate_chain_set_cert(ZCertificateChain *self, X509 *cert)
{
  if (self->cert)
    X509_free(self->cert);

  self->cert = cert;
  CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509);
}

void
z_certificate_chain_add_cert_to_chain(ZCertificateChain *self, X509 *cert)
{
  sk_X509_push(self->chain, cert);
  CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509);
}

X509 *
z_certificate_chain_get_cert_from_chain(ZCertificateChain *self, gint idx)
{
  return sk_X509_value(self->chain, idx);
}

static void
z_certificate_chain_free_method(ZObject *s)
{
  ZCertificateChain *self = Z_CAST(s, ZCertificateChain);
  if (self->cert)
    X509_free(self->cert);
  sk_X509_pop_free(self->chain, X509_free);
  z_object_free_method(s);
}

ZObjectFuncs z_certificate_chain_funcs =
{
  Z_FUNCS_COUNT(ZObject),
  z_certificate_chain_free_method,
};

Z_CLASS_DEF(ZCertificateChain, ZObject, z_certificate_chain_funcs);
