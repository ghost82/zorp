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

#ifndef ZORP_CERTCHAIN_H_INCLUDED
#define ZORP_CERTCHAIN_H_INCLUDED

#include <openssl/x509.h>
#include <zorp/zobject.h>

typedef struct _ZCertificateChain
{
  ZObject super;
  X509 *cert;
  STACK_OF(X509) *chain;
} ZCertificateChain;

typedef ZObjectFuncs ZCertificateChainFuncs;
extern ZClass ZCertificateChain__class;

ZCertificateChain *z_certificate_chain_new(void);
void z_certificate_chain_set_cert(ZCertificateChain *self, X509 *cert);
void z_certificate_chain_add_cert_to_chain(ZCertificateChain *self, X509 *chain);
X509 *z_certificate_chain_get_cert_from_chain(ZCertificateChain *self, gint idx);

static inline gsize
z_certificate_chain_get_chain_length(const ZCertificateChain *self)
{
  return sk_X509_num(self->chain);
}

static inline X509 *
z_certificate_chain_get_cert(ZCertificateChain *self)
{
  return self->cert;
}

#endif
