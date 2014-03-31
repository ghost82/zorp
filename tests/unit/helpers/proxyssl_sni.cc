#include <glib.h>
#include <openssl/ssl.h>
#include <zorp/policy.h>
// proxyssl.h depends on pydict.h
#include <zorp/pydict.h>
#include <zorp/proxyssl.h>
#include "proxyssl_sni.h"

static ProxySSL_SNI_stubs_called stubs_called;

void
proxyssl_sni_clear_times_stubs_called(void)
{
  memset(&stubs_called, 0, sizeof(ProxySSL_SNI_stubs_called));
}

ProxySSL_SNI_stubs_called *
proxyssl_sni_get_stubs_called(void)
{
  return &stubs_called;
}

const char *
SSL_get_servername(const SSL *s G_GNUC_UNUSED, const int type G_GNUC_UNUSED)
{
  return "dummy-servername";
}

gboolean
z_proxy_ssl_use_local_cert_and_key(ZProxy *self G_GNUC_UNUSED, ZEndpoint side G_GNUC_UNUSED, SSL *ssl G_GNUC_UNUSED)
{
  stubs_called.times_z_proxy_ssl_use_local_cert_and_key += 1;
  return TRUE;
}
