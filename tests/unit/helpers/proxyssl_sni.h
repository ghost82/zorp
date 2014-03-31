#ifndef TESTS_UNIT_HELPERS_PROXYSSL_SNI_H_INCLUDED
#define TESTS_UNIT_HELPERS_PROXYSSL_SNI_H_INCLUDED
#include <zorp/proxy.h>

typedef struct _ProxySSL_SNI_stubs_called
{
  gboolean times_z_proxy_ssl_use_local_cert_and_key;
} ProxySSL_SNI_stubs_called;

ProxySSL_SNI_stubs_called * proxyssl_sni_get_stubs_called(void);
void proxyssl_sni_clear_times_stubs_called(void);

// Stub functions
const char *SSL_get_servername(const SSL *s, const int type);
gboolean z_proxy_ssl_use_local_cert_and_key(ZProxy *self, ZEndpoint side, SSL *ssl);

#endif /* TESTS_UNIT_HELPERS_PROXYSSL_SNI_H_INCLUDED */
