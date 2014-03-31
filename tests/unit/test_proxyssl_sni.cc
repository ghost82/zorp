#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

#include "helpers/zproxy.h"
#include <zorp/proxy.h>
#include "helpers/proxyssl_sni.h"
#include <openssl/err.h>

static struct
{
  const char *no_set_servername_cb;
  const char *has_set_servername_cb_accept;
  const char *has_set_servername_cb_reject;
} policy_pys =
    {
            "import Zorp.Proxy\n"
            "class TestProxy(Zorp.Proxy.Proxy):\n"
            "    def __init__(self):\n"
            "        self.test_tlsext_server_name = None\n"
            "        pass\n"
            "    def __pre_config__(self):\n"
            "        pass\n"
            "    def __post_config__(self):\n"
            "        pass\n"
            "    def testGetSniServername(self):\n"
            "        self.test_tlsext_server_name = self.ssl.client_tlsext_server_name\n"
            ,
            "import Zorp.Proxy\n"
            "class TestProxy(Zorp.Proxy.Proxy):\n"
            "    def __init__(self):\n"
            "        self.called_setTlsServername = False\n"
            "    def __pre_config__(self):\n"
            "        pass\n"
            "    def config(self):\n"
            "        self.ssl.client_handshake['set_servername'] = (Zorp.Proxy.SSL_HS_POLICY, self.setTlsServername)\n"
            "    def __post_config__(self):\n"
            "        pass\n"
            "    def setTlsServername(self, side):\n"
            "        self.called_setTlsServername = True\n"
            "        return Zorp.Proxy.SSL_HS_ACCEPT\n"
            ,
            "import Zorp.Proxy\n"
            "class TestProxy(Zorp.Proxy.Proxy):\n"
            "    def __init__(self):\n"
            "        self.called_setTlsServername = False\n"
            "    def __pre_config__(self):\n"
            "        pass\n"
            "    def config(self):\n"
            "        self.ssl.client_handshake['set_servername'] = (Zorp.Proxy.SSL_HS_POLICY, self.setTlsServername)\n"
            "    def __post_config__(self):\n"
            "        pass\n"
            "    def setTlsServername(self, side):\n"
            "        self.called_setTlsServername = True\n"
            "        return Zorp.Proxy.SSL_HS_REJECT\n"
            ,
    };


class ProxysslSetup
{
public:
  ProxysslSetup()
    {
      init_environment();
    }
  ~ProxysslSetup()
    {
    }
};

BOOST_GLOBAL_FIXTURE(ProxysslSetup);

static SSL *
create_ssl(void)
{
  SSL_CTX *ctx;
  SSL *ssl;

  SSL_load_error_strings();
  SSL_library_init();

  ctx = SSL_CTX_new(SSLv3_method());
  if (!ctx)
    {
      unsigned long err = ERR_get_error();
      printf("Error allocating SSL_CTX struct; err='%lu', str='%s'\n", err, ERR_error_string(err, NULL));
      return NULL;
    }

  ssl = SSL_new(ctx);
  if (!ssl)
    {
      printf("Error allocating SSL struct;\n");
      return NULL;
    }

  return ssl;
}

static void
setup_proxy_ssl_handshake(ZProxy *proxy,SSL *ssl)
{
  ZProxySSLHandshake *hs;

  hs = g_new0(ZProxySSLHandshake, 1);
  hs->side = EP_CLIENT;
  hs->proxy = proxy;

  SSL_set_app_data(ssl, hs);
}

class ProxySslFixture
{
public:
  ProxySslFixture(const char *policy_source)
    {
      proxyssl_sni_clear_times_stubs_called();

      proxy = get_proxy_with_policy(policy_source, &(policy), &(proxy_instance), NULL);
      Z_FUNCS_CALL(proxy, ZProxy, config);

      ssl = create_ssl();
      BOOST_CHECK(ssl);

      setup_proxy_ssl_handshake(proxy, ssl);
    }

  ~ProxySslFixture()
    {
      // For simplicity, only the necessary cleanup is done. Some objects are leaked.
      leave_zproxy_test();
      policy = NULL;
      proxy_instance = NULL;
    }

  ZPolicy  *policy;
  PyObject *proxy_instance;
  ZProxy *proxy;
  SSL *ssl;
};

class ProxySslFixtureNoSetServerName : public ProxySslFixture
{
public:
  ProxySslFixtureNoSetServerName() : ProxySslFixture(policy_pys.no_set_servername_cb)
    {
    }
};

class ProxySslFixtureHasSetServerNameAccept : public ProxySslFixture
{
public:
  ProxySslFixtureHasSetServerNameAccept() : ProxySslFixture(policy_pys.has_set_servername_cb_accept)
    {
    }
};

class ProxySslFixtureHasSetServerNameReject : public ProxySslFixture
{
public:
  ProxySslFixtureHasSetServerNameReject() : ProxySslFixture(policy_pys.has_set_servername_cb_reject)
    {
    }
};

BOOST_FIXTURE_TEST_CASE(test_client_tlsext_servername_should_be_readable_in_python, ProxySslFixtureNoSetServerName)
{
  static char dummy_servername[] = "dummy-servername";

  g_string_assign(proxy->ssl_opts.tlsext_server_host_name, dummy_servername);

  call_policy_method(policy, proxy_instance, "testGetSniServername");

  char *returned_servername = fetch_policy_attribute_as_string(
      policy, proxy_instance, "test_tlsext_server_name");

  BOOST_CHECK(returned_servername);
  BOOST_CHECK(!strcmp(dummy_servername, returned_servername));

  g_free(returned_servername);
}

int z_proxy_ssl_tlsext_servername_cb(SSL *ssl, int *_ad, void *_arg);

void
check_tlsext_servername_cb(SSL *ssl, int expected_result)
{
  int cb_result;

  cb_result = z_proxy_ssl_tlsext_servername_cb(ssl, NULL, NULL);
  BOOST_CHECK(cb_result == expected_result);
}

BOOST_FIXTURE_TEST_CASE(test_tlsext_servername_cb_should_set_server_name, ProxySslFixtureHasSetServerNameAccept)
{
  // This is the same as the one returned by SSL_get_servername
  static char dummy_servername[] = "dummy-servername";

  check_tlsext_servername_cb(ssl, SSL_TLSEXT_ERR_OK);
  BOOST_CHECK(!strcmp(dummy_servername, proxy->ssl_opts.tlsext_server_host_name->str));
}

BOOST_FIXTURE_TEST_CASE(test_tlsext_servername_cb_should_call_policy_set_servername, ProxySslFixtureHasSetServerNameAccept)
{
  check_tlsext_servername_cb(ssl, SSL_TLSEXT_ERR_OK);
  gboolean called_set_tls_servername = fetch_policy_attribute_as_boolean(
      policy, proxy_instance, "called_setTlsServername");

  BOOST_CHECK(called_set_tls_servername);
}

BOOST_FIXTURE_TEST_CASE(test_tlsext_servername_cb_should_not_set_keys_when_no_set_servername_is_in_policy, ProxySslFixtureNoSetServerName)
{
  check_tlsext_servername_cb(ssl, SSL_TLSEXT_ERR_OK);
  BOOST_CHECK(proxyssl_sni_get_stubs_called()->times_z_proxy_ssl_use_local_cert_and_key == 0);
}

BOOST_FIXTURE_TEST_CASE(test_tlsext_servername_cb_should_set_keys_when_set_servername_returns_accept, ProxySslFixtureHasSetServerNameAccept)
{
  check_tlsext_servername_cb(ssl, SSL_TLSEXT_ERR_OK);
  BOOST_CHECK(proxyssl_sni_get_stubs_called()->times_z_proxy_ssl_use_local_cert_and_key == 1);
}

BOOST_FIXTURE_TEST_CASE(test_tlsext_servername_cb_should_not_set_keys_when_set_servername_returns_reject, ProxySslFixtureHasSetServerNameReject)
{
  check_tlsext_servername_cb(ssl, SSL_TLSEXT_ERR_ALERT_FATAL);
  BOOST_CHECK(proxyssl_sni_get_stubs_called()->times_z_proxy_ssl_use_local_cert_and_key == 0);
}
