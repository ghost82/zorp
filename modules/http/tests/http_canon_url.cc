#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

#include "../http.h"

void
test_case(gint id, const gchar *parse_url_str, gboolean unicode, gboolean invalid_escape, gboolean format_absolute, gboolean canonicalize, const gchar *expected_url_str)
{
  HttpURL url;
  gchar *fail_reason = NULL;
  const gchar *error_reason = NULL;
  gboolean ok = TRUE, valid;
  GString *formatted_url = g_string_sized_new(0);
  gchar * url_str = g_strdup(parse_url_str);

  http_init_url(&url);
  valid = http_parse_url(&url, unicode, invalid_escape, FALSE, url_str, &error_reason);
  if (ok && !valid)
    {
      fail_reason = g_strdup_printf("Error parsing URL: %s", !valid ? error_reason : "No error");
      ok = FALSE;
    }
  if (ok && !http_format_url(&url, formatted_url, format_absolute, unicode, canonicalize, &error_reason))
    {
      fail_reason = g_strdup_printf("Error reformatting URL: %s", error_reason);
      ok = FALSE;
    }
  if (ok && strcmp(formatted_url->str, expected_url_str) != 0)
    {
      fail_reason = g_strdup_printf("Canonicalized URL not matching: %s <> %s", formatted_url->str, expected_url_str);
      ok = FALSE;
    }

  g_string_free(formatted_url, TRUE);

  BOOST_CHECK_MESSAGE(ok, "test failure, id=" << id << ", url=" << url_str << ", reason=" << fail_reason);
}

struct
{
  const gchar *url_str;
  gboolean invalid_escape;
  gboolean unicode;
  gboolean format_absolute;
  gboolean canonicalize;
  const gchar *expected_url_str;
} test_table[] =

{
  { "http://user:pass@test.host:8080/file",    FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host:8080/file" },
  { "http://user:pass@test.host:8080/file?\xe9",  FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host:8080/file?%E9" },
  { "http://user:pass@test.host:8080/file?\xe9",  FALSE, TRUE,  TRUE,  TRUE, "http://user:pass@test.host:8080/file?%E9" },
  { "http://user:pass@test.host:8080/file\xe9",   FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host:8080/file%E9" },
  { "http://user:pass@test.host:8080/file\xe9",   FALSE, TRUE,  TRUE,  TRUE, "http://user:pass@test.host:8080/file%E9" },
  { "http://user:pass@test.host:8080/file",    FALSE, FALSE, FALSE, TRUE, "/file" },
  { "http://user:pass@test.host/file",         FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/file" },
  { "http://user:pass@test.host",              FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/" },
  { "http://user:pass@test.host/file?query#fragment",
                                               FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/file?query#fragment" },
  { "http://user:pass@test.host/file#fragment",
                                               FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/file#fragment" },
  { "http://user:pass@test.host/file?query",
                                               FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/file?query" },
  { "http://user@test.host:8080/file",         FALSE, FALSE, TRUE,  TRUE, "http://user@test.host:8080/file" },
  { "http://user:pass@test.host/file",         FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/file" },
  { "http://user@test.host/file",              FALSE, FALSE, TRUE,  TRUE, "http://user@test.host/file" },
  { "http://test.host:8080/file",              FALSE, FALSE, TRUE,  TRUE, "http://test.host:8080/file" },
  { "http://test.host/file",                   FALSE, FALSE, TRUE,  TRUE, "http://test.host/file" },
  { "http://test.host/default.idaNNNN%u9090%u6858%ucbd3",
                                               FALSE, TRUE,  TRUE,  TRUE, "http://test.host/default.idaNNNN%u9090%u6858%uCBD3" },
  { "http://test.host/ad/N2558.travelport.telnet/B36496;sz=468x60;ord=%5B%25GMTTIME%25%5D?",
                                               FALSE, FALSE, TRUE,  TRUE, "http://test.host/ad/N2558.travelport.telnet/B36496;sz=468x60;ord=[%25GMTTIME%25]" },
  { "http://test.host/ad/N2558.travelport.telnet/B36496?sz=468x60;ord=%5B%25GMTTIME%25%5D",
                                               FALSE, FALSE, TRUE,  TRUE, "http://test.host/ad/N2558.travelport.telnet/B36496?sz=468x60;ord=%5B%25GMTTIME%25%5D" },
  { "http://user:pass@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26",
                                               FALSE, TRUE,  TRUE,  TRUE, "http://user:pass@test.host/fi/../le?%3Fa&%26" },
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%40",
                                               FALSE, TRUE,  TRUE,  TRUE, "http://user:pass%40@test.host/fi/../le?%3Fa&%26#%40" },
/* Not implemented yet.
  { "http://use%72:p%61ss%40@test.host/fi%%le",
                                               FALSE, FALSE, TRUE,  TRUE, "http://user:pass%40@test.host/fi%%le" }, */
  /* invalid escaping, invalid_escape disabled */
  { "http://use%72:p%61ss%40@test.host/fi%2g%2e%2e%2fle?%u003f%61&%26#%40",
                                               TRUE,  TRUE,  TRUE,  TRUE, "http://user:pass%40@test.host/fi%252g../le?%3Fa&%26#%40" },
  /* no canonicalization, URL must remain the same, except the username/password part */
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%40",
                                               FALSE, TRUE,  TRUE,  FALSE, "http://user:pass%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%40" },
  { "http://[::1]:80/file",                   FALSE, FALSE, TRUE,  TRUE, "http://[::1]:80/file" },
  { NULL, 0,0,0,0, NULL }
};

BOOST_AUTO_TEST_CASE(test_canon_url)
{
  gint i;

  for (i = 0; test_table[i].url_str; i++)
    {
      test_case(i, test_table[i].url_str, test_table[i].unicode, test_table[i].invalid_escape, test_table[i].format_absolute, test_table[i].canonicalize,
                    test_table[i].expected_url_str);
    }
}
