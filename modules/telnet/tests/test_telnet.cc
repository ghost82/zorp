#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

#include <zorp/zorp.h>
#include <zorp/log.h>
#include <zorp/thread.h>
#include <zorp/packetbuf.h>
#include <zorp/proxy.h>

#include "../telnetprotocol.h"
#include "../telnetlineedit.h"
#include "../telnet.h"

#include <glib.h>

class TelnetSetup
{
public:
  TelnetSetup()
    {
      z_thread_init();
      z_log_init("test_telnet_suboptions", ZLF_STDERR);
      z_python_init();

      self = Z_NEW_COMPAT(Z_CLASS(TelnetProxy), TelnetProxy);
      g_strlcpy(self->super.session_id, "test/telnet:1", sizeof(self->super.session_id));
    }
  ~TelnetSetup() { }

  TelnetProxy *self;
};

class TelnetLineEditSetup
{
public:
  TelnetLineEditSetup()
    {
      _lineedit_out = g_string_new("");
      p = new TelnetLineEdit();
      telnet_lineedit_init(p);
    }
  ~TelnetLineEditSetup()
    {
      telnet_lineedit_destroy(p);
      g_string_free(_lineedit_out, TRUE);
      delete p;
    }

  GString *_lineedit_out;
  TelnetLineEdit *p;
};

static gboolean
data_received(ZPktBuf *data, gpointer user_data)
{
  GString *s = (GString *) user_data;
  g_string_append_len(s, static_cast<gchar *>(z_pktbuf_data(data)), z_pktbuf_length(data));

  return TRUE;
}

static gboolean
command_received(guint8 command, gpointer user_data)
{
  GString *s = (GString *) user_data;
  g_string_append_c(s, command);

  return TRUE;
}

static gboolean
opneg_received(guint8 command, guint8 option, gpointer user_data)
{
  GString *s = (GString *) user_data;
  g_string_append_c(s, command);
  g_string_append_c(s, option);

  return TRUE;
}

class TelnetProtocolSetup
{
public:
  TelnetProtocolSetup()
    {
      _data = g_string_new("");
      _suboption = g_string_new("");
      _command_bytes = g_string_new("");
      _opneg_bytes = g_string_new("");

      p = new TelnetProtocol();

      telnet_protocol_init(p, "test_protocol");
      telnet_protocol_set_data_received(p, data_received, _data);
      telnet_protocol_set_subneg_received(p, data_received, _suboption);
      telnet_protocol_set_command_received(p, command_received, _command_bytes);
      telnet_protocol_set_opneg_received(p, opneg_received, _opneg_bytes);
    }
  ~TelnetProtocolSetup()
    {
      telnet_protocol_destroy(p);
      g_string_free(_data, TRUE);
      g_string_free(_suboption, TRUE);
      g_string_free(_command_bytes, TRUE);
      g_string_free(_opneg_bytes, TRUE);

      delete p;
    }

  GString *_data;
  GString *_suboption;
  GString *_command_bytes;
  GString *_opneg_bytes;

  TelnetProtocol *p;
};


/* process data one byte at a time */
#define PROCESS_BYTES(bytes) do { \
  for (gsize i = 0; \
       telnet_protocol_is_running(p) && i < strlen(bytes); \
       i++) { \
    ZPktBuf *data = z_pktbuf_new(); \
    z_pktbuf_put_u8(data, bytes[i]); \
    z_pktbuf_seek(data, G_SEEK_SET, 0); \
    telnet_protocol_process_data(p, data); \
    z_pktbuf_unref(data); \
  } \
} while (0);

/* process data one byte at a time */
#define PROCESS_LINEEDIT_BYTES(bytes) do { \
  ZPktBuf *data = z_pktbuf_new(); \
  for (gsize i = 0; \
       i < sizeof(bytes) - 1; \
       i++) { \
    z_pktbuf_put_u8(data, bytes[i]); \
  } \
  ZPktBuf *out; \
  out = telnet_lineedit_process_data(p, data); \
  z_pktbuf_unref(data); \
  if (z_pktbuf_length(out)) \
    g_string_append_len(_lineedit_out, static_cast<gchar *>(z_pktbuf_data(out)), z_pktbuf_length(out)); \
  z_pktbuf_unref(out); \
} while (0);

#define ASSERT_DATA_EMPTY BOOST_CHECK(_data->len == 0)
#define ASSERT_DATA(bytes) BOOST_CHECK(!strcmp(_data->str, bytes))
#define ASSERT_OPNEG_EMPTY BOOST_CHECK(_opneg_bytes->len == 0)
#define ASSERT_OPNEG(bytes) BOOST_CHECK(!strcmp(_opneg_bytes->str, bytes))
#define ASSERT_COMMAND_EMPTY BOOST_CHECK(_command_bytes->len == 0)
#define ASSERT_COMMAND(bytes) BOOST_CHECK(!strcmp(_command_bytes->str, bytes))
#define ASSERT_SUBNEG_EMPTY BOOST_CHECK(_suboption->len == 0)
#define ASSERT_SUBNEG(bytes) BOOST_CHECK(!strcmp(_suboption->str, bytes))

#define ASSERT_LINEEDIT_OUT(bytes) BOOST_CHECK(!strcmp(_lineedit_out->str, bytes))
#define ASSERT_LINEEDIT_DATA(bytes) do { \
  GString *data = g_string_new(""); \
  g_string_append_len(data, static_cast<gchar *>(z_pktbuf_data(p->data_buffer)), z_pktbuf_length(p->data_buffer)); \
  BOOST_CHECK(!strcmp(data->str, bytes)); \
  g_string_free(data, TRUE); \
} while (0);

#define T_SE "\xf0"
#define T_NOP "\xf1"
#define T_SB "\xfa"
#define T_WILL "\xfb"
#define T_WONT "\xfc"
#define T_DO "\xfd"
#define T_DONT "\xfe"
#define T_IAC "\xff"
#define T_BACKSPACE "\x7f"
#define T_LINEDEL "\x15"
#define T_LINEEND0 "\r\0"
#define T_LINEENDN "\r\n"

BOOST_AUTO_TEST_CASE(test_telnet_protocol_escape_data)
{
  char *testdata = T_IAC "alma" T_IAC "korte" T_IAC;
  char *expecteddata = T_IAC T_IAC "alma" T_IAC T_IAC "korte" T_IAC T_IAC;

  ZPktBuf *buf = z_pktbuf_new();
  z_pktbuf_append(buf, testdata, strlen(testdata));

  telnet_protocol_escape_data(buf);

  ZPktBuf *expected = z_pktbuf_new();
  z_pktbuf_append(expected, expecteddata, strlen(expecteddata));

  BOOST_CHECK(z_pktbuf_data_equal(buf, expected));

  z_pktbuf_unref(buf);
  z_pktbuf_unref(expected);
}

BOOST_FIXTURE_TEST_CASE(test_telnet_protocol_empty, TelnetProtocolSetup)
{
  ASSERT_DATA_EMPTY;
  ASSERT_OPNEG_EMPTY;
  ASSERT_COMMAND_EMPTY;
  ASSERT_SUBNEG_EMPTY;
}

BOOST_FIXTURE_TEST_CASE(test_telnet_protocol_escape, TelnetProtocolSetup)
{
  PROCESS_BYTES(T_IAC T_IAC);
  ASSERT_DATA(T_IAC);
}

BOOST_FIXTURE_TEST_CASE(test_telnet_protocol_opneg, TelnetProtocolSetup)
{
  PROCESS_BYTES(T_IAC T_WILL "\x01");
  PROCESS_BYTES(T_IAC T_WONT "\x01");
  PROCESS_BYTES("data");
  PROCESS_BYTES(T_IAC T_IAC);
  PROCESS_BYTES(T_IAC T_DO "\x02");
  PROCESS_BYTES(T_DO "\x03");

  ASSERT_OPNEG(T_WILL "\x01" T_WONT "\x01" T_DO "\x02");
  ASSERT_COMMAND_EMPTY;
  ASSERT_DATA("data" T_IAC T_DO "\x03");
  ASSERT_SUBNEG_EMPTY;
}

BOOST_FIXTURE_TEST_CASE(test_telnet_protocol_subneg_basic, TelnetProtocolSetup)
{
  PROCESS_BYTES(T_IAC T_SB "\x01" "\x02" "suboption data" T_IAC T_SE);

  ASSERT_SUBNEG("\x01" "\x02" "suboption data");
  ASSERT_DATA_EMPTY;
  ASSERT_OPNEG_EMPTY;
  ASSERT_COMMAND_EMPTY;
}

BOOST_FIXTURE_TEST_CASE(test_telnet_protocol_subneg_escape, TelnetProtocolSetup)
{
  PROCESS_BYTES(T_IAC T_SB "\x01" T_IAC T_IAC "suboption data" T_IAC T_IAC T_IAC "\x01" T_IAC T_SE);

  ASSERT_SUBNEG("\x01" T_IAC "suboption data" T_IAC "\x01");
  ASSERT_DATA_EMPTY;
  ASSERT_OPNEG_EMPTY;
  ASSERT_COMMAND_EMPTY;
}

BOOST_FIXTURE_TEST_CASE(test_telnet_protocol_subneg_complex, TelnetProtocolSetup)
{
  PROCESS_BYTES("alma" T_IAC T_IAC "korte" "alma" T_IAC T_DO "\x01" "korte" "alma" T_IAC T_SB "\x01" "aaa" T_IAC T_SE "korte");

  ASSERT_OPNEG(T_DO "\x01");
  ASSERT_SUBNEG("\x01" "aaa");
  ASSERT_DATA("alma" T_IAC "korte" "alma" "korte" "alma" "korte");
}

BOOST_FIXTURE_TEST_CASE(test_telnet_protocol_subneg_buffer_size, TelnetProtocolSetup)
{
  char testdata[TELNET_BUFFER_SIZE + 16];

  memset(testdata, 'a', sizeof(testdata));
  testdata[0] = 0xff;
  testdata[1] = 0xfa;
  testdata[TELNET_BUFFER_SIZE + 2] = 0xff;
  testdata[TELNET_BUFFER_SIZE + 3] = 0xf0;
  testdata[TELNET_BUFFER_SIZE + 4] = '\0';

  PROCESS_BYTES(testdata);

  ASSERT_DATA_EMPTY;
  ASSERT_OPNEG_EMPTY;
  ASSERT_COMMAND_EMPTY;
  BOOST_CHECK(_suboption->len == TELNET_BUFFER_SIZE);
}

BOOST_FIXTURE_TEST_CASE(test_telnet_protocol_subneg_overrun, TelnetProtocolSetup)
{
  char testdata[TELNET_BUFFER_SIZE + 16];

  memset(testdata, 'a', sizeof(testdata));
  testdata[0] = 0xff;
  testdata[1] = 0xfa;
  testdata[TELNET_BUFFER_SIZE + 3] = 0xff;
  testdata[TELNET_BUFFER_SIZE + 4] = 0xf0;
  testdata[TELNET_BUFFER_SIZE + 5] = '\0';

  PROCESS_BYTES(testdata);

  ASSERT_DATA_EMPTY;
  ASSERT_OPNEG_EMPTY;
  ASSERT_COMMAND_EMPTY;
  ASSERT_SUBNEG_EMPTY;
}

BOOST_FIXTURE_TEST_CASE(test_telnet_protocol_command, TelnetProtocolSetup)
{
  PROCESS_BYTES(T_IAC "\x01" T_IAC T_SB "\x01" T_IAC T_SE "\x02" T_IAC T_IAC T_IAC);

  ASSERT_SUBNEG("\x01");
  ASSERT_DATA("\x02" T_IAC);
  ASSERT_OPNEG_EMPTY;
  ASSERT_COMMAND("\x01");
}

BOOST_FIXTURE_TEST_CASE(test_telnet_lineedit, TelnetLineEditSetup)
{
  BOOST_CHECK(p->do_echo);
  PROCESS_LINEEDIT_BYTES("aaa");
  ASSERT_LINEEDIT_OUT("aaa");
  ASSERT_LINEEDIT_DATA("aaa");
  PROCESS_LINEEDIT_BYTES(T_BACKSPACE T_BACKSPACE);
  ASSERT_LINEEDIT_OUT("aaa\b \b\b \b");
  ASSERT_LINEEDIT_DATA("a");
  PROCESS_LINEEDIT_BYTES("bbcc");
  ASSERT_LINEEDIT_OUT("aaa\b \b\b \bbbcc");
  ASSERT_LINEEDIT_DATA("abbcc");
  PROCESS_LINEEDIT_BYTES(T_LINEDEL);
  ASSERT_LINEEDIT_OUT("aaa\b \b\b \bbbcc\b \b\b \b\b \b\b \b\b \b");
  ASSERT_LINEEDIT_DATA("");
  PROCESS_LINEEDIT_BYTES("abc");
  ASSERT_LINEEDIT_OUT("aaa\b \b\b \bbbcc\b \b\b \b\b \b\b \b\b \babc");
  ASSERT_LINEEDIT_DATA("abc");
  PROCESS_LINEEDIT_BYTES("\rx");
  ASSERT_LINEEDIT_OUT("aaa\b \b\b \bbbcc\b \b\b \b\b \b\b \b\b \babcx");
  ASSERT_LINEEDIT_DATA("abcx");
  PROCESS_LINEEDIT_BYTES("\ny");
  ASSERT_LINEEDIT_OUT("aaa\b \b\b \bbbcc\b \b\b \b\b \b\b \b\b \babcxy");
  ASSERT_LINEEDIT_DATA("abcxy");
  PROCESS_LINEEDIT_BYTES("\r\0");
  ASSERT_LINEEDIT_OUT("aaa\b \b\b \bbbcc\b \b\b \b\b \b\b \b\b \babcxy\r\n");
  ASSERT_LINEEDIT_DATA("abcxy");
  BOOST_CHECK(p->eol);
  g_string_truncate(_lineedit_out, 0);
  PROCESS_LINEEDIT_BYTES(T_BACKSPACE T_BACKSPACE);
  ASSERT_LINEEDIT_OUT("");
  ASSERT_LINEEDIT_DATA("");
  PROCESS_LINEEDIT_BYTES(T_LINEDEL);
  ASSERT_LINEEDIT_OUT("");
  ASSERT_LINEEDIT_DATA("");
  BOOST_CHECK(!p->eol);
  p->do_echo = FALSE;
  PROCESS_LINEEDIT_BYTES("aa");
  ASSERT_LINEEDIT_OUT("");
  ASSERT_LINEEDIT_DATA("aa");
  PROCESS_LINEEDIT_BYTES("bc");
  ASSERT_LINEEDIT_OUT("");
  ASSERT_LINEEDIT_DATA("aabc");
  PROCESS_LINEEDIT_BYTES(T_BACKSPACE);
  ASSERT_LINEEDIT_OUT("");
  ASSERT_LINEEDIT_DATA("aab");
  PROCESS_LINEEDIT_BYTES(T_LINEDEL);
  ASSERT_LINEEDIT_OUT("");
  ASSERT_LINEEDIT_DATA("");
  PROCESS_LINEEDIT_BYTES("aa\r\n");
  ASSERT_LINEEDIT_OUT("\r\n");
  ASSERT_LINEEDIT_DATA("aa");
  BOOST_CHECK(p->eol);
}


BOOST_GLOBAL_FIXTURE(TelnetSetup)
