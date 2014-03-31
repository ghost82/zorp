#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

#include "helpers/zproxy.h"
#include <zorp/proxy.h>


#ifdef ALERTING_ENABLED

struct _Event
{
  char *name;               /**< Name of the event. For the format of a name, see \ref message_name_format. */
  double timestamp;         /**< Timestamp of the event (seconds since epoch). May contain fractions of a second. */

  int data_size;            /**< Raw event data size. */
  void *data;               /**< Raw event data, format depends on name. */
};

static Event
create_event()
{
  Event e =
  {
    /* .name = */ "Name",
    /* .data = */ "DATA",
    /* .data_size = */ 4
  };
  return e;
}

static PyObject*
create_python_string()
{
  return PyString_FromString("#drawing");
}

static gboolean event_processing_result;
#endif

#ifdef ALERTING_ENABLED

BOOST_AUTO_TEST_CASE(test_z_proxy_should_have_alerting_interface)
{
  gboolean (*callback_func)(ZProxy*, const Event*, PyObject *object);
  callback_func = NULL;
  callback_func = &z_proxy_handle_alerting_event_method;
  BOOST_CHECK(callback_func);
}

BOOST_AUTO_TEST_CASE(test_alerting_returns_false_when_proxy_has_no_handle_alerting_event_method)
{
  ZProxy* proxy;
  const char policy_source[] =
      "class TestProxy(object):\n"
      "  def no_such_method(self, type, event):\n"
      "    pass\n";

  proxy = get_proxy_with_policy(policy_source, NULL, NULL, NULL);

   Event event = create_event();
   PyObject *test_channel_id = create_python_string();
   event_processing_result = Z_FUNCS_CALL(proxy, ZProxy, handle_alerting_event, &event, test_channel_id);

  BOOST_CHECK(event_processing_result == FALSE);
  Py_DECREF(test_channel_id);

  leave_zproxy_test();
}

BOOST_AUTO_TEST_CASE(test_alerting_should_return_true_if_no_terminate_required)
{
  ZProxy* proxy;
  const char policy_source[] =
      "class TestProxy(object):\n"
      "  def handleAlertingEvent(self, channel_id, type, event):\n"
      "    return True\n";

  proxy = get_proxy_with_policy(policy_source, NULL, NULL, NULL);

  Event event = create_event();
  PyObject *test_channel_id = create_python_string();

  event_processing_result = Z_FUNCS_CALL(proxy, ZProxy, handle_alerting_event, &event, test_channel_id);
  BOOST_CHECK(event_processing_result == TRUE);
  Py_DECREF(test_channel_id);

  leave_zproxy_test();
}

BOOST_AUTO_TEST_CASE(test_alerting_should_return_false_if_terminate_required)
{
  ZProxy* proxy;
  const char policy_source[] =
      "class TestProxy(object):\n"
      "  def handleAlertingEvent(self, channel_id, type, event):\n"
      "    return False\n";

  proxy = get_proxy_with_policy(policy_source, NULL, NULL, NULL);

  Event event = create_event();
  PyObject *test_channel_id = create_python_string();
  event_processing_result = Z_FUNCS_CALL(proxy, ZProxy, handle_alerting_event, &event, test_channel_id);
  BOOST_CHECK(event_processing_result == FALSE);

  Py_DECREF(test_channel_id);
  leave_zproxy_test();
}

BOOST_AUTO_TEST_CASE(test_alerting_called_python_layer_with_received_event)
{
  ZPolicy *policy;
  PyObject *proxy_instance;
  ZProxy* proxy;
  const char policy_source[] =
    "import Zorp.Proxy\n"
    "class TestProxy(Zorp.Proxy.Proxy):\n"
    "  def __init__(self):\n"
    "    pass\n"
    "  def __pre_config__(self):\n"
    "    pass\n"
    "  def handleAlertingEvent(self, channel_id, type, event):\n"
    "    self.type = type\n"
    "    self.event = event\n"
    "    return True\n";

  proxy = get_proxy_with_policy(policy_source, &policy, &proxy_instance, NULL);

  Event event = create_event();
  event.name = "Test Event";
  event.data = "TEST_DATA";
  event.data_size = 9;
  PyObject *test_channel_id = create_python_string();

  event_processing_result = Z_FUNCS_CALL(proxy, ZProxy, handle_alerting_event, &event, test_channel_id);

  BOOST_CHECK(!strcmp(event.name, fetch_policy_attribute_as_string(policy, proxy_instance, "type")));
  BOOST_CHECK(!strcmp(event.data, fetch_policy_attribute_as_string(policy, proxy_instance, "event")));

  Py_DECREF(test_channel_id);

  leave_zproxy_test();
}

static gboolean handle_alerting_event_mock_called = FALSE;

static gboolean
handle_alerting_event_mock(ZProxy *self G_GNUC_UNUSED, const Event *event G_GNUC_UNUSED, PyObject *channel_id G_GNUC_UNUSED)
{
  handle_alerting_event_mock_called = TRUE;
  return TRUE;
}

BOOST_AUTO_TEST_CASE(test_audit_layer_should_call_the_proxy_when_event_happened)
{
  typedef struct _TestProxy {
    ZProxy *super;
  } TestProxy;

  ZProxyFuncs test_funcs = {
    {
      Z_FUNCS_COUNT (ZProxy),
      z_proxy_free_method
    },
    /* .handle_alerting_event = */ &handle_alerting_event_mock
  };

  Z_CLASS_DEF(TestProxy, ZProxy, test_funcs);

  TestProxy* proxy = Z_NEW(TestProxy);

  EventDetectorUserData user_data;
  user_data.proxy = (ZProxy*)proxy;
  user_data.channel_id = create_python_string();

  Event event = create_event();
  handle_alerting_event_mock_called = FALSE;
  z_audit_event_detector_callback(&event, &user_data);
  BOOST_CHECK(handle_alerting_event_mock_called == TRUE);
}
#else

BOOST_AUTO_TEST_CASE(test_empty)
{
}

#endif

class TestProxySetup
{
public:
  TestProxySetup()
    {
      init_environment();
    }
  ~TestProxySetup()
    {
    }
};

BOOST_GLOBAL_FIXTURE(TestProxySetup);
