#include "zproxy.h"

void
init_environment()
{
  z_proxy_hash_init();
  z_registry_init();
}

/**
 * Create a ZProxy* instance with special python policy.
 *
 * @param policy_source  policy.py contents
 * @param new_policy  pointer to the new policy object will be stored here. May be NULL.
 * @param new_proxy_instance  pointer to the new policy proxy instance object will be stored here. May be NULL.
 * @param proxy_class  proxy class to create, or NULL, in which case a ZProxy will be created.
 * @return pointer to the created ZProxy object
 *
 * The policy's class name MUST BE TestProxy!
 *
 * Example:
 * @code
 *   const char policy_source[] =
 *     "class TestProxy(object):\n"
 *     "  def processEvent(self, type, event):\n"
 *     "    self.type = type\n"
 *     "    self.event = event\n";
 * @endcode
 *
 * If new_policy / new_proxy_instance is NULL, the respective pointer will not be stored.
 */
ZProxy*
get_proxy_with_policy(const char* policy_source, ZPolicy **new_policy, PyObject **new_proxy_instance, ZClass *proxy_class)
{
  ZPolicy *policy;
  PyObject *proxy_instance;
  // Initialize the python interpreter

  z_thread_init();
  if (!z_python_init())
    {
      fprintf(stderr, "Python initialization failed\n");
      exit(1);
    }

  // Create the main
  policy = z_policy_new("");
  z_policy_boot(policy);
  z_policy_thread_acquire(policy->main_thread);

  // Parse and run the source with Python interpreter
  PyRun_SimpleString(policy_source);

  // Create policy proxy instance that can be used by ZProxy
  PyObject* sys_mod_dict = PyImport_GetModuleDict();
  PyObject* main_mod = PyMapping_GetItemString(sys_mod_dict, "__main__");
  proxy_instance = PyObject_CallMethod(main_mod, "TestProxy", "");

  // Create an ssh proxy with the policy
  ZProxyParams params;
  params.session_id = "ssh/ssh";
  params.pyclient = NULL;
  params.client = NULL;
  params.handler = proxy_instance;
  params.parent = NULL;

  ZProxy *proxy;
  Py_BEGIN_ALLOW_THREADS;
  proxy = z_proxy_new(proxy_class ? proxy_class : Z_CLASS(ZProxy), &params);
  Py_END_ALLOW_THREADS;

  z_policy_proxy_set_proxy(proxy_instance, proxy);

  z_policy_thread_ready(proxy->thread);

  z_policy_thread_release(policy->main_thread);

  if (new_policy)
    *new_policy = policy;

  if (new_proxy_instance)
    *new_proxy_instance = proxy_instance;

  return proxy;
}

void
leave_zproxy_test()
{
  z_python_destroy();
}

static PyObject*
fetch_policy_attribute_nolock(PyObject *proxy_instance, const char *attribute_name)
{
  return PyObject_GetAttrString(proxy_instance, attribute_name);
}

/**
 * Fetch a policy proxy attribute, and return it.
 *
 * @param policy  The policy object
 * @param proxy_instance  The policy proxy instance
 * @param attribute_name  Attribute name of the policy proxy instance
 * @return The requested attribute, with a new reference to it.
 *
 * Note that actually using this object later reliably requires locking!
 */
PyObject*
fetch_policy_attribute(ZPolicy *policy, PyObject *proxy_instance, const char* attribute_name)
{
  z_policy_thread_acquire(policy->main_thread);
  PyObject *obj = fetch_policy_attribute_nolock(proxy_instance, attribute_name);
  z_policy_thread_release(policy->main_thread);
  return obj;
}

/**
 * Fetch the string representation of an attribute of the policy proxy instance
 *
 * @param policy  The policy object
 * @param proxy_instance  The policy proxy instance
 * @param attribute_name  Attribute name of the policy proxy instance
 * @return A newly allocated buffer pointing to the string representation, or NULL on error.
 */
char*
fetch_policy_attribute_as_string(ZPolicy *policy, PyObject *proxy_instance, const char* attribute_name)
{
  char *string = NULL;

  z_policy_thread_acquire(policy->main_thread);
  PyObject* temp_obj = fetch_policy_attribute_nolock(proxy_instance, attribute_name);
  if (temp_obj)
    string = g_strdup(PyString_AsString(temp_obj));

  z_policy_thread_release(policy->main_thread);
  return string;
}

/**
 * Fetch an attribute of the policy proxy instance, evaluated as a boolean
 *
 * @param policy  The policy object
 * @param proxy_instance  The policy proxy instance
 * @param attribute_name  Attribute name of the policy proxy instance
 * @return TRUE if the requested attribute evaluates as a Python boolean True value, FALSE otherwise
 */
gboolean
fetch_policy_attribute_as_boolean(ZPolicy *policy, PyObject *proxy_instance, const char* attribute_name)
{
  gboolean result;

  z_policy_thread_acquire(policy->main_thread);
  PyObject* temp_obj = fetch_policy_attribute_nolock(proxy_instance, attribute_name);
  result = PyObject_IsTrue(temp_obj);
  Py_DECREF(temp_obj);
  z_policy_thread_release(policy->main_thread);

  return result;
}

/**
 * Call a method of the policy proxy instance object, without arguments
 *
 * @param policy The policy object
 * @param proxy_instance  The policy proxy instance
 * @param method_name The name of the method to call
 */
void
call_policy_method(ZPolicy *policy, PyObject *proxy_instance, char* method_name)
{
  PyObject *result;

  z_policy_thread_acquire(policy->main_thread);
  result = PyObject_CallMethod(proxy_instance, method_name, "");
  Py_DECREF(result);
  z_policy_thread_release(policy->main_thread);
}
