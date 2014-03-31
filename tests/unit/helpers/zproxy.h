#ifndef TESTS_UNIT_HELPERS_ZPROXY
#define TESTS_UNIT_HELPERS_ZPROXY

#include <zorp/proxy.h>
#include <zorp/zpython.h>
#include <zorp/policy.h>
#include <zorp/pyproxy.h>
#include <zorp/registry.h>

/**
 * Init proxy environment
 */
void
init_environment();

/**
 * Create a ZProxy* instance with special python policy.
 */
ZProxy*
get_proxy_with_policy(const char* policy_source, ZPolicy **new_policy, PyObject **new_proxy_instance, ZClass *proxy_class);

/**
 * After test is finished, it closes python interpreter.
 */
void
leave_zproxy_test();

/**
 * Fetch an attribute of the policy proxy instance as a python object with a new reference
 */
PyObject*
fetch_policy_attribute(ZPolicy *policy, PyObject *proxy_instance, const char* attribute_name);

/**
 * Fetch a string attribute of the policy proxy instance in char*
 */
char*
fetch_policy_attribute_as_string(ZPolicy *policy, PyObject *proxy_instance, const char* attribute_name);

/**
 * Fetch an attribute of the policy proxy instance, evaluated as a boolean
 */
gboolean
fetch_policy_attribute_as_boolean(ZPolicy *policy, PyObject *proxy_instance, const char* attribute_name);

/**
 * Call a method of the policy proxy instance without arguments.
 */
void
call_policy_method(ZPolicy *policy, PyObject *proxy_instance, char* method_name);

#endif /* TESTS_UNIT_HELPERS_ZPROXY*/
