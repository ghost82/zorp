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
 * Author  : Bazsi
 * Auditor :
 * Notes:
 *
 ***************************************************************************/

#include <zorp/proxystack.h>
#include <zorp/streamfd.h>
#include <zorp/streamline.h>
#include <zorp/streambuf.h>
#include <zorp/connect.h>

#include <zorp/pystream.h>
#include <zorp/pyproxy.h>
#include <zorp/pysockaddr.h>

/**
 * Create fd pairs for used for proxy stacking.
 *
 * @param self ZProxy instance
 * @param[out] downpair array to store the downstream file descriptor pair in
 * @param[out] uppair array to store the upstream file descriptor pair in
 *
 **/
static gboolean
z_proxy_stack_prepare_streams(ZProxy *self, gint *downpair, gint *uppair)
{
  z_proxy_enter(self);

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, downpair) == -1)
    {
      /*LOG
        This message indicates that stacking a child proxy failed, because
        creating an AF_UNIX domain socketpair failed on the client side.
       */
      z_proxy_log(self, CORE_ERROR, 1, "Error creating client socketpair for stacked proxy; error='%s'", g_strerror(errno));
      z_proxy_leave(self);
      return FALSE;
    }
  else if (socketpair(AF_UNIX, SOCK_STREAM, 0, uppair) == -1)
    {
      close(downpair[0]);
      close(downpair[1]);
      /*LOG
        This message indicates that stacking a child proxy failed, because
        creating an AF_UNIX domain socketpair failed on the server side.
       */
      z_proxy_log(self, CORE_ERROR, 1, "Error creating server socketpair for stacked proxy; error='%s'", g_strerror(errno));
      z_proxy_leave(self);
      return FALSE;
    }
  z_proxy_leave(self);
  return TRUE;
}

/**
 * Return a python wrapper of the stack info dict.
 *
 * \param stack_info a policy dict containing info provided by parent.
 * \return a Python object wrapping a dict or None if \p stack_info is NULL.
 */
static ZPolicyObj *
wrap_stack_info(ZPolicyDict *stack_info)
{
  if (stack_info)
    return z_policy_struct_new(stack_info, Z_PST_SHARED);
  else
    return z_policy_none_ref();
}


/**
 * Call Python policy method starting a child proxy.
 *
 * @param self proxy instance
 * @param proxy_class a Python class to be instantiated as the child proxy
 * @param client_stream a ZStream instance to be used as the client-side stream of the proxy
 * @param server_stream a ZStream instance to be used as the server-side stream of the proxy
 * @param stacked ZStackedProxy instance to store results in
 * @param stack_info policy dict used to pass info to the stacked proxy
 *
 * @return a new proxy instance that has been stacked
 *
 **/
static ZProxy *
z_proxy_stack_call_policy(ZProxy *self, ZPolicyObj *proxy_class, ZStream *client_stream, ZStream *server_stream, ZPolicyDict *stack_info)
{
  if (proxy_class == z_policy_none)
      return NULL;

  ZPolicyObj *stack_info_obj = wrap_stack_info(stack_info);
  ZPolicyObj *client_stream_obj = z_policy_stream_new(client_stream);
  ZPolicyObj *server_stream_obj = z_policy_stream_new(server_stream);
  ZPolicyObj *stack_proxy_args = z_policy_var_build("(OOOO)", client_stream_obj, server_stream_obj, proxy_class, stack_info_obj);
  ZPolicyObj *proxy_obj = z_policy_call(self->handler, "stackProxy", stack_proxy_args, NULL, self->session_id);
  z_policy_var_unref(server_stream_obj);
  z_policy_var_unref(client_stream_obj);
  z_policy_var_unref(stack_info_obj);

  ZProxy *stacked_proxy = NULL;
  if (proxy_obj == NULL || proxy_obj == z_policy_none || !z_policy_proxy_check(proxy_obj))
    z_proxy_log(self, CORE_ERROR, 3, "Error stacking subproxy;");
  else
    stacked_proxy = z_policy_proxy_get_proxy(proxy_obj);

  if (proxy_obj != NULL)
    z_policy_var_unref(proxy_obj);

  return stacked_proxy;
}

/**
 * Instantiate and start a stacked proxy of a given class.
 *
 * \param self parent proxy
 * \param proxy_class proxy class to be instantiated
 * \param[out] stacked pointer to the newly created stacked proxy object
 * \param stack_info optinal information passed to the child proxy
 * \return TRUE if stacking succeeded
 *
 */
static gboolean
z_proxy_stack_proxy(ZProxy *self, ZPolicyObj *proxy_class, ZStackedProxy **stacked, ZPolicyDict *stack_info)
{
  int clientpair[2], serverpair[2];
  gboolean res = FALSE;

  /* construct down and up stream pairs */
  if (!z_proxy_stack_prepare_streams(self, clientpair, serverpair))
      return FALSE;

  ZStream *client_stream = z_stream_fd_new(clientpair[1], "");
  ZStream *server_stream = z_stream_fd_new(serverpair[1], "");

  /*LOG
    This message reports that Zorp is about to stack a proxy class
    with the given fds as communication channels.
   */
  z_proxy_log(self, CORE_DEBUG, 6, "Stacking subproxy; client='%d:%d', server='%d:%d'",
              clientpair[0], clientpair[1], serverpair[0], serverpair[1]);

  ZProxy *stacked_proxy = z_proxy_stack_call_policy(self, proxy_class, client_stream, server_stream, stack_info);
  if (stacked_proxy != NULL)
    {
      ZStream *client_upstream = z_stream_fd_new(clientpair[0], "");
      ZStream *server_upstream = z_stream_fd_new(serverpair[0], "");

      *stacked = z_stacked_proxy_new(client_upstream, server_upstream, NULL, self, stacked_proxy, 0);

      res = TRUE;
    }
  else
    {
      /* close fds */
      close(clientpair[0]);
      close(serverpair[0]);
      z_stream_close(client_stream, NULL);
      z_stream_close(server_stream, NULL);

      res = FALSE;
    }

  z_stream_unref(client_stream);
  z_stream_unref(server_stream);

  return res;
}

/**
 * Call Python method instantiating a given proxy and starting it in a specific session.
 *
 * \param self parent proxy
 * \param proxy_class proxy class to be instantiated
 * \param session pre-constructed session object to start the proxy in
 * \param stack_info optional information passed to the stacked proxy
 *
 * \return proxy structure of the new proxy instance
 */
static ZProxy *
z_proxy_stack_in_session_call_policy(ZProxy *self, ZPolicyObj *proxy_class, ZPolicyObj *session,
                                     ZPolicyDict *stack_info)
{
  if (proxy_class == z_policy_none)
    return NULL;

  ZPolicyObj *stack_info_obj = wrap_stack_info(stack_info);
  ZPolicyObj *stack_proxy_args = z_policy_var_build("(OOO)", proxy_class, session, stack_info_obj);
  ZPolicyObj *proxy_obj = z_policy_call(self->handler, "stackProxyInSession", stack_proxy_args, NULL, self->session_id);
  z_policy_var_unref(stack_info_obj);

  ZProxy *stacked_proxy = NULL;
  if (proxy_obj == NULL || proxy_obj == z_policy_none || !z_policy_proxy_check(proxy_obj))
    z_proxy_log(self, CORE_ERROR, 3, "Error stacking subproxy, the proxy object returned by stackProxyInSession() is invalid;");
  else
    stacked_proxy = z_policy_proxy_get_proxy(proxy_obj);

  if (proxy_obj != NULL)
    z_policy_var_unref(proxy_obj);

  return stacked_proxy;
}

/**
 * \brief z_proxy_stack_proxy_in_session
 *
 * \param self parent proxy
 * \param proxy_class proxy class to be instantiated
 * \param session Session object to start the proxy in
 * \param client_downstream stream to be used by the parent proxy to read the client endpoint of the child proxy
 * \param server_downstream stream to be used by the parent proxy to read the server endpoint of the child proxy
 * \param[out] stacked on success, this is updated with the newly constructed stacked proxy object
 * \param stack_info optional dictionary containing information that is passed to the child proxy
 *
 * \return TRUE on success
 *
 * This function is intended to be used when full control is required by the
 * proxy over the session the child proxy is started in. For example, it is
 * used by the TSG proxy to stack child proxies for the channels: this way the
 * TSG proxy has full control over the session IDs and streams of the child
 * proxy (and can omit the server-side stream completely, for example).
 */
static gboolean
z_proxy_stack_proxy_in_session(ZProxy *self, ZPolicyObj *proxy_class, ZPolicyObj *session,
                               ZStream *client_downstream, ZStream *server_downstream,
                               ZStackedProxy **stacked, ZPolicyDict *stack_info)
{
  gboolean res = FALSE;

  z_proxy_enter(self);

  /*LOG
    This message reports that Zorp is about to stack a proxy class
    with the given fds as communication channels.
   */
  z_proxy_log(self, CORE_DEBUG, 6, "Stacking subproxy; client_upstream='%d', server_upstream='%d'",
              z_stream_get_fd(client_downstream),
              (server_downstream != NULL) ? z_stream_get_fd(server_downstream) : 0);

  ZProxy *stacked_proxy = z_proxy_stack_in_session_call_policy(self, proxy_class, session, stack_info);
  if (!stacked_proxy)
    {
      z_stream_close(client_downstream, NULL);
      z_stream_unref(client_downstream);

      if (server_downstream != NULL)
        {
          z_stream_close(server_downstream, NULL);
          z_stream_unref(server_downstream);
        }

      res = FALSE;
    }
  else
    {
      *stacked = z_stacked_proxy_new(client_downstream, server_downstream, NULL, self, stacked_proxy, 0);

      res = TRUE;
    }

  z_proxy_return(self, res);
}

/**
 * Stack client and server streams given as file descriptors.
 *
 * \param self          parent proxy
 * \param client_fd     file descriptor used by the parent proxy to read the client side of the stacked object
 * \param server_fd     file descriptor for the server stream of the stacked object
 * \param control_fd    file descriptor to be used for the control protocol
 * \param[out] stacked  pointer to the new stacked proxy created in case of success
 * \param flags         FIXME
 * \return              TRUE on success, FALSE otherwise
 */
static gboolean
z_proxy_stack_fds(ZProxy *self, gint client_fd, gint server_fd, gint control_fd, ZStackedProxy **stacked, guint32 flags)
{
  ZStream *client_upstream, *server_upstream, *control_stream = NULL;

  z_proxy_enter(self);
  client_upstream = z_stream_fd_new(client_fd, "");
  server_upstream = z_stream_fd_new(server_fd, "");
  if (control_fd != -1)
    control_stream = z_stream_fd_new(control_fd, "");

  *stacked = z_stacked_proxy_new(client_upstream, server_upstream, control_stream, self, NULL, flags);

  z_proxy_leave(self);
  return TRUE;
}

/**
 * Read callback for the stacked program control stream.
 *
 * @param stream stream to read from
 * @param cond I/O condition which triggered this call
 * @param user_data ZProxy instance as a generic pointer
 *
 * This function is registered as the read callback for control channels
 * of stacked programs.
 **/
static gboolean
z_proxy_control_stream_read(ZStream *stream, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  ZStackedProxy *stacked = (ZStackedProxy *) user_data;
  ZProxy *proxy = stacked->proxy;
  GIOStatus st;
  gboolean success = FALSE;
  ZCPCommand *request = NULL, *response = NULL;
  ZCPHeader *hdr1, *hdr2;
  guint cp_sid;
  ZProxyIface *iface = NULL;
  const gchar *fail_reason = "Unknown reason";
  gboolean result = TRUE;

  z_enter();
  g_mutex_lock(&stacked->destroy_lock);
  if (stacked->destroyed)
    {
      /* NOTE: this stacked proxy has already been destroyed, but a callback
         was still pending, make sure we don't come back again. Note that
         our arguments except stacked might already be freed. */
      result = FALSE;
      goto exit_unlock;
    }

  if (!stacked->control_proto)
    stacked->control_proto = z_cp_context_new(stream);

  st = z_cp_context_read(stacked->control_proto, &cp_sid, &request);
  if (st == G_IO_STATUS_AGAIN)
    goto exit_unlock;
  if (st != G_IO_STATUS_NORMAL)
    {
      /* FIXME: hack, returning FALSE should be enough but it causes
         the poll loop to spin, see bug #7219 */
      z_stream_set_cond(stream, G_IO_IN, FALSE);
      result = FALSE;
      goto exit_unlock;
    }

  response = z_cp_command_new("RESULT");
  if (cp_sid != 0)
    {
      fail_reason = "Non-zero session-id";
      goto error;
    }

  z_log(NULL, CORE_DEBUG, 6, "Read request from stack-control channel; request='%s'", request->command->str);
  if (strcmp(request->command->str, "SETVERDICT") == 0
     )
    {
      ZProxyStackIface *siface;

      iface = z_proxy_find_iface(proxy, Z_CLASS(ZProxyStackIface));
      if (!iface)
        {
          fail_reason = "Proxy does not support Stack interface";
          goto error;
        }

      siface = (ZProxyBasicIface *) iface;
      if (strcmp(request->command->str, "SETVERDICT") == 0)
        {
          ZVerdict verdict;

          hdr1 = z_cp_command_find_header(request, "Verdict");
          hdr2 = z_cp_command_find_header(request, "Description");
          if (!hdr1)
            {
              fail_reason = "No Verdict header in SETVERDICT request";
              goto error;
            }

	  if (strcmp(hdr1->value->str, "Z_ACCEPT") == 0)
	    verdict = ZV_ACCEPT;
	  else if (strcmp(hdr1->value->str, "Z_REJECT") == 0)
            verdict = ZV_REJECT;
	  else if (strcmp(hdr1->value->str, "Z_DROP") == 0)
            verdict = ZV_DROP;
	  else if (strcmp(hdr1->value->str, "Z_ERROR") == 0)
	    verdict = ZV_ERROR;
	  else
	    verdict = ZV_UNSPEC;

          z_proxy_stack_iface_set_verdict(siface, verdict, hdr2 ? hdr2->value->str : NULL);
        }
    }
  else
    {
      fail_reason = "Unknown request received";
      goto error;
    }
  success = TRUE;

 error:
  z_cp_command_add_header(response, g_string_new("Status"), g_string_new(success ? "OK" : "Failure"), FALSE);
  if (!success)
    {
      z_cp_command_add_header(response, g_string_new("Fail-Reason"), g_string_new(fail_reason), FALSE);
      z_log(NULL, CORE_DEBUG, 6, "Error processing control channel request; request='%s', reason='%s'", request ? request->command->str : "None", fail_reason);
    }

  z_log(NULL, CORE_DEBUG, 6, "Responding on stack-control channel; response='%s'", response->command->str);
  if (z_cp_context_write(stacked->control_proto, 0, response) != G_IO_STATUS_NORMAL)
    {
      /* this should not have happened */
      z_log(NULL, CORE_ERROR, 1, "Internal error writing response to stack-control channel;");
      success = FALSE;
    }

  if (iface)
    z_object_unref(&iface->super);
  if (request)
    z_cp_command_free(request);
  if (response)
    z_cp_command_free(response);

 exit_unlock:
  g_mutex_unlock(&stacked->destroy_lock);
  z_return(result);
}



/**
 * Start a program as a filtering child proxy.
 *
 * @param self proxy instance
 * @param program path to program to execute
 *
 **/
static gboolean
z_proxy_stack_program(ZProxy *self, const gchar *program, ZStackedProxy **stacked)
{
  int downpair[2], uppair[2], controlpair[2];
  pid_t pid;

  z_proxy_enter(self);

  if (!z_proxy_stack_prepare_streams(self, downpair, uppair))
    {
      z_proxy_leave(self);
      return FALSE;
    }

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, controlpair) < 0)
    {
      close(downpair[0]);
      close(downpair[1]);
      close(uppair[0]);
      close(uppair[1]);
      close(controlpair[0]);
      close(controlpair[1]);
      /*LOG
        This message indicates that stacking a child proxy failed, because
        creating an AF_UNIX domain socketpair failed for the control
        channel.
       */
      z_proxy_log(self, CORE_ERROR, 1, "Error creating control socketpair for stacked proxy; error='%s'", g_strerror(errno));
      z_proxy_leave(self);
      return FALSE;
    }

  /*LOG
    This message reports that Zorp is about to stack a program
    with the given fds as communication channels.
   */
  z_proxy_log(self, CORE_DEBUG, 6, "Stacking program; client='%d:%d', server='%d:%d', control='%d:%d', program='%s'",
              downpair[0], downpair[1], uppair[0], uppair[1], controlpair[0], controlpair[1], program);

  pid = fork();

  if (pid == 0)
    {
      int i;
      /* child */

      dup2(downpair[1], 0);
      dup2(uppair[1], 1);
      /* standard error is inherited */
      dup2(controlpair[1], 3);

      for (i = 4; i < sysconf(_SC_OPEN_MAX); i++)
        close(i);
      execl("/bin/sh", "/bin/sh", "-c", program, NULL);
      fprintf(stderr, "Error starting program; program='%s', error='%s'", program, strerror(errno));
      exit(127);
    }
  else if (pid < 0)
    {
      z_proxy_log(self, CORE_ERROR, 2, "Program stacking failed, fork returned error; program='%s', error='%s'", program, g_strerror(errno));

      close(downpair[0]);
      close(downpair[1]);
      close(uppair[0]);
      close(uppair[1]);
      close(controlpair[0]);
      close(controlpair[1]);
      z_proxy_leave(self);
      return FALSE;
    }

  close(downpair[1]);
  close(uppair[1]);
  close(controlpair[1]);
  if (!z_proxy_stack_fds(self, downpair[0], uppair[0], controlpair[0], stacked, 0))
    {
      z_proxy_leave(self);
      return FALSE;
    }
  z_proxy_leave(self);
  return TRUE;
}


/**
 * Parse a (how, what) Python tuple and call the appropriate stacking method.
 *
 * @param self proxy instance
 * @param tuple Python tuple containing the (how, what) pair
 * @param stacked ZStackedProxy structure to store results in
 * @param stack_info_dict dictionary containing info passed to the stacked object
 *
 **/
static gboolean
z_proxy_stack_tuple(ZProxy *self, ZPolicyObj *tuple, ZStackedProxy **stacked, ZPolicyDict *stack_info_dict)
{
  guint stack_method;
  ZPolicyObj *arg = NULL;
  gboolean success = FALSE;

  if (!z_policy_tuple_get_verdict(tuple, &stack_method) ||
      z_policy_seq_length(tuple) < 2)
    goto invalid_tuple;

  arg = z_policy_seq_getitem(tuple, 1);
  switch (stack_method)
    {
    case Z_STACK_PROXY:
      if (z_policy_seq_length(tuple) != 2)
        goto invalid_tuple;

      success = z_proxy_stack_proxy(self, arg, stacked, stack_info_dict);
      break;

    case Z_STACK_PROXY_IN_SESSION:
      {
        /* input is expected to be (Z_STACK_IN_SESSION, ProxyClass, session, client_upstream, server_upstream) */
        if (z_policy_seq_length(tuple) != 5)
          goto invalid_tuple;

        ZPolicyObj *session = z_policy_seq_getitem(tuple, 2);

        ZPolicyObj *client_upstream_obj = z_policy_seq_getitem(tuple, 3);
        ZStream *client_upstream = client_upstream_obj != z_policy_none ? z_policy_stream_get_stream(client_upstream_obj) : NULL;
        z_policy_var_unref(client_upstream_obj);

        ZPolicyObj *server_upstream_obj = z_policy_seq_getitem(tuple, 4);
        ZStream *server_upstream = server_upstream_obj != z_policy_none ? z_policy_stream_get_stream(server_upstream_obj) : NULL;
        z_policy_var_unref(server_upstream_obj);

        success = z_proxy_stack_proxy_in_session(self, arg, session, client_upstream, server_upstream, stacked, stack_info_dict);
        z_policy_var_unref(session);
      }
      break;

    case Z_STACK_PROGRAM:
      if (!z_policy_str_check(arg))
        goto invalid_tuple;

      success = z_proxy_stack_program(self, z_policy_str_as_string(arg), stacked);
      break;

    default:
      break;
    }

 exit:
  if (arg)
    z_policy_var_unref(arg);
  return success;

 invalid_tuple:
  z_proxy_log(self, CORE_POLICY, 1, "Invalid stack tuple;");
  success = FALSE;
  goto exit;
}

/**
 * Choose the appropriate stacking method and stack the object.
 *
 * @param self ZProxy instance
 * @param stack_obj Python object to be stacked
 *
 * This function is a more general interface than z_proxy_stack_proxy
 * or z_proxy_stack_tuple. It first decides how the specified Python
 * object needs to be stacked, performs stacking and returns the
 * stacked proxy.
 **/
gboolean
z_proxy_stack_object(ZProxy *self, ZPolicyObj *stack_obj, ZStackedProxy **stacked, ZPolicyDict *stack_info)
{
  *stacked = NULL;
  if (z_policy_str_check(stack_obj))
    return z_proxy_stack_program(self, z_policy_str_as_string(stack_obj), stacked);
  else
  if (z_policy_seq_check(stack_obj))
    return z_proxy_stack_tuple(self, stack_obj, stacked, stack_info);
  else
    return z_proxy_stack_proxy(self, stack_obj, stacked, stack_info);
}

/* stacked proxy */

static inline ZStackedProxy *
z_stacked_proxy_ref(ZStackedProxy *self)
{
  z_refcount_inc(&self->ref_cnt);
  return self;
}

static void
z_stacked_proxy_unref(ZStackedProxy *self)
{
  if (self && z_refcount_dec(&self->ref_cnt))
    {
      g_mutex_clear(&self->destroy_lock);
      g_free(self);
    }
}

/**
 * Create a new ZStackedProxy instance.
 *
 * @param client_stream client side stream
 * @param server_stream server side stream
 * @param control_stream control stream
 * @param proxy ZProxy instance which initiated stacking
 * @param child_proxy ZProxy instance of the 'child' proxy
 *
 * This function creates a new ZStackedProxy instance encapsulating
 * information about a stacked proxy instance. This information can be freed
 * by calling z_stacked_proxy_destroy().  It consumes the stream references
 * passed to it (client, server) but does not consume the proxy
 * references (@proxy and @child_proxy)
 **/
ZStackedProxy *
z_stacked_proxy_new(ZStream *client_stream, ZStream *server_stream, ZStream *control_stream G_GNUC_UNUSED, ZProxy *proxy, ZProxy *child_proxy, guint32 flags)
{
  ZStackedProxy *self = g_new0(ZStackedProxy, 1);
  gchar buf[Z_STREAM_MAX_NAME];

  z_proxy_enter(proxy);

  g_mutex_init(&self->destroy_lock);

  z_refcount_set(&self->ref_cnt, 1);
  self->flags = flags;

  if (client_stream)
    {
      z_stream_set_nonblock(client_stream, TRUE);

      g_snprintf(buf, sizeof(buf), "%s/client_downstream", proxy->session_id);
      z_stream_set_name(client_stream, buf);
      self->downstreams[EP_CLIENT] = client_stream;
    }

  if (server_stream)
    {
      z_stream_set_nonblock(server_stream, TRUE);

      g_snprintf(buf, sizeof(buf), "%s/server_downstream", proxy->session_id);
      z_stream_set_name(server_stream, buf);
      self->downstreams[EP_SERVER] = server_stream;
    }

  self->proxy = z_proxy_ref(proxy);
  if (child_proxy)
    self->child_proxy = z_proxy_ref(child_proxy);

  if (control_stream)
    {
      g_snprintf(buf, sizeof(buf), "%s/control", proxy->session_id);
      z_stream_set_name(control_stream, buf);

      self->control_stream = z_stream_push(z_stream_push(control_stream,
                                                         z_stream_line_new(NULL, 4096, ZRL_EOL_NL|ZRL_TRUNCATE)),
                                           z_stream_buf_new(NULL, 4096, Z_SBF_IMMED_FLUSH));

      z_stream_set_callback(self->control_stream, G_IO_IN, z_proxy_control_stream_read, z_stacked_proxy_ref(self), (GDestroyNotify) z_stacked_proxy_unref);
      z_stream_set_cond(self->control_stream, G_IO_IN, TRUE);

      /* NOTE: this has to be called after complete initialization of
       * this instance as the callback might be called before
       * ZStackedProxy is actually initialized */

      z_stream_attach_source(self->control_stream, NULL);
    }

  z_proxy_leave(proxy);
  return self;
}

/**
 * Free a ZStackedProxy instasnce.
 *
 * @param self ZStackedProxy instance
 *
 * This function frees all references associated with a stacked proxy
 * and closes the control and downstream streams.
 **/
void
z_stacked_proxy_destroy(ZStackedProxy *self)
{
  gint i;

  z_enter();
  g_mutex_lock(&self->destroy_lock);
  self->destroyed = TRUE;
  if (self->control_stream)
    {
      z_stream_detach_source(self->control_stream);
      z_stream_shutdown(self->control_stream, SHUT_RDWR, NULL);
      z_stream_close(self->control_stream, NULL);
      z_stream_unref(self->control_stream);
      self->control_stream = NULL;
    }

  /* no callbacks after this point, thus the control stream callback
   * does not need a reference */
  for (i = 0; i < EP_MAX; i++)
    {
      if (self->downstreams[i])
        {
          z_stream_shutdown(self->downstreams[i], SHUT_RDWR, NULL);
          z_stream_close(self->downstreams[i], NULL);
          z_stream_unref(self->downstreams[i]);
          self->downstreams[i] = NULL;
        }
    }


  if (self->child_proxy)
    {
      z_proxy_del_child(self->proxy, self->child_proxy);
      z_proxy_unref(self->child_proxy);
      self->child_proxy = NULL;
    }
  if (self->proxy)
    {
      z_proxy_unref(self->proxy);
      self->proxy = NULL;
    }
  g_mutex_unlock(&self->destroy_lock);
  z_stacked_proxy_unref(self);
  z_return();
}
