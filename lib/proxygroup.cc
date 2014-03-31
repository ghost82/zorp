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
 ***************************************************************************/

#include <zorp/proxygroup.h>

#include <zorp/poll.h>
#include <zorp/szig.h>
#include <zorp/thread.h>

struct ZProxyGroup
{
  ZRefCount ref_cnt;
  GMutex lock;
  gboolean thread_started;
  gboolean orphaned;
  GAsyncQueue *nonblocking_start_queue;
  GList *nonblocking_proxies;
  ZPoll *poll;
  guint sessions;
  guint max_sessions;
};

static gpointer
z_proxy_group_thread_func(gpointer s)
{
  ZProxyGroup *self = (ZProxyGroup *) s;

  z_enter();
  g_mutex_lock(&self->lock);
  self->poll = z_poll_new();
  g_mutex_unlock(&self->lock);

  while (!self->orphaned || self->sessions > 0)
    {
      z_proxy_group_iteration(self);
    }
  z_proxy_group_unref(self);
  z_leave();
  return NULL;
}

static gboolean
z_proxy_group_start_thread(ZProxyGroup *self)
{
  z_enter();
  g_mutex_lock(&self->lock);
  if (!self->thread_started)
    {
      self->nonblocking_start_queue = g_async_queue_new();
      self->thread_started = TRUE;
      g_mutex_unlock(&self->lock);

      if (!z_thread_new("group", z_proxy_group_thread_func, z_proxy_group_ref(self)))
        {
          z_proxy_group_unref(self);
          z_leave();
          return FALSE;
        }
    }
  else
    {
      g_mutex_unlock(&self->lock);
    }
  z_leave();
  return TRUE;
}

gboolean
z_proxy_group_start_session(ZProxyGroup *self, ZProxy *proxy)
{
  gboolean started;

  z_enter();
  g_mutex_lock(&self->lock);
  if (self->sessions >= self->max_sessions)
    {
      g_mutex_unlock(&self->lock);
      z_leave();
      return FALSE;
    }

  self->sessions++;
  g_mutex_unlock(&self->lock);

  if (proxy->flags & ZPF_NONBLOCKING)
    {
      if (!z_proxy_group_start_thread(self))
        {
          z_leave();
          return FALSE;
        }
      g_async_queue_push(self->nonblocking_start_queue, z_proxy_ref(proxy));
      g_mutex_lock(&self->lock);
      if (self->poll)
        z_poll_wakeup(self->poll);
      g_mutex_unlock(&self->lock);
      z_leave();
      return TRUE;
    }
  else
    {

      Py_BEGIN_ALLOW_THREADS;
      started = z_proxy_threaded_start(proxy, self);
      Py_END_ALLOW_THREADS;
      if (!started)
        {
          z_log(NULL, CORE_ERROR, 1, "Error starting proxy; module='%s'", proxy->super.isa->name);
          z_leave();
          return FALSE;
        }

      z_policy_thread_ready(proxy->thread);

      z_leave();
      return TRUE;
    }
}

void
z_proxy_group_stop_session(ZProxyGroup *self, ZProxy *proxy)
{
  z_enter();
  if (proxy->flags & ZPF_NONBLOCKING)
    {
      GList *l;

      /* NOTE: nonblocking proxies run in the same thread, thus this
       * function is always called from the ZProxyGroup thread, no locking
       * is necessary */

      /* FIXME: use a better list deletion algorithm (like embed a list
       * header to ZProxy and use an O(1) deletion */

      l = g_list_find(self->nonblocking_proxies, proxy);
      if (l)
        {
          self->nonblocking_proxies = g_list_delete_link(self->nonblocking_proxies, l);
          z_proxy_unref(proxy);
        }
    }
  g_mutex_lock(&self->lock);
  self->sessions--;
  g_mutex_unlock(&self->lock);
  z_leave();

}

GMainContext *
z_proxy_group_get_context(ZProxyGroup *self)
{
  if (self->poll)
    return z_poll_get_context(self->poll);
  return NULL;
}

ZPoll *
z_proxy_group_get_poll(ZProxyGroup *self)
{
  return self->poll;
}

gboolean
z_proxy_group_iteration(ZProxyGroup *self)
{
  ZProxy *proxy;
  GList *p;
  gboolean res = FALSE;

  z_enter();
  while ((proxy = static_cast<ZProxy *>(g_async_queue_try_pop(self->nonblocking_start_queue))))
    {
      z_policy_thread_ready(proxy->thread);
      if (!z_proxy_nonblocking_start(proxy, self))
        {
          z_proxy_nonblocking_stop(proxy);
          z_proxy_unref(proxy);
        }
      else
        {
          z_szig_value_add_thread_id(proxy);
          self->nonblocking_proxies = g_list_prepend(self->nonblocking_proxies, proxy);
        }
    }
  for (p = self->nonblocking_proxies; p; p = p->next)
    {
      if (!z_proxy_loop_iteration((ZProxy *) p->data))
        {
          z_proxy_nonblocking_stop((ZProxy *) p->data);
        }
    }
  if (!self->orphaned || self->sessions > 0)
    res = z_poll_iter_timeout(self->poll, -1);

  z_leave();
  return res;
}

void
z_proxy_group_orphan(ZProxyGroup *self)
{
  self->orphaned = TRUE;
  if (self->poll)
    z_poll_wakeup(self->poll);
  z_proxy_group_unref(self);
}

/**
 * z_proxy_group_wakeup:
 *
 * NOTE: runs from a different thread, but with a reference held to self
 **/
void
z_proxy_group_wakeup(ZProxyGroup *self)
{
  z_poll_wakeup(self->poll);
}

ZProxyGroup *
z_proxy_group_new(gint max_sessions)
{
  ZProxyGroup *self = g_new0(ZProxyGroup, 1);

  g_mutex_init(&self->lock);

  z_refcount_set(&self->ref_cnt, 1);

  if (max_sessions)
    self->max_sessions = max_sessions;
  else
    self->max_sessions = 1;

  return self;
}

ZProxyGroup *
z_proxy_group_ref(ZProxyGroup *self)
{
  z_refcount_inc(&self->ref_cnt);
  return self;
}

void
z_proxy_group_unref(ZProxyGroup *self)
{
  if (self && z_refcount_dec(&self->ref_cnt))
    {
      if (self->nonblocking_start_queue)
        {
          ZProxy *proxy;

          while ((proxy = static_cast<ZProxy *>(g_async_queue_try_pop(self->nonblocking_start_queue))))
            {
              z_proxy_unref(proxy);
            }
          g_async_queue_unref(self->nonblocking_start_queue);
        }
      while (self->nonblocking_proxies)
        {
          z_proxy_unref((ZProxy *) self->nonblocking_proxies->data);
          self->nonblocking_proxies = g_list_delete_link(self->nonblocking_proxies, self->nonblocking_proxies);
        }

      if (self->poll)
        z_poll_unref(self->poll);

      g_mutex_clear(&self->lock);

      g_free(self);
    }
}
