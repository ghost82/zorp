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
 * Author  : Laszlo Attila Toth <laszlo.attila.toth@balabit.com>
 *
 ***************************************************************************/

/**
 * This file contains functions to manage sessions of Zorp instances in case of
 * session-based licensing.
 *
 * A session starts when a new incoming connection appears. A session may contain
 * several proxies, which are stacked or chained. In the Python layer this kind of
 * session is named as MasterSession. Note that there are other Session types, but
 * they are used "internally", for slightly different purposes.
 *
 * The behaviour is the following:
 *   - There is a shared memory page, named as 'zorp-licenses'
 *   - It is guarded by a semaphore, named as 'zorp-licenses-sem'
 *   - The page contains a table, array of fixed-length rows
 *   - Each row represents a Zorp instance, with the following fields:
 *              - the PID of that Zorp instance
 *              - its (instance) name
 *              - its session count
 *   - Each instance registers itself within that table
 *   - Initially the session count is zero, and increased/decreased
 *     by Python's Service.startSession/stopSession methods
 *   - Each instance manages the session counter
 *               - in the shared memory (one row's second field)
 *               - internally in a global variable of the process
 */

#include <zorp/zorp.h>
#include <zorp/log.h>
#include <zorp/session.h>
#include <zorp/session_impl.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sched.h>

/**
 * The session count specified by the license
 * 0 means that it is unused
 */
static gint max_session_count = 0;

static gint current_session_count = 0;

ZSessionInfo session_info =
{
  0,
  0,
  -1,
  NULL,
  NULL,
  NULL
};

gint
z_session_get_max(void)
{
  return max_session_count;
}

void
z_session_set_max(gint max)
{
  max_session_count = max;
}

void
z_session_lock(void)
{
  sem_wait(session_info.sem);
}

void
z_session_unlock(void)
{
  sem_post(session_info.sem);
}

static inline gint
z_session_get_count_from_shmem_unlocked(void)
{
  gint current_count = 0;
  ZInstanceEntry *current = NULL;

  for (uint32_t index = 0; index != session_info.data->instance_count; ++index)
   {
      current = &session_info.data->entries[index];
      if (current->name[0] && current != session_info.self_row)
        current_count += current->count;
    }

  current_count += current_session_count;

  return current_count;
}

static inline ZSessionLimitVerdict
z_session_update_counter_if_limit_not_reached_unlocked(gint total_started_session)
{
  ZSessionLimitVerdict res = Z_SLV_NOT_EXCEEDED;

  gint max = z_session_get_max();
  if (max == -1 || total_started_session < max)
    session_info.self_row->count = current_session_count;
  else if (((double) total_started_session) < max * session_info.graceful_session_limit_modifier)
    {
      session_info.self_row->count = current_session_count;
      res = Z_SLV_GRACEFULLY_EXCEEDED;
    }
  else
    res = Z_SLV_EXCEEDED;

  return res;
}

