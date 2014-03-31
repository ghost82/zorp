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

#ifndef ZORP_PYSTREAM_H_INCLUDED
#define ZORP_PYSTREAM_H_INCLUDED

#include <zorp/zpython.h>
#include <zorp/stream.h>

/*+

  ZPolicyStream is the Python interface to ZStream.

  +*/
typedef struct _ZPolicyStream
{
  PyObject_HEAD
  ZStream *stream;
} ZPolicyStream;

extern PyTypeObject z_policy_stream_type;

#define z_policy_stream_check(ob) ((ob)->ob_type == &z_policy_stream_type)

void z_policy_stream_module_init(void);

PyObject *z_policy_stream_new(ZStream *Stream);

static inline ZStream *
z_policy_stream_get_stream(PyObject *s)
{
  ZPolicyStream *self = (ZPolicyStream *) s;

  g_assert(z_policy_stream_check(s));
  return z_stream_ref(self->stream);
}

#endif
