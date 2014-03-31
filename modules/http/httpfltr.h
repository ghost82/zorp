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

#ifndef ZORP_MODULES_HTTPFLTR_H_INCLUDED
#define ZORP_MODULES_HTTPFLTR_H_INCLUDED

#include <zorp/proxy/transfer2.h>
#include <zorp/proxycommon.h>
#include "http.h"

struct _HttpTransfer
{
  ZTransfer2 super;

  GString *preamble;
  guint preamble_ofs;

  /* whether to actually suppress DATA even if they seem to be some (e.g. response HEAD request) */
  gboolean suppress_data;

  /* whether to expect data if there is nothing explicit indicating it (e.g. response entities) */
  gboolean expect_data;

  /* transfer endpoints */
  ZEndpoint transfer_from, transfer_to;
  gint transfer_type;

  /* the headers to send to the downstream proxy */
  GString *stacked_preamble;
  /* offset within mime_headers if writing blocked */
  guint stacked_preamble_ofs;
  guint stacked_preamble_read_bytes;

  /* function used to format the preamble to stacked proxy/peer */
  HttpTransferPreambleFunc format_preamble_func;

  /* whether to push mime headers to the downstream proxy */
  gboolean push_mime_headers;

  /* whether to force the end of the connection */
  gboolean force_nonpersistent_mode;
  /* we can stay persisent, but only if we receive a content-length hint from downstream proxy */
  gboolean persistent_with_cl_hint_only;

  HttpHeader *transfer_encoding_hdr, *content_length_hdr;

  /* used while stripping off MIME headers returned by the downstream proxy */
  gint dst_eol_count;

  /* complete content_length, -2 if no entity, -1 if length unknown, otherwise the exact length */
  gint64 content_length;

  /* indicates whether source is chunked */
  gboolean src_chunked;

  /* source read state */
  guint src_read_state;

  /* indicates that the current chunk is an EOF chunk */
  gboolean src_last_chunk;

  /* indicates that this is the last chunk and that it was truncated
   * because the body was over max_body_length */
  gboolean src_chunk_truncated;

  /* the number of bytes waiting to be read in the current chunk */
  guint64 src_chunk_left;

  /* the total number of bytes read during this transfer */
  guint64 src_whole_length;

  gboolean dst_chunked;
  guint dst_write_state;

  /* the number of bytes still to be written to the destination */
  guint64 dst_chunk_left;

  gchar dst_chunk_length_buf[32];
  guint dst_chunk_length_ofs;
  guint dst_chunk_length_end;
  guint dst_footer_ofs;

  /* the total number of bytes in the chunk being written */
  guint64 dst_chunk_length;

  /* the total number of transferred bytes on the write side */
  guint64 dst_whole_length;

};

gboolean http_transfer_has_content(HttpTransfer *self);

#endif /* ZORP_MODULES_HTTPFLTR_H_INCLUDED */
