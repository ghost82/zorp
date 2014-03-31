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
 * Stream like operations for datagram based protocols.
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/dgram.h>
#include <zorp/streamfd.h>
#include <zorp/log.h>
#include <zorp/io.h>
#include <zorp/tpsocket.h>
#include <zorp/cap.h>

enum ZorpDgramFlags
{
  ZDS_LISTEN = 1,
  ZDS_ESTABLISHED = 2,
};

#ifndef IP_ORIGDSTADDR
#define IP_ORIGDSTADDR 20
#endif

#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR IP_ORIGDSTADDR
#endif

#ifndef IPV6_ORIGDSTADDR
#define IPV6_ORIGDSTADDR 74
#endif

#ifndef IPV6_RECVORIGDSTADDR
#define IPV6_RECVORIGDSTADDR IPV6_ORIGDSTADDR
#endif

struct ZDgramSocketFuncs
{
  gint (*open)(guint flags, ZSockAddr *remote, ZSockAddr *local, guint32 sock_flags, gint tos, GError **error);
  gboolean (*setup)(gint fd, guint flags, gint tos, gint family);
  GIOStatus (*recv)(gint fd, ZPktBuf **pack, ZSockAddr **from, ZSockAddr **to, gint *tos, gboolean peek, GError **error);
};

/* Wrapper functions calling the underlying OS specific routines */

static ZDgramSocketFuncs *dgram_socket_funcs;

/**
 * Generic dgram_socket_open, will use the enabled one of _l22_, _nf_ or _ipf_.
 */
static gint
z_dgram_socket_open(guint flags, ZSockAddr *remote, ZSockAddr *local, guint32 sock_flags, gint tos, GError **error)
{
  return dgram_socket_funcs->open(flags, remote, local, sock_flags, tos, error);
}

/**
 * Generic dgram_socket_setup, will use the system dependent implementation _l22_ or _nf_.
 */
static gboolean
z_dgram_socket_setup(gint fd, guint flags, gint tos, gint family)
{
  return dgram_socket_funcs->setup(fd, flags, tos, family);
}

/**
 * Generic dgram_socket_recv, will use the enabled one of _l22_, _nf_ or _ipf_.
 */
GIOStatus
z_dgram_socket_recv(gint fd, ZPktBuf **pack, ZSockAddr **from, ZSockAddr **to, gint *tos, gboolean peek, GError **error)
{
  return dgram_socket_funcs->recv(fd, pack, from, to, tos, peek, error);
}

/**
 * Create a new UDP socket - netfilter tproxy version
 *
 * @param flags Additional flags: ZDS_LISTEN for incoming, ZDS_ESTABLISHED for outgoing socket
 * @param remote Address of the remote endpoint
 * @param local Address of the local endpoint
 * @param sock_flags Flags for binding, see 'z_bind' for details
 * @param error not used
 *
 * FIXME: some words about the difference
 *
 * @return -1 on error, socket descriptor otherwise
 */
gint
z_nf_dgram_socket_open(guint flags, ZSockAddr *remote, ZSockAddr *local, guint32 sock_flags, gint tos, GError **error G_GNUC_UNUSED)
{
  gint fd;

  z_enter();

  g_assert(local != NULL);

  fd = socket(z_map_pf(local->sa.sa_family), SOCK_DGRAM, 0);
  if (fd < 0)
    {
      /*LOG
        This message indicate that Zorp failed opening a new socket.
        It is likely that Zorp reached some resource limit.
       */
      z_log(NULL, CORE_ERROR, 3, "Error opening socket; error='%s'", g_strerror(errno));
      close(fd);
      z_return(-1);
    }

  if (!z_dgram_socket_setup(fd, flags, tos, local->sa.sa_family))
    {
      /* z_dgram_socket_setup() already issued a log message */
      close(fd);
      z_return(-1);
    }

  if (flags & ZDS_LISTEN)
    {
      if (z_bind(fd, local, sock_flags) != G_IO_STATUS_NORMAL)
        z_return(-1); /* z_bind already issued a log message */
    }
  else if (flags & ZDS_ESTABLISHED)
    {
      struct sockaddr_in local_sa;
      socklen_t local_salen = sizeof(local_sa);

      if (z_bind(fd, local, sock_flags) != G_IO_STATUS_NORMAL)
        {
          close(fd);
          z_return(-1);
        }

      /* NOTE: we use connect instead of z_connect, as we do tproxy calls ourselves */
      if (connect(fd, &remote->sa, remote->salen) < 0)
        {
          /*LOG
            This message indicates that UDP connection failed.
           */
          z_log(NULL, CORE_ERROR, 3, "Error connecting UDP socket (nf); error='%s'", g_strerror(errno));
          close(fd);
          z_return(-1);
        }

      /* get fully specified bind address (local might have a wildcard port number) */
      if (getsockname(fd, (struct sockaddr *) &local_sa, &local_salen) < 0)
        {
          /*LOG
            This message indicates that Zorp was unable to query the local address.
          */
          z_log(NULL, CORE_ERROR, 3, "Error querying local address (nf); error='%s'", g_strerror(errno));
          close(fd);
          z_return(-1);
        }
    } /* flags & ZDS_ESTABLISHED */
  z_return(fd);
}

/**
 * Set up Linux-specific socket options on a datagram socket.
 *
 * @param fd Socket descriptor to set up
 * @param flags Flags for binding, see 'z_bind' for details
 *
 * @return FALSE if the setup operation failed, TRUE otherwise
 */
gboolean
z_nf_dgram_socket_setup(gint fd, guint flags, gint tos, gint family)
{
  gint tmp = 1;

  z_enter();
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));
  tmp = 1;
  setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &tmp, sizeof(tmp));
  if (flags & ZDS_LISTEN)
    {
      switch (family)
        {
        case PF_INET:
          tmp = 1;
          if (setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &tmp, sizeof(tmp)) < 0)
            {
              /*LOG
                This message indicates that the setsockopt requesting
                reception of original destination addresses of UDP
                frames failed.
              */
              z_log(NULL, CORE_ERROR, 3, "Error during setsockopt(SOL_IP, IP_RECVORIGADDRS); error='%s'", g_strerror(errno));
              z_return(FALSE);
            }
#if ZORPLIB_ENABLE_TOS
          tmp = 1;
          if (setsockopt(fd, SOL_IP, IP_RECVTOS, &tmp, sizeof(tmp)) < 0)
            {
              z_log(NULL, CORE_ERROR, 3, "Error during setsockopt(SOL_IP, IP_RECVTOS); error='%s'", g_strerror(errno));
              z_return(FALSE);
            }
#endif
          break;
        case PF_INET6:
          tmp = 1;
          if (setsockopt(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &tmp, sizeof(tmp)) < 0)
            {
              /*LOG
                This message indicates that the setsockopt requesting
                reception of original destination addresses of UDP
                frames failed.
              */
              z_log(NULL, CORE_ERROR, 3, "Error during setsockopt(SOL_IPV6, IPV6_RECVORIGADDRS); error='%s'", g_strerror(errno));
              /* FIXME: we should signal failure here, however, we
                 must not do so because IPv6 tproxy support is not
                 widespread enough to expect that it will be
                 available. This also makes the unit tests
                 fail. Should be removed once IPv6 tproxy support can
                 be truly required for Zorp to function. Until that,
                 even thoudh we try to set this socket option failing
                 to do so is not a fatal error.
              */
            }
          break;
        default:
          g_assert_not_reached();
        }
    }
  else if (flags & ZDS_ESTABLISHED)
    {
      switch (family)
        {
        case PF_INET:
          z_fd_set_our_tos(fd, tos);
          break;
        }
    }

  z_return(TRUE);
}

/**
 * Receive data from an UDP socket and encapsulate it in a ZPktBuf.
 *
 * @param fd Socket descriptor to read from
 * @param packet The received packet
 * @param from_addr Address of the remote endpoint
 * @param to_addr Address of the local endpoint
 * @param error not used
 *
 * Provides address information about the source and destination of
 * the packet. - netfilter tproxy version.
 * FIXME: some words about the difference
 *
 * @return The status of the operation
 */
GIOStatus
z_nf_dgram_socket_recv(gint fd, ZPktBuf **packet, ZSockAddr **from_addr, ZSockAddr **to_addr, gint *tos, gboolean peek, GError **error G_GNUC_UNUSED)
{
  struct sockaddr from;
  gchar buf[65536], ctl_buf[64];
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct iovec iov;
  gint rc;

  z_enter();

  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &from;
  msg.msg_namelen = sizeof(from);
  msg.msg_controllen = sizeof(ctl_buf);
  msg.msg_control = ctl_buf;
  msg.msg_iovlen = 1;
  msg.msg_iov = &iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  do
    {
      rc = recvmsg(fd, &msg, peek ? MSG_PEEK : 0);
    }
  while (rc < 0 && errno == EINTR);

  if (rc < 0)
    z_return(errno == EAGAIN ? G_IO_STATUS_AGAIN : G_IO_STATUS_ERROR);

  *packet = z_pktbuf_new();
  z_pktbuf_copy(*packet, buf, rc);
  if (from_addr || to_addr || tos)
    {
      if (from_addr)
        *from_addr = NULL;
      if (to_addr)
        *to_addr = NULL;
      if (tos)
        *tos = -1;

      for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg,cmsg))
        {
          if (to_addr && cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_ORIGDSTADDR)
            {
              struct sockaddr_in *orig = (struct sockaddr_in *) CMSG_DATA(cmsg);

              if (orig->sin_addr.s_addr && orig->sin_port)
                {
                  struct sockaddr_in to;

                  to.sin_family = orig->sin_family;
                  to.sin_addr = orig->sin_addr;
                  to.sin_port = orig->sin_port;
                  *to_addr = z_sockaddr_inet_new2(&to);
                }
            }
          else if (to_addr && cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_ORIGDSTADDR)
            {
              struct sockaddr_in6 *orig = (struct sockaddr_in6 *) CMSG_DATA(cmsg);

              if (!IN6_IS_ADDR_UNSPECIFIED(&orig->sin6_addr) && orig->sin6_port)
                {
                  struct sockaddr_in6 to;

                  to.sin6_family = orig->sin6_family;
                  to.sin6_addr = orig->sin6_addr;
                  to.sin6_port = orig->sin6_port;
                  *to_addr = z_sockaddr_inet6_new2(&to);
                }
            }
          else if (tos && cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TOS)
            {
              memcpy(tos, CMSG_DATA(cmsg), sizeof(*tos));
            }
        }

      if (to_addr && *to_addr == NULL)
        {
          struct sockaddr to;
          socklen_t tolen = sizeof(to);

          getsockname(fd, &to, &tolen);
          *to_addr = z_sockaddr_new(&to, tolen);
        }

      if (from_addr)
        {
          *from_addr = z_sockaddr_new(&from, sizeof(from));
        }
    }
  z_return(G_IO_STATUS_NORMAL);

}

ZDgramSocketFuncs z_nf_dgram_socket_funcs =
{
  z_nf_dgram_socket_open,
  z_nf_dgram_socket_setup,
  z_nf_dgram_socket_recv
};

/**
 * Initialize datagram module.
 *
 * @param sysdep_tproxy Required functionality to use: Z_SD_TPROXY_[LINUX22|NETFILTER_V12|NETFILTER_V20]
 *
 * Initialises the function table according to the requested
 * transparency method.
 *
 * @return TRUE on success
 */
gboolean
z_dgram_init(void)
{
  z_enter();

  dgram_socket_funcs = &z_nf_dgram_socket_funcs;

  z_return(TRUE);
}

/* Datagram listener */

struct ZDGramListener
{
  ZListener super;
  gint rcvbuf;
  gint session_limit;
};

static gint
z_dgram_listener_open_listener(ZListener *s)
{
  ZDGramListener *self = Z_CAST(s, ZDGramListener);
  gint fd;

  z_enter();
  fd = z_dgram_socket_open(ZDS_LISTEN, NULL, s->bind_addr, s->sock_flags, -1, NULL);
  if (fd == -1)
    {
      /*LOG
        This message indicate that the creation of a new socket failed
        for the given reason. It is likely that the system is running low
        on memory, or the system is running out of the available fds.
       */
      z_log(s->session_id, CORE_ERROR, 2, "Cannot create socket; error='%s'", g_strerror(errno));
      z_return(-1);
    }
  z_fd_set_nonblock(fd, 1);
  if (self->rcvbuf &&
      setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &self->rcvbuf, sizeof(self->rcvbuf)) < 0)
    {
      z_log(s->session_id, CORE_ERROR, 2, "Cannot set receive buffer size on listening datagram socket; error='%s'", g_strerror(errno));
      close(fd);
      z_return(-1);
    }

  if (z_getsockname(fd, &s->local, s->sock_flags) != G_IO_STATUS_NORMAL)
    {
      z_log(s->session_id, CORE_ERROR, 2, "Cannot query local address of listening datagram socket; error='%s'", g_strerror(errno));
      close(fd);
      z_return(-1);
    }
  z_return(fd);
}

static GIOStatus
z_dgram_listener_accept_connection(ZListener *self, ZStream **fdstream, ZSockAddr **client, ZSockAddr **dest)
{
  gint newfd;
  GIOStatus res;
  ZSockAddr *from = NULL, *to = NULL;
  gint tos;
  ZPktBuf *packet;
  static gboolean udp_accept_available = TRUE;
  cap_t saved_caps;

  z_enter();
  /* FIXME: using accept() on UDP sockets requires kernel extension */
  if (udp_accept_available)
    {
      saved_caps = cap_save();
      cap_enable(CAP_NET_ADMIN);
      cap_enable(CAP_NET_BIND_SERVICE);
      res = z_accept(self->fd, &newfd, client, self->sock_flags);
      if (res != G_IO_STATUS_NORMAL)
        {
          if (errno == EOPNOTSUPP)
            {
              cap_restore(saved_caps);
              udp_accept_available = FALSE;
              z_log(self->session_id, CORE_INFO, 4, "UDP accept() support unavailable, falling back to legacy datagram handling");
              goto no_udp_accept;
            }
          else
            {
              if (errno != EAGAIN)
                z_log(self->session_id, CORE_ERROR, 1, "Error accepting on listening dgram socket; fd='%d', error='%s'", self->fd, g_strerror(errno));
              cap_restore(saved_caps);
              z_return(res);
            }
        }

      cap_restore(saved_caps);

      /* this socket behaves like a listening one when we're reading the first packet to
       * determine the original destination address */
      if (!z_dgram_socket_setup(newfd, ZDS_LISTEN, 0, self->local->sa.sa_family))
        {
          close(newfd);
          z_return(G_IO_STATUS_ERROR);
        }

      /* we are not allowed to block on this operation, as due to a
       * race condition it's possible that accept() returns an fd
       * which has nothing in its queue */
      z_fd_set_nonblock(newfd, 1);
      *dest = NULL;
      res = z_dgram_socket_recv(newfd, &packet, &from, &to, &tos, TRUE, NULL);
      if (res == G_IO_STATUS_AGAIN)
        {
          z_log(self->session_id, CORE_ERROR, 4, "No datagram messages are available in accepted socket; error='%s'", g_strerror(errno));
          close(newfd);
          z_return(G_IO_STATUS_ERROR);
        }

      if (res != G_IO_STATUS_NORMAL)
        {
          z_log(self->session_id, CORE_ERROR, 3, "Error determining original destination address for datagram connection; error='%s'", g_strerror(errno));
          res = G_IO_STATUS_NORMAL;
        }
      else
        {
          z_pktbuf_unref(packet);
          *dest = to;
        }

      z_fd_set_nonblock(newfd, 0);
      /* once we have the original address we set up the socket for establised mode;
       * this includes setting the TOS to the appropriate value */
      if (!z_dgram_socket_setup(newfd, ZDS_ESTABLISHED, tos, self->local->sa.sa_family))
        {
          res = G_IO_STATUS_ERROR;
          goto error_after_recv;
        }
      z_sockaddr_unref(from);
      *fdstream = z_stream_fd_new(newfd, "");
    }
  else
    {
 no_udp_accept:
      *client = NULL;
      *dest = NULL;
      res = z_dgram_socket_recv(self->fd, &packet, &from, &to, &tos, FALSE, NULL);
      /* FIXME: fetch all packets in the receive buffer to be able to stuff
       * all to the newly created socket */
      if (res == G_IO_STATUS_ERROR || from == NULL || to == NULL || packet == NULL)
        {
          z_log(self->session_id, CORE_ERROR, 1, "Error receiving datagram on listening stream; fd='%d', error='%s'", self->fd, g_strerror(errno));
        }
      else
        {
          newfd = z_dgram_socket_open(ZDS_ESTABLISHED, from, to, ZSF_MARK_TPROXY, tos, NULL);
          if (newfd < 0)
            {
              z_log(self->session_id, CORE_ERROR, 3, "Error creating session socket, dropping packet; error='%s'", g_strerror(errno));
              res = G_IO_STATUS_ERROR;
            }
          else
            {
              *fdstream = z_stream_fd_new(newfd, "");
              if (*fdstream && !z_stream_unget_packet(*fdstream, packet, NULL))
                {
                  z_pktbuf_unref(packet);
                  z_log(self->session_id, CORE_ERROR, 3, "Error creating session socket, dropping packet;");
                  close(newfd);
                }
              else
                {
                  *client = z_sockaddr_ref(from);
                  *dest = z_sockaddr_ref(to);
                }
            }
          z_sockaddr_unref(from);
          z_sockaddr_unref(to);
        }
    }
  z_return(res);

error_after_recv:
  if (*dest != NULL)
    {
      z_sockaddr_unref(*dest);
      *dest = NULL;
    }
  z_sockaddr_unref(from);
  close(newfd);
  z_return(res);
}

ZListener *
z_dgram_listener_new(const gchar *session_id,
                     ZSockAddr *local,
                     guint32 sock_flags,
                     gint rcvbuf,
                     ZAcceptFunc callback,
                     gpointer user_data)
{
  ZDGramListener *self;

  self = Z_CAST(z_listener_new(Z_CLASS(ZDGramListener), session_id, local, sock_flags, callback, user_data), ZDGramListener);
  if (self)
    {
      self->rcvbuf = rcvbuf;
      self->session_limit = 10;
    }
  return &self->super;
}

ZListenerFuncs z_dgram_listener_funcs =
{
  {
    Z_FUNCS_COUNT(ZListener),
    NULL,
  },
  z_dgram_listener_open_listener,
  z_dgram_listener_accept_connection
};

Z_CLASS_DEF(ZDGramListener, ZListener, z_dgram_listener_funcs);

/* datagram connector */

static ZConnectorFuncs z_dgram_connector_funcs =
{
  {
    Z_FUNCS_COUNT(ZConnector),
    NULL,
  }
};

ZClass ZDGramConnector__class =
{
  Z_CLASS_HEADER,  /* super, funcs_resolved */
  Z_CLASS(ZConnector), /* super_class */
  "ZDGramConnector", /* name */
  sizeof(ZConnector), /* size */
  &z_dgram_connector_funcs.super /* funcs */
};
