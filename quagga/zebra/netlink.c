/* Kernel routing table updates using netlink over GNU/Linux system.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

/* Hack for GNU libc version 2. */
#ifndef MSG_TRUNC
#define MSG_TRUNC      0x20
#endif /* MSG_TRUNC */

#include "linklist.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "connected.h"
#include "table.h"
#include "rib.h"
#include "thread.h"
#include "privs.h"

#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/netlink.h"

extern struct zebra_t zebrad;
extern struct zebra_privs_t zserv_privs;
extern u_int32_t nl_rcvbufsize;

struct message nlmsg_str[] = {
  {RTM_NEWROUTE, "RTM_NEWROUTE"},
  {RTM_DELROUTE, "RTM_DELROUTE"},
  {RTM_GETROUTE, "RTM_GETROUTE"},
  {RTM_NEWLINK,  "RTM_NEWLINK"},
  {RTM_DELLINK,  "RTM_DELLINK"},
  {RTM_GETLINK,  "RTM_GETLINK"},
  {RTM_NEWADDR,  "RTM_NEWADDR"},
  {RTM_DELADDR,  "RTM_DELADDR"},
  {RTM_GETADDR,  "RTM_GETADDR"},
  {0, NULL}
};

char *nexthop_types_desc(int x)
{
  static char buf[1024];
  if (CHECK_FLAG (x, ZEBRA_NEXTHOP_IFINDEX)) {
    sprintf(buf, "ifindex ");
  }
  if (CHECK_FLAG (x, ZEBRA_NEXTHOP_IFNAME)) {
    sprintf(buf, "ifname ");
  }
  if (CHECK_FLAG (x, ZEBRA_NEXTHOP_IPV4)) {
    sprintf(buf, "IPv4 ");
  }
  if (CHECK_FLAG (x, ZEBRA_NEXTHOP_IPV6)) {
    sprintf(buf, "IPv6 ");
  }
  if (CHECK_FLAG (x, ZEBRA_NEXTHOP_DROP)) {
    sprintf(buf, "Drop ");
  }
  return buf;
}

/* Make socket for Linux netlink interface. */
int
netlink_socket (struct nlsock *nl, int proto, unsigned long groups)
{
  int ret;
  struct sockaddr_nl snl;
  int sock;
  int namelen;
  int save_errno;

  sock = socket (AF_NETLINK, SOCK_RAW, proto);
  if (sock < 0)
    {
      zlog (NULL, LOG_ERR, "Can't open %s socket: %s", nl->name,
            safe_strerror (errno));
      return -1;
    }

  ret = fcntl (sock, F_SETFL, O_NONBLOCK);
  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "Can't set %s socket flags: %s", nl->name,
            safe_strerror (errno));
      close (sock);
      return -1;
    }

  /* Set receive buffer size if it's set from command line */
  if (nl_rcvbufsize)
    {
      u_int32_t oldsize, oldlen;
      u_int32_t newsize, newlen;

      oldlen = sizeof(oldsize);
      newlen = sizeof(newsize);

      ret = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &oldsize, &oldlen);
      if (ret < 0)
	{
	  zlog (NULL, LOG_ERR, "Can't get %s receive buffer size: %s", nl->name,
		safe_strerror (errno));
	  close (sock);
	  return -1;
	}

      ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &nl_rcvbufsize,
		       sizeof(nl_rcvbufsize));
      if (ret < 0)
	{
	  zlog (NULL, LOG_ERR, "Can't set %s receive buffer size: %s", nl->name,
		safe_strerror (errno));
	  close (sock);
	  return -1;
	}

      ret = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &newsize, &newlen);
      if (ret < 0)
	{
	  zlog (NULL, LOG_ERR, "Can't get %s receive buffer size: %s", nl->name,
		safe_strerror (errno));
	  close (sock);
	  return -1;
	}

      zlog (NULL, LOG_INFO,
	    "Setting netlink socket receive buffer size: %u -> %u",
	    oldsize, newsize);
    }

  memset (&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;
  snl.nl_groups = groups;

  /* Bind the socket to the netlink structure for anything. */
  if (zserv_privs.change (ZPRIVS_RAISE))
    {
      zlog (NULL, LOG_ERR, "Can't raise privileges");
      return -1;
    }

  ret = bind (sock, (struct sockaddr *) &snl, sizeof snl);
  save_errno = errno;
  if (zserv_privs.change (ZPRIVS_LOWER))
    zlog (NULL, LOG_ERR, "Can't lower privileges");

  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "Can't bind %s socket to group 0x%x: %s",
            nl->name, snl.nl_groups, safe_strerror (save_errno));
      close (sock);
      return -1;
    }

  /* multiple netlink sockets will have different nl_pid */
  namelen = sizeof snl;
  ret = getsockname (sock, (struct sockaddr *) &snl, (socklen_t *) &namelen);
  if (ret < 0 || namelen != sizeof snl)
    {
      zlog (NULL, LOG_ERR, "Can't get %s socket name: %s", nl->name,
            safe_strerror (errno));
      close (sock);
      return -1;
    }

  nl->snl = snl;
  nl->sock = sock;
  return ret;
}

int
set_netlink_blocking (struct nlsock *nl, int *flags)
{

  /* Change socket flags for blocking I/O.  */
  if ((*flags = fcntl (nl->sock, F_GETFL, 0)) < 0)
    {
      zlog (NULL, LOG_ERR, "%s:%i F_GETFL error: %s",
            __FUNCTION__, __LINE__, safe_strerror (errno));
      return -1;
    }
  *flags &= ~O_NONBLOCK;
  if (fcntl (nl->sock, F_SETFL, *flags) < 0)
    {
      zlog (NULL, LOG_ERR, "%s:%i F_SETFL error: %s",
            __FUNCTION__, __LINE__, safe_strerror (errno));
      return -1;
    }
  return 0;
}

int
set_netlink_nonblocking (struct nlsock *nl, int *flags)
{
  /* Restore socket flags for nonblocking I/O */
  *flags |= O_NONBLOCK;
  if (fcntl (nl->sock, F_SETFL, *flags) < 0)
    {
      zlog (NULL, LOG_ERR, "%s:%i F_SETFL error: %s",
            __FUNCTION__, __LINE__, safe_strerror (errno));
      return -1;
    }
  return 0;
}

static int
do_netlink_request (struct nlsock *nl, void *buf, int size)
{
  int ret;
  struct sockaddr_nl snl;
  int save_errno;

  memset (&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;

  /* Check netlink socket. */
  if (nl->sock < 0)
    {
      zlog (NULL, LOG_ERR, "%s socket isn't active.", nl->name);
      return -1;
    }

  /* linux appears to check capabilities on every message 
   * have to raise caps for every message sent
   */
  if (zserv_privs.change (ZPRIVS_RAISE))
    {
      zlog (NULL, LOG_ERR, "Can't raise privileges");
      return -1;
    }

  ret = sendto (nl->sock, buf, size, 0, (struct sockaddr *) &snl, sizeof snl);
  save_errno = errno;

  if (zserv_privs.change (ZPRIVS_LOWER))
    zlog (NULL, LOG_ERR, "Can't lower privileges");

  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "%s sendto failed: %s", nl->name,
            safe_strerror (save_errno));
      return -1;
    }

  return 0;
}

/* Get type specified information from netlink. */
int
netlink_request (int family, int type, struct nlsock *nl)
{
  struct
  {
    struct nlmsghdr nlh;
    struct rtgenmsg g;
  } req;

  memset (&req, 0, sizeof req);
  req.nlh.nlmsg_len = sizeof req;
  req.nlh.nlmsg_type = type;
  req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
  req.nlh.nlmsg_pid = 0;
  req.nlh.nlmsg_seq = ++nl->seq;
  req.g.rtgen_family = family;

  return do_netlink_request(nl, (void*)&req, sizeof(req));
}

#if defined(HAVE_MPLS) && defined(LINUX_MPLS)
int
genetlink_request (int family, int type, struct nlsock *nl)
{
  struct genlmsghdr *ghdr;

  struct {
    struct nlmsghdr n;
    char            buf[4096];
  } req;

  memset(&req, 0, sizeof(req));

  req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
  req.n.nlmsg_type = family;
  req.n.nlmsg_seq = ++nl->seq;

  ghdr = NLMSG_DATA(&req.n);
  ghdr->cmd = type;

  return do_netlink_request(nl, (void*)&req, sizeof(req));
}
#endif

/* Receive message from netlink interface and pass those information
   to the given function. */
int
netlink_parse_info (int (*filter) (struct nlsock *nl, struct sockaddr_nl *, struct nlmsghdr *),
                    struct nlsock *nl, void *a, unsigned int size)
{
  char buf[16384];
  int status;
  int ret = 0;
  int error;

  if (!a)
    {
      a = (void*)buf;
      size = sizeof(buf);
    }

  while (1)
    {
      struct iovec iov = { a, size };
      struct sockaddr_nl snl;
      struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };
      struct nlmsghdr *h;
      int save_errno;

      if (zserv_privs.change (ZPRIVS_RAISE))
        zlog (NULL, LOG_ERR, "Can't raise privileges");

      status = recvmsg (nl->sock, &msg, 0);
      save_errno = errno;

      if (zserv_privs.change (ZPRIVS_LOWER))
        zlog (NULL, LOG_ERR, "Can't lower privileges");

      if (status < 0)
        {
          if (save_errno == EINTR)
            continue;
          if (save_errno == EWOULDBLOCK || save_errno == EAGAIN)
            break;
          zlog (NULL, LOG_ERR, "%s recvmsg overrun: %s",
	  	nl->name, safe_strerror(save_errno));
          continue;
        }

      if (status == 0)
        {
          zlog (NULL, LOG_ERR, "%s EOF", nl->name);
          return -1;
        }

      if (msg.msg_namelen != sizeof snl)
        {
          zlog (NULL, LOG_ERR, "%s sender address length error: length %d",
                nl->name, msg.msg_namelen);
          return -1;
        }
      
      /* JF: Ignore messages that aren't from the kernel */
      if ( snl.nl_pid != 0 )
        {
          zlog ( NULL, LOG_ERR, "Ignoring message from pid %u", snl.nl_pid );
          continue;
        }

      for (h = (struct nlmsghdr *) a; NLMSG_OK (h, (unsigned int) status);
           h = NLMSG_NEXT (h, status))
        {
          /* Finish of reading. */
          if (h->nlmsg_type == NLMSG_DONE)
            return ret;

          /* Error handling. */
          if (h->nlmsg_type == NLMSG_ERROR)
            {
              struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);

              /* If the error field is zero, then this is an ACK */
              if (err->error == 0)
                {
                  if (IS_ZEBRA_DEBUG_KERNEL)
                    {
                      zlog_debug ("%s: %s ACK: type=%s(%u), seq=%u, pid=%u",
                                 __FUNCTION__, nl->name,
                                 lookup (nlmsg_str, err->msg.nlmsg_type),
                                 err->msg.nlmsg_type, err->msg.nlmsg_seq,
                                 err->msg.nlmsg_pid);
                    }

                  /* return if not a multipart message, otherwise continue */
                  if (!(h->nlmsg_flags & NLM_F_MULTI))
                    {
                      return 0;
                    }
                  continue;
                }

              if (h->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr)))
                {
                  zlog (NULL, LOG_ERR, "%s error: message truncated",
                        nl->name);
                  return -1;
                }

              /* Deal with Error Noise  - MAG */
              {
                int loglvl = LOG_ERR;
                int errnum = err->error;
                int msg_type = err->msg.nlmsg_type;

		/* nl->cmd is defined only for the CMD sockets */
                if (nl->cmd && (-errnum == ENODEV || -errnum == ESRCH))
                  loglvl = LOG_DEBUG;

                zlog (NULL, loglvl, "%s error: %s, type=%s(%u), "
                      "seq=%u, pid=%u",
                      nl->name, safe_strerror (-errnum),
                      lookup (nlmsg_str, msg_type),
                      msg_type, err->msg.nlmsg_seq, err->msg.nlmsg_pid);
              }
              /*
                 ret = -1;
                 continue;
               */
              return -1;
            }

          /* OK we got netlink message. */
          if (IS_ZEBRA_DEBUG_KERNEL)
            zlog_debug ("netlink_parse_info: %s type %s(%u), seq=%u, pid=%u",
                       nl->name,
                       lookup (nlmsg_str, h->nlmsg_type), h->nlmsg_type,
                       h->nlmsg_seq, h->nlmsg_pid);

          error = (*filter) (nl, &snl, h);
          if (error < 0)
            {
              zlog (NULL, LOG_ERR, "%s filter function error", nl->name);
              ret = error;
            }
        }

      /* After error care. */
      if (msg.msg_flags & MSG_TRUNC)
        {
          zlog (NULL, LOG_ERR, "%s error: message truncated", nl->name);
          continue;
        }
      if (status)
        {
          zlog (NULL, LOG_ERR, "%s error: data remnant size %d", nl->name,
                status);
          return -1;
        }
    }
  return ret;
}

/* Utility function for parse rtattr. */
void
netlink_parse_rtattr (struct rtattr **tb, int max, struct rtattr *rta,
                      int len)
{
  while (RTA_OK (rta, len))
    {
      if (rta->rta_type <= max)
        tb[rta->rta_type] = rta;
      rta = RTA_NEXT (rta, len);
    }
}

/* Utility function  comes from iproute2. 
   Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru> */
int
addattr_l (struct nlmsghdr *n, unsigned int maxlen, int type,
           void *data, int alen)
{
  int len;
  struct rtattr *rta;

  len = RTA_LENGTH (alen);

  if (NLMSG_ALIGN (n->nlmsg_len) + len > maxlen)
    return -1;

  rta = (struct rtattr *) (((char *) n) + NLMSG_ALIGN (n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy (RTA_DATA (rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

  return 0;
}

int
rta_addattr_l (struct rtattr *rta, int maxlen, int type, void *data, int alen)
{
  int len;
  struct rtattr *subrta;

  len = RTA_LENGTH (alen);

  if (RTA_ALIGN (rta->rta_len) + len > maxlen)
    return -1;

  subrta = (struct rtattr *) (((char *) rta) + RTA_ALIGN (rta->rta_len));
  subrta->rta_type = type;
  subrta->rta_len = len;
  memcpy (RTA_DATA (subrta), data, alen);
  rta->rta_len = NLMSG_ALIGN (rta->rta_len) + len;

  return 0;
}

/* Utility function comes from iproute2. 
   Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru> */
int
addattr32 (struct nlmsghdr *n, unsigned int maxlen, int type, int data)
{
  int len;
  struct rtattr *rta;

  len = RTA_LENGTH (4);

  if (NLMSG_ALIGN (n->nlmsg_len) + len > maxlen)
    return -1;

  rta = (struct rtattr *) (((char *) n) + NLMSG_ALIGN (n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy (RTA_DATA (rta), &data, 4);
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

  return 0;
}

int
netlink_talk_filter (struct nlsock *nl, struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  zlog_warn ("netlink_talk: ignoring message type 0x%04x", h->nlmsg_type);
  return 0;
}

/* sendmsg() to netlink socket then recvmsg(). */
int
netlink_talk (struct nlmsghdr *n, struct nlsock *nl, void *a, unsigned int size)
{
  int status;
  struct sockaddr_nl snl;
  struct iovec iov = { (void *) n, n->nlmsg_len };
  struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };
  int flags = 0;
  int snb_ret;
  int save_errno;

  memset (&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;

  n->nlmsg_seq = ++nl->seq;

  /* Request an acknowledgement by setting NLM_F_ACK */
  if (!a)
    n->nlmsg_flags |= NLM_F_ACK;

  if (IS_ZEBRA_DEBUG_KERNEL)
    zlog_debug ("netlink_talk: %s type %s(%u), seq=%u", nl->name,
               lookup (nlmsg_str, n->nlmsg_type), n->nlmsg_type,
               n->nlmsg_seq);

  /* Send message to netlink interface. */
  if (zserv_privs.change (ZPRIVS_RAISE))
    zlog (NULL, LOG_ERR, "Can't raise privileges");
  status = sendmsg (nl->sock, &msg, 0);
  save_errno = errno;
  if (zserv_privs.change (ZPRIVS_LOWER))
    zlog (NULL, LOG_ERR, "Can't lower privileges");

  if (status < 0)
    {
      zlog (NULL, LOG_ERR, "netlink_talk sendmsg() error: %s",
            safe_strerror (save_errno));
      return -1;
    }

  if (!a)
    {
      /* 
       * Change socket flags for blocking I/O. 
       * This ensures we wait for a reply in netlink_parse_info().
       */
      snb_ret = set_netlink_blocking (nl, &flags);
      if (snb_ret < 0)
        zlog (NULL, LOG_WARNING,
              "%s:%i Warning: Could not set netlink socket to blocking.",
              __FUNCTION__, __LINE__);
    }

  /* 
   * Get reply from netlink socket. 
   * The reply should either be an acknowlegement or an error.
   */
  status = netlink_parse_info (netlink_talk_filter, nl, a, size);

  /* Restore socket flags for nonblocking I/O */
  if (snb_ret == 0 && !a)
    set_netlink_nonblocking (nl, &flags);

  return status;
}
