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
#ifdef HAVE_MPLS
#include "mpls_lib.h"
#ifdef LINUX_MPLS
#include <linux/shim.h>
#endif
#endif /* HAVE_MPLS */

#include "zebra/rt.h"
#include "zebra/zserv.h"
#include "zebra/rt.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/netlink.h"
#include "zebra/rt_netlink.h"

/* Socket interface to kernel */
static struct nlsock
  netlink      = { -1, 0, {0}, "netlink-listen", 0},	/* kernel messages */
  netlink_cmd  = { -1, 0, {0}, "netlink-cmd", 1};	/* command channel */

/* Note: on netlink systems, there should be a 1-to-1 mapping between interface
   names and ifindex values. */
static void
set_ifindex(struct interface *ifp, unsigned int ifi_index)
{
  struct interface *oifp;

  if (((oifp = if_lookup_by_index(ifi_index)) != NULL) && (oifp != ifp))
    {
      if (ifi_index == IFINDEX_INTERNAL)
        zlog_err("Netlink is setting interface %s ifindex to reserved "
		 "internal value %u", ifp->name, ifi_index);
      else
        {
	  if (IS_ZEBRA_DEBUG_KERNEL)
	    zlog_debug("interface index %d was renamed from %s to %s",
	    	       ifi_index, oifp->name, ifp->name);
	  if (if_is_up(oifp))
	    zlog_err("interface rename detected on up interface: index %d "
		     "was renamed from %s to %s, results are uncertain!", 
	    	     ifi_index, oifp->name, ifp->name);
	  if_delete_update(oifp);
        }
    }
  ifp->ifindex = ifi_index;
}

/* Called from interface_lookup_netlink().  This function is only used
   during bootstrap. */
static int
netlink_interface (struct nlsock *nl, struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct ifinfomsg *ifi;
  struct rtattr *tb[IFLA_MAX + 1];
  struct interface *ifp;
  char *name;
  int i;

  /* skip unsolicited messages originating from command socket */
  if ((!nl->cmd) && h->nlmsg_pid == netlink_cmd.snl.nl_pid)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("netlink_parse_info: %s packet comes from %s",
                    netlink_cmd.name, nl->name);
      return 0;
    }

  ifi = NLMSG_DATA (h);

  if (h->nlmsg_type != RTM_NEWLINK)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct ifinfomsg));
  if (len < 0)
    return -1;

  /* Looking up interface name. */
  memset (tb, 0, sizeof tb);
  netlink_parse_rtattr (tb, IFLA_MAX, IFLA_RTA (ifi), len);
  
#ifdef IFLA_WIRELESS
  /* check for wireless messages to ignore */
  if ((tb[IFLA_WIRELESS] != NULL) && (ifi->ifi_change == 0))
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("%s: ignoring IFLA_WIRELESS message", __func__);
      return 0;
    }
#endif /* IFLA_WIRELESS */

  if (tb[IFLA_IFNAME] == NULL)
    return -1;
  name = (char *) RTA_DATA (tb[IFLA_IFNAME]);

  /* Add interface. */
  ifp = if_get_by_name (name);
  set_ifindex(ifp, ifi->ifi_index);
  ifp->flags = ifi->ifi_flags & 0x0000fffff;
  ifp->mtu6 = ifp->mtu = *(int *) RTA_DATA (tb[IFLA_MTU]);
  ifp->metric = 1;

  /* Hardware type and address. */
  ifp->hw_type = ifi->ifi_type;

  if (tb[IFLA_ADDRESS])
    {
      int hw_addr_len;

      hw_addr_len = RTA_PAYLOAD (tb[IFLA_ADDRESS]);

      if (hw_addr_len > INTERFACE_HWADDR_MAX)
        zlog_warn ("Hardware address is too large: %d", hw_addr_len);
      else
        {
          ifp->hw_addr_len = hw_addr_len;
          memcpy (ifp->hw_addr, RTA_DATA (tb[IFLA_ADDRESS]), hw_addr_len);

          for (i = 0; i < hw_addr_len; i++)
            if (ifp->hw_addr[i] != 0)
              break;

          if (i == hw_addr_len)
            ifp->hw_addr_len = 0;
          else
            ifp->hw_addr_len = hw_addr_len;
        }
    }

  if_add_update (ifp);

  return 0;
}

/* Lookup interface IPv4/IPv6 address. */
static int
netlink_interface_addr (struct nlsock *nl, struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct ifaddrmsg *ifa;
  struct rtattr *tb[IFA_MAX + 1];
  struct interface *ifp;
  void *addr;
  void *broad;
  u_char flags = 0;
  char *label = NULL;

  /* skip unsolicited messages originating from command socket */
  if ((!nl->cmd) && h->nlmsg_pid == netlink_cmd.snl.nl_pid)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("netlink_parse_info: %s packet comes from %s",
                    netlink_cmd.name, nl->name);
      return 0;
    }

  ifa = NLMSG_DATA (h);

  if (ifa->ifa_family != AF_INET
#ifdef HAVE_IPV6
      && ifa->ifa_family != AF_INET6
#endif /* HAVE_IPV6 */
    )
    return 0;

  if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct ifaddrmsg));
  if (len < 0)
    return -1;

  memset (tb, 0, sizeof tb);
  netlink_parse_rtattr (tb, IFA_MAX, IFA_RTA (ifa), len);

  ifp = if_lookup_by_index (ifa->ifa_index);
  if (ifp == NULL)
    {
      zlog_err ("netlink_interface_addr can't find interface by index %d",
                ifa->ifa_index);
      return -1;
    }

  if (IS_ZEBRA_DEBUG_KERNEL)    /* remove this line to see initial ifcfg */
    {
      char buf[BUFSIZ];
      zlog_debug ("netlink_interface_addr %s %s:",
                 lookup (nlmsg_str, h->nlmsg_type), ifp->name);
      if (tb[IFA_LOCAL])
        zlog_debug ("  IFA_LOCAL     %s/%d",
		    inet_ntop (ifa->ifa_family, RTA_DATA (tb[IFA_LOCAL]),
			       buf, BUFSIZ), ifa->ifa_prefixlen);
      if (tb[IFA_ADDRESS])
        zlog_debug ("  IFA_ADDRESS   %s/%d",
		    inet_ntop (ifa->ifa_family, RTA_DATA (tb[IFA_ADDRESS]),
                               buf, BUFSIZ), ifa->ifa_prefixlen);
      if (tb[IFA_BROADCAST])
        zlog_debug ("  IFA_BROADCAST %s/%d",
		    inet_ntop (ifa->ifa_family, RTA_DATA (tb[IFA_BROADCAST]),
			       buf, BUFSIZ), ifa->ifa_prefixlen);
      if (tb[IFA_LABEL] && strcmp (ifp->name, RTA_DATA (tb[IFA_LABEL])))
        zlog_debug ("  IFA_LABEL     %s", (char *)RTA_DATA (tb[IFA_LABEL]));
      
      if (tb[IFA_CACHEINFO])
        {
          struct ifa_cacheinfo *ci = RTA_DATA (tb[IFA_CACHEINFO]);
          zlog_debug ("  IFA_CACHEINFO pref %d, valid %d",
                      ci->ifa_prefered, ci->ifa_valid);
        }
    }
  
  /* logic copied from iproute2/ip/ipaddress.c:print_addrinfo() */
  if (tb[IFA_LOCAL] == NULL)
    tb[IFA_LOCAL] = tb[IFA_ADDRESS];
  if (tb[IFA_ADDRESS] == NULL)
    tb[IFA_ADDRESS] = tb[IFA_LOCAL];
  
  /* local interface address */
  addr = (tb[IFA_LOCAL] ? RTA_DATA(tb[IFA_LOCAL]) : NULL);

  /* is there a peer address? */
  if (tb[IFA_ADDRESS] &&
      memcmp(RTA_DATA(tb[IFA_ADDRESS]), RTA_DATA(tb[IFA_LOCAL]), RTA_PAYLOAD(tb[IFA_ADDRESS])))
    {
      broad = RTA_DATA(tb[IFA_ADDRESS]);
      SET_FLAG (flags, ZEBRA_IFA_PEER);
    }
  else
    /* seeking a broadcast address */
    broad = (tb[IFA_BROADCAST] ? RTA_DATA(tb[IFA_BROADCAST]) : NULL);

  /* addr is primary key, SOL if we don't have one */
  if (addr == NULL)
    {
      zlog_debug ("%s: NULL address", __func__);
      return -1;
    }

  /* Flags. */
  if (ifa->ifa_flags & IFA_F_SECONDARY)
    SET_FLAG (flags, ZEBRA_IFA_SECONDARY);

  /* Label */
  if (tb[IFA_LABEL])
    label = (char *) RTA_DATA (tb[IFA_LABEL]);

  if (ifp && label && strcmp (ifp->name, label) == 0)
    label = NULL;

  /* Register interface address to the interface. */
  if (ifa->ifa_family == AF_INET)
    {
      if (h->nlmsg_type == RTM_NEWADDR)
        connected_add_ipv4 (ifp, flags,
                            (struct in_addr *) addr, ifa->ifa_prefixlen,
                            (struct in_addr *) broad, label);
      else
        connected_delete_ipv4 (ifp, flags,
                               (struct in_addr *) addr, ifa->ifa_prefixlen,
                               (struct in_addr *) broad);
    }
#ifdef HAVE_IPV6
  if (ifa->ifa_family == AF_INET6)
    {
      if (h->nlmsg_type == RTM_NEWADDR)
        connected_add_ipv6 (ifp, flags,
                            (struct in6_addr *) addr, ifa->ifa_prefixlen,
                            (struct in6_addr *) broad, label);
      else
        connected_delete_ipv6 (ifp,
                               (struct in6_addr *) addr, ifa->ifa_prefixlen,
                               (struct in6_addr *) broad);
    }
#endif /* HAVE_IPV6 */

  return 0;
}

/* Looking up routing table by netlink interface. */
static int
netlink_routing_table (struct nlsock *nl, struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb[RTA_MAX + 1];
  u_short zebra_flags = 0;
  struct zapi_nexthop nh;

  char anyaddr[16] = { 0 };

  int index;
  int table;
  int metric;

  void *dest;
  void *gate;
  void *src;

  memset(&nh, 0, sizeof(struct zapi_nexthop));

  /* skip unsolicited messages originating from command socket */
  if ((!nl->cmd) && h->nlmsg_pid == netlink_cmd.snl.nl_pid)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("netlink_parse_info: %s packet comes from %s",
                    netlink_cmd.name, nl->name);
      return 0;
    }

  rtm = NLMSG_DATA (h);

  if (h->nlmsg_type != RTM_NEWROUTE)
    return 0;
  if (rtm->rtm_type != RTN_UNICAST)
    return 0;

  table = rtm->rtm_table;
#if 0                           /* we weed them out later in rib_weed_tables () */
  if (table != RT_TABLE_MAIN && table != zebrad.rtm_table_default)
    return 0;
#endif

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct rtmsg));
  if (len < 0)
    return -1;

  memset (tb, 0, sizeof tb);
  netlink_parse_rtattr (tb, RTA_MAX, RTM_RTA (rtm), len);

  if (rtm->rtm_flags & RTM_F_CLONED)
    return 0;
  if (rtm->rtm_protocol == RTPROT_REDIRECT)
    return 0;
  if (rtm->rtm_protocol == RTPROT_KERNEL)
    return 0;

  if (rtm->rtm_src_len != 0)
    return 0;

  /* Route which inserted by Zebra. */
  if (rtm->rtm_protocol == RTPROT_ZEBRA)
    zebra_flags |= ZEBRA_FLAG_SELFROUTE;

  index = 0;
  metric = 0;
  dest = NULL;
  gate = NULL;
  src = NULL;

  if (tb[RTA_OIF])
    {
      index = *(int *) RTA_DATA (tb[RTA_OIF]);
      nh.intf.index = index;
      SET_FLAG(nh.type, ZEBRA_NEXTHOP_IFINDEX);
    }

  if (tb[RTA_DST])
    dest = RTA_DATA (tb[RTA_DST]);
  else
    dest = anyaddr;

  if (tb[RTA_PREFSRC])
    src = RTA_DATA (tb[RTA_PREFSRC]);

  /* Multipath treatment is needed. */
  if (tb[RTA_GATEWAY])
    {
      gate = RTA_DATA (tb[RTA_GATEWAY]);
    }

  if (tb[RTA_PRIORITY])
    metric = *(int *) RTA_DATA(tb[RTA_PRIORITY]);

  if (rtm->rtm_family == AF_INET)
    {
      struct prefix_ipv4 p;
      p.family = AF_INET;
      memcpy (&p.prefix, dest, 4);
      p.prefixlen = rtm->rtm_dst_len;

      if (gate)
        {
          memcpy(&nh.gw.ipv4, gate, sizeof(struct in_addr));
          SET_FLAG(nh.type, ZEBRA_NEXTHOP_IPV4);
        }

      if (src)
        {
          memcpy(&nh.src.ipv4, src, sizeof(struct in_addr));
          SET_FLAG(nh.type, ZEBRA_NEXTHOP_SRC_IPV4);
        }

      rib_add_route (ZEBRA_ROUTE_KERNEL, zebra_flags, (struct prefix*)&p,
                     &nh, table, metric, 0);
    }
#ifdef HAVE_IPV6
  if (rtm->rtm_family == AF_INET6)
    {
      struct prefix_ipv6 p;
      p.family = AF_INET6;
      memcpy (&p.prefix, dest, 16);
      p.prefixlen = rtm->rtm_dst_len;

      if (gate)
        {
          memcpy(&nh.gw.ipv6, gate, sizeof(struct in6_addr));
          SET_FLAG(nh.type, ZEBRA_NEXTHOP_IPV6);
        }

      rib_add_route (ZEBRA_ROUTE_KERNEL, zebra_flags, (struct prefix*)&p,
                     &nh, table, metric, 0);
    }
#endif /* HAVE_IPV6 */

  return 0;
}

struct message rtproto_str[] = {
  {RTPROT_REDIRECT, "redirect"},
  {RTPROT_KERNEL,   "kernel"},
  {RTPROT_BOOT,     "boot"},
  {RTPROT_STATIC,   "static"},
  {RTPROT_GATED,    "GateD"},
  {RTPROT_RA,       "router advertisement"},
  {RTPROT_MRT,      "MRT"},
  {RTPROT_ZEBRA,    "Zebra"},
#ifdef RTPROT_BIRD
  {RTPROT_BIRD,     "BIRD"},
#endif /* RTPROT_BIRD */
  {0,               NULL}
};

/* Routing information change from the kernel. */
static int
netlink_route_change (struct nlsock *nl, struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb[RTA_MAX + 1];
  struct zapi_nexthop nh;

  char anyaddr[16] = { 0 };

  int index;
  int table;
  void *dest;
  void *gate;
  void *src;

  memset(&nh, 0, sizeof(struct zapi_nexthop));

  /* skip unsolicited messages originating from command socket */
  if ((!nl->cmd) && h->nlmsg_pid == netlink_cmd.snl.nl_pid)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("netlink_parse_info: %s packet comes from %s",
                    netlink_cmd.name, nl->name);
      return 0;
    }

  rtm = NLMSG_DATA (h);

  if (!(h->nlmsg_type == RTM_NEWROUTE || h->nlmsg_type == RTM_DELROUTE))
    {
      /* If this is not route add/delete message print warning. */
      zlog_warn ("Kernel message: %d\n", h->nlmsg_type);
      return 0;
    }

  /* Connected route. */
  if (IS_ZEBRA_DEBUG_KERNEL)
    zlog_debug ("%s %s %s proto %s",
               h->nlmsg_type ==
               RTM_NEWROUTE ? "RTM_NEWROUTE" : "RTM_DELROUTE",
               rtm->rtm_family == AF_INET ? "ipv4" : "ipv6",
               rtm->rtm_type == RTN_UNICAST ? "unicast" : "multicast",
               lookup (rtproto_str, rtm->rtm_protocol));

  if (rtm->rtm_type != RTN_UNICAST)
    {
      return 0;
    }

  table = rtm->rtm_table;
  if (table != RT_TABLE_MAIN && table != zebrad.rtm_table_default)
    {
      return 0;
    }

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct rtmsg));
  if (len < 0)
    return -1;

  memset (tb, 0, sizeof tb);
  netlink_parse_rtattr (tb, RTA_MAX, RTM_RTA (rtm), len);

  if (rtm->rtm_flags & RTM_F_CLONED)
    return 0;
  if (rtm->rtm_protocol == RTPROT_REDIRECT)
    return 0;
  if (rtm->rtm_protocol == RTPROT_KERNEL)
    return 0;

  if (rtm->rtm_protocol == RTPROT_ZEBRA && h->nlmsg_type == RTM_NEWROUTE)
    return 0;

  if (rtm->rtm_src_len != 0)
    {
      zlog_warn ("netlink_route_change(): no src len");
      return 0;
    }

  index = 0;
  dest = NULL;
  gate = NULL;
  src = NULL;

  if (tb[RTA_OIF])
    {
      index = *(int *) RTA_DATA (tb[RTA_OIF]);
      nh.intf.index = index;
      SET_FLAG(nh.type, ZEBRA_NEXTHOP_IFINDEX);
    }

  if (tb[RTA_DST])
    dest = RTA_DATA (tb[RTA_DST]);
  else
    dest = anyaddr;

  if (tb[RTA_GATEWAY])
    gate = RTA_DATA (tb[RTA_GATEWAY]);

  if (tb[RTA_PREFSRC])
    src = RTA_DATA (tb[RTA_PREFSRC]);

  if (rtm->rtm_family == AF_INET)
    {
      struct prefix_ipv4 p;
      p.family = AF_INET;
      memcpy (&p.prefix, dest, 4);
      p.prefixlen = rtm->rtm_dst_len;

      if (IS_ZEBRA_DEBUG_KERNEL)
        {
          if (h->nlmsg_type == RTM_NEWROUTE)
            zlog_debug ("RTM_NEWROUTE %s/%d",
                       inet_ntoa (p.prefix), p.prefixlen);
          else
            zlog_debug ("RTM_DELROUTE %s/%d",
                       inet_ntoa (p.prefix), p.prefixlen);
        }

      if (gate)
        {
          memcpy(&nh.gw.ipv4, gate, sizeof(struct in_addr));
          SET_FLAG(nh.type, ZEBRA_NEXTHOP_IPV4);
        }

      if (src)
        {
          memcpy(&nh.src.ipv4, src, sizeof(struct in_addr));
          SET_FLAG(nh.type, ZEBRA_NEXTHOP_SRC_IPV4);
        }

      if (h->nlmsg_type == RTM_NEWROUTE)
        rib_add_route (ZEBRA_ROUTE_KERNEL, 0, (struct prefix*)&p,
                       &nh, table, 0, 0);
      else
        rib_delete_route (ZEBRA_ROUTE_KERNEL, 0, (struct prefix*)&p,
                          &nh, table);
    }

#ifdef HAVE_IPV6
  if (rtm->rtm_family == AF_INET6)
    {
      struct prefix_ipv6 p;
      char buf[BUFSIZ];

      p.family = AF_INET6;
      memcpy (&p.prefix, dest, 16);
      p.prefixlen = rtm->rtm_dst_len;

      if (IS_ZEBRA_DEBUG_KERNEL)
        {
          if (h->nlmsg_type == RTM_NEWROUTE)
            zlog_debug ("RTM_NEWROUTE %s/%d",
                       inet_ntop (AF_INET6, &p.prefix, buf, BUFSIZ),
                       p.prefixlen);
          else
            zlog_debug ("RTM_DELROUTE %s/%d",
                       inet_ntop (AF_INET6, &p.prefix, buf, BUFSIZ),
                       p.prefixlen);
        }

      if (gate)
        {
          memcpy(&nh.gw.ipv6, gate, sizeof(struct in6_addr));
          SET_FLAG(nh.type, ZEBRA_NEXTHOP_IPV6);
        }

      if (h->nlmsg_type == RTM_NEWROUTE)
        rib_add_route (ZEBRA_ROUTE_KERNEL, 0, (struct prefix*)&p, &nh, 0, 0, 0);
      else
        rib_delete_route (ZEBRA_ROUTE_KERNEL, 0, (struct prefix*)&p, &nh, 0);
    }
#endif /* HAVE_IPV6 */

  return 0;
}

static int
netlink_link_change (struct nlsock *nl, struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct ifinfomsg *ifi;
  struct rtattr *tb[IFLA_MAX + 1];
  struct interface *ifp;
  char *name;

  ifi = NLMSG_DATA (h);

  /* skip unsolicited messages originating from command socket */
  if ((!nl->cmd) && h->nlmsg_pid == netlink_cmd.snl.nl_pid)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("netlink_parse_info: %s packet comes from %s",
                    netlink_cmd.name, nl->name);
      return 0;
    }

  if (!(h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK))
    {
      /* If this is not link add/delete message so print warning. */
      zlog_warn ("netlink_link_change: wrong kernel message %d\n",
                 h->nlmsg_type);
      return 0;
    }

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct ifinfomsg));
  if (len < 0)
    return -1;

  /* Looking up interface name. */
  memset (tb, 0, sizeof tb);
  netlink_parse_rtattr (tb, IFLA_MAX, IFLA_RTA (ifi), len);

#ifdef IFLA_WIRELESS
  /* check for wireless messages to ignore */
  if ((tb[IFLA_WIRELESS] != NULL) && (ifi->ifi_change == 0))
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("%s: ignoring IFLA_WIRELESS message", __func__);
      return 0;
    }
#endif /* IFLA_WIRELESS */
  
  if (tb[IFLA_IFNAME] == NULL)
    return -1;
  name = (char *) RTA_DATA (tb[IFLA_IFNAME]);

  /* Add interface. */
  if (h->nlmsg_type == RTM_NEWLINK)
    {
      ifp = if_lookup_by_name (name);

      if (ifp == NULL || !CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
        {
          if (ifp == NULL)
            ifp = if_get_by_name (name);

          set_ifindex(ifp, ifi->ifi_index);
          ifp->flags = ifi->ifi_flags & 0x0000fffff;
          ifp->mtu6 = ifp->mtu = *(int *) RTA_DATA (tb[IFLA_MTU]);
          ifp->metric = 1;

          /* If new link is added. */
          if_add_update (ifp);
        }
      else
        {
          /* Interface status change. */
          set_ifindex(ifp, ifi->ifi_index);
          ifp->mtu6 = ifp->mtu = *(int *) RTA_DATA (tb[IFLA_MTU]);
          ifp->metric = 1;

          if (if_is_operative (ifp))
            {
              ifp->flags = ifi->ifi_flags & 0x0000fffff;
              if (!if_is_operative (ifp))
                if_down (ifp);
	      else
		/* Must notify client daemons of new interface status. */
	        zebra_interface_up_update (ifp);
            }
          else
            {
              ifp->flags = ifi->ifi_flags & 0x0000fffff;
              if (if_is_operative (ifp))
                if_up (ifp);
            }
        }
    }
  else
    {
      /* RTM_DELLINK. */
      ifp = if_lookup_by_name (name);

      if (ifp == NULL)
        {
          zlog (NULL, LOG_WARNING, "interface %s is deleted but can't find",
                name);
          return 0;
        }

      if_delete_update (ifp);
    }

  return 0;
}

static int
netlink_information_fetch (struct nlsock *nl, struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  /* skip unsolicited messages originating from command socket */
  if ((!nl->cmd) && h->nlmsg_pid == netlink_cmd.snl.nl_pid)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("netlink_parse_info: %s packet comes from %s",
                    netlink_cmd.name, nl->name);
      return 0;
    }

  switch (h->nlmsg_type)
    {
    case RTM_NEWROUTE:
      return netlink_route_change (nl, snl, h);
      break;
    case RTM_DELROUTE:
      return netlink_route_change (nl, snl, h);
      break;
    case RTM_NEWLINK:
      return netlink_link_change (nl, snl, h);
      break;
    case RTM_DELLINK:
      return netlink_link_change (nl, snl, h);
      break;
    case RTM_NEWADDR:
      return netlink_interface_addr (nl, snl, h);
      break;
    case RTM_DELADDR:
      return netlink_interface_addr (nl, snl, h);
      break;
    default:
      zlog_warn ("Unknown netlink nlmsg_type %d\n", h->nlmsg_type);
      break;
    }
  return 0;
}

/* Interface lookup by netlink socket. */
int
interface_lookup_netlink (void)
{
  int ret;
  int flags;
  int snb_ret;

  /* 
   * Change netlink socket flags to blocking to ensure we get 
   * a reply via nelink_parse_info
   */
  snb_ret = set_netlink_blocking (&netlink_cmd, &flags);
  if (snb_ret < 0)
    zlog (NULL, LOG_WARNING,
          "%s:%i Warning: Could not set netlink socket to blocking.",
          __FUNCTION__, __LINE__);

  /* Get interface information. */
  ret = netlink_request (AF_PACKET, RTM_GETLINK, &netlink_cmd);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface, &netlink_cmd, NULL, 0);
  if (ret < 0)
    return ret;

  /* Get IPv4 address of the interfaces. */
  ret = netlink_request (AF_INET, RTM_GETADDR, &netlink_cmd);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface_addr, &netlink_cmd, NULL, 0);
  if (ret < 0)
    return ret;

#ifdef HAVE_IPV6
  /* Get IPv6 address of the interfaces. */
  ret = netlink_request (AF_INET6, RTM_GETADDR, &netlink_cmd);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface_addr, &netlink_cmd, NULL, 0);
  if (ret < 0)
    return ret;
#endif /* HAVE_IPV6 */

  /* restore socket flags */
  if (snb_ret == 0)
    set_netlink_nonblocking (&netlink_cmd, &flags);
  return 0;
}

/* Routing table read function using netlink interface.  Only called
   bootstrap time. */
int
netlink_route_read (void)
{
  int ret;
  int flags;
  int snb_ret;

  /* 
   * Change netlink socket flags to blocking to ensure we get 
   * a reply via nelink_parse_info
   */
  snb_ret = set_netlink_blocking (&netlink_cmd, &flags);
  if (snb_ret < 0)
    zlog (NULL, LOG_WARNING,
          "%s:%i Warning: Could not set netlink socket to blocking.",
          __FUNCTION__, __LINE__);

  /* Get IPv4 routing table. */
  ret = netlink_request (AF_INET, RTM_GETROUTE, &netlink_cmd);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_routing_table, &netlink_cmd, NULL, 0);
  if (ret < 0)
    return ret;

#ifdef HAVE_IPV6
  /* Get IPv6 routing table. */
  ret = netlink_request (AF_INET6, RTM_GETROUTE, &netlink_cmd);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_routing_table, &netlink_cmd, NULL, 0);
  if (ret < 0)
    return ret;
#endif /* HAVE_IPV6 */

  /* restore flags */
  if (snb_ret == 0)
    set_netlink_nonblocking (&netlink_cmd, &flags);
  return 0;
}

/* Routing table change via netlink interface. */
static int
netlink_route (int cmd, int family, void *dest, int length, void *gate,
               int index, int zebra_flags, int table)
{
  int ret;
  int bytelen;
  struct sockaddr_nl snl;
  int discard;

  struct
  {
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[1024];
  } req;

  memset (&req, 0, sizeof req);

  bytelen = (family == AF_INET ? 4 : 16);

  req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
  req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
  req.n.nlmsg_type = cmd;
  req.r.rtm_family = family;
  req.r.rtm_table = table;
  req.r.rtm_dst_len = length;

  if ((zebra_flags & ZEBRA_FLAG_BLACKHOLE)
      || (zebra_flags & ZEBRA_FLAG_REJECT))
    discard = 1;
  else
    discard = 0;

  if (cmd == RTM_NEWROUTE)
    {
      req.r.rtm_protocol = RTPROT_ZEBRA;
      req.r.rtm_scope = RT_SCOPE_UNIVERSE;

      if (discard)
        {
          if (zebra_flags & ZEBRA_FLAG_BLACKHOLE)
            req.r.rtm_type = RTN_BLACKHOLE;
          else if (zebra_flags & ZEBRA_FLAG_REJECT)
            req.r.rtm_type = RTN_UNREACHABLE;
          else
            assert (RTN_BLACKHOLE != RTN_UNREACHABLE);  /* false */
        }
      else
        req.r.rtm_type = RTN_UNICAST;
    }

  if (dest)
    addattr_l (&req.n, sizeof req, RTA_DST, dest, bytelen);

  if (!discard)
    {
      if (gate)
        addattr_l (&req.n, sizeof req, RTA_GATEWAY, gate, bytelen);
      if (index > 0)
        addattr32 (&req.n, sizeof req, RTA_OIF, index);
    }

  /* Destination netlink address. */
  memset (&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;

  /* Talk to netlink socket. */
  ret = netlink_talk (&req.n, &netlink_cmd, NULL, 0);
  if (ret < 0)
    return -1;

  return 0;
}

/* Routing table change via netlink interface. */
static int
netlink_route_multipath (int cmd, struct prefix *p, struct rib *rib,
                         int family)
{
  int bytelen;
  struct sockaddr_nl snl;
  struct nexthop *nexthop = NULL;
  int nexthop_num = 0;
  int discard;
  int advmss = 0;

  struct
  {
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[1024];
  } req;

  memset (&req, 0, sizeof req);

  bytelen = (family == AF_INET ? 4 : 16);

  req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
  req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
  req.n.nlmsg_type = cmd;
  req.r.rtm_family = family;
  req.r.rtm_table = rib->table;
  req.r.rtm_dst_len = p->prefixlen;

  if ((rib->flags & ZEBRA_FLAG_BLACKHOLE) || (rib->flags & ZEBRA_FLAG_REJECT))
    discard = 1;
  else
    discard = 0;

  if (cmd == RTM_NEWROUTE)
    {
      req.r.rtm_protocol = RTPROT_ZEBRA;
      req.r.rtm_scope = RT_SCOPE_UNIVERSE;

      if (discard)
        {
          if (rib->flags & ZEBRA_FLAG_BLACKHOLE)
            req.r.rtm_type = RTN_BLACKHOLE;
          else if (rib->flags & ZEBRA_FLAG_REJECT)
            req.r.rtm_type = RTN_UNREACHABLE;
          else
            assert (RTN_BLACKHOLE != RTN_UNREACHABLE);  /* false */
        }
      else
        req.r.rtm_type = RTN_UNICAST;
    }

  addattr_l (&req.n, sizeof req, RTA_DST, &p->u.prefix, bytelen);

  /* Metric. */
  addattr32 (&req.n, sizeof req, RTA_PRIORITY, rib->metric);

  if (discard)
    {
      if (cmd == RTM_NEWROUTE)
        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next) {
          if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_IGNORE))
	      continue;
          SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
        }
      goto skip;
    }

  /* Multipath case. */
  if (rib->nexthop_active_num == 1 || MULTIPATH_NUM == 1)
    {
      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
        {
	  if (nexthop->advmss && nexthop->advmss > advmss)
	    advmss = nexthop->advmss;

          if ((cmd == RTM_NEWROUTE
               && !CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_IGNORE)
               && CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
              || (cmd == RTM_DELROUTE
                  && CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)))
            {

              if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
                {
                  if (IS_ZEBRA_DEBUG_KERNEL)
                    {
                      zlog_debug
                        ("netlink_route_multipath() (recursive, 1 hop): "
                         "%s %s/%d, type %s", lookup (nlmsg_str, cmd),
#ifdef HAVE_IPV6
			 (family == AF_INET) ? inet_ntoa (p->u.prefix4) :
			 inet6_ntoa (p->u.prefix6),
#else
			 inet_ntoa (p->u.prefix4),
#endif /* HAVE_IPV6 */
			 
			 p->prefixlen, nexthop_types_desc(nexthop->rtype));
                    }

                  if (CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_IPV4))
		    {
		      addattr_l (&req.n, sizeof req, RTA_GATEWAY,
				 &nexthop->rgate.ipv4, bytelen);

                      if (nexthop->src.ipv4.s_addr)
		          addattr_l(&req.n, sizeof req, RTA_PREFSRC,
				     &nexthop->src.ipv4, bytelen);

		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (recursive, "
				   "1 hop): nexthop via %s if %u",
				   inet_ntoa (nexthop->rgate.ipv4),
				   nexthop->rifindex);
		    }
#ifdef HAVE_IPV6
                  else if (CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_IPV6))
		    {
		      addattr_l (&req.n, sizeof req, RTA_GATEWAY,
				 &nexthop->rgate.ipv6, bytelen);

		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (recursive, "
				   "1 hop): nexthop via %s if %u",
				   inet6_ntoa (nexthop->rgate.ipv6),
				   nexthop->rifindex);
		    }
#endif /* HAVE_IPV6 */
		  else if (CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_DROP))
		    {
		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (recursive, "
				   "1 hop): nexthop DROP(%d)", nexthop->drop);
		    }

                  if (CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_IFINDEX) &&
		      !(CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_IPV4) ||
		        CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_IPV6)))
		    {
		      addattr32 (&req.n, sizeof req, RTA_OIF,
				 nexthop->rifindex);

		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (recursive, "
				   "1 hop): nexthop via if %u",
				   nexthop->rifindex);
		    }

#ifdef HAVE_MPLS
                  if (CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_MPLS))
                    {
#ifdef LINUX_MPLS
		      struct zmpls_out_segment *out;
		      char buf[sizeof(struct rtshim) + sizeof(unsigned int)];
		      struct rtshim *shim = (struct rtshim*)buf;
		      out = mpls_out_segment_find(nexthop->rmpls);
		      if (out) {
		        strcpy(shim->name, "mpls");
		        shim->datalen = sizeof(unsigned int);
		        *((unsigned int*)(shim->data)) = out->out_key;
                        addattr_l(&req.n, sizeof(req), RTA_SHIM,
			  shim, sizeof(buf));
		        if (IS_ZEBRA_DEBUG_KERNEL)
			  zlog_debug("netlink_route_multipath() (recursive, "
				     "1 hop): MPLS info %08x", out->out_key);
		      } else {
		        zlog_debug("netlink_route_multipath() (multihop): "
				   "unable to find NHLFE %d", nexthop->rmpls);
		      }
#endif
                    }
#endif /* HAVE_MPLS */
                }
              else
                {
                  if (IS_ZEBRA_DEBUG_KERNEL)
                    {
                      zlog_debug
                        ("netlink_route_multipath() (single hop): "
                         "%s %s/%d, type %s", lookup (nlmsg_str, cmd),
#ifdef HAVE_IPV6
			 (family == AF_INET) ? inet_ntoa (p->u.prefix4) :
			 inet6_ntoa (p->u.prefix6),
#else
			 inet_ntoa (p->u.prefix4),
#endif /* HAVE_IPV6 */
			 p->prefixlen, nexthop_types_desc(nexthop->type));
                    }

                  if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV4))
		    {
		      addattr_l (&req.n, sizeof req, RTA_GATEWAY,
				 &nexthop->gate.ipv4, bytelen);

		      if (nexthop->src.ipv4.s_addr)
                        addattr_l (&req.n, sizeof req, RTA_PREFSRC,
				 &nexthop->src.ipv4, bytelen);

		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (single hop): "
				   "nexthop via %s if %u",
				   inet_ntoa (nexthop->gate.ipv4),
				   nexthop->ifindex);
		    }
#ifdef HAVE_IPV6
                  else if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV6))
		    {
		      addattr_l (&req.n, sizeof req, RTA_GATEWAY,
				 &nexthop->gate.ipv6, bytelen);

		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (single hop): "
				   "nexthop via %s if %u",
				   inet6_ntoa (nexthop->gate.ipv6),
				   nexthop->ifindex);
		    }
#endif /* HAVE_IPV6 */
                  else if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_DROP))
		    {
		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (single hop): "
				   "nexthop DROP(%d)", nexthop->drop);
		    }

                  if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFINDEX) &&
		      !(CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV4) ||
		        CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV6)))
		    {
		      addattr32 (&req.n, sizeof req, RTA_OIF, nexthop->ifindex);

		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (single hop): "
				   "nexthop via if %u", nexthop->ifindex);
		    }

#ifdef HAVE_MPLS
                  if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_MPLS))
                    {
#ifdef LINUX_MPLS
		      struct zmpls_out_segment *out;
		      char buf[sizeof(struct rtshim) + sizeof(unsigned int)];
		      struct rtshim *shim = (struct rtshim*)buf;
		      out = mpls_out_segment_find(nexthop->mpls);
		      if (out) {
		        strcpy(shim->name, "mpls");
		        shim->datalen = sizeof(unsigned int);
		        *((unsigned int*)(shim->data)) = out->out_key;
                        addattr_l(&req.n, sizeof(req), RTA_SHIM,
			  shim, sizeof(buf));
		        if (IS_ZEBRA_DEBUG_KERNEL)
			  zlog_debug("netlink_route_multipath() (single hop): "
				     "MPLS info %08x", out->out_key);
		      } else {
		        zlog_debug("netlink_route_multipath() (single hop): "
				   "unable to find NHLFE %d", nexthop->mpls);
		      }
#endif
                    }
#endif /* HAVE_MPLS */
                }

              if (cmd == RTM_NEWROUTE)
                SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

              nexthop_num++;
              break;
            }
        }
    }
  else
    {
      char buf[1024];
      struct rtattr *rta = (void *) buf;
      struct rtnexthop *rtnh;
      union g_addr *src = NULL;

      rta->rta_type = RTA_MULTIPATH;
      rta->rta_len = RTA_LENGTH (0);
      rtnh = RTA_DATA (rta);

      nexthop_num = 0;
      for (nexthop = rib->nexthop;
           nexthop && (MULTIPATH_NUM == 0 || nexthop_num < MULTIPATH_NUM);
           nexthop = nexthop->next)
        {
          if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_IGNORE))
	      continue;

          if ((cmd == RTM_NEWROUTE
               && !CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_IGNORE)
               && CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
              || (cmd == RTM_DELROUTE
                  && CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)))
            {
              nexthop_num++;

              rtnh->rtnh_len = sizeof (*rtnh);
              rtnh->rtnh_flags = 0;
              rtnh->rtnh_hops = 0;
              rta->rta_len += rtnh->rtnh_len;

              if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
                {
                  if (IS_ZEBRA_DEBUG_KERNEL)
                    {
                      zlog_debug ("netlink_route_multipath() "
                         "(recursive, multihop): %s %s/%d type %s",
			 lookup (nlmsg_str, cmd),
#ifdef HAVE_IPV6
			 (family == AF_INET) ? inet_ntoa (p->u.prefix4) :
			 inet6_ntoa (p->u.prefix6),
#else
			 inet_ntoa (p->u.prefix4),
#endif /* HAVE_IPV6 */
                         p->prefixlen, nexthop_types_desc(nexthop->type));
                    }
                  if (CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_IPV4))
                    {
                      rta_addattr_l (rta, 4096, RTA_GATEWAY,
                                     &nexthop->rgate.ipv4, bytelen);
                      rtnh->rtnh_len += sizeof (struct rtattr) + 4;

		      if (nexthop->src.ipv4.s_addr)
                        src = &nexthop->src;

		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (recursive, "
				   "multihop): nexthop via %s if %u",
				   inet_ntoa (nexthop->rgate.ipv4),
				   nexthop->rifindex);
                    }
#ifdef HAVE_IPV6
                  else if (CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_IPV6))
		    {
		      rta_addattr_l (rta, 4096, RTA_GATEWAY,
				     &nexthop->rgate.ipv6, bytelen);

		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (recursive, "
				   "multihop): nexthop via %s if %u",
				   inet6_ntoa (nexthop->rgate.ipv6),
				   nexthop->rifindex);
		    }
#endif /* HAVE_IPV6 */
		  else if (CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_DROP))
		    {
			zlog_debug("netlink_route_multipath() (recursive, "
				   "multihop): nexthop DROP %d", nexthop->drop);
		    }

                  /* ifindex */
                  if (CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_IFINDEX) &&
		      !(CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_IPV4) ||
		        CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_IPV6)))
		    {
		      rtnh->rtnh_ifindex = nexthop->rifindex;

		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (recursive, "
				   "multihop): nexthop via if %u",
				   nexthop->rifindex);
		    }
                  else
		    {
		      rtnh->rtnh_ifindex = 0;
		    }

#ifdef HAVE_MPLS
                  if (CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_MPLS))
                    {
#ifdef LINUX_MPLS
		      struct zmpls_out_segment *out;
		      char buf[sizeof(struct rtshim) + sizeof(unsigned int)];
		      struct rtshim *shim = (struct rtshim*)buf;
		      out = mpls_out_segment_find(nexthop->rmpls);
		      if (out) {
		        strcpy(shim->name, "mpls");
		        shim->datalen = sizeof(unsigned int);
		        *((unsigned int*)(shim->data)) = out->out_key;
                        addattr_l(&req.n, sizeof(req), RTA_SHIM,
			  shim, sizeof(buf));
		        if (IS_ZEBRA_DEBUG_KERNEL)
			  zlog_debug("netlink_route_multipath() (recursive "
                                     "multihop): MPLS info %08x", out->out_key);
		      } else {
		        zlog_debug("netlink_route_multipath() (recursive "
                                   "multihop): unable to find NHLFE %d",
                                   nexthop->rmpls);
		      }
#endif
                    }
#endif /* HAVE_MPLS */
                }
              else
                {
                  if (IS_ZEBRA_DEBUG_KERNEL)
                    {
                      zlog_debug ("netlink_route_multipath() (multihop): "
                         "%s %s/%d, type %s", lookup (nlmsg_str, cmd),
#ifdef HAVE_IPV6
			 (family == AF_INET) ? inet_ntoa (p->u.prefix4) :
			 inet6_ntoa (p->u.prefix6),
#else
			 inet_ntoa (p->u.prefix4),
#endif /* HAVE_IPV6 */
			 p->prefixlen, nexthop_types_desc(nexthop->type));
                    }
                  if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV4))
                    {
		      rta_addattr_l (rta, 4096, RTA_GATEWAY,
				     &nexthop->gate.ipv4, bytelen);
		      rtnh->rtnh_len += sizeof (struct rtattr) + 4;

		      if (nexthop->src.ipv4.s_addr)
                        src = &nexthop->src;

                      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (multihop): "
				   "nexthop via %s if %u",
				   inet_ntoa (nexthop->gate.ipv4),
				   nexthop->ifindex);
                    }
#ifdef HAVE_IPV6
                  else if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV6))
		    { 
		      rta_addattr_l (rta, 4096, RTA_GATEWAY,
				     &nexthop->gate.ipv6, bytelen);

		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (multihop): "
				   "nexthop via %s if %u",
				   inet6_ntoa (nexthop->gate.ipv6),
				   nexthop->ifindex);
		    }
#endif /* HAVE_IPV6 */
		  else if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_DROP))
		    {
			zlog_debug("netlink_route_multipath() (multihop): "
				   "nexthop DROP %d", nexthop->drop);
		    }

                  /* ifindex */
                  if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFINDEX) &&
		      !(CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV4) ||
		        CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV6)))
		    {
		      rtnh->rtnh_ifindex = nexthop->ifindex;

		      if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("netlink_route_multipath() (multihop): "
				   "nexthop via if %u", nexthop->ifindex);
		    }
                  else
		    {
		      rtnh->rtnh_ifindex = 0;
		    }

#ifdef HAVE_MPLS
                  if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_MPLS))
                    {
#ifdef LINUX_MPLS
		      struct zmpls_out_segment *out;
		      char buf[sizeof(struct rtshim) + sizeof(unsigned int)];
		      struct rtshim *shim = (struct rtshim*)buf;
		      out = mpls_out_segment_find(nexthop->mpls);
		      if (out) {
		        strcpy(shim->name, "mpls");
		        shim->datalen = sizeof(unsigned int);
		        *((unsigned int*)(shim->data)) = out->out_key;
                        addattr_l(&req.n, sizeof(req), RTA_SHIM,
			  shim, sizeof(buf));
		        if (IS_ZEBRA_DEBUG_KERNEL)
			  zlog_debug("netlink_route_multipath() (multihop): "
                                     "MPLS info %08x", out->out_key);
		      } else {
		        zlog_debug("netlink_route_multipath() (multihop): "
				   "unable to find NHLFE %d", nexthop->mpls);
		      }
#endif
                    }
#endif /* HAVE_MPLS */
                }
              rtnh = RTNH_NEXT (rtnh);

              if (cmd == RTM_NEWROUTE)
                SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
            }
        }
      if (src)
        addattr_l (&req.n, sizeof req, RTA_PREFSRC, &src->ipv4, bytelen);

      if (rta->rta_len > RTA_LENGTH (0))
        addattr_l (&req.n, 1024, RTA_MULTIPATH, RTA_DATA (rta),
                   RTA_PAYLOAD (rta));
    }

  if (advmss)
    {
      char buf[1024];
      struct rtattr *rta = (void *) buf;
      unsigned int mss = advmss;

      rta->rta_type = RTA_METRICS;
      rta->rta_len = RTA_LENGTH (0);

      rta_addattr_l (rta, sizeof (buf), RTAX_ADVMSS, &mss, sizeof (mss));
      addattr_l(&req.n, sizeof (buf), RTA_METRICS, RTA_DATA (rta),
	        RTA_PAYLOAD (rta));
   }

  /* If there is no useful nexthop then return. */
  if (nexthop_num == 0)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("netlink_route_multipath(): No useful nexthop.");
      return 0;
    }

skip:

  /* Destination netlink address. */
  memset (&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;

  /* Talk to netlink socket. */
  return netlink_talk (&req.n, &netlink_cmd, NULL, 0);
}

int
kernel_add_ipv4 (struct prefix *p, struct rib *rib)
{
  return netlink_route_multipath (RTM_NEWROUTE, p, rib, AF_INET);
}

int
kernel_delete_ipv4 (struct prefix *p, struct rib *rib)
{
  return netlink_route_multipath (RTM_DELROUTE, p, rib, AF_INET);
}

#ifdef HAVE_IPV6
int
kernel_add_ipv6 (struct prefix *p, struct rib *rib)
{
  return netlink_route_multipath (RTM_NEWROUTE, p, rib, AF_INET6);
}

int
kernel_delete_ipv6 (struct prefix *p, struct rib *rib)
{
  return netlink_route_multipath (RTM_DELROUTE, p, rib, AF_INET6);
}

/* Delete IPv6 route from the kernel. */
int
kernel_delete_ipv6_old (struct prefix_ipv6 *dest, struct in6_addr *gate,
                        unsigned int index, int flags, int table)
{
  return netlink_route (RTM_DELROUTE, AF_INET6, &dest->prefix,
                        dest->prefixlen, gate, index, flags, table);
}
#endif /* HAVE_IPV6 */

/* Interface address modification. */
static int
netlink_address (int cmd, int family, struct interface *ifp,
                 struct connected *ifc)
{
  int bytelen;
  struct prefix *p;

  struct
  {
    struct nlmsghdr n;
    struct ifaddrmsg ifa;
    char buf[1024];
  } req;

  p = ifc->address;
  memset (&req, 0, sizeof req);

  bytelen = (family == AF_INET ? 4 : 16);

  req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifaddrmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST;
  req.n.nlmsg_type = cmd;
  req.ifa.ifa_family = family;

  req.ifa.ifa_index = ifp->ifindex;
  req.ifa.ifa_prefixlen = p->prefixlen;

  addattr_l (&req.n, sizeof req, IFA_LOCAL, &p->u.prefix, bytelen);

  if (family == AF_INET && cmd == RTM_NEWADDR)
    {
      if (!CONNECTED_PEER(ifc) && ifc->destination)
        {
          p = ifc->destination;
          addattr_l (&req.n, sizeof req, IFA_BROADCAST, &p->u.prefix,
                     bytelen);
        }
      else if (if_is_pointopoint (ifp) && ifc->destination)
        {
          p = ifc->destination;
          addattr_l (&req.n, sizeof req, IFA_ADDRESS, &p->u.prefix,
                     bytelen);
        }
    }

  if (CHECK_FLAG (ifc->flags, ZEBRA_IFA_SECONDARY))
    SET_FLAG (req.ifa.ifa_flags, IFA_F_SECONDARY);

  if (ifc->label)
    addattr_l (&req.n, sizeof req, IFA_LABEL, ifc->label,
               strlen (ifc->label) + 1);

  return netlink_talk (&req.n, &netlink_cmd, NULL, 0);
}

int
kernel_address_add_ipv4 (struct interface *ifp, struct connected *ifc)
{
  return netlink_address (RTM_NEWADDR, AF_INET, ifp, ifc);
}

int
kernel_address_delete_ipv4 (struct interface *ifp, struct connected *ifc)
{
  return netlink_address (RTM_DELADDR, AF_INET, ifp, ifc);
}


extern struct thread_master *master;

/* Kernel route reflection. */
static int
kernel_read (struct thread *thread)
{
  int ret;
  int sock;

  sock = THREAD_FD (thread);
  ret = netlink_parse_info (netlink_information_fetch, &netlink, NULL, 0);
  thread_add_read (zebrad.master, kernel_read, NULL, netlink.sock);

  return 0;
}

/* Filter out messages from self that occur on listener socket */
static void netlink_install_filter (int sock)
{
  /*
   * Filter is equivalent to netlink_route_change
   *
   * if (h->nlmsg_type == RTM_DELROUTE || h->nlmsg_type == RTM_NEWROUTE) {
   *    if (rtm->rtm_type != RTM_UNICAST)
   *    	return 0;
   *    if (rtm->rtm_flags & RTM_F_CLONED)
   *    	return 0;
   *    if (rtm->rtm_protocol == RTPROT_REDIRECT)
   *    	return 0;
   *    if (rtm->rtm_protocol == RTPROT_KERNEL)
   *        return 0;
   *    if (rtm->rtm_protocol == RTPROT_ZEBRA && h->nlmsg_type == RTM_NEWROUTE)
   * 	return 0;
   * }
   * return 0xffff;
   */
  struct sock_filter filter[] = {
    /* 0*/ BPF_STMT(BPF_LD|BPF_ABS|BPF_H, offsetof(struct nlmsghdr, nlmsg_type)),
    /* 1*/ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, htons(RTM_DELROUTE), 1, 0),
    /* 2*/ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, htons(RTM_NEWROUTE), 0, 11),
    /* 3*/ BPF_STMT(BPF_LD|BPF_ABS|BPF_B,
		    sizeof(struct nlmsghdr) + offsetof(struct rtmsg, rtm_type)),
    /* 4*/ BPF_JUMP(BPF_JMP|BPF_B, RTN_UNICAST, 0, 8),
    /* 5*/ BPF_STMT(BPF_LD|BPF_ABS|BPF_B,
		    sizeof(struct nlmsghdr) + offsetof(struct rtmsg, rtm_flags)),
    /* 6*/ BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, RTM_F_CLONED, 6, 0),
    /* 7*/ BPF_STMT(BPF_LD|BPF_ABS|BPF_B,
		    sizeof(struct nlmsghdr) + offsetof(struct rtmsg, rtm_protocol)),
    /* 8*/ BPF_JUMP(BPF_JMP+ BPF_B, RTPROT_REDIRECT, 4, 0),
    /* 9*/ BPF_JUMP(BPF_JMP+ BPF_B, RTPROT_KERNEL, 0, 1),
    /*10*/ BPF_JUMP(BPF_JMP+ BPF_B, RTPROT_ZEBRA, 0, 3),
    /*11*/ BPF_STMT(BPF_LD|BPF_ABS|BPF_H, offsetof(struct nlmsghdr, nlmsg_type)),
    /*12*/ BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, htons(RTM_NEWROUTE), 0, 1),
    /*13*/ BPF_STMT(BPF_RET|BPF_K, 0),		/* drop */
    /*14*/ BPF_STMT(BPF_RET|BPF_K, 0xffff),	/* keep */
  };

  struct sock_fprog prog = {
    .len = sizeof(filter) / sizeof(filter[0]),
    .filter = filter,
  };

  if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
    zlog_warn ("Can't install socket filter: %s\n", safe_strerror(errno));
}

/* Exported interface function.  This function simply calls
   netlink_socket (). */
void
kernel_init (void)
{
  unsigned long groups;

  groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR;
#ifdef HAVE_IPV6
  groups |= RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;
#endif /* HAVE_IPV6 */
  netlink_socket (&netlink, NETLINK_ROUTE, groups);
  netlink_socket (&netlink_cmd, NETLINK_ROUTE, 0);

  /* Register kernel socket. */
  if (netlink.sock > 0)
    {
      netlink_install_filter (netlink.sock);
      thread_add_read (zebrad.master, kernel_read, NULL, netlink.sock);
    }
}
