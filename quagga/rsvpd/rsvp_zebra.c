/*
 * Zebra connect library for RSVPd
 * Copyright (C) 1997, 98, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA. 
 */

#include <zebra.h>

#include "thread.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"

#include "rsvp.h"
#include "te.h"

/* Zebra structure to hold current status. */
struct zclient *zclient = NULL;

/* For registering threads. */
extern struct thread_master *master;
struct in_addr router_id_zebra;

/* Router-id update message from zebra. */
static int
rsvp_router_id_update_zebra (int command, struct zclient *zclient,
			     zebra_size_t length)
{
  struct prefix router_id;
  char buf[128];
  zebra_router_id_update_read (zclient->ibuf, &router_id);

  prefix2str (&router_id, buf, sizeof (buf));
  zlog_debug ("Zebra rcvd: router id update %s", buf);

  router_id_zebra = router_id.u.prefix4;
  rdb_set_router_id (router_id_zebra.s_addr);

  return 0;
}

/* Inteface addition message from zebra. */
static int
rsvp_interface_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf);

  zlog_debug ("Zebra: interface add %s index %d flags %ld metric %d mtu %d",
	      ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  if (EnableRsvpOnInterface (ifp->ifindex) != E_OK)
    {
      zlog_err ("cannot enable RSVP on I/F %d", ifp->ifindex);
    }
  else
    {
      zlog_debug (" RSVP enabled");
    }

  return 0;
}

static int
rsvp_interface_delete (int command, struct zclient *zclient,
		       zebra_size_t length)
{
  struct interface *ifp;
  struct stream *s;

  s = zclient->ibuf;
  /* zebra_interface_state_read() updates interface structure in iflist */
  ifp = zebra_interface_state_read (s);

  if (ifp == NULL)
    return 0;

  if (if_is_up (ifp))
    zlog_warn ("Zebra: got delete of %s, but interface is still up",
	       ifp->name);

  zlog_debug
    ("Zebra: interface delete %s index %d flags %ld metric %d mtu %d",
     ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  if (DisableRsvpOnInterface (ifp->ifindex) != E_OK)
    {
      zlog_err ("cannot disable RSVP on I/F %d", ifp->ifindex);
    }
  else
    {
      zlog_debug (" RSVP disabled");
    }

  return 0;
}

static struct interface *
zebra_interface_if_lookup (struct stream *s)
{
  char ifname_tmp[INTERFACE_NAMSIZ];

  /* Read interface name. */
  stream_get (ifname_tmp, s, INTERFACE_NAMSIZ);

  /* And look it up. */
  return if_lookup_by_name_len (ifname_tmp,
				strnlen (ifname_tmp, INTERFACE_NAMSIZ));
}

static int
rsvp_interface_state_up (int command, struct zclient *zclient,
			 zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_if_lookup (zclient->ibuf);

  if (ifp == NULL)
    return 0;

  /* Interface is already up. */
  if (if_is_operative (ifp))
    {
      /* Temporarily keep ifp values. */
      struct interface if_tmp;
      memcpy (&if_tmp, ifp, sizeof (struct interface));

      zebra_interface_if_set_value (zclient->ibuf, ifp);

      zlog_debug ("Zebra: Interface[%s] state update.", ifp->name);

      if (if_tmp.bandwidth != ifp->bandwidth)
	{
	  zlog_debug ("Zebra: Interface[%s] bandwidth change %d -> %d.",
		      ifp->name, if_tmp.bandwidth, ifp->bandwidth);
	}
      return 0;
    }

  zebra_interface_if_set_value (zclient->ibuf, ifp);

  zlog_debug ("Zebra: Interface[%s] state change to up.", ifp->name);

  return 0;
}

static int
rsvp_interface_state_down (int command, struct zclient *zclient,
			   zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_state_read (zclient->ibuf);

  if (ifp == NULL)
    return 0;

  zlog_debug ("Zebra: Interface[%s] state change to down.", ifp->name);

  return 0;
}

static int
rsvp_interface_address_add (int command, struct zclient *zclient,
			    zebra_size_t length)
{
  struct connected *c;
  char buf[128];

  c = zebra_interface_address_read (command, zclient->ibuf);

  if (c == NULL)
    return 0;

  prefix2str (c->address, buf, sizeof (buf));
  zlog_debug ("Zebra: interface %s address add %s", c->ifp->name, buf);

  zlog_info ("trying to add IP address %s", buf);

  if (IfIpAdd (c->address->u.prefix4.s_addr, c->address->prefixlen) != E_OK)
    {
      zlog_err ("Cannot add IP address %s %d", __FILE__, __LINE__);
    }
  if (IpAddrSetByIfIndex (c->ifp->ifindex, c->address->u.prefix4.s_addr) !=
      E_OK)
    {
      zlog_err ("Cannot set IP address %s %d", __FILE__, __LINE__);
    }
  if (IsRsvpEnabledOnIf (c->ifp->ifindex) == E_OK)
    {
      if (EnableRsvpOnInterface2 (c->ifp->ifindex) != E_OK)
        {
          zlog_err ("Cannot enable RSVP on I/F %d %s %d",
                    c->ifp->ifindex, __FILE__, __LINE__);
        }
    }

  return 0;
}

static int
rsvp_interface_address_delete (int command, struct zclient *zclient,
			       zebra_size_t length)
{
  struct connected *c;
  char buf[128];

  c = zebra_interface_address_read (command, zclient->ibuf);

  if (c == NULL)
    return 0;

  prefix2str (c->address, buf, sizeof (buf));
  zlog_debug ("Zebra: interface %s address delete %s", c->ifp->name, buf);

  if (IfIpAddrDel (c->address->u.prefix4.s_addr, c->address->prefixlen) !=
      E_OK)
    {
      zlog_err ("Cannot add IP address %s %d", __FILE__, __LINE__);
    }
  if (IpAddrSetByIfIndex (c->ifp->ifindex, 0) != E_OK)
    {
      zlog_err ("Cannot unset IP address %s %d", __FILE__, __LINE__);
    }
  DisableRsvpOnInterface (c->ifp->ifindex);

  connected_free (c);

  return 0;
}

/* Zebra route add and delete treatment. */
static int
rsvp_zebra_read_ipv4 (int command, struct zclient *zclient,
		      zebra_size_t length)
{
  struct stream *s;
  struct zapi_ipv4 api;
  unsigned long ifindex;
  struct in_addr nexthop;
  struct prefix_ipv4 p;
  int i;

  s = zclient->ibuf;

  zapi_ipv4_read (s, length, &api, &p);

  if (IPV4_NET127 (ntohl (p.prefix.s_addr)))
    return 0;

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      for (i = 0; i < api.nexthop_num; i++)
	{
	  nexthop.s_addr = 0;
	  ifindex = 0;

	  if (CHECK_FLAG (api.nexthop[i].type, ZEBRA_NEXTHOP_IPV4))
	    nexthop.s_addr = api.nexthop[i].gw.ipv4.s_addr;

	  if (CHECK_FLAG (api.nexthop[i].type, ZEBRA_NEXTHOP_IFINDEX))
	    ifindex = api.nexthop[i].intf.index;

	  if (command == ZEBRA_IPV4_ROUTE_ADD)
	    {
	    }
	}
    }

  return 0;
}


COMPONENT_LINK *
new_component_link ()
{
  COMPONENT_LINK *pComponentLink;

  if ((pComponentLink =
       (COMPONENT_LINK *) XMALLOC (MTYPE_TE,
				   sizeof (COMPONENT_LINK))) == NULL)
    {
      zlog_err ("\n can not allocate memory %s %d", __FILE__, __LINE__);
      return NULL;
    }
  pComponentLink->next = NULL;
  return pComponentLink;
}

#if 0
static int
te_zebra_read_link (int command, struct zclient *zclient, zebra_size_t length)
{
  struct stream *s;
  struct zapi_te_link link;
  s = zclient->ibuf;
  zapi_te_link_read(s, &link);
  switch(command)
    {
      case ZEBRA_TE_LINK_ADD:
{
  TE_LINK *pTeLink;
  COMPONENT_LINK *pComponentLink;
  int ComponentLinksNumber = 1, i, j;
  PATRICIA_PARAMS params;

  if ((pTeLink = (TE_LINK *) XMALLOC (MTYPE_TE, sizeof (TE_LINK))) == NULL)
    {
      zlog_err ("\ncannnot allocate memory");
      return;
    }
  pTeLink->component_links = NULL;
  pTeLink->te_link_id = link->linkid;
  pTeLink->type = PSC_PATH;
  pTeLink->te_link_properties.TeMetric = link->metric;
  pTeLink->te_link_properties.color_mask = link->color_mask;
  pTeLink->te_link_properties.MaxLspBW = link->max_lsp_bw;
  pTeLink->te_link_properties.MaxReservableBW = link->max_res_bw;

  for (j = 0; j < 8; j++)
    pTeLink->te_link_properties.ReservableBW[j] = 0;
  for (i = 0; i < ComponentLinksNumber; i++)
    {
      if ((pComponentLink = new_component_link ()) == NULL)
	{
	  zlog_err ("\ncan initiate component link %s %d", __FILE__,
		    __LINE__);
	  return;
	}
      params.key_size = sizeof (FRR_LABEL_ENTRY);
      params.info_size = 0;
      if (patricia_tree_init (&pComponentLink->ProtectionTree, &params) !=
	  E_OK)
	{
	  zlog_err ("\ncannot initiate patricia tree (per SM) for FRR");
	  return;
	}

      params.key_size = sizeof (PSB_KEY);
      params.info_size = 0;
      if (patricia_tree_init (&pComponentLink->IngressProtectionTree, &params)
	  != E_OK)
	{
	  zlog_err ("\ncannot initiate patricia tree (per SM) for FRR");
	  return;
	}
      pComponentLink->next = pTeLink->component_links;
      pTeLink->component_links = pComponentLink;
      pComponentLink->oifIndex = link->ifindex; /*pTeLink->te_link_id */
      for (j = 0; j < 8; j++)
	{
	  pComponentLink->ReservableBW[j] = link->reservable_bw[j];
	  pComponentLink->ConfiguredReservableBW[j] = link->reservable_bw[j];
	  pTeLink->te_link_properties.ReservableBW[j] +=
	    pComponentLink->ReservableBW[j];
	}
    }

  if (rdb_add_te_link (pTeLink) != E_OK)
    {
      zlog_err ("\nCannot delete TE link");
    }
}
        break;
      case ZEBRA_TE_LINK_DELETE:
  if (rdb_del_te_link (link->linkid) != E_OK)
    {
      zlog_err ("\nCannot delete TE link");
    }
        break;
      case ZEBRA_TE_LINK_UPDATE:
  if (rdb_local_link_status_change (link->linkid, link->status) != E_OK)
    {
      zlog_err ("\nCannot set TE link down");
    }

        break;
    }
}

static int
te_zebra_read_remote_link (int command, struct zclient *zclient, zebra_size_t length)
{
  struct zapi_te_remote_link link;
  struct stream *s;
  s = zclient->ibuf;
  zapi_te_remote_link_read(s, &link);
#if 0
  switch (command)
    {
case RemoteLsUpdate:
{
  LINK_PROPERTIES LinkProperties;
  int j;

  LinkProperties.LinkTeMetric = link->metric;
  LinkProperties.LinkColorMask = link->color_mask;
  LinkProperties.LinkMaxLspBW = link->max_lsp_bw;
  LinkProperties.LinkMaxReservableBW = link->max_res_bw;

  for (j = 0; j < 8; j++)
    {
      LinkProperties.LinkReservableBW[j] = link->reservable_bw[j];
    }

  LinkProperties.LinkType = PSC_PATH;

  if (rdb_link_state_update (link->from_node.s_addr, link->to_node.s_addr, &LinkProperties) != E_OK)
    {
      zlog_err ("\nFailure");
    }
}
break;
case ConnectivityBroken:
  if (rdb_connectivity_broken (link->from_node.s_addr, link->to_node.s_addr, PSC_PATH) != E_OK)
    {
      zlog_err ("\nfailed");
    }
break;

    }
#endif
}

static int
te_zebra_read_link2rtrid (int command, struct zclient *zclient, zebra_size_t length)
{
  struct zapi_te_link2rtrid l2ri;
  struct stream *s;
  s = zclient->ibuf;
  zapi_te_link2rtrid_read(s, &l2ri);
  switch (command)
    {
      case ZEBRA_TE_LINK2RTRID_ADD:
  if (rdb_remote_link_2_router_id_mapping (l2ri->linkid, l2ri->routerid.s_addr) != E_OK)
    {
      zlog_err ("Cannot map link with ip address %x to router with id %x",
                l2ri->linkid, l2ri->routerid.s_addr);
    }
        break;
      case ZEBRA_TE_LINK2RTRID_DELETE:
  if (rdb_remote_link_2_router_id_mapping_withdraw (l2ri->linkid) != E_OK)
    {
      zlog_err ("Cannot withdraw mapping of link with ip address %x",
                l2ri->linkid);
    }
        break;
    }
}

static int
te_zebra_read_nexthop (int command, struct zclient *zclient, zebra_size_t length)
{
  struct zapi_te_nexthop nh;
  struct stream *s;
  s = zclient->ibuf;
  zapi_te_nexthop_read(s, &nh);
  switch(command)
    {
      case ZEBRA_TE_NEXTHOP_ADD:
  if (rdb_add_next_hop (nh->nh.gw.ipv4.s_addr, nh->linkid) != E_OK)
    {
      zlog_err ("\nCannot add next hop");
    }
      case ZEBRA_TE_NEXTHOP_DELETE:
  if (rdb_del_next_hop (nh->nh.gw.ipv4.s_addr, nh->linkid) != E_OK)
    {
      zlog_err ("\nCannot delete Next Hop");
    }

    }
}
#endif


void
rsvp_zebra_init ()
{
  /* Allocate zebra structure. */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_RSVP);
  zclient->router_id_update = rsvp_router_id_update_zebra;
  zclient->interface_add = rsvp_interface_add;
  zclient->interface_delete = rsvp_interface_delete;
  zclient->interface_up = rsvp_interface_state_up;
  zclient->interface_down = rsvp_interface_state_down;
  zclient->interface_address_add = rsvp_interface_address_add;
  zclient->interface_address_delete = rsvp_interface_address_delete;
  zclient->ipv4_route_add = rsvp_zebra_read_ipv4;
  zclient->ipv4_route_delete = rsvp_zebra_read_ipv4;
#if 0
  zclient->te_link_add = te_zebra_read_link;
  zclient->te_link_delete = te_zebra_read_link;
  zclient->te_link_update = te_zebra_read_link;
  zclient->te_link_remote_update = te_zebra_read_remote_link;
  zclient->te_link2rtrid_add = te_zebra_read_link2rtrid;
  zclient->te_link2rtrid_delete = te_zebra_read_link2rtrid;
  zclient->te_nexthop_add = te_zebra_read_nexthop;
  zclient->te_nexthop_delete = te_zebra_read_nexthop;
#endif

  zclient_redistribute (ZEBRA_REDISTRIBUTE_ADD, zclient, ZEBRA_ROUTE_TE);
#if 0
  rdb_igp_hello();
#endif
}
