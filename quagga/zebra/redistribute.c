/* Redistribution Handler
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include "vector.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "zclient.h"
#include "linklist.h"
#include "log.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"

/* master zebra server structure */
extern struct zebra_t zebrad;

int
zebra_check_addr (struct prefix *p)
{
  if (p->family == AF_INET)
    {
      u_int32_t addr;

      addr = p->u.prefix4.s_addr;
      addr = ntohl (addr);

      if (IPV4_NET127 (addr)
          || IN_CLASSD (addr)
          || IPV4_LINKLOCAL(addr))
	return 0;
    }
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    {
      if (IN6_IS_ADDR_LOOPBACK (&p->u.prefix6))
	return 0;
      if (IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
	return 0;
    }
#endif /* HAVE_IPV6 */
  return 1;
}

static int
is_default (struct prefix *p)
{
  if (p->family == AF_INET)
    if (p->u.prefix4.s_addr == 0 && p->prefixlen == 0)
      return 1;
#ifdef HAVE_IPV6
#if 0  /* IPv6 default separation is now pending until protocol daemon
          can handle that. */
  if (p->family == AF_INET6)
    if (IN6_IS_ADDR_UNSPECIFIED (&p->u.prefix6) && p->prefixlen == 0)
      return 1;
#endif /* 0 */
#endif /* HAVE_IPV6 */
  return 0;
}

static void
zebra_redistribute_default (struct zserv *client)
{
  struct prefix_ipv4 p;
  struct route_table *table;
  struct route_node *rn;
  struct rib *newrib;
#ifdef HAVE_IPV6
  struct prefix_ipv6 p6;
#endif /* HAVE_IPV6 */


  /* Lookup default route. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;

  /* Lookup table.  */
  table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
  if (table)
    {
      rn = route_node_lookup (table, (struct prefix *)&p);
      if (rn)
	{
	  for (newrib = rn->info; newrib; newrib = newrib->next)
	    if (CHECK_FLAG (newrib->flags, ZEBRA_FLAG_SELECTED)
		&& newrib->distance != DISTANCE_INFINITY)
	      zsend_route_multipath (ZEBRA_IPV4_ROUTE_ADD, client, &rn->p, newrib);
	  route_unlock_node (rn);
	}
    }

#ifdef HAVE_IPV6
  /* Lookup default route. */
  memset (&p6, 0, sizeof (struct prefix_ipv6));
  p6.family = AF_INET6;

  /* Lookup table.  */
  table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
  if (table)
    {
      rn = route_node_lookup (table, (struct prefix *)&p6);
      if (rn)
	{
	  for (newrib = rn->info; newrib; newrib = newrib->next)
	    if (CHECK_FLAG (newrib->flags, ZEBRA_FLAG_SELECTED)
		&& newrib->distance != DISTANCE_INFINITY)
	      zsend_route_multipath (ZEBRA_IPV6_ROUTE_ADD, client, &rn->p, newrib);
	  route_unlock_node (rn);
	}
    }
#endif /* HAVE_IPV6 */
}

/* Redistribute routes. */
static void
zebra_redistribute (struct zserv *client, int type)
{
  struct rib *newrib;
  struct route_table *table;
  struct route_node *rn;

  table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      for (newrib = rn->info; newrib; newrib = newrib->next)
	if (CHECK_FLAG (newrib->flags, ZEBRA_FLAG_SELECTED) 
	    && newrib->type == type 
	    && newrib->distance != DISTANCE_INFINITY
	    && zebra_check_addr (&rn->p))
	  zsend_route_multipath (ZEBRA_IPV4_ROUTE_ADD, client, &rn->p, newrib);
  
#ifdef HAVE_IPV6
  table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      for (newrib = rn->info; newrib; newrib = newrib->next)
	if (CHECK_FLAG (newrib->flags, ZEBRA_FLAG_SELECTED)
	    && newrib->type == type 
	    && newrib->distance != DISTANCE_INFINITY
	    && zebra_check_addr (&rn->p))
	  zsend_route_multipath (ZEBRA_IPV6_ROUTE_ADD, client, &rn->p, newrib);
#endif /* HAVE_IPV6 */

#ifdef HAVE_MPLS
  {
    struct listnode *node;
    struct zmpls_in_segment *in;
    struct zmpls_out_segment *out;
    struct zmpls_ftn *ftn;
    struct zmpls_xc *xc;
    struct interface *ifp;

    for (ALL_LIST_ELEMENTS_RO(iflist, node, ifp))
      if (type == ZEBRA_ROUTE_STATIC &&
          ifp->mpls_labelspace > -1)
          zsend_mpls_labelspace_add (client, ifp);

    for (ALL_LIST_ELEMENTS_RO(&mpls_in_segment_list, node, in))
      if (type == in->owner)
        zsend_mpls_in_segment_add (client, in);

    for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list, node, out))
      if (type == out->owner)
        zsend_mpls_out_segment_add (client, out);

    for (ALL_LIST_ELEMENTS_RO(&mpls_xc_list, node, xc))
      if (type == xc->owner)
        zsend_mpls_xc_add (client, xc);

    for (ALL_LIST_ELEMENTS_RO(&mpls_ftn_list, node, ftn))
      if (type == ftn->owner)
        zsend_mpls_ftn_add (client, ftn);
  }
#endif /* HAVE_MPLS */
}

void
redistribute_add (struct prefix *p, struct rib *rib)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  /* MPLS: check is there are any FTN waiting for this */

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      if (is_default (p))
        {
          if (client->redist_default || client->redist[rib->type])
            {
              if (p->family == AF_INET)
                zsend_route_multipath (ZEBRA_IPV4_ROUTE_ADD, client, p, rib);
#ifdef HAVE_IPV6
              if (p->family == AF_INET6)
                zsend_route_multipath (ZEBRA_IPV6_ROUTE_ADD, client, p, rib);
#endif /* HAVE_IPV6 */	  
	    }
        }
      else if (client->redist[rib->type])
        {
          if (p->family == AF_INET)
            zsend_route_multipath (ZEBRA_IPV4_ROUTE_ADD, client, p, rib);
#ifdef HAVE_IPV6
          if (p->family == AF_INET6)
            zsend_route_multipath (ZEBRA_IPV6_ROUTE_ADD, client, p, rib);
#endif /* HAVE_IPV6 */	  
        }
    }
}

void
redistribute_delete (struct prefix *p, struct rib *rib)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  /* Add DISTANCE_INFINITY check. */
  if (rib->distance == DISTANCE_INFINITY)
    return;

  /* MPLS: check is there are any FTN depending on this */

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      if (is_default (p))
	{
	  if (client->redist_default || client->redist[rib->type])
	    {
	      if (p->family == AF_INET)
		zsend_route_multipath (ZEBRA_IPV4_ROUTE_DELETE, client, p,
				       rib);
#ifdef HAVE_IPV6
	      if (p->family == AF_INET6)
		zsend_route_multipath (ZEBRA_IPV6_ROUTE_DELETE, client, p,
				       rib);
#endif /* HAVE_IPV6 */
	    }
	}
      else if (client->redist[rib->type])
	{
	  if (p->family == AF_INET)
	    zsend_route_multipath (ZEBRA_IPV4_ROUTE_DELETE, client, p, rib);
#ifdef HAVE_IPV6
	  if (p->family == AF_INET6)
	    zsend_route_multipath (ZEBRA_IPV6_ROUTE_DELETE, client, p, rib);
#endif /* HAVE_IPV6 */
	}
    }
}

void
zebra_redistribute_add (int command, struct zserv *client, int length)
{
  int type;

  type = stream_getc (client->ibuf);

  switch (type)
    {
    case ZEBRA_ROUTE_KERNEL:
    case ZEBRA_ROUTE_CONNECT:
    case ZEBRA_ROUTE_STATIC:
    case ZEBRA_ROUTE_RIP:
    case ZEBRA_ROUTE_RIPNG:
    case ZEBRA_ROUTE_OSPF:
    case ZEBRA_ROUTE_OSPF6:
    case ZEBRA_ROUTE_BGP:
    case ZEBRA_ROUTE_LDP:
      if (! client->redist[type])
	{
	  client->redist[type] = 1;
	  zebra_redistribute (client, type);
	}
      break;
    default:
      break;
    }
}     

void
zebra_redistribute_delete (int command, struct zserv *client, int length)
{
  int type;

  type = stream_getc (client->ibuf);

  switch (type)
    {
    case ZEBRA_ROUTE_KERNEL:
    case ZEBRA_ROUTE_CONNECT:
    case ZEBRA_ROUTE_STATIC:
    case ZEBRA_ROUTE_RIP:
    case ZEBRA_ROUTE_RIPNG:
    case ZEBRA_ROUTE_OSPF:
    case ZEBRA_ROUTE_OSPF6:
    case ZEBRA_ROUTE_BGP:
    case ZEBRA_ROUTE_LDP:
      client->redist[type] = 0;
      break;
    default:
      break;
    }
}     

void
zebra_redistribute_default_add (int command, struct zserv *client, int length)
{
  client->redist_default = 1;
  zebra_redistribute_default (client);
}     

void
zebra_redistribute_default_delete (int command, struct zserv *client,
				   int length)
{
  client->redist_default = 0;;
}     

/* Interface up information. */
void
zebra_interface_up_update (struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_UP %s", ifp->name);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    zsend_interface_update (ZEBRA_INTERFACE_UP, client, ifp);

#ifdef HAVE_MPLS
  if (ifp->mpls_labelspace >= 0)
    mpls_ctrl_set_interface_labelspace(ifp, ifp->mpls_labelspace);

  /* MPLS: check if there are any NHLFE waiting for this */
  if (if_is_operative(ifp))
  {
    struct zmpls_out_segment *out;
    for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list, node, out))
    {
      if ((out->installed) ||
          !mpls_nexthop_ready(&out->nh))
        continue;

      out->installed = 1;
      mpls_ctrl_nhlfe_register(out);
      redistribute_add_mpls_out_segment (out);
    }
  } else {
    assert(0);
  }
#endif /* HAVE_MPLS */
}

/* Interface down information. */
void
zebra_interface_down_update (struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_DOWN %s", ifp->name);

#ifdef HAVE_MPLS
  /* MPLS: check if there are any NHLFE depending on this */
  struct zmpls_out_segment *out;
  for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list, node, out))
  {
    if ((!out->installed) ||
        mpls_nexthop_ready(&out->nh))
      continue;

    redistribute_delete_mpls_out_segment (out);
    mpls_ctrl_nhlfe_unregister(out);
    out->installed = 0;
  }
#endif /* HAVE_MPLS */

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    zsend_interface_update (ZEBRA_INTERFACE_DOWN, client, ifp);
}

/* Interface information update. */
void
zebra_interface_add_update (struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_ADD %s", ifp->name);
    
  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    if (client->ifinfo)
      zsend_interface_add (client, ifp);

#ifdef HAVE_MPLS
  /* MPLS: check if there are any NHLFE waiting for this */
  if (if_is_operative(ifp))
  {
    struct zmpls_out_segment *out;
    for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list, node, out))
    {
      if ((out->installed) ||
          !mpls_nexthop_ready(&out->nh))
        continue;

      out->installed = 1;
      mpls_ctrl_nhlfe_register(out);
      redistribute_add_mpls_out_segment (out);
    }
  }
#endif /* HAVE_MPLS */
}

void
zebra_interface_delete_update (struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_DELETE %s", ifp->name);

#ifdef HAVE_MPLS
  /* MPLS: check if there are any NHLFE depending on this */
  struct zmpls_out_segment *out;
  for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list, node, out))
  {
    if ((!out->installed) ||
        mpls_nexthop_ready(&out->nh))
      continue;

    out->installed = 0;
    redistribute_delete_mpls_out_segment (out);
    mpls_ctrl_nhlfe_unregister(out);
  }
#endif /* HAVE_MPLS */

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    if (client->ifinfo)
      zsend_interface_delete (client, ifp);
}

/* Interface address addition. */
void
zebra_interface_address_add_update (struct interface *ifp,
				    struct connected *ifc)
{
  struct listnode *node, *nnode;
  struct zserv *client;
  struct prefix *p;
  char buf[BUFSIZ];

  if (IS_ZEBRA_DEBUG_EVENT)
    {
      p = ifc->address;
      zlog_debug ("MESSAGE: ZEBRA_INTERFACE_ADDRESS_ADD %s/%d on %s",
		  inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		  p->prefixlen, ifc->ifp->name);
    }

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    if (client->ifinfo && CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL))
      zsend_interface_address (ZEBRA_INTERFACE_ADDRESS_ADD, client, ifp, ifc);

  router_id_add_address(ifc);

#ifdef HAVE_MPLS
  /* MPLS: check if there are any NHLFE waiting for this */
  if (if_is_operative(ifp))
  {
    struct zmpls_out_segment *out;
    for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list, node, out))
    {
      if ((out->installed) ||
          !mpls_nexthop_ready(&out->nh))
        continue;

      out->installed = 1;
      mpls_ctrl_nhlfe_register(out);
      redistribute_add_mpls_out_segment (out);
    }
  }
#endif /* HAVE_MPLS */
}

/* Interface address deletion. */
void
zebra_interface_address_delete_update (struct interface *ifp,
				       struct connected *ifc)
{
  struct listnode *node, *nnode;
  struct zserv *client;
  struct prefix *p;
  char buf[BUFSIZ];

  if (IS_ZEBRA_DEBUG_EVENT)
    {
      p = ifc->address;
      zlog_debug ("MESSAGE: ZEBRA_INTERFACE_ADDRESS_DELETE %s/%d on %s",
		  inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		 p->prefixlen, ifc->ifp->name);
    }

#ifdef HAVE_MPLS
  /* MPLS: check if there are any NHLFE depending on this */
  struct zmpls_out_segment *out;
  for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list, node, out))
  {
    if ((!out->installed) ||
        mpls_nexthop_ready(&out->nh))
      continue;

    redistribute_delete_mpls_out_segment (out);
    mpls_ctrl_nhlfe_unregister(out);
    out->installed = 0;
  }
#endif /* HAVE_MPLS */

  router_id_del_address(ifc);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    if (client->ifinfo && CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL))
      zsend_interface_address (ZEBRA_INTERFACE_ADDRESS_DELETE, client, ifp, ifc);
}

#ifdef HAVE_MPLS
void
redistribute_add_mpls_xc (struct zmpls_xc *xc)
{
  struct listnode *node;
  struct zserv *client;

  /* Check to see and and ILM are waiting for this xc */
  struct zmpls_in_segment *in;
  for (ALL_LIST_ELEMENTS_RO(&mpls_in_segment_list, node, in))
  {
    if (in->installed || in->xc != xc->index)
      continue;

    in->installed = 1;
    mpls_ctrl_ilm_register (in);
    redistribute_add_mpls_in_segment (in);
  }

  for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
     if (client->redist[xc->owner])
	zsend_mpls_xc_add (client, xc);
}

void
redistribute_delete_mpls_xc (struct zmpls_xc *xc)
{
  struct listnode *node;
  struct zserv *client;

  for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
     if (client->redist[xc->owner])
	zsend_mpls_xc_delete (client, xc);

  /* Check to see and and ILM depend on this xc */
  struct zmpls_in_segment *in;
  for (ALL_LIST_ELEMENTS_RO(&mpls_in_segment_list, node, in))
  {
    if ((!in->installed) || in->xc != xc->index)
      continue;

    in->installed = 0;
    mpls_ctrl_ilm_unregister (in);
    redistribute_delete_mpls_in_segment (in);
  }
}

void
redistribute_add_mpls_in_segment (struct zmpls_in_segment *in)
{
  struct listnode *node;
  struct zserv *client;

  /* MPLS: check is there are any XC waiting for this */
  struct zmpls_xc *xc;
  for (ALL_LIST_ELEMENTS_RO(&mpls_xc_list, node, xc))
  {
    struct zmpls_out_segment *out;
    struct zmpls_in_segment tmp;

    tmp.labelspace = xc->in_labelspace;
    memcpy(&tmp.label, &xc->in_label, sizeof(struct zmpls_label));

    if (xc->installed || !mpls_in_segment_match(in, &tmp))
      continue;

    out = mpls_out_segment_find (xc->out_index);

    xc->installed = 1;
    mpls_ctrl_xc_register (in, out);
    redistribute_add_mpls_xc (xc);
  }

  for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
     if (client->redist[in->owner])
	zsend_mpls_in_segment_add (client, in);
}

void
redistribute_delete_mpls_in_segment (struct zmpls_in_segment *in)
{
  struct listnode *node;
  struct zserv *client;

  for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
     if (client->redist[in->owner])
	zsend_mpls_in_segment_delete (client, in);

  /* MPLS: check is there are any XC depending on this */
  struct zmpls_xc *xc;
  for (ALL_LIST_ELEMENTS_RO(&mpls_xc_list, node, xc))
  {
    struct zmpls_out_segment *out;
    struct zmpls_in_segment tmp;

    tmp.labelspace = xc->in_labelspace;
    memcpy(&tmp.label, &xc->in_label, sizeof(struct zmpls_label));

    if ((!xc->installed) || !mpls_in_segment_match(in, &tmp))
      continue;

    out = mpls_out_segment_find (xc->out_index);

    xc->installed = 0;
    mpls_ctrl_xc_unregister (in, out);
    redistribute_delete_mpls_xc (xc);
  }
}

void
redistribute_add_mpls_out_segment (struct zmpls_out_segment *out)
{
  struct listnode *node;
  struct zserv *client;

  /* MPLS: check is there are any FTN waiting for this */
  /* MPLS: check is there are any XC waiting for this */
  struct zmpls_xc *xc;
  for (ALL_LIST_ELEMENTS_RO(&mpls_xc_list, node, xc))
  {
    struct zmpls_in_segment tmp;
    struct zmpls_in_segment *in;

    if (xc->installed || xc->out_index != out->index)
      continue;

    tmp.labelspace = xc->in_labelspace;
    memcpy(&tmp.label, &xc->in_label, sizeof(struct zmpls_label));
    in = mpls_in_segment_find (&tmp);

    xc->installed = 1;
    redistribute_add_mpls_xc (xc);
    mpls_ctrl_xc_register (in, out);
  }

  for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
     if (client->redist[out->owner])
	zsend_mpls_out_segment_add (client, out);
}

void
redistribute_delete_mpls_out_segment (struct zmpls_out_segment *out)
{
  struct listnode *node;
  struct zserv *client;

  for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
     if (client->redist[out->owner])
	zsend_mpls_out_segment_delete (client, out);

  /* MPLS: check is there are any FTN depending on this */
  /* MPLS: check is there are any XC depending on this */
  struct zmpls_xc *xc;
  for (ALL_LIST_ELEMENTS_RO(&mpls_xc_list, node, xc))
  {
    struct zmpls_in_segment tmp;
    struct zmpls_in_segment *in;

    if ((!xc->installed) || xc->out_index != out->index)
      continue;

    tmp.labelspace = xc->in_labelspace;
    memcpy(&tmp.label, &xc->in_label, sizeof(struct zmpls_label));
    in = mpls_in_segment_find (&tmp);

    xc->installed = 0;
    mpls_ctrl_xc_unregister (in, out);
    redistribute_delete_mpls_xc (xc);
  }
}

void
redistribute_add_mpls_labelspace (struct interface *ifp)
{
  struct listnode *node;
  struct zserv *client;

  for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
     if (client->redist[ZEBRA_ROUTE_STATIC])
	zsend_mpls_labelspace_add (client, ifp);
}

void
redistribute_delete_mpls_labelspace (struct interface *ifp)
{
  struct listnode *node;
  struct zserv *client;

  for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
     if (client->redist[ZEBRA_ROUTE_STATIC])
	zsend_mpls_labelspace_delete (client, ifp);
}

void
redistribute_add_mpls_ftn (struct zmpls_ftn *ftn)
{
  struct listnode *node;
  struct zserv *client;

  for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
     if (client->redist[ftn->owner])
	zsend_mpls_ftn_add (client, ftn);
}

void
redistribute_delete_mpls_ftn (struct zmpls_ftn *ftn)
{
  struct listnode *node;
  struct zserv *client;

  for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
     if (client->redist[ftn->owner])
	zsend_mpls_ftn_delete (client, ftn);
}
#endif /* HAVE_MPLS */
