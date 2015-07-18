/* Routing Information Base.
 * Copyright (C) 1997, 98, 99, 2001 Kunihiro Ishiguro
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

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "str.h"
#include "command.h"
#include "if.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "thread.h"
#include "workqueue.h"
#include "prefix.h"
#include "routemap.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"

/* Default rtm_table for all clients */
extern struct zebra_t zebrad;

/* Hold time for RIB process, should be very minimal.
 * it is useful to able to set it otherwise for testing, hence exported
 * as global here for test-rig code.
 */
int rib_process_hold_time = 10;

/* Each route type's string and default distance value. */
struct
{  
  int key;
  int distance;
} route_info[] =
{
  {ZEBRA_ROUTE_SYSTEM,    0},
  {ZEBRA_ROUTE_KERNEL,    0},
  {ZEBRA_ROUTE_CONNECT,   0},
  {ZEBRA_ROUTE_STATIC,    1},
  {ZEBRA_ROUTE_RIP,     120},
  {ZEBRA_ROUTE_RIPNG,   120},
  {ZEBRA_ROUTE_OSPF,    110},
  {ZEBRA_ROUTE_OSPF6,   110},
  {ZEBRA_ROUTE_ISIS,    115},
  {ZEBRA_ROUTE_BGP,      20  /* IBGP is 200. */}
};

/* Vector for routing table.  */
vector vrf_vector;

#ifdef HAVE_IPV6
static int
rib_bogus_ipv6 (int, struct prefix_ipv6*, struct in6_addr*, unsigned int, int);
#endif

/* Allocate new VRF.  */
static struct vrf *
vrf_alloc (const char *name)
{
  struct vrf *vrf;

  vrf = XCALLOC (MTYPE_VRF, sizeof (struct vrf));

  /* Put name.  */
  if (name)
    vrf->name = XSTRDUP (MTYPE_VRF_NAME, name);

  /* Allocate routing table and static table.  */
  vrf->table[AFI_IP][SAFI_UNICAST] = route_table_init ();
  vrf->table[AFI_IP6][SAFI_UNICAST] = route_table_init ();
  vrf->stable[AFI_IP][SAFI_UNICAST] = route_table_init ();
  vrf->stable[AFI_IP6][SAFI_UNICAST] = route_table_init ();

  return vrf;
}

/* Free VRF.  */
static void
vrf_free (struct vrf *vrf)
{
  if (vrf->name)
    XFREE (MTYPE_VRF_NAME, vrf->name);
  XFREE (MTYPE_VRF, vrf);
}

/* Lookup VRF by identifier.  */
struct vrf *
vrf_lookup (u_int32_t id)
{
  return vector_lookup (vrf_vector, id);
}

/* Lookup VRF by name.  */
static struct vrf *
vrf_lookup_by_name (char *name)
{
  unsigned int i;
  struct vrf *vrf;

  for (i = 0; i < vector_active (vrf_vector); i++)
    if ((vrf = vector_slot (vrf_vector, i)) != NULL)
      if (vrf->name && name && strcmp (vrf->name, name) == 0)
	return vrf;
  return NULL;
}

/* Initialize VRF.  */
static void
vrf_init (void)
{
  struct vrf *default_table;

  /* Allocate VRF vector.  */
  vrf_vector = vector_init (1);

  /* Allocate default main table.  */
  default_table = vrf_alloc ("Default-IP-Routing-Table");

  /* Default table index must be 0.  */
  vector_set_index (vrf_vector, 0, default_table);
}

/* Lookup route table.  */
struct route_table *
vrf_table (afi_t afi, safi_t safi, u_int32_t id)
{
  struct vrf *vrf;

  vrf = vrf_lookup (id);
  if (! vrf)
    return NULL;

  return vrf->table[afi][safi];
}

/* Lookup static route table.  */
struct route_table *
vrf_static_table (afi_t afi, safi_t safi, u_int32_t id)
{
  struct vrf *vrf;

  vrf = vrf_lookup (id);
  if (! vrf)
    return NULL;

  return vrf->stable[afi][safi];
}

static int
zapi_nexthop_str(struct zapi_nexthop *nh, char *buf, int size)
{
  struct interface *ifp = NULL;
  char buf1[BUFSIZ];
  char *ptr = buf;
  int len = 0;

  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_DROP))
    {
      switch (nh->gw.drop)
        {
	  case ZEBRA_DROP_NULL:
	    len = snprintf(buf, size, " Null0");
	    break;
	  case ZEBRA_DROP_REJECT:
	    len = snprintf(buf, size, " reject");
	    break;
	  case ZEBRA_DROP_BLACKHOLE:
	    len = snprintf(buf, size, " blackhole");
	    break;
	  default:
	    assert(0);
        }
    }

  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IPV4))
    {
      inet_ntop (AF_INET, &nh->gw.ipv4, buf1, BUFSIZ),
      len += snprintf(ptr, size, " via %s", buf1);
      ptr = &buf[len];
    }
#ifdef HAVE_IPV6
  else if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IPV6))
    {
      inet_ntop (AF_INET6, &nh->gw.ipv6, buf1, BUFSIZ),
      len += snprintf(ptr, size, " via %s", buf1);
      ptr = &buf[len];
    }
#endif

  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IFINDEX))
    {
      ifp = if_lookup_by_index (nh->intf.index);
    }
  else if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IFNAME))
    {
      ifp = if_lookup_by_name (nh->intf.name);
    }

  if (ifp)
    {
      len += snprintf(ptr, size - len, " intf %s(%d)", ifp->name, ifp->ifindex);
      ptr = &buf[len];
    }
#ifdef HAVE_MPLS
  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_MPLS))
    {
      struct zmpls_out_segment *out;
      out = mpls_out_segment_find(&nh->mpls);
      if (out)
	{
	  len += snprintf(ptr, size - len, " mpls 0x%08x", nh->mpls);
	  ptr = &buf[len];
	}
    }
#endif
  return len;  
}

static int
nexthop_str(struct nexthop *nh, char *buf, int size)
{
  struct interface *ifp = NULL;
  char buf1[BUFSIZ];
  char *ptr = buf;
  int len = 0;

  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_DROP))
    {
      switch (nh->drop)
        {
	  case ZEBRA_DROP_NULL:
	    len = snprintf(buf, size, " Null0");
	    break;
	  case ZEBRA_DROP_REJECT:
	    len = snprintf(buf, size, " reject");
	    break;
	  case ZEBRA_DROP_BLACKHOLE:
	    len = snprintf(buf, size, " blackhole");
	    break;
	  default:
	    assert(0);
        }
    }

  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IPV4))
    {
      inet_ntop (AF_INET, &nh->gate.ipv4, buf1, BUFSIZ),
      len += snprintf(ptr, size, " via %s", buf1);
      ptr = &buf[len];
    }
#ifdef HAVE_IPV6
  else if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IPV6))
    {
      inet_ntop (AF_INET6, &nh->gate.ipv6, buf1, BUFSIZ),
      len += snprintf(ptr, size, " via %s", buf1);
      ptr = &buf[len];
    }
#endif

  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IFINDEX))
    {
      ifp = if_lookup_by_index (nh->ifindex);
    }
  else if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IFNAME))
    {
      ifp = if_lookup_by_name (nh->ifname);
    }

  if (ifp)
    {
      len += snprintf(ptr, size - len, " intf %s(%d)", ifp->name, ifp->ifindex);
      ptr = &buf[len];
    }
#ifdef HAVE_MPLS
  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_MPLS))
    {
      struct zmpls_out_segment *out;
      out = mpls_out_segment_find(&nh->mpls);
      if (out)
	{
	  len += snprintf(ptr, size - len, " mpls 0x%08x", nh->mpls);
	  ptr = &buf[len];
	}
    }
#endif
  return len;  
}

static int
zapi_nexthop_match_nexthop(struct zapi_nexthop *znh, struct nexthop *nh, int mask)
{
  int either = (nh->type | znh->type) & mask;
  int both = (nh->type & znh->type) & mask;
  int try = 0;
  int match = 0;
  int v4_gate_match = 0;

  try++;
  if (nh->advmss == znh->advmss)
    match++;

  if (CHECK_FLAG(either, ZEBRA_NEXTHOP_DROP))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_DROP) &&
	  nh->drop == znh->gw.drop)
        match++;
    }
  else if (CHECK_FLAG(either, ZEBRA_NEXTHOP_IPV4))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_IPV4) &&
         (IPV4_ADDR_SAME (&nh->gate.ipv4, &znh->gw.ipv4) ||
          IPV4_ADDR_SAME (&nh->rgate.ipv4, &znh->gw.ipv4)))
	{
	  match++;
	  v4_gate_match = 1;
	}
    }
#ifdef HAVE_IPV6
  else if (CHECK_FLAG(either, ZEBRA_NEXTHOP_IPV6))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_IPV6) &&
         (IPV6_ADDR_SAME (&nh->gate.ipv6, &znh->gw.ipv6) ||
          IPV6_ADDR_SAME (&nh->rgate.ipv6, &znh->gw.ipv6)))
        match++;
    }
#endif

  if (CHECK_FLAG(either, ZEBRA_NEXTHOP_IFINDEX))
    {
      if (!v4_gate_match)
        {
          try++;
          if (CHECK_FLAG (both, ZEBRA_NEXTHOP_IFINDEX) &&
            (nh->ifindex == znh->intf.index))
            match++;
        }
      else if (CHECK_FLAG (both, ZEBRA_NEXTHOP_IFINDEX))
        {
            try++;
            if (nh->ifindex == znh->intf.index)
              match++;
        }
    }
  else if (CHECK_FLAG(either, ZEBRA_NEXTHOP_IFNAME))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_IFNAME) &&
         (!strncmp(nh->ifname, znh->intf.name, IFNAMSIZ)))
        match++;
    }

  if (CHECK_FLAG(either, ZEBRA_NEXTHOP_SRC_IPV4))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_SRC_IPV4) &&
          IPV4_ADDR_SAME (&nh->src.ipv4, &znh->src.ipv4))
        match++;
    }
#ifdef HAVE_IPV6
  else if (CHECK_FLAG(either, ZEBRA_NEXTHOP_SRC_IPV6))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_SRC_IPV6) &&
          IPV6_ADDR_SAME (&nh->src.ipv6, &znh->src.ipv6))
        match++;
    }
#endif
#ifdef HAVE_MPLS
  if (CHECK_FLAG(either, ZEBRA_NEXTHOP_MPLS))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_MPLS) &&
          nh->mpls == mpls_out_segment_find_index_by_nexthop(znh))
        match++;
    }
#endif
  return (try && try == match) ? 1 : 0;
}

static int
zapi_nexthop_match_static_route(u_char distance, struct zapi_nexthop *znh,
                                struct static_route *si)
{
  int try = 0;
  int match = 0;

  try++;
  if (distance == si->distance)
    match++;

  try++;
  if (zapi_nexthop_match(znh, &si->nh, ZEBRA_NEXTHOP_ALL))
    match++;

  return (try && try == match) ? 1 : 0;
}

void
zapi_nexthop2nexthop(struct zapi_nexthop* znh, struct nexthop *nh)
{
  nh->type = znh->type;
  nh->advmss = znh->advmss;

  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_DROP))
    nh->drop = znh->gw.drop;
  else if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_SRC_IPV4))
    nh->src.ipv4 = znh->src.ipv4;
#ifdef HAVE_IPV6
  else if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_SRC_IPV6))
    nh->src.ipv6 = znh->src.ipv6;
#endif

  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IPV4))
    nh->gate.ipv4 = znh->gw.ipv4;
#ifdef HAVE_IPV6
  else if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IPV6))
    nh->gate.ipv6 = znh->gw.ipv6;
#endif

  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IFINDEX))
    nh->ifindex = znh->intf.index;
  else if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_IFNAME))
    nh->ifname = XSTRDUP (0, znh->intf.name);
#ifdef HAVE_MPLS
  if (CHECK_FLAG(nh->type, ZEBRA_NEXTHOP_MPLS))
    nh->mpls = mpls_out_segment_find_index_by_nexthop(znh);
#endif
}

static int
nexthop_match(struct nexthop *znh, struct nexthop *nh, int mask)
{
  int either = (nh->type | znh->type) & mask;
  int both = (nh->type & znh->type) & mask;
  int try = 0;
  int match = 0;
  int v4_gate_match = 0;

  try++;
  if (nh->advmss == znh->advmss)
    match++;

  if (CHECK_FLAG(either, ZEBRA_NEXTHOP_DROP))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_DROP) &&
	  nh->drop == znh->drop)
        match++;
    }
  else if (CHECK_FLAG(either, ZEBRA_NEXTHOP_IPV4))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_IPV4) &&
         (IPV4_ADDR_SAME (&nh->gate.ipv4, &znh->gate.ipv4) ||
          IPV4_ADDR_SAME (&nh->rgate.ipv4, &znh->rgate.ipv4)))
	{
	  match++;
	  v4_gate_match = 1;
	}
    }
#ifdef HAVE_IPV6
  else if (CHECK_FLAG(either, ZEBRA_NEXTHOP_IPV6))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_IPV6) &&
         (IPV6_ADDR_SAME (&nh->gate.ipv6, &znh->gate.ipv6) ||
          IPV6_ADDR_SAME (&nh->rgate.ipv6, &znh->rgate.ipv6)))
        match++;
    }
#endif

  if (CHECK_FLAG(either, ZEBRA_NEXTHOP_IFINDEX))
    {
      if (!v4_gate_match)
        {
          try++;
          if (CHECK_FLAG (both, ZEBRA_NEXTHOP_IFINDEX) &&
            (nh->ifindex == znh->ifindex))
            match++;
        }
      else if (CHECK_FLAG (both, ZEBRA_NEXTHOP_IFINDEX))
        {
            try++;
            if (nh->ifindex == znh->ifindex)
              match++;
        }
    }
  else if (CHECK_FLAG(either, ZEBRA_NEXTHOP_IFNAME))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_IFNAME) &&
         (!strncmp(nh->ifname, znh->ifname, IFNAMSIZ)))
        match++;
    }

  if (CHECK_FLAG(either, ZEBRA_NEXTHOP_SRC_IPV4))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_SRC_IPV4) &&
          IPV4_ADDR_SAME (&nh->src.ipv4, &znh->src.ipv4))
        match++;
    }
#ifdef HAVE_IPV6
  else if (CHECK_FLAG(either, ZEBRA_NEXTHOP_SRC_IPV6))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_SRC_IPV6) &&
          IPV6_ADDR_SAME (&nh->src.ipv6, &znh->src.ipv6))
        match++;
    }
#endif
#ifdef HAVE_MPLS
  if (CHECK_FLAG(either, ZEBRA_NEXTHOP_MPLS))
    {
      try++;
      if (CHECK_FLAG(both, ZEBRA_NEXTHOP_MPLS) &&
          nh->mpls == znh->mpls)
        match++;
    }
#endif
  return (try && try == match) ? 1 : 0;
}
/* Add nexthop to the end of the list.  */
static void
nexthop_add (struct rib *rib, struct nexthop *nexthop)
{
  struct nexthop *last;

  for (last = rib->nexthop; last && last->next; last = last->next)
    ;
  if (last)
    last->next = nexthop;
  else
    rib->nexthop = nexthop;
  nexthop->prev = last;

  rib->nexthop_num++;
}

/* Delete specified nexthop from the list. */
void
nexthop_delete (struct rib *rib, struct nexthop *nexthop)
{
  if (nexthop->next)
    nexthop->next->prev = nexthop->prev;
  if (nexthop->prev)
    nexthop->prev->next = nexthop->next;
  else
    rib->nexthop = nexthop->next;
  rib->nexthop_num--;
}

/* Free nexthop. */
void
nexthop_free (struct nexthop *nexthop)
{
  if (nexthop->ifname)
    XFREE (0, nexthop->ifname);
  XFREE (MTYPE_NEXTHOP, nexthop);
}

struct nexthop *
nexthop_zapi_nexthop_add(struct rib *rib, struct zapi_nexthop* znh)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));

  zapi_nexthop2nexthop(znh, nexthop);
  nexthop_add(rib, nexthop);

  return nexthop;
}

/* If force flag is not set, do not modify falgs at all for uninstall
   the route from FIB. */
static int
nexthop_active_route (struct rib *rib, struct nexthop *nexthop, int set,
		      struct route_node *top)
{
  struct prefix p;
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *newhop;
  int afi;

  memset (&p, 0, sizeof (struct prefix));

  if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV4))
    {
      nexthop->ifindex = 0;
      UNSET_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFINDEX);

      /* Make lookup prefix. */
      p.family = AF_INET;
      p.prefixlen = IPV4_MAX_PREFIXLEN;
      p.u.prefix4 = nexthop->gate.ipv4;
      afi = AFI_IP;
    }
#ifdef HAVE_IPV6
  else if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV6))
    {
      nexthop->ifindex = 0;
      UNSET_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFINDEX);

      /* Make lookup prefix. */
      p.family = AF_INET6;
      p.prefixlen = IPV6_MAX_PREFIXLEN;
      p.u.prefix6 = nexthop->gate.ipv6;
      afi = AFI_IP6;
    }
#endif
  else
    return 0;

  if (set)
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);

  /* Lookup table.  */
  table = vrf_table (afi, SAFI_UNICAST, 0);
  if (! table)
    return 0;

  rn = route_node_match (table, &p);
  while (rn)
    {
      route_unlock_node (rn);
      
      /* If lookup self prefix return immidiately. */
      if (rn == top)
	return 0;

      /* Pick up selected route. */
      for (match = rn->info; match; match = match->next)
	if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	  break;

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match 
	  || match->type == ZEBRA_ROUTE_BGP)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
	  if (match->type == ZEBRA_ROUTE_CONNECT)
	    {
	      /* Directly point connected route. */
	      newhop = match->nexthop;
	      if (newhop)
		{
		  SET_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFINDEX);
		  nexthop->ifindex = newhop->ifindex;
		}
	      
	      return 1;
	    }
	  else if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_INTERNAL))
	    {
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB)
		    && ! CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_IGNORE)
		    && ! CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_RECURSIVE))
		  {
		    if (set)
		      {
			SET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
			nexthop->rtype = newhop->type;

			if (CHECK_FLAG (newhop->type, ZEBRA_NEXTHOP_IPV4))
			  nexthop->rgate.ipv4 = newhop->gate.ipv4;
#ifdef HAVE_IPV6
			else if (CHECK_FLAG (newhop->type, ZEBRA_NEXTHOP_IPV6))
			  nexthop->rgate.ipv6 = newhop->gate.ipv6;
#endif
			else
			  assert (0);

			if (CHECK_FLAG (newhop->type, ZEBRA_NEXTHOP_IFINDEX))
			  nexthop->rifindex = newhop->ifindex;
#ifdef HAVE_MPLS
			if (CHECK_FLAG (newhop->type, ZEBRA_NEXTHOP_MPLS))
			    nexthop->rmpls = newhop->mpls;
#endif
		      }
		    return 1;
		  }
	      return 0;
	    }
	  else
	    {
	      return 0;
	    }
	}
    }
  return 0;
}

int
rib_check_drop (struct rib *rib)
{
  struct nexthop *nexthop;
  int flags = 0;
  int drop = 0;

  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
      if ((CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE) ||
           CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)) &&
           ((CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE) &&
	     CHECK_FLAG (nexthop->rtype, ZEBRA_NEXTHOP_DROP)) ||
	     CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_DROP)))
	{
	  drop = nexthop->drop;
	  break;
	}
    }

  switch (drop)
    {
      case 0:
	break;
      case ZEBRA_DROP_NULL:
      case ZEBRA_DROP_BLACKHOLE:
        flags = ZEBRA_FLAG_BLACKHOLE;
        break;
      case ZEBRA_DROP_REJECT:
        flags = ZEBRA_FLAG_REJECT;
        break;
      default:
        assert(0);
    }

  return flags;
}

struct rib *
rib_match_route (struct prefix *p)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *newhop;
  int afi;

  switch (p->family)
    {
      case AF_INET:
        afi = AFI_IP;
	p->prefixlen = IPV4_MAX_PREFIXLEN;
        break;
      case AF_INET6:
        afi = AFI_IP6;
	p->prefixlen = IPV6_MAX_PREFIXLEN;
        break;
      default:
        assert(0);
    }

  /* Lookup table.  */
  table = vrf_table (afi, SAFI_UNICAST, 0);
  if (! table)
    return 0;

  rn = route_node_match (table, p);

  while (rn)
    {
      route_unlock_node (rn);
      
      /* Pick up selected route. */
      for (match = rn->info; match; match = match->next)
	if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	  break;

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match 
	  || match->type == ZEBRA_ROUTE_BGP)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
	  if (match->type == ZEBRA_ROUTE_CONNECT)
	    /* Directly point connected route. */
	    return match;
	  else
	    {
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB)
		    && ! CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_IGNORE))
		  return match;
	      return NULL;
	    }
	}
    }
  return NULL;
}

struct rib *
rib_lookup_route (struct prefix *p)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *nexthop;
  int afi;

  switch (p->family)
    {
      case AF_INET:
        afi = AFI_IP;
        break;
      case AF_INET6:
        afi = AFI_IP6;
        break;
      default:
        assert(0);
    }

  /* Lookup table.  */
  table = vrf_table (afi, SAFI_UNICAST, 0);
  if (! table)
    return 0;

  rn = route_node_lookup (table, p);

  /* No route for this prefix. */
  if (! rn)
    return NULL;

  /* Unlock node. */
  route_unlock_node (rn);

  /* Pick up selected route. */
  for (match = rn->info; match; match = match->next)
    if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
      break;

  if (! match || match->type == ZEBRA_ROUTE_BGP)
    return NULL;

  if (match->type == ZEBRA_ROUTE_CONNECT)
    return match;
  
  for (nexthop = match->nexthop; nexthop; nexthop = nexthop->next)
    if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
	&& ! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_IGNORE))
      return match;

  return NULL;
}

/*
 * This clone function, unlike its original rib_lookup_route(), checks
 * if specified route record (prefix/mask -> gate) exists in
 * the whole RIB and has ZEBRA_FLAG_SELECTED set.
 *
 * Return values:
 * -1: error
 * 0: exact match found
 * 1: a match was found with a different gate
 * 2: connected route found
 * 3: no matches found
 */
int
rib_lookup_route_nexthop (struct prefix *p, struct zapi_nexthop *znh)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *nexthop;
  int afi;

  switch (p->family)
    {
      case AF_INET:
        afi = AFI_IP;
        break;
      case AF_INET6:
        afi = AFI_IP6;
        break;
      default:
	assert(0);
    }

  /* Lookup table.  */
  table = vrf_table (afi, SAFI_UNICAST, 0);
  if (! table)
    return ZEBRA_RIB_LOOKUP_ERROR;

  /* Scan the RIB table for exactly matching RIB entry. */
  rn = route_node_lookup (table, p);

  /* No route for this prefix. */
  if (! rn)
    return ZEBRA_RIB_NOTFOUND;

  /* Unlock node. */
  route_unlock_node (rn);

  /* Find out if a "selected" RR for the discovered RIB entry exists ever. */
  for (match = rn->info; match; match = match->next)
  {
    if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
      continue;
    if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
      break;
  }

  /* None such found :( */
  if (!match)
    return ZEBRA_RIB_NOTFOUND;

  if (match->type == ZEBRA_ROUTE_CONNECT)
    return ZEBRA_RIB_FOUND_CONNECTED;
  
  /* Ok, we have a cood candidate, let's check it's nexthop list... */
  for (nexthop = match->nexthop; nexthop; nexthop = nexthop->next)
    if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
    {
      /* We are happy with either direct or recursive hexthop */
      if (zapi_nexthop_match_nexthop(znh, nexthop,
	ZEBRA_NEXTHOP_IPV4|ZEBRA_NEXTHOP_IPV6))
        return ZEBRA_RIB_FOUND_EXACT;
      else
      {
        if (IS_ZEBRA_DEBUG_RIB)
        {
          char gate_buf[INET_ADDRSTRLEN], rgate_buf[INET_ADDRSTRLEN], qgate_buf[INET_ADDRSTRLEN];
          inet_ntop (p->family, &nexthop->gate, gate_buf, INET_ADDRSTRLEN);
          inet_ntop (p->family, &nexthop->rgate, rgate_buf, INET_ADDRSTRLEN);
          inet_ntop (p->family, &znh->gw, qgate_buf, INET_ADDRSTRLEN);
          zlog_debug ("%s: qgate == %s, gate == %s, rgate == %s", __func__, qgate_buf, gate_buf, rgate_buf);
        }
        return ZEBRA_RIB_FOUND_NOGATE;
      }
    }

  return ZEBRA_RIB_NOTFOUND;
}

#define RIB_SYSTEM_ROUTE(R) \
        ((R)->type == ZEBRA_ROUTE_KERNEL || (R)->type == ZEBRA_ROUTE_CONNECT)

/* This function verifies reachability of one given nexthop, which can be
 * numbered or unnumbered, IPv4 or IPv6. The result is unconditionally stored
 * in nexthop->flags field. If the 4th parameter, 'set', is non-zero,
 * nexthop->ifindex will be updated appropriately as well.
 * An existing route map can turn (otherwise active) nexthop into inactive, but
 * not vice versa.
 *
 * The return value is the final value of 'ACTIVE' flag.
 */

static int
nexthop_active_check (struct route_node *rn, struct rib *rib,
		      struct nexthop *nexthop, int set)
{
  struct interface *ifp;
  route_map_result_t ret = RMAP_MATCH;
  extern char *proto_rm[AFI_MAX][ZEBRA_ROUTE_MAX+1];
  struct route_map *rmap;
  int family;
  int try = 0;
  int match = 0;

  family = 0;
  if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFNAME))
    {
      try++;
      ifp = if_lookup_by_name (nexthop->ifname);
      if (ifp && if_is_operative(ifp))
	{
	  if (set)
	    {
	      nexthop->ifindex = ifp->ifindex;
	      SET_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFINDEX);
	      UNSET_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFNAME);
	    }
          match++;
	}
      else
	{
	  if (set)
	    {
	      nexthop->ifindex = 0;
	      UNSET_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFINDEX);
	      SET_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFNAME);
	    }
	}
    }
  else if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFINDEX))
    {
      try++;
      ifp = if_lookup_by_index (nexthop->ifindex);
      if (ifp && if_is_up (ifp)) {
        match++;
      }
    }

#ifdef HAVE_MPLS
  if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_MPLS))
    {
      try++;
      if (mpls_out_segment_find(nexthop->mpls))
	match++;
    }
#endif

  if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV4))
    {
      family = AFI_IP;
      try++;
      if (nexthop_active_route (rib, nexthop, set, rn)) {
        match++;
      }
    }
#ifdef HAVE_IPV6
  else if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IPV6))
    {
      family = AFI_IP6;
      try++;
      if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_IFINDEX))
        {
          if (IN6_IS_ADDR_LINKLOCAL (&nexthop->gate.ipv6))
            {
              ifp = if_lookup_by_index (nexthop->ifindex);
              if (ifp && if_is_operative(ifp)) {
                match++;
              }
            }
          else
            {
              if (nexthop_active_route (rib, nexthop, set, rn)) {
                match++;
              }
            }
        }
      else
        {
          if (nexthop_active_route (rib, nexthop, set, rn)) {
            match++;
          }
        }
    }
#endif /* HAVE_IPV6 */
  else if (CHECK_FLAG (nexthop->type, ZEBRA_NEXTHOP_DROP))
    {
      try++;
      match++;
    }

  try++;
  if (!CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_IGNORE))
    match++;

  if (try && (try == match))
    SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
  else
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);

  if (!CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
    return 0;

  if (RIB_SYSTEM_ROUTE(rib) ||
      (family == AFI_IP && rn->p.family != AF_INET) ||
      (family == AFI_IP6 && rn->p.family != AF_INET6))
    return CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);

  rmap = 0;
  if (rib->type >= 0 && rib->type < ZEBRA_ROUTE_MAX &&
        	proto_rm[family][rib->type])
    rmap = route_map_lookup_by_name (proto_rm[family][rib->type]);
  if (!rmap && proto_rm[family][ZEBRA_ROUTE_MAX])
    rmap = route_map_lookup_by_name (proto_rm[family][ZEBRA_ROUTE_MAX]);
  if (rmap) {
      ret = route_map_apply(rmap, &rn->p, RMAP_ZEBRA, nexthop);
  }

  if (ret == RMAP_DENYMATCH)
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
  return CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
}

/* Iterate over all nexthops of the given RIB entry and refresh their
 * ACTIVE flag. rib->nexthop_active_num is updated accordingly. If any
 * nexthop is found to toggle the ACTIVE flag, the whole rib structure
 * is flagged with ZEBRA_FLAG_CHANGED. The 4th 'set' argument is
 * transparently passed to nexthop_active_check().
 *
 * Return value is the new number of active nexthops.
 */

static int
nexthop_active_update (struct route_node *rn, struct rib *rib, int set)
{
  struct nexthop *nexthop;
  int prev_active, new_active;

  rib->nexthop_active_num = 0;
  UNSET_FLAG (rib->flags, ZEBRA_FLAG_CHANGED);
  UNSET_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE|ZEBRA_FLAG_REJECT);

  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
  {
    /*
     * we want to process all nexthops even IGNORED ones incase
     * a newly ignored nexthop was active, that should trigger
     * a route change.  So nexthop_active_check is responsible
     * for checking IGNORED and handling accordingly
     */
    prev_active = CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
    if ((new_active = nexthop_active_check (rn, rib, nexthop, set)))
      rib->nexthop_active_num++;
    if (prev_active != new_active)
      SET_FLAG (rib->flags, ZEBRA_FLAG_CHANGED);
  }
#ifdef HAVE_MPLS
  if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_CHANGED_MPLS))
    SET_FLAG (rib->flags, ZEBRA_FLAG_CHANGED);
#endif
  SET_FLAG (rib->flags, rib_check_drop(rib));
  return rib->nexthop_active_num;
}



static void
rib_install_kernel (struct route_node *rn, struct rib *rib)
{
  int ret = 0;
  struct nexthop *nexthop;

  switch (PREFIX_FAMILY (&rn->p))
    {
    case AF_INET:
      ret = kernel_add_ipv4 (&rn->p, rib);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      ret = kernel_add_ipv6 (&rn->p, rib);
      break;
#endif /* HAVE_IPV6 */
    }

  /* This condition is never met, if we are using rt_socket.c */
  if (ret < 0)
    {
      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
    }
}

/* Uninstall the route from kernel. */
int
rib_uninstall_kernel (struct route_node *rn, struct rib *rib)
{
  int ret = 0;
  struct nexthop *nexthop;

  switch (PREFIX_FAMILY (&rn->p))
    {
    case AF_INET:
      ret = kernel_delete_ipv4 (&rn->p, rib);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: calling kernel_delete_ipv4 (%p, %p)", __func__, rn, rib);
      ret = kernel_delete_ipv6 (&rn->p, rib);
      break;
#endif /* HAVE_IPV6 */
    }

  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  return ret;
}

/* Uninstall the route from kernel. */
static void
rib_uninstall (struct route_node *rn, struct rib *rib)
{
  if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
    {
      redistribute_delete (&rn->p, rib);
      if (! RIB_SYSTEM_ROUTE (rib))
	rib_uninstall_kernel (rn, rib);
      UNSET_FLAG (rib->flags, ZEBRA_FLAG_SELECTED);
    }
}

static void rib_unlink (struct route_node *, struct rib *);

/* Core function for processing routing information base. */
static void
rib_process (struct route_node *rn)
{
  struct rib *rib;
  struct rib *next;
  struct rib *fib = NULL;
  struct rib *select = NULL;
  struct rib *del = NULL;
  int installed = 0;
  struct nexthop *nexthop = NULL;
  char buf[INET6_ADDRSTRLEN];
  
  assert (rn);
  
  if (IS_ZEBRA_DEBUG_RIB || IS_ZEBRA_DEBUG_RIB_Q)
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);

  for (rib = rn->info; rib; rib = next)
    {
      /* The next pointer is saved, because current pointer
       * may be passed to rib_unlink() in the middle of iteration.
       */
      next = rib->next;
      
      /* Currently installed rib. */
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
        {
          assert (fib == NULL);
          fib = rib;
        }
      
      /* Unlock removed routes, so they'll be freed, bar the FIB entry,
       * which we need to do do further work with below.
       */
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        {
          if (rib != fib)
            {
              if (IS_ZEBRA_DEBUG_RIB)
                zlog_debug ("%s: %s/%d: rn %p, removing rib %p", __func__,
                  buf, rn->p.prefixlen, rn, rib);
                rib_unlink (rn, rib);
            }
          else
            del = rib;
          
          continue;
        }
      
      /* Skip unreachable nexthop. */
      if (! nexthop_active_update (rn, rib, 0))
        continue;

      /* Infinit distance. */
      if (rib->distance == DISTANCE_INFINITY)
        continue;

      /* Newly selected rib, the common case. */
      if (!select)
        {
          select = rib;
          continue;
        }
      
      /* filter route selection in following order:
       * - connected beats other types
       * - lower distance beats higher
       * - lower metric beats higher for equal distance
       * - last, hence oldest, route wins tie break.
       */
      
      /* Connected routes. Pick the last connected
       * route of the set of lowest metric connected routes.
       */
      if (rib->type == ZEBRA_ROUTE_CONNECT)
        {
          if (select->type != ZEBRA_ROUTE_CONNECT
              || rib->metric <= select->metric)
            select = rib;
          continue;
        }
      else if (select->type == ZEBRA_ROUTE_CONNECT)
        continue;
      
      /* higher distance loses */
      if (rib->distance > select->distance)
        continue;
      
      /* lower wins */
      if (rib->distance < select->distance)
        {
          select = rib;
          continue;
        }
      
      /* metric tie-breaks equal distance */
      if (rib->metric <= select->metric)
        select = rib;
    } /* for (rib = rn->info; rib; rib = next) */

  /* After the cycle is finished, the following pointers will be set:
   * select --- the winner RIB entry, if any was found, otherwise NULL
   * fib    --- the SELECTED RIB entry, if any, otherwise NULL
   * del    --- equal to fib, if fib is queued for deletion, NULL otherwise
   * rib    --- NULL
   */

  /* Same RIB entry is selected. Update FIB and finish. */
  if (select && select == fib)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: %s/%d: Updating existing route, select %p, fib %p",
                     __func__, buf, rn->p.prefixlen, select, fib);
      if (CHECK_FLAG (select->flags, ZEBRA_FLAG_CHANGED))
        {
#ifdef HAVE_MPLS
	  if (!CHECK_FLAG (select->flags, ZEBRA_FLAG_CHANGED_MPLS))
#endif
	    redistribute_delete (&rn->p, select);

          if (! RIB_SYSTEM_ROUTE (select))
            rib_uninstall_kernel (rn, select);

          /* Set real nexthop. */
          nexthop_active_update (rn, select, 1);
  
          if (! RIB_SYSTEM_ROUTE (select))
            rib_install_kernel (rn, select);

#ifdef HAVE_MPLS
	  if (!CHECK_FLAG (select->flags, ZEBRA_FLAG_CHANGED_MPLS))
#endif
	    redistribute_add (&rn->p, select);
        }
      else if (! RIB_SYSTEM_ROUTE (select))
        {
          /* Housekeeping code to deal with 
             race conditions in kernel with linux
             netlink reporting interface up before IPv4 or IPv6 protocol
             is ready to add routes.
             This makes sure the routes are IN the kernel.
           */

          for (nexthop = select->nexthop; nexthop; nexthop = nexthop->next)
            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
            {
              installed = 1;
              break;
            }
          if (! installed) 
            rib_install_kernel (rn, select);
        }
#ifdef HAVE_MPLS
      UNSET_FLAG (select->flags, ZEBRA_FLAG_CHANGED_MPLS);
#endif
      goto end;
    }

  /* At this point we either haven't found the best RIB entry or it is
   * different from what we currently intend to flag with SELECTED. In both
   * cases, if a RIB block is present in FIB, it should be withdrawn.
   */
  if (fib)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: %s/%d: Removing existing route, fib %p", __func__,
          buf, rn->p.prefixlen, fib);
      redistribute_delete (&rn->p, fib);
      if (! RIB_SYSTEM_ROUTE (fib))
	rib_uninstall_kernel (rn, fib);
      UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);

      /* Set real nexthop. */
      nexthop_active_update (rn, fib, 1);
    }

  /* Regardless of some RIB entry being SELECTED or not before, now we can
   * tell, that if a new winner exists, FIB is still not updated with this
   * data, but ready to be.
   */
  if (select)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: %s/%d: Adding route, select %p", __func__, buf,
          rn->p.prefixlen, select);
      /* Set real nexthop. */
      nexthop_active_update (rn, select, 1);

      if (! RIB_SYSTEM_ROUTE (select))
        rib_install_kernel (rn, select);
      SET_FLAG (select->flags, ZEBRA_FLAG_SELECTED);
#ifdef HAVE_MPLS
      if (!CHECK_FLAG (select->flags, ZEBRA_FLAG_CHANGED_MPLS))
#endif
        redistribute_add (&rn->p, select);
#ifdef HAVE_MPLS
      UNSET_FLAG (select->flags, ZEBRA_FLAG_CHANGED_MPLS);
#endif
    }

  /* FIB route was removed, should be deleted */
  if (del)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: %s/%d: Deleting fib %p, rn %p", __func__, buf,
          rn->p.prefixlen, del, rn);
      rib_unlink (rn, del);
    }

end:
  if (IS_ZEBRA_DEBUG_RIB_Q)
    zlog_debug ("%s: %s/%d: rn %p dequeued", __func__, buf, rn->p.prefixlen, rn);
}

/* Take a list of route_node structs and return 1, if there was a record picked from
 * it and processed by rib_process(). Don't process more, than one RN record; operate
 * only in the specified sub-queue.
 */
unsigned int
process_subq (struct list * subq, u_char qindex)
{
  struct listnode *lnode;
  struct route_node *rnode;
  if (!(lnode = listhead (subq)))
    return 0;
  rnode = listgetdata (lnode);
  rib_process (rnode);
  if (rnode->info) /* The first RIB record is holding the flags bitmask. */
    UNSET_FLAG (((struct rib *)rnode->info)->rn_status, RIB_ROUTE_QUEUED(qindex));
  route_unlock_node (rnode);
  list_delete_node (subq, lnode);
  return 1;
}

/* Dispatch the meta queue by picking, processing and unlocking the next RN from
 * a non-empty sub-queue with lowest priority. wq is equal to zebra->ribq and data
 * is pointed to the meta queue structure.
 */
static wq_item_status
meta_queue_process (struct work_queue *dummy, void *data)
{
  struct meta_queue * mq = data;
  u_char i;
  for (i = 0; i < MQ_SIZE; i++)
    if (process_subq (mq->subq[i], i))
    {
      mq->size--;
      break;
    }
  return mq->size ? WQ_REQUEUE : WQ_SUCCESS;
}

/* Look into the RN and queue it into one or more priority queues, increasing the size
 * for each data push done.
 */
void rib_meta_queue_add (struct meta_queue *mq, struct route_node *rn)
{
  u_char qindex;
  struct rib *rib;
  char buf[INET6_ADDRSTRLEN];
  if (IS_ZEBRA_DEBUG_RIB_Q)
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
  for (rib = rn->info; rib; rib = rib->next)
  {
    switch (rib->type)
    {
      case ZEBRA_ROUTE_KERNEL:
      case ZEBRA_ROUTE_CONNECT:
        qindex = 0;
        break;
      case ZEBRA_ROUTE_STATIC:
        qindex = 1;
        break;
      case ZEBRA_ROUTE_RIP:
      case ZEBRA_ROUTE_RIPNG:
      case ZEBRA_ROUTE_OSPF:
      case ZEBRA_ROUTE_OSPF6:
      case ZEBRA_ROUTE_ISIS:
        qindex = 2;
        break;
      case ZEBRA_ROUTE_BGP:
        qindex = 3;
        break;
      default:
        qindex = 4;
        break;
    }
    /* Invariant: at this point we always have rn->info set. */
    if (CHECK_FLAG (((struct rib *)rn->info)->rn_status, RIB_ROUTE_QUEUED(qindex)))
    {
      if (IS_ZEBRA_DEBUG_RIB_Q)
        zlog_debug ("%s: %s/%d: rn %p is already queued in sub-queue %u", __func__, buf, rn->p.prefixlen, rn, qindex);
      continue;
    }
    SET_FLAG (((struct rib *)rn->info)->rn_status, RIB_ROUTE_QUEUED(qindex));
    listnode_add (mq->subq[qindex], rn);
    route_lock_node (rn);
    mq->size++;
    if (IS_ZEBRA_DEBUG_RIB_Q)
      zlog_debug ("%s: %s/%d: queued rn %p into sub-queue %u", __func__, buf, rn->p.prefixlen, rn, qindex);
  }
}

/* Add route_node to work queue and schedule processing */
void
rib_queue_add (struct zebra_t *zebra, struct route_node *rn)
{
  char buf[INET_ADDRSTRLEN];
  assert (zebra && rn);
  
  if (IS_ZEBRA_DEBUG_RIB_Q)
    inet_ntop (AF_INET, &rn->p.u.prefix, buf, INET_ADDRSTRLEN);

  /* Pointless to queue a route_node with no RIB entries to add or remove */
  if (!rn->info)
    {
      zlog_debug ("%s: called for route_node (%p, %d) with no ribs",
                  __func__, rn, rn->lock);
      zlog_backtrace(LOG_DEBUG);
      return;
    }

  if (IS_ZEBRA_DEBUG_RIB_Q)
    zlog_info ("%s: %s/%d: work queue added", __func__, buf, rn->p.prefixlen);

  assert (zebra);

  if (zebra->ribq == NULL)
    {
      zlog_err ("%s: work_queue does not exist!", __func__);
      return;
    }

  /* The RIB queue should normally be either empty or holding the only work_queue_item
   * element. In the latter case this element would hold a pointer to the meta queue
   * structure, which must be used to actually queue the route nodes to process. So
   * create the MQ holder, if necessary, then push the work into it in any case.
   * This semantics was introduced after 0.99.9 release.
   */

  /* Should I invent work_queue_empty() and use it, or it's Ok to do as follows? */
  if (!zebra->ribq->items->count)
    work_queue_add (zebra->ribq, zebra->mq);

  rib_meta_queue_add (zebra->mq, rn);

  if (IS_ZEBRA_DEBUG_RIB_Q)
    zlog_debug ("%s: %s/%d: rn %p queued", __func__, buf, rn->p.prefixlen, rn);

  return;
}

/* Create new meta queue. A destructor function doesn't seem to be necessary here. */
struct meta_queue *
meta_queue_new ()
{
  struct meta_queue *new;
  unsigned i, failed = 0;

  if ((new = XCALLOC (MTYPE_WORK_QUEUE, sizeof (struct meta_queue))) == NULL)
    return NULL;
  for (i = 0; i < MQ_SIZE; i++)
    if ((new->subq[i] = list_new ()) == NULL)
      failed = 1;
  if (failed)
  {
    for (i = 0; i < MQ_SIZE; i++)
      if (new->subq[i])
        list_delete (new->subq[i]);
    XFREE (MTYPE_WORK_QUEUE, new);
    return NULL;
  }
  new->size = 0;
  return new;
}

/* initialise zebra rib work queue */
static void
rib_queue_init (struct zebra_t *zebra)
{
  assert (zebra);
  
  if (! (zebra->ribq = work_queue_new (zebra->master, 
                                       "route_node processing")))
    {
      zlog_err ("%s: could not initialise work queue!", __func__);
      return;
    }

  /* fill in the work queue spec */
  zebra->ribq->spec.workfunc = &meta_queue_process;
  zebra->ribq->spec.errorfunc = NULL;
  /* XXX: TODO: These should be runtime configurable via vty */
  zebra->ribq->spec.max_retries = 3;
  zebra->ribq->spec.hold = rib_process_hold_time;
  
  if (!(zebra->mq = meta_queue_new ()))
  {
    zlog_err ("%s: could not initialise meta queue!", __func__);
    return;
  }
  return;
}

/* RIB updates are processed via a queue of pointers to route_nodes.
 *
 * The queue length is bounded by the maximal size of the routing table,
 * as a route_node will not be requeued, if already queued.
 *
 * RIBs are submitted via rib_addnode or rib_delnode which set minimal
 * state, or static_install_ipv{4,6} (when an existing RIB is updated)
 * and then submit route_node to queue for best-path selection later.
 * Order of add/delete state changes are preserved for any given RIB.
 *
 * Deleted RIBs are reaped during best-path selection.
 *
 * rib_addnode
 * |-> rib_link or unset RIB_ENTRY_REMOVE        |->Update kernel with
 *       |-------->|                             |  best RIB, if required
 *                 |                             |
 * static_install->|->rib_addqueue...... -> rib_process
 *                 |                             |
 *       |-------->|                             |-> rib_unlink
 * |-> set RIB_ENTRY_REMOVE                           |
 * rib_delnode                                  (RIB freed)
 *
 *
 * Queueing state for a route_node is kept in the head RIB entry, this
 * state must be preserved as and when the head RIB entry of a
 * route_node is changed by rib_unlink / rib_link. A small complication,
 * but saves having to allocate a dedicated object for this.
 * 
 * Refcounting (aka "locking" throughout the GNU Zebra and Quagga code):
 *
 * - route_nodes: refcounted by:
 *   - RIBs attached to route_node:
 *     - managed by: rib_link/unlink
 *   - route_node processing queue
 *     - managed by: rib_addqueue, rib_process.
 *
 */
 
/* Add RIB to head of the route node. */
static void
rib_link (struct route_node *rn, struct rib *rib)
{
  struct rib *head;
  char buf[INET6_ADDRSTRLEN];
  
  assert (rib && rn);
  
  route_lock_node (rn); /* rn route table reference */

  if (IS_ZEBRA_DEBUG_RIB)
  {
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
    zlog_debug ("%s: %s/%d: rn %p, rib %p", __func__,
      buf, rn->p.prefixlen, rn, rib);
  }

  head = rn->info;
  if (head)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: %s/%d: new head, rn_status copied over", __func__,
          buf, rn->p.prefixlen);
      head->prev = rib;
      /* Transfer the rn status flags to the new head RIB */
      rib->rn_status = head->rn_status;
    }
  rib->next = head;
  rn->info = rib;
  rib_queue_add (&zebrad, rn);
}

static void
rib_addnode (struct route_node *rn, struct rib *rib)
{
  /* RIB node has been un-removed before route-node is processed. 
   * route_node must hence already be on the queue for processing.. 
   */
  if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
    {
      if (IS_ZEBRA_DEBUG_RIB)
      {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
        zlog_debug ("%s: %s/%d: rn %p, un-removed rib %p",
                    __func__, buf, rn->p.prefixlen, rn, rib);
      }
      UNSET_FLAG (rib->status, RIB_ENTRY_REMOVED);
      return;
    }
  rib_link (rn, rib);
}

static void
rib_unlink (struct route_node *rn, struct rib *rib)
{
  struct nexthop *nexthop, *next;
  char buf[INET6_ADDRSTRLEN];

  assert (rn && rib);

  if (IS_ZEBRA_DEBUG_RIB)
  {
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
    zlog_debug ("%s: %s/%d: rn %p, rib %p",
                __func__, buf, rn->p.prefixlen, rn, rib);
  }

  if (rib->next)
    rib->next->prev = rib->prev;

  if (rib->prev)
    rib->prev->next = rib->next;
  else
    {
      rn->info = rib->next;
      
      if (rn->info)
        {
          if (IS_ZEBRA_DEBUG_RIB)
            zlog_debug ("%s: %s/%d: rn %p, rib %p, new head copy",
                        __func__, buf, rn->p.prefixlen, rn, rib);
          rib->next->rn_status = rib->rn_status;
        }
    }

  /* free RIB and nexthops */
  for (nexthop = rib->nexthop; nexthop; nexthop = next)
    {
      next = nexthop->next;
      nexthop_free (nexthop);
    }
  XFREE (MTYPE_RIB, rib);

  route_unlock_node (rn); /* rn route table reference */
}

static void
rib_delnode (struct route_node *rn, struct rib *rib)
{
  if (IS_ZEBRA_DEBUG_RIB)
  {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
    zlog_debug ("%s: %s/%d: rn %p, rib %p, removing", __func__,
      buf, rn->p.prefixlen, rn, rib);
  }
  SET_FLAG (rib->status, RIB_ENTRY_REMOVED);
  rib_queue_add (&zebrad, rn);
}

int
rib_find_nexthop2 (int owner, struct rib *rib_in, struct nexthop *nh_in,
  struct rib **rib_out, struct nexthop **nh_out)
{
  struct nexthop *nh = NULL;
  struct rib *rib = NULL;

  for (rib = rib_in; rib; rib = rib->next)
    {
      if ((owner >= 0) && (rib->type != owner))
        continue;

      for (nh = rib->nexthop; nh; nh = nh->next)
        {
          if (nexthop_match(nh_in, nh,
	      (ZEBRA_NEXTHOP_ALL & (~ZEBRA_NEXTHOP_MPLS))))
            {
	      *rib_out = rib;
	      *nh_out = nh;
	      return 0;
            }
        }
    }
  return 1;
}

int
rib_find_nexthop (int owner, struct prefix *p_in, struct nexthop *nh_in,
  struct route_node **rn_out, struct rib **rib_out, struct nexthop **nh_out)
{
  struct route_table *table = NULL;
  struct route_node *rn = NULL;

  *rn_out = NULL;
  *rib_out = NULL;
  *nh_out = NULL;

  switch (p_in->family)
    {
      case AF_INET:
        table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
        break;
      case AF_INET6:
        table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
        break;
      default:
        assert(0);
    }

  if ((!table) || (!(rn = route_node_lookup (table, p_in))))
    return 1;
 
  if (!rib_find_nexthop2(owner, rn->info, nh_in, rib_out, nh_out))
    {
      *rn_out = rn;
      return 0;
    }
  route_unlock_node (rn);
  return 1;
}

int
rib_add_route (int type, int flags, struct prefix *p, 
	       struct zapi_nexthop *nh, u_int32_t vrf_id,
	       u_int32_t metric, u_char distance)
{
  struct rib *rib;
  struct rib *same = NULL;
  struct route_table *table;
  struct route_node *rn;
  struct nexthop *nexthop;
  int afi;

  switch (p->family)
    {
      case AF_INET:
        afi = AFI_IP;
        break;
      case AF_INET6:
        afi = AFI_IP6;
        break;
      default:
        assert(0);
    }

  /* Lookup table.  */
  table = vrf_table (afi, SAFI_UNICAST, 0);
  if (! table)
    return 0;

  /* Make it sure prefixlen is applied to the prefix. */
  apply_mask (p);

  /* Set default distance by route type. */
  if (distance == 0)
    {
      distance = route_info[type].distance;

      /* iBGP distance is 200. */
      if (type == ZEBRA_ROUTE_BGP && CHECK_FLAG (flags, ZEBRA_FLAG_IBGP))
	distance = 200;
    }

#ifdef HAVE_IPV6
  /* Filter bogus route. */
  if (afi == AFI_IP6 &&
      rib_bogus_ipv6 (type, (struct prefix_ipv6*)p, &nh->gw.ipv6,
                      nh->intf.index, 0))
    return 0;
#endif

  /* Lookup route node.*/
  rn = route_node_get (table, p);

  /* If same type of route are installed, treat it as a implicit
     withdraw. */
  for (rib = rn->info; rib; rib = rib->next)
    {
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        continue;
      
      if (rib->type != type)
	continue;
      if (rib->type != ZEBRA_ROUTE_CONNECT)
        {
          same = rib;
          break;
        }
      /* Duplicate connected route comes in. */
      else if ((nexthop = rib->nexthop) &&
	       zapi_nexthop_match_nexthop(nh, nexthop,
               ZEBRA_NEXTHOP_IPV4|ZEBRA_NEXTHOP_IPV6) &&
	       !CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
	{
	  rib->refcnt++;
	  return 0 ;
	}
    }

  /* Allocate new rib structure. */
  rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
  rib->type = type;
  rib->distance = distance;
  rib->flags = flags;
  rib->metric = metric;
  rib->table = vrf_id;
  rib->nexthop_num = 0;
  rib->uptime = time (NULL);

  /* Nexthop settings. */
  nexthop_zapi_nexthop_add(rib, nh);

  /* If this route is kernel route, set FIB flag to the route. */
  if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
      {
        if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_IGNORE))
	  continue;
        SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
      }

  /* Link new rib to node.*/
  if (IS_ZEBRA_DEBUG_RIB)
    zlog_debug ("%s: calling rib_addnode (%p, %p)", __func__, rn, rib);
  rib_addnode (rn, rib);
  
  /* Free implicit route.*/
  if (same)
  {
    if (IS_ZEBRA_DEBUG_RIB)
      zlog_debug ("%s: calling rib_delnode (%p, %p)", __func__, rn, rib);
    rib_delnode (rn, same);
  }
  
  route_unlock_node (rn);
  return 0;
}

/* This function dumps the contents of a given RIB entry into
 * standard debug log. Calling function name and IP prefix in
 * question are passed as 1st and 2nd arguments.
 */

void rib_dump (const char * func, const struct prefix_ipv4 * p, const struct rib * rib)
{
  char straddr1[INET_ADDRSTRLEN], straddr2[INET_ADDRSTRLEN];
  struct nexthop *nexthop;

  inet_ntop (AF_INET, &p->prefix, straddr1, INET_ADDRSTRLEN);
  zlog_debug ("%s: dumping RIB entry %p for %s/%d", func, rib, straddr1, p->prefixlen);
  zlog_debug
  (
    "%s: refcnt == %lu, uptime == %u, type == %u, table == %d",
    func,
    rib->refcnt,
    rib->uptime,
    rib->type,
    rib->table
  );
  zlog_debug
  (
    "%s: metric == %u, distance == %u, flags == %u, status == %u",
    func,
    rib->metric,
    rib->distance,
    rib->flags,
    rib->status
  );
  zlog_debug
  (
    "%s: nexthop_num == %u, nexthop_active_num == %u, nexthop_fib_num == %u",
    func,
    rib->nexthop_num,
    rib->nexthop_active_num,
    rib->nexthop_fib_num
  );
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
  {
    inet_ntop (AF_INET, &nexthop->gate.ipv4.s_addr, straddr1, INET_ADDRSTRLEN);
    inet_ntop (AF_INET, &nexthop->rgate.ipv4.s_addr, straddr2, INET_ADDRSTRLEN);
    zlog_debug
    (
      "%s: NH %s (%s) with flags %s%s%s",
      func,
      straddr1,
      straddr2,
      (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE) ? "ACTIVE " : ""),
      (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? "FIB " : ""),
      (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE) ? "RECURSIVE" : "")
    );
  }
  zlog_debug ("%s: dump complete", func);
}

/* This is an exported helper to rtm_read() to dump the strange
 * RIB entry found by rib_lookup_route_nexthop()
 */

void rib_lookup_and_dump (struct prefix_ipv4 * p)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  char prefix_buf[INET_ADDRSTRLEN];

  /* Lookup table.  */
  table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
  if (! table)
  {
    zlog_err ("%s: vrf_table() returned NULL", __func__);
    return;
  }

  inet_ntop (AF_INET, &p->prefix.s_addr, prefix_buf, INET_ADDRSTRLEN);
  /* Scan the RIB table for exactly matching RIB entry. */
  rn = route_node_lookup (table, (struct prefix *) p);

  /* No route for this prefix. */
  if (! rn)
  {
    zlog_debug ("%s: lookup failed for %s/%d", __func__, prefix_buf, p->prefixlen);
    return;
  }

  /* Unlock node. */
  route_unlock_node (rn);

  /* let's go */
  for (rib = rn->info; rib; rib = rib->next)
  {
    zlog_debug
    (
      "%s: rn %p, rib %p: %s, %s",
      __func__,
      rn,
      rib,
      (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED) ? "removed" : "NOT removed"),
      (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED) ? "selected" : "NOT selected")
    );
    rib_dump (__func__, p, rib);
  }
}

/* Check if requested address assignment will fail due to another
 * route being installed by zebra in FIB already. Take necessary
 * actions, if needed: remove such a route from FIB and deSELECT
 * corresponding RIB entry. Then put affected RN into RIBQ head.
 */
void rib_lookup_and_pushup (struct prefix_ipv4 * p)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  unsigned changed = 0;

  if (NULL == (table = vrf_table (AFI_IP, SAFI_UNICAST, 0)))
  {
    zlog_err ("%s: vrf_table() returned NULL", __func__);
    return;
  }

  /* No matches would be the simplest case. */
  if (NULL == (rn = route_node_lookup (table, (struct prefix *) p)))
    return;

  /* Unlock node. */
  route_unlock_node (rn);

  /* Check all RIB entries. In case any changes have to be done, requeue
   * the RN into RIBQ head. If the routing message about the new connected
   * route (generated by the IP address we are going to assign very soon)
   * comes before the RIBQ is processed, the new RIB entry will join
   * RIBQ record already on head. This is necessary for proper revalidation
   * of the rest of the RIB.
   */
  for (rib = rn->info; rib; rib = rib->next)
  {
    if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED) &&
      ! RIB_SYSTEM_ROUTE (rib))
    {
      changed = 1;
      if (IS_ZEBRA_DEBUG_RIB)
      {
        char buf[INET_ADDRSTRLEN];
        inet_ntop (rn->p.family, &p->prefix, buf, INET_ADDRSTRLEN);
        zlog_debug ("%s: freeing way for connected prefix %s/%d", __func__, buf, p->prefixlen);
        rib_dump (__func__, (struct prefix_ipv4 *)&rn->p, rib);
      }
      rib_uninstall (rn, rib);
    }
  }
  if (changed)
    rib_queue_add (&zebrad, rn);
}

int
rib_add_multipath (struct prefix *p, struct rib *rib)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *same;
  struct nexthop *nexthop;
  int afi;

  switch (p->family)
    {
      case AF_INET:
        afi = AFI_IP;
        break;
      case AF_INET6:
        afi = AFI_IP6;
        break;
      default:
        assert(0);
    }

  
  /* Lookup table.  */
  table = vrf_table (afi, SAFI_UNICAST, 0);
  if (! table)
    return 0;
  /* Make it sure prefixlen is applied to the prefix. */
  apply_mask (p);

  /* Set default distance by route type. */
  if (rib->distance == 0)
    {
      rib->distance = route_info[rib->type].distance;

      /* iBGP distance is 200. */
      if (rib->type == ZEBRA_ROUTE_BGP 
	  && CHECK_FLAG (rib->flags, ZEBRA_FLAG_IBGP))
	rib->distance = 200;
    }

  /* Lookup route node.*/
  rn = route_node_get (table, p);

  /* If same type of route are installed, treat it as a implicit
     withdraw. */
  for (same = rn->info; same; same = same->next)
    {
      if (CHECK_FLAG (same->status, RIB_ENTRY_REMOVED))
        continue;
      
      if (same->type == rib->type && same->table == rib->table
	  && same->type != ZEBRA_ROUTE_CONNECT)
        break;
    }
  
  /* If this route is kernel route, set FIB flag to the route. */
  if (rib->type == ZEBRA_ROUTE_KERNEL || rib->type == ZEBRA_ROUTE_CONNECT)
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
      {
        if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_IGNORE))
	  continue;
        SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
      }

  /* Link new rib to node.*/
  rib_addnode (rn, rib);
  if (IS_ZEBRA_DEBUG_RIB)
  {
    zlog_debug ("%s: called rib_addnode (%p, %p) on new RIB entry",
      __func__, rn, rib);
    rib_dump (__func__, p, rib);
  }

  /* Free implicit route.*/
  if (same)
  {
    if (IS_ZEBRA_DEBUG_RIB)
    {
      zlog_debug ("%s: calling rib_delnode (%p, %p) on existing RIB entry",
        __func__, rn, same);
      rib_dump (__func__, p, same);
    }
    rib_delnode (rn, same);
  }
  
  route_unlock_node (rn);
  return 0;
}

int
rib_delete_route (int type, int flags, struct prefix *p,
                  struct zapi_nexthop *nh, u_int32_t vrf_id)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct rib *fib = NULL;
  struct rib *same = NULL;
  char prefix_str[BUFSIZ];
  int afi;

  switch (p->family)
    {
      case AF_INET:
        afi = AFI_IP;
        break;
      case AF_INET6:
        afi = AFI_IP6;
        break;
      default:
        assert(0);
    }

  /* Lookup table.  */
  table = vrf_table (afi, SAFI_UNICAST, 0);
  if (! table)
    return 0;

  /* Apply mask. */
  apply_mask (p);

  if (IS_ZEBRA_DEBUG_KERNEL)
    {
      inet_ntop (p->family, &p->u.prefix, prefix_str, BUFSIZ),
      snprintf(&prefix_str[strlen(prefix_str)], BUFSIZ - strlen(prefix_str),
               "/%d", p->prefixlen);
      zapi_nexthop_str(nh, &prefix_str[strlen(prefix_str)],
                         BUFSIZ - strlen(prefix_str));

      zlog_debug ("rib_delete_route(): route delete %s", prefix_str);
    }

  /* Lookup route node. */
  rn = route_node_lookup (table, p);
  if (! rn)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("route %s doesn't exist in rib", prefix_str);
      return ZEBRA_ERR_RTNOEXIST;
    }

  /* Lookup same type route. */
  for (rib = rn->info; rib; rib = rib->next)
    {
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        continue;

      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	fib = rib;

      if (rib->type != type)
	continue;

      /* Make sure that the route found matched */
      if (zapi_nexthop_match_nexthop(nh, rib->nexthop, ZEBRA_NEXTHOP_ALL))
        {
          if (rib->type == ZEBRA_ROUTE_CONNECT)
	    {
	      if (rib->refcnt)
	        {
	          rib->refcnt--;
	          route_unlock_node (rn);
	          route_unlock_node (rn);
	          return 0;
	        }
	      same = rib;
	      break;
	    }
          else
            {
	      same = rib;
	      break;
	    }
        }
    }

  /* If same type of route can't be found and this message is from kernel. */
  if (! same)
    {
      if (fib && type == ZEBRA_ROUTE_KERNEL)
	{
          struct nexthop *nexthop = NULL;
	  /* Unset flags. */
	  for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
	    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

	  UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);
	}
      else
	{
	  if (IS_ZEBRA_DEBUG_KERNEL)
	    zlog_debug ("route %s type %d doesn't exist in rib",
                        prefix_str, type);
	  route_unlock_node (rn);
	  return ZEBRA_ERR_RTNOEXIST;
	}
    }
  
  if (same)
    rib_delnode (rn, same);
  
  route_unlock_node (rn);
  return 0;
}

static int
static_route_compare(struct static_route *a, struct static_route *b, int mask)
{
  int both = (a->nh.type & b->nh.type) & mask;
  int ret = 0;

  if (a->distance < b->distance)
    return -1;

  if (a->distance > b->distance)
    return 1;

  if (CHECK_FLAG (both, ZEBRA_NEXTHOP_IPV4))
    {
      ret = IPV4_ADDR_CMP(&a->nh.gw.ipv4, &b->nh.gw.ipv4);
      if (ret)
	return ret;
    }
  else if (CHECK_FLAG (both, ZEBRA_NEXTHOP_IPV6))
    {
      ret = IPV6_ADDR_CMP(&a->nh.gw.ipv6, &b->nh.gw.ipv6);
      if (ret)
	return ret;
    }

  if (CHECK_FLAG (both, ZEBRA_NEXTHOP_IFNAME))
    {
      ret = strncmp(a->nh.intf.name, b->nh.intf.name, IFNAMSIZ);
      if (ret)
	return ret;
    }
  else if (CHECK_FLAG (both, ZEBRA_NEXTHOP_IFINDEX))
    {
      if (a->nh.intf.index < b->nh.intf.index)
        return -1;
      if (a->nh.intf.index > b->nh.intf.index)
        return 1;
    }
#ifdef HAVE_MPLS
  if (CHECK_FLAG (both, ZEBRA_NEXTHOP_MPLS))
    {
      int aos = mpls_out_segment_find_index_by_nexthop(&a->nh);
      int bos = mpls_out_segment_find_index_by_nexthop(&b->nh);
      if (aos < bos)
        return -1;
      if (aos > bos)
        return 1;
    }
#endif

  return 0;
}

/* Install static route into rib. */
static void
static_install_route (struct prefix *p, struct zapi_nexthop *nexthop, int distance)
{
  struct rib *rib;
  struct route_node *rn;
  struct route_table *table;
  int new = 0;
  int afi;

  switch (p->family)
    {
      case AF_INET:
        afi = AFI_IP;
        break;
      case AF_INET6:
        afi = AFI_IP6;
        break;
      default:
        assert(0);
    }
    
  /* Lookup table.  */
  table = vrf_table (afi, SAFI_UNICAST, 0);
  if (! table)
    return;

  /* Lookup existing route */
  rn = route_node_get (table, p);
  for (rib = rn->info; rib; rib = rib->next)
    {
       if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
         continue;
        
       if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == distance)
         break;
    }

  if (!rib)
    {
      new = 1;

      /* This is new static route. */
      rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
      
      rib->type = ZEBRA_ROUTE_STATIC;
      rib->distance = distance;
      rib->metric = 0;
      rib->nexthop_num = 0;
    }
  else
    {
      /* Same distance static route is there.  Update it with new
         nexthop. */
      route_unlock_node (rn);
    }

  nexthop_zapi_nexthop_add(rib, nexthop);

  if (new)
    {
      /* Link this rib to the tree. */
      rib_addnode (rn, rib);
    }
  else
    {
      rib_queue_add (&zebrad, rn);
    }
}

/* Uninstall static route from RIB. */
static void
static_uninstall_route (struct prefix *p, struct zapi_nexthop *znexthop, int distance)
{
  struct route_node *rn;
  struct rib *rib;
  struct nexthop *nexthop;
  struct route_table *table;
  int afi;

  switch (p->family)
    {
      case AF_INET:
        afi = AFI_IP;
        break;
      case AF_INET6:
        afi = AFI_IP6;
        break;
      default:
        assert(0);
    }

  /* Lookup table.  */
  table = vrf_table (afi, SAFI_UNICAST, 0);
  if (! table)
    return;
  
  /* Lookup existing route with type and distance. */
  rn = route_node_lookup (table, p);
  if (! rn)
    return;

  for (rib = rn->info; rib; rib = rib->next)
    {
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        continue;

      if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == distance)
        break;
    }

  if (! rib)
    {
      route_unlock_node (rn);
      return;
    }

  /* Lookup nexthop. */
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    if (zapi_nexthop_match_nexthop (znexthop, nexthop, ZEBRA_NEXTHOP_ALL))
      break;

  /* Can't find nexthop. */
  if (! nexthop)
    {
      route_unlock_node (rn);
      return;
    }
  
  /* Check nexthop. */
  if (rib->nexthop_num == 1)
    rib_delnode (rn, rib);
  else
    {
      if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
        rib_uninstall (rn, rib);
      nexthop_delete (rib, nexthop);
      nexthop_free (nexthop);
      rib_queue_add (&zebrad, rn);
    }
  /* Unlock node. */
  route_unlock_node (rn);
}

/* Add static route into static route configuration. */
int
static_add_route (struct prefix *p, struct zapi_nexthop *nexthop,
		  u_char distance, u_int32_t vrf_id)
{
  struct route_node *rn;
  struct static_route *si;
  struct static_route *pp;
  struct static_route *cp;
  struct static_route *update = NULL;
  struct route_table *stable;
  int afi;

  switch (p->family)
    {
      case AF_INET:
        afi = AFI_IP;
        break;
      case AF_INET6:
        afi = AFI_IP6;
        break;
      default:
        assert(0);
    }

  /* Lookup table.  */
  stable = vrf_static_table (afi, SAFI_UNICAST, vrf_id);
  if (! stable)
    return -1;
  
  /* Lookup static route prefix. */
  rn = route_node_get (stable, p);

  /* Do nothing if there is a same static route.  */
  for (si = rn->info; si; si = si->next)
    if (zapi_nexthop_match_static_route(distance, nexthop, si))
      {
	route_unlock_node (rn);
	return 0;
      }
    else if (afi == AFI_IP)
      update = si;

  /* Distance or nexthop changed.  */
  if (update)
    static_delete_route (p, nexthop, update->distance, vrf_id);

  /* Make new static route structure. */
  si = XMALLOC (MTYPE_STATIC_ROUTE, sizeof (struct static_route));
  memset (si, 0, sizeof (struct static_route));

  si->distance = distance;
  memcpy(&si->nh, nexthop, sizeof(struct zapi_nexthop));

  /* Add new static route information to the tree with sort by
     distance value and gateway address. */
  for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next)
    {
      int cmp = static_route_compare(si, cp, ZEBRA_NEXTHOP_ALL);
      if (cmp < 0)
	break;
      if (cmp > 0)
	continue;
    }

  /* Make linked list. */
  if (pp)
    pp->next = si;
  else
    rn->info = si;
  if (cp)
    cp->prev = si;
  si->prev = pp;
  si->next = cp;

  /* Install into rib. */
  static_install_route (p, nexthop, distance);

  return 1;
}

/* Delete static route from static route configuration. */
int
static_delete_route (struct prefix *p, struct zapi_nexthop *nexthop,
		     u_char distance, u_int32_t vrf_id)
{
  struct route_node *rn;
  struct static_route *si;
  struct route_table *stable;
  int afi;

  switch (p->family)
    {
      case AF_INET:
        afi = AFI_IP;
        break;
      case AF_INET6:
        afi = AFI_IP6;
        break;
      default:
        assert(0);
    }

  /* Lookup table.  */
  stable = vrf_static_table (afi, SAFI_UNICAST, vrf_id);
  if (! stable)
    return -1;

  /* Lookup static route prefix. */
  rn = route_node_lookup (stable, p);
  if (! rn)
    return 0;

  /* Find same static route is the tree */
  for (si = rn->info; si; si = si->next)
    if (zapi_nexthop_match_static_route(distance, nexthop, si))
      break;

  /* Can't find static route. */
  if (! si)
    {
      route_unlock_node (rn);
      return 0;
    }

  /* Install into rib. */
  static_uninstall_route (p, nexthop, distance);

  /* Unlink static route from linked list. */
  if (si->prev)
    si->prev->next = si->next;
  else
    rn->info = si->next;
  if (si->next)
    si->next->prev = si->prev;
  route_unlock_node (rn);
  
  /* Free static route configuration. */
  XFREE (MTYPE_STATIC_ROUTE, si);

  route_unlock_node (rn);

  return 1;
}

#ifdef HAVE_IPV6
static int
rib_bogus_ipv6 (int type, struct prefix_ipv6 *p,
		struct in6_addr *gate, unsigned int ifindex, int table)
{
  if (type == ZEBRA_ROUTE_CONNECT && IN6_IS_ADDR_UNSPECIFIED (&p->prefix)) {
#if defined (MUSICA) || defined (LINUX)
    /* IN6_IS_ADDR_V4COMPAT(&p->prefix) */
    if (p->prefixlen == 96)
      return 0;
#endif /* MUSICA */
    return 1;
  }
  if (type == ZEBRA_ROUTE_KERNEL && IN6_IS_ADDR_UNSPECIFIED (&p->prefix)
      && p->prefixlen == 96 && gate && IN6_IS_ADDR_UNSPECIFIED (gate))
    {
      kernel_delete_ipv6_old (p, gate, ifindex, 0, table);
      return 1;
    }
  return 0;
}
#endif /* HAVE_IPV6 */

/* RIB update function. */
void
rib_update (void)
{
  struct route_node *rn;
  struct route_table *table;
  
  table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      if (rn->info)
        rib_queue_add (&zebrad, rn);

  table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      if (rn->info)
        rib_queue_add (&zebrad, rn);
}

/* Interface goes up. */
static void
rib_if_up (struct interface *ifp)
{
  rib_update ();
}

/* Interface goes down. */
static void
rib_if_down (struct interface *ifp)
{
  rib_update ();
}

/* Remove all routes which comes from non main table.  */
static void
rib_weed_table (struct route_table *table)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *next;

  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      for (rib = rn->info; rib; rib = next)
	{
	  next = rib->next;

	  if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
	    continue;

	  if (rib->table != zebrad.rtm_table_default &&
	      rib->table != RT_TABLE_MAIN)
            rib_delnode (rn, rib);
	}
}

/* Delete all routes from non main table. */
void
rib_weed_tables (void)
{
  rib_weed_table (vrf_table (AFI_IP, SAFI_UNICAST, 0));
  rib_weed_table (vrf_table (AFI_IP6, SAFI_UNICAST, 0));
}

/* Delete self installed routes after zebra is relaunched.  */
static void
rib_sweep_table (struct route_table *table)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *next;
  int ret = 0;

  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      for (rib = rn->info; rib; rib = next)
	{
	  next = rib->next;

	  if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
	    continue;

	  if (rib->type == ZEBRA_ROUTE_KERNEL && 
	      CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELFROUTE))
	    {
	      ret = rib_uninstall_kernel (rn, rib);
	      if (! ret)
                rib_delnode (rn, rib);
	    }
	}
}

/* Sweep all RIB tables.  */
void
rib_sweep_route (void)
{
  rib_sweep_table (vrf_table (AFI_IP, SAFI_UNICAST, 0));
  rib_sweep_table (vrf_table (AFI_IP6, SAFI_UNICAST, 0));
}

/* Close RIB and clean up kernel routes. */
static void
rib_close_table (struct route_table *table)
{
  struct route_node *rn;
  struct rib *rib;

  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      for (rib = rn->info; rib; rib = rib->next)
        {
          if (! RIB_SYSTEM_ROUTE (rib)
	      && CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
            rib_uninstall_kernel (rn, rib);
        }
}

/* Close all RIB tables.  */
void
rib_close (void)
{
  rib_close_table (vrf_table (AFI_IP, SAFI_UNICAST, 0));
  rib_close_table (vrf_table (AFI_IP6, SAFI_UNICAST, 0));
}

/* Routing information base initialize. */
void
rib_init (void)
{
  rib_queue_init (&zebrad);
  /* VRF initialization.  */
  vrf_init ();
}
