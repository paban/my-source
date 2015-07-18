/*
 * Routing Information Base header
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#ifndef _ZEBRA_RIB_H
#define _ZEBRA_RIB_H

#include "prefix.h"
#include "zclient.h"

#define DISTANCE_INFINITY  255

#include "table.h"

/* Routing information base. */

union g_addr {
  struct in_addr ipv4;
#ifdef HAVE_IPV6
  struct in6_addr ipv6;
#endif /* HAVE_IPV6 */
};

struct rib
{
  /* Status Flags for the *route_node*, but kept in the head RIB.. */
  u_char rn_status;
#define RIB_ROUTE_QUEUED(x)	(1 << (x))

  /* Link list. */
  struct rib *next;
  struct rib *prev;
  
  /* Nexthop structure */
  struct nexthop *nexthop;
  
  /* Refrence count. */
  unsigned long refcnt;
  
  /* Uptime. */
  time_t uptime;

  /* Type fo this route. */
  int type;

  /* Which routing table */
  int table;			

  /* Metric */
  u_int32_t metric;

  /* Distance. */
  u_char distance;

  /* Flags of this route.
   * This flag's definition is in lib/zebra.h ZEBRA_FLAG_* and is exposed
   * to clients via Zserv
   */
  u_short flags;

  /* RIB internal status */
  u_char status;
#define RIB_ENTRY_REMOVED	(1 << 0)

  /* Nexthop information. */
  u_char nexthop_num;
  u_char nexthop_active_num;
  u_char nexthop_fib_num;
};

/* meta-queue structure:
 * sub-queue 0: connected, kernel
 * sub-queue 1: static
 * sub-queue 2: RIP, RIPng, OSPF, OSPF6, IS-IS
 * sub-queue 3: iBGP, eBGP
 * sub-queue 4: any other origin (if any)
 */
#define MQ_SIZE 5
struct meta_queue
{
  struct list *subq[MQ_SIZE];
  u_int32_t size; /* sum of lengths of all subqueues */
};

/* Static route information. */
struct static_route
{
  /* For linked list. */
  struct static_route *prev;
  struct static_route *next;

  /* Administrative distance. */
  u_char distance;
  struct zapi_nexthop nh;
};

/* Nexthop structure. */
struct nexthop
{
  struct nexthop *next;
  struct nexthop *prev;
  struct nexthop *tied;

  /* Interface index. */
  char *ifname;
  unsigned int ifindex;
  
  unsigned int mpls;
  unsigned int type;
  unsigned int advmss;

  u_char flags;
#define NEXTHOP_FLAG_ACTIVE     (1 << 0) /* This nexthop is alive. */
#define NEXTHOP_FLAG_FIB        (1 << 1) /* FIB nexthop. */
#define NEXTHOP_FLAG_RECURSIVE  (1 << 2) /* Recursive nexthop. */
#define NEXTHOP_FLAG_IGNORE     (1 << 3) /* Ignore this nexthop */

  /* the type of drop (REJECT, BLACKHOLE, NULL) */
  u_char drop;

  /* Nexthop address or interface name. */
  union g_addr gate;

  /* Recursive lookup nexthop. */
  u_char rtype;
  unsigned int rifindex;
  union g_addr rgate;
  union g_addr src;
  unsigned int rmpls;
};

/* Routing table instance.  */
struct vrf
{
  /* Identifier.  This is same as routing table vector index.  */
  u_int32_t id;

  /* Routing table name.  */
  char *name;

  /* Description.  */
  char *desc;

  /* FIB identifier.  */
  u_char fib_id;

  /* Routing table.  */
  struct route_table *table[AFI_MAX][SAFI_MAX];

  /* Static route configuration.  */
  struct route_table *stable[AFI_MAX][SAFI_MAX];
};

extern void
nexthop_delete (struct rib *rib, struct nexthop *nexthop);

extern void
nexthop_free (struct nexthop *nexthop);

extern struct nexthop *nexthop_zapi_nexthop_add(struct rib *rib,
  struct zapi_nexthop* znh);
extern void zapi_nexthop2nexthop(struct zapi_nexthop* znh, struct nexthop *nh);

extern void rib_lookup_and_dump (struct prefix_ipv4 *);
extern void rib_lookup_and_pushup (struct prefix_ipv4 *);
extern void rib_dump (const char *, const struct prefix_ipv4 *, const struct rib *);
extern int rib_lookup_route_nexthop (struct prefix *, struct zapi_nexthop *);
#define ZEBRA_RIB_LOOKUP_ERROR -1
#define ZEBRA_RIB_FOUND_EXACT 0
#define ZEBRA_RIB_FOUND_NOGATE 1
#define ZEBRA_RIB_FOUND_CONNECTED 2
#define ZEBRA_RIB_NOTFOUND 3

extern struct vrf *vrf_lookup (u_int32_t);
extern struct route_table *vrf_table (afi_t afi, safi_t safi, u_int32_t id);
extern struct route_table *vrf_static_table (afi_t afi, safi_t safi, u_int32_t id);

/* NOTE:
 * All rib_add_route function will not just add prefix into RIB, but
 * also implicitly withdraw equal prefix of same type. */
extern int rib_add_route (int type, int flags, struct prefix *p, 
			  struct zapi_nexthop *nh, u_int32_t vrf_id,
			  u_int32_t, u_char);

extern int rib_delete_route (int type, int flags, struct prefix *p,
			     struct zapi_nexthop *nh, u_int32_t);
extern int
rib_find_nexthop2 (int owner, struct rib *rib_in, struct nexthop *nh_in,
		   struct rib **rib_out, struct nexthop **nh_out);

extern int
rib_find_nexthop (int owner, struct prefix *p_in, struct nexthop *nh_in,
		  struct route_node **rn_out, struct rib **rib_out,
		  struct nexthop **nh_out);

extern int rib_add_multipath (struct prefix *, struct rib *);

extern struct rib *rib_match_route (struct prefix *p);

extern struct rib *rib_lookup_route (struct prefix *);

extern int rib_check_drop (struct rib *);
extern void rib_update (void);
extern void rib_weed_tables (void);
extern void rib_sweep_route (void);
extern void rib_close (void);
extern void rib_init (void);
extern int rib_uninstall_kernel (struct route_node *rn, struct rib *rib);

extern int
static_add_route (struct prefix *p, struct zapi_nexthop *nh,
		  u_char distance, u_int32_t vrf_id);

extern int
static_delete_route (struct prefix *p, struct zapi_nexthop *nh,
		     u_char distance, u_int32_t vrf_id);

#ifdef HAVE_IPV6
extern struct route_table *rib_table_ipv6;
#endif /* HAVE_IPV6 */

#endif /*_ZEBRA_RIB_H */
