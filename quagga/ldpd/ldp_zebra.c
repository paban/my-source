#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "stream.h"
#include "table.h"
#include "memory.h"
#include "zclient.h"
#include "linklist.h"
#include "log.h"

#include "ldp_cfg.h"
#include "mpls_compare.h"

#include "ldp.h"
#include "impl_fib.h"
#include "impl_ifmgr.h"
#include "impl_mpls.h"
#include "ldp_interface.h"
#include "mpls_mpls_impl.h"

/* All information about zebra. */
struct zclient *zclient = NULL;
struct list *pending_out_segment = NULL;
struct list *pending_ftn = NULL;
struct list *pending_xc = NULL;

/* For registering threads. */
extern struct thread_master *master;

struct prefix router_id;

/* Router-id update message from zebra. */
static int ldp_router_id_update_zebra(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct ldp *ldp = ldp_get();

    zebra_router_id_update_read(zclient->ibuf,&router_id);

    zlog_info("router-id change %s",
	inet_ntoa(router_id.u.prefix4));

    if (ldp && ldp->lsr_id_is_static != MPLS_BOOL_TRUE) 
	ldp_router_id_update(ldp, &router_id);
    return 0;
}

/* Inteface addition message from zebra. */
static int ldp_interface_add(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct interface *ifp;

    if (!(ifp = zebra_interface_add_read(zclient->ibuf))) {
	return 1;
    }

    zlog_info("interface add %s index %d flags %ld metric %d mtu %d",
	       ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

    return 0;
}

/* this is not the same as ldp_interface_delete() which is found in
 * ldp_interface.c
 */
static int ldp_interface_deletez(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct interface *ifp;
    struct stream *s;

    s = zclient->ibuf;
    /* zebra_interface_state_read() updates interface structure in iflist */
    ifp = zebra_interface_state_read(s);

    if (ifp == NULL) {
	return 0;
    }

    if (if_is_up(ifp)) {
	zlog_warn("got delete of %s, but interface is still up",
	    ifp->name);
    }

    zlog_info("interface delete %s index %d flags %ld metric %d mtu %d",
       ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

    return 0;
}

struct interface * zebra_interface_if_lookup(struct stream *s) {
    struct interface *ifp;
    u_char ifname_tmp[INTERFACE_NAMSIZ];

    /* Read interface name. */
    stream_get(ifname_tmp, s, INTERFACE_NAMSIZ);

    /* Lookup this by interface index. */
    ifp = if_lookup_by_name(ifname_tmp);

    /* If such interface does not exist, indicate an error */
    if (!ifp) {
	return NULL;
    }

    return ifp;
}

static int ldp_interface_state_up(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct interface *ifp;
    struct interface if_tmp;

    ifp = zebra_interface_if_lookup(zclient->ibuf);
    if (ifp == NULL) {
	return 0;
    }

    /* Interface is already up. */
    if (if_is_up (ifp)) {
	/* Temporarily keep ifp values. */
	memcpy (&if_tmp, ifp, sizeof (struct interface));

	zebra_interface_if_set_value (zclient->ibuf, ifp);

	zlog_info ("Interface[%s] state update.", ifp->name);

	return 0;
    }

    zebra_interface_if_set_value(zclient->ibuf, ifp);

    zlog_info ("Interface[%s] state change to up.", ifp->name);

    ldp_interface_up(ifp->info);

    return 0;
}

static int ldp_interface_state_down(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct interface *ifp;

    ifp = zebra_interface_state_read (zclient->ibuf);
    if (ifp == NULL) {
	return 0;
    }

    zlog_info ("Interface[%s] state change to down.", ifp->name);

    ldp_interface_down(ifp->info);

    return 0;
}

void prefix2mpls_inet_addr(struct prefix *p, struct mpls_inet_addr *a)
{
    a->type = MPLS_FAMILY_IPV4;
    a->u.ipv4 = (uint32_t)ntohl(p->u.prefix4.s_addr);
}

void zebra_prefix2mpls_fec(struct prefix *p, mpls_fec *fec)
{
  fec->u.prefix.length = p->prefixlen;
  fec->type = MPLS_FEC_PREFIX;
  fec->u.prefix.network.type = MPLS_FAMILY_IPV4;
  fec->u.prefix.network.u.ipv4 = ntohl(p->u.prefix4.s_addr);
}

void mpls_fec2zebra_prefix(mpls_fec *lp, struct prefix *p)
{
  p->family = AF_INET;
  switch(lp->type) {
    case MPLS_FEC_PREFIX:
      p->prefixlen = lp->u.prefix.length;
      p->u.prefix4.s_addr = htonl(lp->u.prefix.network.u.ipv4);
      break;
    case MPLS_FEC_HOST:
      p->prefixlen = 32;
      p->u.prefix4.s_addr = htonl(lp->u.host.u.ipv4);
      break;
    default:
      MPLS_ASSERT(0);
      break;
  }
}

static int ldp_interface_address_add(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct ldp *ldp = ldp_get();
    struct connected *c;
    struct interface *ifp;
    struct prefix *p;
    struct ldp_addr addr;
    struct ldp_if iff;
    struct ldp_interface *li;

    c = zebra_interface_address_read(command, zclient->ibuf);
    if (c == NULL || c->address->family != AF_INET) {
	return 0;
    }

    ifp = c->ifp;
    p = c->address;

    /* Don't register addresses connected to the loopback interface */
    if (if_is_loopback(ifp))
	return 0;

    zlog_info("address add %s to interface %s(%p)",inet_ntoa(p->u.prefix4),
	ifp->name, ifp);

    if (ldp) {
	prefix2mpls_inet_addr(p, &addr.address);
	iff.handle = ifp;
	ldp_cfg_if_addr_set(ldp->h, &iff, &addr, LDP_CFG_ADD);

	li = ifp->info;
	if (ldp->trans_addr == LDP_TRANS_ADDR_STATIC_INTERFACE &&
	    !strncmp(ldp->trans_addr_ifname,ifp->name,IFNAMSIZ + 1)) {
	    ldp_global g;

	    zlog_info("updating global transport address");
	    g.transport_address.u.ipv4 = ntohl(if_ipv4_src_address (ifp));
	    g.transport_address.type =
		(g.transport_address.u.ipv4)?MPLS_FAMILY_IPV4:MPLS_FAMILY_NONE;
	    ldp_admin_state_start(ldp);
	    ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_TRANS_ADDR);
	    ldp_admin_state_finish(ldp);
	}
	if (ldp->trans_addr == LDP_TRANS_ADDR_INTERFACE) {
	    zlog_info("updating entity transport address");
	    li->entity.transport_address.u.ipv4 =
		ntohl(if_ipv4_src_address (ifp));

	    li->entity.transport_address.type =
		li->entity.transport_address.u.ipv4 ?
		MPLS_FAMILY_IPV4 : MPLS_FAMILY_NONE;

	    if (li->entity.index) {
		ldp_interface_admin_state_start(li);
		ldp_cfg_entity_set(ldp->h, &li->entity,
		    LDP_ENTITY_CFG_TRANS_ADDR);
		ldp_interface_admin_state_finish(li);
	    }
	}
    }

    return 0;
}

static int ldp_interface_address_delete(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct ldp *ldp = ldp_get();
    struct connected *c;
    struct interface *ifp;
    struct prefix *p;
    struct ldp_addr addr;
    struct ldp_if iff;
    struct ldp_interface *li;

    c = zebra_interface_address_read(command, zclient->ibuf);
    if (c == NULL || c->address->family != AF_INET) {
	return 0;
    }

    ifp = c->ifp;
    p = c->address;

    zlog_info("address delete %s from interface %s",
	inet_ntoa(p->u.prefix4), ifp->name);

    if (ldp) {
	prefix2mpls_inet_addr(p, &addr.address);
	iff.handle = ifp;
	ldp_cfg_if_addr_set(ldp->h, &iff, &addr, LDP_CFG_DEL);

	li = ifp->info;
	if (ldp->trans_addr == LDP_TRANS_ADDR_STATIC_INTERFACE &&
	    !strncmp(ldp->trans_addr_ifname,ifp->name,IFNAMSIZ + 1)) {
	    ldp_global g;

	    zlog_info("updating global transport address");
	    g.transport_address.u.ipv4 = ntohl(if_ipv4_src_address (ifp));
	    g.transport_address.type =
		(g.transport_address.u.ipv4)?MPLS_FAMILY_IPV4:MPLS_FAMILY_NONE;
	    ldp_admin_state_start(ldp);
	    ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_TRANS_ADDR);
	    ldp_admin_state_finish(ldp);
	}
	if (ldp->trans_addr == LDP_TRANS_ADDR_INTERFACE) {
	    zlog_info("updating entity transport address");
	    li->entity.transport_address.u.ipv4 =
		ntohl(if_ipv4_src_address (ifp));

	    li->entity.transport_address.type =
		li->entity.transport_address.u.ipv4 ?
		MPLS_FAMILY_IPV4 : MPLS_FAMILY_NONE;

	    if (li->entity.index) {
		ldp_interface_admin_state_start(li);
		ldp_cfg_entity_set(ldp->h, &li->entity,
		    LDP_ENTITY_CFG_TRANS_ADDR);
		ldp_interface_admin_state_finish(li);
	    }
	}
    }

    connected_free(c);

    return 0;
}

static int ldp_zebra_read_ipv4(int cmd, struct zclient *client,
  zebra_size_t length) {
  struct prefix_ipv4 prefix;
  struct zapi_ipv4 api;
  int i = 0;
  int j;

  struct mpls_nexthop nexthop[8];
  struct ldp *ldp = ldp_get();
  struct mpls_fec fec;
  struct stream *s;
  struct in_addr tmp;

  memset(&api,0,sizeof(api));
  memset(nexthop,0,sizeof(nexthop));

  s = client->ibuf;
  zapi_ipv4_read (s, length, &api, &prefix);

  zlog_info("route %s/%d", inet_ntoa(prefix.prefix), prefix.prefixlen);

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      for (i = 0; i < api.nexthop_num; i++)
        {
          if (api.type == ZEBRA_ROUTE_CONNECT)
            {
	      nexthop[i].attached = MPLS_BOOL_TRUE;
	      zlog_info("\tattached");
            }
          nexthop[i].ip.type = MPLS_FAMILY_IPV4;
          if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
            nexthop[i].distance = api.message;
          if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
            nexthop[i].metric = api.metric;
          if (CHECK_FLAG (api.nexthop[i].type, ZEBRA_NEXTHOP_IPV4))
            {
              nexthop[i].ip.u.ipv4 = ntohl(api.nexthop[i].gw.ipv4.s_addr);
              nexthop[i].type |= MPLS_NH_IP;
              tmp.s_addr = htonl(nexthop[i].ip.u.ipv4);
              zlog_info("\tnexthop %s", inet_ntoa(tmp));
            }
          if (CHECK_FLAG (api.nexthop[i].type, ZEBRA_NEXTHOP_IFINDEX))
            {
              nexthop[i].if_handle =
                  if_lookup_by_index(api.nexthop[i].intf.index);
              if (nexthop[i].if_handle)
                {
	          nexthop[i].type |= MPLS_NH_IF;
	          zlog_info("\tifindex %d", nexthop[i].if_handle->ifindex);
                }
            }
        }
    }

  zebra_prefix2mpls_fec((struct prefix*)&prefix, &fec);
  for (j = 0; j < i; j++) {
    if (cmd == ZEBRA_IPV4_ROUTE_ADD) {
      zlog_info("\tadd");
      if ((ldp_cfg_fec_get(ldp->h, &fec, 0) != MPLS_SUCCESS) ||
	  (fec.is_route == MPLS_BOOL_FALSE)) {
        if (ldp_cfg_fec_set(ldp->h, &fec, LDP_CFG_ADD) != MPLS_SUCCESS) {
          MPLS_ASSERT(0);
        }
      }
      if (ldp_cfg_fec_nexthop_get(ldp->h, &fec, &nexthop[j],
        LDP_FEC_CFG_BY_INDEX) != MPLS_SUCCESS) {
        if (ldp_cfg_fec_nexthop_set(ldp->h, &fec, &nexthop[j],
          LDP_CFG_ADD|LDP_FEC_CFG_BY_INDEX) != MPLS_SUCCESS) {
          MPLS_ASSERT(0);
        }
      } else {
	/*
	 * already exists ... looks like we can get the same route sent
	 * to us twice ... multiple protocols?
        MPLS_ASSERT(0);
	 */
      }
    } else {
      zlog_info("\tdelete");
      if ((ldp_cfg_fec_get(ldp->h, &fec, 0) == MPLS_SUCCESS) &&
	  (fec.is_route == MPLS_BOOL_TRUE)) {
        if (ldp_cfg_fec_nexthop_get(ldp->h, &fec, &nexthop[j],
          LDP_FEC_CFG_BY_INDEX) == MPLS_SUCCESS) {
          if (ldp_cfg_fec_nexthop_set(ldp->h, &fec, &nexthop[j],
            LDP_FEC_CFG_BY_INDEX|LDP_CFG_DEL|
            LDP_FEC_NEXTHOP_CFG_BY_INDEX) != MPLS_SUCCESS) {
            MPLS_ASSERT(0);
          }
        } else {
          MPLS_ASSERT(0);
        }
        if (ldp_cfg_fec_set(ldp->h, &fec, LDP_CFG_DEL|LDP_FEC_CFG_BY_INDEX) !=
          MPLS_SUCCESS) {
          MPLS_ASSERT(0);
        }
      } else {
        MPLS_ASSERT(0);
      }
    }
  }
  return 0;
}

static int ldp_zebra_read_ipv6(int cmd, struct zclient *client,
    zebra_size_t length) {
    struct prefix_ipv6 prefix;
    struct zapi_ipv6 api;

    memset(&api,0,sizeof(api));
    zapi_ipv6_route_read (client, length, &api, &prefix);

    return 0;
}

static int ldp_xc_read(int cmd, struct zclient *client, zebra_size_t size) {
    struct zapi_mpls_xc api;
    mpls_xc_stream_read(client->ibuf, &api);
    return 0;
}

static int ldp_in_segment_read(int cmd, struct zclient *client,
    zebra_size_t size) {
    struct zapi_mpls_in_segment api;
    mpls_in_segment_stream_read(client->ibuf, &api);
    return 0;
}

static int ldp_out_segment_read(int cmd, struct zclient *client,
    zebra_size_t size) {
    struct zapi_mpls_out_segment api;
    struct listnode *n;
    struct listnode *nn;
    mpls_outsegment *o;
    struct pending_ftn_data *fn;
    struct pending_xc_data *x;

    mpls_out_segment_stream_read(client->ibuf, &api);

    for (ALL_LIST_ELEMENTS(pending_out_segment, n, nn, o)) {
	if (api.req == o->handle) {
	    zlog_info("found pending NHLFE: %p", o);
	    o->handle = api.index;
	    list_delete_node(pending_out_segment,n);
	    goto ftn;
	}
    }
    zlog_info("requested out segment %d not in list", api.req);
    return 0;

ftn:
    /* if we've gotten this for then the o->handle is not the proper index */
    for (ALL_LIST_ELEMENTS(pending_ftn, n, nn, fn)) {
	if (api.index == fn->o->handle) {
	    mpls_mpls_fec2out_add(fn->h, fn->f, fn->o);
	    list_delete_node(pending_ftn,n);
	    break;
	}
    }
    for (ALL_LIST_ELEMENTS(pending_xc, n, nn, x)) {
	if (api.index == x->o->handle) {
	    mpls_mpls_xconnect_add(x->h, x->i, x->o);
	    list_delete_node(pending_xc,n);
	    break;
	}
    }
    return 0;
}

static int ldp_labelspace_read(int cmd, struct zclient *client,
    zebra_size_t size) {
    struct zapi_mpls_labelspace api;
    struct interface *ifp;
    struct ldp_interface *li;
    int labelspace;

    mpls_labelspace_stream_read(client->ibuf, &api);
    ifp = if_lookup_by_name(api.ifname);

    if (ifp) {
	labelspace = ifp->mpls_labelspace;
	ifp->mpls_labelspace = api.labelspace;

	if (ifp->info) {
	    li = ifp->info;

	    if (api.labelspace < 0) {
		if (li->configured == MPLS_BOOL_TRUE)
		    ldp_interface_shutdown (li);
	    } else {
		if (labelspace >= 0) {
		    if (li->configured == MPLS_BOOL_TRUE)
			ldp_interface_shutdown (li);
		}
		if (li->configured == MPLS_BOOL_TRUE)
		    ldp_interface_startup (li);
	    }
	}
    }
    return 0;
}

static int ldp_ftn_read(int cmd, struct zclient *client, zebra_size_t size) {
    struct zapi_mpls_ftn api;
    mpls_ftn_stream_read(client->ibuf, &api);
    return 0;
}

void ldp_zebra_startup() {
  int i;
  for (i = 0;i < ZEBRA_ROUTE_MAX;i++) {
	if (i != ZEBRA_ROUTE_LDP)
	    zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient,i);
  }
}

void ldp_zebra_shutdown() {
  int i;
  for (i = 0;i < ZEBRA_ROUTE_MAX;i++) {
	if (i != ZEBRA_ROUTE_LDP)
	    zclient_redistribute(ZEBRA_REDISTRIBUTE_DELETE, zclient,i);
  }
}

void pending_delete(void *m) {
    XFREE(MTYPE_TMP, m);
}

void ldp_zebra_init() {

  pending_out_segment = list_new();
  pending_ftn = list_new();
  pending_ftn->del = pending_delete;
  pending_xc = list_new();
  pending_xc->del = pending_delete;

  /* Allocate zebra structure. */
  zclient = zclient_new();
  zclient_init(zclient, ZEBRA_ROUTE_LDP);
  zclient->router_id_update = ldp_router_id_update_zebra;
  zclient->interface_add = ldp_interface_add;
  zclient->interface_delete = ldp_interface_deletez;
  zclient->interface_up = ldp_interface_state_up;
  zclient->interface_down = ldp_interface_state_down;
  zclient->interface_address_add = ldp_interface_address_add;
  zclient->interface_address_delete = ldp_interface_address_delete;
  zclient->ipv4_route_add = ldp_zebra_read_ipv4;
  zclient->ipv4_route_delete = ldp_zebra_read_ipv4;
/*
 *zclient->ipv6_route_add = ldp_zebra_read_ipv6;
 *zclient->ipv6_route_delete = ldp_zebra_read_ipv6;
 */
  zclient->mpls_xc_add = ldp_xc_read;
  zclient->mpls_xc_delete = ldp_xc_read;
  zclient->mpls_in_segment_add = ldp_in_segment_read;
  zclient->mpls_in_segment_delete = ldp_in_segment_read;
  zclient->mpls_out_segment_add = ldp_out_segment_read;
  zclient->mpls_out_segment_delete = ldp_out_segment_read;
  zclient->mpls_labelspace_add = ldp_labelspace_read;
  zclient->mpls_labelspace_delete = ldp_labelspace_read;
  zclient->mpls_ftn_add = ldp_ftn_read;
  zclient->mpls_ftn_delete = ldp_ftn_read;

  memset(&router_id, 0, sizeof(router_id));
}
