#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "thread.h"
#include "prefix.h"
#include "table.h"
#include "linklist.h"
#include "filter.h"
#include "vty.h"
#include "plist.h"

#include "ldp.h"
#include "ldp_cfg.h"
#include "ldp_struct.h"
#include "ldp_interface.h"
#include "ldp_zebra.h"

#include "impl_fib.h"

int ldp_shutdown(struct ldp *ldp) {
  ldp_global g;

  g.admin_state = MPLS_ADMIN_DISABLE;
  return ldp_cfg_global_set(ldp->h,&g,LDP_GLOBAL_CFG_ADMIN_STATE);
}

int ldp_startup(struct ldp *ldp) {
  ldp_global g;

  g.admin_state = MPLS_ADMIN_ENABLE;
  return ldp_cfg_global_set(ldp->h,&g,LDP_GLOBAL_CFG_ADMIN_STATE);
}

int ldp_admin_state_start(struct ldp *ldp) {
  if (ldp->admin_up == MPLS_BOOL_TRUE) {
    return ldp_shutdown(ldp);
  }
  return MPLS_SUCCESS;
}

int ldp_admin_state_finish(struct ldp *ldp) {
  if (ldp->admin_up == MPLS_BOOL_TRUE) {
    return ldp_startup(ldp);
  }
  return MPLS_SUCCESS;
}

int do_ldp_router_id_update(struct ldp *ldp, unsigned int router_id) {
    ldp_global g;
    g.lsr_identifier.type = MPLS_FAMILY_IPV4;
    g.lsr_identifier.u.ipv4 = router_id;
    g.transport_address.type = MPLS_FAMILY_NONE;
    g.transport_address.u.ipv4 = 0;

    if (ldp->trans_addr == LDP_TRANS_ADDR_LSRID) {
	g.transport_address.type = MPLS_FAMILY_IPV4;
	g.transport_address.u.ipv4 = router_id;
    }

    return ldp_cfg_global_set(ldp->h,&g,
	LDP_GLOBAL_CFG_LSR_IDENTIFIER|LDP_GLOBAL_CFG_TRANS_ADDR);
}

int ldp_router_id_update(struct ldp *ldp, struct prefix *router_id) {

  zlog_info("router-id update %s", inet_ntoa(router_id->u.prefix4));

  if (!ldp->lsr_id_is_static) {
    ldp_admin_state_start(ldp);

    do_ldp_router_id_update(ldp, ntohl(router_id->u.prefix4.s_addr));

    ldp_admin_state_finish(ldp);
  }
  return 0;
}

/* LDP instance top. */
struct ldp *ldp_top = NULL;

struct ldp *ldp_new(void) {
    struct ldp *new = XMALLOC(MTYPE_LDP, sizeof(struct ldp));
    ldp_global g;
    struct route_node *rn;
    struct prefix n;

    struct interface *ifp;
    struct connected *c;
    struct listnode *node, *cnode;
    struct ldp_interface *li;
    struct ldp_addr addr;
    struct prefix *p;

    memset(new,0,sizeof(*new));

    new->h = ldp_cfg_open(new);
    new->admin_up = MPLS_BOOL_TRUE;
    new->lsr_id_is_static = 0;

    new->egress = LDP_EGRESS_CONNECTED;
    new->address = LDP_ADDRESS_ALL;
    new->peer_list = list_new();

    ldp_top = new;

    do_ldp_router_id_update(new, ntohl(router_id.u.prefix4.s_addr));
    g.admin_state = MPLS_ADMIN_ENABLE;

    ldp_cfg_global_set(new->h,&g, LDP_GLOBAL_CFG_LSR_HANDLE|
	LDP_GLOBAL_CFG_ADMIN_STATE);

    n.u.prefix4.s_addr = htonl(INADDR_LOOPBACK);
    n.prefixlen = 8;
    n.family = AF_INET;

    for (ALL_LIST_ELEMENTS_RO(iflist, node, ifp)) {
        MPLS_ASSERT(ifp->info);
	li = ifp->info;

	ldp_interface_create(li);

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, c)) {
	    p = c->address;
	    if (p->family == AF_INET) {
		if (!prefix_match(&n, c->address)) {
		    prefix2mpls_inet_addr(p, &addr.address);
		    ldp_cfg_if_addr_set(new->h, &li->iff, &addr, LDP_CFG_ADD);
		}
	    }
	}

	if (li->configured == MPLS_BOOL_TRUE)
	    ldp_interface_create2(li);
    }

    ldp_zebra_startup();

    return new;
}

struct ldp *ldp_get() {
    if (ldp_top) {
	return ldp_top;
    }
    return NULL;
}

void ldp_finish(struct ldp *ldp) {
    struct ldp_interface *li;
    struct interface *ifp;
    struct listnode* node;
    int flag;

    ldp_zebra_shutdown();

    ldp_admin_state_start(ldp);

    for (ALL_LIST_ELEMENTS_RO(iflist, node, ifp)) {
        MPLS_ASSERT(ifp->info);
	flag = li->iff.index ? 1 : 0;
	li = ifp->info;
	ldp_interface_delete(li);
	if (flag) {
	    li->configured = MPLS_BOOL_TRUE;
	    li->admin_up = MPLS_BOOL_TRUE;
	}
    }

    ldp_cfg_close(ldp->h);
    list_free(ldp->peer_list);

    XFREE(MTYPE_LDP,ldp);
    ldp_top = NULL;
}

#if 0
/* Update access-list list. */
void mpls_access_list_update(struct access_list *access) {
}

/* Update prefix-list list. */
void mpls_prefix_list_update(struct prefix_list *plist) {
}
#endif

void ldp_init() {

#if 0
    access_list_init();
    access_list_add_hook(mpls_access_list_update);
    access_list_delete_hook(mpls_access_list_update);
#endif

}
