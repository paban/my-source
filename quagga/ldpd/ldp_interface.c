#include <zebra.h>

#include "if.h"
#include "memory.h"

#include "ldp_cfg.h"
#include "ldp_struct.h"

#include "ldp.h"
#include "ldp_interface.h"
#include "impl_mpls.h"

extern struct prefix router_id;

unsigned int if_ipv4_src_address (struct interface *ifp) {
  struct listnode *node;
  struct connected *c;
  for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, c))
  {
    struct prefix *p = c->address;

    if (p && p->family == AF_INET)
      return p->u.prefix4.s_addr;
  }
  return router_id.u.prefix4.s_addr;
}

struct ldp_interface *ldp_interface_new(struct interface *ifp) {
    struct ldp_interface *li;

    li = XMALLOC(MTYPE_LDP, sizeof(struct ldp_interface));
    if (!li) {
	return NULL;
    }
    memset(li, 0, sizeof(struct ldp_interface));
    li->ifp = ifp;
    ifp->info = li;

    li->configured = MPLS_BOOL_FALSE;
    li->admin_up = MPLS_BOOL_FALSE;
    li->create_on_hold = MPLS_BOOL_TRUE;
    ldp_entity_set_defaults(&li->entity);

    return li;
}

void ldp_interface_free(struct ldp_interface *li) {
    XFREE(MTYPE_LDP, li);
}

int ldp_interface_create2(struct ldp_interface *li) {
    struct ldp *ldp = ldp_get();

    if (!ldp || !li->iff.index) {
	li->create_on_hold = MPLS_BOOL_TRUE;
	return MPLS_SUCCESS;
    }

    li->create_on_hold = MPLS_BOOL_FALSE;

    li->entity.sub_index = li->iff.index;
    li->entity.entity_type = LDP_DIRECT;
    li->entity.admin_state = MPLS_ADMIN_DISABLE;

    if (ldp->trans_addr == LDP_TRANS_ADDR_INTERFACE) {
	li->entity.transport_address.type = MPLS_FAMILY_IPV4;
	li->entity.transport_address.u.ipv4 =
	    ntohl(if_ipv4_src_address (li->ifp));
    } else {
	li->entity.transport_address.type = MPLS_FAMILY_NONE;
    }

    ldp_cfg_entity_set(ldp->h, &li->entity,
	LDP_CFG_ADD | LDP_ENTITY_CFG_SUB_INDEX |
	LDP_ENTITY_CFG_ADMIN_STATE | LDP_ENTITY_CFG_TRANS_ADDR);

    ldp_cfg_entity_get(ldp->h, &li->entity, 0xFFFFFFFF);
    return ldp_interface_admin_state_finish(li);
}

int ldp_interface_create(struct ldp_interface *li) {
    struct ldp *ldp = ldp_get();

    MPLS_ASSERT (!li->iff.index);
    MPLS_ASSERT(ldp);

    /* tell LDP about this interface */
    if (li->ifp->mpls_labelspace < 0) {
	li->ifp->mpls_labelspace = 0;
    }
    li->iff.label_space = li->ifp->mpls_labelspace;
    li->iff.handle = li->ifp;

    zlog_debug("Creating interface %s(%p)\n", li->ifp->name, li->ifp);

    ldp_cfg_if_set(ldp->h, &li->iff,LDP_CFG_ADD|LDP_IF_CFG_LABEL_SPACE);
    ldp_cfg_if_get(ldp->h, &li->iff, 0xFFFFFFFF);

    return MPLS_SUCCESS;
}

void ldp_interface_delete2(struct ldp_interface *li) {
    struct ldp *ldp = ldp_get();

    li->create_on_hold = MPLS_BOOL_TRUE;
    li->entity.admin_state = MPLS_ADMIN_DISABLE;

    if (ldp) {
	ldp_interface_admin_state_start(li);
	if (li->entity.index) {
	    ldp_cfg_entity_set(ldp->h, &li->entity, LDP_CFG_DEL);
	}
    }
    li->entity.index = 0;
}

void ldp_interface_delete(struct ldp_interface *li) {
    struct ldp *ldp = ldp_get();

    MPLS_ASSERT(ldp);
    MPLS_ASSERT(li->iff.index);

    ldp_cfg_if_set(ldp->h, &li->iff, LDP_CFG_DEL);
    li->iff.index = 0;
}

int ldp_interface_startup(struct ldp_interface *li) {
    struct ldp *ldp = ldp_get();

    MPLS_ASSERT(ldp && li->iff.index && li->entity.index);

    /* only real interfaces get here */
    li->entity.admin_state = MPLS_ADMIN_ENABLE;
    ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_ADMIN_STATE);

    return MPLS_SUCCESS;
}

int ldp_interface_shutdown(struct ldp_interface *li) {
    struct ldp *ldp = ldp_get();

    MPLS_ASSERT(ldp && li->iff.index && li->entity.index);

    li->entity.admin_state = MPLS_ADMIN_DISABLE;
    ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_ADMIN_STATE);

    return MPLS_SUCCESS;
}

int ldp_interface_admin_state_start(struct ldp_interface *li) {
  if (li->admin_up == MPLS_BOOL_TRUE && ldp_interface_is_up(li)) {
    return ldp_interface_shutdown(li);
  }
  return MPLS_SUCCESS;
}

int ldp_interface_admin_state_finish(struct ldp_interface *li) {
  if (li->admin_up == MPLS_BOOL_TRUE && ldp_interface_is_up(li)) {
    return ldp_interface_startup(li);
  }
  return MPLS_SUCCESS;
}

void ldp_interface_up(struct ldp_interface *li) {
    if (li->configured == MPLS_BOOL_TRUE && li->admin_up == MPLS_BOOL_TRUE) {
	ldp_interface_startup(li);
    }
}

void ldp_interface_down(struct ldp_interface *li) {
    if (li->configured == MPLS_BOOL_TRUE && li->admin_up == MPLS_BOOL_TRUE) {
	ldp_interface_shutdown(li);
    }
}

int ldp_interface_is_up(struct ldp_interface *li) {
    return if_is_up(li->ifp);
}

static
int ldp_interface_new_hook(struct interface *ifp) {
    if (!ldp_interface_new(ifp)) {
	return 1;
    }

    if (ldp_get())
	ldp_interface_create(ifp->info);

    return 0;
}

static
int ldp_interface_delete_hook(struct interface *ifp) {
    if (ifp->info) {
	if (ldp_get())
	    ldp_interface_delete(ifp->info);
	ldp_interface_free(ifp->info);
    }
    ifp->info = NULL;
    return 0;
}

void ldp_interface_init() {
    /* Initialize Zebra interface data structure. */
    if_init();
    if_add_hook(IF_NEW_HOOK, ldp_interface_new_hook);
    if_add_hook(IF_DELETE_HOOK, ldp_interface_delete_hook);
}
