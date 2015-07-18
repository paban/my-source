#ifndef LDP_H
#define LDP_H

#include <zebra.h>
#include "sockunion.h"
#include "prefix.h"
#include "zclient.h"
#include "linklist.h"
#include "if.h"

#include "ldp_struct.h"

#define LDP_DEFAULT_CONFIG "ldpd.conf"
#define LDP_VTY_PORT                2610

typedef enum {
    LDP_EGRESS_ALL,
    LDP_EGRESS_LSRID,
    LDP_EGRESS_CONNECTED
} ldp_egress_mode;

typedef enum {
    LDP_ADDRESS_ALL,
    LDP_ADDRESS_LSRID,
    LDP_ADDRESS_LDP
} ldp_address_mode;

typedef enum {
  LDP_TRANS_ADDR_NONE = 0,
  LDP_TRANS_ADDR_INTERFACE,
  LDP_TRANS_ADDR_LSRID,
  LDP_TRANS_ADDR_STATIC_IP,
  LDP_TRANS_ADDR_STATIC_INTERFACE,
} ldp_trans_addr_mode;

struct ldp {
    struct list *peer_list;
    mpls_cfg_handle h;
    mpls_bool admin_up;
    mpls_bool lsr_id_is_static;
    ldp_egress_mode egress;
    ldp_address_mode address;
    ldp_trans_addr_mode trans_addr;
    char trans_addr_ifname[IFNAMSIZ + 1];
    mpls_bool use_lsr_id_for_global_trans_addr;
    mpls_bool use_interface_addr_for_local_trans_addr;
};

struct ldp *ldp_get();
struct ldp *ldp_new();
void ldp_init();
int ldp_router_id_update(struct ldp *ldp, struct prefix *router_id);
int do_ldp_router_id_update(struct ldp *ldp, unsigned int router_id);
void ldp_finish(struct ldp *ldp);

int ldp_admin_state_start(struct ldp *ldp);
int ldp_admin_state_finish(struct ldp *ldp);
int ldp_add_ipv4(struct ldp *ldp, mpls_fec *fec, mpls_nexthop *nexthop);
int ldp_delete_ipv4(struct ldp *ldp, mpls_fec *fec, mpls_nexthop *nexthop);

#endif
