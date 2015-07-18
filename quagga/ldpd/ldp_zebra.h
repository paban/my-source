#ifndef _ZEBRA_LDP_ZEBRA_H
#define _ZEBRA_LDP_ZEBRA_H

#include "prefix.h"

#include "ldp_struct.h"

extern struct prefix router_id;

void ldp_zebra_init();
void prefix2mpls_inet_addr(struct prefix *p, struct mpls_inet_addr *a);
void zebra_prefix2mpls_fec(struct prefix *p, mpls_fec *fec);
void mpls_fec2zebra_prefix(mpls_fec *fec, struct prefix *p);
void ldp_zebra_startup();
void ldp_zebra_shutdown();

#endif
