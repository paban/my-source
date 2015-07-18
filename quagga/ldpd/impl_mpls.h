#ifndef IMPL_MPLS_H
#define IMPL_MPLS_H

#include "ldp_interface.h"

struct pending_ftn_data
{
    mpls_mpls_handle h;
    mpls_outsegment *o;
    mpls_fec *f;
};

struct pending_xc_data
{
    mpls_mpls_handle h;
    mpls_outsegment *o;
    mpls_insegment *i;
};

int do_mpls_labelspace(struct ldp_interface *li);

#endif
