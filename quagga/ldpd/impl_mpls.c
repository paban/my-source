#include <zebra.h>

#include "stream.h"
#include "prefix.h"
#include "memory.h"
#include "log.h"
#include "zclient.h"
#include "if.h"

#include "ldp.h"
#include "ldp_struct.h"
#include "ldp_entity.h"
#include "mpls_mpls_impl.h"
#include "mpls_socket_impl.h"

#include "ldp_interface.h"
#include "impl_mpls.h"
#include "impl_fib.h"

#include "ldp_zebra.h"
#include "zclient.h"

static int label = 10000;
static int request = -2;
extern struct zclient *zclient;
extern struct list *pending_out_segment;
extern struct list *pending_ftn;
extern struct list *pending_xc;

static int new_request()
{
  request--;
  if (request > -2) {
    request = -2;
  }
  return request;
}

mpls_mpls_handle mpls_mpls_open(mpls_instance_handle user_data)
{
  return MPLS_SUCCESS;
}

void mpls_mpls_close(mpls_mpls_handle handle)
{
}

mpls_return_enum mpls_mpls_outsegment_add(mpls_mpls_handle handle, mpls_outsegment * o)
{
  struct zapi_mpls_out_segment out;
  struct interface *ifp;

  memset(&out, 0, sizeof(out));

  out.index = 0;
  out.req = new_request();
  out.owner = ZEBRA_ROUTE_LDP;
  out.nh.mpls.type = ZEBRA_MPLS_LABEL_GEN;
  out.nh.mpls.u.gen = o->label.u.gen;
  SET_FLAG (out.nh.type, ZEBRA_NEXTHOP_MPLS);

  if (o->nexthop.type & MPLS_NH_IP) {
    SET_FLAG (out.nh.type, ZEBRA_NEXTHOP_IPV4);
    out.nh.gw.ipv4.s_addr = htonl(o->nexthop.ip.u.ipv4);
  }

  if (o->nexthop.type & MPLS_NH_IF) {
    strcpy(out.nh.intf.name, o->nexthop.if_handle->name);
    SET_FLAG (out.nh.type, ZEBRA_NEXTHOP_IFNAME);
  } else {
    MPLS_ASSERT(o->nexthop.type & MPLS_NH_IP);

    ifp = if_lookup_address(out.nh.gw.ipv4);
    if (ifp) {
      strcpy(out.nh.intf.name, ifp->name);
      SET_FLAG (out.nh.type, ZEBRA_NEXTHOP_IFNAME);
    } else {
      return MPLS_FAILURE;
    }
  }

  /* store the request number as the handle, we'll need it when the
   * response from zebra arrives */
  o->handle = out.req;

  listnode_add(pending_out_segment, o);

  zapi_mpls_out_segment_add(zclient, &out);
  return MPLS_SUCCESS;
}

void mpls_mpls_outsegment_del(mpls_mpls_handle handle, mpls_outsegment * o)
{
  struct zapi_mpls_out_segment out;
  struct interface *ifp;
  struct listnode *n;

  memset(&out, 0, sizeof(out));

  out.index = 0;
  out.owner = ZEBRA_ROUTE_LDP;
  out.nh.mpls.type = ZEBRA_MPLS_LABEL_GEN;
  out.nh.mpls.u.gen = o->label.u.gen;
  SET_FLAG (out.nh.type, ZEBRA_NEXTHOP_MPLS);

  if (o->nexthop.type & MPLS_NH_IP) {
    SET_FLAG (out.nh.type, ZEBRA_NEXTHOP_IPV4);
    out.nh.gw.ipv4.s_addr = htonl(o->nexthop.ip.u.ipv4);
  }

  if (o->nexthop.type & MPLS_NH_IF) {
    strncpy(out.nh.intf.name, o->nexthop.if_handle->name, INTERFACE_NAMSIZ);
    SET_FLAG (out.nh.type, ZEBRA_NEXTHOP_IFNAME);
  } else {
    MPLS_ASSERT(o->nexthop.type & MPLS_NH_IP);

    ifp = if_lookup_address(out.nh.gw.ipv4);
    if (ifp) {
      strcpy(out.nh.intf.name, ifp->name);
      SET_FLAG (out.nh.type, ZEBRA_NEXTHOP_IFNAME);
    } else {
      return;
    }
  }

  /* the out segment might still be in the pending list, remove it */
  n = listnode_lookup(pending_out_segment, o);
  if (n) {
    list_delete_node(pending_out_segment, n);
  }

  out.index = o->handle;
  zapi_mpls_out_segment_delete(zclient, &out);
}

mpls_return_enum mpls_mpls_insegment_add(mpls_mpls_handle handle,
  mpls_insegment * i)
{
  struct zapi_mpls_in_segment api;

  if (i->label.type == MPLS_LABEL_TYPE_NONE) {
    i->label.type = MPLS_LABEL_TYPE_GENERIC;
    i->label.u.gen = label++;
  }

  api.owner = ZEBRA_ROUTE_LDP;
  api.labelspace = i->labelspace;
  api.protocol = i->family;
  api.pop = i->npop;
  api.label.type = ZEBRA_MPLS_LABEL_GEN;
  api.label.u.gen = i->label.u.gen;

  zapi_mpls_in_segment_add(zclient, &api);
  return MPLS_SUCCESS;
}

void mpls_mpls_insegment_del(mpls_mpls_handle handle, mpls_insegment * i)
{
  struct zapi_mpls_in_segment api;

  api.owner = ZEBRA_ROUTE_LDP;
  api.labelspace = i->labelspace;
  api.protocol = i->family;
  api.pop = i->npop;
  api.label.type = ZEBRA_MPLS_LABEL_GEN;
  api.label.u.gen = i->label.u.gen;

  zapi_mpls_in_segment_delete(zclient, &api);
}

mpls_return_enum mpls_mpls_xconnect_add(mpls_mpls_handle handle, mpls_insegment * i, mpls_outsegment * o)
{
  struct zapi_mpls_xc api;
  struct listnode *n;

  n = listnode_lookup(pending_out_segment, o);
  if (n) {
    struct pending_xc_data *x = XMALLOC(MTYPE_TMP,
	sizeof(struct pending_xc_data));
    x->o = o;
    x->i = i;
    x->h = handle;
    listnode_add(pending_xc, x);
    return MPLS_SUCCESS;
  }

  api.owner = ZEBRA_ROUTE_LDP;
  api.in_labelspace = i->labelspace;
  api.in_label.type = ZEBRA_MPLS_LABEL_GEN;
  api.in_label.u.gen = i->label.u.gen;
  api.out_index = o->handle;

  zapi_mpls_xc_add(zclient, &api);
  return MPLS_SUCCESS;
}

void mpls_mpls_xconnect_del(mpls_mpls_handle handle, mpls_insegment * i,
  mpls_outsegment * o)
{
  struct zapi_mpls_xc api;
  struct listnode *n;

  /* if its in the pending XC list, no need to send the delete because
   * the add was never sent
   */
  n = listnode_lookup(pending_xc, o);
  if (n) {
    list_delete_node(pending_xc, n);
    return;
  }

  api.owner = ZEBRA_ROUTE_LDP;
  api.in_labelspace = i->labelspace;
  api.in_label.type = ZEBRA_MPLS_LABEL_GEN;
  api.in_label.u.gen = i->label.u.gen;
  api.out_index = o->handle;

  zapi_mpls_xc_delete(zclient, &api);
}

mpls_return_enum mpls_mpls_fec2out_add(mpls_mpls_handle handle, mpls_fec * f,
  mpls_outsegment * o)
{
  struct zapi_mpls_ftn api;
  struct listnode *n;
  int retval;

  n = listnode_lookup(pending_out_segment, o);
  if (n) {
    struct pending_ftn_data *fn = XMALLOC(MTYPE_TMP,
	sizeof(struct pending_ftn_data));
    fn->o = o;
    fn->f = f;
    fn->h = handle;
    listnode_add(pending_ftn, fn);
    return MPLS_SUCCESS;
  }

  api.fec.type = ZEBRA_MPLS_FEC_IPV4;
  mpls_fec2zebra_prefix(f,&api.fec.u.p);
  api.out_index = o->handle;
  api.fec.owner = -1;
  api.owner = ZEBRA_ROUTE_LDP;

  retval = zapi_mpls_ftn_add(zclient, &api);
  return MPLS_SUCCESS;
}

void mpls_mpls_fec2out_del(mpls_mpls_handle handle, mpls_fec * f,
  mpls_outsegment * o)
{
  struct zapi_mpls_ftn api;
  struct listnode *n;
  int retval;

  /* if its in the pending FTN list, no need to send the delete because
   * the add was never sent
   */
  n = listnode_lookup(pending_ftn, o);
  if (n) {
    list_delete_node(pending_ftn, n);
    return;
  }

  api.fec.type = ZEBRA_MPLS_FEC_IPV4;
  mpls_fec2zebra_prefix(f,&api.fec.u.p);
  api.out_index = o->handle;
  api.fec.owner = -1;
  api.owner = ZEBRA_ROUTE_LDP;

  retval = zapi_mpls_ftn_delete(zclient, &api);
}

mpls_return_enum mpls_mpls_get_label_space_range(mpls_mpls_handle handle,
  mpls_range * r)
{
  r->type = MPLS_LABEL_RANGE_GENERIC;
  r->min.u.gen = 16;
  r->max.u.gen = 0xFFFFF;

  return MPLS_SUCCESS;
}
