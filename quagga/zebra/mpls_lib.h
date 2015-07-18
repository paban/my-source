/*
 * MPLS Label Information Base for zebra daemon.
 *
 * Copyright (C) 2004 James R. Leu 
 *
 * This file is part of Quagga routing suite.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_MPLS_LIB_H
#define _ZEBRA_MPLS_LIB_H

#ifdef LINUX_MPLS
#include <linux/mpls.h>
#endif

#include "zclient.h"
#include "table.h"
#include "vty.h"
#include "zebra/rib.h"

struct zmpls_in_segment
{
  struct listnode global;
  u_char installed;
  u_char owner;
  u_char labelspace;
  u_short protocol;
  u_int xc;
  struct zmpls_label label;
  u_char pop;
};

struct zmpls_out_segment
{
  struct listnode global;
  u_char installed;
  u_char owner;
  struct zapi_nexthop nh;
  u_int index;
  u_int out_key;
};

struct zmpls_xc
{
  struct listnode global;
  u_char installed;
  u_char owner;
  u_int index;
  u_char in_labelspace;
  struct zmpls_label in_label;
  u_int out_index;
};

struct zmpls_ftn
{
  struct listnode global;
  u_char installed;
  u_char owner;
  u_int index;
  struct zmpls_fec fec;
  u_int out_index;
};

extern struct list mpls_xc_list;
extern struct list mpls_ftn_list;
extern struct list mpls_in_segment_list;
extern struct list mpls_out_segment_list;

extern int
mpls_nexthop_ready(struct zapi_nexthop *nh);

extern int
mpls_in_segment_match(struct zmpls_in_segment *a, struct zmpls_in_segment *b);

extern struct zmpls_in_segment*
mpls_in_segment_find(struct zmpls_in_segment *in);

extern int
mpls_in_segment_register(struct zmpls_in_segment *in, int install);

extern int
mpls_in_segment_unregister(struct zmpls_in_segment *in, int flag);

extern int
mpls_out_segment_register(struct zmpls_out_segment *out);

extern int
mpls_out_segment_unregister(struct zmpls_out_segment *out);

extern int
mpls_out_segment_unregister_by_index(unsigned int index);

extern int
mpls_labelspace_register(int labelspace);

extern int
mpls_labelspace_unregister(int labelspace);

extern int
mpls_labelspace_is_registered(int labelspace);

extern struct zmpls_out_segment*
mpls_out_segment_find(unsigned int index);

struct zmpls_out_segment*
mpls_out_segment_find_by_out_key(unsigned int key);

extern unsigned int
mpls_out_segment_find_index_by_nhlfe (struct zmpls_out_segment *out);

extern unsigned int
mpls_out_segment_find_index_by_nexthop(struct zapi_nexthop *nh);

extern struct zmpls_xc* mpls_xc_find (unsigned int);

extern int
mpls_xc_register (struct zmpls_xc *xc);

extern void
mpls_xc_unregister (struct zmpls_xc *xc);

extern struct zmpls_ftn* mpls_ftn_find (unsigned int);

extern struct zmpls_ftn*
mpls_ftn_find_by_fec(struct zmpls_fec* fec);

extern int
mpls_ftn_register (struct zmpls_ftn *ftn, int modify);

extern void
mpls_ftn_register_finish(struct zmpls_ftn *ftn, struct route_node *rn,
  struct rib *rib, struct nexthop *nh);

extern void
mpls_ftn_unregister (struct zmpls_ftn *ftn, int modify);

extern void
mpls_ftn_unregister_finish(struct zmpls_ftn *ftn, struct route_node *rn,
  struct rib *rib, struct nexthop *nh);

extern int
mpls_ctrl_init(void);

extern int
mpls_ctrl_show_hardware(struct vty *vty);

extern int
mpls_ctrl_nhlfe_unregister(struct zmpls_out_segment *old);

extern int
mpls_ctrl_nhlfe_register(struct zmpls_out_segment *new);

extern int
mpls_ctrl_ilm_unregister(struct zmpls_in_segment *old);

extern int
mpls_ctrl_ilm_register(struct zmpls_in_segment *new);

extern int
mpls_ctrl_xc_register(struct zmpls_in_segment *in,
    struct zmpls_out_segment *out);

extern int
mpls_ctrl_xc_unregister(struct zmpls_in_segment *in,
    struct zmpls_out_segment *out);

extern int
mpls_ctrl_ftn_register(struct zmpls_ftn *ftn);

extern int
mpls_ctrl_ftn_unregister(struct zmpls_ftn *ftn);

extern int
mpls_ctrl_set_interface_labelspace(struct interface *ifp, int labelspace);

extern int
mpls_ctrl_tunnel_register(struct interface *ifp, int update);

extern int
mpls_ctrl_tunnel_unregister(struct interface *ifp);

extern int
mpls_ctrl_read(void);

extern void
mpls_init(void);

extern void
mpls_close(void);

#endif /* _ZEBRA_MPLS_VTY_H */
