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

#include <zebra.h>

#ifdef HAVE_MPLS

#include "linklist.h"
#include "memory.h"
#include "if.h"
#include "log.h"
#include "mpls_lib.h"
#include "redistribute.h"
#include "zclient.h"

extern struct zebra_t zebrad;
extern void rib_queue_add (struct zebra_t *zebra, struct route_node *rn);
void mpls_xc_unregister(struct zmpls_xc *old);

/*************************** out segment *****************************/

int
mpls_nexthop_ready(struct zapi_nexthop *nh)
{
  struct interface *ifp = NULL;
  int match = 0;
  int try = 0;

  if (CHECK_FLAG (nh->type, ZEBRA_NEXTHOP_IFINDEX))
    {
      ifp = if_lookup_by_index(nh->intf.index);
      try++;
      if (ifp && if_is_operative(ifp))
        match++;
    }
  else if (CHECK_FLAG (nh->type, ZEBRA_NEXTHOP_IFNAME))
    {
      ifp = if_lookup_by_name(nh->intf.name);
      try++;
      if (ifp && if_is_operative(ifp))
        match++;
    }

  if (CHECK_FLAG (nh->type, ZEBRA_NEXTHOP_IPV6))
    {

      try++;
      if (ifp)
        {
          struct listnode *node;
          struct connected *ifc;
          struct prefix np;
          memset (&np, 0, sizeof (struct prefix));

          np.family = AF_INET6;
          np.prefixlen = IPV6_MAX_PREFIXLEN;
          np.u.prefix6 = nh->gw.ipv6;

          for (ALL_LIST_ELEMENTS_RO(ifp->connected,node,ifc))
            {
              if (prefix_match(ifc->address, &np))
                {
                  match++;
                  break;
                }
            }
        }
    }
  else if (CHECK_FLAG (nh->type, ZEBRA_NEXTHOP_IPV4))
    {
      try++;
      if (!ifp)
        {
          ifp = if_lookup_address(nh->gw.ipv4);
          if (ifp && if_is_operative(ifp))
            match++;
        }
      else
        {
          struct listnode *node;
          struct connected *ifc;
          struct prefix np;
          memset (&np, 0, sizeof (struct prefix));

          np.family = AF_INET;
          np.prefixlen = IPV4_MAX_PREFIXLEN;
          np.u.prefix4 = nh->gw.ipv4;

          for (ALL_LIST_ELEMENTS_RO(ifp->connected,node,ifc))
            {
              if (prefix_match(ifc->address, &np))
                {
                  match++;
                  break;
                }
            }
        }
    }

  return (try && try == match) ? 1 : 0;
}

static
int mpls_out_segment_cmp(void *val1, void *val2)
{
  struct zmpls_out_segment *v1 = val1;
  struct zmpls_out_segment *v2 = val2;

  if (v1->index > v2->index)
  {
    return 1;
  }
  else if (v1->index < v2->index)
  {
    return -1;
  }
  return 0;
}

static int mpls_out_segment_nextindex = 1;

struct list mpls_out_segment_list = {
  .head = NULL,
  .tail = NULL, 
  .count = 0,
  .cmp = mpls_out_segment_cmp,
  .del = NULL,
};

unsigned int
mpls_out_segment_find_index_by_nexthop(struct zapi_nexthop *nh)
{
  struct listnode *node;
  struct zmpls_out_segment *old;

  for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list,node,old))
  {
    if (zapi_nexthop_match(&old->nh, nh, ZEBRA_NEXTHOP_ALL))
      goto found;
  }
  return 0;
found:
  return old->index;
}

unsigned int
mpls_out_segment_find_index_by_nhlfe(struct zmpls_out_segment *out)
{
  struct listnode *node;
  struct zmpls_out_segment *old;

  for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list,node,old))
  {
    if (old->owner == out->owner &&
	zapi_nexthop_match(&old->nh, &out->nh, ZEBRA_NEXTHOP_ALL))
      goto found;
  }
  return 0;
found:
  return old->index;
}

struct zmpls_out_segment*
mpls_out_segment_find(unsigned int index)
{
  struct listnode *node;
  struct zmpls_out_segment *old;

  for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list,node,old))
    if (index == old->index)
      goto found;

  return NULL;
found:
  return old;
}

struct zmpls_out_segment*
mpls_out_segment_find_by_out_key(unsigned int key)
{
  struct listnode *node;
  struct zmpls_out_segment *old;

  for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list,node,old))
    if (key == old->out_key)
      goto found;

  return NULL;
found:
  return old;
}

static int
do_mpls_out_segment_unregister(struct zmpls_out_segment *old)
{
  int ret = 0;
  if (old->owner != ZEBRA_ROUTE_KERNEL && old->installed)
    ret = mpls_ctrl_nhlfe_unregister(old);

  redistribute_delete_mpls_out_segment (old);
  LISTNODE_DETACH(&mpls_out_segment_list, &old->global);
  XFREE (MTYPE_TMP, old);
  return ret;
}

int
mpls_out_segment_unregister(struct zmpls_out_segment *out)
{
  struct zmpls_out_segment *old = mpls_out_segment_find (out->index);

  if (!old)
    return 1;

  return do_mpls_out_segment_unregister (old);
}

int
mpls_out_segment_unregister_by_index(unsigned int index)
{
  struct zmpls_out_segment *old = mpls_out_segment_find (index);

  if (!old)
    return 1;

  return do_mpls_out_segment_unregister (old);
}

int
mpls_out_segment_register(struct zmpls_out_segment *out)
{
  struct zmpls_out_segment *new;
  int err;

  if ((err = mpls_out_segment_find_index_by_nhlfe (out)))
    return err;

  new = XMALLOC (MTYPE_TMP, sizeof (struct zmpls_out_segment));
  if (!new)
    return -ENOMEM;

  memcpy (new, out, sizeof (struct zmpls_out_segment));

  new->global.data = new;
  new->global.next = NULL;
  new->global.prev = NULL;
  out->index = new->index = mpls_out_segment_nextindex++;
  new->installed = out->installed = 0;

  if (new->owner != ZEBRA_ROUTE_KERNEL)
  {
    if (mpls_nexthop_ready(&new->nh))
    {
      if ((err = mpls_ctrl_nhlfe_register(new))) {
	XFREE (MTYPE_TMP, new);
	return err;
      }
      out->out_key = new->out_key;
      new->installed = out->installed = 1;
    } else {
      /*
       * in the future we should add this to a specific list, instead of
       * relying on brute force search foreach interface/address event
       */
    }
  } else {
    new->installed = out->installed = 1;
  }

  LISTNODE_ATTACH(&mpls_out_segment_list, &new->global);

  if (new->installed)
    redistribute_add_mpls_out_segment (new);

  return 0;
}

/*************************** in segment *****************************/

struct list mpls_in_segment_list = {
  .head = NULL,
  .tail = NULL, 
  .count = 0,
  .cmp = NULL,
  .del = NULL,
};

int
mpls_in_segment_match(struct zmpls_in_segment *a, struct zmpls_in_segment *b)
{

  if (a->labelspace == b->labelspace)
    return mpls_label_match(&a->label, &b->label);

  return 0;
}

struct zmpls_in_segment*
mpls_in_segment_find(struct zmpls_in_segment *in)
{
  struct listnode *node;
  struct zmpls_in_segment *old;

  for (ALL_LIST_ELEMENTS_RO(&mpls_in_segment_list,node,old))
    if (mpls_in_segment_match(in, old))
      return old;

  return NULL;
}

static int
do_mpls_in_segment_unregister(struct zmpls_in_segment *in, int flag)
{
  if (in->installed)
    mpls_ctrl_ilm_unregister (in);

  if (in->xc)
  {
    struct zmpls_xc *xc = mpls_xc_find(in->xc);
    if (xc)
      mpls_xc_unregister (xc);
    else
      zlog_warn("do_mpls_in_segment_unregister: xc %d does not exist", in->xc);

    if (flag)
       mpls_out_segment_unregister_by_index (xc->out_index);
  }

  redistribute_delete_mpls_in_segment (in);
  LISTNODE_DETACH (&mpls_in_segment_list, &in->global);
  XFREE (MTYPE_TMP, in);

  return 0;
}

int
mpls_in_segment_unregister(struct zmpls_in_segment *in, int flag)
{
  struct zmpls_in_segment *old = mpls_in_segment_find (in);

  if (!old)
    return 1;

  return do_mpls_in_segment_unregister (old, flag);
}

int
mpls_in_segment_register(struct zmpls_in_segment *in, int install)
{
  struct zmpls_in_segment *new;
  int ret = 0;

  if (mpls_in_segment_find (in))
    return 1;

  new = XMALLOC (MTYPE_TMP, sizeof (*new));
  if (!new)
    return 1;

  memcpy (new, in, sizeof (*new));
  new->global.data = new;
  new->global.next = NULL;
  new->global.prev = NULL;
  new->xc = 0;

  if (new->owner != ZEBRA_ROUTE_KERNEL && install)
    ret = mpls_ctrl_ilm_register(new);

  if (ret) {
    XFREE (MTYPE_TMP, new);
    return ret;
  }

  LISTNODE_ATTACH(&mpls_in_segment_list, &new->global);
  redistribute_add_mpls_in_segment (new);
  return 0;
}

/******************************* cross connect ******************************/

static int mpls_xc_cmp(void *val1, void *val2)
{
  struct zmpls_xc *v1 = val1;
  struct zmpls_xc *v2 = val2;

  if (v1->index > v2->index)
    return 1;
  else if (v1->index < v2->index)
    return -1;
  return 0;
}

static int mpls_xc_nextindex = 1;

struct list mpls_xc_list = {
  .head = NULL,
  .tail = NULL, 
  .count = 0,
  .cmp = mpls_xc_cmp,
  .del = NULL,
};

struct zmpls_xc *mpls_xc_find(unsigned int index)
{
  struct listnode *node;
  struct zmpls_xc *xc;

  for (ALL_LIST_ELEMENTS_RO(&mpls_xc_list,node,xc))
    if (index == xc->index)
      return xc;

  return NULL;
}

int
mpls_xc_register(struct zmpls_xc *xc)
{
  struct zmpls_in_segment tmp;
  struct zmpls_out_segment *out;
  struct zmpls_in_segment *in;
  struct zmpls_xc *new;

  tmp.labelspace = xc->in_labelspace;
  memcpy(&tmp.label, &xc->in_label, sizeof(struct zmpls_label));
  in = mpls_in_segment_find (&tmp);
  out = mpls_out_segment_find (xc->out_index);

  if (in->xc)
    return 1;

  new = XMALLOC (MTYPE_TMP, sizeof (*new));
  if (!new)
    return 1;

  new->global.data = new;
  new->global.next = NULL;
  new->global.prev = NULL;

  new->in_labelspace = in->labelspace;
  memcpy(&new->in_label, &in->label, sizeof(struct zmpls_label));
  new->out_index = out->index;
  new->index = mpls_xc_nextindex++;
  in->xc = new->index;

  LISTNODE_ATTACH(&mpls_xc_list, &new->global);

  if (in->owner != ZEBRA_ROUTE_KERNEL)
  {
    if (in->installed && out->installed)
    {
      mpls_ctrl_xc_register(in, out);
      new->installed = xc->installed = 1;
    } else {
      new->installed = xc->installed = 0;
    }
  } else {
    new->installed = xc->installed = 1;
  }

  if (new->installed)
    redistribute_add_mpls_xc (new);

  return 0;
}

void
mpls_xc_unregister(struct zmpls_xc *old)
{
  struct zmpls_out_segment *out;
  struct zmpls_in_segment *in;
  struct zmpls_in_segment tmp;

  tmp.labelspace = old->in_labelspace;
  memcpy(&tmp.label, &old->in_label, sizeof(struct zmpls_label));
  in = mpls_in_segment_find(&tmp);
  out = mpls_out_segment_find(old->out_index);

  if (old->installed)
    mpls_ctrl_xc_unregister(in, out);

  in->xc = 0;

  redistribute_delete_mpls_xc(old);
  LISTNODE_DETACH(&mpls_xc_list, &old->global);
  XFREE (MTYPE_TMP, old);
}

/*********************************** FTN **********************************/

static int mpls_ftn_cmp(void *val1, void *val2)
{
  struct zmpls_xc *v1 = val1;
  struct zmpls_xc *v2 = val2;

  if (v1->index > v2->index)
    return 1;
  else if (v1->index < v2->index)
    return -1;
  return 0;
}

static int mpls_ftn_nextindex = 1;

struct list mpls_ftn_list = {
  .head = NULL,
  .tail = NULL, 
  .count = 0,
  .cmp = mpls_ftn_cmp,
  .del = NULL,
};

struct zmpls_ftn*
mpls_ftn_find(unsigned int index)
{
  struct listnode *node;
  struct zmpls_ftn *ftn;

  for (ALL_LIST_ELEMENTS_RO(&mpls_ftn_list,node,ftn))
    if (index == ftn->index)
      return ftn;

  return NULL;
}

struct zmpls_ftn*
mpls_ftn_find_by_prefix(struct prefix* p)
{
  struct listnode *node;
  struct zmpls_ftn *ftn;

  for (ALL_LIST_ELEMENTS_RO(&mpls_ftn_list,node,ftn))
    if ((ftn->fec.type == ZEBRA_MPLS_FEC_IPV4 ||
	ftn->fec.type == ZEBRA_MPLS_FEC_IPV6) &&
	prefix_match(&ftn->fec.u.p, p))
      return ftn;

  return NULL;
}

struct zmpls_ftn*
mpls_ftn_find_by_fec(struct zmpls_fec* fec)
{
  struct listnode *node;
  struct zmpls_ftn *ftn;

  for (ALL_LIST_ELEMENTS_RO(&mpls_ftn_list,node,ftn))
    if (mpls_fec_match(fec, &ftn->fec))
      return ftn;

  return NULL;
}

static struct zmpls_ftn*
do_mpls_ftn_register(struct zmpls_ftn *ftn)
{
  struct zmpls_ftn *new;

  new = XMALLOC (MTYPE_TMP, sizeof (*new));
  if (!new)
    return NULL;

  memcpy (new, ftn, sizeof (*new));

  new->global.data = new;
  new->global.next = NULL;
  new->global.prev = NULL;

  new->index = mpls_ftn_nextindex++;
  ftn->index = new->index;

  LISTNODE_ATTACH(&mpls_ftn_list, &new->global);
  mpls_ctrl_ftn_register(new);
  redistribute_add_mpls_ftn (new);
  return new;
}

void
mpls_ftn_register_finish(struct zmpls_ftn *ftn, struct route_node *rn,
  struct rib *rib, struct nexthop *nh)
{
  struct nexthop *newnh;
  struct zmpls_out_segment *out;

  if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
    {
      rib_uninstall_kernel (rn, rib);
      UNSET_FLAG (rib->flags, ZEBRA_FLAG_SELECTED);
    }

  SET_FLAG (nh->flags, NEXTHOP_FLAG_IGNORE);
  out = mpls_out_segment_find(ftn->out_index);
  newnh = nexthop_zapi_nexthop_add(rib, &out->nh);
  newnh->tied = nh;
  nh->tied = newnh;

  SET_FLAG (rib->flags, ZEBRA_FLAG_CHANGED_MPLS);
  rib_queue_add (&zebrad, rn);
}

int
mpls_ftn_register(struct zmpls_ftn *ftn, int modify)
{
  struct zmpls_out_segment *out;
  struct zmpls_ftn *new;
  if (!(out = mpls_out_segment_find(ftn->out_index)))
    {
      zlog_warn("mpls_ftn_register: unable to find outsegment with index %d",
        ftn->out_index);
      return 1;
    }

  if (!(new = do_mpls_ftn_register(ftn)))
    return 1;
  
  switch (ftn->fec.type)
  {
    case ZEBRA_MPLS_FEC_IPV4:
    case ZEBRA_MPLS_FEC_IPV6:
    {  
      struct route_node *rn = NULL;
      struct nexthop *nh = NULL;
      struct rib *rib = NULL;
      struct nexthop nh_in;

      zapi_nexthop2nexthop(&out->nh, &nh_in);

      if (modify)
      {
        rib_find_nexthop(ftn->fec.owner, &ftn->fec.u.p, &nh_in,&rn,&rib,&nh);
        if (rn)
	{
          mpls_ftn_register_finish(ftn, rn, rib, nh);
          route_unlock_node(rn);
	} else {
	  char str[33];
	  prefix2str(&ftn->fec.u.p, str, sizeof(str));
          zlog_warn("mpls_ftn_register: unable to find FEC %s", str);
        }
      } else {
        zlog_warn("mpls_ftn_register: modify flag not set");
      }
      break;
    }
    default:
      assert(0);
      break;
  }
  return 0;
}

static void
do_mpls_ftn_unregister(struct zmpls_ftn *ftn)
{
  mpls_ctrl_ftn_unregister(ftn);

  redistribute_delete_mpls_ftn(ftn);
  LISTNODE_DETACH(&mpls_ftn_list, &ftn->global);
  XFREE (MTYPE_TMP, ftn);
}

void
mpls_ftn_unregister_finish(struct zmpls_ftn *ftn, struct route_node *rn,
  struct rib *rib, struct nexthop *nh)
{
  if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
    {
      rib_uninstall_kernel (rn, rib);
      UNSET_FLAG (rib->flags, ZEBRA_FLAG_SELECTED);
    }

  if (nh->tied)
    {
      if (CHECK_FLAG (nh->flags, NEXTHOP_FLAG_IGNORE))
        {
	  /* we've been handed the original non-mpls nexthop */
          UNSET_FLAG (nh->flags, NEXTHOP_FLAG_IGNORE);
          nexthop_delete (rib, nh->tied);
          nexthop_free (nh->tied);
          nh->tied = NULL;
        }
      else
        {
	  /* we've been handed the mpls nexthop */
          UNSET_FLAG (nh->tied->flags, NEXTHOP_FLAG_IGNORE);
          nh->tied->tied = NULL;
          nexthop_delete (rib, nh);
          nexthop_free (nh);
        }
  }

  SET_FLAG (rib->flags, ZEBRA_FLAG_CHANGED_MPLS);
  rib_queue_add (&zebrad, rn);
}

void
mpls_ftn_unregister(struct zmpls_ftn *ftn, int modify)
{
  struct zmpls_out_segment *out;
  if (!(out = mpls_out_segment_find(ftn->out_index)))
    return;

  switch (ftn->fec.type)
  {
    case ZEBRA_MPLS_FEC_IPV4:
    case ZEBRA_MPLS_FEC_IPV6:
    {
      struct route_node *rn = NULL;
      struct nexthop *nh = NULL;
      struct rib *rib = NULL;
      struct nexthop nh_in;

      zapi_nexthop2nexthop(&out->nh, &nh_in);

      if (modify)
      {
        rib_find_nexthop(ftn->fec.owner, &ftn->fec.u.p, &nh_in,&rn,&rib,&nh);
	if (rn)
	{
	  mpls_ftn_unregister_finish(ftn, rn, rib, nh);
	  route_unlock_node(rn);
	}
      }
      break;
    }
    default:
      assert(0);
      break;
  }
  do_mpls_ftn_unregister(ftn);
}

void
mpls_init (void)
{
}

void
mpls_close (void)
{
  struct listnode *node;

  while ((node = listhead (&mpls_in_segment_list)))
    do_mpls_in_segment_unregister ((struct zmpls_in_segment*)listgetdata (node), 0);

  while ((node = listhead (&mpls_out_segment_list)))
    do_mpls_out_segment_unregister ((struct zmpls_out_segment*)listgetdata (node));
}

#endif /* HAVE_MPLS */
