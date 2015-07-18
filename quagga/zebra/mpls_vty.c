/*
 * MPLS CLI for zebra daemon.
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

#include "zclient.h"
#include "vty.h"
#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "mpls_lib.h"
#include "if.h"
#include "connected.h"
#include "interface.h"
#include "ioctl.h"
#include "zserv.h"
#include "router-id.h"
#include "mpls_vty.h"

static
int label_parse(struct vty *vty, const char **argv, struct zmpls_label *label)
{
  if (!strncmp(argv[0], "gen", 3))
  {
    label->type = ZEBRA_MPLS_LABEL_GEN;
  }
  else if (!strncmp(argv[0], "atm", 3))
  {
    label->type = ZEBRA_MPLS_LABEL_ATM;
  }
  else if (!strncmp(argv[0], "fr", 2))
  {
    label->type = ZEBRA_MPLS_LABEL_FR;
  }
  else
  {
    vty_out (vty, "'%s' is not a valid label type (gen|atm|fr)%s",
      argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  switch (label->type)
  {
    case ZEBRA_MPLS_LABEL_GEN:
      if ((!sscanf(argv[1], "%u", &label->u.gen)))
      {
        vty_out (vty, "'%s' is not an valid gen label value (16 .. 2^20 - 1)%s",
          argv[1], VTY_NEWLINE);
        return CMD_WARNING;
      }
      break;
    case ZEBRA_MPLS_LABEL_ATM:
      if ((sscanf(argv[1], "%hu/%hu", &label->u.atm.vpi,
	&label->u.atm.vci) != 2))
      {
        vty_out (vty, "'%s' is not an valid atm label value (vpi/vci)%s",
          argv[1], VTY_NEWLINE);
        return CMD_WARNING;
      }
      break;
    case ZEBRA_MPLS_LABEL_FR:
      if ((!sscanf(argv[1], "%u", &label->u.fr)))
      {
        vty_out (vty, "'%s' is not an valid fr label value (1 .. 2^17 - 1)%s",
          argv[1], VTY_NEWLINE);
        return CMD_WARNING;
      }
      break;
  }
  return CMD_SUCCESS;
}

int
nhlfe_parse(struct vty *vty, const char **argv, struct zmpls_out_segment *out,
  const char* addr)
{
  struct prefix p;
  int result;

  result = label_parse (vty, argv, &out->nh.mpls);
  if (result != CMD_SUCCESS)
    return result;

  strncpy(out->nh.intf.name, argv[2], IFNAMSIZ);
  SET_FLAG (out->nh.type, ZEBRA_NEXTHOP_IFNAME);

  if (addr)
  {
    str2prefix (addr, &p);
    if ((p.family == AF_INET && p.prefixlen != IPV4_MAX_BITLEN) ||
        (p.family == AF_INET6 && p.prefixlen != IPV6_MAX_BITLEN))
    {
      vty_out (vty, "Nexthop IP address must be a host address(%s)%s",
	addr, VTY_NEWLINE);
      return CMD_WARNING;
    }
    switch (p.family)
    {
      case AF_INET:
        if (p.prefixlen != IPV4_MAX_BITLEN)
        {
          vty_out (vty, "Nexthop IP address must be a host address(%s)%s",
            addr, VTY_NEWLINE);
          return CMD_WARNING;
        }
        out->nh.gw.ipv4 = p.u.prefix4;
        SET_FLAG (out->nh.type, ZEBRA_NEXTHOP_IPV4);
        break;
      case AF_INET6:
        if (p.prefixlen != IPV6_MAX_BITLEN)
        {  
          vty_out (vty, "Nexthop IP address must be a host address(%s)%s",
            addr, VTY_NEWLINE);
          return CMD_WARNING;
        }
        out->nh.gw.ipv6 = p.u.prefix6;
        SET_FLAG (out->nh.type, ZEBRA_NEXTHOP_IPV6);
        break;
      default:
        vty_out (vty, "Invalid nexthop(%s)%s", addr, VTY_NEWLINE);
        return CMD_WARNING;
        break;
    }
  }
  return CMD_SUCCESS;
}

/******************************** vty commands ******************************/

DEFUN (mpls_static_num,
       mpls_static_num_cmd,
       "mpls static <0-255>",
       "Multi-protocol Label Switching\n"
       "Static label information base\n"
       "Labelspace number\n")
{
    int labelspace = -1;
    if (!sscanf(argv[0], "%u", &labelspace)) {
	vty_out (vty, "'%s' is not an valid labelspace (0 .. 255)%s",
	    argv[0], VTY_NEWLINE);
	return CMD_WARNING;
    }
    vty->index = (void*)labelspace;
    vty->node = MPLS_LABELSPACE_NODE;
    return CMD_SUCCESS;
}

DEFUN (no_mpls_static_num,
       no_mpls_static_num_cmd,
       "no mpls static <0-255>",
       NO_STR
       "Multi-protocol Label Switching\n"
       "Static labeling information\n"
       "Labelspace number\n")
{
    struct listnode *node;
    struct listnode *nnode;
    struct zmpls_in_segment *in;
    int labelspace = -1;

    if (!sscanf(argv[0], "%u", &labelspace)) {
	vty_out (vty, "'%s' is not an valid labelspace (0 .. 255)%s",
	    argv[0], VTY_NEWLINE);
	return CMD_WARNING;
    }

    for (ALL_LIST_ELEMENTS(&mpls_in_segment_list, node, nnode, in))
	if (in->labelspace == labelspace)
	    mpls_in_segment_unregister(in, 1);

    return CMD_SUCCESS;
}

DEFUN (label_map_pop,
       label_map_pop_cmd,
       "label-map (gen|atm|fr) VALUE pop",
       "Create a static incoming label-map (ILM)\n"
       "In-coming Generic label\n"
       "In-coming ATM VC\n"
       "In-coming FR DLCI\n"
       "Label value\n"
       "Pop and lookup\n")
{
  struct zmpls_in_segment in;
  int result;

  in.owner = ZEBRA_ROUTE_STATIC;
  in.labelspace = (int)vty->index;

  result = label_parse(vty,argv,&in.label);
  if (result != CMD_SUCCESS)
    return result;

  in.pop = 1;

  return mpls_in_segment_register(&in, 1) ? CMD_WARNING : CMD_SUCCESS;
}

static int
create_ilm_xc_nhlfe(struct vty *vty, const char **ilm, const char **nhlfe,
  const char *addr)
{
  struct zmpls_in_segment in;
  struct zmpls_out_segment out;
  struct zmpls_xc xc;
  int result;

  in.owner = ZEBRA_ROUTE_STATIC;

  in.labelspace = (int)vty->index;

  result = label_parse (vty, ilm, &in.label);
  if (result != CMD_SUCCESS)
    return result;

  memset (&out, 0, sizeof (out));
  out.owner = ZEBRA_ROUTE_STATIC;
  result = nhlfe_parse (vty, nhlfe, &out, addr);
  if (result != CMD_SUCCESS)
    return result;

  if (mpls_out_segment_find_index_by_nhlfe(&out))
  {
    vty_out(vty, "NHLFE already exists%s",VTY_NEWLINE);
    goto error_out;
  }

  out.index = 0;
  if (mpls_out_segment_register (&out))
  {
    vty_out(vty, "Unable to register NHLFE%s",VTY_NEWLINE);
    goto error_out;
  }

  in.pop = 1;
  if (mpls_in_segment_register (&in, (out.installed)))
  {
    goto error_in;
  }

  xc.in_labelspace = in.labelspace;
  memcpy(&xc.in_label, &in.label, sizeof(struct zmpls_label));
  xc.out_index = out.index;

  if (mpls_xc_register (&xc))
  {
    goto error_xc;
  }
  return CMD_SUCCESS;

error_xc:
  mpls_in_segment_unregister (&in, 1);

error_in:
  mpls_out_segment_unregister (&out);

error_out:
  return CMD_WARNING;
}

DEFUN (label_map_swap_if,
       label_map_swap_if_cmd,
       "label-map (gen|atm|fr) VALUE swap (gen|atm|fr) VALUE nexthop INTERFACE",
       "Create a static incoming label-map (ILM)\n"
       "In-coming Generic label\n"
       "In-coming ATM VC\n"
       "In-coming FR DLCI\n"
       "Label value\n"
       "Forward\n"
       "Out-going Generic label\n"
       "Out-going ATM VC\n"
       "Out-going FR DLCI\n"
       "Label value\n"
       "Nexthop\n"
       "Out-going interface name\n")
{
  return create_ilm_xc_nhlfe(vty, argv, &argv[2], NULL);
}

DEFUN (label_map_swap_if_addr,
       label_map_swap_if_addr_cmd,
       "label-map (gen|atm|fr) VALUE swap (gen|atm|fr) VALUE nexthop INTERFACE IPADDR",
       "Incoming label-map (ILM)\n"
       "In-coming Generic label\n"
       "In-coming ATM VC\n"
       "In-coming FR DLCI\n"
       "Label value\n"
       "Forward\n"
       "Out-going Generic label\n"
       "Out-going ATM VC\n"
       "Out-going FR DLCI\n"
       "Label value\n"
       "Nexthop\n"
       "Out-going interface name\n"
       "Nexthop IP address\n")
{
  return create_ilm_xc_nhlfe(vty, argv, &argv[2], argv[5]);
}

DEFUN (no_label_map,
       no_label_map_cmd,
       "no label-map (gen|atm|fr) VALUE",
       NO_STR
       "Incoming label-map (ILM)\n"
       "In-coming Generic label\n"
       "In-coming ATM VC\n"
       "In-coming FR DLCI\n"
       "Label value\n")
{
  struct zmpls_in_segment in;
  int result;

  in.labelspace = (int)vty->index;

  result = label_parse(vty, argv, &in.label);
  if (result != CMD_SUCCESS)
    return result;

  return mpls_in_segment_unregister(&in, 1) ? CMD_WARNING : CMD_SUCCESS;
}

static void
mpls_interface_show_write (struct vty *vty, struct interface *ifp)
{
  struct zebra_if *if_data;
  if_data = ifp->info;

  vty_out (vty, " Static MPLS tunnel out-segment: ");
  if (if_data && if_data->ops && if_data->ops->info)
  {
    struct zmpls_out_segment *out;

    out = mpls_out_segment_find_by_out_key((int)if_data->ops->info);
    if (out)
    {
      mpls_out_segment_config_write (vty, out);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
    else
    {
      vty_out (vty, "  (invalid)%s", VTY_NEWLINE);
    }
  }
  else
  {
    vty_out (vty, "  (not configured)%s", VTY_NEWLINE);
  }
}

DEFUN (mpls_labelspace,
       mpls_labelspace_cmd,
       "mpls labelspace <0-255>",
       "MPLS interface configuration\n"
       "labelspace\n"
       "labelspace number\n")
{
  struct interface *ifp;
  int labelspace = atoi(argv[0]);

  ifp = vty->index;
  vty_out(vty, "Labelspace: %d%s",labelspace, VTY_NEWLINE);
  if (labelspace < 0) {
    vty_out(vty, "%% Invalid labelspace '%s'%s",argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  mpls_ctrl_set_interface_labelspace(ifp, labelspace);
  ifp->mpls_labelspace = labelspace;
  redistribute_add_mpls_labelspace (ifp);

  return CMD_SUCCESS;
}

DEFUN (no_mpls_labelspace,
       no_mpls_labelspace_cmd,
       "no mpls labelspace",
       NO_STR
       "MPLS interface configuration\n"
       "labelspace\n")
{
  struct interface *ifp;
  ifp = vty->index;

  mpls_ctrl_set_interface_labelspace(ifp, -1);
  redistribute_delete_mpls_labelspace (ifp);
  ifp->mpls_labelspace = -1;

  return CMD_SUCCESS;
}

void mpls_print_label(struct zmpls_label *label, char *buf)
{
  switch (label->type)
  {
    case ZEBRA_MPLS_LABEL_GEN:
      sprintf(buf, "%u", label->u.gen);
      break;
    case ZEBRA_MPLS_LABEL_ATM:
      sprintf(buf, "%hu/%hu", label->u.atm.vpi, label->u.atm.vci);
      break;
    case ZEBRA_MPLS_LABEL_FR:
      sprintf(buf, "%u", label->u.fr);
      break;
  }
}

DEFUN (mpls_show_mpls_fwd,
       mpls_show_mpls_fwd_cmd,
       "show mpls forwarding",
       SHOW_STR
       "MPLS commands\n"
       "forwarding table\n")
{
  struct zmpls_out_segment *out;
  struct zmpls_in_segment *in;
  struct zmpls_xc *xc;
  struct listnode *node;
  int count;

  vty_out(vty, "Insegments:%s",VTY_NEWLINE);

  count = 0;
  for (ALL_LIST_ELEMENTS_RO(&mpls_in_segment_list, node, in)) 
  {
    char buf[16];

    mpls_print_label(&in->label, buf);

    if (!count) {
      vty_out(vty, "  Lbl Spc  Label Owner%s", VTY_NEWLINE);
    }
    vty_out(vty, "    %-3d  %7s %-6s", in->labelspace,
      buf, zebra_route_string(in->owner));

    if (!in->installed)
      vty_out(vty, " (inactive)");

    vty_out(vty, "%s", VTY_NEWLINE);
    count++;
  }
  if (!count) {
    vty_out(vty, "%s", VTY_NEWLINE);
  }
  vty_out(vty, "Total %d%s",count, VTY_NEWLINE);
  vty_out(vty, "%s", VTY_NEWLINE);

  vty_out(vty, "Outsegments:%s",VTY_NEWLINE);
  count = 0;
  for (ALL_LIST_ELEMENTS_RO(&mpls_out_segment_list, node, out))
  {
    char buf2[16];
    char buf[48];
    char *ifname = NULL;

    if (!count) {
      vty_out (vty, "  Interface          Label Next Hop        Owner%s",
        VTY_NEWLINE);
    }

    if (CHECK_FLAG (out->nh.type, ZEBRA_NEXTHOP_IFNAME))
    {
      ifname = out->nh.intf.name;
    } else {
      ifname = "(remote)";
    }

    if (CHECK_FLAG (out->nh.type, ZEBRA_NEXTHOP_IPV4))
    {
      inet_ntop (AF_INET, &out->nh.gw.ipv4, buf, sizeof(buf));
    } else if (CHECK_FLAG (out->nh.type, ZEBRA_NEXTHOP_IPV6)) {
      inet_ntop (AF_INET6, &out->nh.gw.ipv6, buf, sizeof(buf));
    } else {
      strcpy (buf, "0.0.0.0");
    }

    mpls_print_label(&out->nh.mpls, buf2);

    vty_out(vty, "  %-16s %7s %-15s %-6s",  ifname, 
      buf2, buf, zebra_route_string(out->owner));

    if (!out->installed)
      vty_out(vty, " (inactive)");

    vty_out(vty, "%s", VTY_NEWLINE);
    count++;
  }
  if (!count) {
    vty_out(vty, "%s", VTY_NEWLINE);
  }
  vty_out(vty, "Total %d%s",count, VTY_NEWLINE);
  vty_out(vty, "%s", VTY_NEWLINE);

  vty_out(vty, "Cross Connects:%s",VTY_NEWLINE);
  count = 0;
  for (ALL_LIST_ELEMENTS_RO(&mpls_xc_list, node, xc))
  {
    char buf[48];
    char buf2[48];
    char buf3[48];
    char *ifname = NULL;
    struct zmpls_in_segment tmp;
    struct zmpls_in_segment *in;
    struct zmpls_out_segment *out;

    out = mpls_out_segment_find(xc->out_index);

    tmp.labelspace = xc->in_labelspace;
    memcpy(&tmp.label, &xc->in_label, sizeof(struct zmpls_label));
    in = mpls_in_segment_find(&tmp);

    if (!count) {
      vty_out(vty, "  Lbl Spc  In Label Out Label Interface        "
        "Next Hop        Owner%s", VTY_NEWLINE);
    }

    mpls_print_label(&in->label, buf);
    mpls_print_label(&out->nh.mpls, buf2);

    if (CHECK_FLAG (out->nh.type, ZEBRA_NEXTHOP_IFNAME))
    {
      ifname = out->nh.intf.name;
    } else {
      ifname = "(remote)";
    }

    if (CHECK_FLAG (out->nh.type, ZEBRA_NEXTHOP_IPV4))
    {
      inet_ntop (AF_INET, &out->nh.gw.ipv6, buf3, sizeof(buf3));
    } else if (CHECK_FLAG (out->nh.type, ZEBRA_NEXTHOP_IPV6)) {
      inet_ntop (AF_INET6, &out->nh.gw.ipv6, buf3, sizeof(buf3));
    } else {
      strcpy (buf3, "0.0.0.0");
    }

    vty_out(vty, "    %-3d     %7s   %7s %-16s %-15s %-6s",
      xc->in_labelspace, buf, buf2, ifname, buf3,
      zebra_route_string(in->owner));

    if (!xc->installed)
      vty_out(vty, " (inactive)");

    vty_out(vty, "%s", VTY_NEWLINE);
    count++;
  }
  if (!count) {
      vty_out(vty, "%s", VTY_NEWLINE);
  }
  vty_out(vty, "Total %d%s",count, VTY_NEWLINE);
  vty_out(vty, "%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

#ifdef LINUX_MPLS
DEFUN (mpls_show_mpls_version,
       mpls_show_mpls_version_cmd,
       "show mpls version",
       SHOW_STR
       "MPLS 'show' commands\n"
       "Show MPLS version\n")
{
  vty_out(vty, "Version %d.%d%d%d%s", (MPLS_LINUX_VERSION >> 24) & 0xFF,
    (MPLS_LINUX_VERSION >> 16) & 0xFF, (MPLS_LINUX_VERSION >> 8) & 0xFF,
    (MPLS_LINUX_VERSION) & 0xFF, VTY_NEWLINE);
  return CMD_SUCCESS;
}
#endif

DEFUN (mpls_show_mpls_hardware,
       mpls_show_mpls_hardware_cmd,
       "show mpls hardware",
       SHOW_STR
       "MPLS 'show' commands\n"
       "Show MPLS forwarder type\n")
{
  return mpls_ctrl_show_hardware(vty);
}

static void
mpls_label_config_write (struct vty *vty, struct zmpls_label *label)
{
  switch (label->type)
  {
    case ZEBRA_MPLS_LABEL_GEN:
      vty_out (vty, "gen %d", label->u.gen);
      break;
    case ZEBRA_MPLS_LABEL_ATM:
      vty_out (vty, "atm %d/%d", label->u.atm.vpi, label->u.atm.vci);
      break;
    case ZEBRA_MPLS_LABEL_FR:
      vty_out (vty, "fr %d", label->u.fr);
      break;
  }
}

void
mpls_out_segment_config_write (struct vty *vty, struct zmpls_out_segment *out)
{
  char buf[128] = "";

  mpls_label_config_write (vty, &out->nh.mpls);
  vty_out (vty, " nexthop");

  if (CHECK_FLAG (out->nh.type, ZEBRA_NEXTHOP_IFNAME))
  {
      vty_out (vty, " %s", out->nh.intf.name);
  }

  if (CHECK_FLAG (out->nh.type, ZEBRA_NEXTHOP_IPV6))
  {
      inet_ntop (AF_INET6, &out->nh.gw.ipv6, buf, sizeof (buf));
  }
  else if (CHECK_FLAG (out->nh.type, ZEBRA_NEXTHOP_IPV4))
  {
      inet_ntop (AF_INET, &out->nh.gw.ipv4, buf, sizeof (buf));
  }
  vty_out (vty, " %s", buf);
}

static void
mpls_in_segment_config_write (struct vty *vty, struct zmpls_in_segment *in)
{
  mpls_label_config_write (vty, &in->label);

  if (in->xc)
  {
    struct zmpls_out_segment *out;
    struct zmpls_xc *xc;

    vty_out (vty, " swap ");
    xc = mpls_xc_find (in->xc);
    out = mpls_out_segment_find (xc->out_index);
    if (out)
    {
      mpls_out_segment_config_write (vty, out);
    }
    else
    {
      vty_out (vty, "(unable to find out-segment with index %d)", in->xc);
    }
  } else if (in->pop) {
    vty_out (vty, " pop");
  } else {
    vty_out (vty, "(invalid ILM)");
  }
}

static int
mpls_static_config_write (struct vty *vty)
{
  struct listnode *node;
  struct zmpls_in_segment *in;
  int labelspace;
  int first;

  for (labelspace = 0;labelspace < 256;labelspace++)
  {
    first = 1;

    for (ALL_LIST_ELEMENTS_RO (&mpls_in_segment_list, node, in))
    {
      if (in->owner != ZEBRA_ROUTE_STATIC &&
	  in->owner != ZEBRA_ROUTE_KERNEL )
        continue;

      if (in->labelspace != labelspace)
        continue;

      if (first)
        vty_out (vty, "mpls static %d%s", labelspace, VTY_NEWLINE);

      vty_out (vty, " label-map ");
      mpls_in_segment_config_write (vty, in);
      vty_out (vty, "%s", VTY_NEWLINE);
      first = 0;
    }
    vty_out (vty, "!%s", VTY_NEWLINE);
  }
  return 0;
}

static
struct cmd_node mpls_static_node =
{
  MPLS_LABELSPACE_NODE,
  "%s(config-ls)# ",
  1
};

void
mpls_vty_init ()
{
  install_element (CONFIG_NODE, &mpls_static_num_cmd);
  install_element (CONFIG_NODE, &no_mpls_static_num_cmd);
  install_element (INTERFACE_NODE, &mpls_labelspace_cmd);
  install_element (INTERFACE_NODE, &no_mpls_labelspace_cmd);

  install_node (&mpls_static_node, mpls_static_config_write);
  install_default (MPLS_LABELSPACE_NODE);

  install_element (MPLS_LABELSPACE_NODE, &label_map_pop_cmd);
  install_element (MPLS_LABELSPACE_NODE, &label_map_swap_if_cmd);
  install_element (MPLS_LABELSPACE_NODE, &label_map_swap_if_addr_cmd);
  install_element (MPLS_LABELSPACE_NODE, &no_label_map_cmd);

  install_element (VIEW_NODE, &mpls_show_mpls_fwd_cmd);
  install_element (ENABLE_NODE, &mpls_show_mpls_fwd_cmd);
#ifdef LINUX_MPLS
  install_element (VIEW_NODE, &mpls_show_mpls_version_cmd);
  install_element (ENABLE_NODE, &mpls_show_mpls_version_cmd);
#endif
  install_element (VIEW_NODE, &mpls_show_mpls_hardware_cmd);
  install_element (ENABLE_NODE, &mpls_show_mpls_hardware_cmd);
}

#endif /* HAVE_MPLS */
