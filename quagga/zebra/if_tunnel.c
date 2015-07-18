/* Zebra Tunnel VTY functions
 * Copyright (C) 2005 James R. Leu
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
/* #include <linux/if.h>
#include <arpa/inet.h>
#include <linux/if_arp.h> */
#include <netinet/ip.h>
#include <linux/if_tunnel.h>
#include <linux/sockios.h>

#include <zebra.h>

#include "if.h"
#include "memory.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "prefix.h"
#include "table.h"
#include "interface.h"
#ifdef HAVE_MPLS
#include "mpls_vty.h"
#endif
#include "ioctl.h"

enum tunnel_type
{
  TUNNEL_GRE = 1,
  TUNNEL_IPIP,
  TUNNEL_SIT,
  TUNNEL_MPLS,
  TUNNEL_MAX,
};

struct tunnel_info
{
  enum tunnel_type type;
  struct prefix dest;
  int configured;
  int (*action)(int, struct interface*);
  int (*check)(int, struct interface*);
  void *data;
};

static const char*
tunnel_mode_str (int type)
{
  const char *mode;
  switch (type)
  {
    case TUNNEL_GRE:
      mode = "gre";
      break;
    case TUNNEL_IPIP:
      mode = "ipip";
      break;
    case TUNNEL_SIT:
      mode = "sit";
      break;
#ifdef HAVE_MPLS
    case TUNNEL_MPLS:
      mode = "mpls";
      break;
#endif
    default:
      assert (0);
      break;
  }
  return mode;
}

static void
tunnel_config (struct vty *vty, struct interface *ifp)
{
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;
  char buf[BUFSIZ];

  vty_out (vty, "create tunnel %s%s", ifp->name, VTY_NEWLINE);
  prefix2str (&tun_data->dest, buf, sizeof (buf));
  vty_out (vty, " tunnel dest %s%s", buf, VTY_NEWLINE);
  vty_out (vty, " tunnel mode %s%s", tunnel_mode_str (tun_data->type),
    VTY_NEWLINE);
}

static void
tunnel_show (struct vty *vty, struct interface *ifp)
{
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;
  char buf[BUFSIZ];

  prefix2str (&tun_data->dest, buf, sizeof (buf));

  vty_out (vty, "  Tunnel mode: %s Destination: %s%s",
    tunnel_mode_str (tun_data->type), buf, VTY_NEWLINE);
}

static void
tunnel_free (struct interface *ifp)
{
  struct zebra_if *if_data = ifp->info;
  XFREE (MTYPE_TMP, if_data->ops);
  if_data->ops = NULL;
}

static int
do_tunnel (int cmd, struct interface *ifp)
{
  struct ip_tunnel_parm args;
  struct ifreq ifr;
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;

  memset(&args, 0, sizeof(args));
  strncpy(args.name, ifp->name, IFNAMSIZ);
  args.iph.version = 4;
  args.iph.ihl = 5;
  args.iph.frag_off = htons(IP_DF);
  args.iph.daddr = tun_data->dest.u.prefix4.s_addr;

  switch (tun_data->type)
  {
    case TUNNEL_GRE:
      args.iph.protocol = IPPROTO_GRE;
      strcpy(ifr.ifr_name, "gre0");
      break;
    case TUNNEL_IPIP:
      args.iph.protocol = IPPROTO_IPIP;
      strcpy(ifr.ifr_name, "tunl0");
      break;
    case TUNNEL_SIT:
      args.iph.protocol = IPPROTO_IPV6;
      strcpy(ifr.ifr_name, "sit0");
      break;
    default:
      assert (0);
  }

  ifr.ifr_ifru.ifru_data = (void*)&args;
  return if_ioctl(cmd, (caddr_t)&ifr);
}

static int
do_tunnel_check (int cmd, struct interface *ifp)
{
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;

  if (cmd == SIOCADDTUNNEL)
    {
      if ((!tun_data->configured) && tun_data->type &&
	tun_data->dest.family && tun_data->data)
        return 1;
    }
  else
    {
      if (tun_data->configured)
        return 1;
    }
  return 0;
}

#ifdef LINUX_MPLS
static int
do_mpls_tunnel (int cmd, struct interface *ifp)
{
  struct mpls_tunnel_req mtr;
  struct ifreq ifr;
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;
  struct zmpls_out_segment *out = tun_data->data;

  memset(&mtr, 0, sizeof(mtr));
  strncpy(mtr.mt_ifname, ifp->name, IFNAMSIZ);
  strcpy(ifr.ifr_name, "mpls0");
  mtr.mt_nhlfe_key = out->out_key;

  ifr.ifr_ifru.ifru_data = (void*)&mtr;
  return if_ioctl(cmd, (caddr_t)&ifr);

#if 0

  ADD

  struct interface *ifp;
  struct connected *ifc;
  struct prefix dest;
  struct prefix *p;
  int ret;

  if (listcount (ifp->connected))
  {
    vty_out (vty, "%% Tunnel destination already configured %s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  ifc = connected_new ();
  ifc->ifp = ifp;

  /* source */
  p = prefix_new ();
  router_id_get (p);
  ifc->address = (struct prefix *) p;

  /* destination. */
  p = prefix_new ();
  *p = dest;
  p->prefixlen = (p->family == AF_INET)?IPV4_MAX_BITLEN:IPV6_MAX_PREFIXLEN;
  ifc->destination = (struct prefix *) p;

  /* Add to linked list. */
  listnode_add (ifp->connected, ifc);

  SET_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED);

  if_set_flags (ifp, IFF_UP | IFF_RUNNING);
  if_refresh (ifp);

  ret = if_set_prefix (ifp, ifc);
  if (ret < 0)
  {
    vty_out (vty, "%% Can't set interface IP address: %s.%s",
             strerror(errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  /* IP address propery set. */
  SET_FLAG (ifc->conf, ZEBRA_IFC_REAL);

  /* Update interface address information to protocol daemon. */
  zebra_interface_address_add_update (ifp, ifc);

  /* If interface is up register connected route. */
  if (if_is_operative(ifp))
    connected_up_ipv4 (ifp, ifc);

  mpls_ctrl_tunnel_register(ifp, 1);


  DEL

  struct interface *ifp;
  struct connected *ifc;
  int ret;

  ifp = (struct interface *) vty->index;
  ifc = listgetdata (listhead (ifp->connected));

  /* This is real route. */
  ret = if_unset_prefix (ifp, ifc);
  if (ret < 0)
  {
    vty_out (vty, "%% Can't unset interface IP address: %s.%s",
             strerror(errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  /* Redistribute this information. */
  zebra_interface_address_delete_update (ifp, ifc);

  /* Remove connected route. */
  connected_down_ipv4 (ifp, ifc);

  /* Free address information. */
  listnode_delete (ifp->connected, ifc);
  connected_free (ifc);

  mpls_ctrl_tunnel_unregister(ifp, 1);

static void
mpls_interface_config_write (struct vty *vty, struct interface *ifp)
{
  struct zebra_if *if_data;
  if_data = ifp->info;

  vty_out (vty, "create mpls-tunnel %s%s", ifp->name, VTY_NEWLINE);

  if (if_data && if_data->ops && if_data->ops->info)
  {
    struct zmpls_out_segment *out;

    out = mpls_out_segment_find_by_out_key((int)if_data->ops->info);
    if (out)
    {
      vty_out (vty, " tunnel mode mpls static ");
      mpls_out_segment_config_write (vty, out);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
  }
}


#endif
}

static int
do_mpls_tunnel_check (int cmd, struct interface *ifp)
{
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;

  if (cmd == SIOCADDTUNNEL)
    {
      if ((!tun_data->configured) && tun_data->type && tun_data->dest.family)
        return 1;
    }
  else
    {
      if (tun_data->configured)
        return 1;
    }
  return 0;
}
#endif

static int
tunnel_create_check (struct interface *ifp)
{
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;
  return tun_data->check(SIOCDELTUNNEL, ifp);
}

static int
tunnel_delete_check (struct interface *ifp)
{
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;
  return tun_data->check(SIOCDELTUNNEL, ifp);
}

static int
tunnel_create (struct interface *ifp)
{
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;
  int ret = tun_data->action (SIOCADDTUNNEL, ifp);
  if (!ret)
    tun_data->configured = 1;
  return ret;
}

static int
tunnel_delete (struct interface *ifp)
{
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;
  int ret = tun_data->action (SIOCADDTUNNEL, ifp);
  tun_data->configured = 0;
  return ret;
}

static struct interface_ops*
tunnel_create_ops ()
{
  struct tunnel_info *tun_data;
  struct interface_ops *ops = XMALLOC (MTYPE_TMP,
    sizeof(struct interface_ops) + sizeof (struct tunnel_info));

  if (!ops)
    return NULL;

  memset (ops, 0, sizeof(struct interface_ops));
  ops->type = INTERFACE_TYPE_TUNNEL;
  ops->config = &tunnel_config;
  ops->show = &tunnel_show;
  ops->create_check = &tunnel_create_check;
  ops->delete_check = &tunnel_delete_check;
  ops->create = &tunnel_create;
  ops->delete = &tunnel_delete;
  ops->free = &tunnel_free;
  ops->info = &ops[1];

  tun_data = ops->info;
  tun_data->action = &do_tunnel;
  tun_data->check = &do_tunnel_check;

  return ops;
}

DEFUN (create_tunnel,
       create_tunnel_cmd,
       "create tunnel IFNAME",
       "Create virtual interface\n"
       "Create tunnel interface\n"
       "Tunnel interface name\n")
{
  struct zebra_if *if_data;
  struct interface *ifp;

  ifp = if_lookup_by_name(argv[0]);
  if (!ifp)
    {
      ifp = if_create (argv[0], strlen (argv[0]));
      if (!ifp)
	{
          vty_out (vty, "%% Unable to create tunnel%s", VTY_NEWLINE);
          return CMD_WARNING;
	}
    }

  if_data = ifp->info;
  if (if_data->ops)
    {
      if (if_data->ops->type != INTERFACE_TYPE_TUNNEL)
        {
          vty_out (vty, "%% Interface is already owned by a protocol other then tunnel%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
   else
    {
      if_data->ops = tunnel_create_ops();
      if (!if_data->ops)
        {
          vty_out (vty, "%% Unable to create tunnel%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  vty->index = ifp;
  vty->node = TUNNEL_NODE;

  return CMD_SUCCESS;
}

DEFUN (no_create_tunnel,
       no_create_tunnel_cmd,
       "no create tunnel IFNAME",
       NO_STR
       "Delete virtual interface\n"
       "Delete tunnel interface\n"
       "Tunnel interface name\n")
{
  struct zebra_if *if_data;
  struct interface *ifp;

  ifp = if_lookup_by_name (argv[0]);
  if (!ifp)
    {
      vty_out (vty, "%% No such tunnel interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if_data = ifp->info;
  if (if_data && if_data->ops && if_data->ops->type == INTERFACE_TYPE_TUNNEL)
    {
      struct tunnel_info *tun_data = if_data->ops->info;

      if (tun_data->configured)
	if_data->ops->delete (ifp);

      if_zebra_delete_ops (ifp);
    }
  else
    {
      vty_out (vty, "%% Interface is not a tunnel interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (tunnel_destination,
       tunnel_destination_cmd,
       "tunnel destination IPADDR",
       "Tunnel configuration\n"
       "Destination of tunnel\n"
       "IP Address of the destination of tunnel\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;
  int ret;

  ret = str2prefix (argv[0], &tun_data->dest);
  if (ret <= 0)
    {
      vty_out (vty, "%% Malformed destination address %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (if_data->ops->create_check (ifp))
    if (if_data->ops->create (ifp) < 0)
      {
	vty_out (vty, "%% Unable to create tunnel%s", VTY_NEWLINE);
	return CMD_WARNING;
      }

  return CMD_SUCCESS;
}

DEFUN (no_tunnel_destination,
       no_tunnel_destination_cmd,
       "no tunnel destination",
       NO_STR
       "Tunnel configuration\n"
       "Destination of tunnel\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;

  if (if_data->ops->delete_check(ifp))
    if_data->ops->delete (ifp);

  memset(&tun_data->dest, 0, sizeof (struct prefix));

  return CMD_SUCCESS;
}

DEFUN (tunnel_mode,
       tunnel_mode_cmd,
       "tunnel mode (gre|sit|ipip)",
       "Tunnel configuration\n"
       "Tunnel mode configuration\n"
       "Generic Routing Encapsulation\n"
       "IPv6 in IPv4\n"
       "IPv4 in IPv4\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;
  int new_type = 0;

  if (strncmp(argv[0], "gre", 3) == 0) {
    new_type = TUNNEL_GRE;
  } else if (strncmp(argv[0], "sit", 3) == 0) {
    new_type = TUNNEL_SIT;
  } else if (strncmp(argv[0], "ipip", 4) == 0) {
    new_type = TUNNEL_IPIP;
  } else {
    vty_out (vty, "%% Unknown tunnel mode%s\n", VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (tun_data->type != new_type)
    {
      if (if_data->ops->delete_check (ifp))
        if_data->ops->delete (ifp);

      tun_data->type = new_type;
      vty->node = TUNNEL_NODE;

      tun_data->action = &do_tunnel;
      tun_data->check = &do_tunnel_check;
    }

  if (if_data->ops->create_check (ifp))
    if (if_data->ops->create (ifp) < 0)
      {
	vty_out (vty, "%% Unable to create tunnel%s", VTY_NEWLINE);
	return CMD_WARNING;
      }

  return CMD_SUCCESS;
}

DEFUN (no_tunnel_mode,
       no_tunnel_mode_cmd,
       "no tunnel mode",
       NO_STR
       "Tunnel configuration\n"
       "Tunnel mode configuration\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;

  if (if_data->ops->delete_check(ifp))
    if_data->ops->delete (ifp);

  tun_data->type = 0;
  tun_data->action = &do_tunnel;
  tun_data->check = &do_tunnel_check;

  return CMD_SUCCESS;
}

#ifdef LINUX_MPLS
DEFUN (tunnel_mode_mpls,
       tunnel_mode_mpls_cmd,
       "tunnel mode mpls",
       "Tunnel configuration\n"
       "Tunnel mode configuration\n"
       "MPLS\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;

  if (tun_data->type != TUNNEL_MPLS)
    {
      if (if_data->ops->delete_check (ifp))
        if_data->ops->delete (ifp);

      tun_data->type = TUNNEL_MPLS;
      vty->node = MPLS_TUNNEL_NODE;

      tun_data->action = &do_mpls_tunnel;
      tun_data->check = &do_mpls_tunnel_check;
    }

  if (if_data->ops->create_check (ifp))
    if (if_data->ops->create (ifp) < 0)
      {
	vty_out (vty, "%% Unable to create tunnel%s", VTY_NEWLINE);
	return CMD_WARNING;
      }

  return CMD_SUCCESS;
}

static int
mpls_static(struct vty *vty, struct zmpls_out_segment *new, struct interface *ifp)
{
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;
  struct zmpls_out_segment *out = NULL;
  int index;

  if (tun_data->data)
    {
      return CMD_WARNING;
    }

  if (mpls_out_segment_register(new))
    {
      return CMD_WARNING;
    }

  index = mpls_out_segment_find_index_by_nhlfe(new);
  assert(index);
  tun_data->data = mpls_out_segment_find(index);

  if (if_data->ops->create_check (ifp))
    if (if_data->ops->create (ifp) < 0)
      {
	vty_out (vty, "%% Unable to create tunnel%s", VTY_NEWLINE);
	return CMD_WARNING;
      }

  return CMD_SUCCESS;
}

DEFUN (tunnel_mpls_static_addr,
       tunnel_mpls_static_addr_cmd,
       "tunnel mpls static (gen|atm|fr) VALUE nexthop INTERFACE ADDR",
       "Tunnel configuration\n"
       "MPLS Tunnel configuration\n"
       "Static Tunnel Configuration\n"
       "Out-going generic MPLS label (16 - 2^20-1)\n"
       "Out-going ATM MPLS label (VPI/VCI)\n"
       "Out-going Frame Relay MPLS label (16 - 2^17-1)\n"
       "Out-going label value\n"
       "Nexthop\n"
       "IP gateway interface name\n"
       "IP gateway address\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct zmpls_out_segment new;
  int result;

  memset (&new, 0, sizeof (new));
  new.owner = ZEBRA_ROUTE_STATIC;
  result = nhlfe_parse (vty, &argv[0], &new, argv[3]);
  if (result != CMD_SUCCESS)
    return result;

  return mpls_static(vty, &new, ifp);
}

DEFUN (tunnel_mpls_static_intf,
       tunnel_mpls_static_intf_cmd,
       "tunnel mpls static (gen|atm|fr) VALUE nexthop INTERFACE",
       "Tunnel configuration\n"
       "MPLS Tunnel configuration\n"
       "Static Tunnel Configuration\n"
       "Out-going generic MPLS label (16 - 2^20-1)\n"
       "Out-going ATM MPLS label (VPI/VCI)\n"
       "Out-going Frame Relay MPLS label (16 - 2^17-1)\n"
       "Out-going label value\n"
       "Nexthop\n"
       "IP gateway interface name\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct zmpls_out_segment new;
  int result;

  memset (&new, 0, sizeof (new));
  new.owner = ZEBRA_ROUTE_STATIC;
  result = nhlfe_parse (vty, &argv[0], &new, NULL);
  if (result != CMD_SUCCESS)
    return result;

  return mpls_static(vty, &new, ifp);
}

static int
no_mpls_static(struct vty *vty, struct zmpls_out_segment *old, struct interface *ifp)
{
  struct zebra_if *if_data = ifp->info;
  struct tunnel_info *tun_data = if_data->ops->info;
  struct zmpls_out_segment *out = tun_data->data;
  struct zmpls_out_segment *tmp;
  int index;

  if (!out)
    {
      return CMD_WARNING;
    }

  index = mpls_out_segment_find_index_by_nhlfe(old);
  if (!index)
    {
      return CMD_WARNING;
    }

  tmp = mpls_out_segment_find(index);
  if (tmp->index != out->index)
    {
      return CMD_WARNING;
    }

  if (if_data->ops->delete_check(ifp))
    if_data->ops->delete (ifp);

  mpls_out_segment_unregister (out);
  tun_data->data = NULL;

  return CMD_SUCCESS;
}

DEFUN (no_tunnel_mpls_static_addr,
       no_tunnel_mpls_static_addr_cmd,
       "no tunnel mpls static (gen|atm|fr) VALUE nexthop INTERFACE ADDR",
       NO_STR
       "Tunnel configuration\n"
       "MPLS Tunnel configuration\n"
       "Static Tunnel Configuration\n"
       "Out-going generic MPLS label (16 - 2^20-1)\n"
       "Out-going ATM MPLS label (VPI/VCI)\n"
       "Out-going Frame Relay MPLS label (16 - 2^17-1)\n"
       "Out-going label value\n"
       "Nexthop\n"
       "IP gateway interface name\n"
       "IP gateway address\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct zmpls_out_segment old;
  int result;

  memset (&old, 0, sizeof (old));
  old.owner = ZEBRA_ROUTE_STATIC;
  result = nhlfe_parse (vty, &argv[0], &old, argv[3]);
  if (result != CMD_SUCCESS)
    return result;

  return no_mpls_static(vty, &old, ifp);
}

DEFUN (no_tunnel_mpls_static_intf,
       no_tunnel_mpls_static_intf_cmd,
       "no tunnel mpls static (gen|atm|fr) VALUE nexthop INTERFACE",
       NO_STR
       "Tunnel configuration\n"
       "MPLS Tunnel configuration\n"
       "Static Tunnel Configuration\n"
       "Out-going generic MPLS label (16 - 2^20-1)\n"
       "Out-going ATM MPLS label (VPI/VCI)\n"
       "Out-going Frame Relay MPLS label (16 - 2^17-1)\n"
       "Out-going label value\n"
       "Nexthop\n"
       "IP gateway interface name\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct zmpls_out_segment old;
  int result;

  memset (&old, 0, sizeof (old));
  old.owner = ZEBRA_ROUTE_STATIC;
  result = nhlfe_parse (vty, &argv[0], &old, NULL);
  if (result != CMD_SUCCESS)
    return result;

  return no_mpls_static(vty, &old, ifp);
}

struct cmd_node mpls_tunnel_node =
{
  MPLS_TUNNEL_NODE,
  "%s(config-tun-mpls)# ",
  1
};
#endif

struct cmd_node tunnel_node =
{
  TUNNEL_NODE,
  "%s(config-tun)# ",
  1
};

static int
tunnel_config_write (struct vty *vty)
{
  return 0;
}

void
if_tunnel_init ()
{
  install_element (CONFIG_NODE, &create_tunnel_cmd);
  install_element (CONFIG_NODE, &no_create_tunnel_cmd);

  install_node (&tunnel_node, tunnel_config_write);

  install_element (TUNNEL_NODE, &tunnel_destination_cmd);
  install_element (TUNNEL_NODE, &no_tunnel_destination_cmd);
  install_element (TUNNEL_NODE, &tunnel_mode_cmd);
  install_element (TUNNEL_NODE, &no_tunnel_mode_cmd);
#ifdef LINUX_MPLS
  install_element (TUNNEL_NODE, &tunnel_mode_mpls_cmd);
  install_node (&mpls_tunnel_node, tunnel_config_write);
  install_element (MPLS_TUNNEL_NODE, &tunnel_destination_cmd);
  install_element (MPLS_TUNNEL_NODE, &no_tunnel_destination_cmd);
  install_element (MPLS_TUNNEL_NODE, &tunnel_mode_cmd);
  install_element (MPLS_TUNNEL_NODE, &tunnel_mode_mpls_cmd);
  install_element (MPLS_TUNNEL_NODE, &no_tunnel_mode_cmd);
  install_element (MPLS_TUNNEL_NODE, &tunnel_mpls_static_addr_cmd);
  install_element (MPLS_TUNNEL_NODE, &tunnel_mpls_static_intf_cmd);
  install_element (MPLS_TUNNEL_NODE, &no_tunnel_mpls_static_addr_cmd);
  install_element (MPLS_TUNNEL_NODE, &no_tunnel_mpls_static_intf_cmd);
#endif
}
