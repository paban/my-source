/* Zebra VLAN VTY functions
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

#include <zebra.h>

#include "if.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "prefix.h"
#include "table.h"
#include "interface.h"

#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include "ioctl.h"

static void
vlan_config (struct vty *vty, struct interface *ifp)
{
  vty_out (vty, "create vlan %s%s", ifp->name, VTY_NEWLINE);
}

static void
vlan_show (struct vty *vty, struct interface *ifp)
{
  struct zebra_if *if_data;
  if_data = ifp->info;
  vty_out (vty, "  802.1q VLAN Tag %d%s", (int)if_data->ops->info, VTY_NEWLINE);
}

static void
vlan_free (struct interface *ifp)
{
  struct zebra_if *if_data;
  if_data = ifp->info;
  XFREE (MTYPE_TMP, if_data->ops);
  if_data->ops = NULL;
}

static int
vlan_name_check(const char *input, char *ifname, int *vlan)
{
  char iff_str[IFNAMSIZ];
  char *vlan_str;
  char *iff;

  strncpy(iff_str, input, IFNAMSIZ);

  iff = strtok(iff_str, ".");
  vlan_str = strtok(NULL, ".");
  *vlan = atoi(vlan_str);

  if (!(iff && vlan_str && (vlan > 0)))
    return 0;

  strncpy(ifname, iff, IFNAMSIZ);
  return 1;
}

static struct interface_ops*
vlan_create_ops(int vlan)
{
  struct interface_ops *ops = XMALLOC (MTYPE_TMP, sizeof(struct interface_ops));
  if (!ops)
    return NULL;

  memset (ops, 0, sizeof(struct interface_ops));
  ops->type = INTERFACE_TYPE_VLAN;
  ops->config = &vlan_config;
  ops->show = &vlan_show;
  ops->free = &vlan_free;
  ops->info = (void*)vlan;
  return ops;
}

static int
do_vlan (int cmd, char *name, int vlan)
{
  struct vlan_ioctl_args args;

  strncpy(args.device1, name, IFNAMSIZ);
  args.cmd = cmd;
  if (cmd == ADD_VLAN_CMD)
    args.u.VID = vlan;

  return if_ioctl(SIOCSIFVLAN, (caddr_t)&args);
}

DEFUN (create_vlan,
       create_vlan_cmd,
       "create vlan IFNAME",
       "Create virtual interface\n"
       "Create VLAN interface\n"
       "VLAN interface name\n")
{
  struct zebra_if *if_data;
  struct interface *ifp;
  char iff[IFNAMSIZ];
  int vlan;

  if (!vlan_name_check(argv[0], iff, &vlan))
    {
      vty_out (vty, "%% Invalid VLAN name%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ifp = if_lookup_by_name(argv[0]);
  if (!ifp)
    {
      ifp = if_create (argv[0], strlen (argv[0]));
      if (!ifp)
	{
          vty_out (vty, "%% Unable to create VLAN%s", VTY_NEWLINE);
          return CMD_WARNING;
	}
    }

  if_data = ifp->info;
  if (if_data->ops)
    {
      vty_out (vty, "%% Interface is already owned by a protocol other then 802.1q%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if_data->ops = vlan_create_ops(vlan);
  if (!if_data->ops)
    {
      vty_out (vty, "%% Unable to create VLAN%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (do_vlan (ADD_VLAN_CMD, iff, vlan) < 0)
    {
      if_zebra_delete_ops (ifp);
      vty_out (vty, "%% Unable creating VLAN%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (no_create_vlan,
       no_create_vlan_cmd,
       "no create vlan IFNAME",
       NO_STR
       "Delete virtual interface\n"
       "Delete VLAN interface\n"
       "VLAN interface name\n")
{
  struct zebra_if *if_data;
  struct interface *ifp;
  char iff[IFNAMSIZ];
  int vlan;

  if (!vlan_name_check(argv[0], iff, &vlan))
    {
      vty_out (vty, "%% Invalid VLAN name%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ifp = if_lookup_by_name (argv[0]);
  if (!ifp)
    return CMD_WARNING;

  if_data = ifp->info;
  if (if_data && if_data->ops && if_data->ops->type == INTERFACE_TYPE_VLAN)
    {
      if_zebra_delete_ops (ifp);
      do_vlan (DEL_VLAN_CMD, ifp->name, 0);
    }

  return CMD_SUCCESS;
}

void
if_vlan_init ()
{
  install_element (CONFIG_NODE, &create_vlan_cmd);
  install_element (CONFIG_NODE, &no_create_vlan_cmd);
}
