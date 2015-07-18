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

#ifndef _ZEBRA_MPLS_VTY_H
#define _ZEBRA_MPLS_VTY_H

#include "mpls_lib.h"
#include "vty.h"

extern void mpls_vty_init();
extern void mpls_print_label(struct zmpls_label *label, char *buf);

extern void
mpls_out_segment_config_write (struct vty *vty, struct zmpls_out_segment *out);

extern int
nhlfe_parse(struct vty *vty, const char **argv, struct zmpls_out_segment *out,
  const char* addr);

#endif /* _ZEBRA_MPLS_VTY_H */
