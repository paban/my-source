/* Zebra's client header.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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

#ifndef _ZEBRA_ZCLIENT_H
#define _ZEBRA_ZCLIENT_H

/* For struct interface and struct connected. */
#include "if.h"
#include "prefix.h"

/* For input/output buffer to zebra. */
#define ZEBRA_MAX_PACKET_SIZ          4096

/* Zebra header size. */
#define ZEBRA_HEADER_SIZE             6

/* Zebra maximum number of nexthops per API struct */
#define ZEBRA_MAX_NEXTHOP                8

/* Structure for the zebra client. */
struct zclient
{
  /* Socket to zebra daemon. */
  int sock;

  /* Flag of communication to zebra is enabled or not.  Default is on.
     This flag is disabled by `no router zebra' statement. */
  int enable;

  /* Connection failure count. */
  int fail;

  /* Input buffer for zebra message. */
  struct stream *ibuf;

  /* Output buffer for zebra message. */
  struct stream *obuf;

  /* Buffer of data waiting to be written to zebra. */
  struct buffer *wb;

  /* Read and connect thread. */
  struct thread *t_read;
  struct thread *t_connect;

  /* Thread to write buffered data to zebra. */
  struct thread *t_write;

  /* Redistribute information. */
  u_char redist_default;
  u_char redist[ZEBRA_ROUTE_MAX];

  /* Redistribute defauilt. */
  u_char default_information;

  /* Router-id information. */
  u_char ridinfo;

  /* Pointer to the callback functions. */
  int (*router_id_update) (int, struct zclient *, uint16_t);
  int (*interface_add) (int, struct zclient *, uint16_t);
  int (*interface_delete) (int, struct zclient *, uint16_t);
  int (*interface_up) (int, struct zclient *, uint16_t);
  int (*interface_down) (int, struct zclient *, uint16_t);
  int (*interface_address_add) (int, struct zclient *, uint16_t);
  int (*interface_address_delete) (int, struct zclient *, uint16_t);
  int (*ipv4_route_add) (int, struct zclient *, uint16_t);
  int (*ipv4_route_delete) (int, struct zclient *, uint16_t);
  int (*ipv6_route_add) (int, struct zclient *, uint16_t);
  int (*ipv6_route_delete) (int, struct zclient *, uint16_t);
  int (*mpls_xc_add) (int, struct zclient *, uint16_t);
  int (*mpls_xc_delete) (int, struct zclient *, uint16_t);
  int (*mpls_in_segment_add) (int, struct zclient *, uint16_t);
  int (*mpls_in_segment_delete) (int, struct zclient *, uint16_t);
  int (*mpls_out_segment_add) (int, struct zclient *, uint16_t);
  int (*mpls_out_segment_delete) (int, struct zclient *, uint16_t);
  int (*mpls_labelspace_add) (int, struct zclient *, uint16_t);
  int (*mpls_labelspace_delete) (int, struct zclient *, uint16_t);
  int (*mpls_ftn_add) (int, struct zclient *, uint16_t);
  int (*mpls_ftn_delete) (int, struct zclient *, uint16_t);
};

/* Zebra API message flag. */
#define ZAPI_MESSAGE_NEXTHOP  0x01
#define ZAPI_MESSAGE_IFINDEX  0x02
#define ZAPI_MESSAGE_DISTANCE 0x04
#define ZAPI_MESSAGE_METRIC   0x08

/* Zserv protocol message header */
struct zserv_header
{
  uint16_t length;
  uint8_t marker;	/* corresponds to command field in old zserv
                         * always set to 255 in new zserv.
                         */
  uint8_t version;
#define ZSERV_VERSION	2
  uint16_t command;
};

#ifdef HAVE_MPLS

#define ZEBRA_MPLS_LABEL_GEN 1
#define ZEBRA_MPLS_LABEL_ATM 2
#define ZEBRA_MPLS_LABEL_FR  3

struct zmpls_label
{
  u_char type;
  union {
    u_int32_t gen;
    u_int32_t fr;
    struct {
      u_int16_t  vpi;
      u_int16_t  vci;
    } atm;
  } u;
};
#endif

struct zapi_nexthop {
  u_char type;
  union
    {
      char name[INTERFACE_NAMSIZ + 1];
      unsigned int index;
    } intf;
  union
    {
      struct in_addr ipv4;
#ifdef HAVE_IPV6
      struct in6_addr ipv6;
#endif
      u_char drop;
    } gw;
  union
    {
      struct in_addr ipv4;
      struct in6_addr ipv6;
    } src;

  /* Advertised MSS */
  int advmss;
#ifdef HAVE_MPLS
  struct zmpls_label mpls;
#endif
};

/* Zebra IPv4 route message API. */
struct zapi_ipv4
{
  u_char type;

  u_char flags;

  u_char message;

  u_char nexthop_num;
  struct zapi_nexthop nexthop[8];

  u_char distance;

  u_int32_t metric;
};

/* Prototypes of zebra client service functions. */
extern struct zclient *zclient_new (void);
extern void zclient_init (struct zclient *, int);
extern int zclient_start (struct zclient *);
extern void zclient_stop (struct zclient *);
extern void zclient_reset (struct zclient *);

/* Get TCP socket connection to zebra daemon at loopback address. */
extern int zclient_socket (void);

/* Get unix stream socket connection to zebra daemon at given path. */
extern int zclient_socket_un (const char *);

/* Send redistribute command to zebra daemon. Do not update zclient state. */
extern int zebra_redistribute_send (int command, struct zclient *, int type);

/* If state has changed, update state and call zebra_redistribute_send. */
extern void zclient_redistribute (int command, struct zclient *, int type);

/* If state has changed, update state and send the command to zebra. */
extern void zclient_redistribute_default (int command, struct zclient *);

/* Send the message in zclient->obuf to the zebra daemon (or enqueue it).
   Returns 0 for success or -1 on an I/O error. */
extern int zclient_send_message(struct zclient *);

/* create header for command, length to be filled in by user later */
extern void zclient_create_header (struct stream *, uint16_t);

extern struct interface *zebra_interface_add_read (struct stream *);
extern struct interface *zebra_interface_state_read (struct stream *s);
extern struct connected *zebra_interface_address_read (int, struct stream *);
extern void zebra_interface_if_set_value (struct stream *, struct interface *);
extern void zebra_router_id_update_read (struct stream *s, struct prefix *rid);

extern void zapi_nexthop_write(struct stream *s, struct zapi_nexthop *nh);
extern void zapi_nexthop_read(struct stream *s, struct zapi_nexthop *nh);

extern int zapi_ipv4_write (u_char cmd, struct stream *s, struct prefix_ipv4 *p,
                            struct zapi_ipv4 *api);
extern int zapi_ipv4_read (struct stream *, zebra_size_t, struct zapi_ipv4 *,
                           struct prefix_ipv4 *);

extern int zapi_ipv4_route (u_char, struct zclient *, struct prefix_ipv4 *, 
                            struct zapi_ipv4 *);
extern int zapi_ipv4_route_read (struct zclient *, zebra_size_t, struct zapi_ipv4 *,
                                 struct prefix_ipv4 *);

#ifdef HAVE_IPV6
/* IPv6 prefix add and delete function prototype. */

struct zapi_ipv6
{
  u_char type;

  u_char flags;

  u_char message;

  u_char nexthop_num;
  struct zapi_nexthop nexthop[8];

  u_char distance;

  u_int32_t metric;
};

extern int zapi_ipv6_write (u_char cmd, struct stream *s, struct prefix_ipv6 *p,
                            struct zapi_ipv6 *api);
extern int zapi_ipv6_read (struct stream *, zebra_size_t, struct zapi_ipv6 *,
                           struct prefix_ipv6 *);

extern int zapi_ipv6_route (u_char cmd, struct zclient *zclient, 
                            struct prefix_ipv6 *p, struct zapi_ipv6 *api);
extern int zapi_ipv6_route_read (struct zclient *, zebra_size_t, struct zapi_ipv6 *,
                                 struct prefix_ipv6 *);
#endif /* HAVE_IPV6 */

#ifdef HAVE_MPLS

#define ZEBRA_MPLS_FEC_IPV4 1
#define ZEBRA_MPLS_FEC_IPV6 2
#define ZEBRA_MPLS_FEC_L2  3

struct zmpls_fec
{
  u_char type;
  char owner;
  union {
    struct prefix p;
    char l2_ifname[INTERFACE_NAMSIZ + 1];
  } u;
};

/* structures used by clients */

struct zapi_mpls_xc
{
  u_int index;
  u_char owner;
  u_char in_labelspace;
  struct zmpls_label in_label;
  u_int out_index;
};

struct zapi_mpls_in_segment
{
  u_char owner;
  u_char labelspace;
  u_short protocol;
  u_char pop;
  struct zmpls_label label;
};

struct zapi_mpls_out_segment
{
  u_char owner;
  /* label is embeded in zapi_nexthop */
  struct zapi_nexthop nh;
  u_int index;
  int req;
};

struct zapi_mpls_labelspace
{
  u_char owner;
  char labelspace;
  char ifname[INTERFACE_NAMSIZ + 1];
};

struct zapi_mpls_ftn
{
  u_char owner;
  struct zmpls_fec fec;
  u_int out_index;
};

int
mpls_label_match (struct zmpls_label *a, struct zmpls_label *b);

int
mpls_fec_match (struct zmpls_fec *a, struct zmpls_fec *b);

int
zapi_nexthop_match(struct zapi_nexthop *a, struct zapi_nexthop *b, int mask);

void
mpls_xc_stream_write (struct stream *s, struct zapi_mpls_xc *api);

int
mpls_xc_stream_read (struct stream *s, struct zapi_mpls_xc *api);

void
mpls_in_segment_stream_write (struct stream *s,
                              struct zapi_mpls_in_segment *api);
int
mpls_in_segment_stream_read (struct stream *s,
                             struct zapi_mpls_in_segment *api);

void
mpls_out_segment_stream_write (struct stream *s,
                               struct zapi_mpls_out_segment *api);
int
mpls_out_segment_stream_read (struct stream *s,
                              struct zapi_mpls_out_segment *api);

void
mpls_labelspace_stream_write (struct stream *s,
                              struct zapi_mpls_labelspace *api);
int
mpls_labelspace_stream_read (struct stream *s,
                             struct zapi_mpls_labelspace *api);

void
mpls_ftn_stream_write (struct stream *s,
                              struct zapi_mpls_ftn *api);
int
mpls_ftn_stream_read (struct stream *s,
                             struct zapi_mpls_ftn *api);

int
zapi_mpls_xc_add (struct zclient *zclient, struct zapi_mpls_xc *api);

int
zapi_mpls_xc_delete (struct zclient *zclient, struct zapi_mpls_xc *api);

int
zapi_mpls_in_segment_add (struct zclient *zclient,
                          struct zapi_mpls_in_segment *api);

int
zapi_mpls_in_segment_delete (struct zclient *zclient,
                             struct zapi_mpls_in_segment *api);

int
zapi_mpls_out_segment_add (struct zclient *zclient,
                           struct zapi_mpls_out_segment *api);

int
zapi_mpls_out_segment_delete (struct zclient *zclient,
                              struct zapi_mpls_out_segment *api);

int
zapi_mpls_labelspace_add (struct zclient *zclient,
                          struct zapi_mpls_labelspace *api);

int
zapi_mpls_labelspace_delete (struct zclient *zclient,
                             struct zapi_mpls_labelspace *api);

int
zapi_mpls_ftn_add (struct zclient *zclient, struct zapi_mpls_ftn *api);

int
zapi_mpls_ftn_delete (struct zclient *zclient,
                      struct zapi_mpls_ftn *api);

#endif /* HAVE_MPLS */
#endif /* _ZEBRA_ZCLIENT_H */
