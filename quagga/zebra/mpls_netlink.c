#include <linux/mpls.h>
#include <linux/if_ether.h>
#include "zebra.h"
#include "debug.h"
#include "mpls_lib.h"
#include "interface.h"
#include "log.h"
#include "command.h"
#include "zebra/netlink.h"

#ifndef AF_MPLS
#define AF_MPLS 29
#endif

#ifndef NETLINK_GENERIC
#define NETLINK_GENERIC 16
#endif

/* Socket interface to kernel */
struct nlsock
  mpls_netlink      = {-1,0,{0},"mpls-netlink-listen",0},/* kernel messages */
  mpls_netlink_cmd  = {-1,0,{0},"mpls-netlink-cmd",1},   /* command channel */
  mpls_netlink_nhlfe= {-1,0,{0},"mpls-netlink-nhlfe",1}; /* nhlfe adds */

int
mpls_ctrl_show_hardware(struct vty *vty)
{
  vty_out(vty, "MPLS-Linux: %d.%d%d%d netlink control%s",
    (MPLS_LINUX_VERSION >> 24) & 0xFF,
    (MPLS_LINUX_VERSION >> 16) & 0xFF,
    (MPLS_LINUX_VERSION >> 8) & 0xFF,
    (MPLS_LINUX_VERSION) & 0xFF, VTY_NEWLINE);
  return CMD_SUCCESS;
}

int
mpls_ctrl_nhlfe_unregister(struct zmpls_out_segment *old)
{
  struct genlmsghdr *ghdr;
  struct
  {
    struct nlmsghdr n;
    char buf[4096];
  } req;
  struct mpls_out_label_req mol;

  memset (&req, 0, sizeof(req));
  memset (&mol, 0, sizeof(mol));

  req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_CREATE|NLM_F_REQUEST;
  req.n.nlmsg_type = AF_MPLS;

  ghdr = NLMSG_DATA(&req.n);
  ghdr->cmd = MPLS_CMD_DELNHLFE;

  mol.mol_label.ml_type = MPLS_LABEL_KEY;
  mol.mol_label.u.ml_key = old->out_key;

  addattr_l(&req.n, sizeof(req), MPLS_ATTR_NHLFE, &mol, sizeof(mol));

  return netlink_talk (&req.n, &mpls_netlink_cmd, NULL, 0);
}

int
mpls_ctrl_nhlfe_register(struct zmpls_out_segment *new)
{
  struct genlmsghdr *ghdr;
  struct
  {
    struct nlmsghdr n;
    char buf[4096];
  } req, res;

  struct mpls_out_label_req mol, *molp;
  struct mpls_instr_req mir;
  struct rtattr *tb[MPLS_ATTR_MAX + 1];
  struct rtattr *attrs;
  int result;

  memset (&req, 0, sizeof(req));
  memset (&res, 0, sizeof(res));
  memset (&mol, 0, sizeof(mol));
  memset (&mir, 0, sizeof(mir));

  req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_CREATE|NLM_F_REQUEST;
  req.n.nlmsg_type = AF_MPLS;

  ghdr = NLMSG_DATA(&req.n);
  ghdr->cmd = MPLS_CMD_NEWNHLFE;

  mol.mol_label.ml_type = MPLS_LABEL_KEY;
  mol.mol_label.u.ml_key = 0;
  mol.mol_change_flag |= MPLS_CHANGE_INSTR;

  mir.mir_direction = MPLS_OUT;
  memcpy(&mir.mir_label,&mol.mol_label,sizeof(struct mpls_label));

  mir.mir_instr[0].mir_opcode = MPLS_OP_PUSH;
  mir.mir_instr[0].mir_data.push.ml_type = MPLS_LABEL_GEN;
  mir.mir_instr[0].mir_data.push.u.ml_gen = new->nh.mpls.u.gen;

  mir.mir_instr[1].mir_opcode = MPLS_OP_SET;

  if (CHECK_FLAG (new->nh.type, ZEBRA_NEXTHOP_IFNAME))
    {
      struct interface *ifp = if_lookup_by_name (new->nh.intf.name);
      mir.mir_instr[1].mir_data.set.mni_if = ifp ? ifp->ifindex : 0;
    }

  if (CHECK_FLAG (new->nh.type, ZEBRA_NEXTHOP_IPV4))
    {
      struct sockaddr_in addr;
      addr.sin_family = AF_INET;
      addr.sin_addr = new->nh.gw.ipv4;
      memcpy(&mir.mir_instr[1].mir_data.set.mni_addr, &addr, sizeof(addr));
    }
  else if (CHECK_FLAG (new->nh.type, ZEBRA_NEXTHOP_IPV6))
    {
      struct sockaddr_in6 addr;
      addr.sin6_family = AF_INET6;
      addr.sin6_addr = new->nh.gw.ipv6;
      memcpy(&mir.mir_instr[1].mir_data.set.mni_addr, &addr, sizeof(addr));
    }
  else
    {
      assert (0);
    }

  mir.mir_instr_length = 2;

  addattr_l(&req.n, sizeof(req), MPLS_ATTR_NHLFE, &mol, sizeof(mol));
  addattr_l(&req.n, sizeof(req), MPLS_ATTR_INSTR, &mir, sizeof(mir));

  result = netlink_talk (&req.n, &mpls_netlink_nhlfe, (void*)&res, sizeof(res));

  ghdr = NLMSG_DATA(&res.n);
  attrs = (struct rtattr *) ((char *) ghdr + GENL_HDRLEN);
  netlink_parse_rtattr(tb, MPLS_ATTR_MAX, attrs,
    res.n.nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));
  molp = RTA_DATA(tb[MPLS_ATTR_NHLFE]);

  new->out_key = molp->mol_label.u.ml_key;
  zlog(NULL, LOG_ERR, "mpls_ctrl_nhlfe_register(): "
             "NHLFE 0x%08x", new->out_key);
  return result;
}

static int do_ilm(int cmd, struct zmpls_in_segment *ilm)
{
  struct genlmsghdr *ghdr;
  struct
  {
    struct nlmsghdr n;
    char buf[4096];
  } req;
  struct mpls_in_label_req mil;

  memset (&req, 0, sizeof(req));
  memset (&mil, 0, sizeof(mil));

  req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_CREATE|NLM_F_REQUEST;
  req.n.nlmsg_type = AF_MPLS;

  ghdr = NLMSG_DATA(&req.n);
  ghdr->cmd = cmd;

  mil.mil_proto = AF_INET;
  mil.mil_label.ml_type = MPLS_LABEL_GEN;
  mil.mil_label.u.ml_gen = ilm->label.u.gen;
  mil.mil_label.ml_index = ilm->labelspace;

  addattr_l(&req.n, sizeof(req), MPLS_ATTR_ILM, &mil, sizeof(mil));

  return netlink_talk (&req.n, &mpls_netlink_cmd, NULL, 0);
}

int
mpls_ctrl_ilm_unregister(struct zmpls_in_segment *old)
{
  return do_ilm(MPLS_CMD_DELILM, old);
}

int
mpls_ctrl_ilm_register(struct zmpls_in_segment *new)
{
  return do_ilm(MPLS_CMD_NEWILM, new);
}

static int do_xc(int cmd, struct zmpls_in_segment *in,
  struct zmpls_out_segment *out)
{
  struct genlmsghdr *ghdr;
  struct
  {
    struct nlmsghdr n;
    char buf[4096];
  } req;
  struct mpls_xconnect_req mx;

  memset (&req, 0, sizeof(req));
  memset (&mx, 0, sizeof(mx));

  req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_CREATE|NLM_F_REQUEST;
  req.n.nlmsg_type = AF_MPLS;

  ghdr = NLMSG_DATA(&req.n);
  ghdr->cmd = cmd;

  mx.mx_in.ml_type = MPLS_LABEL_GEN;
  mx.mx_in.u.ml_gen = in->label.u.gen;
  mx.mx_in.ml_index = in->labelspace;
  mx.mx_out.ml_type = MPLS_LABEL_KEY;
  mx.mx_out.u.ml_key = out->out_key;

  addattr_l(&req.n, sizeof(req), MPLS_ATTR_XC, &mx, sizeof(mx));

  return netlink_talk (&req.n, &mpls_netlink_cmd, NULL, 0);
}

int mpls_ctrl_xc_register(struct zmpls_in_segment *in,
  struct zmpls_out_segment *out)
{
  return do_xc(MPLS_CMD_NEWXC, in, out);
}

int mpls_ctrl_xc_unregister(struct zmpls_in_segment *in,
  struct zmpls_out_segment *out)
{
  return do_xc(MPLS_CMD_DELXC, in, out);
}

int mpls_ctrl_ftn_register(struct zmpls_ftn *ftn)
{
  return 0;
}

int mpls_ctrl_ftn_unregister(struct zmpls_ftn *ftn)
{
  return 0;
}

int mpls_ctrl_tunnel_register(struct interface *ifp, int update)
{
#if 0
  struct zebra_if *if_data = ifp->info;
  struct
  {
    struct nlmsghdr n;
    struct mpls_tunnel_req  mt;
    char buf[1024];
  } req;

  memset (&req, 0, sizeof(req));
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct mpls_tunnel_req));
  req.n.nlmsg_flags = NLM_F_REQUEST;
  if (update)
  {
    req.n.nlmsg_flags |= NLM_F_APPEND;
    req.mt.mt_nhlfe_key = (int)if_data->ops->info;
  }
  else
  {
    req.n.nlmsg_flags |= NLM_F_CREATE;
  }

  req.n.nlmsg_type = MPLS_RTM_ADDTUNNEL;

  strncpy(req.mt.mt_ifname, ifp->name, IFNAMSIZ);

  return netlink_talk (&req.n, &netlink_cmd, NULL, 0);
#else
  return 0;
#endif
}

int mpls_ctrl_tunnel_unregister(struct interface *ifp)
{
#if 0
  struct genlmsghdr *ghdr;
  struct
  {
    struct nlmsghdr n;
    char buf[1024];
  } req;
  struct mpls_labelspace_req      ls;

  memset (&req, 0, sizeof(req));
  memset (&ls, 0, sizeof(ls));

  req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_CREATE|NLM_F_REQUEST;
  req.n.nlmsg_type = AF_MPLS;

  ghdr = NLMSG_DATA(&req.n);
  ghdr->cmd = MPLS_CMD_SETLABELSPACE;
  struct
  {
    struct nlmsghdr n;
    struct mpls_tunnel_req  mt;
    char buf[1024];
  } req;

  memset (&req, 0, sizeof(req));
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct mpls_tunnel_req));
  req.n.nlmsg_flags = NLM_F_CREATE|NLM_F_REQUEST;
  req.n.nlmsg_type = MPLS_RTM_DELTUNNEL;

  req.mt.mt_nhlfe_key = 0;
  strncpy(req.mt.mt_ifname, ifp->name, IFNAMSIZ);

  return netlink_talk (&req.n, &netlink_cmd, NULL, 0);
#else
  return 0;
#endif
}

int mpls_ctrl_set_interface_labelspace(struct interface *ifp, int labelspace)
{
  struct genlmsghdr *ghdr;
  struct
  {
    struct nlmsghdr n;
    char buf[1024];
  } req;
  struct mpls_labelspace_req      ls;

  memset (&req, 0, sizeof(req));
  memset (&ls, 0, sizeof(ls));

  req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_CREATE|NLM_F_REQUEST;
  req.n.nlmsg_type = AF_MPLS;

  ghdr = NLMSG_DATA(&req.n);
  ghdr->cmd = MPLS_CMD_SETLABELSPACE;

  ls.mls_labelspace = (labelspace < 0) ? -1 : labelspace;
  ls.mls_ifindex    = ifp->ifindex;

  addattr_l(&req.n, sizeof(req), MPLS_ATTR_LABELSPACE, &ls, sizeof(ls));

  return netlink_talk (&req.n, &mpls_netlink_cmd, NULL, 0);
}

static int
mpls_netlink_information_fetch (struct nlsock *nl, struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  struct rtattr *tb[MPLS_ATTR_MAX + 1];
  struct genlmsghdr *ghdr = NLMSG_DATA(h);
  int len = h->nlmsg_len;
  struct rtattr *attrs;

  /* skip unsolicited messages originating from command socket */
  if (!nl->cmd)
    {
      struct nlsock *tmp = NULL;

      if (h->nlmsg_pid == mpls_netlink_cmd.snl.nl_pid)
        tmp = &mpls_netlink_cmd;
      else if (h->nlmsg_pid == mpls_netlink_nhlfe.snl.nl_pid)
        tmp = &mpls_netlink_nhlfe;

      if (tmp)
        {
          if (IS_ZEBRA_DEBUG_KERNEL)
            zlog_debug ("netlink_parse_info: %s packet comes from %s",
                        tmp->name, nl->name);
          return 0;
        }
    }

  if (h->nlmsg_type != AF_MPLS) {
      zlog_warn ("Invalid mpls-netlink nlmsg_type %d\n", h->nlmsg_type);
      return 0;
  }

  len -= NLMSG_LENGTH(GENL_HDRLEN);
  if (len < 0) {
      zlog_warn ("Invalid mpls-netlink nlmsg length %d\n", len);
      return 0;
  }

  attrs = (struct rtattr *) ((char *) ghdr + GENL_HDRLEN);
  netlink_parse_rtattr(tb, MPLS_ATTR_MAX, attrs, len);

  switch (ghdr->cmd)
    {
    case MPLS_CMD_NEWNHLFE:
    case MPLS_CMD_DELNHLFE:
      {
        struct mpls_out_label_req *molr = RTA_DATA(tb[MPLS_ATTR_NHLFE]);
        struct mpls_instr_req *mir = RTA_DATA(tb[MPLS_ATTR_INSTR]);
        struct zmpls_out_segment out;
        int i;

        out.owner = ZEBRA_ROUTE_KERNEL;
        out.out_key = molr->mol_label.u.ml_key;

        for (i = 0;i < mir->mir_instr_length;i++)
        {
	  if (mir->mir_instr[i].mir_opcode == MPLS_OP_PUSH)
	  {
	    out.nh.mpls.u.gen = mir->mir_instr[i].mir_push.u.ml_gen;
	    out.nh.mpls.type = ZEBRA_MPLS_LABEL_GEN;
	  }

	  if (mir->mir_instr[i].mir_opcode == MPLS_OP_SET)
	  {
	    struct interface *ifp;
	    struct sockaddr_in *saddr;

	    saddr = (struct sockaddr_in*)&mir->mir_instr[i].mir_set.mni_addr;
	    ifp = if_lookup_by_index(mir->mir_instr[i].mir_set.mni_if);
	    strncpy(out.nh.intf.name, ifp->name, IFNAMSIZ);
	    out.nh.gw.ipv4.s_addr = saddr->sin_addr.s_addr;
	    SET_FLAG (out.nh.type, ZEBRA_NEXTHOP_IPV4);
	    SET_FLAG (out.nh.type, ZEBRA_NEXTHOP_IFNAME);
	  }
        }
        if (ghdr->cmd == MPLS_CMD_NEWNHLFE) {
	   if (mpls_out_segment_find_by_out_key(out.out_key))
	      return 0;
	   if (mir->mir_instr_length == 2)
              mpls_out_segment_register(&out);
        } else {
	   if (!mpls_out_segment_find_by_out_key(out.out_key))
	      return 0;
           mpls_out_segment_unregister(&out);
        }
        break;
      }
    case MPLS_CMD_NEWILM:
    case MPLS_CMD_DELILM:
      {
        struct mpls_in_label_req *milr = RTA_DATA(tb[MPLS_ATTR_ILM]);
        struct zmpls_in_segment in;

        in.labelspace = milr->mil_label.ml_index;
        in.label.type = ZEBRA_MPLS_LABEL_GEN;
        in.label.u.gen = milr->mil_label.u.ml_gen;
        in.protocol = milr->mil_proto;
        in.owner = ZEBRA_ROUTE_KERNEL;
        in.pop = 1;

        if (ghdr->cmd == MPLS_CMD_NEWILM) {
	  if (mpls_in_segment_find(&in))
	    return 0;
          mpls_in_segment_register(&in, 0);
        } else {
	  if (!mpls_in_segment_find(&in))
	    return 0;
          mpls_in_segment_unregister(&in, 0);
        }
        break;
      }
    case MPLS_CMD_NEWXC:
    case MPLS_CMD_DELXC:
      {
        struct mpls_xconnect_req *mxr = RTA_DATA(tb[MPLS_ATTR_XC]);
        struct zmpls_out_segment *out;
        struct zmpls_in_segment tmp;
        struct zmpls_in_segment *in;
        struct zmpls_xc xc;

        tmp.labelspace = mxr->mx_in.ml_index;
        tmp.label.type = ZEBRA_MPLS_LABEL_GEN;
        tmp.label.u.gen = mxr->mx_in.u.ml_gen;

        out = mpls_out_segment_find_by_out_key(mxr->mx_out.u.ml_key);
        in = mpls_in_segment_find (&tmp);

        xc.in_labelspace = in->labelspace;
        memcpy(&xc.in_label, &in->label, sizeof(struct zmpls_label));
        xc.out_index = out->index;

        if (ghdr->cmd == MPLS_CMD_NEWXC) {
	  if (in->xc)
	    return 0;
          mpls_xc_register(&xc);
        } else {
	  if (!in->xc)
	    return 0;
          mpls_xc_unregister(&xc);
        }
        break;
      }
    case MPLS_CMD_SETLABELSPACE:
      {
        struct mpls_labelspace_req *mlr = RTA_DATA(tb[MPLS_ATTR_LABELSPACE]);
        struct interface *ifp;

        ifp = if_lookup_by_index(mlr->mls_ifindex);
        if (ifp)
	  ifp->mpls_labelspace = mlr->mls_labelspace;

        break;
      }
    default:
      zlog_warn ("Unknown mpls-netlink cmd %d\n", ghdr->cmd);
      break;
    }
  return 0;
}

void
mpls_read (void)
{
#if 0
  int ret;
  int flags;
  int snb_ret;

  /* 
   * Change netlink socket flags to blocking to ensure we get 
   * a reply via nelink_parse_info
   */
  snb_ret = set_netlink_blocking (&mpls_netlink_cmd, &flags);
  if (snb_ret < 0)
    zlog (NULL, LOG_WARNING,
          "%s:%i Warning: Could not set netlink socket to blocking.",
          __FUNCTION__, __LINE__);

  /* Get NHLFE entries. */
  ret = genetlink_request (AF_MPLS, MPLS_CMD_GETNHLFE, &mpls_netlink_cmd);
  if (ret < 0)
    return;
  ret = netlink_parse_info (mpls_netlink_information_fetch,
	&mpls_netlink_cmd, NULL, 0);
  if (ret < 0)
    return;

  /* Get ILM entries */
  ret = genetlink_request (AF_MPLS, MPLS_CMD_GETILM, &mpls_netlink_cmd);
  if (ret < 0)
    return;
  ret = netlink_parse_info (mpls_netlink_information_fetch,
	&mpls_netlink_cmd, NULL, 0);
  if (ret < 0)
    return;

  /* Get LABELSPACE entries */
  ret = netlink_request (AF_MPLS, MPLS_CMD_GETLABELSPACE, &mpls_netlink_cmd);
  if (ret < 0)
    return;
  ret = netlink_parse_info (mpls_netlink_information_fetch,
	&mpls_netlink_cmd, NULL, 0);
  if (ret < 0)
    return;

  /* Get XC entries */
  ret = netlink_request (AF_MPLS, MPLS_CMD_GETXC, &mpls_netlink_cmd);
  if (ret < 0)
    return;
  ret = netlink_parse_info (mpls_netlink_information_fetch,
	&mpls_netlink_cmd, NULL, 0);
  if (ret < 0)
    return;

  /* restore flags */
  if (snb_ret == 0)
    set_netlink_nonblocking (&mpls_netlink_cmd, &flags);
#endif
}

extern struct thread_master *master;

/* Kernel route reflection. */
static int
mpls_kernel_read (struct thread *thread)
{
  int ret;
  int sock;

  sock = THREAD_FD (thread);
  ret = netlink_parse_info (mpls_netlink_information_fetch,
	&mpls_netlink, NULL, 0);
  thread_add_read (zebrad.master, mpls_kernel_read, NULL, mpls_netlink.sock);

  return 0;
}

/* Exported interface function.  This function simply calls
   netlink_socket (). */
void
mpls_kernel_init ()
{
  unsigned long groups;

  groups = MPLS_GRP_NHLFE | MPLS_GRP_ILM | MPLS_GRP_XC | MPLS_GRP_LABELSPACE;
  netlink_socket (&mpls_netlink, NETLINK_GENERIC, groups);
  netlink_socket (&mpls_netlink_cmd, NETLINK_GENERIC, 0);
  netlink_socket (&mpls_netlink_nhlfe, NETLINK_GENERIC, MPLS_GRP_NHLFE);

  /* Register kernel socket. */
  if (mpls_netlink.sock > 0)
    thread_add_read (zebrad.master, mpls_kernel_read, NULL, mpls_netlink.sock);
}
