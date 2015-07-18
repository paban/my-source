#include "zebra.h"
#include "mpls_lib.h"

static int mpls_linux_fd = 0;

int
mpls_ctrl_show_hardware(struct *vty)
{
  vty_out(vty, "MPLS-Linux: %d.%d%d%d%s ioctl control%s",
    (MPLS_LINUX_VERSION >> 24) & 0xFF,
    (MPLS_LINUX_VERSION >> 16) & 0xFF,
    (MPLS_LINUX_VERSION >> 8) & 0xFF,
    (MPLS_LINUX_VERSION) & 0xFF, VTY_NEWLINE);
  return CMD_SUCCESS;
}

int
mpls_kernel_init()
{
  mpls_linux_fd = socket(AF_INET,SOCK_DGRAM,0);
#if 0
  struct ifreq ifr;
#endif

  if(mpls_linux_fd < 0)
  {
    return -1;
  }

#if 0
  ioctl(mpls_linux_fd,SIOCMPLSILMFLUSH,&ifr);
  ioctl(mpls_linux_fd,SIOCMPLSNHLFEFLUSH,&ifr);
#endif

  return 0;
}

int
mpls_ctrl_nhlfe_unregister(struct zmpls_out_segment *old)
{
  struct mpls_out_label_req mol_req;

  mol_req.mol_label.ml_type = MPLS_LABEL_KEY;
  mol_req.mol_label.u.ml_key = old->out_key;
  return ioctl(mpls_linux_fd,SIOCMPLSNHLFEDEL,&mol_req);
}

int
mpls_ctrl_nhlfe_register(struct zmpls_out_segment *new)
{
  struct mpls_out_label_req mol_req;
  struct mpls_instr_req mir_req;
  struct interface *ifp;
  int result;

  mol_req.mol_label.ml_type = MPLS_LABEL_KEY;
  mol_req.mol_label.u.ml_key = 0;
  
  result = ioctl(mpls_linux_fd,SIOCMPLSNHLFEADD,&mol_req);
  if (result < 0)
  {
    return -1;
  }
  new->out_key = mol_req.mol_label.u.ml_key;

  mir_req.mir_direction = MPLS_OUT;
  memcpy(&mir_req.mir_label,&mol_req.mol_label,sizeof(struct mpls_label));

  mir_req.mir_instr[0].mir_opcode = MPLS_OP_PUSH;
  mir_req.mir_instr[0].mir_data.push.ml_type = MPLS_LABEL_GEN;
  mir_req.mir_instr[0].mir_data.push.u.ml_gen = new->push.u.gen;

  mir_req.mir_instr[1].mir_opcode = MPLS_OP_SET;

  if (new->nh.type & NEXTHOP_TYPE_IFNAME)
  {
      ifp = if_lookup_by_name (new->nh.ifname);
      mir_req.mir_instr[1].mir_data.set.mni_if = ifp ? ifp->ifindex : 0;
  }

  if (new->nh.type & NEXTHOP_TYPE_IPV4)
    {
      struct sockaddr_in addr;
      addr.sin_family = AF_INET;
      addr.sin_addr = new->nh.gate.ipv4;
      memcpy(&mir_req.mir_instr[1].mir_data.set.mni_addr, &addr, sizeof(addr));
    }
  else if (new->nh.type & NEXTHOP_TYPE_IPV6)
    {
      struct sockaddr_in6 addr;
      addr.sin6_family = AF_INET6;
      addr.sin6_addr = new->nh.gate.ipv6;
      memcpy(&mir_req.mir_instr[1].mir_data.set.mni_addr, &addr, sizeof(addr));
    }
  else
    {
      assert (0);
    }

  mir_req.mir_instr_length = 2;

  result = ioctl(mpls_linux_fd,SIOCSMPLSOUTINSTR,&mir_req);

  return (result < 0) ? mpls_ctrl_nhlfe_unregister(new) : 0;
}

int
mpls_ctrl_ilm_unregister(struct zmpls_in_segment *old)
{
  struct mpls_in_label_req mil_req;

  mil_req.mil_label.ml_type = MPLS_LABEL_GEN;
  mil_req.mil_label.u.ml_gen = old->label.u.gen;
  mil_req.mil_label.ml_index = old->labelspace;

  return ioctl(mpls_linux_fd,SIOCMPLSILMDEL,&mil_req);
}

int
mpls_ctrl_ilm_register(struct zmpls_in_segment *new)
{
  struct mpls_in_label_req mil_req;
  int result;

  mil_req.mil_label.ml_type = MPLS_LABEL_GEN;
  mil_req.mil_label.u.ml_gen = new->label.u.gen;
  mil_req.mil_label.ml_index = new->labelspace;

  result = ioctl(mpls_linux_fd,SIOCMPLSILMADD,&mil_req);

  if (result < 0)
  {
    return -1;
  }

  return 0;
}

int mpls_ctrl_xc_register(struct zmpls_in_segment *in,
  struct zmpls_out_segment *out)
{
  struct mpls_xconnect_req mx_req;
  int result;

  mx_req.mx_in.ml_type = MPLS_LABEL_GEN;
  mx_req.mx_in.u.ml_gen = in->label.u.gen;
  mx_req.mx_in.ml_index = in->labelspace;
  mx_req.mx_out.ml_type = MPLS_LABEL_KEY;
  mx_req.mx_out.u.ml_key = out->out_key;

  result = ioctl(mpls_linux_fd,SIOCMPLSXCADD,&mx_req);
  if (result < 0)
  {
    return -1;
  }

  return 0;
}

int mpls_ctrl_xc_unregister(struct zmpls_in_segment *in,
  struct zmpls_out_segment *out)
{
  struct mpls_xconnect_req mx_req;
  int result;

  mx_req.mx_in.ml_type = MPLS_LABEL_GEN;
  mx_req.mx_in.u.ml_gen = in->label.u.gen;
  mx_req.mx_in.ml_index = in->labelspace;
  mx_req.mx_out.ml_type = MPLS_LABEL_KEY;
  mx_req.mx_out.u.ml_key = out->out_key;

  result = ioctl(mpls_linux_fd,SIOCMPLSXCDEL,&mx_req);
  if (result < 0)
  {
    return -1;
  }

  return 0;
}

int mpls_ctrl_ftn_register(struct zmpls_ftn *ftn)
{
  return 0;
}

int mpls_ctrl_ftn_unregister(struct zmpls_ftn *ftn)
{
  return 0;
}

int mpls_ctrl_set_interface_labelspace(struct interface *ifp)
{
  struct mpls_labelspace_req  mls_req;

  mls_req.mls_ifindex    = ifp->ifindex;
  mls_req.mls_labelspace = ifp->mpls_labelspace;
  ioctl(mpls_linux_fd,SIOCSLABELSPACEMPLS,&mls_req);

  return 0;
}

int
mpls_read (void)
{
}
