#include <zebra.h>
#include "command.h"
#include "mpls_lib.h"

void
mpls_kernel_init()
{
}

int
mpls_ctrl_show_hardware(struct vty *vty)
{
  vty_out(vty, "MPLS Null driver%s", VTY_NEWLINE);
  return CMD_SUCCESS;
}


int
mpls_ctrl_nhlfe_unregister(struct zmpls_out_segment *old)
{
  return 0;
}

int
mpls_ctrl_nhlfe_register(struct zmpls_out_segment *new)
{
  return 0;
}

int
mpls_ctrl_ilm_unregister(struct zmpls_in_segment *old)
{
  return 0;
}

int
mpls_ctrl_ilm_register(struct zmpls_in_segment *new)
{
  return 0;
}

int mpls_ctrl_set_interface_labelspace(struct interface *ifp, int labelspace)
{
  return 0;
}

int mpls_ctrl_xc_register(struct zmpls_in_segment *in,
  struct zmpls_out_segment *out)
{
  return 0;
}

int mpls_ctrl_xc_unregister(struct zmpls_in_segment *in,
  struct zmpls_out_segment *out)
{
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

int mpls_ctrl_tunnel_register(struct interface *ifp, int update)
{
  return 0;
}

int mpls_ctrl_tunnel_unregister(struct interface *ifp)
{
  return 0;
}

int mpls_read(void)
{
  return 0;
}
