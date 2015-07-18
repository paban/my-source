#include <zebra.h>
#include "if.h"

#include "ldp.h"
#include "ldp_struct.h"
#include "mpls_ifmgr_impl.h"

static int opened = 0;

mpls_ifmgr_handle mpls_ifmgr_open(mpls_instance_handle handle,
  mpls_cfg_handle cfg)
{
  opened = 1;
  return 0xdeadbeef;
}

void mpls_ifmgr_close(mpls_ifmgr_handle ifmgr_handle)
{
  opened = 0;
}

mpls_return_enum mpls_ifmgr_get_mtu(mpls_ifmgr_handle ifmgr_handle,
  mpls_if_handle if_handle, int *mtu)
{
  *mtu = if_handle->mtu;
  return MPLS_SUCCESS;
}

mpls_return_enum mpls_ifmgr_get_name(const mpls_ifmgr_handle handle,
  const mpls_if_handle if_handle, char *name, int len)
{
  strncpy(name, if_handle->name, len);
  return MPLS_SUCCESS;
}
