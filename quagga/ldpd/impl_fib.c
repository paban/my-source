#include <zebra.h>
#include "prefix.h"
#include "table.h"
#include "if.h"
#include "memory.h"
#include "vty.h"

#include "mpls_compare.h"

#include "ldp.h"
#include "ldp_struct.h"
#include "ldp_cfg.h"

#include "ldp_zebra.h"
#include "mpls_fib_impl.h"

void mpls_fib_close(mpls_fib_handle handle)
{
}

mpls_fib_handle mpls_fib_open(const mpls_instance_handle handle,
  const mpls_cfg_handle cfg)
{
  struct ldp *ldp = ldp_get();
  return ldp;
}
