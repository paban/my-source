/* Module:   rsvp_vty.c
   Contains: RSVP vty function
   Module creator: original code by Vadim Suraev, vadim_suraev@hotmail.com
                   adapted by James R. Leu, jleu@mindspring.com
   */

#include <zebra.h>

#include "memory.h"
#include "thread.h"
#include "vty.h"
#include "command.h"
#include "log.h"

#include "rsvp.h"
#include "te.h"
#include "te_cspf.h"

char MplsTePrompt[50] = "%s(mpls_te_tunnel-";
char CurrentTunnelName[20];

struct cmd_node mpls_te_conf_node = {
  MPLS_TE_TUNNEL_CONF_NODE,
  ""
};

struct cmd_node mpls_te_tunnel_node = {
  MPLS_TE_TUNNEL_NODE,
  MplsTePrompt,
  1
};

int
DummyConfigWrite (struct vty *vty)
{
  return 0;
}

void
WriteTunnel (USER_LSP * pUserLsp, struct vty *vty)
{
  struct in_addr tmp;
  tmp.s_addr = ntohl (pUserLsp->params.to);
  vty_out (vty, "interface tunnel %s%s", pUserLsp->params.LspName,
	   VTY_NEWLINE);
  vty_out (vty, "  tunnel destination %s%s", inet_ntoa (tmp), VTY_NEWLINE);
  if (pUserLsp->params.lsp_params.BW)
    {
#if 0				/* for now - no support for floating point input */
      vty_out (vty, "  tunnel mpls traffic-eng bandwidth %f%s",
	       pUserLsp->params.lsp_params.BW, VTY_NEWLINE);
#else
      int bw = pUserLsp->params.lsp_params.BW;
      vty_out (vty, "  tunnel mpls traffic-eng bandwidth %d%s",
	       /*pUserLsp->params.lsp_params.BW */ bw,
	       VTY_NEWLINE);
#endif
    }

  if ((pUserLsp->params.lsp_params.setup_priority != 4) ||
      (pUserLsp->params.lsp_params.hold_priority != 4))
    {
      vty_out (vty, "  tunnel mpls traffic-eng priority %d %d%s",
	       pUserLsp->params.lsp_params.setup_priority,
	       pUserLsp->params.lsp_params.hold_priority, VTY_NEWLINE);
    }
  if (pUserLsp->params.lsp_params.hop_limit)
    {
      vty_out (vty, "  tunnel mpls traffic-eng hop-limit %d%s",
	       pUserLsp->params.lsp_params.hop_limit, VTY_NEWLINE);
    }
  if (pUserLsp->params.lsp_params.optimize_timer)
    {
      vty_out (vty, "  tunnel mpls traffic-eng optimize-timer %d%s",
	       pUserLsp->params.lsp_params.optimize_timer, VTY_NEWLINE);
    }
  if (pUserLsp->params.lsp_params.record)
    {
      vty_out (vty, "  tunnel mpls traffic-eng record-route%s", VTY_NEWLINE);
    }
  if (pUserLsp->params.lsp_params.affinity_properties)
    {
      vty_out (vty, "  tunnel mpls traffic-eng affinity %x %x%s",
	       pUserLsp->params.lsp_params.affinity_properties,
	       pUserLsp->params.lsp_params.affinity_mask, VTY_NEWLINE);
    }
  if (pUserLsp->params.retry_timer)
    {
      vty_out (vty, "  tunnel mpls traffic-eng retry-timer %d%s",
	       pUserLsp->params.retry_timer, VTY_NEWLINE);
    }
  if (pUserLsp->params.retry_limit)
    {
      vty_out (vty, "  tunnel mpls traffic-eng retry-limit %d%s",
	       pUserLsp->params.retry_limit, VTY_NEWLINE);
    }
  vty_out (vty, "  exit%s", VTY_NEWLINE);
}

int
MPLS_TE_ConfigWrite (struct vty *vty)
{
  UserLspLoop ((LSP_LOOP_CALLBACK_T) WriteTunnel, vty);
  return 0;
}

static void
TeEndConfigureCallback (struct vty *vty)
{
  USER_LSP *pUserLsp;
  SM_CALL_T *pCall;

  pUserLsp = vty->index;

  if ((pCall =
       lsp_sm_sync_invoke (0, pUserLsp, USER_LSP_REQUEST_EVENT)) == NULL)
    {
      zlog_err ("\ncan not invoke sm %s %d", __FILE__, __LINE__);
    }
  else
    {
      zlog_info ("%s %d", __FILE__, __LINE__);
      sm_call (pCall);
    }
}

DEFUN (mpls_te_tunnel,
       mpls_te_tunnel_cmd,
       "interface tunnel WORD ",
       "MPLS TE tunnel name\n" "Start MPLS TE tunnel configuration\n")
{
  USER_LSP *pUserLsp, *pCurrUserLsp;
  vty->node = MPLS_TE_TUNNEL_NODE;
  strcpy (CurrentTunnelName, argv[0]);
  strcpy (MplsTePrompt, "%s(mpls_te_tunnel-");
  strcat (MplsTePrompt, CurrentTunnelName);
  strcat (MplsTePrompt, ")# ");
  if ((pUserLsp = (USER_LSP *) XMALLOC (MTYPE_TE, sizeof (USER_LSP))) == NULL)
    {
      zlog_info ("leaving UserLspAPI %s %d", __FILE__, __LINE__);
      return CMD_SUCCESS;
    }
  memset (pUserLsp, 0, sizeof (USER_LSP));
  strcpy (pUserLsp->params.LspName, CurrentTunnelName);
  if ((pCurrUserLsp = UserLspGet (pUserLsp->params.LspName)) != NULL)
    {
      USER_LSP_PARAMS *pDestParams = &pUserLsp->params, *pSrcParams =
	&pCurrUserLsp->params;
      SECONDARY_PATH_LIST *pSrcSecPathList =
	pSrcParams->SecondaryPaths, *pDestSecPathList = NULL, *pPathListTemp;
      pDestParams->to = pSrcParams->to;
      pDestParams->from = pSrcParams->from;
      pDestParams->metric = pSrcParams->metric;
      pDestParams->no_decrement_ttl = pSrcParams->no_decrement_ttl;
      pDestParams->bw_policy = pSrcParams->bw_policy;
      pDestParams->retry_timer = pSrcParams->retry_timer;
      pDestParams->retry_limit = pSrcParams->retry_limit;
      pDestParams->FastReRoute = pSrcParams->FastReRoute;
      strcpy (pDestParams->PolicyName, pSrcParams->PolicyName);
      memcpy (&pDestParams->lsp_params, &pSrcParams->lsp_params,
	      sizeof (LSP_PATH_SHARED_PARAMS));
      strcpy (pDestParams->Primary, pSrcParams->Primary);
      if (pSrcParams->PrimaryPathParams != NULL)
	{
	  if ((pDestParams->PrimaryPathParams =
	       (LSP_PATH_SHARED_PARAMS *) XMALLOC (MTYPE_TE,
						   sizeof
						   (LSP_PATH_SHARED_PARAMS)))
	      == NULL)
	    {
	      zlog_info ("leaving UserLspAPI %s %d", __FILE__, __LINE__);
	      return CMD_SUCCESS;
	    }
	  memcpy (pDestParams->PrimaryPathParams,
		  pSrcParams->PrimaryPathParams,
		  sizeof (LSP_PATH_SHARED_PARAMS));
	}
      while (pSrcSecPathList != NULL)
	{
	  if ((pPathListTemp =
	       (SECONDARY_PATH_LIST *) XMALLOC (MTYPE_TE,
						sizeof (SECONDARY_PATH_LIST)))
	      == NULL)
	    {
	      zlog_info ("leaving UserLspAPI %s %d", __FILE__, __LINE__);
	      return CMD_SUCCESS;
	    }
	  memset (pPathListTemp, 0, sizeof (SECONDARY_PATH_LIST));
	  if (pDestParams->SecondaryPaths == NULL)
	    {
	      pDestSecPathList = pDestParams->SecondaryPaths = pPathListTemp;
	    }
	  else
	    {
	      pDestSecPathList->next = pPathListTemp;
	      pDestSecPathList = pDestSecPathList->next;
	    }
	  strcpy (pDestSecPathList->Secondary, pSrcSecPathList->Secondary);
	  if (pSrcSecPathList->SecondaryPathParams != NULL)
	    {
	      if ((pDestSecPathList->SecondaryPathParams =
		   (LSP_PATH_SHARED_PARAMS *) XMALLOC (MTYPE_TE,
						       sizeof
						       (LSP_PATH_SHARED_PARAMS)))
		  == NULL)
		{
		  zlog_info ("leaving UserLspAPI %s %d", __FILE__, __LINE__);
		  return CMD_SUCCESS;
		}
	      memcpy (pDestSecPathList->SecondaryPathParams,
		      pSrcSecPathList->SecondaryPathParams,
		      sizeof (LSP_PATH_SHARED_PARAMS));
	    }
	  pSrcSecPathList = pSrcSecPathList->next;
	}
    }
  else
    {
      pUserLsp->params.lsp_params.setup_priority =
	pUserLsp->params.lsp_params.hold_priority = 4;
    }
  vty->index = pUserLsp;
  return CMD_SUCCESS;
}

DEFUN (no_mpls_te_tunnel,
       no_mpls_te_tunnel_cmd,
       "no interface tunnel WORD",
       "MPLS TE tunnel name\n" "Remove MPLS TE tunnel configuration\n")
{
  USER_LSP *pCurrUserLsp;
  SM_CALL_T *pCall;

  strcpy (CurrentTunnelName, "");
  if ((pCurrUserLsp = UserLspGet (argv[0])) != NULL)
    {
      pCurrUserLsp->params.lsp_params.disable = TRUE;
      if ((pCall =
	   lsp_sm_sync_invoke (0, pCurrUserLsp,
			       USER_LSP_REQUEST_EVENT)) == NULL)
	{
	  zlog_err ("\ncan not invoke sm %s %d", __FILE__, __LINE__);
	}
      else
	{
	  zlog_info ("%s %d", __FILE__, __LINE__);
	  sm_call (pCall);
	}
    }
  return CMD_SUCCESS;
}

DEFUN (show_mpls_te_tunnel,
       show_mpls_te_tunnel_cmd,
       "show mpls traffic-eng tunnel WORD", "MPLS TE Tunnel's name")
{
  UserLspsDump (argv[0], vty);
  return CMD_SUCCESS;
}

DEFUN (show_mpls_te_tunnels,
       show_mpls_te_tunnels_cmd,
       "show mpls traffic-eng tunnels", "Shows MPLS TE tunnels")
{
  UserLspsDump (NULL, vty);
  return CMD_SUCCESS;
}

DEFUN (mpls_te_tunnel_dest,
       mpls_te_tunnel_dest_cmd,
       "tunnel destination A.B.C.D",
       "MPLS TE Tunnel's destination IP address")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  struct in_addr dest;
  int ret;
  ret = inet_aton (argv[0], &dest);
  if (!ret)
    {
      vty_out (vty, "Please specify destination IP address %s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  pDestParams->to = ntohl (dest.s_addr);
  return CMD_SUCCESS;
}

DEFUN (mpls_te_tunnel_bandwidth,
       mpls_te_tunnel_bandwidth_cmd,
       "tunnel mpls traffic-eng bandwidth <0-4294967295>",
       "MPLS TE Tunnel's bandwidth")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.BW = atol (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (no_mpls_te_tunnel_bandwidth,
       no_mpls_te_tunnel_bandwidth_cmd,
       "no tunnel mpls traffic-eng bandwidth", "MPLS TE Tunnel's bandwidth")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.BW = 0;
  return CMD_SUCCESS;
}

DEFUN (mpls_te_tunnel_sprio,
       mpls_te_tunnel_sprio_cmd,
       "tunnel mpls traffic-eng priority <0-7>",
       "MPLS TE Tunnel's setup priority")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.setup_priority = atol (argv[0]);
  pDestParams->lsp_params.hold_priority =
    pDestParams->lsp_params.setup_priority;
  return CMD_SUCCESS;
}

DEFUN (mpls_te_tunnel_shprio,
       mpls_te_tunnel_shprio_cmd,
       "tunnel mpls traffic-eng priority <0-7> <0-7>",
       "MPLS TE Tunnel's setup priority" "MPLS TE Tunnel's hold priority")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.setup_priority = atol (argv[0]);
  pDestParams->lsp_params.hold_priority = atol (argv[1]);
  return CMD_SUCCESS;
}

DEFUN (no_mpls_te_tunnel_prio,
       no_mpls_te_tunnel_prio_cmd,
       "no tunnel mpls traffic-eng priority", "MPLS TE Tunnel's priority")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.hold_priority =
    pDestParams->lsp_params.setup_priority = 4;
  return CMD_SUCCESS;
}

DEFUN (mpls_te_tunnel_hop_limit,
       mpls_te_tunnel_hop_limit_cmd,
       "tunnel mpls traffic-eng hop-limit <0-255>",
       "MPLS TE Tunnel's path hop limit")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.hop_limit = atol (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (no_mpls_te_tunnel_hop_limit,
       no_mpls_te_tunnel_hop_limit_cmd,
       "no tunnel mpls traffic-eng hop-limit",
       "MPLS TE Tunnel's path hop limit")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.hop_limit = 0;
  return CMD_SUCCESS;
}

DEFUN (mpls_te_tunnel_optimize_timer,
       mpls_te_tunnel_optimize_timer_cmd,
       "tunnel mpls traffic-eng optimize-timer <0-604800>",
       "MPLS TE Tunnel's optimize timer")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.optimize_timer = atol (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (no_mpls_te_tunnel_optimize_timer,
       no_mpls_te_tunnel_optimize_timer_cmd,
       "no tunnel mpls traffic-eng optimize-timer",
       "MPLS TE Tunnel's optimize timer")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.optimize_timer = 0;
  return CMD_SUCCESS;
}

DEFUN (mpls_te_tunnel_record_route,
       mpls_te_tunnel_record_route_cmd,
       "tunnel mpls traffic-eng record-route",
       "MPLS TE Tunnel's record route")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.record = 1;
  return CMD_SUCCESS;
}

DEFUN (no_mpls_te_tunnel_record_route,
       no_mpls_te_tunnel_record_route_cmd,
       "no tunnel mpls traffic-eng record-route",
       "MPLS TE Tunnel's record route")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.record = 0;
  return CMD_SUCCESS;
}

#if 0				/* for now - no support for hexa input */
DEFUN (mpls_te_tunnel_affinity,
       mpls_te_tunnel_affinity_cmd,
       "tunnel mpls traffic-eng affinity <0-255>",
       "MPLS TE Tunnel's resource affinity")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.affinity_properties = atol (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (no_mpls_te_tunnel_affinity,
       no_mpls_te_tunnel_affinity_cmd,
       "no tunnel mpls traffic-eng affinity",
       "MPLS TE Tunnel's resource affinity")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->lsp_params.affinity_properties = 0;
  return CMD_SUCCESS;
}
#endif

DEFUN (mpls_te_tunnel_retry_timer,
       mpls_te_tunnel_retry_timer_cmd,
       "tunnel mpls traffic-eng retry-timer <1-604800>",
       "MPLS TE Tunnel's setup retry timer")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->retry_timer = atol (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (no_mpls_te_tunnel_retry_timer,
       no_mpls_te_tunnel_retry_timer_cmd,
       "no tunnel mpls traffic-eng retry-timer",
       "MPLS TE Tunnel's setup retry timer")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->retry_timer = 0;
  return CMD_SUCCESS;
}

DEFUN (mpls_te_tunnel_retry_limit,
       mpls_te_tunnel_retry_limit_cmd,
       "tunnel mpls traffic-eng retry-limit <0-4294967295>",
       "MPLS TE Tunnel's setup retry attempts limit")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->retry_limit = atol (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (no_mpls_te_tunnel_retry_limit,
       no_mpls_te_tunnel_retry_limit_cmd,
       "no tunnel mpls traffic-eng retry-limit",
       "MPLS TE Tunnel's setup retry attempts limit")
{
  USER_LSP *pUserLsp = vty->index;
  USER_LSP_PARAMS *pDestParams = &pUserLsp->params;
  pDestParams->retry_limit = 0;
  return CMD_SUCCESS;
}


DEFUN (show_mpls_te_links,
       show_mpls_te_links_cmd, "show mpls traffic-eng links", "MPLS TE links")
{
  rdb_te_links_dump (vty);
  return CMD_SUCCESS;
}

DEFUN (show_mpls_te_path_cache,
       show_mpls_te_path_cache_cmd,
       "show mpls traffic-eng path-cache",
       "MPLS TE CSPF calculated path cache")
{
  rdb_path_dump (vty);
  return CMD_SUCCESS;
}

DEFUN (show_mpls_te_remote_link,
       show_mpls_te_remote_link_cmd,
       "show mpls traffic-eng remote-link", "MPLS TE remote links cache")
{
  rdb_remote_link_dump (vty);
  return CMD_SUCCESS;
}

DEFUN (show_mpls_te_next_hop,
       show_mpls_te_next_hop_cmd,
       "show mpls traffic-eng next-hop", "MPLS TE next hops cache")
{
  rdb_next_hop_dump (vty);
  return CMD_SUCCESS;
}

DEFUN (show_mpls_te_configured_paths,
       show_mpls_te_configured_paths_cmd,
       "show mpls traffic-eng static-path", "MPLS TE configured static paths")
{
  rdb_static_path_dump (NULL, vty);
  return CMD_SUCCESS;
}

DEFUN (show_mpls_te_ip_2_rtr_id_map,
       show_mpls_te_ip_2_rtr_id_map_cmd,
       "show mpls traffic-eng ip2routerID",
       "MPLS TE show I/F IP addresses to RouterIDs mapping")
{
  rdb_remote_link_router_id_mapping_dump (vty);
  return CMD_SUCCESS;
}


DEFUN (show_rsvp_te_psbs,
       show_rsvp_te_psbs_cmd, "show rsvpte psbs", "RSVP TE PSBs")
{
  PSB_KEY PsbKey;
  memset (&PsbKey, 0, sizeof (PSB_KEY));
  DumpPSB (&PsbKey, vty);
  return CMD_SUCCESS;
}

DEFUN (show_rsvp_te_rsbs,
       show_rsvp_te_rsbs_cmd, "show rsvpte rsbs", "RSVP TE RSBs")
{
  RSB_KEY RsbKey;
  memset (&RsbKey, 0, sizeof (RSB_KEY));
  DumpRSB (&RsbKey, vty);
  return CMD_SUCCESS;
}

DEFUN (show_rsvp_te_psb,
       show_rsvp_te_psb_cmd, "show rsvpte psb A.B.C.D", "RSVP TE PSB")
{
  PSB_KEY PsbKey;
  struct in_addr dest;
  int ret;
  ret = inet_aton (argv[0], &dest);
  if (!ret)
    {
      vty_out (vty, "Please specify destination IP address %s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  memset (&PsbKey, 0, sizeof (PSB_KEY));
  PsbKey.Session.Dest = dest.s_addr;
  DumpPSB (&PsbKey, vty);
  return CMD_SUCCESS;
}

DEFUN (show_rsvp_te_rsb,
       show_rsvp_te_rsb_cmd, "show rsvpte rsb A.B.C.D", "RSVP TE RSB ")
{
  RSB_KEY RsbKey;
  struct in_addr dest;
  int ret;

  ret = inet_aton (argv[0], &dest);
  if (!ret)
    {
      vty_out (vty, "Please specify destination IP address %s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  memset (&RsbKey, 0, sizeof (RSB_KEY));
  RsbKey.Session.Dest = dest.s_addr;
  DumpRSB (&RsbKey, vty);
  return CMD_SUCCESS;
}

DEFUN (show_rsvp_te_statistics,
       show_rsvp_te_statistics_cmd,
       "show rsvpte statistics", "RSVP TE statistics")
{
  DumpRsvpStatistics (vty);
  return CMD_SUCCESS;
}

void
rsvp_vty ()
{
  install_node (&mpls_te_tunnel_node, DummyConfigWrite);
  install_node (&mpls_te_conf_node, MPLS_TE_ConfigWrite);

  /* Install ospf commands. */
  install_element (VIEW_NODE, &show_mpls_te_tunnel_cmd);
  install_element (VIEW_NODE, &show_mpls_te_tunnels_cmd);
  install_element (VIEW_NODE, &show_mpls_te_links_cmd);
  install_element (VIEW_NODE, &show_mpls_te_path_cache_cmd);
  install_element (VIEW_NODE, &show_mpls_te_remote_link_cmd);
  install_element (VIEW_NODE, &show_mpls_te_next_hop_cmd);
  install_element (VIEW_NODE, &show_mpls_te_configured_paths_cmd);
  install_element (VIEW_NODE, &show_mpls_te_ip_2_rtr_id_map_cmd);

  install_element (ENABLE_NODE, &show_mpls_te_tunnel_cmd);
  install_element (ENABLE_NODE, &show_mpls_te_tunnels_cmd);
  install_element (ENABLE_NODE, &show_mpls_te_links_cmd);
  install_element (ENABLE_NODE, &show_mpls_te_path_cache_cmd);
  install_element (ENABLE_NODE, &show_mpls_te_remote_link_cmd);
  install_element (ENABLE_NODE, &show_mpls_te_next_hop_cmd);
  install_element (ENABLE_NODE, &show_mpls_te_configured_paths_cmd);
  install_element (ENABLE_NODE, &show_mpls_te_ip_2_rtr_id_map_cmd);

  install_element (CONFIG_NODE, &mpls_te_tunnel_cmd);
  install_element (CONFIG_NODE, &no_mpls_te_tunnel_cmd);

  install_default (MPLS_TE_TUNNEL_NODE);
  install_element (MPLS_TE_TUNNEL_NODE, &mpls_te_tunnel_dest_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &mpls_te_tunnel_bandwidth_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &no_mpls_te_tunnel_bandwidth_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &mpls_te_tunnel_sprio_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &mpls_te_tunnel_shprio_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &no_mpls_te_tunnel_prio_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &mpls_te_tunnel_hop_limit_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &no_mpls_te_tunnel_hop_limit_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &mpls_te_tunnel_optimize_timer_cmd);
  install_element (MPLS_TE_TUNNEL_NODE,
		   &no_mpls_te_tunnel_optimize_timer_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &mpls_te_tunnel_record_route_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &no_mpls_te_tunnel_record_route_cmd);
#if 0				/* for now - no support for hexa input */
  install_element (MPLS_TE_TUNNEL_NODE, &mpls_te_tunnel_affinity_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &no_mpls_te_tunnel_affinity_cmd);
#endif
  install_element (MPLS_TE_TUNNEL_NODE, &mpls_te_tunnel_retry_timer_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &no_mpls_te_tunnel_retry_timer_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &mpls_te_tunnel_retry_limit_cmd);
  install_element (MPLS_TE_TUNNEL_NODE, &no_mpls_te_tunnel_retry_limit_cmd);

  install_element (VIEW_NODE, &show_rsvp_te_psbs_cmd);
  install_element (ENABLE_NODE, &show_rsvp_te_psbs_cmd);
  install_element (VIEW_NODE, &show_rsvp_te_rsbs_cmd);
  install_element (ENABLE_NODE, &show_rsvp_te_rsbs_cmd);

  install_element (VIEW_NODE, &show_rsvp_te_psb_cmd);
  install_element (ENABLE_NODE, &show_rsvp_te_psb_cmd);
  install_element (VIEW_NODE, &show_rsvp_te_rsb_cmd);
  install_element (ENABLE_NODE, &show_rsvp_te_rsb_cmd);

  install_element (VIEW_NODE, &show_rsvp_te_statistics_cmd);
  install_element (ENABLE_NODE, &show_rsvp_te_statistics_cmd);
}
