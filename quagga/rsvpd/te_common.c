/* Module:   te_common_proc.c
   Contains: TE application common procedures
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "te.h"
#include "thread.h"
#include "vty.h"

extern struct thread_master *master;

PATRICIA_TREE PlatformWideFreeLabels;
PATRICIA_TREE BwOwnersTree[8];
PATRICIA_TREE IfBwOwnersTree[8];
PATRICIA_TREE SeparateAdaptiveLspsTrunkTree;
PATRICIA_TREE SeparateNonAdaptiveLspsTrunkTree;
PATRICIA_TREE NonSeparateServiceLspsTrunkTree;
PATRICIA_TREE NonSeparateServiceBWAdaptiveLspsTrunkTree;
PATRICIA_TREE NonSeparateTunnelsLspsTrunkTree;
PATRICIA_TREE SLAsTree;
PATRICIA_TREE ConstraintRouteResReqTree;
PATRICIA_TREE ConstraintRouteResClientsTree;

USER_LSP_LIST *UserLspListHead;

#define MAX_TUNNELS_IF 1000
#define TUNNELS_IF_OFFSET 100

IPV4_ADDR tunnels_if_array[MAX_TUNNELS_IF];
extern LABEL_ENTRY PlatformWideLabelSpace[LABEL_SPACE_SIZE];

SM_CALL_T *(*sm_handler[MAX_SM]) (SM_T * pSm, SM_EVENT_T * sm_data) =
{
  lsp_sm_handler,
    transit_req_sm_handler, constraint_route_resolution_sm_handler
#ifdef FRR_SM_DEFINED
    , fast_reroute_sm_handler
#endif
};

void
sm_gen_event_trace (SM_E event)
{
  switch (event)
    {
    case USER_LSP_REQUEST_EVENT:
      zlog_info ("USER_LSP_REQUEST_EVENT\n");
      break;
    case SLA_USER_REQUEST_EVENT:
      zlog_info ("SLA_USER_REQUEST_EVENT\n");
      break;
    case INGRESS_LSP_REQUEST_EVENT:
      zlog_info ("INGRESS_LSP_REQUEST_EVENT\n");
      break;
    case SLA_DELETE_USER_REQUEST_EVENT:
      zlog_info ("SLA_DELETE_USER_REQUEST_EVENT\n");
      break;
    case INGRESS_LSP_DELETE_REQUEST_EVENT:
      zlog_info ("INGRESS_LSP_DELETE_REQUEST_EVENT\n");
      break;
    case TRANSIT_REQ_EVENT:
      zlog_info ("TRANSIT_REQ_EVENT\n");
      break;
    case CONSTRAINT_ROUTE_RESOLUTION_REQ_EVENT:
      zlog_info ("CONSTRAINT_ROUTE_RESOLUTION_REQ_EVENT\n");
      break;
    case CONSTRAINT_ROUTE_RESOLVED_EVENT:
      zlog_info ("CONSTRAINT_ROUTE_RESOLVED_EVENT\n");
      break;
    case CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT:
      zlog_info ("CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT\n");
      break;
    case CSPF_REPLY_EVENT:
      zlog_info ("CSPF_REPLY_EVENT\n");
      break;
    case DYNAMIC_ADAPTATION_REQ_EVENT:
      zlog_info ("DYNAMIC_ADAPTATION_REQ_EVENT\n");
      break;
    case SLA_ADAPTATION_REQ_EVENT:
      zlog_info ("SLA_ADAPTATION_REQ_EVENT\n");
      break;
    case SLA_ADAPTATION_COMPLETE_EVENT:
      zlog_info ("SLA_ADAPTATION_COMPLETE_EVENT\n");
      break;
    case SLA_ADAPTATION_FAILED_EVENT:
      zlog_info ("SLA ADAPTATION FAILED EVENT\n");
      break;
    case INGRESS_LSP_OPERATION_COMPLETE_EVENT:
      zlog_info ("INGRESS_LSP_OPERATION_COMPLETE_EVENT\n");
      break;
    case INGRESS_LSP_OPERATION_FAILED_EVENT:
      zlog_info ("INGRESS_LSP_OPERATION_FAILED_EVENT\n");
      break;
    case MPLS_SIGNALING_INGRESS_ESTABLISHED_NOTIFICATION_EVENT:
      zlog_info ("MPLS_SIGNALING_INGRESS_ESTABLISHED_NOTIFICATION_EVENT\n");
      break;
    case MPLS_SIGNALING_INGRESS_FAILED_NOTIFICATION_EVENT:
      zlog_info ("MPLS_SIGNALING_INGRESS_FAILED_NOTIFICATION_EVENT\n");
      break;
    case LSP_SETUP_TIMER_EXPIRY:
      zlog_info ("LSP_SETUP_TIMER_EXPIRY\n");
      break;
    case ADAPTIVITY_TIMER_EXPIRY:
      zlog_info ("ADAPTIVITY_TIMER_EXPIRY\n");
      break;
    case RETRY_TIMER_EXPIRY:
      zlog_info ("RETRY_TIMER_EXPIRY\n");
      break;
    case CSPF_RETRY_EVENT:
      zlog_info ("CSPF_RETRY_EVENT\n");
      break;
    default:
      zlog_err ("\nunknown event %d", event);
    }
}


int
sm_gen_async_event_send (SM_T * sm, SM_EVENT_E event, void *data)
{
  TE_MSG dmsg;
  SM_CALL_T *sm_packet;
  SM_EVENT_T *pEvent = (SM_EVENT_T *) XMALLOC (MTYPE_TE, sizeof (SM_EVENT_T));
  if (pEvent == NULL)
    {
      zlog_err ("\nmalloc failed %s %d %d", __FILE__, __LINE__, event);
      return 1;
    }
  dmsg.event = EVENT_TE_SM;
  pEvent->event = event;
  pEvent->data = data;
  sm_packet = (SM_CALL_T *) XMALLOC (MTYPE_TE, sizeof (SM_CALL_T));
  if (sm_packet == NULL)
    {
      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
      XFREE (MTYPE_TE, pEvent);
      return 1;
    }
  sm_packet->sm = sm;
  sm_packet->sm_data = pEvent;
  dmsg.u.te_sm_event.data = sm_packet;
  te_send_msg (&dmsg, sizeof (TE_MSG));
  return 0;
}

SM_CALL_T *
sm_gen_sync_event_send (SM_T * sm, SM_EVENT_E event, void *data)
{
  SM_CALL_T *sm_packet;
  SM_EVENT_T *pEvent = (SM_EVENT_T *) XMALLOC (MTYPE_TE, sizeof (SM_EVENT_T));
  if (pEvent == NULL)
    {
      zlog_err ("\nmalloc failed %s %d %d", __FILE__, __LINE__, event);
      return NULL;
    }
  pEvent->event = event;
  pEvent->data = data;
  sm_packet = (SM_CALL_T *) XMALLOC (MTYPE_TE, sizeof (SM_CALL_T));
  if (sm_packet == NULL)
    {
      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
      XFREE (MTYPE_TE, pEvent);
      return NULL;
    }
  sm_packet->sm = sm;
  sm_packet->sm_data = pEvent;
  return sm_packet;
}

void
sm_call (SM_CALL_T * sm_packet)
{
  SM_CALL_T *pPacket = sm_packet, *pPrevPacket;
  SM_E sm_type;

  do
    {
      sm_type = pPacket->sm->sm_type;
      pPrevPacket = pPacket;
      pPacket = sm_handler[sm_type] (pPacket->sm, pPacket->sm_data);
      XFREE (MTYPE_TE, pPrevPacket->sm_data);
      XFREE (MTYPE_TE, pPrevPacket);
    }
  while (pPacket != NULL);
}

SM_T *
sm_gen_alloc (SM_T * caller, SM_E sm_type)
{
  SM_T *pSmGen;
  pSmGen = (SM_T *) XMALLOC (MTYPE_TE, sizeof (SM_T));
  if (pSmGen == NULL)
    {
      zlog_err ("\ncannot allocate memory %s %d", __FILE__, __LINE__);
      return NULL;
    }
  pSmGen->data = NULL;
  pSmGen->sm_type = sm_type;
  pSmGen->caller = caller;
  pSmGen->state = INIT_STATE;
  return pSmGen;
}

void
sm_gen_free (SM_T * sm)
{
  XFREE (MTYPE_TE, sm);
  return;
}

#if 1

//extern PATRICIA_TREE BwOwnersTree[8];

void
BwHoldTimerExpiry (BW_HOLD_TIMER_DATA * pBwHoldTimerExpiry)
{
  BW_OWNER_ENTRY *pBwOwnerEntry;
  BW_OWNER_DATA *pBwOwnerData;
  COMPONENT_LINK *pComponentLink = NULL;
  TE_LINK *pTeLink = NULL;
  int j;
  uns8 Priority = pBwHoldTimerExpiry->Priority;

  if ((pBwOwnerEntry =
       (BW_OWNER_ENTRY *) patricia_tree_get (&BwOwnersTree[Priority],
					     (const uns8 *)
					     &pBwHoldTimerExpiry->key)) !=
      NULL)
    {
      pBwOwnerData = pBwOwnerEntry->pBwOwnerData;
      while (pBwOwnerData != NULL)
	{
	  if ((pBwOwnerData->TeLinkId == pBwHoldTimerExpiry->TeLinkId) &&
	      (pBwOwnerData->OutIf == pBwHoldTimerExpiry->OutIf))
	    {
	      if (pBwOwnerData !=
		  (BW_OWNER_DATA *) pBwHoldTimerExpiry->handle)
		{
		  zlog_err ("unexpected timer expiry %s %d", __FILE__,
			    __LINE__);
		  pBwOwnerData->PreAllocBW = 0;
		  pBwOwnerData->BwHoldTimer.data.bw_hold_data.BW = 0;
		  pBwOwnerData->BwHoldTimer.is_active = FALSE;
		  return;
		}
	      if (pBwOwnerData->PreAllocBW !=
		  pBwOwnerData->BwHoldTimer.data.bw_hold_data.BW)
		{
		  zlog_err ("unexpected timer expiry %s %d", __FILE__,
			    __LINE__);
		  pBwOwnerData->PreAllocBW = 0;
		  pBwOwnerData->BwHoldTimer.data.bw_hold_data.BW = 0;
		  pBwOwnerData->BwHoldTimer.is_active = FALSE;
		  return;
		}
	      if (rdb_get_component_link (pBwHoldTimerExpiry->TeLinkId,
					  pBwHoldTimerExpiry->OutIf,
					  &pComponentLink) != E_OK)
		{
		  zlog_err ("cannot get component link %s %d", __FILE__,
			    __LINE__);
		  pBwOwnerData->PreAllocBW = 0;
		  pBwOwnerData->BwHoldTimer.data.bw_hold_data.BW = 0;
		  pBwOwnerData->BwHoldTimer.is_active = FALSE;
		  return;
		}
	      zlog_info
		("releasing BW: DestIP %x Source %x tunnel %x TmrBW %f EntryBW %f Priority %x",
		 pBwHoldTimerExpiry->key.Session.Dest,
		 pBwHoldTimerExpiry->key.Session.ExtTunelId,
		 pBwHoldTimerExpiry->key.Session.TunnelId,
		 pBwHoldTimerExpiry->BW, pBwOwnerData->BW,
		 pBwHoldTimerExpiry->Priority);
	      if (rdb_get_te_link (pBwHoldTimerExpiry->TeLinkId, &pTeLink) !=
		  E_OK)
		{
		  zlog_err ("\ncannot get TE link %s %d", __FILE__, __LINE__);
		}
	      for (j = Priority; j < 8; j++)
		{
		  pComponentLink->ReservableBW[j] += pBwOwnerData->PreAllocBW;
		  pTeLink->te_link_properties.ReservableBW[j] +=
		    pBwOwnerData->PreAllocBW;
		}
	      rdb_te_link_max_lsp_bw_calc (pTeLink);
	      pBwOwnerData->PreAllocBW = 0;
	      pBwOwnerData->BwHoldTimer.is_active = FALSE;
	      pBwOwnerData->BwHoldTimer.data.bw_hold_data.BW = 0;
	      return;
	    }
	  pBwOwnerData = pBwOwnerData->next;
	}
      zlog_info ("\nBW owner data is not found %s %d", __FILE__, __LINE__);
    }
  else
    {
      zlog_err
	("\ncannot get entry for BW holder %s %d destIP %x Tunnel ID %x SourceIP %x %x %x Priority %x",
	 __FILE__, __LINE__, pBwHoldTimerExpiry->key.Session.Dest,
	 pBwHoldTimerExpiry->key.Session.TunnelId,
	 pBwHoldTimerExpiry->key.Session.ExtTunelId,
	 pBwHoldTimerExpiry->key.SenderTemplate.IpAddr,
	 pBwHoldTimerExpiry->key.SenderTemplate.LspId,
	 pBwHoldTimerExpiry->Priority);
    }
}

void
LspSetupTimerExpiry (LSP_SETUP_TIMER_DATA * pData)
{
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  SM_CALL_T *pCall = NULL;
  if (FindTunnel (&pData->key, &pTunnel, ALL_TRUNKS) != TRUE)
    {
      zlog_err ("\ncannot find tunnel %x %x %x",
		pData->key.Session.Dest,
		pData->key.Session.ExtTunelId, pData->key.Session.TunnelId);
      return;
    }
  if (pTunnel->sm_handle == 0)
    {
      zlog_err
	("\nThere is no SM to process LSP SETUP RETRY for tunnle %x %x %x",
	 pData->key.Session.Dest, pData->key.Session.ExtTunelId,
	 pData->key.Session.TunnelId);
      return;
    }
  if ((pCall =
       sm_gen_sync_event_send (pTunnel->sm_handle, LSP_SETUP_TIMER_EXPIRY,
			       &pData->key)) == NULL)
    {
      zlog_err ("\ncannot send sync event %s %d", __FILE__, __LINE__);
      return;
    }
  sm_call (pCall);
}

void
AdaptivityTimerExpiry (ADAPTIVITY_TIMER_DATA * pData)
{
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  SM_CALL_T *pCall = NULL;
  if (FindTunnel (&pData->key, &pTunnel, ALL_TRUNKS) != TRUE)
    {
      zlog_err ("\ncannot find tunnel %x %x %x",
		pData->key.Session.Dest,
		pData->key.Session.ExtTunelId, pData->key.Session.TunnelId);
      return;
    }
  if (pTunnel->sm_handle == 0)
    {
      zlog_err
	("\nThere is no SM to process LSP SETUP RETRY for tunnle %x %x %x",
	 pData->key.Session.Dest, pData->key.Session.ExtTunelId,
	 pData->key.Session.TunnelId);
      return;
    }
  if ((pCall =
       sm_gen_sync_event_send (pTunnel->sm_handle, ADAPTIVITY_TIMER_EXPIRY,
			       &pData->key)) == NULL)
    {
      zlog_err ("\ncannot send sync event %s %d", __FILE__, __LINE__);
      return;
    }
  sm_call (pCall);
}

void
LspSetupRetryTimerExpiry (LSP_SETUP_RETRY_TIMER_DATA * pData)
{
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  SM_CALL_T *pCall = NULL;
  if (FindTunnel (&pData->key, &pTunnel, ALL_TRUNKS) != TRUE)
    {
      zlog_err ("\ncannot find tunnel %x %x %x",
		pData->key.Session.Dest,
		pData->key.Session.ExtTunelId, pData->key.Session.TunnelId);
      return;
    }
  if (pTunnel->sm_handle == 0)
    {
      zlog_err
	("\nThere is no SM to process LSP SETUP RETRY for tunnlel %x %x %x",
	 pData->key.Session.Dest, pData->key.Session.ExtTunelId,
	 pData->key.Session.TunnelId);
      return;
    }
  if ((pCall =
       sm_gen_sync_event_send (pTunnel->sm_handle, RETRY_TIMER_EXPIRY,
			       &pData->key)) == NULL)
    {
      zlog_err ("\ncannot send sync event %s %d", __FILE__, __LINE__);
      return;
    }
  sm_call (pCall);
}

void
CspfRetryTimerExpiry (CSPF_RETRY_TIMER_DATA * pData)
{
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  SM_CALL_T *pCall = NULL;
  if (FindTunnel (&pData->key, &pTunnel, ALL_TRUNKS) != TRUE)
    {
      zlog_err ("\ncannot find tunnel %x %x %x",
		pData->key.Session.Dest,
		pData->key.Session.ExtTunelId, pData->key.Session.TunnelId);
      return;
    }
  if (pTunnel->sm_handle == 0)
    {
      zlog_err ("There is no SM to process CSPF RETRY for tunnlel %x %x %x",
		pData->key.Session.Dest,
		pData->key.Session.ExtTunelId, pData->key.Session.TunnelId);
      return;
    }
  if ((pCall =
       sm_gen_sync_event_send (pTunnel->sm_handle, CSPF_RETRY_EVENT,
			       &pData->key)) == NULL)
    {
      zlog_err ("\ncannot send sync event %s %d", __FILE__, __LINE__);
      return;
    }
  sm_call (pCall);
}

void
te_timer_expiry (struct thread *thread)
{
  TE_TMR *tmr = (TE_TMR *) THREAD_ARG (thread);
  int period = THREAD_VAL (tmr->thread);
  tmr->thread = thread_add_timer (master, te_timer_expiry, tmr, period);

  tmr->is_active = FALSE;

  switch (tmr->type)
    {
    case BW_HOLD_EXPIRY:
      zlog_info
	("BW Hold expiry: TE Link ID %x IP Dest %x Tunnel ID %x Source %x BW %f Priority %x",
	 tmr->data.bw_hold_data.TeLinkId,
	 tmr->data.bw_hold_data.key.Session.Dest,
	 tmr->data.bw_hold_data.key.Session.TunnelId,
	 tmr->data.bw_hold_data.key.Session.ExtTunelId,
	 tmr->data.bw_hold_data.BW, tmr->data.bw_hold_data.Priority);
      BwHoldTimerExpiry (&tmr->data.bw_hold_data);
      break;
    case LSP_SETUP_EXPIRY:
      zlog_info ("LSP SETUP expiry: %x %x %x",
		 tmr->data.lsp_setup_data.key.Session.Dest,
		 tmr->data.lsp_setup_data.key.Session.TunnelId,
		 tmr->data.lsp_setup_data.key.Session.ExtTunelId);
      LspSetupTimerExpiry (&tmr->data.lsp_setup_data);
      break;
    case ADAPTIVITY_EXPIRY:
      AdaptivityTimerExpiry (&tmr->data.adaptivity_timer_data);
      break;
    case LSP_SETUP_RETRY_EXPIRY:
      zlog_info ("LSP SETUP RETRY expiry: %x %x %x",
		 tmr->data.lsp_setup_retry_data.key.Session.Dest,
		 tmr->data.lsp_setup_retry_data.key.Session.TunnelId,
		 tmr->data.lsp_setup_retry_data.key.Session.ExtTunelId);
      LspSetupRetryTimerExpiry (&tmr->data.lsp_setup_retry_data);
      break;
    case CSPF_RETRY_EXPIRY:
      zlog_info ("CSPF RETRY expiry: %x %x %x",
		 tmr->data.cspf_retry_data.key.Session.Dest,
		 tmr->data.cspf_retry_data.key.Session.TunnelId,
		 tmr->data.cspf_retry_data.key.Session.ExtTunelId);
      CspfRetryTimerExpiry (&tmr->data.cspf_retry_data);
      break;
#if 0
    case BYPASS_TUNNEL_RETRY_EXPIRY:
      dmsg.event = EVENT_BYPASS_TUNNEL_RETRY_EXPIRY;
      memcpy (&dmsg.u.bypass_retry_expiry.key,
	      &tmr->data.bypass_retry_data, sizeof (FRR_SM_KEY));
      zlog_info ("\nBYPASS TUNNEL RETRY expiry: %x %x %x",
		 tmr->data.bypass_retry_data.merge_node,
		 tmr->data.bypass_retry_data.OutIfIndex,
		 tmr->data.bypass_retry_data.protected_node);
      te_send_msg (&dmsg, sizeof (TE_MSG));
      break;
#endif
    default:
      zlog_err ("\ndefault case %s %d", __FILE__, __LINE__);
    }
  return;
}

uns32
te_start_timer (TE_TMR * tmr, TE_TMR_E type, uns32 period)
{
  zlog_info ("entering te_start_timer");
  if (tmr->thread)
    {
      te_stop_timer (tmr);
    }
  tmr->type = type;
  if (tmr->is_active == FALSE)
    {
      tmr->thread = thread_add_timer (master, te_timer_expiry, tmr, period);
      THREAD_VAL (tmr->thread) = period;
      tmr->is_active = TRUE;
    }
  zlog_info ("leaving te_start_timer");
  return E_OK;
}

void
te_stop_timer (TE_TMR * tmr)
{
  /* Stop the timer if it is active... */
  zlog_info ("entering te_stop_timer");
  if (tmr->is_active == TRUE)
    {
      thread_cancel (tmr->thread);
      tmr->thread = NULL;
      tmr->is_active = FALSE;
    }
  zlog_info ("leaving te_stop_timer");
}
#endif

uns32
TeApplicationInit ()
{
  PATRICIA_PARAMS params;
  unsigned int i;

  UserLspListHead = NULL;

  params.key_size = sizeof (unsigned int);
  params.info_size = 0;
  memset (PlatformWideLabelSpace, 0, sizeof (LABEL_ENTRY) * LABEL_SPACE_SIZE);
  if (patricia_tree_init (&PlatformWideFreeLabels, &params) != E_OK)
    {
      return E_ERR;
    }
  zlog_info ("\nPlatformWideFreeLabelsTree init succeeded");

  for (i = 0; i < LABEL_SPACE_SIZE; i++)
    {
      PlatformWideLabelSpace[i].label = i + 1;
      PlatformWideLabelSpace[i].ReceivedOutLabel = 0;
      PlatformWideLabelSpace[i].Node.key_info =
	(uns8 *) & PlatformWideLabelSpace[i].label;
      if (patricia_tree_add
	  (&PlatformWideFreeLabels,
	   &(PlatformWideLabelSpace[i].Node)) != E_OK)
	{
	  zlog_err ("\ncannot add label %d", i + 1);
	  return E_ERR;
	}
    }
  params.key_size = sizeof (PSB_KEY);
  params.info_size = 0;

  for (i = 0; i < 8; i++)
    {
      if (patricia_tree_init (&BwOwnersTree[i], &params) != E_OK)
	{
	  return E_ERR;
	}
    }

  params.key_size = sizeof (PSB_KEY) + sizeof (uns32);
  params.info_size = 0;

  for (i = 0; i < 8; i++)
    {
      if (patricia_tree_init (&IfBwOwnersTree[i], &params) != E_OK)
	{
	  return E_ERR;
	}
    }

  memset (&params, 0, sizeof (params));
  params.key_size = sizeof (TRUNK_KEY);
  params.info_size = 0;

  if (patricia_tree_init (&SeparateNonAdaptiveLspsTrunkTree, &params) != E_OK)
    {
      return E_ERR;
    }

  if (patricia_tree_init (&SeparateAdaptiveLspsTrunkTree, &params) != E_OK)
    {
      return E_ERR;
    }

  if (patricia_tree_init (&NonSeparateServiceLspsTrunkTree, &params) != E_OK)
    {
      return E_ERR;
    }

  if (patricia_tree_init (&NonSeparateTunnelsLspsTrunkTree, &params) != E_OK)
    {
      return E_ERR;
    }

  if (patricia_tree_init (&NonSeparateServiceBWAdaptiveLspsTrunkTree,
			  &params) != E_OK)
    {
      return E_ERR;
    }

  memset (&params, 0, sizeof (params));
  params.key_size = sizeof (SLA_KEY);
  params.info_size = 0;
  if (patricia_tree_init (&SLAsTree, &params) != E_OK)
    {
      return E_ERR;
    }

  params.key_size = sizeof (IPV4_ADDR);
  params.info_size = 0;

  if (patricia_tree_init (&ConstraintRouteResReqTree, &params) != E_OK)
    {
      return E_ERR;
    }

  params.key_size = sizeof (int);
  params.info_size = 0;

  if (patricia_tree_init (&ConstraintRouteResClientsTree, &params) != E_OK)
    {
      return E_ERR;
    }
#ifdef FRR_SM_DEFINED
  InitFastReRoute ();
#endif
  zlog_info ("\nTE application init success");
  return E_OK;
}

PATRICIA_TREE *
GetPatriciaTree (TRUNK_TYPE trunk_type)
{
  PATRICIA_TREE *pTree = NULL;
  switch (trunk_type)
    {
    case SEPARATE_NON_ADAPTIVE:
      pTree = &SeparateNonAdaptiveLspsTrunkTree;
      break;
    case SEPARATE_ADAPTIVE:
      pTree = &SeparateAdaptiveLspsTrunkTree;
      break;
    case NON_SEPARATE_SERVICE:
      pTree = &NonSeparateServiceLspsTrunkTree;
      break;
    case NON_SEPARATE_SERVICE_BW_ADAPTIVE:
      pTree = &NonSeparateServiceBWAdaptiveLspsTrunkTree;
      break;
    case NON_SEPARATE_TUNNELS:
      pTree = &NonSeparateTunnelsLspsTrunkTree;
      break;
    default:
      zlog_err ("\ndefault case %s %d", __FILE__, __LINE__);
    }
  return pTree;
}

BOOL
FindTunnel (PSB_KEY * PsbKey, RSVP_TUNNEL_PROPERTIES ** ppTunnel,
	    TRUNK_TYPE trunk_type)
{
  TRUNK_KEY trunk_key;
  TRUNK_ENTRY *pTrunkEntry;
  int i, l;
  PATRICIA_TREE *pTree = NULL;

  switch (trunk_type)
    {
    case SEPARATE_NON_ADAPTIVE:
    case SEPARATE_ADAPTIVE:
    case NON_SEPARATE_SERVICE:
    case NON_SEPARATE_TUNNELS:
      i = l = trunk_type;
      break;
    case ALL_TRUNKS:
      i = 0;
      l = ALL_TRUNKS - 1;
      break;
    default:
      zlog_err ("\ndefault case %s %d", __FILE__, __LINE__);
      i = 0;
      l = ALL_TRUNKS - 1;
    }

  memset (&trunk_key, 0, sizeof (TRUNK_KEY));
  trunk_key.Dest = PsbKey->Session.Dest;
  for (; i <= l; i++)
    {
      if ((pTree = GetPatriciaTree (i)) == NULL)
	continue;
      if ((pTrunkEntry =
	   (TRUNK_ENTRY *) patricia_tree_get (pTree,
					      (const uns8 *) &trunk_key)) !=
	  NULL)
	{
	  RSVP_TUNNEL_PROPERTIES *pTunnel = pTrunkEntry->Lsps;
	  while (pTunnel != NULL)
	    {
	      if (pTunnel->TunnelId == PsbKey->Session.TunnelId)
		{
		  *ppTunnel = pTunnel;
		  return TRUE;
		}
	      pTunnel = pTunnel->next;
	    }
	}
    }
  return FALSE;
}

uns32
NewRsvpLsp (RSVP_TUNNEL_PROPERTIES * pTunnel,
	    RSVP_LSP_PROPERTIES ** ppRsvpLsp)
{
  RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties;

  if (pTunnel->properties == NULL)
    {
      if ((pTunnel->properties =
	   (RSVP_LSP_PROPERTIES *) XMALLOC (MTYPE_TE,
					    sizeof (RSVP_LSP_PROPERTIES))) ==
	  NULL)
	{
	  zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      memset (pTunnel->properties, 0, sizeof (RSVP_LSP_PROPERTIES));
      *ppRsvpLsp = pTunnel->properties;
      return E_OK;
    }

  while (pRsvpLsp != NULL)
    {
      if (pRsvpLsp->next == NULL)
	{
	  if ((pRsvpLsp->next =
	       (RSVP_LSP_PROPERTIES *) XMALLOC (MTYPE_TE,
						sizeof (RSVP_LSP_PROPERTIES)))
	      == NULL)
	    {
	      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }
	  *ppRsvpLsp = pRsvpLsp->next;	/* !!! */
	  return E_OK;
	}
      pRsvpLsp = pRsvpLsp->next;
    }
  return E_ERR;			/* should not be reached */
}

uns32
NewTunnel (PSB_KEY * PsbKey, RSVP_TUNNEL_PROPERTIES ** ppNewTunnel,
	   TRUNK_TYPE trunk_type)
{
  TRUNK_ENTRY *pTrunkEntry;
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  TRUNK_KEY trunk_key;
  PATRICIA_TREE *pTree;

  if ((pTree = GetPatriciaTree (trunk_type)) == NULL)
    {
      zlog_err ("\nno trunk type specified %s %d", __FILE__, __LINE__);
      return E_ERR;
    }

  memset (&trunk_key, 0, sizeof (TRUNK_KEY));
  trunk_key.Dest = PsbKey->Session.Dest;

  if ((pTrunkEntry =
       (TRUNK_ENTRY *) patricia_tree_get (pTree,
					  (const uns8 *) &trunk_key)) == NULL)
    {
      if ((pTrunkEntry =
	   (TRUNK_ENTRY *) XMALLOC (MTYPE_TE, sizeof (TRUNK_ENTRY))) == NULL)
	{
	  zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      memset (pTrunkEntry, 0, sizeof (TRUNK_ENTRY));
      pTrunkEntry->trunk_key.Dest = PsbKey->Session.Dest;
      pTrunkEntry->Node.key_info = (uns8 *) & (pTrunkEntry->trunk_key);
      if (patricia_tree_add (pTree, &(pTrunkEntry->Node)) != E_OK)
	{
	  XFREE (MTYPE_TE, pTrunkEntry);
	  zlog_err ("\ncannot add node to patricia %s %d", __FILE__,
		    __LINE__);
	  return E_ERR;
	}
    }
  if ((pTunnel =
       (RSVP_TUNNEL_PROPERTIES *) XMALLOC (MTYPE_TE,
					   sizeof (RSVP_TUNNEL_PROPERTIES)))
      == NULL)
    {
      zlog_err ("\ncannot allocate memory %s %d", __FILE__, __LINE__);
      if (pTrunkEntry->Lsps == NULL)
	{
	  if (patricia_tree_del (pTree, &pTrunkEntry->Node) != E_OK)
	    {
	      zlog_err ("\ncannot delete node from patricia");
	    }
	  else
	    XFREE (MTYPE_TE, pTrunkEntry);
	}
      return E_ERR;
    }
  pTunnel->TunnelId = PsbKey->Session.TunnelId;
  pTunnel->adaptivity_timer.data.adaptivity_timer_data.key = *PsbKey;
  pTunnel->lsp_setup_timer.data.lsp_setup_data.key = *PsbKey;
  pTunnel->lsp_setup_retry_timer.data.lsp_setup_retry_data.key = *PsbKey;
  pTunnel->cspf_retry_timer.data.cspf_retry_data.key = *PsbKey;
  pTunnel->next = pTrunkEntry->Lsps;
  pTrunkEntry->Lsps = pTunnel;
  pTrunkEntry->TunnelsCounter++;
  *ppNewTunnel = pTunnel;
  return E_OK;
}

uns32
DeleteTunnel (PSB_KEY * PsbKey, TRUNK_TYPE trunk_type)
{
  TRUNK_KEY trunk_key;
  TRUNK_ENTRY *pTrunkEntry;
  RSVP_TUNNEL_PROPERTIES *pTunnel, *pTunnelPrev = NULL;
  PATRICIA_TREE *pTree;

  if ((pTree = GetPatriciaTree (trunk_type)) == NULL)
    {
      zlog_err ("\ntrunk type is not specified %s %d", __FILE__, __LINE__);
      return E_ERR;
    }

  memset (&trunk_key, 0, sizeof (TRUNK_KEY));
  trunk_key.Dest = PsbKey->Session.Dest;
  if ((pTrunkEntry =
       (TRUNK_ENTRY *) patricia_tree_get (pTree,
					  (const uns8 *) &trunk_key)) != NULL)
    {
      pTunnel = pTrunkEntry->Lsps;
      while (pTunnel != NULL)
	{
	  if (pTunnel->TunnelId == PsbKey->Session.TunnelId)
	    {
	      RSVP_LSP_PROPERTIES *pLsp, *pLspNext;
	      if (pTrunkEntry->Lsps == pTunnel)
		pTrunkEntry->Lsps = pTrunkEntry->Lsps->next;
	      else
		pTunnelPrev->next = pTunnel->next;
	      pLsp = pTunnel->properties;
	      while (pLsp != NULL)
		{
		  if (pLsp->forw_info.path.pErHopsList != NULL)
		    XFREE (MTYPE_TE, pLsp->forw_info.path.pErHopsList);
		  pLspNext = pLsp->next;
		  XFREE (MTYPE_TE, pLsp);
		  pLsp = pLspNext;
		}
	      XFREE (MTYPE_TE, pTunnel);
	      pTrunkEntry->TunnelsCounter--;
	      if (pTrunkEntry->Lsps == NULL)
		{
		  if (patricia_tree_del (pTree, &pTrunkEntry->Node) != E_OK)
		    zlog_err ("\ncannot delete node from patricia %s %d",
			      __FILE__, __LINE__);
		  else
		    XFREE (MTYPE_TE, pTrunkEntry);
		}
	      return E_OK;
	    }
	  pTunnelPrev = pTunnel;
	  pTunnel = pTunnel->next;
	}
    }
  return E_ERR;
}

void
TE_RSVPTE_API_RsvpTunnelEstablished (RESV_NOTIFICATION * resv_notif)
{
  PSB_KEY PsbKey;
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  LSP_SM_NOTIF_DATA *pLspSmNotifData = NULL;
  SM_CALL_T *pCall = NULL;
  int i;
  zlog_info ("entering of RsvpTunnelEstablished");
  memset (&PsbKey, 0, sizeof (PSB_KEY));
  PsbKey.Session = resv_notif->RsbKey.Session;

  if (FindTunnel (&PsbKey, &pTunnel, ALL_TRUNKS) == FALSE)
    {
      zlog_err ("\nunexpected TUNNEL Dest %x Tunnel ID %x",
		PsbKey.Session.Dest, PsbKey.Session.TunnelId);
      return;
    }
  if (pTunnel->sm_handle == 0)	/* one is waiting for this... */
    {
      zlog_err ("\nThere is no SM to process RSVP TUNNEL %x TO %x",
		pTunnel->TunnelId, PsbKey.Session.Dest);
      return;
    }
  if ((pLspSmNotifData =
       (LSP_SM_NOTIF_DATA *) XMALLOC (MTYPE_TE,
				      sizeof (LSP_SM_NOTIF_DATA))) == NULL)
    {
      zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
      return;
    }
  pLspSmNotifData->ingress_lsp_notif = SETUP_COMPLETE_NOTIF;
  pLspSmNotifData->PsbKey = PsbKey;

  if (resv_notif->SharedExplicit)
    {
      pLspSmNotifData->data.setup_complete.NumberOfItems =
	resv_notif->u.FilterDataSE.FilterSpecNumber;

      if ((pLspSmNotifData->data.setup_complete.pLspLabel =
	   (LSP_LABEL *) XMALLOC (MTYPE_TE,
				  sizeof (LSP_LABEL) *
				  (pLspSmNotifData->data.setup_complete.
				   NumberOfItems))) == NULL)
	{
	  zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
	  return;
	}
      pLspSmNotifData->data.setup_complete.BW = resv_notif->u.FilterDataSE.BW;
      for (i = 0; i < resv_notif->u.FilterDataSE.FilterSpecNumber; i++)
	{
	  pLspSmNotifData->data.setup_complete.pLspLabel[i].LspId
	    =
	    resv_notif->u.FilterDataSE.FilterDataArraySE[i].FilterSpec.LspId;
	  pLspSmNotifData->data.setup_complete.pLspLabel[i].Label =
	    resv_notif->u.FilterDataSE.FilterDataArraySE[i].ReceivedLabel;
	  zlog_info ("LspId %x Label %x",
		     resv_notif->u.FilterDataSE.FilterDataArraySE[i].
		     FilterSpec.LspId,
		     resv_notif->u.FilterDataSE.FilterDataArraySE[i].
		     ReceivedLabel);
	}
    }
  else
    {
      pLspSmNotifData->data.setup_complete.NumberOfItems = 1;
      if ((pLspSmNotifData->data.setup_complete.pLspLabel =
	   (LSP_LABEL *) XMALLOC (MTYPE_TE, sizeof (LSP_LABEL))) == NULL)
	{
	  zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
	  return;
	}
      pLspSmNotifData->data.setup_complete.BW = resv_notif->u.FilterDataFF.BW;
      pLspSmNotifData->data.setup_complete.pLspLabel->LspId
	= resv_notif->u.FilterDataFF.FilterSpec.LspId;
      pLspSmNotifData->data.setup_complete.pLspLabel->Label
	= resv_notif->u.FilterDataFF.ReceivedLabel;
      zlog_info ("LspId %x Label %x",
		 resv_notif->u.FilterDataFF.FilterSpec.LspId,
		 resv_notif->u.FilterDataFF.ReceivedLabel);
    }
  if (pLspSmNotifData != NULL)
    {
      if ((pCall = sm_gen_sync_event_send ((SM_T *) (pTunnel->sm_handle),
					   MPLS_SIGNALING_INGRESS_ESTABLISHED_NOTIFICATION_EVENT,
					   pLspSmNotifData)) == NULL)
	{
	  zlog_err ("can not invoke sm %s %d", __FILE__, __LINE__);
	}
      sm_call (pCall);
    }
  zlog_info ("leaving of RsvpTunnelEstablished");
}


void
RsvpTunnelsDump ()
{
  TRUNK_KEY trunk_key;
  TRUNK_ENTRY *pTrunkEntry;
  int i;

  memset (&trunk_key, 0, sizeof (TRUNK_KEY));

  for (i = 0; i < ALL_TRUNKS; i++)
    {
      PATRICIA_TREE *pTree;

      if ((pTree = GetPatriciaTree (i)) == NULL)
	{
	  zlog_info ("\ncannot get patricia tree %s %d", __FILE__, __LINE__);
	  continue;
	}
      while ((pTrunkEntry =
	      (TRUNK_ENTRY *) patricia_tree_getnext (pTree,
						     (const uns8 *)
						     &trunk_key)) != NULL)
	{
	  RSVP_TUNNEL_PROPERTIES *pTunnel = pTrunkEntry->Lsps;
	  while (pTunnel != NULL)
	    {
	      RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties;

	      zlog_info
		("RSVP TUNNEL %x AllocBW %f ReqBW %f LSP ID %x ReRoute %x",
		 pTunnel->TunnelId, pTunnel->AllocatedBW, pTunnel->RequiredBW,
		 pTunnel->LspId, pTunnel->ReRoute);
	      zlog_info
		("\nAdjustment Required %x UserLspName %s StaticPath %s Adaptivity %x LspSetup %x LspSetupRetry %x",
		 pTunnel->AdjustmentRequired, pTunnel->UserLspName,
		 pTunnel->StaticPathName, pTunnel->adaptivity_timer.is_active,
		 pTunnel->lsp_setup_timer.is_active,
		 pTunnel->lsp_setup_retry_timer.is_active);
	      if (pTunnel->sm_handle != 0)
		zlog_info ("\nTunnel's SM %x",
			   ((SM_T *) pTunnel->sm_handle)->sm_type);

	      while (pRsvpLsp != NULL)
		{
		  zlog_info
		    ("\nRSVP LSP: LSP ID %x RequestedBW %f Label(out) %x",
		     pRsvpLsp->LspId, pRsvpLsp->RequestedBW, pRsvpLsp->Label);

		  if (pRsvpLsp->tunneled == FALSE)
		    {
		      int j;
		      zlog_info ("\nPath:");
		      for (j = 0; j < pRsvpLsp->forw_info.path.HopCount; j++)
			zlog_info ("\nER HOP#%d %x", j + 1,
				   pRsvpLsp->forw_info.path.pErHopsList[j]);
		      zlog_info
			("\nRSVP LSP Backup Info: Merge node %x OutIf %x Protected node %x Bypass label %x Merege node label valid %x Merge node label %x OutIF %x",
			 pRsvpLsp->forw_info.path.BackupForwardingInformation.
			 frr_key.merge_node,
			 pRsvpLsp->forw_info.path.BackupForwardingInformation.
			 frr_key.OutIfIndex,
			 pRsvpLsp->forw_info.path.BackupForwardingInformation.
			 frr_key.protected_node,
			 pRsvpLsp->forw_info.path.BackupForwardingInformation.
			 BypassTunnelsLabel,
			 pRsvpLsp->forw_info.path.BackupForwardingInformation.
			 MergeNodeLabelValid,
			 pRsvpLsp->forw_info.path.BackupForwardingInformation.
			 MergeNodeLabel,
			 pRsvpLsp->forw_info.path.BackupForwardingInformation.
			 OutIf);
		    }
		  pRsvpLsp = pRsvpLsp->next;
		}
	      pTunnel = pTunnel->next;
	    }
	  trunk_key = pTrunkEntry->trunk_key;
	}
    }
}

void
UserLspsDump (char *pName, struct vty *vty)
{
  USER_LSP_LIST *pUserLsp = UserLspListHead;


  while (pUserLsp != NULL)
    {
      RSVP_TUNNEL_PROPERTIES *pTunnel = pUserLsp->lsp->pUserLspTunnels;
      if (pName)
	{
	  if (strcmp (pName, pUserLsp->lsp->params.LspName) != 0)
	    {
	      pUserLsp = pUserLsp->next;
	      continue;
	    }
	}
      vty_out (vty, "Tunnel's name %s%s",
	       pUserLsp->lsp->params.LspName, VTY_NEWLINE);
      vty_out (vty, "Destination %x%s", pUserLsp->lsp->params.to,
	       VTY_NEWLINE);
      if (pUserLsp->lsp->params.Primary[0] != '\0')
	vty_out (vty, "Primary path %s%s", pUserLsp->lsp->params.Primary,
		 VTY_NEWLINE);
      else
	vty_out (vty, "No primary path%s", VTY_NEWLINE);
      {
	LSP_PATH_SHARED_PARAMS *pParams = &pUserLsp->lsp->params.lsp_params;
	vty_out (vty, "Common tunnel's parameters%s", VTY_NEWLINE);
	vty_out (vty, "Bandwidth %f %s", pParams->BW, VTY_NEWLINE);
	vty_out (vty, "Setup priority %d Hold priority %d%s",
		 pParams->setup_priority, pParams->hold_priority,
		 VTY_NEWLINE);
	vty_out (vty, "Hop limit %d%s", pParams->hop_limit, VTY_NEWLINE);
	vty_out (vty, "Optimize timer %d%s", pParams->optimize_timer,
		 VTY_NEWLINE);
	vty_out (vty, "Record route: %s%s", (pParams->record) ? "yes" : "no",
		 VTY_NEWLINE);
      }
      if (pUserLsp->lsp->params.PrimaryPathParams != NULL)
	{
	  LSP_PATH_SHARED_PARAMS *pParams =
	    pUserLsp->lsp->params.PrimaryPathParams;

	  vty_out (vty, "Primary path parameters %s", VTY_NEWLINE);
	  vty_out (vty, "Bandwidth %f %s", pParams->BW, VTY_NEWLINE);
	  vty_out (vty, "Setup priority %d Hold priority %d%s",
		   pParams->setup_priority, pParams->hold_priority,
		   VTY_NEWLINE);
	  vty_out (vty, "Hop limit %d%s", pParams->hop_limit, VTY_NEWLINE);
	  vty_out (vty, "Optimize timer %d%s", pParams->optimize_timer,
		   VTY_NEWLINE);
	  vty_out (vty, "Record route: %s%s",
		   (pParams->record) ? "yes" : "no", VTY_NEWLINE);
	}
      {
	SECONDARY_PATH_LIST *pSecPathList =
	  pUserLsp->lsp->params.SecondaryPaths;
	while (pSecPathList != NULL)
	  {
	    vty_out (vty, "Secondary %s%s", pSecPathList->Secondary,
		     VTY_NEWLINE);
	    if (pSecPathList->SecondaryPathParams != NULL)
	      {
		LSP_PATH_SHARED_PARAMS *pParams =
		  pSecPathList->SecondaryPathParams;
		vty_out (vty, "Bandwidth %f %s", pParams->BW, VTY_NEWLINE);
		vty_out (vty, "Setup priority %d Hold priority %d%s",
			 pParams->setup_priority, pParams->hold_priority,
			 VTY_NEWLINE);
		vty_out (vty, "Hop limit %d%s", pParams->hop_limit,
			 VTY_NEWLINE);
		vty_out (vty, "Optimize timer %d%s", pParams->optimize_timer,
			 VTY_NEWLINE);
		vty_out (vty, "Record route: %s%s",
			 (pParams->record) ? "yes" : "no", VTY_NEWLINE);
		vty_out (vty, "Standby %s%s",
			 (pParams->standby) ? "yes" : "no", VTY_NEWLINE);
	      }
	    pSecPathList = pSecPathList->next;
	  }
      }
      while (pTunnel != NULL)
	{
	  RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties;
	  vty_out (vty, "Tunnel ID %x%s", pTunnel->TunnelId, VTY_NEWLINE);
	  if (pTunnel->LspId)
	    {
	      vty_out (vty, " is UP%s", VTY_NEWLINE);
	    }
	  if (pTunnel->StaticPathName[0] != '\0')
	    {
	      vty_out (vty, "Static Path Name %s%s",
		       pTunnel->StaticPathName, VTY_NEWLINE);
	    }
	  while (pRsvpLsp != NULL)
	    {
	      vty_out (vty, "LSP ID %x", pRsvpLsp->LspId);
	      if (pTunnel->LspId == pRsvpLsp->LspId)
		{
		  vty_out (vty, " is installed");
		}
	      vty_out (vty, "%s", VTY_NEWLINE);
	      if (pRsvpLsp->tunneled == FALSE)
		{
		  int k;

		  vty_out (vty, "Setup Prio %d Hold Prio %d %s",
			   pRsvpLsp->SetupPriority, pRsvpLsp->HoldPriority,
			   VTY_NEWLINE);
		  vty_out (vty, "ExcludeAny %x IncludeAny %x IncludeAll %x%s",
			   pRsvpLsp->ExcludeAny, pRsvpLsp->IncludeAny,
			   pRsvpLsp->IncludeAll, VTY_NEWLINE);
		  if (pRsvpLsp->FrrDesired)
		    {
		      vty_out (vty, "FastReRoute desired%s", VTY_NEWLINE);
		    }
		  if (pRsvpLsp->LabelRecordingDesired)
		    {
		      vty_out (vty, "Label Recording desired%s", VTY_NEWLINE);
		    }
		  if (pRsvpLsp->Label)
		    {
		      vty_out (vty, "Label %x%s", pRsvpLsp->Label,
			       VTY_NEWLINE);
		    }
		  if (pRsvpLsp->RequestedBW)
		    {
		      vty_out (vty, "Bandwidth %f%s", pRsvpLsp->RequestedBW,
			       VTY_NEWLINE);
		    }
		  vty_out (vty, "Path:%s", VTY_NEWLINE);
		  for (k = 0; k < pRsvpLsp->forw_info.path.HopCount; k++)
		    {
		      vty_out (vty, "HOP %x%s",
			       pRsvpLsp->forw_info.path.pErHopsList[k],
			       VTY_NEWLINE);
		    }
		}
	      pRsvpLsp = pRsvpLsp->next;
	    }
	  pTunnel = pTunnel->next_user_lsp_tunnel;
	}
      if (pName)
	{
	  if (strcmp (pName, pUserLsp->lsp->params.LspName) == 0)
	    {
	      break;
	    }
	}
      pUserLsp = pUserLsp->next;
    }
}

void
TE_RSVPTE_API_RsvpResvTear (RESV_TEAR_NOTIF * pResvTearNotif)
{
  PSB_KEY PsbKey;
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  LSP_SM_NOTIF_DATA *pLspSmNotifData = NULL;
  SM_CALL_T *pCall = NULL;
  zlog_info ("inside of RsvpResvTear");
  memset (&PsbKey, 0, sizeof (PSB_KEY));
  PsbKey.Session = pResvTearNotif->RsbKey.Session;

  if (FindTunnel (&PsbKey, &pTunnel, ALL_TRUNKS) == FALSE)
    {
      zlog_err ("\ncannot find tunnel %x %x %x",
		PsbKey.Session.Dest,
		PsbKey.Session.TunnelId, PsbKey.Session.ExtTunelId);
      return;
    }
  if (pTunnel->sm_handle == 0)	/* one is waiting for this... */
    {
      zlog_err ("\nThere is no SM for tunnel %x %x %x",
		PsbKey.Session.Dest,
		PsbKey.Session.TunnelId, PsbKey.Session.ExtTunelId);
      return;
    }
  if ((pLspSmNotifData =
       (LSP_SM_NOTIF_DATA *) XMALLOC (MTYPE_TE,
				      sizeof (LSP_SM_NOTIF_DATA))) == NULL)
    {
      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
      return;
    }
  pLspSmNotifData->ingress_lsp_notif = TEAR_DOWN_NOTIF;
  pLspSmNotifData->PsbKey.Session = pResvTearNotif->RsbKey.Session;
  pLspSmNotifData->data.tunnel_down.Lsps.LspId =
    pResvTearNotif->FilterSpec.LspId;
  pLspSmNotifData->data.tunnel_down.NumberOfItems = 1;
  if (pLspSmNotifData != NULL)
    {

      zlog_info ("\nDestIP %x Tunnel ID %x LSP ID %x",
		 pLspSmNotifData->PsbKey.Session.Dest,
		 pLspSmNotifData->PsbKey.Session.TunnelId,
		 pLspSmNotifData->data.tunnel_down.Lsps.LspId);
      if ((pCall = sm_gen_sync_event_send ((SM_T *) pTunnel->sm_handle,
					   MPLS_SIGNALING_INGRESS_FAILED_NOTIFICATION_EVENT,
					   pLspSmNotifData)) == NULL)
	{
	  zlog_err ("\ncan not invoke sm %s %d", __FILE__, __LINE__);
	}
      else
	sm_call (pCall);
    }
}

void
TE_RSVPTE_API_RsvpPathErr (PATH_ERR_NOTIF * pPathErrNotif)
{
  PSB_KEY PsbKey;
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  LSP_SM_NOTIF_DATA *pLspSmNotifData = NULL;
  SM_CALL_T *pCall = NULL;
  zlog_info ("inside of RsvpPathErr");
  memset (&PsbKey, 0, sizeof (PSB_KEY));
  PsbKey.Session = pPathErrNotif->PsbKey.Session;

  if (FindTunnel (&PsbKey, &pTunnel, ALL_TRUNKS) == FALSE)
    {
      zlog_err ("\ncannot find tunnel %x %x %x",
		PsbKey.Session.Dest,
		PsbKey.Session.TunnelId, PsbKey.Session.ExtTunelId);
      return;
    }
  if (pTunnel->sm_handle == 0)	/* one is waiting for this... */
    {
      zlog_err ("\nThere is no SM for tunnel %x %x %x",
		PsbKey.Session.Dest,
		PsbKey.Session.TunnelId, PsbKey.Session.ExtTunelId);
      return;
    }
  if ((pLspSmNotifData =
       (LSP_SM_NOTIF_DATA *) XMALLOC (MTYPE_TE,
				      sizeof (LSP_SM_NOTIF_DATA))) == NULL)
    {
      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
      return;
    }
  if (pPathErrNotif->ErrSpec.ErrCode == NOTIFY_ERR_CODE)
    {
      if (((pPathErrNotif->ErrSpec.ErrVal & 0xC000) == 0)
	  && ((pPathErrNotif->ErrSpec.ErrVal & 0xC000) ==
	      RRO_TOO_LARGE_4_MTU))
	{
	  zlog_info ("Error code %d is not handled yet",
		     pPathErrNotif->ErrSpec.ErrCode);
	  XFREE (MTYPE_TE, pLspSmNotifData);
	  return;
	}
    }
  pLspSmNotifData->ingress_lsp_notif = SETUP_FAILED_NOTIF;
  pLspSmNotifData->PsbKey.Session = pPathErrNotif->PsbKey.Session;
  pLspSmNotifData->data.setup_failed.LspId =
    pPathErrNotif->PsbKey.SenderTemplate.LspId;
  pLspSmNotifData->data.setup_failed.IpAddr = pPathErrNotif->ErrSpec.IpAddr;

  if ((pCall = sm_gen_sync_event_send ((SM_T *) pTunnel->sm_handle,
				       MPLS_SIGNALING_INGRESS_FAILED_NOTIFICATION_EVENT,
				       pLspSmNotifData)) == NULL)
    {
      zlog_err ("\ncan not invoke sm %s %d", __FILE__, __LINE__);
    }
  else
    sm_call (pCall);
}

TRUNK_ENTRY *
GetTunnelsTrunk (TRUNK_KEY * trunk_key)
{
  return (TRUNK_ENTRY *) patricia_tree_get (&NonSeparateTunnelsLspsTrunkTree,
					    (const uns8 *) trunk_key);
}

TRUNK_ENTRY *
NewTunnelsTrunk (TRUNK_KEY * trunk_key)
{
  TRUNK_ENTRY *pTrunkEntry;

  if ((pTrunkEntry =
       (TRUNK_ENTRY *) XMALLOC (MTYPE_TE, sizeof (TRUNK_ENTRY))) == NULL)
    {
      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
      return NULL;
    }
  if ((pTrunkEntry->pTrunkData =
       (TRUNK_DATA *) XMALLOC (MTYPE_TE, sizeof (TRUNK_DATA))) == NULL)
    {
      XFREE (MTYPE_TE, pTrunkEntry);
      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
      return NULL;
    }

  pTrunkEntry->trunk_key = *trunk_key;
  pTrunkEntry->Node.key_info = (uns8 *) & pTrunkEntry->trunk_key;

  if (patricia_tree_add (&NonSeparateTunnelsLspsTrunkTree, &pTrunkEntry->Node)
      != E_OK)
    {
      zlog_err ("\ncannot add node to patricia %s %d", __FILE__, __LINE__);
      return NULL;
    }
  return pTrunkEntry;
}

BOOL
PathsEqual (ER_HOP_L_LIST * pErHopsLList, IPV4_ADDR * pIpAddr, int HopCount)
{
  int i;
  for (i = 0; ((i < HopCount) && (pErHopsLList != NULL));
       i += 2, pErHopsLList = pErHopsLList->next)
    {
      if (pErHopsLList->er_hop->remote_ip != pIpAddr[i])
	{
	  /*zlog_info("\nlocal ip %x %x",pErHopsLList->er_hop->local_ip,pIpAddr[i]); */
	  return FALSE;
	}
    }
  return TRUE;
}

PATH *
GetLspPath (RSVP_LSP_PROPERTIES * pRsvpLsp)
{
  PATH_L_LIST *pPathLList = NULL;
  IPV4_ADDR dest;

  if (pRsvpLsp->tunneled)
    {
      return NULL;
    }
  if (pRsvpLsp->forw_info.path.pErHopsList == NULL)
    {
      return NULL;
    }
  dest =
    pRsvpLsp->forw_info.path.pErHopsList[pRsvpLsp->forw_info.path.HopCount -
					 1];

  if (IsDestinationIntraArea (dest, &pPathLList) != E_OK)
    {
      zlog_err ("\nsome error in IsDestinationIntraArea %s %d ...", __FILE__,
		__LINE__);
      return NULL;
    }
  zlog_info ("\npPathLList %x dest %x", pPathLList, dest);
  while (pPathLList != NULL)
    {
      if ((pPathLList->pPath->PathProperties.PathHopCount >=
	   (pRsvpLsp->forw_info.path.HopCount / 2))
	  &&
	  (PathsEqual
	   (pPathLList->pPath->u.er_hops_l_list,
	    pRsvpLsp->forw_info.path.pErHopsList,
	    pRsvpLsp->forw_info.path.HopCount) == TRUE))
	{
	  return pPathLList->pPath;
	}
      pPathLList = pPathLList->next;
    }
  return NULL;
}

uns8 TunnelIds[0xFFFF];

uns16
NewTunnelId (PSB_KEY * PsbKey)
{
  uns16 TunnelId = 0;
  uns32 i;
  PATRICIA_TREE *pTree;
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  TRUNK_ENTRY *pTrunkEntry;
  TRUNK_KEY trunk_key;

  memset (&trunk_key, 0, sizeof (TRUNK_KEY));
  memset (TunnelIds, 0, sizeof (uns8) * 0xFFFF);

  trunk_key.Dest = PsbKey->Session.Dest;

  for (i = 0; i < ALL_TRUNKS; i++)
    {
      pTree = GetPatriciaTree (i);
      if ((pTrunkEntry =
	   (TRUNK_ENTRY *) patricia_tree_get (pTree,
					      (const uns8 *) &trunk_key)) !=
	  NULL)
	{
	  pTunnel = pTrunkEntry->Lsps;
	  while (pTunnel != NULL)
	    {
	      TunnelIds[pTunnel->TunnelId - 1] = 1;
	      pTunnel = pTunnel->next;
	    }
	}
    }
  for (i = 0; i < 0xFFFF; i++)
    if (TunnelIds[i] == 0)
      TunnelId = i + 1;
  return TunnelId;
}

uns32
UserLspAdd (USER_LSP * pUserLsp)
{
  USER_LSP_LIST *pUserLspList;

  if ((pUserLspList =
       (USER_LSP_LIST *) XMALLOC (MTYPE_TE, sizeof (USER_LSP_LIST))) == NULL)
    {
      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
      return E_ERR;
    }

  pUserLspList->lsp = pUserLsp;
  pUserLspList->next = UserLspListHead;
  UserLspListHead = pUserLspList;
  return E_OK;
}

USER_LSP *
UserLspGet (char *pLspName)
{
  USER_LSP_LIST *pUserLsp = UserLspListHead;
  zlog_info ("entering UserLspGet");
  while (pUserLsp != NULL)
    {
      if (strcmp (pLspName, pUserLsp->lsp->params.LspName) == 0)
	{
	  zlog_info ("leaving UserLspGet+");
	  return pUserLsp->lsp;
	}
      pUserLsp = pUserLsp->next;
    }
  zlog_info ("leaving UserLspGet-");
  return NULL;
}

uns32
UserLspDelete (char *pLspName)
{
  USER_LSP_LIST *pUserLsp = UserLspListHead, *pUserLspPrev = NULL;
  SECONDARY_PATH_LIST *pSecondaryPathList, *pSecondaryPathListNext;

  while (pUserLsp != NULL)
    {
      if (strcmp (pLspName, pUserLsp->lsp->params.LspName) == 0)
	{
	  if (pUserLsp == UserLspListHead)
	    UserLspListHead = UserLspListHead->next;
	  else
	    pUserLspPrev->next = pUserLsp->next;
#if 0
	  if (pUserLsp->lsp->params.FastReroute != NULL)
	    XFREE (MTYPE_TE, pUserLsp->lsp->params.FastReroute);
#endif
	  if (pUserLsp->lsp->params.PrimaryPathParams != NULL)
	    XFREE (MTYPE_TE, pUserLsp->lsp->params.PrimaryPathParams);
	  pSecondaryPathList = pUserLsp->lsp->params.SecondaryPaths;
	  while (pSecondaryPathList != NULL)
	    {
	      if (pSecondaryPathList->SecondaryPathParams != NULL)
		XFREE (MTYPE_TE, pSecondaryPathList->SecondaryPathParams);
	      pSecondaryPathListNext = pSecondaryPathList->next;
	      XFREE (MTYPE_TE, pSecondaryPathList);
	      pSecondaryPathList = pSecondaryPathListNext;
	    }
	  XFREE (MTYPE_TE, pUserLsp->lsp);
	  XFREE (MTYPE_TE, pUserLsp);
	  return E_OK;
	}
      pUserLspPrev = pUserLsp;
      pUserLsp = pUserLsp->next;
    }
  return E_ERR;
}

void
UserLspLoop (void (*CallBackFunc) (USER_LSP *, void *), void *data)
{
  USER_LSP_LIST *pUserLsp = UserLspListHead, *pUserLspNext;
  while (pUserLsp != NULL)
    {
      pUserLspNext = pUserLsp->next;
      CallBackFunc (pUserLsp->lsp, data);
      pUserLsp = pUserLspNext;
    }
}

uns16
GetPimaryTunnelId (char *pLspName)
{
  USER_LSP_LIST *pUserLsp = UserLspListHead;
  while (pUserLsp != NULL)
    {
      if (strcmp (pLspName, pUserLsp->lsp->params.LspName) == 0)
	{
	  if (pUserLsp->lsp->pUserLspTunnels != NULL)
	    return pUserLsp->lsp->pUserLspTunnels->TunnelId;
	}
      pUserLsp = pUserLsp->next;
    }
  return 0;
}

BOOL
RightPathCheaper (PATH_PROPERTIES * pLeftPathProp,
		  PATH_PROPERTIES * pRightPathProp, uns8 Priority)
{
  if (pLeftPathProp->PathCost < pRightPathProp->PathCost)
    {
      zlog_info ("\nmore expensive...");
      return FALSE;
    }
  if (pLeftPathProp->PathCost > pRightPathProp->PathCost)
    {
      zlog_info ("\ncheaper....");
      return TRUE;
    }
  if (pLeftPathProp->PathHopCount < pRightPathProp->PathHopCount)
    {
      zlog_info ("\nlonger...");
      return FALSE;
    }
  if (pLeftPathProp->PathHopCount > pRightPathProp->PathHopCount)
    {
      zlog_info ("\nshorter....");
      return TRUE;
    }
  if (pLeftPathProp->PathReservableBW[Priority] >
      pRightPathProp->PathReservableBW[Priority])
    {
      zlog_info ("\nless reservable BW....");
      return FALSE;
    }
  if (pLeftPathProp->PathReservableBW[Priority] <
      pRightPathProp->PathReservableBW[Priority])
    {
      zlog_info ("\nmore reservable BW....");
      return TRUE;
    }
  if (pLeftPathProp->PathMaxLspBW > pRightPathProp->PathMaxLspBW)
    {
      zlog_info ("\nless Max LSP BW....");
      return FALSE;
    }
  if (pLeftPathProp->PathMaxLspBW < pRightPathProp->PathMaxLspBW)
    {
      zlog_info ("\nmore Max LSP BW....");
      return TRUE;
    }
  if (pLeftPathProp->PathMaxReservableBW >
      pRightPathProp->PathMaxReservableBW)
    {
      zlog_info ("\nmore Max Reservable BW....");
      return FALSE;
    }
  if (pLeftPathProp->PathMaxReservableBW <
      pRightPathProp->PathMaxReservableBW)
    {
      zlog_info ("\nless Max Reservable BW....");
      return TRUE;
    }
  return FALSE;
}

uns32
TunnelIfIdRelease (uns32 IfIndex)
{
  if ((IfIndex < MAX_TUNNELS_IF) && (IfIndex > 6))
    {
      tunnels_if_array[IfIndex] = 0;
      return E_OK;
    }
  return E_ERR;
}

INGRESS_API *
CreateRequest2Signalling (IPV4_ADDR dest,
			  uns16 tunnel_id,
			  uns32 ErHopsNumber,
			  ER_HOP * pErHops,
			  float BW,
			  uns8 SetupPriority,
			  uns8 HoldPriority,
			  uns8 Flags,
			  uns32 ExcludeAny,
			  uns32 IncludeAny, uns32 IncludeAll)
{
  INGRESS_API *pOpenLspParams;
  int i;

  zlog_info ("entering CreateRequest2Signalling");

  if ((pOpenLspParams =
       (INGRESS_API *) XMALLOC (MTYPE_TE, sizeof (INGRESS_API))) == NULL)
    {
      zlog_err ("\nmalloc failed %s %d...", __FILE__, __LINE__);
      return NULL;
    }
  pOpenLspParams->Egress = dest;
  pOpenLspParams->src_ip = rdb_get_router_id ();
  pOpenLspParams->TunnelId = tunnel_id;
  pOpenLspParams->BW = BW;
  pOpenLspParams->HopNum = ErHopsNumber;
  for (i = 0; i < pOpenLspParams->HopNum; i++, pErHops++)
    {
      pOpenLspParams->Path[i].IpAddr = pErHops->IpAddr;
      pOpenLspParams->Path[i].PrefixLength = pErHops->PrefixLength;
      pOpenLspParams->Path[i].Loose = pErHops->Loose;
    }
  pOpenLspParams->Shared = TRUE;
  if (Flags & LABEL_RECORDING_DESIRED)
    pOpenLspParams->LabelRecordingDesired = TRUE;
  if (Flags & LOCAL_PROTECTION_DESIRED)
    pOpenLspParams->FrrDesired = TRUE;
  pOpenLspParams->SetPrio = SetupPriority;
  pOpenLspParams->HoldPrio = HoldPriority;
  pOpenLspParams->ExcludeAny = ExcludeAny;
  pOpenLspParams->IncludeAny = IncludeAny;
  pOpenLspParams->IncludeAll = IncludeAll;
  zlog_info ("leaving CreateRequest2Signalling");
  return pOpenLspParams;
}
