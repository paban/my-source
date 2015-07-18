/* Module:   fast_reroute.c
   Contains: TE application fast-reroute state machine 
   functions.
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "te.h"
#include "mpls_rtm.h"


PATRICIA_TREE FastReRouteSmTree;

static SM_CALL_T *
fast_reroute_sm_empty_handler (SM_T * pSm, SM_EVENT_T * sm_data)
{
  zlog_err ("\nfast_reroute_sm_empty_handler, state %d", pSm->state);
  return NULL;
}

static SM_CALL_T *
fast_reroute_sm_init (SM_T * pSm, SM_EVENT_T * sm_event)
{
  INGRESS_API *pOpenLspParams;
  PSB_KEY PsbKey;
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  RSVP_LSP_PROPERTIES *pRsvpLsp;
  TUNNEL_KEY_T tunnel_key;
  SM_CALL_T *pCall = NULL;
  FRR_SM_DATA *pFrrSmData = pSm->data;
  FRR_SM_ENTRY *pFrrEntry = &pFrrSmData->FrrSmEntry;

  switch (sm_event->event)
    {
    case BYPASS_SETUP_REQ_EVENT:
      if ((pOpenLspParams = XMALLOC (MTYPE_TE, sizeof (INGRESS_API))) == NULL)
	{
	  zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	  /* Do some clean up here */
	  return NULL;
	}
      memset (&PsbKey, 0, sizeof (PSB_KEY));
      PsbKey.Session.Dest = pFrrEntry->frr_key.merge_node;
      pOpenLspParams->TunnelId = NewTunnelId (&PsbKey);
      pOpenLspParams->ErHops2Exclude[0] = pFrrEntry->frr_key.protected_node;
      pOpenLspParams->ErHops2Exclude[1] =
	pFrrEntry->frr_key.prohibited_penultimate_node;
      pOpenLspParams->Egress = pFrrEntry->frr_key.merge_node;
      pOpenLspParams->BW = 0;
      pOpenLspParams->SetupPriority = 4;
      pOpenLspParams->HoldPriority = 4;
      pFrrEntry->BypassTunnelId = pOpenLspParams->tunnel_id;
      if ((pCall =
	   lsp_sm_sync_invoke (pSm, pOpenLspParams,
			       INGRESS_LSP_REQUEST_EVENT)) == NULL)
	{
	  zlog_err ("\ncan not invoke sm %s %d", __FILE__, __LINE__);
	}
      else
	sm_call (pCall);
      break;
    case INGRESS_LSP_OPERATION_COMPLETE_EVENT:
      if (pFrrEntry->bypass_retry_timer.is_active == TRUE)
	{
	  te_stop_timer (&pFrrEntry->bypass_retry_timer);
	}
      pSm->state = FAST_REROUTE_SM_UP_STATE;
      memset (&PsbKey, 0, sizeof (PSB_KEY));
      PsbKey.Session.Dest = pFrrEntry->frr_key.merge_node;
      PsbKey.Session.TunnelId = pFrrEntry->BypassTunnelId;
      PsbKey.Session.ExtTunelId = rdb_get_router_id ();
      if (FindTunnel (&PsbKey, &pTunnel, ALL_TRUNKS) == TRUE)
	{
	  if ((pRsvpLsp = GetWorkingRsvpLsp (pTunnel)) != NULL)
	    {
	      pFrrSmData->BackupOutIf = pRsvpLsp->oIfIndex;
	      pFrrSmData->BypassTunnelsLabel = pRsvpLsp->Label;
	      memset (&tunnel_key, 0, sizeof (TUNNEL_KEY_T));
	      tunnel_key.Dest = PsbKey.Session.Dest;
	      tunnel_key.TunnelId = PsbKey.Session.TunnelId;
	      tunnel_key.Source = PsbKey.Session.ExtTunelId;
	      /*if(CreateRsvpRequest(rdb_get_router_id(),
	         GetLSP(&tunnel_key),
	         100,900000,
	         100,900000,
	         FALSE,FALSE,
	         pFrrSmData->card) != E_OK)
	         {
	         zlog_info("\ncannnot create RSVP instance on LSP-Tunnel");
	         } HERE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
	    }
	  else
	    {
	      zlog_err ("\ncannot get working RSVP LSP %s %d", __FILE__,
			__LINE__);
	    }
	}
      else
	{
	  zlog_err ("\ncannot find tunnel %x %x %x %s %d",
		    PsbKey.Session.Dest,
		    PsbKey.Session.TunnelId,
		    PsbKey.Session.ExtTunelId, __FILE__, __LINE__);
	}
      UpdateIfWithBacupInfo (pFrrSmData);
      break;
    case INGRESS_LSP_OPERATION_FAILED_EVENT:
      zlog_info ("\nBypass tunnel setup is failed %x %x %x %s %d",
		 pFrrEntry->frr_key.protected_node,
		 pFrrEntry->frr_key.merge_node,
		 pFrrEntry->frr_key.OutIfIndex, __FILE__, __LINE__);
      pFrrEntry->bypass_retry_timer.data.bypass_retry_data =
	pFrrEntry->frr_key;
      if (te_start_timer
	  (&pFrrEntry->bypass_retry_timer, BYPASS_TUNNEL_RETRY_EXPIRY,
	   10000) != E_OK)
	{
	  zlog_err ("\ncannot start timer %s %d", __FILE__, __LINE__);
	}
      pSm->state = FAST_REROUTE_RETRY_STATE;
      break;
    default:
      zlog_err ("\nDefault case reached %s %d", __FILE__, __LINE__);
    }
  return NULL;
}

static SM_CALL_T *
fast_reroute_sm_up (SM_T * pSm, SM_EVENT_T * sm_event)
{
  FRR_SM_DATA *pFrrSmData = pSm->data;
  FRR_SM_ENTRY *pFrrEntry = &pFrrSmData->FrrSmEntry;
  SM_CALL_T *pCall = NULL;
  TUNNEL_KEY_T tunnel_key;

  switch (sm_event->event)
    {
    case BYPASS_SETUP_REQ_EVENT:
      UpdateIfWithBacupInfo (pFrrSmData);
      break;
    case INGRESS_LSP_OPERATION_FAILED_EVENT:
      BypassTunnelFailed (pFrrSmData);
      pFrrEntry->bypass_retry_timer.data.bypass_retry_data =
	pFrrEntry->frr_key;
      if (te_start_timer
	  (&pFrrEntry->bypass_retry_timer, BYPASS_TUNNEL_RETRY_EXPIRY,
	   10000) != E_OK)
	{
	  zlog_info ("\ncannot start timer %s %d", __FILE__, __LINE__);
	}
      memset (&tunnel_key, 0, sizeof (TUNNEL_KEY_T));
      tunnel_key.Dest = pFrrEntry->frr_key.merge_node;
      tunnel_key.TunnelId = pFrrEntry->BypassTunnelId;
      tunnel_key.Source = rdb_get_router_id ();
      /*if(DestroyRsvpRequest(rdb_get_router_id(),
         GetLSP(&tunnel_key),
         pFrrSmData->card) != E_OK)
         {
         zlog_info("\ncannot put down RSVP");
         } HERE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
      pSm->state = FAST_REROUTE_RETRY_STATE;
      break;
    default:
      zlog_err ("\nDefault case reached %s %d", __FILE__, __LINE__);
    }
  return pCall;
}

static SM_CALL_T *
fast_reroute_sm_retry (SM_T * pSm, SM_EVENT_T * sm_event)
{
  PSB_KEY PsbKey;
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  RSVP_LSP_PROPERTIES *pRsvpLsp;
  TUNNEL_KEY_T tunnel_key;
  SM_CALL_T *pCall = NULL;
  FRR_SM_DATA *pFrrSmData = pSm->data;
  FRR_SM_ENTRY *pFrrEntry = &pFrrSmData->FrrSmEntry;

  switch (sm_event->event)
    {
    case INGRESS_LSP_OPERATION_COMPLETE_EVENT:
      if (pFrrEntry->bypass_retry_timer.is_active == TRUE)
	{
	  te_stop_timer (&pFrrEntry->bypass_retry_timer);
	}
      pSm->state = FAST_REROUTE_SM_UP_STATE;
      memset (&PsbKey, 0, sizeof (PSB_KEY));
      PsbKey.Session.Dest = pFrrEntry->frr_key.merge_node;
      PsbKey.Session.TunnelId = pFrrEntry->BypassTunnelId;
      PsbKey.Session.ExtTunelId = rdb_get_router_id ();
      if (FindTunnel (&PsbKey, &pTunnel, ALL_TRUNKS) == TRUE)
	{
	  if ((pRsvpLsp = GetWorkingRsvpLsp (pTunnel)) != NULL)
	    {
	      pFrrSmData->BackupOutIf = pRsvpLsp->oIfIndex;
	      pFrrSmData->BypassTunnelsLabel = pRsvpLsp->Label;
	      memset (&tunnel_key, 0, sizeof (TUNNEL_KEY_T));
	      tunnel_key.Dest = PsbKey.Session.Dest;
	      tunnel_key.TunnelId = PsbKey.Session.TunnelId;
	      tunnel_key.Source = PsbKey.Session.ExtTunelId;
	      /*if(CreateRsvpRequest(rdb_get_router_id(),
	         GetLSP(&tunnel_key),
	         100,900000,
	         100,900000,
	         FALSE,FALSE,
	         pFrrSmData->card) != E_OK)
	         {
	         zlog_info("\ncannnot create RSVP instance on LSP-Tunnel");
	         } HERE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
	    }
	  else
	    {
	      zlog_err ("\ncannot get working RSVP LSP %s %d", __FILE__,
			__LINE__);
	    }
	}
      else
	{
	  zlog_err ("\ncannot find tunnel %x %x %x %s %d",
		    PsbKey.Session.Dest,
		    PsbKey.Session.TunnelId,
		    PsbKey.Session.ExtTunelId, __FILE__, __LINE__);
	}
      UpdateIfWithBacupInfo (pFrrSmData);
      pSm->state = FAST_REROUTE_SM_UP_STATE;
      break;
    case INGRESS_LSP_OPERATION_FAILED_EVENT:
      zlog_info ("\nBypass tunnel setup is failed %x %x %x %s %d",
		 pFrrEntry->frr_key.protected_node,
		 pFrrEntry->frr_key.merge_node,
		 pFrrEntry->frr_key.OutIfIndex, __FILE__, __LINE__);
      pFrrEntry->bypass_retry_timer.data.bypass_retry_data =
	pFrrEntry->frr_key;
      if (te_start_timer
	  (&pFrrEntry->bypass_retry_timer, BYPASS_TUNNEL_RETRY_EXPIRY,
	   10000) != E_OK)
	{
	  zlog_err ("\ncannot start timer %s %d", __FILE__, __LINE__);
	}
      break;
    case BYPASS_SETUP_REQ_EVENT:
      break;
    default:
      zlog_err ("\nDefault case reached %s %d", __FILE__, __LINE__);
    }
  return NULL;
}

static SM_CALL_T *(*lsp_sm_event_handler[FAST_REROUTE_SM_MAX_STATE])
  (HANDLE sm_handle, SM_EVENT_T * sm_data) =
{
fast_reroute_sm_empty_handler,
    fast_reroute_sm_init, fast_reroute_sm_up, fast_reroute_sm_retry};

SM_CALL_T *
fast_reroute_sm_handler (HANDLE sm_handle, SM_EVENT_T * sm_data)
{
  SM_T *pSm = (SM_T *) sm_handle;
  if (sm_data == NULL)
    {
      zlog_err ("\nfatal: sm_data is NULL %s %d", __FILE__, __LINE__);
      FastReRouteSmDestroy (pSm);
      return NULL;
    }
  if ((pSm->state < INIT_STATE) || (pSm->state >= FAST_REROUTE_SM_MAX_STATE))
    {
      FastReRouteSmDestroy (pSm);
      return NULL;
    }
  return lsp_sm_event_handler[pSm->state] (pSm, sm_data);
}

SM_CALL_T *
fast_reroute_sm_sync_invoke (FRR_SM_CALL * pFrrCall, SM_EVENT_E event)
{
  SM_T *pSm;
  SM_CALL_T *pEvent = NULL;
  FRR_SM_DATA *pFrrSmData;
  FRR_SM_ENTRY *pFrrEntry;
  FRR_LABEL_ENTRY *pLabelEntry;
  FRR_INGRESS_ENTRY *pIngressEntry;
  PATRICIA_PARAMS params;
  BOOL malloc_performed = FALSE;
  zlog_info ("\ninside of fast_reroute_sm_sync_invoke");
  if (event == BYPASS_SETUP_REQ_EVENT)
    {
      if ((pFrrEntry = FindFastRerouteSm (&pFrrCall->frr_key)) == NULL)
	{
	  zlog_info ("\nnew FRR SM creation...");
	  pSm = sm_gen_alloc (0, FAST_REROUTE_SM);
	  if (pSm == NULL)
	    {
	      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	      return NULL;
	    }

	  if ((pFrrSmData = XMALLOC (MTYPE_TE, sizeof (FRR_SM_DATA))) == NULL)
	    {
	      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	      sm_gen_free (pSm);
	      return NULL;
	    }
	  malloc_performed = TRUE;
	  pFrrEntry = &pFrrSmData->FrrSmEntry;
	  pFrrEntry->frr_key = pFrrCall->frr_key;
	  pFrrEntry->Node.key_info = &pFrrEntry->frr_key;
	  pFrrEntry->sm_handle = pSm;
	  pSm->data = pFrrSmData;
	  params.key_size = sizeof (unsigned int);
	  params.info_size = 0;
	  zlog_info ("\nLabel's tree initialization...");
	  if (patricia_tree_init (&pFrrEntry->labels_tree, &params) != E_OK)
	    {
	      zlog_err ("\ncannot initiate patricia tree (per SM) for FRR");
	      sm_gen_free (pSm);
	      XFREE (MTYPE_TE, pFrrSmData);
	      return NULL;
	    }

	  params.key_size = sizeof (PSB_KEY);
	  params.info_size = 0;
	  zlog_info ("\nIngress tree initialization...");
	  if (patricia_tree_init (&pFrrEntry->ingress_tree, &params) != E_OK)
	    {
	      zlog_err ("\ncannot initiate patricia tree (per SM) for FRR");
	      sm_gen_free (pSm);
	      XFREE (MTYPE_TE, pFrrSmData);
	      return NULL;
	    }

	  zlog_info ("\nadding FRR SM node to the tree...");

	  if (patricia_tree_add (&FastReRouteSmTree, &pFrrEntry->Node) !=
	      E_OK)
	    {
	      sm_gen_free (pSm);
	      XFREE (MTYPE_TE, pFrrSmData);
	      return NULL;
	    }
	}
      else
	{
	  pSm = pFrrEntry->sm_handle;
	}
      if (pFrrCall->Label != 0)
	{
	  if ((pLabelEntry =
	       XMALLOC (MTYPE_TE, sizeof (FRR_LABEL_ENTRY))) == NULL)
	    {
	      zlog_err ("\nmalloc failed...");
	      if (malloc_performed == TRUE)
		{
		  if (patricia_tree_del (&FastReRouteSmTree, &pFrrEntry->Node)
		      != E_OK)
		    {
		      zlog_err
			("\ncannot delete FRR ENTRY from FastReRouteTree");
		      return NULL;
		    }
		  XFREE (MTYPE_TE, pFrrSmData);
		  sm_gen_free (pSm);
		}
	      return NULL;
	    }
	  pLabelEntry->Label = pFrrCall->Label;
	  pLabelEntry->Node.key_info = &pLabelEntry->Label;
	  if (patricia_tree_add (&pFrrEntry->labels_tree, &pLabelEntry->Node)
	      != E_OK)
	    {
	      if (patricia_tree_get (&pFrrEntry->labels_tree,
				     (const uns8 *) &pLabelEntry->Label) ==
		  NULL)
		{
		  zlog_err ("\ncannot add label frr entry - unknown reason");
		}
	      XFREE (MTYPE_TE, pLabelEntry);
	      return NULL;
	    }
	  PlatformWideLabelSpace[pLabelEntry->Label -
				 1].BackupForwardingInformation.frr_key =
	    pFrrCall->frr_key;
	  PlatformWideLabelSpace[pLabelEntry->Label -
				 1].BackupForwardingInformation.MergeNode =
	    pFrrCall->MergeNode;
	  PlatformWideLabelSpace[pLabelEntry->Label -
				 1].BackupForwardingInformation.PSB_KEY =
	    pFrrCall->PSB_KEY;
	  zlog_info ("\nINVOKE: %x %x %x %x %x",
		     PlatformWideLabelSpace[pLabelEntry->Label -
					    1].BackupForwardingInformation.
		     PSB_KEY.Session.Dest,
		     PlatformWideLabelSpace[pLabelEntry->Label -
					    1].BackupForwardingInformation.
		     PSB_KEY.Session.TunnelId,
		     PlatformWideLabelSpace[pLabelEntry->Label -
					    1].BackupForwardingInformation.
		     PSB_KEY.Session.ExtTunelId,
		     PlatformWideLabelSpace[pLabelEntry->Label -
					    1].BackupForwardingInformation.
		     PSB_KEY.sender.Lsp_IdNet,
		     PlatformWideLabelSpace[pLabelEntry->Label -
					    1].BackupForwardingInformation.
		     PSB_KEY.sender.IPv4TunnelSenderNet);
	}
      else
	{
	  RSVP_TUNNEL_PROPERTIES *pTunnel;
	  RSVP_LSP_PROPERTIES *pRsvpLsp;
	  uns16 SavedLspId;
	  IPV4_ADDR SavedSenderIp;
	  zlog_info ("\nIngress LER call...");
	  if ((pIngressEntry =
	       XMALLOC (MTYPE_TE, sizeof (FRR_INGRESS_ENTRY))) == NULL)
	    {
	      zlog_info ("\nmalloc failed...");
	      if (malloc_performed == TRUE)
		{
		  if (patricia_tree_del (&FastReRouteSmTree, &pFrrEntry->Node)
		      != E_OK)
		    {
		      zlog_err
			("\ncannot delete FRR ENTRY from FastReRouteTree");
		      return NULL;
		    }
		  XFREE (MTYPE_TE, pFrrSmData);
		  sm_gen_free (pSm);
		}
	      return NULL;
	    }
	  pIngressEntry->PsbKey = pFrrCall->PsbKey;
	  pIngressEntry->Node.key_info = &pIngressEntry->PsbKey;
	  zlog_info ("\nadding node to Ingress tree....");
	  if (patricia_tree_add
	      (&pFrrEntry->ingress_tree, &pIngressEntry->Node) != E_OK)
	    {
	      if (patricia_tree_get (&pFrrEntry->ingress_tree,
				     (const uns8 *) &pIngressEntry->PsbKey) ==
		  NULL)
		{
		  zlog_err ("\ncannot add label frr entry - unknown reason");
		}
	      XFREE (MTYPE_TE, pIngressEntry);
	      return NULL;
	    }
	  SavedLspId = pFrrCall->PsbKey.SenderTemplate.LspId;
	  SavedSenderIp = pFrrCall->PsbKey.SenderTemplate.IpAddr;
	  pFrrCall->PsbKey.sender.Lsp_IdNet = 0;
	  pFrrCall->PsbKey.sender.IPv4TunnelSenderNet = 0;
	  if (FindTunnel (&pFrrCall->PsbKey, &pTunnel, ALL_TRUNKS) == TRUE)
	    {
	      pFrrCall->PsbKey.SenderTemplate.LspId = SavedLspId;
	      pFrrCall->PsbKey.SenderTemplate.IpAddr = SavedSenderIp;
	      if (((pRsvpLsp =
		    FindRsvpLspByLspId (pTunnel, SavedLspId)) != NULL)
		  && (pRsvpLsp->tunneled == FALSE))
		{
		  pRsvpLsp->forw_info.path.BackupForwardingInformation.
		    frr_key = pFrrCall->frr_key;
		  pRsvpLsp->forw_info.path.BackupForwardingInformation.
		    MergeNode = pFrrCall->MergeNode;
		  pRsvpLsp->forw_info.path.BackupForwardingInformation.
		    PsbKey = pFrrCall->PsbKey;
		}
	      else
		{
		  zlog_err
		    ("\ncannot get RSVP LSP by LSP ID or LSP is tunneled %x %s %d",
		     pRsvpLsp, __FILE__, __LINE__);
		}
	    }
	  else
	    {
	      zlog_err ("\ncannot find tunnel %x %x %x %s %d",
			pFrrCall->PsbKey.Session.Dest,
			pFrrCall->PsbKey.Session.TunnelId,
			pFrrCall->PsbKey.Session.ExtTunelId,
			__FILE__, __LINE__);
	    }
	}
      zlog_info ("\ncreation event...");
      if ((pEvent =
	   sm_gen_sync_event_send ((HANDLE) pSm, event, NULL)) == NULL)
	{
	  zlog_err ("\ncan not invoke sm %s %d", __FILE__, __LINE__);
	  XFREE (MTYPE_TE, pFrrSmData);
	  sm_gen_free (pSm);
	}
    }
  return pEvent;
}

extern PATRICIA_TREE PlatformWideFreeLabels;
extern LABEL_ENTRY PlatformWideLabelSpace[LABEL_SPACE_SIZE];

uns32
UpdateIfWithSingleBacupInfo (FRR_SM_DATA * pFrrSmData,
			     unsigned int Label,
			     PSB_KEY * PSB_KEY, unsigned int MergeNodeLabel)
{
  COMPONENT_LINK *pComponentLink;
  FRR_LABEL_ENTRY *pLabelEntry;
  FRR_INGRESS_ENTRY *pIngressEntry;
  FRR_SM_ENTRY *pFrrEntry = &pFrrSmData->FrrSmEntry;

  if (rdb_get_component_link (pFrrEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      pFrrEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      &pComponentLink) != E_OK)
    {
      zlog_err ("\ncannot get component link %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  if ((pLabelEntry =
       patricia_tree_get (&pFrrEntry->labels_tree,
			  (const uns8 *) &Label)) != NULL)
    {
      if (patricia_tree_get
	  (&PlatformWideFreeLabels,
	   (const uns8 *) &pLabelEntry->Label) == NULL)
	{
	  PlatformWideLabelSpace[pLabelEntry->Label -
				 1].BackupForwardingInformation.
	    MergeNodeLabel = MergeNodeLabel;
	  PlatformWideLabelSpace[pLabelEntry->Label -
				 1].BackupForwardingInformation.
	    MergeNodeLabelValid = TRUE;
	  /*PlatformWideLabelSpace[pLabelEntry->Label-1].BackupForwardingInformation.PSB_KEY = *PSB_KEY; */
	  if (pFrrSmData->BypassTunnelsLabel != 0)
	    {
	      PlatformWideLabelSpace[pLabelEntry->Label -
				     1].BackupForwardingInformation.
		BypassTunnelsLabel = pFrrSmData->BypassTunnelsLabel;
	      PlatformWideLabelSpace[pLabelEntry->Label -
				     1].BackupForwardingInformation.OutIf =
		pFrrSmData->BackupOutIf;
	      zlog_info
		("\nLSR: deletion from FRR SM tree and insertion to component link tree");
	      if (patricia_tree_del
		  (&pFrrEntry->labels_tree, &pLabelEntry->Node) != E_OK)
		{
		  zlog_err ("\ncannot delete node from patricia tree %s %d",
			    __FILE__, __LINE__);
		}
	      else
		if (patricia_tree_add
		    (&pComponentLink->ProtectionTree,
		     &pLabelEntry->Node) != E_OK)
		{
		  zlog_err ("\ncannot add node to patricia %s %d", __FILE__,
			    __LINE__);
		}
	      else
		{
		  if (InformRsvpAboutFrr
		      (&PlatformWideLabelSpace[pLabelEntry->Label - 1].
		       BackupForwardingInformation.PSB_KEY,
		       PlatformWideLabelSpace[pLabelEntry->Label -
					      1].allocator,
		       PlatformWideLabelSpace[pLabelEntry->Label - 1].IfIndex,
		       pFrrSmData->BackupOutIf, pFrrSmData->card,
		       PlatformWideLabelSpace[pLabelEntry->Label -
					      1].BackupForwardingInformation.
		       MergeNode) != E_OK)
		    {
		      zlog_err ("\ncannot update LCC with backup intfo");
		    }
		}
	    }
	}
      else
	{
	  zlog_err ("\nAllocated Label %x is not really allocated %s %d...",
		    pLabelEntry->Label, __FILE__, __LINE__);
	}
    }
  return E_OK;
}

uns32
UpdateIfWithSingleIngressBacupInfo (FRR_SM_DATA * pFrrSmData,
				    PSB_KEY * PsbKey,
				    unsigned int MergeNodeLabel)
{
  COMPONENT_LINK *pComponentLink;
  FRR_INGRESS_ENTRY *pIngressEntry;
  FRR_SM_ENTRY *pFrrEntry = &pFrrSmData->FrrSmEntry;

  PsbKey->SenderTemplate.LspId = ntohs (PsbKey->SenderTemplate.LspId);

  if (rdb_get_component_link (pFrrEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      pFrrEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      &pComponentLink) != E_OK)
    {
      zlog_err ("\ncannot get component link %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  if ((pIngressEntry =
       patricia_tree_get (&pFrrEntry->ingress_tree,
			  (const uns8 *) PSB_KEY)) != NULL)
    {
      /* update working RSVP LSP with valid info */
      if (pFrrSmData->BypassTunnelsLabel != 0)
	{
	  RSVP_TUNNEL_PROPERTIES *pTunnel;
	  RSVP_LSP_PROPERTIES *pRsvpLsp;
	  uns16 SavedLspId = pIngressEntry->PSB_KEY.sender.Lsp_IdNet;
	  IPV4_ADDR SavedSenderIp =
	    pIngressEntry->PSB_KEY.sender.IPv4TunnelSenderNet;
	  pIngressEntry->PsbKey.SenderTemplate.LspId = 0;
	  pIngressEntry->PsbKey.SenderTemplate.IpAddr = 0;
	  if (FindTunnel (&pIngressEntry->PsbKey, &pTunnel, ALL_TRUNKS) ==
	      TRUE)
	    {
	      pIngressEntry->PsbKey.SenderTemplate.LspId = SavedLspId;
	      pIngressEntry->PsbKey.SenderTemplate.IpAddr = SavedSenderIp;
	      if (((pRsvpLsp =
		    FindRsvpLspByLspId (pTunnel, SavedLspId)) != NULL)
		  && (pRsvpLsp->tunneled == FALSE))
		{
		  pRsvpLsp->forw_info.path.BackupForwardingInformation.
		    MergeNodeLabelValid = TRUE;
		  pRsvpLsp->forw_info.path.BackupForwardingInformation.
		    MergeNodeLabel = MergeNodeLabel;
		  /*pRsvpLsp->forw_info.path.BackupForwardingInformation.PSB_KEY = *PSB_KEY; */
		  if (pFrrSmData->BypassTunnelsLabel != 0)
		    {
		      pRsvpLsp->forw_info.path.BackupForwardingInformation.
			BypassTunnelsLabel = pFrrSmData->BypassTunnelsLabel;
		      pRsvpLsp->forw_info.path.BackupForwardingInformation.
			OutIf = pFrrSmData->BackupOutIf;
		      zlog_info
			("\nIngress: deletion from FRR SM tree and insertion to component link tree");
		      if (patricia_tree_del
			  (&pFrrEntry->ingress_tree,
			   &pIngressEntry->Node) != E_OK)
			{
			  zlog_err
			    ("\ncannot delete node from patricia tree %s %d",
			     __FILE__, __LINE__);
			}
		      else
			if (patricia_tree_add
			    (&pComponentLink->IngressProtectionTree,
			     &pIngressEntry->Node) != E_OK)
			{
			  zlog_err ("\ncannot add node to patricia %s %d",
				    __FILE__, __LINE__);
			}
		      else
			{
			  if (InformRsvpAboutFrr (PsbKey,
						  pRsvpLsp->card,
						  pRsvpLsp->oIfIndex,
						  pFrrSmData->BackupOutIf,
						  pRsvpLsp->forw_info.path.
						  BackupForwardingInformation.
						  MergeNode) != E_OK)
			    {
			      zlog_err
				("\ncannot update LCC with backup intfo");
			    }
			}
		    }
		}
	      else
		{
		  if (pRsvpLsp == NULL)
		    {
		      zlog_err
			("\ncannot get working RSVP LSP %x %x %x %x %x %s %d",
			 pIngressEntry->PsbKey.Session.Dest,
			 pIngressEntry->PsbKey.Session.TunnelId,
			 pIngressEntry->PsbKey.Session.ExtTunelId, SavedLspId,
			 SavedSenderIp, __FILE__, __LINE__);
		    }
		  else
		    {
		      zlog_err ("\nRSVP LSP %x %x %x is tunneled %x %s %d",
				pIngressEntry->PsbKey.Session.Dest,
				pIngressEntry->PsbKey.Session.TunnelId,
				pIngressEntry->PsbKey.Session.ExtTunelId,
				pRsvpLsp->tunneled, __FILE__, __LINE__);
		    }
		}
	    }
	}
    }
  return E_OK;
}

uns32
UpdateIfWithBacupInfo (FRR_SM_DATA * pFrrSmData)
{
  COMPONENT_LINK *pComponentLink;
  FRR_LABEL_ENTRY *pLabelEntry;
  FRR_INGRESS_ENTRY *pIngressLabelEntry;
  unsigned int key = 0;
  PSB_KEY PsbKey;
  FRR_SM_ENTRY *pFrrEntry = &pFrrSmData->FrrSmEntry;

  if (rdb_get_component_link (pFrrEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      pFrrEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      &pComponentLink) != E_OK)
    {
      zlog_err ("\ncannot get component link %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  /* first - update LSR entries */
  zlog_info ("\nupdating an LSR entries %x %x %x...",
	     pFrrEntry->frr_key.merge_node, pFrrEntry->frr_key.OutIfIndex,
	     pFrrEntry->frr_key.protected_node);
  while ((pLabelEntry =
	  patricia_tree_getnext (&pFrrEntry->labels_tree,
				 (const uns8 *) &key)) != NULL)
    {
      if (patricia_tree_get
	  (&PlatformWideFreeLabels,
	   (const uns8 *) &pLabelEntry->Label) == NULL)
	{
	  if (PlatformWideLabelSpace[pLabelEntry->Label - 1].
	      BackupForwardingInformation.MergeNodeLabelValid == TRUE)
	    {
	      PlatformWideLabelSpace[pLabelEntry->Label -
				     1].BackupForwardingInformation.
		BypassTunnelsLabel = pFrrSmData->BypassTunnelsLabel;
	      PlatformWideLabelSpace[pLabelEntry->Label -
				     1].BackupForwardingInformation.OutIf =
		pFrrSmData->BackupOutIf;
	      zlog_info
		("\naLSR: deletion from FRR SM tree and insertion to component link tree");
	      if (patricia_tree_del
		  (&pFrrEntry->labels_tree, &pLabelEntry->Node) != E_OK)
		{
		  zlog_err ("\ncannot delete node from patricia tree %s %d",
			    __FILE__, __LINE__);
		}
	      else
		{
		  if (patricia_tree_add
		      (&pComponentLink->ProtectionTree,
		       &pLabelEntry->Node) != E_OK)
		    {
		      zlog_err ("\ncannot add node to patricia %s %d",
				__FILE__, __LINE__);
		    }
		  else
		    if (InformRsvpAboutFrr
			(&PlatformWideLabelSpace[pLabelEntry->Label - 1].
			 BackupForwardingInformation.PSB_KEY,
			 PlatformWideLabelSpace[pLabelEntry->Label -
						1].allocator,
			 PlatformWideLabelSpace[pLabelEntry->Label -
						1].IfIndex,
			 pFrrSmData->BackupOutIf, pFrrSmData->card,
			 PlatformWideLabelSpace[pLabelEntry->Label -
						1].
			 BackupForwardingInformation.MergeNode) != E_OK)
		    {
		      zlog_err ("\ncannot update LCC with backup intfo");
		    }
		}
	    }
	}
      else
	{
	  zlog_err ("\nAllocated Label %x is not really allocated %s %d...",
		    pLabelEntry->Label, __FILE__, __LINE__);
	}
      key = pLabelEntry->Label;
    }
  /* second - update Ingress entries */
  memset (&PSB_KEY, 0, sizeof (PSB_KEY));
  zlog_info ("\nupdating an Ingress entries...");
  while ((pIngressLabelEntry =
	  patricia_tree_getnext (&pFrrEntry->ingress_tree,
				 (const uns8 *) &PSB_KEY)) != NULL)
    {
      RSVP_TUNNEL_PROPERTIES *pTunnel;
      uns16 SavedLspId = pIngressLabelEntry->PSB_KEY.sender.Lsp_IdNet;
      IPV4_ADDR SavedSenderIp =
	pIngressLabelEntry->PSB_KEY.sender.IPv4TunnelSenderNet;

      pIngressLabelEntry->PsbKey.SenderTemplate.LspId = 0;
      pIngressLabelEntry->PsbKey.SenderTemplate.IpAddr = 0;
      zlog_info ("\nfinding a tunnel...");
      if (FindTunnel (&pIngressLabelEntry->PsbKey, &pTunnel, ALL_TRUNKS) ==
	  TRUE)
	{
	  RSVP_LSP_PROPERTIES *pRsvpLsp;

	  pIngressLabelEntry->PsbKey.SenderTemplate.LspId = SavedLspId;
	  pIngressLabelEntry->PsbKey.SenderTemplate.IpAddr = SavedSenderIp;
	  zlog_info ("\nfinding an LSP...");
	  if (((pRsvpLsp = FindRsvpLspByLspId (pTunnel, SavedLspId)) != NULL)
	      && (pRsvpLsp->tunneled == FALSE))
	    {
	      if (pRsvpLsp->forw_info.path.BackupForwardingInformation.
		  MergeNodeLabelValid == TRUE)
		{
		  pRsvpLsp->forw_info.path.BackupForwardingInformation.
		    BypassTunnelsLabel = pFrrSmData->BypassTunnelsLabel;
		  pRsvpLsp->forw_info.path.BackupForwardingInformation.OutIf =
		    pFrrSmData->BackupOutIf;
		  zlog_info
		    ("\naIngress: deletion from FRR SM tree and insertion to component link tree");
		  if (patricia_tree_del
		      (&pFrrEntry->ingress_tree,
		       &pIngressLabelEntry->Node) == E_OK)
		    {
		      if (patricia_tree_add
			  (&pComponentLink->IngressProtectionTree,
			   &pIngressLabelEntry->Node) != E_OK)
			{
			  zlog_err
			    ("\ncannot add entry to Ingress tree %x %x %x %x %s %d",
			     pComponentLink->oifIndex,
			     pIngressLabelEntry->PsbKey.Session.Dest,
			     pIngressLabelEntry->PsbKey.Session.TunnelId,
			     pIngressLabelEntry->PsbKey.Session.ExtTunelId,
			     __FILE__, __LINE__);
			}
		      else
			{
			  if (InformRsvpAboutFrr
			      (&pRsvpLsp->forw_info.path.
			       BackupForwardingInformation.PsbKey,
			       pRsvpLsp->oIfIndex, pFrrSmData->BackupOutIf,
			       pRsvpLsp->forw_info.path.
			       BackupForwardingInformation.MergeNode) != E_OK)
			    {
			      zlog_err
				("\ncannot update LCC with backup intfo");
			    }
			}
		    }
		  else
		    {
		      zlog_err
			("\ncannot delete node from patricia %x %x %x %s %d",
			 pIngressLabelEntry->PsbKey.Session.Dest,
			 pIngressLabelEntry->PsbKey.Session.TunnelId,
			 pIngressLabelEntry->PsbKey.Session.ExtTunelId,
			 __FILE__, __LINE__);
		    }
		}
	    }
	  else
	    {
	      if (pRsvpLsp == NULL)
		{
		  zlog_err
		    ("\ncannot get working RSVP LSP %x %x %x %x %x %s %d",
		     pIngressLabelEntry->PsbKey.Session.Dest,
		     pIngressLabelEntry->PsbKey.Session.TunnelId,
		     pIngressLabelEntry->PsbKey.Session.ExtTunelId,
		     SavedLspId, SavedSenderIp, __FILE__, __LINE__);
		}
	      else
		{
		  zlog_err ("\nRSVP LSP %x %x %x is tunneled %x %s %d",
			    pIngressLabelEntry->PsbKey.Session.Dest,
			    pIngressLabelEntry->PsbKey.Session.TunnelId,
			    pIngressLabelEntry->PsbKey.Session.ExtTunelId,
			    pRsvpLsp->tunneled, __FILE__, __LINE__);
		}
	    }
	}
      else
	{
	  zlog_err ("\ncannot find tunnel %x %x %x %s %d", __FILE__,
		    __LINE__);
	}
      PsbKey = pIngressLabelEntry->PsbKey;
    }
  return E_OK;
}

FRR_SM_ENTRY *
FindFastRerouteSm (FRR_SM_KEY * frr_key)
{
  return patricia_tree_get (&FastReRouteSmTree, (const uns8 *) frr_key);
}

void
InitFastReRoute ()
{
  PATRICIA_PARAMS params;

  params.key_size = sizeof (FRR_SM_KEY);
  params.info_size = 0;
  if (patricia_tree_init (&FastReRouteSmTree, &params) != E_OK)
    {
      zlog_err ("\ncannot initiate patricia tree for FRR");
      return;
    }
}

void
RRO_ChangedHook (uns32 Label,
		 RSVP_RRO_LSP_TUNNEL * pRro,
		 SESSION_OBJ * pSess,
		 SENDER_TEMPLATE_OBJ * pSender, uns32 IfIndex)
{
  TE_MSG *pMsg;
  /* clone RRO and send it up */
  /*if((pMsg = dmsg_create(GetLcbPtr(),LTCS_EVENT_RRO_CHANGED)) == NULL)
     {
     zlog_info("\ncannot create message %s %d",__FILE__,__LINE__);
     return;
     } */
  if (Label == 0)
    {
      zlog_info
	("\ninside of RRO_ChangedHook: Dest#%x Tunnel#%x Source#%x LspId#%x Source %x",
	 pSess->Dest, pSess->TunnelId, pSess->ExtTunelId, pSender->LspId,
	 pSender->IpAddr);
    }
  else
    {
      zlog_info ("\ninside of RRO_ChangedHook: Label#%x", Label);
    }
  if ((pRro != NULL) && (pRro->nSubObjects != 0))
    {
      if ((pMsg->info.rro_changed_hook.pRro =
	   XMALLOC (MTYPE_TE,
		    (sizeof (RSVP_RRO_LSP_TUNNEL) +
		     sizeof (RSVP_RRO_SUBOBJ) * (pRro->nSubObjects - 1)))) ==
	  NULL)
	{
	  zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	  dmsg_release (pMsg);
	  return;
	}
      pMsg->info.rro_changed_hook.pRro->nSubObjects = pRro->nSubObjects;
      memcpy (pMsg->info.rro_changed_hook.pRro->SubObjects,
	      pRro->SubObjects,
	      sizeof (RSVP_RRO_SUBOBJ) * (pRro->nSubObjects));
#if 1
      {
	int i;
	RSVP_RRO_SUBOBJ *pDbg = pMsg->info.rro_changed_hook.pRro->SubObjects;
	for (i = 0; i < pMsg->info.rro_changed_hook.pRro->nSubObjects; i++)
	  {
	    switch (pDbg[i].SubType)
	      {
	      case 1:
		zlog_info
		  ("\nobj#%d IP ADDR %x/%x prefix len %x/%x flag %x/%x", i,
		   pDbg[i].SubData.IPv4.Addr,
		   pRro->SubObjects[i].SubData.IPv4.Addr,
		   pDbg[i].SubData.IPv4.PrefixBitLen,
		   pRro->SubObjects[i].SubData.IPv4.PrefixBitLen,
		   pDbg[i].SubData.IPv4.Flags,
		   pRro->SubObjects[i].SubData.IPv4.Flags);
		break;
	      case 3:
		zlog_info
		  ("\nobj#%d LABEL ctype %x/%x flags %x/%x value %x/%x", i,
		   pDbg[i].SubData.Label.Label_CType,
		   pRro->SubObjects[i].SubData.Label.Label_CType,
		   pDbg[i].SubData.Label.Label_Flags,
		   pRro->SubObjects[i].SubData.Label.Label_Flags,
		   pDbg[i].SubData.Label.Label_Value,
		   pRro->SubObjects[i].SubData.Label.Label_Value);
		break;
	      default:
		zlog_info ("\nobject of unknown type %x/%x", pDbg[i].SubType,
			   pRro->SubObjects[i].SubType);
	      }
	  }
      }
#endif
    }
  pMsg->info.rro_changed_hook.Label = Label;
  pMsg->info.rro_changed_hook.OutIf = IfIndex;
  if (pMsg->info.rro_changed_hook.Label == 0)
    {
      pMsg->info.rro_changed_hook.PSB_KEY.Session.Dest = pSess->IPDestNet;
      pMsg->info.rro_changed_hook.PSB_KEY.Session.TunnelId = pSess->TunnelId;
      pMsg->info.rro_changed_hook.PSB_KEY.Session.ExtTunelId =
	pSess->ExtendedTunnelId;
      pMsg->info.rro_changed_hook.PSB_KEY.sender.Lsp_IdNet =
	pSender->Lsp_IdNet;
      pMsg->info.rro_changed_hook.PSB_KEY.sender.IPv4TunnelSenderNet =
	pSender->IPv4TunnelSenderNet;
    }
  if (svc_send_msg (pMsg, 1, MDS_USR_CONSOLE_SVC) != E_OK)
    zlog_info ("\nFatal: can not send mds message %s %d", __FILE__, __LINE__);
  if (pMsg->info.rro_changed_hook.pRro != NULL)
    XFREE (MTYPE_TE, pMsg->info.rro_changed_hook.pRro);
  return;
}

void
RRO_ChangedMsg (RRO_CHANGED_HOOK * pChangedRRO)
{
  int i;
  RSVP_RRO_LSP_TUNNEL *pRro = pChangedRRO->pRro;
  FRR_SM_ENTRY *pFrrSmEntry;
  FRR_SM_KEY *pFrrSmKey;
  IPV4_ADDR merge_node_router_id = 0;
  HJCONTEXT rdb_handle = ((LTCS_CB *) GetLcbPtr ())->rdb_layer_handle;

  zlog_info ("\ninside of RRO_ChangedMsg %x", pChangedRRO->Label);
  if (pChangedRRO->Label != 0)
    {
      pFrrSmKey =
	&PlatformWideLabelSpace[pChangedRRO->Label -
				1].BackupForwardingInformation.frr_key;
      pFrrSmEntry = FindFastRerouteSm (pFrrSmKey);
      if (pFrrSmEntry == NULL)
	{
	  zlog_err ("\ncannot get FRR SM entry for %x %x %x %s %d",
		    pFrrSmKey->merge_node, pFrrSmKey->OutIfIndex,
		    pFrrSmKey->protected_node, __FILE__, __LINE__);
	  return;
	}
    }
  else
    {
      RSVP_TUNNEL_PROPERTIES *pTunnel;
      uns16 SavedLspId = pChangedRRO->PSB_KEY.sender.Lsp_IdNet;
      IPV4_ADDR SavedSenderIp =
	pChangedRRO->PSB_KEY.sender.IPv4TunnelSenderNet;

      pChangedRRO->PSB_KEY.Session.Dest =
	ntohl (pChangedRRO->PSB_KEY.Session.Dest);

      pChangedRRO->PSB_KEY.sender.Lsp_IdNet = 0;
      pChangedRRO->PSB_KEY.sender.IPv4TunnelSenderNet = 0;

      if (FindTunnel (&pChangedRRO->PSB_KEY, &pTunnel, ALL_TRUNKS) == TRUE)
	{
	  RSVP_LSP_PROPERTIES *pRsvpLsp;

	  pChangedRRO->PSB_KEY.sender.Lsp_IdNet = ntohs (SavedLspId);
	  pChangedRRO->PSB_KEY.sender.IPv4TunnelSenderNet = SavedSenderIp;

	  if (((pRsvpLsp =
		FindRsvpLspByLspId (pTunnel, ntohs (SavedLspId))) != NULL)
	      && (pRsvpLsp->tunneled == FALSE))
	    {
	      pFrrSmKey =
		&pRsvpLsp->forw_info.path.BackupForwardingInformation.frr_key;
	      pFrrSmEntry = FindFastRerouteSm (pFrrSmKey);
	      if (pFrrSmEntry == NULL)
		{
		  zlog_err
		    ("\ncannot get FRR SM entry for %x/%x %x/%x %x/%x %s %d",
		     pFrrSmKey->merge_node,
		     pRsvpLsp->forw_info.path.BackupForwardingInformation.
		     frr_key.merge_node, pFrrSmKey->OutIfIndex,
		     pRsvpLsp->forw_info.path.BackupForwardingInformation.
		     frr_key.OutIfIndex, pFrrSmKey->protected_node,
		     pRsvpLsp->forw_info.path.BackupForwardingInformation.
		     frr_key.protected_node, __FILE__, __LINE__);
		  return;
		}
	    }
	  else
	    {
	      if (pRsvpLsp == NULL)
		{
		  zlog_err
		    ("\ncannot get working RSVP LSP for %x %x %x %x %x %s %d",
		     pChangedRRO->PSB_KEY.Session.Dest,
		     pChangedRRO->PSB_KEY.Session.TunnelId,
		     pChangedRRO->PSB_KEY.Session.ExtTunelId, SavedLspId,
		     SavedSenderIp, __FILE__, __LINE__);
		}
	      else
		{
		  zlog_err ("\nRSVP LSP %x %x %x %x %x is tunneled %x %s %d",
			    pChangedRRO->PSB_KEY.Session.Dest,
			    pChangedRRO->PSB_KEY.Session.TunnelId,
			    pChangedRRO->PSB_KEY.Session.ExtTunelId,
			    SavedLspId,
			    SavedSenderIp,
			    pRsvpLsp->tunneled, __FILE__, __LINE__);
		}
	      return;
	    }
	}
      else
	{
	  zlog_err ("\ncannot find tunnel %x %x %x %x %x %s %d",
		    pChangedRRO->PSB_KEY.Session.Dest,
		    pChangedRRO->PSB_KEY.Session.TunnelId,
		    pChangedRRO->PSB_KEY.Session.ExtTunelId,
		    SavedLspId, SavedSenderIp, __FILE__, __LINE__);
	  return;
	}
    }


  if (pFrrSmEntry == NULL)
    {
      zlog_err ("\ncannot find FastReRoute SM by key %x %x %x",
		pFrrSmKey->merge_node,
		pFrrSmKey->OutIfIndex, pFrrSmKey->protected_node);
      return;
    }
  if (rdb_remote_link_router_id_get (rdb_handle,
				     pFrrSmKey->merge_node,
				     &merge_node_router_id) != E_OK)
    {
      zlog_err ("\ncannot get merge node's %x router ID %s %d",
		pFrrSmKey->merge_node, __FILE__, __LINE__);
    }
  zlog_info ("\nRouterID of the merge node %x", merge_node_router_id);

  if (pRro != NULL)
    {
      for (i = 0; i < pRro->nSubObjects; i++)
	{
	  if (pRro->SubObjects[i].SubType == RSVP_RRO_SUBOBJ_TYPE_IPV4_ADDR)
	    {
	      IPV4_ADDR node_router_id = 0;
	      if (rdb_remote_link_router_id_get (rdb_handle,
						 pRro->SubObjects[i].SubData.
						 IPv4.Addr,
						 &node_router_id) != E_OK)
		{
		  node_router_id = pRro->SubObjects[i].SubData.IPv4.Addr;
		}

	      zlog_info ("\nnode#%d/%x router ID %x",
			 i,
			 pRro->SubObjects[i].SubData.IPv4.Addr,
			 node_router_id);

	      if ((node_router_id == merge_node_router_id) &&
		  (i < (pRro->nSubObjects - 1)))
		{
		  if ((pRro->SubObjects[i + 1].SubType ==
		       RSVP_RRO_SUBOBJ_TYPE_LABEL_OBJ)
		      && (pRro->SubObjects[i + 1].SubData.Label.Label_Flags !=
			  0))
		    {
		      /* call here SM */
		      if (pChangedRRO->Label != 0)
			{
			  UpdateIfWithSingleBacupInfo (((SM_T *) pFrrSmEntry->
							sm_handle)->data,
						       pChangedRRO->Label,
						       &pChangedRRO->PSB_KEY,
						       pRro->SubObjects[i +
									1].
						       SubData.Label.
						       Label_Value);
			}
		      else
			{
			  UpdateIfWithSingleIngressBacupInfo (((SM_T *)
							       pFrrSmEntry->
							       sm_handle)->
							      data,
							      &pChangedRRO->
							      PSB_KEY,
							      pRro->
							      SubObjects[i +
									 1].
							      SubData.Label.
							      Label_Value);
			}
		      return;
		    }
		  else
		    if ((pRro->SubObjects[i + 1].SubType ==
			 RSVP_RRO_SUBOBJ_TYPE_LABEL_OBJ)
			&& (pRro->SubObjects[i + 1].SubData.Label.
			    Label_Flags == 0))
		    {
		      zlog_err
			("\nMerge node does not use platform-wide label space");
		    }
		  else
		    {
		      zlog_err
			("\nThere is no label object after hop object");
		    }
		}
	      else if (merge_node_router_id == node_router_id)
		{
		  zlog_err ("\nMerge node is found but it is last object");
		}
	    }
	}
      XFREE (MTYPE_TE, pRro);
    }
  zlog_err ("\nMerge node is not found %s %d", __FILE__, __LINE__);
}

void
FrrLabelRelease (unsigned int Label)
{
  FRR_SM_KEY *pFrrSmKey;
  FRR_SM_ENTRY *pFrrSmEntry;
  FRR_LABEL_ENTRY *pLabelEntry;
  COMPONENT_LINK *pComponentLink;
  /* validate the Label here */
  zlog_info ("\ninside of FrrLabelRelease %x", Label);
  pFrrSmKey =
    &PlatformWideLabelSpace[Label - 1].BackupForwardingInformation.frr_key;
  if ((pFrrSmEntry = FindFastRerouteSm (pFrrSmKey)) != NULL)
    {
      if ((pLabelEntry =
	   patricia_tree_get (&pFrrSmEntry->labels_tree,
			      (const uns8 *) &Label)) != NULL)
	{
	  zlog_info ("\nLabel entry is on FRR's tree...");
	  if (patricia_tree_del
	      (&pFrrSmEntry->labels_tree, &pLabelEntry->Node) != E_OK)
	    {
	      zlog_err ("\ncannot delete node from patricia %s %d", __FILE__,
			__LINE__);
	      return;
	    }
	  XFREE (MTYPE_TE, pLabelEntry);
	  return;
	}
    }
  else
    {
      zlog_err ("\ncannot find FRR SM entry %x %x %x %s %d",
		pFrrSmKey->merge_node,
		pFrrSmKey->OutIfIndex,
		pFrrSmKey->protected_node, __FILE__, __LINE__);
      return;
    }
  if (rdb_get_component_link (((LTCS_CB *) GetLcbPtr ())->rdb_layer_handle, pFrrSmEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      pFrrSmEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      &pComponentLink) != E_OK)
    {
      zlog_err ("\ncannot get component link %s %d", __FILE__, __LINE__);
      return;
    }
  zlog_info ("\nLooking for the label entry on component link's tree...");
  if ((pLabelEntry =
       patricia_tree_get (&pComponentLink->ProtectionTree,
			  (const uns8 *) &Label)) != NULL)
    {
      if (patricia_tree_del
	  (&pComponentLink->ProtectionTree, &pLabelEntry->Node) != E_OK)
	{
	  zlog_err ("\ncannot delete node from patricia %s %d", __FILE__,
		    __LINE__);
	  return;
	}
      XFREE (MTYPE_TE, pLabelEntry);
      return;
    }
  zlog_err ("\nLabel is not backuped nor goes to be backuped %s %d", __FILE__,
	    __LINE__);
}

void
FrrIngressRelease (PSB_KEY * PSB_KEY)
{
  FRR_SM_KEY *pFrrSmKey;
  FRR_SM_ENTRY *pFrrSmEntry;
  FRR_INGRESS_ENTRY *pIngressLabelEntry;
  COMPONENT_LINK *pComponentLink;
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  RSVP_LSP_PROPERTIES *pRsvpLsp;
  uns16 SavedLspId = PSB_KEY->sender.Lsp_IdNet;
  IPV4_ADDR SavedSenderIp = PSB_KEY->sender.IPv4TunnelSenderNet;
  zlog_info ("\nInside of FrrIngressRelease...");
  PSB_KEY->sender.Lsp_IdNet = 0;
  PSB_KEY->sender.IPv4TunnelSenderNet = 0;
  if (FindTunnel (PSB_KEY, &pTunnel, ALL_TRUNKS) == TRUE)
    {
      if (((pRsvpLsp =
	    FindRsvpLspByLspId (pTunnel, ntohs (SavedLspId))) != NULL)
	  && (pRsvpLsp->tunneled == FALSE))
	{
	  pFrrSmKey =
	    &pRsvpLsp->forw_info.path.BackupForwardingInformation.frr_key;
	  if ((pFrrSmEntry = FindFastRerouteSm (pFrrSmKey)) != NULL)
	    {
	      PSB_KEY->sender.Lsp_IdNet = SavedLspId;
	      PSB_KEY->sender.IPv4TunnelSenderNet = SavedSenderIp;
	      zlog_info
		("\nLooking for the label entry on ont hte FRR's tree...");
	      if ((pIngressLabelEntry =
		   patricia_tree_get (&pFrrSmEntry->ingress_tree,
				      (const uns8 *) PSB_KEY)) != NULL)
		{
		  if (patricia_tree_del
		      (&pFrrSmEntry->ingress_tree,
		       &pIngressLabelEntry->Node) != E_OK)
		    {
		      zlog_err ("\ncannot delete node from patricia %s %d",
				__FILE__, __LINE__);
		      return;
		    }
		  XFREE (MTYPE_TE, pIngressLabelEntry);
		  return;
		}
	    }
	  else
	    {
	      zlog_err ("\ncannot find FRR SM %x %x %x %s %d",
			pFrrSmKey->merge_node,
			pFrrSmKey->OutIfIndex,
			pFrrSmKey->protected_node, __FILE__, __LINE__);
	      return;
	    }
	}
      else
	{
	  zlog_err ("\ncannot get RSVP LSP by id %x %s %d", SavedLspId,
		    __FILE__, __LINE__);
	  return;
	}
    }
  else
    {
      zlog_err ("\ncannot find tunnel %x %x %x %s %d",
		PSB_KEY->Session.Dest,
		PSB_KEY->Session.TunnelId,
		PSB_KEY->Session.ExtTunelId, __FILE__, __LINE__);
      return;
    }

  if (rdb_get_component_link (((LTCS_CB *) GetLcbPtr ())->rdb_layer_handle, pFrrSmEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      pFrrSmEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      &pComponentLink) != E_OK)
    {
      zlog_err ("\ncannot get component link %s %d", __FILE__, __LINE__);
      return;
    }
  zlog_info ("\nLooking for the label entry on component link's tree...");
  if ((pIngressLabelEntry =
       patricia_tree_get (&pComponentLink->IngressProtectionTree,
			  (const uns8 *) PSB_KEY)) != NULL)
    {
      if (patricia_tree_del
	  (&pComponentLink->IngressProtectionTree,
	   &pIngressLabelEntry->Node) != E_OK)
	{
	  zlog_err ("\ncannot delete node from patricia %s %d", __FILE__,
		    __LINE__);
	  return;
	}
      XFREE (MTYPE_TE, pIngressLabelEntry);
      return;
    }
  zlog_err ("\nLabel is not backuped nor goes to be backuped %s %d", __FILE__,
	    __LINE__);
}

void
BypassTunnelFailed (FRR_SM_DATA * pFrrSmData)
{
  COMPONENT_LINK *pComponentLink;
  FRR_LABEL_ENTRY *pLabelEntry;
  FRR_INGRESS_ENTRY *pIngressLabelEntry;
  unsigned int key = 0;
  PSB_KEY PSB_KEY;
  FRR_SM_ENTRY *pFrrEntry = &pFrrSmData->FrrSmEntry;

  if (rdb_get_component_link (((LTCS_CB *) GetLcbPtr ())->rdb_layer_handle, pFrrEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      pFrrEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
			      &pComponentLink) != E_OK)
    {
      zlog_err ("\ncannot get component link %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  memset (&PSB_KEY, 0, sizeof (PSB_KEY));
  while ((pIngressLabelEntry =
	  patricia_tree_getnext (&pComponentLink->IngressProtectionTree,
				 (const uns8 *) &PSB_KEY)) != NULL)
    {
      if (patricia_tree_del
	  (&pComponentLink->IngressProtectionTree,
	   &pIngressLabelEntry->Node) != E_OK)
	{
	  zlog_err ("\ncannot delete a node from patricia %s %d", __FILE__,
		    __LINE__);
	}
      else
	{
	  if (patricia_tree_add
	      (&pFrrEntry->ingress_tree, &pIngressLabelEntry->Node) != E_OK)
	    {
	      zlog_err ("\ncannot add node to patricia tree %s %d", __FILE__,
			__LINE__);
	    }
	}
      PSB_KEY = pIngressLabelEntry->PSB_KEY;
    }
  while ((pLabelEntry =
	  patricia_tree_getnext (&pComponentLink->ProtectionTree,
				 (const uns8 *) &key)) != NULL)
    {
      if (patricia_tree_del
	  (&pComponentLink->ProtectionTree, &pLabelEntry->Node) != E_OK)
	{
	  zlog_err ("\ncannot delete a node from patricia %s %d", __FILE__,
		    __LINE__);
	}
      else
	{
	  if (patricia_tree_add (&pFrrEntry->labels_tree, &pLabelEntry->Node)
	      != E_OK)
	    {
	      zlog_err ("\ncannot add node to patricia tree %s %d", __FILE__,
			__LINE__);
	    }
	}
      key = pLabelEntry->Label;
    }
}

void
BypassTunnelRetryExpiry (LTCS_MSG * pMsg)
{
  FRR_SM_ENTRY *pFrrSmEntry;
  OPEN_RSVP_CRLSP *pOpenLspParams;
  PSB_KEY PSB_KEY;
  SM_CALL_T *pCall;
  SM_T *pSm;

  if ((pFrrSmEntry =
       FindFastRerouteSm (&pMsg->info.bypass_retry_expiry.key)) != NULL)
    {
      pSm = pFrrSmEntry->sm_handle;
      if ((pOpenLspParams =
	   XMALLOC (MTYPE_TE, sizeof (OPEN_RSVP_CRLSP))) == NULL)
	{
	  zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	  /* Do some clean up here */
	  return;
	}
      pOpenLspParams->tunnel_id = pFrrSmEntry->BypassTunnelId;
      pOpenLspParams->ErHops2Exclude[0] = pFrrSmEntry->frr_key.protected_node;
      pOpenLspParams->ErHops2Exclude[1] =
	pFrrSmEntry->frr_key.prohibited_penultimate_node;
      pOpenLspParams->dest_ip = pFrrSmEntry->frr_key.merge_node;
      pOpenLspParams->src_ip = rdb_get_router_id ();
      pOpenLspParams->BW = 0;
      pOpenLspParams->Flags = RSVP_SESS_ATTRIBUTE_FLAG_SE_STYLE;
      pOpenLspParams->SetupPriority = 4;
      pOpenLspParams->HoldPriority = 4;

      if ((pCall =
	   lsp_sm_sync_invoke (pSm, pOpenLspParams,
			       INGRESS_LSP_REQUEST_EVENT)) == NULL)
	{
	  zlog_err ("\ncan not invoke sm %s %d", __FILE__, __LINE__);
	}
      else
	sm_call (pCall);
    }
  else
    {
      zlog_err ("\ncannot get FRR SM entry %x %x %x %s %d",
		pMsg->info.bypass_retry_expiry.key.merge_node,
		pMsg->info.bypass_retry_expiry.key.OutIfIndex,
		pMsg->info.bypass_retry_expiry.key.protected_node,
		__FILE__, __LINE__);
    }
}

uns32
InformRsvpAboutFrr (PSB_KEY * PSB_KEY,
		    V_CARD_ID to_card,
		    uns32 to_if,
		    uns32 NewOutIf, V_CARD_ID NewVcardId, IPV4_ADDR first_hop)
{
  LTCS_MSG *pMsg;
  if ((pMsg = dmsg_create (GetLcbPtr (), LTCS_EVENT_FRR_INFO_SET)) == NULL)
    {
      zlog_info ("\ncannot create message %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  zlog_info ("\ninside of InformRsvpAboutFrr %x %x %x %x %x",
	     PSB_KEY->Session.Dest,
	     PSB_KEY->Session.TunnelId,
	     PSB_KEY->Session.ExtTunelId,
	     PSB_KEY->sender.Lsp_IdNet, PSB_KEY->sender.IPv4TunnelSenderNet);
  pMsg->info.frr_data_set.PSB_KEY = *PSB_KEY;
  pMsg->info.frr_data_set.IfIndex = to_if;
  pMsg->info.frr_data_set.BackupOutIf = NewOutIf;
  pMsg->info.frr_data_set.BackupVcardId = NewVcardId;
  pMsg->info.frr_data_set.MergeNodeIp = first_hop;
  if (svc_send_msg (pMsg, to_card, MDS_USR_CONSOLE_SVC) != E_OK)
    {
      zlog_info ("\nFatal: can not send mds message %s %d", __FILE__,
		 __LINE__);
      return E_ERR;
    }
  dmsg_release (pMsg);
  return E_OK;
}

void
FastReRouteSmDestroy (SM_T * pSm)
{
  sm_gen_free (pSm);
}

void
FrrSmDump ()
{
  FRR_SM_ENTRY *pFrrSmEntry;
  FRR_SM_KEY frr_key;
  FRR_INGRESS_ENTRY *pIngressEntry;
  FRR_LABEL_ENTRY *pLabelEntry;
  PSB_KEY PSB_KEY;
  unsigned int label;
  SM_T *pSm;
  FRR_SM_DATA *pFrrSmData;
  COMPONENT_LINK *pComponentLink;

  memset (&frr_key, 0, sizeof (FRR_SM_KEY));

  while ((pFrrSmEntry =
	  patricia_tree_getnext (&FastReRouteSmTree,
				 (const uns8 *) &frr_key)) != NULL)
    {
      pSm = pFrrSmEntry->sm_handle;
      pFrrSmData = pSm->data;
      zlog_info
	("\nFRR SM protected node: %x I/F %x merge node %x tunnel ID %x BypassLabel %x BypasIfIndex %x",
	 pFrrSmEntry->frr_key.protected_node, pFrrSmEntry->frr_key.OutIfIndex,
	 pFrrSmEntry->frr_key.merge_node, pFrrSmEntry->BypassTunnelId,
	 pFrrSmData->BypassTunnelsLabel, pFrrSmData->BackupOutIf);
      label = 0;
      zlog_info ("\nNot completed Label (LSR) entries:");
      while ((pLabelEntry =
	      patricia_tree_getnext (&pFrrSmEntry->labels_tree,
				     (const uns8 *) &label)) != NULL)
	{
	  zlog_info
	    ("\nLabel#%x valid %x merge node label %x Out I/F %x Bypass label %x",
	     pLabelEntry->Label,
	     PlatformWideLabelSpace[pLabelEntry->Label -
				    1].BackupForwardingInformation.
	     MergeNodeLabelValid,
	     PlatformWideLabelSpace[pLabelEntry->Label -
				    1].BackupForwardingInformation.
	     MergeNodeLabel,
	     PlatformWideLabelSpace[pLabelEntry->Label -
				    1].BackupForwardingInformation.OutIf,
	     PlatformWideLabelSpace[pLabelEntry->Label -
				    1].BackupForwardingInformation.
	     BypassTunnelsLabel);
	  label = pLabelEntry->Label;
	}
      memset (&PSB_KEY, 0, sizeof (PSB_KEY));
      zlog_info ("\nNot completed Ingress entries:");
      while ((pIngressEntry =
	      patricia_tree_getnext (&pFrrSmEntry->ingress_tree,
				     (const uns8 *) &PSB_KEY)) != NULL)
	{
	  RSVP_TUNNEL_PROPERTIES *pTunnel;
	  RSVP_LSP_PROPERTIES *pRsvpLsp;
	  PSB_KEY rkey;

	  zlog_info ("\nDEST#%x Tunnel#%x Source#%x LSP ID#%x",
		     pIngressEntry->PSB_KEY.Session.Dest,
		     pIngressEntry->PSB_KEY.Session.TunnelId,
		     pIngressEntry->PSB_KEY.Session.ExtTunelId,
		     pIngressEntry->PSB_KEY.sender.Lsp_IdNet);

	  memset (&rkey, 0, sizeof (PSB_KEY));
	  rkey = pIngressEntry->PSB_KEY;
	  rkey.sender.Lsp_IdNet = 0;
	  if (FindTunnel (&rkey, &pTunnel, ALL_TRUNKS) == TRUE)
	    {
	      if ((pRsvpLsp =
		   FindRsvpLspByLspId (pTunnel,
				       pIngressEntry->PSB_KEY.sender.
				       Lsp_IdNet)) != NULL)
		{
		  zlog_info
		    ("\n Bypass label %x Merge node label valid %x Merge node label %x Out I/F %x",
		     pRsvpLsp->forw_info.path.BackupForwardingInformation.
		     BypassTunnelsLabel,
		     pRsvpLsp->forw_info.path.BackupForwardingInformation.
		     MergeNodeLabelValid,
		     pRsvpLsp->forw_info.path.BackupForwardingInformation.
		     MergeNodeLabel,
		     pRsvpLsp->forw_info.path.BackupForwardingInformation.
		     OutIf);
		}
	    }
	  PSB_KEY = pIngressEntry->PSB_KEY;
	}

      if (rdb_get_component_link (((LTCS_CB *) GetLcbPtr ())->rdb_layer_handle, pFrrSmEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
				  pFrrSmEntry->frr_key.OutIfIndex,	/* SAME FOR NOW!!! */
				  &pComponentLink) != E_OK)
	{
	  zlog_err ("\ncannot get component link %s %d", __FILE__, __LINE__);
	  frr_key = pFrrSmEntry->frr_key;
	  continue;
	}
      zlog_info ("\nCompleted Label (LSR) entries:");
      while ((pLabelEntry =
	      patricia_tree_getnext (&pComponentLink->ProtectionTree,
				     (const uns8 *) &label)) != NULL)
	{
	  zlog_info
	    ("\nLabel#%x valid %x merge node label %x Out I/F %x Bypass label %x",
	     pLabelEntry->Label,
	     PlatformWideLabelSpace[pLabelEntry->Label -
				    1].BackupForwardingInformation.
	     MergeNodeLabelValid,
	     PlatformWideLabelSpace[pLabelEntry->Label -
				    1].BackupForwardingInformation.
	     MergeNodeLabel,
	     PlatformWideLabelSpace[pLabelEntry->Label -
				    1].BackupForwardingInformation.OutIf,
	     PlatformWideLabelSpace[pLabelEntry->Label -
				    1].BackupForwardingInformation.
	     BypassTunnelsLabel);
	  label = pLabelEntry->Label;
	}
      memset (&PSB_KEY, 0, sizeof (PSB_KEY));
      zlog_info ("\nCompleted Ingress entries:");
      while ((pIngressEntry =
	      patricia_tree_getnext (&pComponentLink->IngressProtectionTree,
				     (const uns8 *) &PSB_KEY)) != NULL)
	{
	  RSVP_TUNNEL_PROPERTIES *pTunnel;
	  RSVP_LSP_PROPERTIES *pRsvpLsp;
	  PSB_KEY rkey;

	  zlog_info ("\nDEST#%x Tunnel#%x Source#%x LSP ID#%x",
		     pIngressEntry->PSB_KEY.Session.Dest,
		     pIngressEntry->PSB_KEY.Session.TunnelId,
		     pIngressEntry->PSB_KEY.Session.ExtTunelId,
		     pIngressEntry->PSB_KEY.sender.Lsp_IdNet);
	  memset (&rkey, 0, sizeof (PSB_KEY));
	  rkey = pIngressEntry->PSB_KEY;
	  rkey.sender.Lsp_IdNet = 0;
	  if (FindTunnel (&rkey, &pTunnel, ALL_TRUNKS) == TRUE)
	    {
	      if ((pRsvpLsp =
		   FindRsvpLspByLspId (pTunnel,
				       pIngressEntry->PSB_KEY.sender.
				       Lsp_IdNet)) != NULL)
		{
		  zlog_info
		    ("\n Bypass label %x Merge node label valid %x Merge node label %x Out I/F %x",
		     pRsvpLsp->forw_info.path.BackupForwardingInformation.
		     BypassTunnelsLabel,
		     pRsvpLsp->forw_info.path.BackupForwardingInformation.
		     MergeNodeLabelValid,
		     pRsvpLsp->forw_info.path.BackupForwardingInformation.
		     MergeNodeLabel,
		     pRsvpLsp->forw_info.path.BackupForwardingInformation.
		     OutIf);
		}
	    }
	  PSB_KEY = pIngressEntry->PSB_KEY;
	}
      frr_key = pFrrSmEntry->frr_key;
    }
}
