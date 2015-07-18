/* Module:   transit_req_sm.c
   Contains: TE application transit PATH message processing
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "te.h"

static SM_CALL_T *transit_req_sm_empty_handler (SM_T * pSm,
						SM_EVENT_T * sm_data);
static SM_CALL_T *transit_req_sm_init (SM_T * pSm, SM_EVENT_T * sm_data);
static SM_CALL_T *transit_req_sm_constraint_route_resolution (SM_T * pSm,
							      SM_EVENT_T *
							      sm_data);
static void TransitReqSmDestroy (SM_T * pSm);

static SM_CALL_T *
transit_req_sm_empty_handler (SM_T * pSm, SM_EVENT_T * sm_data)
{
  zlog_err ("new_transit_req_sm_empty_handler, state %d", pSm->state);
  return NULL;
}

static SM_CALL_T *
transit_req_sm_init (SM_T * pSm, SM_EVENT_T * sm_event)
{
  SM_CALL_T *pCall = NULL;
  TRANSIT_REQ_SM_DATA *pTransitReqSmData = NULL;
  CONSTRAINT_ROUTE_RESOLUTION_ARGS *pCrArgs;
  PATH_NOTIFICATION *pTransitReqParams;

  switch (sm_event->event)
    {
    case TRANSIT_REQ_EVENT:
      sm_gen_event_trace (sm_event->event);

      if ((pTransitReqSmData =
	   (TRANSIT_REQ_SM_DATA *) XMALLOC (MTYPE_TE,
					    sizeof (TRANSIT_REQ_SM_DATA))) ==
	  NULL)
	{
	  zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	  TransitReqSmDestroy (pSm);
	  return NULL;
	}

      pTransitReqSmData->pTransitReqParams = sm_event->data;
      pSm->data = pTransitReqSmData;
      pTransitReqParams = pTransitReqSmData->pTransitReqParams;

      if ((pCrArgs =
	   (CONSTRAINT_ROUTE_RESOLUTION_ARGS *) XMALLOC (MTYPE_TE,
							 sizeof
							 (CONSTRAINT_ROUTE_RESOLUTION_ARGS)))
	  == NULL)
	{
	  zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	  TransitReqSmDestroy (pSm);
	  return NULL;
	}
      pCrArgs->BW = pTransitReqParams->BW;
      zlog_info ("\npCrArgs->BW %d", pCrArgs->BW);
      if (pTransitReqParams->ErHopNumber != 0)
	{
	  zlog_info ("\ndestination %x", pTransitReqParams->ErHops[0]);
	  pCrArgs->dest = pTransitReqParams->ErHops[0];
	}
      else
	{
	  pCrArgs->dest = ntohl (pTransitReqParams->PsbKey.Session.Dest);
	  zlog_info ("\ndestination1 %x",
		     pTransitReqParams->PsbKey.Session.Dest);
	}

      pCrArgs->PsbKey.Session = pTransitReqParams->PsbKey.Session;

      if (pTransitReqParams->RA_Valid == TRUE)
	{
	  zlog_info
	    ("\nSESSION ATTRIBUTES: SetPrio %x HoldPrio %x Shared %x FRR %x LabelRecording %x ExclAny %x InclAny %x InclAll %x",
	     pTransitReqParams->SetupPrio, pTransitReqParams->HoldPrio,
	     pTransitReqParams->SharedExplicit,
	     pTransitReqParams->LocalProtection,
	     pTransitReqParams->LabelRecordingDesired,
	     pTransitReqParams->ExcludeAny, pTransitReqParams->IncludeAny,
	     pTransitReqParams->IncludeAll);
	  pCrArgs->SetupPriority = pTransitReqParams->SetupPrio;
	  pCrArgs->HoldPriority = pTransitReqParams->HoldPrio;
	  pCrArgs->ExclColorMask = pTransitReqParams->ExcludeAny;
	  pCrArgs->InclColorMask = pTransitReqParams->IncludeAny;
	}
      else
	{
	  zlog_info ("\nSESSION ATTRIBUTES: %x %x %x %x %x",
		     pTransitReqParams->SetupPrio,
		     pTransitReqParams->HoldPrio,
		     pTransitReqParams->SharedExplicit,
		     pTransitReqParams->LocalProtection,
		     pTransitReqParams->LocalProtection);
	  pCrArgs->SetupPriority = pTransitReqParams->SetupPrio;
	  pCrArgs->HoldPriority = pTransitReqParams->HoldPrio;
	}

      if ((pCall =
	   (SM_CALL_T *) constraint_route_resolution_sm_invoke (pSm,
								pCrArgs)) ==
	  NULL)
	{
	  zlog_err ("\ncannot invoke constraint route resolution sm");
	  XFREE (MTYPE_TE, pCrArgs);
	  TransitReqSmDestroy (pSm);
	}
      pSm->state = TRANSIT_REQ_SM_CONSTRAINT_ROUTE_RESOLUTION_STATE;
      break;
    default:
      zlog_err ("\nunexpected event %d %s %d",
		sm_event->event, __FILE__, __LINE__);
      TransitReqSmDestroy (pSm);
    }
  return pCall;
}

static SM_CALL_T *
transit_req_sm_constraint_route_resolution (SM_T * pSm, SM_EVENT_T * sm_event)
{
  TRANSIT_REQ_SM_DATA *pTransitReqSmData = NULL;
  CONSTRAINT_ROUTE_RESOLUTION_ARGS *pCrArgs;
  PATH_NOTIFICATION *pTransitReqParams;
  PSB_KEY PsbKey;
  TE_API_MSG dmsg;
  SM_CALL_T *pCall = NULL;
  int i;
  unsigned int label = 0;


  pCrArgs = sm_event->data;

  switch (sm_event->event)
    {
    case CONSTRAINT_ROUTE_RESOLVED_EVENT:
      sm_gen_event_trace (sm_event->event);
      pTransitReqSmData = pSm->data;
      pTransitReqParams = pTransitReqSmData->pTransitReqParams;
      pTransitReqParams->OutIfIndex = pCrArgs->OutIf;
      pTransitReqParams->NextHop = ntohl (pCrArgs->OutNHop);


      if (pCrArgs->rc == OUTPUT_CAC_FAILED)
	{
	  pTransitReqParams->rc = BW_UNAVAIL;
	}
      else if (pCrArgs->rc == OUTPUT_UNREACHABLE)
	{
	  pTransitReqParams->rc = NO_ROUTE;
	}
      else if (pCrArgs->rc == OUTPUT_NEXT_HOP)
	{
	  pTransitReqParams->rc = PATH_PROC_OK;
	}
      else if (pCrArgs->rc == OUTPUT_PATH)
	{
	  /* copy path here */
	  pTransitReqParams->ErHopNumber = pCrArgs->data.path.ErHopNumber;
	  for (i = 0; i < pTransitReqParams->ErHopNumber; i++)
	    {
	      pTransitReqParams->ErHops[i] = pCrArgs->data.path.pErHop[i];
	    }
	  pTransitReqParams->rc = PATH_PROC_OK;
	}
      else if (pCrArgs->rc == OUTPUT_LSP)
	{
	  zlog_info ("\nTunneled %x", pTransitReqParams->ErHopNumber);
	  pTransitReqParams->ErHopNumber = 0;
	  zlog_info ("\nLSP HIERARCHY is not supported currently");
	  XFREE (MTYPE_TE, pCrArgs);
	  TransitReqSmDestroy (pSm);
	  return NULL;
	}
      else
	{
	  zlog_err ("\nunknown RC");
	  XFREE (MTYPE_TE, pCrArgs);
	  TransitReqSmDestroy (pSm);
	  return NULL;
	}

      memset (&PsbKey, 0, sizeof (PSB_KEY));

      PsbKey.Session = pTransitReqParams->PsbKey.Session;

      if (LabelAllocate
	  (&label, ALL_LABELS, &PsbKey,
	   pTransitReqParams->OutIfIndex) != E_OK)
	{
	  zlog_err ("\ncannot allocate label %s %d", __FILE__, __LINE__);
	  pTransitReqParams->Label = 0;
	}
      else
	pTransitReqParams->Label = label;

      dmsg.NotificationType = PATH_MSG_NOTIFICATION;
      memcpy (&dmsg.u.PathNotification,
	      pTransitReqParams, sizeof (PATH_NOTIFICATION));

      te_send_msg (&dmsg, sizeof (TE_API_MSG));
#ifdef FRR_SM_DEFINED
      if (pTransitReqParams)
	{
	  if ((pCrArgs->rc == OUTPUT_PATH) &&
	      (pTransitReqParams->ErHopNumber > 1))
	    {
	      FRR_SM_CALL frr_sm_call;
	      int k;
	      IPV4_ADDR protected_node_router_id = 0, merge_node_router_id =
		0, after_merge_node_router_id = 0;

	      memset (&frr_sm_call, 0, sizeof (FRR_SM_CALL));

	      frr_sm_call.frr_key.OutIfIndex = pTransitReqParams->OutIfIndex;

	      if (rdb_remote_link_router_id_get (pTransitReqParams->NextHop,
						 &protected_node_router_id) !=
		  E_OK)
		{
		  protected_node_router_id = pTransitReqParams->NextHop;
		}
	      frr_sm_call.frr_key.protected_node = protected_node_router_id;
	      for (k = 1; k < pTransitReqParams->ErHopNumber; k++)
		{
		  rdb_remote_link_router_id_get (pTransitReqParams->ErHops[k],
						 &merge_node_router_id);
		  if ((merge_node_router_id != 0) &&
		      (merge_node_router_id != protected_node_router_id))
		    {
		      frr_sm_call.frr_key.merge_node = merge_node_router_id;
		      frr_sm_call.MergeNode = pTransitReqParams->ErHops[k];
		      break;
		    }
		}
	      if (frr_sm_call.frr_key.merge_node == 0)
		{
		  merge_node_router_id =
		    frr_sm_call.frr_key.merge_node =
		    pTransitReqParams->ErHops[1];
		  frr_sm_call.MergeNode = pTransitReqParams->ErHops[1];
		}
	      for (; k < pTransitReqParams->ErHopNumber; k++)
		{
		  rdb_remote_link_router_id_get (pTransitReqParams->ErHops[k],
						 &after_merge_node_router_id);
		  if ((after_merge_node_router_id != 0) &&
		      (after_merge_node_router_id != merge_node_router_id))
		    {
		      frr_sm_call.frr_key.prohibited_penultimate_node =
			after_merge_node_router_id;
		      break;
		    }
		}
	      frr_sm_call.Label = label;

	      PsbKey.SenderTemplate =
		pTransitReqParams->PsbKey.SenderTemplate;
	      frr_sm_call.PsbKey = PsbKey;

	      if ((pCall =
		   fast_reroute_sm_sync_invoke (&frr_sm_call,
						BYPASS_SETUP_REQ_EVENT)) ==
		  NULL)
		{
		  zlog_err ("\ncannot invoke FRR SM %s %d", __FILE__,
			    __LINE__);
		}
	    }
	  else if ((pCrArgs->rc == OUTPUT_NEXT_HOP) &&
		   (pTransitReqParams->ErHopNumber > 1))
	    {
	      FRR_SM_CALL frr_sm_call;
	      int k;
	      IPV4_ADDR protected_node_router_id = 0, merge_node_router_id =
		0, after_merge_node_router_id = 0;

	      memset (&frr_sm_call, 0, sizeof (FRR_SM_CALL));

	      frr_sm_call.frr_key.OutIfIndex = pTransitReqParams->OutIfIndex;

	      if (rdb_remote_link_router_id_get (pTransitReqParams->NextHop,
						 &protected_node_router_id) !=
		  E_OK)
		{
		  protected_node_router_id = pTransitReqParams->NextHop;
		}
	      frr_sm_call.frr_key.protected_node = protected_node_router_id;
	      for (k = 1; k < pTransitReqParams->ErHopNumber; k++)
		{
		  rdb_remote_link_router_id_get (pTransitReqParams->ErHops[k],
						 &merge_node_router_id);
		  if ((merge_node_router_id != 0) &&
		      (merge_node_router_id != protected_node_router_id))
		    {
		      frr_sm_call.frr_key.merge_node = merge_node_router_id;
		      frr_sm_call.MergeNode = pTransitReqParams->ErHops[k];
		      break;
		    }
		}
	      if (frr_sm_call.frr_key.merge_node == 0)
		{
		  merge_node_router_id =
		    frr_sm_call.frr_key.merge_node =
		    pTransitReqParams->ErHops[1];
		  frr_sm_call.MergeNode = pTransitReqParams->ErHops[1];
		}
	      for (; k < pTransitReqParams->ErHopNumber; k++)
		{
		  rdb_remote_link_router_id_get (pTransitReqParams->ErHops[k],
						 &after_merge_node_router_id);
		  if ((after_merge_node_router_id != 0) &&
		      (after_merge_node_router_id != merge_node_router_id))
		    {
		      frr_sm_call.frr_key.prohibited_penultimate_node =
			after_merge_node_router_id;
		      break;
		    }
		}
	      frr_sm_call.Label = label;

	      PsbKey.SenderTemplate =
		pTransitReqParams->PsbKey.SenderTemplate;
	      frr_sm_call.PsbKey = PsbKey;

	      if ((pCall =
		   fast_reroute_sm_sync_invoke (&frr_sm_call,
						BYPASS_SETUP_REQ_EVENT)) ==
		  NULL)
		{
		  zlog_err ("\ncannot invoke FRR SM %s %d", __FILE__,
			    __LINE__);
		}
	    }
	}
#endif
      break;
    case CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT:
      sm_gen_event_trace (sm_event->event);
      pTransitReqSmData = pSm->data;
      pTransitReqParams = pTransitReqSmData->pTransitReqParams;
      pTransitReqParams->ErHopNumber = 0;
      pTransitReqParams->OutIfIndex = 0;
      pTransitReqParams->NextHop = 0;


      pTransitReqParams->rc = NO_ROUTE;

      memset (&PsbKey, 0, sizeof (PSB_KEY));

      PsbKey.Session = pTransitReqParams->PsbKey.Session;

      pTransitReqParams->Label = 0;

      dmsg.NotificationType = PATH_MSG_NOTIFICATION;
      memcpy (&dmsg.u.PathNotification,
	      pTransitReqParams, sizeof (PATH_NOTIFICATION));

      te_send_msg (&dmsg, sizeof (TE_API_MSG));
      break;
    default:
      zlog_err ("\nunexpected event %d %s %d",
		sm_event->event, __FILE__, __LINE__);
    }
  XFREE (MTYPE_TE, pCrArgs);
  TransitReqSmDestroy (pSm);
  zlog_info ("\nExiting SM %x...", pCall);
  return pCall;
}

static SM_CALL_T
  *(*transit_req_sm_event_handler[TRANSIT_REQ_SM_MAX_STATE]) (SM_T * pSm,
							      SM_EVENT_T *
							      sm_data) =
{
transit_req_sm_empty_handler,
    transit_req_sm_init, transit_req_sm_constraint_route_resolution};

SM_CALL_T *
transit_req_sm_handler (SM_T * pSm, SM_EVENT_T * sm_data)
{
  if (sm_data == NULL)
    {
      zlog_err ("\nfatal: sm_data is NULL %s %d", __FILE__, __LINE__);
      return NULL;
    }
  zlog_info ("\ntransit_req_sm_event_handler. state %d\n", pSm->state);
  if ((pSm->state < INIT_STATE) || (pSm->state >= TRANSIT_REQ_SM_MAX_STATE))
    {
      zlog_err ("\nstate is invalid");
      TransitReqSmDestroy (pSm);
      return NULL;
    }
  return transit_req_sm_event_handler[pSm->state] (pSm, sm_data);
}

SM_CALL_T *
transit_req_sm_invoke (HANDLE caller, void *data)
{
  SM_T *pNewSm;
  SM_CALL_T *pEvent;

  pNewSm = sm_gen_alloc ((SM_T *) caller, TRANSIT_LSP_SM);
  if (pNewSm == NULL)
    {
      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
      return NULL;
    }
  if ((pEvent = sm_gen_sync_event_send (pNewSm,
					TRANSIT_REQ_EVENT, data)) == NULL)
    {
      zlog_err ("\ncan not invoke sm %s %d", __FILE__, __LINE__);
    }
  return pEvent;
}

static void
TransitReqSmDestroy (SM_T * pSm)
{
  TRANSIT_REQ_SM_DATA *pTransitReqSmData = pSm->data;
  PATH_NOTIFICATION *pTransitReqParams = pTransitReqSmData->pTransitReqParams;

  if (pTransitReqParams != NULL)
    XFREE (MTYPE_TE, pTransitReqParams);
  if (pTransitReqSmData != NULL)
    XFREE (MTYPE_TE, pTransitReqSmData);
  sm_gen_free (pSm);
}
