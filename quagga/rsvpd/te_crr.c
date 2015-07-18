/* Module:   constraint_route_resolution.c
   Contains: TE application constraint route resolution
   state machine
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */

#include "te.h"
#include "te_cspf.h"

static E_RC CreateConstraintRouteResReq (SM_T * pSm, int handle);

static uns32 InterAreaConstraintRouteResolution (SM_T * pSm,
						 CONSTRAINT_ROUTE_RESOLUTION_ARGS
						 * args);
static uns32 IntraAreaConstraintRouteResolution (SM_T * pSm,
						 CONSTRAINT_ROUTE_RESOLUTION_ARGS
						 * args);
static uns32 NextHopConstraintRouteResolution (SM_T * pSm,
					       CONSTRAINT_ROUTE_RESOLUTION_ARGS
					       * args);
static uns32 DetermineDestinationType (SM_T * pSm,
				       CONSTRAINT_ROUTE_RESOLUTION_ARGS *
				       args, DESTINATION_TYPE_E * type);
static BOOL OwnTunnel (IPV4_ADDR addr);

static BOOL TunnelsTunnel2BeModified (CONSTRAINT_ROUTE_RESOLUTION_ARGS * args,
				      SM_T * pSm);

static BOOL SummaryAdmissionControl (SUMMARY_PROPERTIES * pSummaryProperties,
				     CONSTRAINT_ROUTE_RESOLUTION_ARGS * args);
static RSVP_TUNNEL_PROPERTIES *FindTunnelByPath (TRUNK_ENTRY * pTrunkEntry,
						 PATH * pPath);

static BOOL SummaryTieBreak (SUMMARY_PROPERTIES * pLeftSummary,
			     PATH * pLeftPath,
			     SUMMARY_PROPERTIES * pRightSummary,
			     PATH * pRightPath, uns8 Priority);
static int SelectAreaBorder (SM_T * pSm, ABRS_L_LIST * pAbrs,
			     CONSTRAINT_ROUTE_RESOLUTION_ARGS * args,
			     ABR ** ppAbr, PATH ** ppPath);
static BOOL PathAdmissionControl (PATH * pPath,
				  CONSTRAINT_ROUTE_RESOLUTION_ARGS * args);

static uns32 GetSharedHopsNumber (PATH * pPath,
				  CONSTRAINT_ROUTE_RESOLUTION_ARGS * args);

static BOOL PathTieBreak (PATH * pLeftPath,
			  PATH * pRigthPath,
			  CONSTRAINT_ROUTE_RESOLUTION_ARGS * args,
			  uns32 * CurrentSharedHopsNumber);

static BOOL LinkAdmissionControl (TE_LINK_PROPERTIES * pTeLinkProperties,
				  COMPONENT_LINK * pComponentLink,
				  CONSTRAINT_ROUTE_RESOLUTION_ARGS * args);

static uns32 DetermineDestinationType (SM_T * pSm,
				       CONSTRAINT_ROUTE_RESOLUTION_ARGS *
				       args, DESTINATION_TYPE_E * type);

static SM_CALL_T *constraint_route_resolution_sm_dynamic_adaptivity (SM_T *
								     pSm,
								     SM_EVENT_T
								     *
								     sm_event);
static SM_CALL_T *constraint_route_resolution_sm_empty_handler (SM_T * pSm,
								SM_EVENT_T *
								sm_data);
static SM_CALL_T *constraint_route_resolution_sm_init (SM_T * pSm,
						       SM_EVENT_T * sm_event);
static void constraint_route_resolution_sm_destroy (SM_T * pSm);

BOOL TunnelsAutoSetup = FALSE;
BOOL DontUsePathCash = FALSE;

void
TunnelsAutoSetupEnable ()
{
  TunnelsAutoSetup = TRUE;
}

void
TunnelsAutoSetupDisable ()
{
  TunnelsAutoSetup = FALSE;
}

CSPF_REQUEST *
CreateCspfRequest (int Dest /* IN */ ,
		   int Priority /* IN */ ,
		   int ExcludeColorMask /* IN */ ,
		   int IncludeAnyColorMask /* IN */ ,
		   int IncludeColorMask /* IN */ ,
		   int HopCountLimit /* IN */ ,
		   float Bw /* IN */ ,
		   int LinkBwCount /* IN */ ,
		   LINK_BW * pLinkBw /* IN */ ,
		   int Hops2AvoidCount /* IN */ ,
		   int *Hops2Avoid /* IN */ ,
		   int Hops2ExcludeCount /* IN */ ,
		   int *Hops2Exclude /* IN */ ,
		   int *Len /* OUT */ ,
		   int **ppMessage)
{
  int size =
    sizeof (CSPF_REQUEST) + LinkBwCount * sizeof (LINK_BW) +
    Hops2AvoidCount * sizeof (int) + Hops2ExcludeCount * sizeof (int) +
    sizeof (int);
  CSPF_REQUEST *pCspfRequest;
  int *pMessage;
  char *pData;

  pMessage = XMALLOC (MTYPE_TE, size);

  if (pMessage == NULL)
    {
      return NULL;
    }
  *pMessage = CSPF_REQ;
  pCspfRequest = (CSPF_REQUEST *) (pMessage + 1);
  pCspfRequest->Destination.s_addr = Dest;
  pCspfRequest->Priority = Priority;
  pCspfRequest->ExcludeColorMask = ExcludeColorMask;
  pCspfRequest->IncludeAnyColorMask = IncludeAnyColorMask;
  pCspfRequest->IncludeColorMask = IncludeColorMask;
  pCspfRequest->HopCountLimit = HopCountLimit;
  pCspfRequest->Bw = Bw;
  pCspfRequest->LinkBwCount = LinkBwCount;
  pCspfRequest->Hops2AvoidCount = Hops2AvoidCount;
  pCspfRequest->Hops2ExcludeCount = Hops2ExcludeCount;
  pCspfRequest->pLinkBw = NULL;
  pCspfRequest->Hops2Avoid = NULL;
  pData = (char *) (pCspfRequest + 1);
  if (LinkBwCount)
    {
      memcpy (pData, pLinkBw, sizeof (LINK_BW) * LinkBwCount);
      pData += sizeof (LINK_BW) * LinkBwCount;
    }
  if (Hops2AvoidCount)
    {
      memcpy (pData, Hops2Avoid, sizeof (int) * Hops2AvoidCount);
      pData += sizeof (int) * Hops2AvoidCount;
    }
  if (Hops2ExcludeCount)
    {
      memcpy (pData, Hops2Exclude, sizeof (int) * Hops2ExcludeCount);
    }
  *Len = size;
  *ppMessage = pMessage;
  return pCspfRequest;
}

void
RegisterClient (int handle, int instance, IPV4_ADDR dest, void *pSm)
{
  CR_CLIENT_NODE *pCrClientNode;
  CR_CLIENT_KEY key;
  zlog_info ("entering RegisterClient");
  key.handle = handle;
  key.instance = instance;

  if ((pCrClientNode =
       (CR_CLIENT_NODE *) patricia_tree_get (&ConstraintRouteResClientsTree,
					     (const uns8 *) &key)) != NULL)
    {
      CR_REQ_NODE *pCrNode;
      CR_REQUESTS_LIST *pCrReqList, *pCrReqListPrev = NULL, *pCrReqList2;
      if ((pCrNode =
	   (CR_REQ_NODE *) patricia_tree_get (&ConstraintRouteResReqTree,
					      (const uns8 *) &pCrClientNode->
					      dest)) != NULL)
	{
	  pCrReqList = pCrNode->pCrReqList;
	  while (pCrReqList != NULL)
	    {
	      if (pCrReqList->pParentSm == (void *) handle)
		{
		  constraint_route_resolution_sm_destroy (pCrReqList->pSm);
		  pCrReqList->pSm = pSm;
		  if (pCrClientNode->dest != dest)
		    {
		      if (pCrReqListPrev == NULL)
			{
			  pCrNode->pCrReqList = pCrNode->pCrReqList->next;
			}
		      else
			{
			  pCrReqListPrev->next = pCrReqList->next;
			}
		      pCrReqList->next = NULL;
		      if (pCrNode->pCrReqList == NULL)
			{
			  patricia_tree_del (&ConstraintRouteResReqTree,
					     &pCrNode->Node);
			  pCrNode->dest = dest;
			  if (patricia_tree_add
			      (&ConstraintRouteResReqTree,
			       &pCrNode->Node) != E_OK)
			    {
			      zlog_err ("Cannot add node to patricia %s %d",
					__FILE__, __LINE__);
			    }
			}
		      if ((pCrReqList2 = pCrNode->pCrReqList) == NULL)
			{
			  pCrNode->pCrReqList = pCrReqList;
			}
		      else
			{
			  while (pCrReqList2->next != NULL)
			    pCrReqList2 = pCrReqList2->next;
			  pCrReqList2->next = pCrReqList;
			}
		    }
		  break;
		}
	      pCrReqListPrev = pCrReqList;
	      pCrReqList = pCrReqList->next;
	    }
	}
      pCrClientNode->dest = dest;
//      pCrClientNode->sm = pSm;
      zlog_info ("leaving RegisterClient1");
      return;
    }

  if ((pCrClientNode =
       (CR_CLIENT_NODE *) XMALLOC (MTYPE_TE,
				   sizeof (CR_CLIENT_NODE))) == NULL)
    {
      zlog_err ("canot allocate memory %s %d", __FILE__, __LINE__);
      return;
    }
  pCrClientNode->Node.key_info = (uns8 *) & pCrClientNode->key;
  pCrClientNode->key = key;
  pCrClientNode->dest = dest;

  if (patricia_tree_add (&ConstraintRouteResClientsTree, &pCrClientNode->Node)
      != E_OK)
    {
      zlog_err ("Cannot add node to patricia %s %d", __FILE__, __LINE__);
    }
  if (CreateConstraintRouteResReq (pSm, handle) != E_OK)
    {
      zlog_err ("cannot create CR request %s %d", __FILE__, __LINE__);
    }
  zlog_info ("leaving RegisterClient2");
}

void
UnregisterClient (int handle, int TunnelId)
{
  CR_CLIENT_NODE *pCrClientNode;
  CR_CLIENT_KEY key;

  zlog_info ("entering UnregisterClient");

  key.handle = handle;
  key.instance = TunnelId;

  if ((pCrClientNode =
       (CR_CLIENT_NODE *) patricia_tree_get (&ConstraintRouteResClientsTree,
					     (const uns8 *) &key)) != NULL)
    {
      CR_REQ_NODE *pCrNode;
      CR_REQUESTS_LIST *pCrReqList, *pCrReqListPrev = NULL;

      if ((pCrNode =
	   (CR_REQ_NODE *) patricia_tree_get (&ConstraintRouteResReqTree,
					      (const uns8 *) &pCrClientNode->
					      dest)) == NULL)
	{
	  zlog_err ("leaving UnregisterClient-");
	  return;
	}

      pCrReqList = pCrNode->pCrReqList;
      while (pCrReqList != NULL)
	{
	  if (pCrReqList->pParentSm == (void *) handle)
	    {
	      if (pCrReqListPrev == NULL)
		{
		  pCrNode->pCrReqList = pCrNode->pCrReqList->next;
		  if (pCrNode->pCrReqList == NULL)
		    {
		      if (patricia_tree_del
			  (&ConstraintRouteResReqTree,
			   &pCrNode->Node) != E_OK)
			{
			  zlog_err ("Cannot delete node from patricia %s %d",
				    __FILE__, __LINE__);
			  return;
			}
		      else
			{
			  XFREE (MTYPE_TE, pCrNode);
			}
		    }
		}
	      else
		{
		  pCrReqListPrev->next = pCrReqList->next;
		}
	      if (patricia_tree_del
		  (&ConstraintRouteResClientsTree,
		   &pCrClientNode->Node) != E_OK)
		{
		  zlog_err ("Cannot delete a node from patricia %s %d",
			    __FILE__, __LINE__);
		  return;
		}
	      constraint_route_resolution_sm_destroy (pCrReqList->pSm);
	      XFREE (MTYPE_TE, pCrReqList);
	      XFREE (MTYPE_TE, pCrClientNode);
	      zlog_info ("leaving UnregisterClient2");
	      return;
	    }
	  pCrReqListPrev = pCrReqList;
	  pCrReqList = pCrReqList->next;
	}
    }
  zlog_info ("leaving UnregisterClient3");
}

int
constraint_route_resolution_sm_cspf_reply (SM_T * pSm)
{
  SM_CALL_T *pCall = NULL;
  SM_EVENT_E event = CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT;
  CONSTRAINT_ROUTE_RESOLUTION_ARGS *pCrArgs =
    ((CONSTRAINT_ROUTE_RESOLUTION_SM_DATA *) pSm->data)->args;

  if (IntraAreaConstraintRouteResolution (pSm, pCrArgs) != E_OK)
    {
      zlog_info ("intra-area constraint route resolution is failed");
      if ((pCall =
	   sm_gen_sync_event_send (pSm->caller, event, pCrArgs)) == NULL)
	{
	  zlog_err ("cannot send sycn event %s %d", __FILE__, __LINE__);
	  constraint_route_resolution_sm_destroy (pSm);
	}
      else
	{
	  constraint_route_resolution_sm_destroy (pSm);
	  sm_call (pCall);
	}
      return 1;
    }
  switch (pCrArgs->rc)
    {
    case OUTPUT_LSP_SETUP_PENDING:
      pSm->state = CONSTAINT_ROUTE_RESOLUTION_SM_ADAPTIVITY_STATE;
      return 0;
    case OUTPUT_EGRESS:
    case OUTPUT_LSP:
    case OUTPUT_NEXT_HOP:
    case OUTPUT_PATH:
      event = CONSTRAINT_ROUTE_RESOLVED_EVENT;
      break;
    case OUTPUT_CAC_FAILED:
    case OUTPUT_UNREACHABLE:
      event = CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT;
      break;
    default:
      zlog_err ("default case %s %d", __FILE__, __LINE__);
      event = CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT;
    }
  if ((pCall = sm_gen_sync_event_send (pSm->caller, event, pCrArgs)) == NULL)
    {
      zlog_err ("cannot send sycn event %s %d", __FILE__, __LINE__);
      return 1;
    }
  sm_call (pCall);
  return (event == CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT);
}

void
CspfReply (IPV4_ADDR dest, void *handle)
{
  CR_REQ_NODE *pCrNode;
  CR_REQUESTS_LIST *pCrReqList, *pCrReqListPrev = NULL, *pCrReqListNew;
  CR_CLIENT_NODE *pCrClientNode;
  CR_CLIENT_KEY key;
  int rc;
  zlog_info ("entering CspfReply");
  if ((pCrNode =
       (CR_REQ_NODE *) patricia_tree_get (&ConstraintRouteResReqTree,
					  (const uns8 *) &dest)) == NULL)
    {
      zlog_info ("leaving CspfReply1 %x", dest);
      return;
    }
  pCrReqList = pCrNode->pCrReqList;

  while (pCrReqList != NULL)
    {
      if (pCrReqList->pSm == handle)
	{
	  CONSTRAINT_ROUTE_RESOLUTION_ARGS *pCrArgs;
	  int TunnelId;
	  SM_T *pSm;
	  pSm = pCrReqList->pSm;
	  pCrArgs =
	    ((CONSTRAINT_ROUTE_RESOLUTION_SM_DATA *) (pSm->data))->args;
	  TunnelId = pCrArgs->PsbKey.Session.TunnelId;
	  constraint_route_resolution_sm_cspf_reply (pSm);
	  //UnregisterClient(pSm->caller,TunnelId);
	  key.handle = (int) pSm->caller;
	  key.instance = TunnelId;
	  if ((pCrClientNode =
	       (CR_CLIENT_NODE *)
	       patricia_tree_get (&ConstraintRouteResClientsTree,
				  (const uns8 *) &key)) != NULL)
	    {
	      if (patricia_tree_del
		  (&ConstraintRouteResClientsTree,
		   &pCrClientNode->Node) != E_OK)
		{
		  zlog_err ("Cannot delete a node from patricia %s %d",
			    __FILE__, __LINE__);
		}
	      else
		{
		  XFREE (MTYPE_TE, pCrClientNode);
		}
	    }
	  else
	    {
	      zlog_err ("Cannot get a node from patricia %s %d", __FILE__,
			__LINE__);
	    }
	  if (pCrReqListPrev == NULL)
	    {
	      pCrNode->pCrReqList = pCrNode->pCrReqList->next;
	      if (pCrNode->pCrReqList == NULL)
		{
		  if (patricia_tree_del
		      (&ConstraintRouteResReqTree, &pCrNode->Node) != E_OK)
		    {
		      zlog_err ("Cannot delete node from patricia %s %d",
				__FILE__, __LINE__);
		    }
		  else
		    {
		      XFREE (MTYPE_TE, pCrNode);
		    }
		  XFREE (MTYPE_TE, pCrReqList);
		  zlog_info ("leaving CspfReply2");
		  return;
		}
	    }
	  else
	    {
	      pCrReqListPrev->next = pCrReqList->next;
	      XFREE (MTYPE_TE, pCrReqList);
	    }
	  break;
	}
      pCrReqListPrev = pCrReqList;
      pCrReqList = pCrReqList->next;
    }

  if (DontUsePathCash)
    {
      return;
    }
  pCrReqListPrev = NULL;
  pCrReqList = pCrNode->pCrReqList;
  rc = 0;
  while (pCrReqList != NULL)
    {
      CONSTRAINT_ROUTE_RESOLUTION_ARGS *pCrArgs;
      int TunnelId;
      SM_T *pSm;
      pSm = pCrReqList->pSm;
      pCrArgs = ((CONSTRAINT_ROUTE_RESOLUTION_SM_DATA *) (pSm->data))->args;
      TunnelId = pCrArgs->PsbKey.Session.TunnelId;
      if ((rc = constraint_route_resolution_sm_cspf_reply (pSm)) == 0)
	{
	  key.handle = (int) pSm->caller;
	  key.instance = TunnelId;
	  //zlog_info("trying to get RouteResClient node (%s %d): handle %x tunnel_id %x sm %x",__FILE__,__LINE__,handle,TunnelId,pSm);
	  if ((pCrClientNode =
	       (CR_CLIENT_NODE *)
	       patricia_tree_get (&ConstraintRouteResClientsTree,
				  (const uns8 *) &key)) != NULL)
	    {
	      if (patricia_tree_del
		  (&ConstraintRouteResClientsTree,
		   &pCrClientNode->Node) != E_OK)
		{
		  zlog_err ("Cannot delete a node from patricia %s %d",
			    __FILE__, __LINE__);
		}
	      else
		{
		  XFREE (MTYPE_TE, pCrClientNode);
		}
	    }
	  else
	    {
	      zlog_err ("Cannot get a node from patricia %s %d", __FILE__,
			__LINE__);
	    }
	  if (pCrReqListPrev == NULL)
	    {
	      pCrNode->pCrReqList = pCrNode->pCrReqList->next;
	    }
	  else
	    {
	      pCrReqListPrev->next = pCrReqList->next;
	    }
	  pCrReqListNew = pCrReqList->next;
	  XFREE (MTYPE_TE, pCrReqList);
	  pCrReqList = pCrReqListNew;
	  if (pCrNode->pCrReqList == NULL)
	    {
	      if (patricia_tree_del
		  (&ConstraintRouteResReqTree, &pCrNode->Node) != E_OK)
		{
		  zlog_err ("Cannot delete node from patricia %s %d",
			    __FILE__, __LINE__);
		}
	      else
		{
		  XFREE (MTYPE_TE, pCrNode);
		}
	      XFREE (MTYPE_TE, pCrReqList);
	      zlog_info ("leaving CspfReply3");
	      return;
	    }
	}
      else
	{
	  pCrReqListPrev = pCrReqList;
	  pCrReqList = pCrReqList->next;
	}
    }
  zlog_info ("leaving CspfReply4");
}

E_RC
CreateConstraintRouteResReq (SM_T * pSm, int handle)
{
  CR_REQ_NODE *pCrNode;
  CR_REQUESTS_LIST *pCrReqList, *pCrReqListNew;
  CONSTRAINT_ROUTE_RESOLUTION_ARGS *pCrArgs;

  zlog_info ("entering CreateConstraintRouteResReq");

  pCrArgs = ((CONSTRAINT_ROUTE_RESOLUTION_SM_DATA *) (pSm->data))->args;

  if ((pCrReqListNew =
       (CR_REQUESTS_LIST *) XMALLOC (MTYPE_TE,
				     sizeof (CR_REQUESTS_LIST))) == NULL)
    {
      zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  pCrReqListNew->pSm = pSm;
  pCrReqListNew->pParentSm = (void *) handle;
  //zlog_info("handle %x tunnel_id %x sm %x",handle,pCrArgs->dest,pSm);
  if ((pCrNode =
       (CR_REQ_NODE *) patricia_tree_get (&ConstraintRouteResReqTree,
					  (const uns8 *) &pCrArgs->dest)) ==
      NULL)
    {
      if ((pCrNode =
	   (CR_REQ_NODE *) XMALLOC (MTYPE_TE, sizeof (CR_REQ_NODE))) == NULL)
	{
	  zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
	  XFREE (MTYPE_TE, pCrReqListNew);
	  return E_ERR;
	}
      pCrNode->dest = pCrArgs->dest;
      pCrNode->Node.key_info = (uns8 *) & pCrNode->dest;
      pCrNode->pCrReqList = pCrReqListNew;
      if (patricia_tree_add (&ConstraintRouteResReqTree, &pCrNode->Node) !=
	  E_OK)
	{
	  zlog_err ("Cannot add node to patricia %s %d", __FILE__, __LINE__);
	  XFREE (MTYPE_TE, pCrReqListNew);
	  XFREE (MTYPE_TE, pCrNode);
	  return E_ERR;
	}
      zlog_info ("leaving CreateConstraintRouteResReq0 %x",
		 ((CONSTRAINT_ROUTE_RESOLUTION_SM_DATA *) (pSm->data))->args);
      return E_OK;
    }
  pCrReqList = pCrNode->pCrReqList;
  if (!pCrReqList)
    {
      pCrNode->pCrReqList = pCrReqListNew;
      zlog_info ("leaving CreateConstraintRouteResReq1 %x",
		 ((CONSTRAINT_ROUTE_RESOLUTION_SM_DATA *) (pSm->data))->args);
      return E_OK;
    }
  while (pCrReqList->next != NULL)
    pCrReqList = pCrReqList->next;
  pCrReqList->next = pCrReqListNew;
  zlog_info ("leaving CreateConstraintRouteResReq2");
  return E_OK;
}

static SM_CALL_T *
constraint_route_resolution_sm_empty_handler (SM_T * pSm,
					      SM_EVENT_T * sm_data)
{
  zlog_err ("\nconstraint_route_resolution_sm_empty_handler, state %d",
	    pSm->state);
  return NULL;
}

static SM_CALL_T *
constraint_route_resolution_sm_init (SM_T * pSm, SM_EVENT_T * sm_event)
{
  SM_CALL_T *pCall = NULL;
  CONSTRAINT_ROUTE_RESOLUTION_ARGS *pCrArgs = NULL;
  DESTINATION_TYPE_E type;
  CSPF_REQUEST *pCspfRequest;
  int Len = 0, *pMessage;
  SM_EVENT_E event = CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT;


  if ((pSm->data =
       (CONSTRAINT_ROUTE_RESOLUTION_SM_DATA *) XMALLOC (MTYPE_TE,
							sizeof
							(CONSTRAINT_ROUTE_RESOLUTION_SM_DATA)))
      == NULL)
    {
      zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
      if ((pCall =
	   sm_gen_sync_event_send (pSm->caller, event, pCrArgs)) == NULL)
	{
	  zlog_err ("cannot send sycn event %s %d", __FILE__, __LINE__);
	  constraint_route_resolution_sm_destroy (pSm);
	  return NULL;
	}
      else
	{
	  constraint_route_resolution_sm_destroy (pSm);
	  return pCall;
	}
    }
  switch (sm_event->event)
    {
    case CONSTRAINT_ROUTE_RESOLUTION_REQ_EVENT:
      sm_gen_event_trace (sm_event->event);
      pCrArgs = sm_event->data;
      if ((!pSm) || (!pSm->data) || (!pCrArgs))
	{
	  printf ("fatal error: %x %x %x %s %d", pSm,
		  (int) ((pSm) ? pSm->data : 0), (int) pCrArgs, __FILE__,
		  __LINE__);
	  exit (0);
	}
      ((CONSTRAINT_ROUTE_RESOLUTION_SM_DATA *) pSm->data)->args = pCrArgs;

      if ((DontUsePathCash) || (pCrArgs->AvoidHopNumber != 0))
	{
	  if ((pCspfRequest = CreateCspfRequest (pCrArgs->dest,
						 pCrArgs->SetupPriority,
						 pCrArgs->ExclColorMask,
						 pCrArgs->InclAnyColorMask,
						 pCrArgs->InclColorMask,
						 pCrArgs->HopCount,
						 pCrArgs->BW,
						 pCrArgs->LinkBwNumber,
						 (LINK_BW *) pCrArgs->pLinkBw,
						 pCrArgs->AvoidHopNumber,
						 pCrArgs->AvoidHopsArray,
						 pCrArgs->ExcludeHopNumber,
						 pCrArgs->ExcludeHopsArray,
						 &Len, &pMessage)) == NULL)
	    {
	      return NULL;
	    }
	  pCspfRequest->handle = pSm;
	  te_send_msg (pMessage, Len);
	  XFREE (MTYPE_TE, pMessage);
	  RegisterClient ((int) pSm->caller,
			  pCrArgs->PsbKey.Session.TunnelId,
			  pCrArgs->dest, pSm);
	  return NULL;
	}

      if (TunnelsTunnel2BeModified (pCrArgs, pSm) == TRUE)
	{
	  pSm->state = CONSTAINT_ROUTE_RESOLUTION_SM_ADAPTIVITY_STATE;
	  return NULL;
	}

      if (DetermineDestinationType (pSm, pCrArgs, &type) != E_OK)
	{
	  zlog_info ("DetermineDestinationType failed...");
	  if ((pCall =
	       sm_gen_sync_event_send (pSm->caller, event, pCrArgs)) == NULL)
	    {
	      zlog_err ("cannot send sycn event %s %d", __FILE__, __LINE__);
	      constraint_route_resolution_sm_destroy (pSm);
	      return NULL;
	    }
	  else
	    {
	      constraint_route_resolution_sm_destroy (pSm);
	      return pCall;
	    }
	}
      switch (type)
	{
	case OUT_OF_AREA_DEST:
	  if (InterAreaConstraintRouteResolution (pSm, pCrArgs) != E_OK)
	    {
	      zlog_info ("inter-area constraint route resolution is failed");
	      if ((pCall =
		   sm_gen_sync_event_send (pSm->caller, event,
					   pCrArgs)) == NULL)
		{
		  zlog_err ("cannot send sycn event %s %d", __FILE__,
			    __LINE__);
		  constraint_route_resolution_sm_destroy (pSm);
		  return NULL;
		}
	      else
		{
		  constraint_route_resolution_sm_destroy (pSm);
		  return pCall;
		}
	    }
	  switch (pCrArgs->rc)
	    {
	    case OUTPUT_LSP_SETUP_PENDING:
	      pSm->state = CONSTAINT_ROUTE_RESOLUTION_SM_ADAPTIVITY_STATE;
	      return NULL;
	    case OUTPUT_EGRESS:
	    case OUTPUT_LSP:
	    case OUTPUT_NEXT_HOP:
	    case OUTPUT_PATH:
	      event = CONSTRAINT_ROUTE_RESOLVED_EVENT;
	      break;
	    case OUTPUT_CAC_FAILED:
	    case OUTPUT_UNREACHABLE:
	      if ((pCspfRequest = CreateCspfRequest (pCrArgs->dest,
						     pCrArgs->SetupPriority,
						     pCrArgs->ExclColorMask,
						     pCrArgs->
						     InclAnyColorMask,
						     pCrArgs->InclColorMask,
						     pCrArgs->HopCount,
						     pCrArgs->BW,
						     pCrArgs->LinkBwNumber,
						     (LINK_BW *) pCrArgs->
						     pLinkBw,
						     pCrArgs->AvoidHopNumber,
						     pCrArgs->AvoidHopsArray,
						     pCrArgs->
						     ExcludeHopNumber,
						     pCrArgs->
						     ExcludeHopsArray, &Len,
						     &pMessage)) == NULL)
		{
		  return NULL;
		}
	      pCspfRequest->handle = pSm;
	      te_send_msg (pMessage, Len);
	      XFREE (MTYPE_TE, pMessage);
	      RegisterClient ((int) pSm->caller,
			      pCrArgs->PsbKey.Session.TunnelId,
			      pCrArgs->dest, pSm);
	      return NULL;
	    default:
	      zlog_err ("default case %s %d", __FILE__, __LINE__);
	      event = CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT;
	    }
	  if ((pCall =
	       sm_gen_sync_event_send (pSm->caller, event, pCrArgs)) == NULL)
	    {
	      zlog_err ("cannot send sycn event %s %d", __FILE__, __LINE__);
	    }
	  break;
	case INTRA_AREA_DEST:
	  if (IntraAreaConstraintRouteResolution (pSm, pCrArgs) != E_OK)
	    {
	      zlog_info ("intra-area constraint route resolution is failed");
	      if ((pCall =
		   sm_gen_sync_event_send (pSm->caller, event,
					   pCrArgs)) == NULL)
		{
		  zlog_err ("cannot send sycn event %s %d", __FILE__,
			    __LINE__);
		  constraint_route_resolution_sm_destroy (pSm);
		  return NULL;
		}
	      else
		{
		  constraint_route_resolution_sm_destroy (pSm);
		  return pCall;
		}
	    }
	  switch (pCrArgs->rc)
	    {
	    case OUTPUT_LSP_SETUP_PENDING:
	      pSm->state = CONSTAINT_ROUTE_RESOLUTION_SM_ADAPTIVITY_STATE;
	      return NULL;
	    case OUTPUT_EGRESS:
	    case OUTPUT_LSP:
	    case OUTPUT_NEXT_HOP:
	    case OUTPUT_PATH:
	      event = CONSTRAINT_ROUTE_RESOLVED_EVENT;
	      break;
	    case OUTPUT_CAC_FAILED:
	    case OUTPUT_UNREACHABLE:
	      if ((pCspfRequest = CreateCspfRequest (pCrArgs->dest,
						     pCrArgs->SetupPriority,
						     pCrArgs->ExclColorMask,
						     pCrArgs->
						     InclAnyColorMask,
						     pCrArgs->InclColorMask,
						     pCrArgs->HopCount,
						     pCrArgs->BW,
						     pCrArgs->LinkBwNumber,
						     (LINK_BW *) pCrArgs->
						     pLinkBw,
						     pCrArgs->AvoidHopNumber,
						     pCrArgs->AvoidHopsArray,
						     pCrArgs->
						     ExcludeHopNumber,
						     pCrArgs->
						     ExcludeHopsArray, &Len,
						     &pMessage)) == NULL)
		{
		  return NULL;
		}
	      pCspfRequest->handle = pSm;
	      te_send_msg (pMessage, Len);
	      XFREE (MTYPE_TE, pMessage);
	      RegisterClient ((int) pSm->caller,
			      pCrArgs->PsbKey.Session.TunnelId,
			      pCrArgs->dest, pSm);
	      return NULL;
	    default:
	      zlog_err ("default case %s %d", __FILE__, __LINE__);
	      event = CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT;
	    }
	  if ((pCall =
	       sm_gen_sync_event_send (pSm->caller, event, pCrArgs)) == NULL)
	    {
	      zlog_err ("cannot send sycn event %s %d", __FILE__, __LINE__);
	    }
	  break;
	case NEXT_HOP_DEST:
	  if (NextHopConstraintRouteResolution (pSm, pCrArgs) != E_OK)
	    {
	      zlog_info ("Next Hop constraint route resolution failed");
	      if ((pCall =
		   sm_gen_sync_event_send (pSm->caller, event,
					   pCrArgs)) == NULL)
		{
		  zlog_err ("cannot send sycn event %s %d", __FILE__,
			    __LINE__);
		  constraint_route_resolution_sm_destroy (pSm);
		  return NULL;
		}
	      else
		{
		  constraint_route_resolution_sm_destroy (pSm);
		  return pCall;
		}
	    }
	  switch (pCrArgs->rc)
	    {
	    case OUTPUT_EGRESS:
	    case OUTPUT_LSP:
	    case OUTPUT_NEXT_HOP:
	    case OUTPUT_PATH:
	      event = CONSTRAINT_ROUTE_RESOLVED_EVENT;
	      break;
	    case OUTPUT_CAC_FAILED:
	    case OUTPUT_UNREACHABLE:
	      event = CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT;
	      break;
	    default:
	      zlog_err ("default case %s %d", __FILE__, __LINE__);
	      event = CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT;
	    }
	  if ((pCall =
	       sm_gen_sync_event_send (pSm->caller, event, pCrArgs)) == NULL)
	    {
	      zlog_err ("cannot send sycn event %s %d", __FILE__, __LINE__);
	    }
	  break;
	case UNKNOWN_DEST:
	  if ((pCspfRequest = CreateCspfRequest (pCrArgs->dest,
						 pCrArgs->SetupPriority,
						 pCrArgs->ExclColorMask,
						 pCrArgs->InclAnyColorMask,
						 pCrArgs->InclColorMask,
						 pCrArgs->HopCount,
						 pCrArgs->BW,
						 pCrArgs->LinkBwNumber,
						 (LINK_BW *) pCrArgs->pLinkBw,
						 pCrArgs->AvoidHopNumber,
						 pCrArgs->AvoidHopsArray,
						 pCrArgs->ExcludeHopNumber,
						 pCrArgs->ExcludeHopsArray,
						 &Len, &pMessage)) == NULL)
	    {
	      return NULL;
	    }
	  pCspfRequest->handle = pSm;
	  te_send_msg (pMessage, Len);
	  XFREE (MTYPE_TE, pMessage);
	  RegisterClient ((int) pSm->caller,
			  pCrArgs->PsbKey.Session.TunnelId,
			  pCrArgs->dest, pSm);
	  return NULL;
	case LOCAL_IF_DEST:
	  pCrArgs->rc = OUTPUT_EGRESS;
	  if ((pCall = sm_gen_sync_event_send (pSm->caller,
					       CONSTRAINT_ROUTE_RESOLVED_EVENT,
					       pCrArgs)) == NULL)
	    {
	      zlog_err ("cannot send sycn event %s %d", __FILE__, __LINE__);
	    }
	  break;
	default:
	  zlog_err ("default case %s %d", __FILE__, __LINE__);
	  if ((pCall = sm_gen_sync_event_send (pSm->caller,
					       CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT,
					       pCrArgs)) == NULL)
	    {
	      zlog_err ("cannot send sycn event %s %d", __FILE__, __LINE__);
	    }
	}
      break;
    default:
      zlog_err ("unexpected event %d %s %d",
		sm_event->event, __FILE__, __LINE__);
    }
  constraint_route_resolution_sm_destroy (pSm);
  return pCall;
}

static SM_CALL_T *
constraint_route_resolution_sm_dynamic_adaptivity (SM_T * pSm,
						   SM_EVENT_T * sm_event)
{
  LSP_SM_REPLY *pLspSmReply = sm_event->data;
  SM_CALL_T *pCall = NULL;
  CONSTRAINT_ROUTE_RESOLUTION_SM_DATA *pCrSmData = pSm->data;
  SM_EVENT_E event = CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT;
  //TUNNEL_KEY_T tunnel_key;

  switch (sm_event->event)
    {
    case INGRESS_LSP_OPERATION_COMPLETE_EVENT:
      sm_gen_event_trace (sm_event->event);
      pCrSmData->args->rc = OUTPUT_LSP;
      pCrSmData->args->data.tunnel.Session.Dest = pLspSmReply->dest;
      pCrSmData->args->data.tunnel.Session.TunnelId = pLspSmReply->tunnel_id;
      pCrSmData->args->data.tunnel.Session.ExtTunelId = rdb_get_router_id ();
      pCrSmData->args->OutNHop = pLspSmReply->dest;

      zlog_info ("\nTUNNELED: Tunnels Dest %x tunnel id %x IfIndex %d",
		 pLspSmReply->dest, pLspSmReply->tunnel_id,
		 pCrSmData->args->OutIf);
      break;
    case INGRESS_LSP_OPERATION_FAILED_EVENT:
      sm_gen_event_trace (sm_event->event);
      pCrSmData->args->rc = OUTPUT_UNREACHABLE;
      break;
    default:
      zlog_err ("\nunexpected event %d %s %d",
		sm_event->event, __FILE__, __LINE__);
    }
  if ((pCall =
       sm_gen_sync_event_send (pSm->caller, event, pCrSmData->args)) == NULL)
    {
      zlog_err ("\ncannot send sycn event %s %d", __FILE__, __LINE__);
    }
  constraint_route_resolution_sm_destroy (pSm);
  return pCall;
}

static SM_CALL_T
  *(*constraint_route_resolution_sm_event_handler
    [CONSTRAINT_ROUTE_RESOLUTION_SM_MAX_STATE]) (SM_T * pSm,
						 SM_EVENT_T * sm_data) =
{
constraint_route_resolution_sm_empty_handler,
    constraint_route_resolution_sm_init,
    constraint_route_resolution_sm_dynamic_adaptivity};

SM_CALL_T *
constraint_route_resolution_sm_handler (SM_T * pSm, SM_EVENT_T * sm_data)
{
  if (sm_data == NULL)
    {
      zlog_err ("\nfatal: sm_data is NULL %s %d", __FILE__, __LINE__);
      return NULL;
    }
  zlog_info ("constraint_route_resolution_sm_handler. state %d", pSm->state);
  if ((pSm->state < INIT_STATE)
      || (pSm->state >= CONSTRAINT_ROUTE_RESOLUTION_SM_MAX_STATE))
    {
      zlog_err ("\nstate is invalid");
      XFREE (MTYPE_TE, sm_data);
      sm_gen_free (pSm);
      return NULL;
    }
  return constraint_route_resolution_sm_event_handler[pSm->state] (pSm,
								   sm_data);
}

SM_CALL_T *
constraint_route_resolution_sm_invoke (SM_T * caller, void *data)
{
  SM_T *pNewSm;
  SM_CALL_T *pEvent;

  pNewSm = sm_gen_alloc (caller, CONSTRAINT_ROUTE_RESOLUTION_SM);
  if (pNewSm == NULL)
    {
      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
      return NULL;
    }
  if ((pEvent = sm_gen_sync_event_send (pNewSm,
					CONSTRAINT_ROUTE_RESOLUTION_REQ_EVENT,
					data)) == NULL)
    {
      zlog_err ("\ncan not invoke sm %s %d", __FILE__, __LINE__);
    }
  return pEvent;
}

static RSVP_TUNNEL_PROPERTIES *
FindTunnelByPath (TRUNK_ENTRY * pTrunkEntry, PATH * pPath)
{
  RSVP_TUNNEL_PROPERTIES *pTunnel = pTrunkEntry->Lsps;
  while (pTunnel != NULL)
    {
      RSVP_LSP_PROPERTIES *pRsvpLsp;
      if ((pRsvpLsp = GetWorkingRsvpLsp (pTunnel)) != NULL)
	{
	  if (PathsEqual (pPath->u.er_hops_l_list,
			  pRsvpLsp->forw_info.path.pErHopsList,
			  (pPath->PathProperties.PathHopCount >=
			   (pRsvpLsp->forw_info.path.HopCount - 1)) ?
			  pRsvpLsp->forw_info.path.HopCount : pPath->
			  PathProperties.PathHopCount) == TRUE)
	    {
	      return pTunnel;
	    }
	}
      pTunnel = pTunnel->next;
    }
  return NULL;
}

static BOOL
SummaryAdmissionControl (SUMMARY_PROPERTIES * pSummaryProperties,
			 CONSTRAINT_ROUTE_RESOLUTION_ARGS * args)
{
  if (pSummaryProperties->SummaryMaxLspBW < args->BW)
    {
      zlog_info ("\nSummaryMaxLspBW#%x < BW#%x",
		 pSummaryProperties->SummaryMaxLspBW, args->BW);
      return FALSE;
    }
  if (pSummaryProperties->SummaryMaxReservableBW < args->BW)
    {
      zlog_info ("\nSummaryMaxReservableBW#%x < BW#%x",
		 pSummaryProperties->SummaryMaxReservableBW, args->BW);
      return FALSE;
    }
  /*
     if(pSummaryProperties->ColorMask & args->ExclColorMask)
     {
     zlog_info("\nColors to be excluded#%x exist#%x",
     args->ExclColorMask,
     pPathProperties->PathColorMask);
     return FALSE;
     }
     if((pSummaryProperties->ColorMask & args->InclColorMask) != args->InclColorMask)
     {
     zlog_info("\nColors to be included#%x don't exist#%x",
     args->InclColorMask,
     pPathProperties->PathColorMask);
     return FALSE;
     }
     if(pSummaryProperties->HopCount > args->HopCount)
     {
     zlog_info("\nHop count#%x is higher#%x",args->HopCount,pPathProperties->PathHopCount);
     return FALSE;
     }
   */
  return TRUE;
}

static BOOL
SummaryTieBreak (SUMMARY_PROPERTIES * pLeftSummary, PATH * pLeftPath,
		 SUMMARY_PROPERTIES * pRightSummary, PATH * pRightPath,
		 uns8 Priority)
{
  float LeftMin, RightMin;
  if ((pLeftSummary->SummaryCost + pLeftPath->PathProperties.PathCost) <
      (pRightSummary->SummaryCost + pRightPath->PathProperties.PathCost))
    {
      return FALSE;
    }

  if ((pLeftSummary->SummaryCost + pLeftPath->PathProperties.PathCost) >
      (pRightSummary->SummaryCost + pRightPath->PathProperties.PathCost))
    {
      return TRUE;
    }

  LeftMin =
    (pLeftSummary->SummaryReservableBW[Priority] <
     pLeftPath->PathProperties.PathReservableBW[Priority]) ? pLeftSummary->
    SummaryReservableBW[Priority] : pLeftPath->PathProperties.
    PathReservableBW[Priority];

  RightMin =
    (pRightSummary->SummaryReservableBW[Priority] <
     pRightPath->PathProperties.PathReservableBW[Priority]) ? pRightSummary->
    SummaryReservableBW[Priority] : pRightPath->PathProperties.
    PathReservableBW[Priority];

  if (LeftMin > RightMin)
    {
      return FALSE;
    }

  if (LeftMin < RightMin)
    {
      return TRUE;
    }

  LeftMin =
    (pLeftSummary->SummaryMaxLspBW <
     pLeftPath->PathProperties.PathMaxLspBW) ? pLeftSummary->
    SummaryMaxLspBW : pLeftPath->PathProperties.PathMaxLspBW;

  RightMin =
    (pRightSummary->SummaryMaxLspBW <
     pRightPath->PathProperties.PathMaxLspBW) ? pRightSummary->
    SummaryMaxLspBW : pRightPath->PathProperties.PathMaxLspBW;
  if (LeftMin > RightMin)
    {
      return FALSE;
    }
  if (LeftMin < RightMin)
    {
      return TRUE;
    }
  return FALSE;
}

static int
SelectAreaBorder (SM_T * pSm,
		  ABRS_L_LIST * pAbrs,
		  CONSTRAINT_ROUTE_RESOLUTION_ARGS * args,
		  ABR ** ppAbr, PATH ** ppPath)
{
  PATH_L_LIST *pPathList = NULL;
  PATH *pPath, *pSelectedPath = NULL;
  ABR *pSelectedAbr = NULL;
  zlog_info ("\ninside of Select AreaBorder...");
  while (pAbrs != NULL)
    {
      SUMMARY_PROPERTIES *pProperties = pAbrs->Abr->SummaryProperties;
      int NumberOfSummaries = pAbrs->Abr->NumberOfSummaries, i;
      zlog_info ("\n#");
      for (i = 0; i < NumberOfSummaries; i++)
	{
	  zlog_info ("\n##");
	  if (pProperties->SummaryPathType == PSC_PATH)
	    {
	      if (SummaryAdmissionControl (pProperties, args) == TRUE)
		{
		  if (IsDestinationIntraArea
		      (pAbrs->Abr->AbrIpAddr, &pPathList) != E_OK)
		    {
		      zlog_err
			("\nsome error in IsDestinationIntraArea %s %d ...",
			 __FILE__, __LINE__);
		      return E_ERR;
		    }
		  else
		    {
		      pPath = NULL;
		      if (SelectPath (pPathList, args, &pPath) != E_OK)
			{
			  pPath = NULL;
			}
		      else if ((pSelectedPath != NULL)
			       && (pSelectedAbr != NULL))
			{
			  if (SummaryTieBreak
			      (pSelectedAbr->SummaryProperties, pSelectedPath,
			       pProperties, pPath,
			       args->SetupPriority) == TRUE)
			    {
			      pSelectedAbr = pAbrs->Abr;
			      pSelectedPath = pPath;
			    }
			}
		      else
			{
			  pSelectedAbr = pAbrs->Abr;
			  pSelectedPath = pPath;
			}
		    }
		}
	    }
	  else
	    {
	      zlog_err ("\ntype %x is not supported",
			pProperties->SummaryPathType);
	    }
	  pProperties++;
	}
      pAbrs = pAbrs->next;
    }
  *ppAbr = pSelectedAbr;
  *ppPath = pSelectedPath;
  return E_OK;
}

static BOOL
PathAdmissionControl (PATH * pPath, CONSTRAINT_ROUTE_RESOLUTION_ARGS * args)
{
  int i, j;
  ER_HOP_L_LIST *er_hop_l_list;
  PATH_PROPERTIES *pPathProperties = &pPath->PathProperties;
  if (pPathProperties->PathMaxLspBW < args->BW)
    {
      zlog_info ("MaxLspBW#%f < BW#%f", pPathProperties->PathMaxLspBW,
		 args->BW);
      return FALSE;
    }
  if (pPathProperties->PathMaxReservableBW < args->BW)
    {
      zlog_info ("MaxReservableBW#%f < BW#%f",
		 pPathProperties->PathMaxReservableBW, args->BW);
      return FALSE;
    }
  if (pPathProperties->PathReservableBW[args->HoldPriority] < args->BW)
    {
      zlog_info ("ReservableBW#%f < BW#%f",
		 pPathProperties->PathReservableBW[args->HoldPriority],
		 args->BW);
      return FALSE;
    }
  if (pPathProperties->PathColorMask & args->ExclColorMask)
    {
      zlog_info ("nColors to be excluded#%x exist#%x",
		 args->ExclColorMask, pPathProperties->PathColorMask);
      return FALSE;
    }
  if ((args->InclAnyColorMask)
      && ((pPathProperties->PathColorMask & args->InclAnyColorMask) == 0))
    {
      return FALSE;
    }
  if ((args->InclColorMask)
      &&
      (((pPathProperties->PathColorMask & args->InclColorMask) ^ args->
	InclColorMask) != 0))
    {
      return FALSE;
    }
  if ((args->HopCount != 0) &&
      (pPathProperties->PathHopCount > args->HopCount))
    {
      zlog_info ("Hop count#%x is higher#%x", args->HopCount,
		 pPathProperties->PathHopCount);
      return FALSE;
    }
  for (er_hop_l_list = pPath->u.er_hops_l_list, i = 0;
       i < (pPathProperties->PathHopCount) && (er_hop_l_list != NULL);
       i++, er_hop_l_list = er_hop_l_list->next)
    {
      IPV4_ADDR router_id = er_hop_l_list->er_hop->local_ip;
      rdb_remote_link_router_id_get (er_hop_l_list->er_hop->local_ip,
				     &router_id);
      for (j = 0; j < args->ExcludeHopNumber; j++)
	{
	  if (args->ExcludeHopsArray[j] == router_id)
	    {
	      return FALSE;
	    }
	}
    }
  return TRUE;
}

static uns32
GetSharedHopsNumber (PATH * pPath, CONSTRAINT_ROUTE_RESOLUTION_ARGS * args)
{
  uns32 SharedHopsNumber = 0, i;
  for (i = 0; i < args->AvoidHopNumber; i++)
    {
      ER_HOP_L_LIST *pErHopsLList = pPath->u.er_hops_l_list;
      while (pErHopsLList != NULL)
	{
	  IPV4_ADDR router_id;
	  /* zlog_info("\nLeft ER HOP %x Right ER HOP %x",
	     pErHopsLList->er_hop->local_ip,
	     args->ExcludeHopsArray[i]); */
	  if (rdb_remote_link_router_id_get
	      (pErHopsLList->er_hop->remote_ip, &router_id) == E_OK)
	    {
	      if (router_id == args->AvoidHopsArray[i])
		{
		  SharedHopsNumber++;
		}
	    }
	  else
	    {
	      SharedHopsNumber++;
	    }
	  pErHopsLList = pErHopsLList->next;
	}
    }
  return SharedHopsNumber;
}

static BOOL
PathTieBreak (PATH * pLeftPath,
	      PATH * pRigthPath,
	      CONSTRAINT_ROUTE_RESOLUTION_ARGS * args,
	      uns32 * CurrentSharedHopsNumber)
{
  uns32 SharedHopsNumber = 0;
  PATH_PROPERTIES *pLeftPathProperties =
    &pLeftPath->PathProperties, *pRightPathProperties =
    &pRigthPath->PathProperties;
  if ((SharedHopsNumber =
       GetSharedHopsNumber (pRigthPath, args)) < *CurrentSharedHopsNumber)
    {
      zlog_info ("Tie break by shared hops");
      *CurrentSharedHopsNumber = SharedHopsNumber;
      return TRUE;
    }
  else if (SharedHopsNumber > *CurrentSharedHopsNumber)
    {
      return FALSE;
    }
  /* if(args->BwPolicy == LEAST_FILL)
     {
     }
     else if(args->BwPolicy == MOST_FILL)
     {
     }
     else
     {
     }
   */
  return RightPathCheaper (pLeftPathProperties, pRightPathProperties,
			   args->SetupPriority);
}

int
SelectPath (PATH_L_LIST * pPaths,
	    CONSTRAINT_ROUTE_RESOLUTION_ARGS * args, PATH ** ppPath)
{
  uns32 OutIf;
  TE_LINK_L_LIST *pTeLinks = NULL;
  uns32 SharedHopsNumber = 0;
  IPV4_ADDR router_id;

  while (pPaths != NULL)
    {
      zlog_info ("\n...");
      if (PathAdmissionControl (pPaths->pPath, args) == TRUE)
	{
	  zlog_info ("looking for first ER hop %x...",
		     pPaths->pPath->u.er_hops_l_list->er_hop->remote_ip);

	  if (rdb_remote_link_router_id_get
	      (pPaths->pPath->u.er_hops_l_list->er_hop->remote_ip,
	       &router_id) != E_OK)
	    {
	      router_id = pPaths->pPath->u.er_hops_l_list->er_hop->remote_ip;
	    }
	  if (IsDestinationNextHop (router_id, &pTeLinks) != E_OK)
	    {
	      zlog_err ("some error in IsDestinationNextHop %s %d ...",
			__FILE__, __LINE__);
	      return E_ERR;
	    }
	  if (pTeLinks != NULL)
	    {
	      zlog_info ("looking for Out IF...");
	      if (SelectOutIf (pTeLinks, &OutIf, args, FALSE) != E_OK)
		{
		  zlog_err ("some error in SelectOutIf %s %d ...", __FILE__,
			    __LINE__);
		  return E_ERR;
		}
	      else if (OutIf != 0xFFFFFFFF)
		{
		  if (*ppPath != NULL)
		    {
		      zlog_info ("Second matching path %x %x %x %x...",
				 SharedHopsNumber, *ppPath, pPaths->pPath,
				 args);
		      if (PathTieBreak
			  (*ppPath, pPaths->pPath, args,
			   &SharedHopsNumber) == TRUE)
			{
			  zlog_info (" Selected %x.", SharedHopsNumber);
			  *ppPath = pPaths->pPath;
			}
		      zlog_info ("After PathTieBreak...");
		    }
		  else
		    {
		      zlog_info ("First matching path...");
		      SharedHopsNumber =
			GetSharedHopsNumber (pPaths->pPath, args);
		      *ppPath = pPaths->pPath;
		    }
		}
	    }
	  else
	    {
	      zlog_info ("there is no TE link...");
	    }
	}
      pPaths = pPaths->next;
    }
  return E_OK;
}

static BOOL
LinkAdmissionControl (TE_LINK_PROPERTIES * pTeLinkProperties,
		      COMPONENT_LINK * pComponentLink,
		      CONSTRAINT_ROUTE_RESOLUTION_ARGS * args)
{
  int reason = 0;
  if (pTeLinkProperties->MaxLspBW < args->BW)
    {
      reason = 1;
    }
  if (pTeLinkProperties->MaxReservableBW < args->BW)
    {
      reason = 2;
    }
  if (pTeLinkProperties->ReservableBW[args->HoldPriority] < args->BW)
    {
      zlog_info ("HoldPrio %x ResBw %d BW %d", args->HoldPriority,
		 pTeLinkProperties->ReservableBW[args->HoldPriority],
		 args->BW);
      reason = 3;
    }
  if ((pTeLinkProperties->color_mask & args->ExclColorMask) != 0)
    {
      reason = 4;
    }
  if ((args->InclAnyColorMask)
      && ((pTeLinkProperties->color_mask & args->InclAnyColorMask) == 0))
    {
      reason = 5;
    }
  if ((args->InclColorMask)
      &&
      (((pTeLinkProperties->color_mask & args->InclColorMask) ^ args->
	InclColorMask) != 0))
    {
      reason = 6;
    }
  if (reason)
    zlog_info ("LinkAdmissionControl failed. Reason %d", reason);
  return (reason) ? FALSE : TRUE;
}

int
SelectOutIf (TE_LINK_L_LIST * pTeLinks,
	     uns32 * OutIf,
	     CONSTRAINT_ROUTE_RESOLUTION_ARGS * args, BOOL PerformAllocation)
{
  COMPONENT_LINK *pComponentLink, *pSelectedComponentLink = NULL;
  TE_LINK *pSelectedTeLink = NULL;
  float ActuallyRequired, LeastActuallyRequired = 0xFFFFFFFF;
  /*FIXME*/ PSB_KEY * owner = &args->PsbKey;
  float BW = args->BW;
  uns8 PreemptedPriority = args->HoldPriority, MostPreemptedPriority = 0;
  ActuallyRequired = BW;
  *OutIf = 0xFFFFFFFF;

  while (pTeLinks != NULL)
    {
      zlog_info ("TE link %x ActuallyRequired %f...",
		 pTeLinks->te_link->te_link_id, BW);
      pComponentLink = pTeLinks->te_link->component_links;
      while (pComponentLink != NULL)
	{
	  if (LinkAdmissionControl
	      (&pTeLinks->te_link->te_link_properties, pComponentLink,
	       args) == FALSE)
	    {
	      pComponentLink = pComponentLink->next;
	      continue;
	    }
	  zlog_info ("trying to calculate BW to be allocated actually...");
	  if (CalcActualAlloc (owner,
			       pTeLinks->te_link->te_link_id,
			       pComponentLink,
			       &ActuallyRequired,
			       args->SetupPriority,
			       args->HoldPriority,
			       &PreemptedPriority) == E_OK)
	    {
	      zlog_info ("Actual BW to be allocated %f PreemptedPriority %x",
			 ActuallyRequired, PreemptedPriority);
	      if (PerformAllocation == TRUE)
		{
		  if ((ActuallyRequired < LeastActuallyRequired) &&
		      (PreemptedPriority >= MostPreemptedPriority))
		    {
		      zlog_info
			("##Actual BW to be allocated %f PreemptedPriority %x",
			 ActuallyRequired, PreemptedPriority);
		      LeastActuallyRequired = ActuallyRequired;
		      MostPreemptedPriority = PreemptedPriority;
		      pSelectedComponentLink = pComponentLink;
		      pSelectedTeLink = pTeLinks->te_link;
		    }
		}
	      else
		{
		  *OutIf = pComponentLink->oifIndex;
		  return E_OK;
		}
	    }
	  pComponentLink = pComponentLink->next;
	}
      pTeLinks = pTeLinks->next;
    }
  if (PerformAllocation == TRUE)
    {
      if ((pSelectedComponentLink != NULL) && (pSelectedTeLink != NULL))
	{
	  zlog_info ("trying to perform allocation...");
	  if (DoPreBwAllocation (owner,
				 pSelectedTeLink->te_link_id,
				 pSelectedComponentLink,
				 ActuallyRequired,
				 args->HoldPriority) != E_OK)
	    {
	      zlog_err ("something wrong %s %d", __FILE__, __LINE__);
	    }
	  else
	    {
	      zlog_info ("Success!!!");
	      *OutIf = pSelectedComponentLink->oifIndex;
	    }
	}
      else
	{
	  *OutIf = 0xFFFFFFFF;
	}
    }
  zlog_info ("inside of %x...", *OutIf);
  return E_OK;
}

static uns32
DetermineDestinationType (SM_T * pSm,
			  CONSTRAINT_ROUTE_RESOLUTION_ARGS * args,
			  DESTINATION_TYPE_E * type)
{
  TE_LINK_L_LIST *pTeLinks = NULL;
  PATH_L_LIST *pPaths = NULL;
  ABRS_L_LIST *pAbrs = NULL;
  uns32 OutIf = 0xFFFFFFFF;
  IPV4_ADDR router_id;

  zlog_info ("Am I the destination? %x", args->dest);
  if (AmIDestination (args->dest, &OutIf) != E_OK)
    {
      zlog_err ("some error in AmIDestination %s %d...", __FILE__, __LINE__);
      return E_ERR;
    }

  if ((OutIf == 0) || (OutIf != 0xFFFFFFFF))
    {
      zlog_info ("\nYes");
      *type = LOCAL_IF_DEST;
      return E_OK;
    }

  zlog_info ("Is destination %x a Next Hop?", args->dest);

  if (rdb_remote_link_router_id_get (args->dest, &router_id) != E_OK)
    {
      router_id = args->dest;
    }

  if (IsDestinationNextHop (router_id, &pTeLinks) != E_OK)
    {
      zlog_err ("some error in IsDestinationNextHop %s %d...", __FILE__,
		__LINE__);
      return E_ERR;
    }
  if (pTeLinks == NULL)
    {
      zlog_info ("Is destination intra-area?");
      if (IsDestinationIntraArea (args->dest, &pPaths) != E_OK)
	{
	  zlog_err ("some error in IsDestinationIntraArea %s %d...", __FILE__,
		    __LINE__);
	  return E_ERR;
	}
      if (pPaths == NULL)
	{
	  zlog_info ("Is destination AS border?");
	  if (IsDestinationASBorder (args->dest, &pAbrs) != E_OK)
	    {
	      zlog_err ("some error in IsDestinationASBorder %s %d...",
			__FILE__, __LINE__);
	      return E_ERR;
	    }
	  if (pAbrs == NULL)
	    {
	      zlog_info
		("Destination seems to be nor Next Hop nor Area Border nor AS Border...");
	      *type = UNKNOWN_DEST;
	    }
	  else
	    {
	      *type = OUT_OF_AREA_DEST;
	    }
	}
      else
	{
	  *type = INTRA_AREA_DEST;
	}
    }
  else
    {
      *type = NEXT_HOP_DEST;
    }
  return E_OK;
}

static uns32
NextHopConstraintRouteResolution (SM_T * pSm,
				  CONSTRAINT_ROUTE_RESOLUTION_ARGS * args)
{
  TE_LINK_L_LIST *pTeLinks = NULL;
  IPV4_ADDR router_id;

  if (rdb_remote_link_router_id_get (args->dest, &router_id) != E_OK)
    {
      router_id = args->dest;
    }

  if (IsDestinationNextHop (router_id, &pTeLinks) != E_OK)
    {
      zlog_err ("some error in IsDestinationNextHop %s %d ...", __FILE__,
		__LINE__);
      return E_ERR;
    }
  if (pTeLinks == NULL)
    {
      zlog_err ("unexpected error: pTeLink == NULL %s %d", __FILE__,
		__LINE__);
      return E_ERR;
    }
  if (SelectOutIf (pTeLinks, &args->OutIf, args, TRUE) != E_OK)
    {
      zlog_err ("error in SelectOutIf %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  if (args->OutIf == 0xFFFFFFFF)
    {
      args->rc = OUTPUT_CAC_FAILED;
    }
  else
    {
      args->OutNHop = args->dest;
      args->rc = OUTPUT_NEXT_HOP;
    }
  return E_OK;
}

static BOOL
OwnTunnel (IPV4_ADDR addr)
{
  return (addr == rdb_get_router_id ());
}

static uns32
IntraAreaConstraintRouteResolution (SM_T * pSm,
				    CONSTRAINT_ROUTE_RESOLUTION_ARGS * args)
{
  PATH_L_LIST *pPaths = NULL;
  PATH *pSelectedPath = NULL;
  TE_LINK_L_LIST *pTeLinks = NULL;
  PSB_KEY PsbKey;
  IPV4_ADDR *pIpAddrArray, router_id;

  if (IsDestinationIntraArea (args->dest, &pPaths) != E_OK)
    {
      zlog_err ("some error in IsDestinationIntraArea %s %d ...", __FILE__,
		__LINE__);
      return E_ERR;
    }
  if (pPaths != NULL)
    {
      if (SelectPath (pPaths, args, &pSelectedPath) != E_OK)
	{
	  zlog_err ("some error in SelectPath %s %d ...", __FILE__, __LINE__);
	  return E_ERR;
	}
      if (pSelectedPath != NULL)
	{
	  ER_HOP_L_LIST *pErHopList = pSelectedPath->u.er_hops_l_list;
	  int i;

	  if ((TunnelsAutoSetup == TRUE) &&
	      (!((args->dest == args->PsbKey.Session.Dest) &&
		 (OwnTunnel (args->PsbKey.Session.ExtTunelId)))))
	    {
	      TRUNK_KEY trunk_key;
	      TRUNK_ENTRY *pTrunkEntry;
	      RSVP_TUNNEL_PROPERTIES *pTunnel;
	      INGRESS_API *pOpenLspParams;
	      SM_CALL_T *pCall;

	      memset (&trunk_key, 0, sizeof (TRUNK_KEY));
	      trunk_key.Dest = args->dest;
	      if ((pTrunkEntry = GetTunnelsTrunk (&trunk_key)) == NULL)
		{
		  if ((pTrunkEntry = NewTunnelsTrunk (&trunk_key)) == NULL)
		    {
		      zlog_err ("cannot create tunnels trunk %s %d", __FILE__,
				__LINE__);
		      return E_ERR;
		    }
		}
	      pTunnel = pTrunkEntry->Lsps;
	      if ((pOpenLspParams = CreateRequest2Signalling (pSelectedPath->destination, 0,	/* Filled below */
							      0, NULL,	/* Filled below */
							      0,	/* Filled below */
							      4, 4,	/* Default */
							      LOCAL_PROTECTION_DESIRED,
							      0, 0,
							      0
							      /* Default for now */
							      )) == NULL)
		{
		  zlog_err ("cannot create request %s %d", __FILE__,
			    __LINE__);
		  return E_ERR;
		}

	      pOpenLspParams->HopNum =
		pSelectedPath->PathProperties.PathHopCount * 2;

	      for (i = 0, pErHopList = pSelectedPath->u.er_hops_l_list;
		   pErHopList != NULL; pErHopList = pErHopList->next)
		{
		  if (i)
		    {
		      pOpenLspParams->Path[i++].IpAddr =
			pErHopList->er_hop->local_ip;
		    }
		  pOpenLspParams->Path[i++].IpAddr =
		    pErHopList->er_hop->remote_ip;
		}
	      args->OutNHop = pOpenLspParams->Path[0].IpAddr;
	      args->tunneled = TRUE;
	      if ((pTunnel =
		   FindTunnelByPath (pTrunkEntry, pSelectedPath)) != NULL)
		{
		  if (CurrentPathHasAvBw (pTunnel, args->BW) != NULL)
		    {
		      pOpenLspParams->TunnelId = pTunnel->TunnelId;
		      pOpenLspParams->BW = pTunnel->RequiredBW + args->BW;
		    }
		  else
		    {
		      memset (&PsbKey, 0, sizeof (PSB_KEY));
		      PsbKey.Session.Dest = pSelectedPath->destination;
		      pOpenLspParams->TunnelId = NewTunnelId (&PsbKey);
		      pOpenLspParams->BW = args->BW;
		    }
		}
	      else
		{
		  memset (&PsbKey, 0, sizeof (PSB_KEY));
		  PsbKey.Session.Dest = pSelectedPath->destination;
		  pOpenLspParams->TunnelId = NewTunnelId (&PsbKey);
		  pOpenLspParams->BW = args->BW;
		}
	      if ((pCall =
		   lsp_sm_sync_invoke (pSm, pOpenLspParams,
				       INGRESS_LSP_REQUEST_EVENT)) == NULL)
		{
		  zlog_err ("cannot invoke lsp sm %s %d", __FILE__, __LINE__);
		  return E_ERR;
		}
	      else
		sm_call (pCall);
	      args->rc = OUTPUT_LSP_SETUP_PENDING;
	      return E_OK;
	    }

	  if (rdb_remote_link_router_id_get
	      (pSelectedPath->u.er_hops_l_list->er_hop->remote_ip,
	       &router_id) != E_OK)
	    {
	      router_id = pSelectedPath->u.er_hops_l_list->er_hop->remote_ip;
	    }

	  if (IsDestinationNextHop (router_id, &pTeLinks) != E_OK)
	    {
	      zlog_err ("some error in IsDestinationNextHop %s %d ...",
			__FILE__, __LINE__);
	      return E_ERR;
	    }
	  if (pTeLinks == NULL)
	    {
	      zlog_err ("unexpected error: pTeLink == NULL %s %d", __FILE__,
			__LINE__);
	      return E_ERR;
	    }

	  args->tunneled = FALSE;

	  if (SelectOutIf (pTeLinks, &args->OutIf, args, TRUE) != E_OK)
	    {
	      zlog_err ("an error in SelectOutIf %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }
	  if (args->OutIf == 0xFFFFFFFF)
	    {
	      args->rc = OUTPUT_CAC_FAILED;
	    }
	  else
	    {
	      if ((pIpAddrArray =
		   (IPV4_ADDR *) XMALLOC (MTYPE_TE,
					  sizeof (IPV4_ADDR) *
					  (pSelectedPath->PathProperties.
					   PathHopCount * 2))) == NULL)
		{
		  zlog_err ("mem_alloc failed %s %d", __FILE__, __LINE__);
		  args->rc = OUTPUT_CAC_FAILED;
		  return E_ERR;
		}
	      for (i = 0, pErHopList = pSelectedPath->u.er_hops_l_list;
		   pErHopList; pErHopList = pErHopList->next)
		{
		  if (i)
		    pIpAddrArray[i++] = pErHopList->er_hop->local_ip;
		  pIpAddrArray[i++] = pErHopList->er_hop->remote_ip;
		}
	      pIpAddrArray[i] = pSelectedPath->destination;
	      args->OutNHop = pIpAddrArray[0];
	      args->data.path.ErHopNumber =
		pSelectedPath->PathProperties.PathHopCount * 2;
	      args->data.path.pErHop = pIpAddrArray;
	      zlog_info ("\nConsRouteResolution ErHopNumber %d pErHop %x",
			 args->data.path.ErHopNumber, args->data.path.pErHop);
	      args->rc = OUTPUT_PATH;
	    }
	}
      else
	{
	  args->rc = OUTPUT_CAC_FAILED;
	}
    }
  return E_OK;
}

static uns32
InterAreaConstraintRouteResolution (SM_T * pSm,
				    CONSTRAINT_ROUTE_RESOLUTION_ARGS * args)
{
  PATH *pPath = NULL;
  ABRS_L_LIST *pAbrs = NULL;
  TE_LINK_L_LIST *pTeLinks = NULL;
  ABR *pAbr = NULL;
  RSVP_TUNNEL_PROPERTIES *pTunnel = NULL;
  IPV4_ADDR *pErHopArray, router_id;
  INGRESS_API *pOpenLspParams;
  PSB_KEY PsbKey;
  SM_CALL_T *pCall;
  ER_HOP_L_LIST *pErHopList;
  int i;

  /* select the existing tunnels */
  if (IsDestinationASBorder (args->dest, &pAbrs) != E_OK)
    {
      zlog_err ("\nsome error in IsDestinationASBorder %s %d...", __FILE__,
		__LINE__);
      return E_ERR;
    }
  if (SelectAreaBorder (pSm, pAbrs, args, &pAbr, &pPath) != E_OK)
    {
      zlog_err ("\nSelectAreaBorders failed...");
      return E_ERR;
    }
  if ((pAbr == NULL) || (pPath == NULL))
    {
      zlog_info ("\nRR failed %s %d", __FILE__, __LINE__);
      args->rc = OUTPUT_UNREACHABLE;
      return E_ERR;
    }
  pErHopList = pPath->u.er_hops_l_list;

  if ((TunnelsAutoSetup == TRUE) &&
      (!((pAbr->AbrIpAddr == args->PsbKey.Session.Dest) &&
	 (OwnTunnel (args->PsbKey.Session.ExtTunelId)))))
    {
      TRUNK_ENTRY *pTrunkEntry;
      TRUNK_KEY trunk_key;

      memset (&trunk_key, 0, sizeof (TRUNK_KEY));
      trunk_key.Dest = pAbr->AbrIpAddr;
      if ((pTrunkEntry = GetTunnelsTrunk (&trunk_key)) == NULL)
	{
	  if ((pTrunkEntry = NewTunnelsTrunk (&trunk_key)) == NULL)
	    {
	      zlog_err ("\ncannot create new tunnels trunk %s %d", __FILE__,
			__LINE__);
	      return E_ERR;
	    }
	}
      if ((pOpenLspParams = CreateRequest2Signalling (pAbr->AbrIpAddr, 0,	/* Filled below */
						      0, NULL,	/* Filled below */
						      0,	/* Filled below */
						      4, 4,	/* Default for now */
						      LOCAL_PROTECTION_DESIRED,
						      0, 0,
						      0 /* Default for now */
						      )) == NULL)
	{
	  zlog_info ("\nmalloc failed %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pOpenLspParams->Egress = pAbr->AbrIpAddr;
      args->tunneled = TRUE;
      if ((pTunnel = FindTunnelByPath (pTrunkEntry, pPath)) != NULL)
	{
	  if (CurrentPathHasAvBw (pTunnel, args->BW) != NULL)
	    {
	      pOpenLspParams->TunnelId = pTunnel->TunnelId;
	      pOpenLspParams->BW = pTunnel->RequiredBW + args->BW;
	    }
	  else
	    {
	      memset (&PsbKey, 0, sizeof (PSB_KEY));
	      PsbKey.Session.Dest = pAbr->AbrIpAddr;
	      pOpenLspParams->TunnelId = NewTunnelId (&PsbKey);
	      pOpenLspParams->BW = args->BW;
	    }
	}
      else
	{
	  memset (&PsbKey, 0, sizeof (PSB_KEY));
	  PsbKey.Session.Dest = pAbr->AbrIpAddr;
	  pOpenLspParams->TunnelId = NewTunnelId (&PsbKey);
	  pOpenLspParams->BW = args->BW;
	}
      if ((pCall =
	   lsp_sm_sync_invoke (pSm, pOpenLspParams,
			       INGRESS_LSP_REQUEST_EVENT)) == NULL)
	{
	  zlog_err ("\ncannot invoke lsp sm %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      else
	sm_call (pCall);
      args->rc = OUTPUT_LSP_SETUP_PENDING;
      return E_OK;
    }
  if (rdb_remote_link_router_id_get
      (pPath->u.er_hops_l_list->er_hop->remote_ip, &router_id) != E_OK)
    {
      router_id = pPath->u.er_hops_l_list->er_hop->remote_ip;
    }
  if (IsDestinationNextHop (router_id, &pTeLinks) != E_OK)
    {
      zlog_err ("\nsome error in IsDestinationNextHop %s %d ...", __FILE__,
		__LINE__);
      return E_ERR;
    }
  if (pTeLinks == NULL)
    {
      zlog_err ("\nunexpected error: pTeLink == NULL %s %d", __FILE__,
		__LINE__);
      return E_ERR;
    }
  if ((pErHopArray =
       (IPV4_ADDR *) XMALLOC (MTYPE_TE,
			      sizeof (IPV4_ADDR) *
			      (pPath->PathProperties.PathHopCount * 2))) ==
      NULL)
    {
      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  args->tunneled = FALSE;
  args->data.path.ErHopNumber = pPath->PathProperties.PathHopCount * 2;

  for (i = 0, pErHopList = pPath->u.er_hops_l_list;
       pErHopList != NULL; pErHopList = pErHopList->next)
    {
      if (i)
	{
	  *(pErHopArray + i) = pErHopList->er_hop->local_ip;
	  i++;
	}
      *(pErHopArray + i) = pErHopList->er_hop->remote_ip;
      i++;
    }

  if (SelectOutIf (pTeLinks, &args->OutIf, args, TRUE) != E_OK)
    {
      zlog_err ("\nerror in SelectOutIf %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  args->data.path.pErHop = pErHopArray;
  args->OutNHop = pPath->u.er_hops_l_list->er_hop->remote_ip;
  args->rc = OUTPUT_PATH;

  return E_OK;
}

static BOOL
TunnelsTunnel2BeModified (CONSTRAINT_ROUTE_RESOLUTION_ARGS * args, SM_T * pSm)
{
  RSVP_TUNNEL_PROPERTIES *pTunnel;
  if (FindTunnel (&args->PsbKey, &pTunnel, ALL_TRUNKS) == TRUE)
    {
      RSVP_LSP_PROPERTIES *pRsvpLsp = GetWorkingRsvpLsp (pTunnel);
      if (pRsvpLsp != NULL)
	{
	  if (pRsvpLsp->tunneled == TRUE)
	    {
	      SM_CALL_T *pCall;
	      INGRESS_API *pOpenLspParams;
	      RSVP_TUNNEL_PROPERTIES *pTunnelsTunnel;
	      if (FindTunnel
		  (&pRsvpLsp->forw_info.tunnel, &pTunnelsTunnel,
		   ALL_TRUNKS) != TRUE)
		{
		  zlog_err ("\ncannot find tunnels tunnel %s %d...", __FILE__,
			    __LINE__);
		  return FALSE;
		}
	      if ((pOpenLspParams = CreateRequest2Signalling (pRsvpLsp->forw_info.tunnel.Session.Dest, pRsvpLsp->forw_info.tunnel.Session.TunnelId, 0, NULL, pTunnelsTunnel->RequiredBW + args->BW, 4, 4,	/* Default for now */
							      LOCAL_PROTECTION_DESIRED,
							      0, 0,
							      0
							      /* Default for now */
							      )) == NULL)
		{
		  zlog_err ("\ncannot create request %s %d", __FILE__,
			    __LINE__);
		  return FALSE;
		}

	      if ((pCall =
		   lsp_sm_sync_invoke (pSm, pOpenLspParams,
				       INGRESS_LSP_REQUEST_EVENT)) == NULL)
		{
		  zlog_err ("\ncannot invoke lsp sm %s %d", __FILE__,
			    __LINE__);
		  return FALSE;
		}
	      else
		{
		  sm_call (pCall);
		  return TRUE;
		}
	    }
	}
    }
  return FALSE;
}

static void
constraint_route_resolution_sm_destroy (SM_T * pSm)
{
  XFREE (MTYPE_TE, pSm->data);
  sm_gen_free (pSm);
}
