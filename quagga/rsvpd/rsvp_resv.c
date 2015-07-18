/* Module:   rsvp_resv.c
   Contains: RSVP RESV, RESV TEAR and RESV ERROR message 
   processing functions.
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "rsvp.h"
#include "thread.h"

uns32 ResvRefreshInterval = 30;	/* sec */
uns32 ResvRefreshMultiple = /*3 */ 12;

extern RSVP_STATISTICS RsvpStatistics;
extern struct thread_master *master;

PATRICIA_TREE ResbTree;

static E_RC ResvRefreshProc (RSB * pRsb,
			     PHOP_RESV_REFRESH_LIST * pPHopResvRefreshList);
static E_RC BuildRRSubObj (FILTER_SPEC_DATA * pFilterSpecData);
static void PrepareAndSendMsg2TE4SE (RSB * pRsb,
				     EFFECTIVE_FLOW * pEffectiveFlow);
static void PrepareAndSendMsg2TE4FF (RSB * pRsb,
				     FILTER_SPEC_DATA * pFilterSpecData);
static void PrepareAndSendBWReleaseMsg2TE (PSB * pPsb, uns8 Priority,
					   uns32 IfIndex, uns8 Shared);
static void PrepareAndSendResvTearNotificationMsg2TE (RSB * pRsb,
						      FILTER_SPEC_OBJ *
						      pFilterSpec);
E_RC StartBlocadeTimer (uns32 time, struct thread **pTimerId, void *data);

RSB *
NewRSB (RSB_KEY * pRsbKey)
{
  RSB *pRsb = NULL;
  if ((pRsb = (RSB *) XMALLOC (MTYPE_RSVP, sizeof (RSB))) != NULL)
    {
      memset (pRsb, 0, sizeof (RSB));
      pRsb->RsbKey = *pRsbKey;
      pRsb->Node.key_info = (uns8 *) & pRsb->RsbKey;
      if (patricia_tree_add (&ResbTree, &pRsb->Node) != E_OK)
	{
	  XFREE (MTYPE_RSVP, pRsb);
	  return NULL;
	}
    }
  RsvpStatistics.NewRsbCount++;
  return pRsb;
}

RSB *
GetNextRSB (RSB_KEY * pRsbKey)
{
  return (RSB *) patricia_tree_getnext (&ResbTree, (const uns8 *) pRsbKey);
}

RSB *
FindRsb (RSB_KEY * pRsbKey)
{
  return (RSB *) patricia_tree_get (&ResbTree, (const uns8 *) pRsbKey);
}

E_RC
RemoveRSB (RSB_KEY * pRsbKey)
{
  RSB *pRsb = (RSB *) patricia_tree_get (&ResbTree, (const uns8 *) pRsbKey);
  if (pRsb == NULL)
    {
      zlog_err ("RSB is not found in patricia %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  return patricia_tree_del (&ResbTree, &pRsb->Node);
}

E_RC
GenerateResvErr4SingleFilterSpec (FILTER_SPEC_DATA * pFilterSpecData,
				  RSB * pRsb,
				  IPV4_ADDR Dest,
				  uns32 OutIfIndex,
				  uns8 ErrCode, uns16 ErrVal)
{
  FILTER_LIST *pFilterList;
  RSVP_PKT RsvpPkt;

  memset (&RsvpPkt, 0, sizeof (RSVP_PKT));
  RsvpPkt.Session = pRsb->RsbKey.Session;
  RsvpPkt.Style = pRsb->OldPacket.Style;
  RsvpPkt.ErrorSpec.IpAddr = GetRouterId ();
  RsvpPkt.ErrorSpec.ErrCode = ErrCode;
  RsvpPkt.ErrorSpec.ErrVal = ErrVal;
  RsvpPkt.SentRsvpHop.LIH = OutIfIndex;
  if (IpAddrGetByIfIndex (OutIfIndex, &RsvpPkt.SentRsvpHop.PHop) != E_OK)
    {
      zlog_err ("Cannot get IP address by IfIndex");
      return E_ERR;
    }
  if ((pFilterList =
       (FILTER_LIST *) XMALLOC (MTYPE_RSVP, sizeof (FILTER_LIST))) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  memset (pFilterList, 0, sizeof (FILTER_LIST));
  pFilterList->pFilterSpecData = pFilterSpecData;
  RsvpPkt.pFilterList = pFilterList;
  if (EncodeAndSendRsvpResvErrMessage (&RsvpPkt, Dest, OutIfIndex, 200) !=
      E_OK)
    {
      zlog_err ("An error on encode/send %s %d", __FILE__, __LINE__);
      XFREE (MTYPE_RSVP, pFilterList);
      return E_ERR;
    }
  XFREE (MTYPE_RSVP, pFilterList);
  return E_OK;
}

E_RC
InitResvProcessing ()
{
  PATRICIA_PARAMS params;
  memset (&params, 0, sizeof (params));

  params.key_size = sizeof (RSB_KEY);

  if (patricia_tree_init (&ResbTree, &params) != E_OK)
    {
      zlog_err ("Cannot initiate patricia tree %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  return E_OK;
}

PHOP_RESV_REFRESH_LIST *
GetOrCreatePHopResvRefreshNode (RSB * pRsb,
				IPV4_ADDR IpAddr, uns32 LIH, uns32 InIfIndex)
{
  PHOP_RESV_REFRESH_LIST *pPHopResvRefreshList =
    pRsb->pPHopResvRefreshList, *pPHopResvRefreshListPrev =
    NULL, *pPHopResvRefreshListNew;

  while (pPHopResvRefreshList != NULL)
    {
      if ((pPHopResvRefreshList->PHop.PHop == IpAddr) &&
	  (pPHopResvRefreshList->PHop.LIH == LIH))
	{
	  return pPHopResvRefreshList;
	}
      pPHopResvRefreshListPrev = pPHopResvRefreshList;
      pPHopResvRefreshList = pPHopResvRefreshList->next;
    }
  if ((pPHopResvRefreshListNew =
       (PHOP_RESV_REFRESH_LIST *) XMALLOC (MTYPE_RSVP,
					   sizeof (PHOP_RESV_REFRESH_LIST)))
      == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return NULL;
    }
  memset (pPHopResvRefreshListNew, 0, sizeof (PHOP_RESV_REFRESH_LIST));
  pPHopResvRefreshListNew->PHop.PHop = IpAddr;
  pPHopResvRefreshListNew->PHop.LIH = LIH;
  pPHopResvRefreshListNew->InIfIndex = InIfIndex;
  pPHopResvRefreshListNew->RefreshValue =
    ResvRefreshInterval + RefreshRandomize (ResvRefreshInterval);
  if (pPHopResvRefreshListPrev == NULL)
    {
      pRsb->pPHopResvRefreshList = pPHopResvRefreshListNew;
    }
  else
    {
      pPHopResvRefreshListPrev->next = pPHopResvRefreshListNew;
      pPHopResvRefreshListNew->next = pPHopResvRefreshList;
    }
  return pPHopResvRefreshListNew;
}

E_RC
DeletePHopResvRefreshList (RSB * pRsb,
			   PHOP_RESV_REFRESH_LIST * pPHopResvRefreshList)
{
  PHOP_RESV_REFRESH_LIST *pPHopResvRefreshList2 =
    pRsb->pPHopResvRefreshList, *pPHopResvRefreshListPrev = NULL;
  zlog_info ("entering DeletePHopResvRefreshList");
  while (pPHopResvRefreshList2 != NULL)
    {
      if (pPHopResvRefreshList2 == pPHopResvRefreshList)
	{
	  if (pPHopResvRefreshListPrev == NULL)
	    {
	      pRsb->pPHopResvRefreshList = pRsb->pPHopResvRefreshList->next;
	    }
	  else
	    {
	      pPHopResvRefreshListPrev->next = pPHopResvRefreshList2->next;
	    }
	  if (pPHopResvRefreshList2->pAddedRro)
	    XFREE (MTYPE_RSVP, pPHopResvRefreshList2->pAddedRro);
	  if (pPHopResvRefreshList2->pSentBuffer)
	    XFREE (MTYPE_RSVP, pPHopResvRefreshList2->pSentBuffer);
	  XFREE (MTYPE_RSVP, pPHopResvRefreshList2);
	  zlog_info ("leaving DeletePHopResvRefreshList+");
	  return E_OK;
	}
      pPHopResvRefreshListPrev = pPHopResvRefreshList2;
      pPHopResvRefreshList2 = pPHopResvRefreshList2->next;
    }
  zlog_info ("leaving DeletePHopResvRefreshList-");
  return E_ERR;
}

EFFECTIVE_FLOW *
GetOrCreateEffectiveFlow (RSB * pRsb, uns32 IfIndex)
{
  EFFECTIVE_FLOW *pEffectiveFlow, *pEffectiveFlowPrev = NULL;
  zlog_info ("entering GetOrCreateEffectiveFlow");
  pEffectiveFlow = pRsb->pEffectiveFlow;
  while (pEffectiveFlow != NULL)
    {
      if (pEffectiveFlow->IfIndex == IfIndex)
	{
	  break;
	}
      pEffectiveFlow = pEffectiveFlow->next;
    }
  if (pEffectiveFlow != NULL)
    {
      zlog_info ("leaving GetOrCreateEffectiveFlow(1)");
      return pEffectiveFlow;
    }
  if ((pEffectiveFlow =
       (EFFECTIVE_FLOW *) XMALLOC (MTYPE_RSVP,
				   sizeof (EFFECTIVE_FLOW))) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return NULL;
    }
  memset (pEffectiveFlow, 0, sizeof (EFFECTIVE_FLOW));
  pEffectiveFlow->IfIndex = IfIndex;
//    pEffectiveFlow->MustBeProcessed = 1;
  if (pEffectiveFlowPrev == NULL)
    {
      pRsb->pEffectiveFlow = pEffectiveFlow;
    }
  else
    {
      pEffectiveFlowPrev->next = pEffectiveFlow;
    }
  zlog_info ("leaving GetOrCreateEffectiveFlow(2)");
  return pEffectiveFlow;
}

E_RC
DeleteEffectiveFlow (RSB * pRsb, EFFECTIVE_FLOW * pEffectiveFlow)
{
  EFFECTIVE_FLOW *pEffectiveFlow2 =
    pRsb->pEffectiveFlow, *pEffectiveFlowPrev = NULL;
  zlog_info ("entering DeleteEffectiveFlow");
  while (pEffectiveFlow2 != NULL)
    {
      if (pEffectiveFlow2 == pEffectiveFlow)
	{
	  if (pEffectiveFlowPrev == NULL)
	    {
	      pRsb->pEffectiveFlow = pRsb->pEffectiveFlow->next;
	    }
	  else
	    {
	      pEffectiveFlowPrev->next = pEffectiveFlow2->next;
	    }
	  XFREE (MTYPE_RSVP, pEffectiveFlow2);
	  zlog_info ("leaving DeleteEffectiveFlow+");
	  return E_OK;
	}
      pEffectiveFlowPrev = pEffectiveFlow2;
      pEffectiveFlow2 = pEffectiveFlow2->next;
    }
  zlog_info ("leaving DeleteEffectiveFlow-");
  return E_ERR;
}

E_RC
DeleteFilterListNode (FILTER_LIST ** ppFilterList,
		      FILTER_SPEC_DATA * pFilterSpecData)
{
  FILTER_LIST *pFilterList, *pFilterListPrev = NULL;
  zlog_info ("entering DeleteFilterListNode");
  if (ppFilterList == NULL)
    {
      return E_OK;
    }
  pFilterList = *ppFilterList;
  while (pFilterList != NULL)
    {
      if (pFilterList->pFilterSpecData == pFilterSpecData)
	{
	  break;
	}
      pFilterListPrev = pFilterList;
      pFilterList = pFilterList->next;
    }
  if (pFilterList == NULL)
    {
      return E_ERR;
    }
  if (pFilterListPrev == NULL)
    {
      *ppFilterList = (*ppFilterList)->next;
    }
  else
    {
      pFilterListPrev->next = pFilterList->next;
    }
  XFREE (MTYPE_RSVP, pFilterList);
  zlog_info ("leaving DeleteFilterListNode");
  return E_OK;
}

E_RC
NewFilterListNode (FILTER_LIST ** ppFilterListHead,
		   FILTER_SPEC_DATA * pFilterSpecData)
{
  FILTER_LIST *pFilterList = *ppFilterListHead, *pFilterListPrev = NULL;
  zlog_info ("entering NewFilterListNode");
  while (pFilterList != NULL)
    {
      if (pFilterList->pFilterSpecData == pFilterSpecData)
	{
	  zlog_err ("Node already exists %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pFilterListPrev = pFilterList;
      pFilterList = pFilterList->next;
    }
  if ((pFilterList =
       (FILTER_LIST *) XMALLOC (MTYPE_RSVP, sizeof (FILTER_LIST))) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  memset (pFilterList, 0, sizeof (FILTER_LIST));
  pFilterList->pFilterSpecData = pFilterSpecData;
  if (pFilterListPrev == NULL)
    {
      *ppFilterListHead = pFilterList;
    }
  else
    {
      pFilterListPrev->next = pFilterList;
    }
  zlog_info ("leaving NewFilterListNode");
  return E_OK;
}


uns8
AdSpecBWGreaterThanTSpecBW (PSB * pPsb)
{
  if (pPsb->OldPacket.SentAdSpec.CType != 0)
    {
      if (pPsb->OldPacket.SentAdSpec.AdSpecGen.PathBW >
	  pPsb->OldPacket.SenderTSpec.PeakDataRate)
	{
	  return TRUE;
	}
    }
  return FALSE;
}

uns8
TSpecGreaterThanFlowSpecGuar (SENDER_TSPEC_OBJ * pSenderTSpec,
			      FLOW_SPEC_OBJ * pFlowSpec)
{
  if (pSenderTSpec->PeakDataRate > pFlowSpec->u.Guar.CtrlLoad.PeakDataRate)
    {
      return TRUE;
    }
  return FALSE;
}

uns8
TSpecGreaterThanFlowSpecCtrl (SENDER_TSPEC_OBJ * pSenderTSpec,
			      FLOW_SPEC_OBJ * pFlowSpec)
{
  if (pSenderTSpec->PeakDataRate > pFlowSpec->u.CtrlLoad.PeakDataRate)
    {
      return TRUE;
    }
  return FALSE;
}

uns8
FlowSpec1GreaterThanFlowSpec2 (FLOW_SPEC_OBJ * pFlowSpec1,
			       FLOW_SPEC_OBJ * pFlowSpec2)
{
  if (pFlowSpec1->ServHdr.ServHdr == FLOW_SPEC_CTRL_LOAD_SERV_NUMBER)
    {
      if (pFlowSpec1->u.CtrlLoad.PeakDataRate >
	  pFlowSpec2->u.CtrlLoad.PeakDataRate)
	{
	  return TRUE;
	}
    }
  else if (pFlowSpec1->ServHdr.ServHdr == FLOW_SPEC_GUAR_SERV_NUMBER)
    {
      if (pFlowSpec1->u.Guar.CtrlLoad.PeakDataRate >
	  pFlowSpec2->u.Guar.CtrlLoad.PeakDataRate)
	{
	  return TRUE;
	}
    }
  return FALSE;
}

void
ComposeFlowSpec (PSB * pPsb, FLOW_SPEC_OBJ * pFilterFlowSpec)
{
  pFilterFlowSpec->MsgHdr.VersionResvd = FLOW_SPEC_MSG_FORMAT;
  pFilterFlowSpec->MsgHdr.MessageLength = FLOW_SPEC_MSG_LENGTH;
  pFilterFlowSpec->ServHdr.ServHdr = FLOW_SPEC_CTRL_LOAD_SERV_NUMBER;	/* temp */
  pFilterFlowSpec->ServHdr.Resvd = 0;
  pFilterFlowSpec->ServHdr.ServLength = FLOW_SPEC_DATA_LENGTH;
  pFilterFlowSpec->ParamHdr.ParamID = FLOW_SPEC_TOCKEN_BUCKET_PARAM_ID;
  pFilterFlowSpec->ParamHdr.ParamFlags = 0;
  pFilterFlowSpec->ParamHdr.ParamLength =
    FLOW_SPEC_TOCKEN_BUCKET_PARAM_LENGTH;
  pFilterFlowSpec->u.CtrlLoad.TockenBucketRate =
    pPsb->OldPacket.SenderTSpec.TockenBucketRate;
  pFilterFlowSpec->u.CtrlLoad.TockenBucketSize =
    pPsb->OldPacket.SenderTSpec.TockenBucketSize;
  pFilterFlowSpec->u.CtrlLoad.PeakDataRate =
    pPsb->OldPacket.SenderTSpec.PeakDataRate;
  pFilterFlowSpec->u.CtrlLoad.MinPolicedUnit =
    pPsb->OldPacket.SenderTSpec.MinPolicedUnit;
  pFilterFlowSpec->u.CtrlLoad.MaxPacketSize =
    pPsb->OldPacket.SenderTSpec.MaxPacketSize;
}

void
CheckAndSetFlowSpecObj (PSB * pPsb, FLOW_SPEC_OBJ * pFilterFlowSpec,
			FLOW_SPEC_OBJ * pEffectiveFlowSpec)
{
  uns8 TSpecSelected = FALSE;

  if (pFilterFlowSpec->ServHdr.ServHdr == FLOW_SPEC_CTRL_LOAD_SERV_NUMBER)
    {
      if (TSpecGreaterThanFlowSpecCtrl
	  (&pPsb->OldPacket.SenderTSpec, pFilterFlowSpec) == FALSE)
	{
	  TSpecSelected = TRUE;
	}
    }
  else if (pFilterFlowSpec->ServHdr.ServHdr == FLOW_SPEC_GUAR_SERV_NUMBER)
    {
      if (TSpecGreaterThanFlowSpecGuar
	  (&pPsb->OldPacket.SenderTSpec, pFilterFlowSpec) == FALSE)
	{
	  TSpecSelected = TRUE;
	}
    }
  if (pEffectiveFlowSpec->ServHdr.ServHdr == 0)
    {
      pEffectiveFlowSpec->MsgHdr.VersionResvd = FLOW_SPEC_MSG_FORMAT;
      pEffectiveFlowSpec->MsgHdr.MessageLength = FLOW_SPEC_MSG_LENGTH;
      pEffectiveFlowSpec->ServHdr.ServHdr = pFilterFlowSpec->ServHdr.ServHdr;	/* temp */
      pEffectiveFlowSpec->ServHdr.Resvd = 0;
      pEffectiveFlowSpec->ServHdr.ServLength = FLOW_SPEC_DATA_LENGTH;
      pEffectiveFlowSpec->ParamHdr.ParamID = FLOW_SPEC_TOCKEN_BUCKET_PARAM_ID;
      pEffectiveFlowSpec->ParamHdr.ParamFlags = 0;
      pEffectiveFlowSpec->ParamHdr.ParamLength =
	FLOW_SPEC_TOCKEN_BUCKET_PARAM_LENGTH;
    }
  if (TSpecSelected)
    {
      if (pEffectiveFlowSpec->ServHdr.ServHdr ==
	  FLOW_SPEC_CTRL_LOAD_SERV_NUMBER)
	{
	  if (TSpecGreaterThanFlowSpecCtrl
	      (&pPsb->OldPacket.SenderTSpec, pEffectiveFlowSpec) == TRUE)
	    {
	      pEffectiveFlowSpec->u.CtrlLoad.MaxPacketSize =
		pPsb->OldPacket.SenderTSpec.MaxPacketSize;
	      pEffectiveFlowSpec->u.CtrlLoad.MinPolicedUnit =
		pPsb->OldPacket.SenderTSpec.MinPolicedUnit;
	      pEffectiveFlowSpec->u.CtrlLoad.PeakDataRate =
		pPsb->OldPacket.SenderTSpec.PeakDataRate;
	      pEffectiveFlowSpec->u.CtrlLoad.TockenBucketRate =
		pPsb->OldPacket.SenderTSpec.TockenBucketRate;
	      pEffectiveFlowSpec->u.CtrlLoad.TockenBucketSize =
		pPsb->OldPacket.SenderTSpec.TockenBucketSize;
	    }
	}
      else if (pEffectiveFlowSpec->ServHdr.ServHdr ==
	       FLOW_SPEC_GUAR_SERV_NUMBER)
	{
	  if (TSpecGreaterThanFlowSpecGuar
	      (&pPsb->OldPacket.SenderTSpec, pEffectiveFlowSpec) == TRUE)
	    {
	      pEffectiveFlowSpec->u.Guar.CtrlLoad.MaxPacketSize =
		pPsb->OldPacket.SenderTSpec.MaxPacketSize;
	      pEffectiveFlowSpec->u.Guar.CtrlLoad.MinPolicedUnit =
		pPsb->OldPacket.SenderTSpec.MinPolicedUnit;
	      pEffectiveFlowSpec->u.Guar.CtrlLoad.PeakDataRate =
		pPsb->OldPacket.SenderTSpec.PeakDataRate;
	      pEffectiveFlowSpec->u.Guar.CtrlLoad.TockenBucketRate =
		pPsb->OldPacket.SenderTSpec.TockenBucketRate;
	      pEffectiveFlowSpec->u.Guar.CtrlLoad.TockenBucketSize =
		pPsb->OldPacket.SenderTSpec.TockenBucketSize;
	    }
	}
    }
  else
    {
      if (FlowSpec1GreaterThanFlowSpec2 (pEffectiveFlowSpec, pFilterFlowSpec)
	  == FALSE)
	{
	  *pEffectiveFlowSpec = *pFilterFlowSpec;
	}
    }
}

static int
BlocadeTimerExpiry (struct thread *thread)
{
  FILTER_SPEC_DATA *pFilterSpecData = THREAD_ARG (thread);
  memset (&pFilterSpecData->BlocadeTimer, 0, sizeof (struct thread *));
  pFilterSpecData->Blocked = FALSE;
  if ((pFilterSpecData->pPsb->pRsb->OldPacket.Style.OptionVector2 & 0x001F) ==
      SE_STYLE_BITS)
    {
      if (ProcessEffectiveFlows (pFilterSpecData->pPsb->pRsb) != E_OK)
	{
	  zlog_err ("An error on ProcessEffectiveFlows");
	}
    }
  else
    {
      if (pFilterSpecData->pPsb->TE_InProcess == TRUE)
	{
	  if (StartBlocadeTimer
	      (1, &pFilterSpecData->BlocadeTimer, pFilterSpecData) != E_OK)
	    {
	      zlog_info ("Cannot run Blocade Timer %s %d", __FILE__,
			 __LINE__);
	    }
	  return;
	}
      zlog_info ("Locking Flow %x %x %x %x %x %s %d",
		 pFilterSpecData->pPsb->pRsb->RsbKey.Session.Dest,
		 pFilterSpecData->pPsb->pRsb->RsbKey.Session.TunnelId,
		 pFilterSpecData->pPsb->pRsb->RsbKey.Session.ExtTunelId,
		 pFilterSpecData->FilterSpec.IpAddr,
		 pFilterSpecData->FilterSpec.LspId, __FILE__, __LINE__);
      pFilterSpecData->pPsb->TE_InProcess = TRUE;
      PrepareAndSendMsg2TE4FF (pFilterSpecData->pPsb->pRsb, pFilterSpecData);
    }
}

static int
FilterAgeOut (struct thread *thread)
{
  FILTER_SPEC_DATA *pFilterSpecData = THREAD_ARG (thread);
  RSB *pRsb;
  PSB *pPsb;
  uns8 Shared = 0;

  zlog_info ("entering FilterAgeOut");
  if (pFilterSpecData == NULL)
    {
      zlog_err ("pFilterSpecData == NULL %s %d", __FILE__, __LINE__);
      return;
    }
  memset (&pFilterSpecData->AgeOutTimer, 0, sizeof (struct thread *));
  if (pFilterSpecData->pPsb == NULL)
    {
      zlog_err ("pFilterSpecData->pPsb == NULL %s %d", __FILE__, __LINE__);
      return;
    }
  if ((pRsb = pFilterSpecData->pPsb->pRsb) == NULL)
    {
      zlog_err ("pFilterSpecData->pPsb->pRsb == NULL %s %d", __FILE__,
		__LINE__);
      return;
    }
  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x Src %x LspId %x",
	     pFilterSpecData->pPsb->pRsb->RsbKey.Session.Dest,
	     pFilterSpecData->pPsb->pRsb->RsbKey.Session.TunnelId,
	     pFilterSpecData->pPsb->pRsb->RsbKey.Session.ExtTunelId,
	     pFilterSpecData->FilterSpec.IpAddr,
	     pFilterSpecData->FilterSpec.LspId);
  if ((pRsb->OldPacket.Style.OptionVector2 & 0x001F) == SE_STYLE_BITS)
    {
      Shared = 1;
    }
  if (DeleteFilterListNode (&pRsb->OldPacket.pFilterList, pFilterSpecData) !=
      E_OK)
    {
      zlog_err ("Cannot delete filter from RSB's filter list %s %d", __FILE__,
		__LINE__);
      return;
    }
  pPsb = pFilterSpecData->pPsb;
  if (FilterShutDown (pFilterSpecData, Shared) != E_OK)
    {
      zlog_err ("An error in FilterShutDown %s %d", __FILE__, __LINE__);
      return;
    }
  if (pRsb->OldPacket.pFilterList != NULL)
    {
      if (Shared)
	{
	  if (ProcessEffectiveFlows (pRsb) != E_OK)
	    {
	      zlog_err ("An error in ProcessEffectiveFlows %s %d", __FILE__,
			__LINE__);
	    }
	}
      /* update TE (BW release) */
      if (ProcessPHopFilterSpecLists (pRsb, Shared) != E_OK)
	{
	  zlog_err ("An error in ProcessPHopFilterSpecLists %s %d", __FILE__,
		    __LINE__);
	}
    }
  else
    {
      FreeRSB (pRsb);
    }
  RsvpStatistics.FilterAgeOutCount++;
  zlog_info ("leaving FilterAgeOut");
}

static int
PHopResvRefreshTimeOut (struct thread *thread)
{
  PHOP_RESV_REFRESH_LIST *pPhopResvRefreshList = THREAD_ARG (thread);
  FILTER_LIST *pFilterList;
  FILTER_SPEC_DATA *pFilterSpecData;
  RSB *pRsb;
  zlog_info ("entering PHopResvRefreshTimeOut");
  if (pPhopResvRefreshList == NULL)
    {
      zlog_err ("pPhopResvRefreshList == NULL %s %d", __FILE__, __LINE__);
      zlog_info ("leaving PHopResvRefreshTimeOut-");
      return;
    }
  pFilterList = pPhopResvRefreshList->pFilterList;
  memset (&pPhopResvRefreshList->ResvRefreshTimer, 0,
	  sizeof (struct thread *));
  if (pFilterList == NULL)
    {
      zlog_err ("pFilterList == NULL!!! %s %d", __FILE__, __LINE__);
      return;
    }
  if ((pFilterSpecData = pFilterList->pFilterSpecData) == NULL)
    {
      zlog_err ("pFilterSpecData == NULL!!! %s %d", __FILE__, __LINE__);
      return;
    }
  if (pFilterSpecData->pPsb == NULL)
    {
      zlog_err ("pFilterSpecData->pPsb == NULL!!! %s %d", __FILE__, __LINE__);
      return;
    }
  if ((pRsb = pFilterSpecData->pPsb->pRsb) == NULL)
    {
      zlog_err ("pFilterSpecData->pPsb->pRsb == NULL!!! %s %d", __FILE__,
		__LINE__);
      return;
    }
  if (ResvRefreshProc (pRsb, pPhopResvRefreshList) != E_OK)
    {
      zlog_err ("An error on ResvRefreshProc %s %d", __FILE__, __LINE__);
    }
  zlog_info ("leaving PHopResvRefreshTimeOut+");
}

E_RC
StartPHopResvRefreshTimer (uns32 time, struct thread **pTimerId, void *data)
{
  zlog_info ("entering StartPHopResvRefreshTimer");
  *pTimerId = thread_add_timer (master, PHopResvRefreshTimeOut, data, time);
  zlog_info ("leaving StartPHopResvRefreshTimer");
  return E_OK;
}

E_RC
StopPHopResvRefreshTimer (struct thread * *pTimerId)
{
  zlog_info ("entering StopPHopResvRefreshTimer");
  thread_cancel (*pTimerId);
  *pTimerId = NULL;
  zlog_info ("leaving StopPHopResvRefreshTimer");
  return E_OK;
}

E_RC
StartFilterAgeOutTimer (uns32 time, struct thread * *pTimerId, void *data)
{
  zlog_info ("entering StartFilterAgeOutTimer");
  *pTimerId = thread_add_timer (master, FilterAgeOut, data, time);
  zlog_info ("leaving StartFilterAgeOutTimer");
  return E_OK;
}

E_RC
StopFilterAgeOutTimer (struct thread * *pTimerId)
{
  zlog_info ("entering StopFilterAgeOutTimer");
  thread_cancel (*pTimerId);
  *pTimerId = NULL;
  zlog_info ("leaving StopFilterAgeOutTimer");
  return E_OK;
}

E_RC
StartBlocadeTimer (uns32 time, struct thread * *pTimerId, void *data)
{
  zlog_info ("entering StartBlocadeTimer");
  *pTimerId = thread_add_timer (master, BlocadeTimerExpiry, data, time);
  zlog_info ("leaving StartBlocadeTimer");
  return E_OK;
}

E_RC
StopBlocadeTimer (struct thread * *pTimerId)
{
  zlog_info ("entering StopBlocadeTimer");
  thread_cancel (*pTimerId);
  *pTimerId = NULL;
  zlog_info ("leaving StopBlocadeTimer");
  return E_OK;
}

static E_RC
ResvRefreshProc (RSB * pRsb, PHOP_RESV_REFRESH_LIST * pPHopResvRefreshList)
{
  RSVP_PKT RsvpPkt;
  zlog_info ("entering ResvRefreshProc");
  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x",
	     pRsb->RsbKey.Session.Dest,
	     pRsb->RsbKey.Session.TunnelId, pRsb->RsbKey.Session.ExtTunelId);
  if (pPHopResvRefreshList == NULL)
    {
      zlog_err ("ResvRefreshProc: pPHopResvRefreshList is NULL");
      return E_ERR;
    }
  if ((pPHopResvRefreshList->pSentBuffer == NULL) ||
      (pPHopResvRefreshList->SentBufferLen == 0))
    {
      memset (&RsvpPkt, 0, sizeof (RSVP_PKT));
      RsvpPkt.Session = pRsb->RsbKey.Session;
      RsvpPkt.TimeValues.TimeValues = ResvRefreshInterval * 1000;
      RsvpPkt.SentRsvpHop.LIH = pPHopResvRefreshList->PHop.LIH;
      RsvpPkt.Style = pRsb->OldPacket.Style;
      RsvpPkt.pFilterList = pPHopResvRefreshList->pFilterList;

      if (IpAddrGetByIfIndex
	  (pPHopResvRefreshList->InIfIndex,
	   &RsvpPkt.SentRsvpHop.PHop) != E_OK)
	{
	  zlog_err ("Cannot set RSVP HOP %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}

      RsvpPkt.AddedRro.rr = pPHopResvRefreshList->pAddedRro;

      if (EncodeAndSendRsvpResvMessage (&RsvpPkt,
					ntohl (pPHopResvRefreshList->PHop.
					       PHop),
					pPHopResvRefreshList->InIfIndex, 255,
					&pPHopResvRefreshList->pSentBuffer,
					&pPHopResvRefreshList->
					SentBufferLen) != E_OK)
	{
	  zlog_err ("Cannot encode or send RESV message");
	  return E_ERR;
	}
    }
  else
    {
      if (SendRawData (pPHopResvRefreshList->pSentBuffer,
		       pPHopResvRefreshList->SentBufferLen,
		       ntohl (pPHopResvRefreshList->PHop.PHop),
		       pPHopResvRefreshList->pFilterList->pFilterSpecData->
		       pPsb->InIfIndex, 2, FALSE) != E_OK)
	{
	  zlog_err ("Cannot send raw data %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
    }
  if (StopPHopResvRefreshTimer (&pPHopResvRefreshList->ResvRefreshTimer) !=
      E_OK)
    {
      zlog_err ("Cannot stop PHopResvRefreshTimer %s %d", __FILE__, __LINE__);
      return E_ERR;
    }

  if (StartPHopResvRefreshTimer (pPHopResvRefreshList->RefreshValue,
				 &pPHopResvRefreshList->ResvRefreshTimer,
				 pPHopResvRefreshList) != E_OK)
    {
      zlog_err ("Cannot start timer %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  zlog_info ("leaving ResvRefreshProc");
  return E_OK;
}


E_RC
LinkFilter2PHopList (FILTER_SPEC_DATA * pFilterSpecData)
{
  PSB *pPsb;
  RSB *pRsb;
  uns8 AddRro = FALSE;

  pPsb = pFilterSpecData->pPsb;
  pRsb = pPsb->pRsb;

  if (((pFilterSpecData->pPHopResvRefreshList != NULL) &&
       (!((pFilterSpecData->pPHopResvRefreshList->PHop.PHop ==
	   pPsb->OldPacket.ReceivedRsvpHop.PHop)
	  && (pFilterSpecData->pPHopResvRefreshList->PHop.LIH ==
	      pPsb->OldPacket.ReceivedRsvpHop.LIH))))
      || (pFilterSpecData->pPHopResvRefreshList == NULL))
    {
      if (pFilterSpecData->pPHopResvRefreshList != NULL)
	{
	  if (DeleteFilterListNode
	      (&pFilterSpecData->pPHopResvRefreshList->pFilterList,
	       pFilterSpecData) != E_OK)
	    {
	      zlog_err ("Cannot delete filter list node %s %d", __FILE__,
			__LINE__);
	      return E_ERR;
	    }
	  pFilterSpecData->pPHopResvRefreshList->MustBeProcessed = 1;
	  if (pFilterSpecData->pPHopResvRefreshList->pSentBuffer != NULL)
	    {
	      XFREE (MTYPE_RSVP,
		     pFilterSpecData->pPHopResvRefreshList->pSentBuffer);
	      pFilterSpecData->pPHopResvRefreshList->pSentBuffer = NULL;
	      pFilterSpecData->pPHopResvRefreshList->SentBufferLen = 0;
	    }
	}
      if ((pFilterSpecData->pPHopResvRefreshList =
	   GetOrCreatePHopResvRefreshNode (pRsb,
					   pPsb->OldPacket.ReceivedRsvpHop.
					   PHop,
					   pPsb->OldPacket.ReceivedRsvpHop.
					   LIH, pPsb->InIfIndex)) == NULL)
	{
	  zlog_err ("Cannot create or get PHOP RESV refresh node");
	  return E_ERR;
	}
      pFilterSpecData->pPHopResvRefreshList->MustBeProcessed = 1;
      if (pFilterSpecData->pPHopResvRefreshList->pSentBuffer != NULL)
	{
	  XFREE (MTYPE_RSVP,
		 pFilterSpecData->pPHopResvRefreshList->pSentBuffer);
	  pFilterSpecData->pPHopResvRefreshList->pSentBuffer = NULL;
	  pFilterSpecData->pPHopResvRefreshList->SentBufferLen = 0;
	}
      if (NewFilterListNode
	  (&pFilterSpecData->pPHopResvRefreshList->pFilterList,
	   pFilterSpecData) != E_OK)
	{
	  zlog_err ("Cannot create new FILTER LIST node");
	  return E_ERR;
	}
      if (pPsb->OutIfIndex == 0)
	{
	  if (pPsb->OldPacket.ReceivedRro.rr != NULL)
	    {
	      AddRro = TRUE;
	    }
	}
      else
	{
	  if (pFilterSpecData->Rro.rr != NULL)
	    {
	      AddRro = TRUE;
	    }
	}
      if (AddRro)
	{
	  if (BuildRRSubObj (pFilterSpecData) != E_OK)
	    {
	      zlog_err ("an error on BuildRRSubObj %s %d", __FILE__,
			__LINE__);
	    }
	}
    }
  return E_OK;
}

E_RC
NewModifiedPath (PSB * pPsb)
{
  uns8 Shared = 0;
  RSB *pRsb;
  RSB_KEY RsbKey;
  FILTER_LIST *pFilterList, *pFilterListPrev = NULL;
  FILTER_SPEC_DATA *pFilterSpecData;

  memset (&RsbKey, 0, sizeof (RSB_KEY));
  RsbKey.Session = pPsb->PsbKey.Session;

  /* First - get or create RSB */
  if ((pRsb = FindRsb (&RsbKey)) == NULL)
    {
      if ((pRsb = NewRSB (&RsbKey)) == NULL)
	{
	  zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pRsb->OldPacket.Session = RsbKey.Session;
    }
  pFilterList = pRsb->OldPacket.pFilterList;

  /* second - get or create filter list node */
  while (pFilterList != NULL)
    {
      if (pFilterList->pFilterSpecData != NULL)
	{
	  if ((pFilterList->pFilterSpecData->FilterSpec.IpAddr ==
	       pPsb->PsbKey.SenderTemplate.IpAddr)
	      && (pFilterList->pFilterSpecData->FilterSpec.LspId ==
		  pPsb->PsbKey.SenderTemplate.LspId))
	    {
	      break;
	    }
	}
      else
	{
	  zlog_warn
	    ("Warning!!! pFilterList->pFilterSpecData is NULL while node is in the list");
	}
      pFilterListPrev = pFilterList;
      pFilterList = pFilterList->next;
    }

  /* create new, if required */
  if (pFilterList == NULL)
    {
      if ((pFilterList =
	   (FILTER_LIST *) XMALLOC (MTYPE_RSVP,
				    sizeof (FILTER_LIST))) == NULL)
	{
	  zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	}
      memset (pFilterList, 0, sizeof (FILTER_LIST));
      if ((pFilterList->pFilterSpecData =
	   (FILTER_SPEC_DATA *) XMALLOC (MTYPE_RSVP,
					 sizeof (FILTER_SPEC_DATA))) == NULL)
	{
	  zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	  XFREE (MTYPE_RSVP, pFilterList);
	  return E_ERR;
	}
      memset (pFilterList->pFilterSpecData, 0, sizeof (FILTER_SPEC_DATA));
      pFilterList->pFilterSpecData->FilterSpec.IpAddr =
	pPsb->PsbKey.SenderTemplate.IpAddr;
      pFilterList->pFilterSpecData->FilterSpec.LspId =
	pPsb->PsbKey.SenderTemplate.LspId;
      pFilterList->pFilterSpecData->pPsb = pPsb;
      pFilterList->pFilterSpecData->pPsb->pRsb = pRsb;
      pFilterList->pFilterSpecData->SentLabel.Label =
	pFilterList->pFilterSpecData->pPsb->Label;
      pFilterList->next = pRsb->OldPacket.pFilterList;
      pRsb->OldPacket.pFilterList = pFilterList;
    }

  pFilterSpecData = pFilterList->pFilterSpecData;

  if (LinkFilter2PHopList (pFilterSpecData) != E_OK)
    {
      zlog_err ("An error on LinkFilter2PHopList %s %d", __FILE__, __LINE__);
      return E_ERR;
    }

  if (pPsb->OldPacket.SessionAttributes.CType ==
      SESSION_ATTRIBUTES_RA_CLASS_TYPE)
    {
#if 0				/* temporary */
      pPsb->OldPacket.SessionAttributes.u.SessAttrRa.Flags |=
	SE_STYLE_DESIRED;
#endif
      if (pPsb->OldPacket.SessionAttributes.u.SessAttrRa.
	  Flags & SE_STYLE_DESIRED)
	{
	  Shared = 1;
	  pRsb->OldPacket.Style.OptionVector2 = SE_STYLE_BITS;
	}
      else
	{
	  pRsb->OldPacket.Style.OptionVector2 = FF_STYLE_BITS;
	}
    }
  else if (pPsb->OldPacket.SessionAttributes.CType ==
	   SESSION_ATTRIBUTES_CLASS_TYPE)
    {
#if 0				/* temporary */
      pPsb->OldPacket.SessionAttributes.u.SessAttr.Flags |= SE_STYLE_DESIRED;
#endif
      if (pPsb->OldPacket.SessionAttributes.u.SessAttr.
	  Flags & SE_STYLE_DESIRED)
	{
	  Shared = 1;
	  pRsb->OldPacket.Style.OptionVector2 = SE_STYLE_BITS;
	}
      else
	{
	  pRsb->OldPacket.Style.OptionVector2 = FF_STYLE_BITS;
	}
    }
  else
    {
      Shared = 1;
      pRsb->OldPacket.Style.OptionVector2 = SE_STYLE_BITS;
    }

  ComposeFlowSpec (pFilterSpecData->pPsb, &pFilterSpecData->FlowSpec);

  return ProcessPHopFilterSpecLists (pRsb, Shared);
}

E_RC
ProcessEffectiveFlows (RSB * pRsb)
{
  EFFECTIVE_FLOW *pEffectiveFlow = pRsb->pEffectiveFlow;
  uns8 NewFlow;
  zlog_info ("entering ProcessEffectiveFlows");
  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x",
	     pRsb->RsbKey.Session.Dest,
	     pRsb->RsbKey.Session.TunnelId, pRsb->RsbKey.Session.ExtTunelId);
  while (pEffectiveFlow != NULL)
    {
      if ((pEffectiveFlow->MustBeProcessed) &&
	  (pEffectiveFlow->TE_InProcess == FALSE))
	{
	  FILTER_LIST *pFilterList = pEffectiveFlow->pFilterList;
	  FLOW_SPEC_OBJ *pEffectiveFlowSpec;
	  memset (&pEffectiveFlow->NewFlowSpec, 0, sizeof (FLOW_SPEC_OBJ));
	  NewFlow = FALSE;
	  pEffectiveFlowSpec = &pEffectiveFlow->NewFlowSpec;
	  while (pFilterList != NULL)
	    {
	      FLOW_SPEC_OBJ *pFlowSpec;
	      if (pFilterList->pFilterSpecData != NULL)
		{
		  zlog_info ("processing filter spec %x %x",
			     pFilterList->pFilterSpecData->FilterSpec.IpAddr,
			     pFilterList->pFilterSpecData->FilterSpec.LspId);

		  if (pFilterList->pFilterSpecData->NewFlowSpecValid)
		    {
		      pFlowSpec = &pFilterList->pFilterSpecData->NewFlowSpec;
		      NewFlow = TRUE;
		      zlog_info ("New");
		    }
		  else
		    {
		      pFlowSpec = &pFilterList->pFilterSpecData->FlowSpec;
		      zlog_info ("Not new");
		    }

		  if (pEffectiveFlowSpec->ServHdr.ServHdr == 0)
		    {
		      pEffectiveFlowSpec->ServHdr.ServHdr =
			pFlowSpec->ServHdr.ServHdr;
		    }
		  if (FlowSpec1GreaterThanFlowSpec2
		      (pFlowSpec, pEffectiveFlowSpec) == TRUE)
		    {
		      zlog_info ("Setting Effective flow's BW to %f",
				 pFlowSpec->u.CtrlLoad.PeakDataRate);
		      *pEffectiveFlowSpec = *pFlowSpec;
		    }
		}
	      pFilterList = pFilterList->next;
	    }
	  if ((NewFlow == TRUE) || (memcmp (&pEffectiveFlow->CurrentFlowSpec,
					    &pEffectiveFlow->NewFlowSpec,
					    sizeof (FLOW_SPEC_OBJ))))
	    {
	      /* send notification to TE */
	      if (FlowSpec1GreaterThanFlowSpec2
		  (&pEffectiveFlow->CurrentFlowSpec,
		   &pEffectiveFlow->NewFlowSpec) == TRUE)
		{
		  pEffectiveFlow->CurrentFlowSpec =
		    pEffectiveFlow->NewFlowSpec;
		}
	      else
		if (FlowSpec1GreaterThanFlowSpec2
		    (&pEffectiveFlow->NewFlowSpec,
		     &pEffectiveFlow->CurrentFlowSpec) == TRUE)
		{
		  pEffectiveFlow->TE_InProcess = TRUE;
		}
	      else if (NewFlow == TRUE)
		{
		  pEffectiveFlow->TE_InProcess = TRUE;
		}
	      PrepareAndSendMsg2TE4SE (pRsb, pEffectiveFlow);
	    }
	  else
	    {
	      zlog_info ("no change...");
	    }
	  pEffectiveFlow->MustBeProcessed = 0;
	}
      pEffectiveFlow = pEffectiveFlow->next;
    }
  zlog_info ("leaving ProcessEffectiveFlows");
  return E_OK;
}

E_RC
ProcessReceivedFilterSpecs (RSB * pRsb, RSVP_PKT * pRsvpPkt)
{
  PSB_KEY PsbKey;
  FILTER_LIST *pFilterList, *pFilterListPrev = NULL, *pFilterListNext;
  uns8 ItemExtracted;
  int Shared = 0;
  zlog_info ("entering ProcessReceivedFilterSpecs");
  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x",
	     pRsb->RsbKey.Session.Dest,
	     pRsb->RsbKey.Session.TunnelId, pRsb->RsbKey.Session.ExtTunelId);
  if ((pRsvpPkt->Style.OptionVector2 & 0x001F) == SE_STYLE_BITS)
    {
      Shared = 1;
    }
  else if (!((pRsvpPkt->Style.OptionVector2 & 0x001F) == FF_STYLE_BITS))
    {
      RSVP_PKT RsvpPkt;
      zlog_err ("Unknown style %d", pRsvpPkt->Style.OptionVector2);
      memset (&RsvpPkt, 0, sizeof (RSVP_PKT));
      RsvpPkt.Session = pRsb->RsbKey.Session;
      RsvpPkt.Style = pRsb->OldPacket.Style;
      RsvpPkt.pFilterList = pRsvpPkt->pFilterList;
      RsvpPkt.ErrorSpec.IpAddr = GetRouterId ();
      RsvpPkt.ErrorSpec.ErrCode = UNKNOWN_RESV_STYLE_ERR_CODE;
      RsvpPkt.SentRsvpHop.LIH = pRsvpPkt->SentRsvpHop.LIH;
      if (IpAddrGetByIfIndex
	  (RsvpPkt.SentRsvpHop.LIH, &RsvpPkt.SentRsvpHop.PHop) != E_OK)
	{
	  zlog_err ("Cannot get IP address by IfIndex");
	  return E_ERR;
	}
      if (EncodeAndSendRsvpResvErrMessage
	  (&RsvpPkt, pRsvpPkt->ReceivedRsvpHop.PHop, RsvpPkt.SentRsvpHop.LIH,
	   255) != E_OK)
	{
	  zlog_err ("An error on encode/send %s %d", __FILE__, __LINE__);
	}
      return E_ERR;
    }

  pFilterList = pRsvpPkt->pFilterList;
  memset (&PsbKey, 0, sizeof (PSB_KEY));
  PsbKey.Session = pRsvpPkt->Session;
  while (pFilterList != NULL)
    {
      FILTER_SPEC_DATA *pFilterSpecData = pFilterList->pFilterSpecData;

      pFilterListNext = pFilterList->next;
      ItemExtracted = FALSE;

      if (pFilterSpecData != NULL)
	{
	  FILTER_LIST *pRsbFilterList = pRsb->OldPacket.pFilterList;
	  uns8 Found = 0;

	  /* First - update the reservations for the existing  filters */
	  while (pRsbFilterList != NULL)
	    {
	      if (pRsbFilterList->pFilterSpecData != NULL)
		{
		  /* is that the same filter ? */
		  if ((pRsbFilterList->pFilterSpecData->FilterSpec.IpAddr ==
		       pFilterList->pFilterSpecData->FilterSpec.IpAddr)
		      && (pRsbFilterList->pFilterSpecData->FilterSpec.LspId ==
			  pFilterList->pFilterSpecData->FilterSpec.LspId))
		    {
		      zlog_info ("existing filter spec found");
		      Found = 1;

		      if ((pRsbFilterList->pFilterSpecData->pPsb)
			  && (pRsbFilterList->pFilterSpecData->pPsb->
			      TE_InProcess == TRUE))
			{
			  RSVP_PKT_QUEUE *pQueuedItem;
			  RSVP_PKT *pSavedRsvpPkt;
			  if (pFilterListPrev == NULL)
			    {
			      pRsvpPkt->pFilterList = pFilterListNext;
			    }
			  else
			    {
			      pFilterListPrev->next = pFilterListNext;
			    }
			  ItemExtracted = TRUE;
			  if ((pSavedRsvpPkt =
			       (RSVP_PKT *) XMALLOC (MTYPE_RSVP,
						     sizeof (RSVP_PKT))) ==
			      NULL)
			    {
			      zlog_err ("memory allocation failed %s %d",
					__FILE__, __LINE__);
			      return E_ERR;
			    }
			  memcpy (pSavedRsvpPkt, pRsvpPkt, sizeof (RSVP_PKT));
			  pSavedRsvpPkt->pFilterList = pFilterList;
			  pSavedRsvpPkt->pFilterList->next = NULL;
			  pSavedRsvpPkt->pIntegrityObj = NULL;	/* temp. */
			  pSavedRsvpPkt->pPolicyDataObj = NULL;	/* temp. */
			  pSavedRsvpPkt->pOpaqueObjList = NULL;	/* temp. */
			  pSavedRsvpPkt->ReceivedRro.rr = NULL;	/* TEMP!!! */
			  if ((pQueuedItem =
			       (RSVP_PKT_QUEUE *) XMALLOC (MTYPE_RSVP,
							   sizeof
							   (RSVP_PKT_QUEUE)))
			      == NULL)
			    {
			      zlog_err ("memory allocation failed %s %d",
					__FILE__, __LINE__);
			      return E_ERR;
			    }

			  pQueuedItem->MsgType = RESV_MSG;
			  pQueuedItem->pRsvpPkt = pSavedRsvpPkt;
			  pQueuedItem->next = NULL;
			  if (EnqueueRsvpPacket
			      (pQueuedItem,
			       &pRsbFilterList->pFilterSpecData->pPsb->
			       packet_queue) != E_OK)
			    {
			      zlog_err ("Cannot enqueue packet %s %d",
					__FILE__, __LINE__);
			      return E_ERR;
			    }
			  break;
			}

		      if (StopFilterAgeOutTimer
			  (&pRsbFilterList->pFilterSpecData->AgeOutTimer) !=
			  E_OK)
			{
			  zlog_err ("Cannot stop timer %s %d", __FILE__,
				    __LINE__);
			}

		      if ((pRsbFilterList->pFilterSpecData->Blocked == TRUE)
			  &&
			  (FlowSpec1GreaterThanFlowSpec2
			   (&pRsbFilterList->pFilterSpecData->
			    BlockadeFlowSpec,
			    &pFilterSpecData->NewFlowSpec) == FALSE))
			{
			  if (StartFilterAgeOutTimer
			      (pRsbFilterList->pFilterSpecData->AgeOutValue,
			       &pRsbFilterList->pFilterSpecData->AgeOutTimer,
			       pRsbFilterList->pFilterSpecData) != E_OK)
			    {
			      zlog_err ("Cannot add timer %s %d", __FILE__,
					__LINE__);
			    }
			  break;
			}
		      else if (pRsbFilterList->pFilterSpecData->Blocked ==
			       TRUE)
			{
			  if (StopBlocadeTimer
			      (&pRsbFilterList->pFilterSpecData->
			       BlocadeTimer) != E_OK)
			    {
			      zlog_err ("Cannot delete timer %s %d", __FILE__,
					__LINE__);
			    }
			  pRsbFilterList->pFilterSpecData->Blocked = FALSE;
			}
		      if (pRsbFilterList->pFilterSpecData->pPsb->OutIfIndex !=
			  pRsvpPkt->ReceivedRsvpHop.LIH)
			{
			  zlog_err ("LIH does not match OutIf from PSB");
			  break;
			}

		      if ((Shared) &&
			  ((pFilterSpecData->pEffectiveFlow =
			    GetOrCreateEffectiveFlow (pRsb,
						      pRsbFilterList->
						      pFilterSpecData->pPsb->
						      OutIfIndex)) == NULL))
			{
			  zlog_err ("Cannot get/create effective flowspec");
			  return E_ERR;
			}
		      if ((Shared) &&
			  (pFilterSpecData->pEffectiveFlow !=
			   pRsbFilterList->pFilterSpecData->pEffectiveFlow))
			{
			  zlog_info
			    ("Deletion of filter_spec from effective_flow list .Src %x .LspId %x",
			     pFilterSpecData->FilterSpec.IpAddr,
			     pFilterSpecData->FilterSpec.LspId);

			  if (DeleteFilterListNode
			      (&pRsbFilterList->pFilterSpecData->
			       pEffectiveFlow->pFilterList,
			       pRsbFilterList->pFilterSpecData) != E_OK)
			    {
			      zlog_err
				("Cannot delete filter spec from effective flow list");
			    }
			  if (pRsbFilterList->pFilterSpecData->
			      pEffectiveFlow->pFilterList == NULL)
			    {
			      if (DeleteEffectiveFlow
				  (pRsbFilterList->pFilterSpecData->pPsb->
				   pRsb,
				   pRsbFilterList->pFilterSpecData->
				   pEffectiveFlow) != E_OK)
				{
				  zlog_err
				    ("Cannot delete effective flow list item");
				}
			    }
			  else
			    {
			      pRsbFilterList->pFilterSpecData->
				pEffectiveFlow->MustBeProcessed = 1;
			    }
			  if (pFilterSpecData->pEffectiveFlow->TE_InProcess ==
			      TRUE)
			    {
			      RSVP_PKT_QUEUE *pQueuedItem;
			      RSVP_PKT *pSavedRsvpPkt;
			      if (pFilterListPrev == NULL)
				{
				  pRsvpPkt->pFilterList = pFilterListNext;
				}
			      else
				{
				  pFilterListPrev->next = pFilterListNext;
				}
			      ItemExtracted = TRUE;
			      if ((pSavedRsvpPkt =
				   (RSVP_PKT *) XMALLOC (MTYPE_RSVP,
							 sizeof (RSVP_PKT)))
				  == NULL)
				{
				  zlog_err ("memory allocation failed %s %d",
					    __FILE__, __LINE__);
				  return E_ERR;
				}
			      memcpy (pSavedRsvpPkt, pRsvpPkt,
				      sizeof (RSVP_PKT));
			      pSavedRsvpPkt->pFilterList = pFilterList;
			      pSavedRsvpPkt->pFilterList->next = NULL;
			      pSavedRsvpPkt->pIntegrityObj = NULL;	/* temp. */
			      pSavedRsvpPkt->pPolicyDataObj = NULL;	/* temp. */
			      pSavedRsvpPkt->pOpaqueObjList = NULL;	/* temp. */
			      pSavedRsvpPkt->ReceivedRro.rr = NULL;	/* TEMP!!! */
			      if ((pQueuedItem =
				   (RSVP_PKT_QUEUE *) XMALLOC (MTYPE_RSVP,
							       sizeof
							       (RSVP_PKT_QUEUE)))
				  == NULL)
				{
				  zlog_err ("memory allocation failed %s %d",
					    __FILE__, __LINE__);
				  return E_ERR;
				}

			      pQueuedItem->MsgType = RESV_MSG;
			      pQueuedItem->pRsvpPkt = pSavedRsvpPkt;
			      pQueuedItem->next = NULL;
			      if (EnqueueRsvpPacket
				  (pQueuedItem,
				   &pRsbFilterList->pFilterSpecData->pPsb->
				   packet_queue) != E_OK)
				{
				  zlog_err ("Cannot enqueue packet %s %d",
					    __FILE__, __LINE__);
				  return E_ERR;
				}
			      break;
			    }
			  pRsbFilterList->pFilterSpecData->pEffectiveFlow =
			    pFilterSpecData->pEffectiveFlow;
			  pRsbFilterList->pFilterSpecData->pEffectiveFlow->
			    MustBeProcessed = 1;
			  pRsbFilterList->pFilterSpecData->NewFlowSpecValid =
			    1;
			  pRsbFilterList->pFilterSpecData->NewFlowSpec =
			    pFilterList->pFilterSpecData->NewFlowSpec;
			  zlog_info
			    ("Adding filter_spec to effective_flow list .Src %x .LspId %x",
			     pFilterSpecData->FilterSpec.IpAddr,
			     pFilterSpecData->FilterSpec.LspId);

			  if (NewFilterListNode
			      (&pRsbFilterList->pFilterSpecData->
			       pEffectiveFlow->pFilterList,
			       pRsbFilterList->pFilterSpecData) != E_OK)
			    {
			      zlog_err ("Cannot create new FILTER LIST node");
			      return E_ERR;
			    }
			}
		      else if ((Shared)
			       && (pFilterSpecData->pEffectiveFlow->
				   TE_InProcess == TRUE))
			{
			  RSVP_PKT_QUEUE *pQueuedItem;
			  RSVP_PKT *pSavedRsvpPkt;
			  if (pFilterListPrev == NULL)
			    {
			      pRsvpPkt->pFilterList = pFilterListNext;
			    }
			  else
			    {
			      pFilterListPrev->next = pFilterListNext;
			    }
			  ItemExtracted = TRUE;
			  if ((pSavedRsvpPkt =
			       (RSVP_PKT *) XMALLOC (MTYPE_RSVP,
						     sizeof (RSVP_PKT))) ==
			      NULL)
			    {
			      zlog_err ("memory allocation failed %s %d",
					__FILE__, __LINE__);
			      return E_ERR;
			    }
			  memcpy (pSavedRsvpPkt, pRsvpPkt, sizeof (RSVP_PKT));
			  pSavedRsvpPkt->pFilterList = pFilterList;
			  pSavedRsvpPkt->pFilterList->next = NULL;
			  pSavedRsvpPkt->pIntegrityObj = NULL;	/* temp. */
			  pSavedRsvpPkt->pPolicyDataObj = NULL;	/* temp. */
			  pSavedRsvpPkt->pOpaqueObjList = NULL;	/* temp. */
			  pSavedRsvpPkt->ReceivedRro.rr = NULL;	/* TEMP!!! */
			  if ((pQueuedItem =
			       (RSVP_PKT_QUEUE *) XMALLOC (MTYPE_RSVP,
							   sizeof
							   (RSVP_PKT_QUEUE)))
			      == NULL)
			    {
			      zlog_err ("memory allocation failed %s %d",
					__FILE__, __LINE__);
			      return E_ERR;
			    }

			  pQueuedItem->MsgType = RESV_MSG;
			  pQueuedItem->pRsvpPkt = pSavedRsvpPkt;
			  pQueuedItem->next = NULL;
			  if (EnqueueRsvpPacket
			      (pQueuedItem,
			       &pRsbFilterList->pFilterSpecData->pPsb->
			       packet_queue) != E_OK)
			    {
			      zlog_err ("Cannot enqueue packet %s %d",
					__FILE__, __LINE__);
			      return E_ERR;
			    }
			  break;
			}
		      else
			if (memcmp
			    (&pRsbFilterList->pFilterSpecData->FlowSpec,
			     &pFilterList->pFilterSpecData->NewFlowSpec,
			     sizeof (FLOW_SPEC_OBJ)))
			{
			  /* if BW should be decreased/increased for the filter */
			  pRsbFilterList->pFilterSpecData->NewFlowSpec =
			    pFilterList->pFilterSpecData->NewFlowSpec;
			  pRsbFilterList->pFilterSpecData->NewFlowSpecValid =
			    1;
			  if (Shared)
			    {
			      pRsbFilterList->pFilterSpecData->
				pEffectiveFlow->MustBeProcessed = 1;
			    }
			  else
			    {
			      /* send notification to TE */
			      if (FlowSpec1GreaterThanFlowSpec2
				  (&pRsbFilterList->pFilterSpecData->
				   NewFlowSpec,
				   &pFilterList->pFilterSpecData->
				   NewFlowSpec) == TRUE)
				{
				  zlog_info
				    ("Locking Flow %x %x %x %x %x %s %d",
				     pRsbFilterList->pFilterSpecData->pPsb->
				     pRsb->RsbKey.Session.Dest,
				     pRsbFilterList->pFilterSpecData->pPsb->
				     pRsb->RsbKey.Session.TunnelId,
				     pRsbFilterList->pFilterSpecData->pPsb->
				     pRsb->RsbKey.Session.ExtTunelId,
				     pRsbFilterList->pFilterSpecData->
				     FilterSpec.IpAddr,
				     pRsbFilterList->pFilterSpecData->
				     FilterSpec.LspId, __FILE__, __LINE__);
				  pRsbFilterList->pFilterSpecData->pPsb->
				    TE_InProcess = TRUE;
				}
			      PrepareAndSendMsg2TE4FF (pRsb,
						       pRsbFilterList->
						       pFilterSpecData);
			    }
			}
		      else
			{
			  if (StartFilterAgeOutTimer
			      (pRsbFilterList->pFilterSpecData->AgeOutValue,
			       &pRsbFilterList->pFilterSpecData->AgeOutTimer,
			       pRsbFilterList->pFilterSpecData) != E_OK)
			    {
			      zlog_err ("Cannot add timer %s %d", __FILE__,
					__LINE__);
			    }
			}
		      Found = 1;
		      break;
		    }
		}
	      pRsbFilterList = pRsbFilterList->next;
	    }

	  if (Found == 0)
	    {
	      zlog_info ("the filter spec is new %x %x",
			 pFilterSpecData, pFilterSpecData->pPsb);
	      PsbKey.SenderTemplate.IpAddr =
		pFilterSpecData->FilterSpec.IpAddr;
	      PsbKey.SenderTemplate.LspId = pFilterSpecData->FilterSpec.LspId;
	      zlog_info ("%x %x %x %x %x %s %d",
			 PsbKey.Session.Dest,
			 PsbKey.Session.TunnelId,
			 PsbKey.Session.ExtTunelId,
			 PsbKey.SenderTemplate.IpAddr,
			 PsbKey.SenderTemplate.LspId, __FILE__, __LINE__);
	      if ((pFilterSpecData->pPsb = FindPsb (&PsbKey)) == NULL)
		{
		  zlog_err ("cannot find PSB %s %d", __FILE__, __LINE__);
		  zlog_err ("Generating ResvErr to %x on %x",
			    pRsvpPkt->ReceivedRsvpHop.PHop,
			    pRsvpPkt->ReceivedRsvpHop.LIH);
		  if (GenerateResvErr4SingleFilterSpec
		      (pFilterSpecData, pRsb, pRsvpPkt->ReceivedRsvpHop.PHop,
		       pRsvpPkt->ReceivedRsvpHop.LIH,
		       NO_PATH_INFO_4_RESV_ERR_CODE, 0) != E_OK)
		    {
		      zlog_err ("Cannot generate/send ResvErr message %s %d",
				__FILE__, __LINE__);
		    }
		  goto outer_loop_cont;
		}

	      if (pFilterSpecData->pPsb->TE_InProcess == TRUE)
		{
		  RSVP_PKT_QUEUE *pQueuedItem;
		  RSVP_PKT *pSavedRsvpPkt;
		  if (pFilterListPrev == NULL)
		    {
		      pRsvpPkt->pFilterList = pFilterListNext;
		    }
		  else
		    {
		      pFilterListPrev->next = pFilterListNext;
		    }
		  ItemExtracted = TRUE;
		  if ((pSavedRsvpPkt =
		       (RSVP_PKT *) XMALLOC (MTYPE_RSVP,
					     sizeof (RSVP_PKT))) == NULL)
		    {
		      zlog_err ("memory allocation failed %s %d", __FILE__,
				__LINE__);
		      return E_ERR;
		    }
		  memcpy (pSavedRsvpPkt, pRsvpPkt, sizeof (RSVP_PKT));
		  pSavedRsvpPkt->pFilterList = pFilterList;
		  pSavedRsvpPkt->pFilterList->next = NULL;
		  pSavedRsvpPkt->pIntegrityObj = NULL;	/* temp. */
		  pSavedRsvpPkt->pPolicyDataObj = NULL;	/* temp. */
		  pSavedRsvpPkt->pOpaqueObjList = NULL;	/* temp. */
		  pSavedRsvpPkt->ReceivedRro.rr = NULL;	/* TEMP!!! */
		  if ((pQueuedItem =
		       (RSVP_PKT_QUEUE *) XMALLOC (MTYPE_RSVP,
						   sizeof (RSVP_PKT_QUEUE)))
		      == NULL)
		    {
		      zlog_err ("memory allocation failed %s %d", __FILE__,
				__LINE__);
		      return E_ERR;
		    }

		  pQueuedItem->MsgType = RESV_MSG;
		  pQueuedItem->pRsvpPkt = pSavedRsvpPkt;
		  pQueuedItem->next = NULL;
		  if (EnqueueRsvpPacket
		      (pQueuedItem,
		       &pFilterSpecData->pPsb->packet_queue) != E_OK)
		    {
		      zlog_err ("Cannot enqueue packet %s %d", __FILE__,
				__LINE__);
		      return E_ERR;
		    }
		  break;
		}

	      pFilterSpecData->pPsb->pRsb = pRsb;
	      pFilterSpecData->pPsb->pFilterSpecData = pFilterSpecData;
	      {
		uns32 val;
		zlog_info ("TimeValue %x", pRsvpPkt->TimeValues.TimeValues);
		val = (uns32) pRsvpPkt->TimeValues.TimeValues / 10000;
		zlog_info ("val %x", val);
		/* 3*R: */
		val *= 3;
		zlog_info ("val %x", val);
		/* (2M+1) * (3*R): */
		val = (2 * ResvRefreshMultiple + 1) * val;
		zlog_info ("val %x", val);
		/* and divide by 4 to get (M + 0.5) * (1.5 * R) */
		pFilterSpecData->AgeOutValue = val >> 2;
		//pFilterSpecData->AgeOutValue = 1;
		zlog_info ("AgeOut value %d", pFilterSpecData->AgeOutValue);
	      }
	      pFilterSpecData->SentLabel.Label = pFilterSpecData->pPsb->Label;

	      if (Shared)
		{
		  zlog_info ("and shared...");
		  if ((pFilterSpecData->pEffectiveFlow =
		       GetOrCreateEffectiveFlow (pRsb,
						 pFilterSpecData->pPsb->
						 OutIfIndex)) == NULL)
		    {
		      zlog_err ("Cannot get/create effective flowspec");
		      return E_ERR;
		    }
		  if (pFilterSpecData->pEffectiveFlow->TE_InProcess == TRUE)
		    {
		      RSVP_PKT_QUEUE *pQueuedItem;
		      RSVP_PKT *pSavedRsvpPkt;

		      pFilterSpecData->pPsb->pRsb = NULL;
		      pFilterSpecData->pPsb->pFilterSpecData = NULL;

		      if (pFilterListPrev == NULL)
			{
			  pRsvpPkt->pFilterList = pFilterListNext;
			}
		      else
			{
			  pFilterListPrev->next = pFilterListNext;
			}
		      ItemExtracted = TRUE;
		      if ((pSavedRsvpPkt =
			   (RSVP_PKT *) XMALLOC (MTYPE_RSVP,
						 sizeof (RSVP_PKT))) == NULL)
			{
			  zlog_err ("memory allocation failed %s %d",
				    __FILE__, __LINE__);
			  return E_ERR;
			}
		      memcpy (pSavedRsvpPkt, pRsvpPkt, sizeof (RSVP_PKT));
		      pSavedRsvpPkt->pFilterList = pFilterList;
		      pSavedRsvpPkt->pFilterList->next = NULL;
		      pSavedRsvpPkt->pIntegrityObj = NULL;	/* temp. */
		      pSavedRsvpPkt->pPolicyDataObj = NULL;	/* temp. */
		      pSavedRsvpPkt->pOpaqueObjList = NULL;	/* temp. */
		      pSavedRsvpPkt->ReceivedRro.rr = NULL;	/* TEMP!!! */
		      if ((pQueuedItem =
			   (RSVP_PKT_QUEUE *) XMALLOC (MTYPE_RSVP,
						       sizeof
						       (RSVP_PKT_QUEUE))) ==
			  NULL)
			{
			  zlog_err ("memory allocation failed %s %d",
				    __FILE__, __LINE__);
			  return E_ERR;
			}

		      pQueuedItem->MsgType = RESV_MSG;
		      pQueuedItem->pRsvpPkt = pSavedRsvpPkt;
		      pQueuedItem->next = NULL;
		      if (EnqueueRsvpPacket
			  (pQueuedItem,
			   &pFilterSpecData->pPsb->packet_queue) != E_OK)
			{
			  zlog_err ("Cannot enqueue packet %s %d", __FILE__,
				    __LINE__);
			  return E_ERR;
			}
		      goto outer_loop_cont;
		    }
		  pFilterSpecData->pEffectiveFlow->MustBeProcessed = 1;
		  zlog_info
		    ("Adding filter_spec to effective_flow list .Src %x .LspId %x",
		     pFilterSpecData->FilterSpec.IpAddr,
		     pFilterSpecData->FilterSpec.LspId);
		  if (NewFilterListNode
		      (&pFilterSpecData->pEffectiveFlow->pFilterList,
		       pFilterSpecData) != E_OK)
		    {
		      zlog_err ("Cannot create new FILTER LIST node");
		      goto outer_loop_cont;
		    }
		  else
		    {
		      pFilterSpecData->NewFlowSpecValid = 1;
		      pFilterSpecData->pEffectiveFlow->MustBeProcessed = 1;
		      pFilterList->next = pRsb->OldPacket.pFilterList;
		      pRsb->OldPacket.pFilterList = pFilterList;
		    }
		}
	      else
		{
		  pFilterSpecData->NewFlowSpecValid = 1;
		  pFilterList->next = pRsb->OldPacket.pFilterList;
		  pRsb->OldPacket.pFilterList = pFilterList;
		  /* send notification to TE */
		  zlog_info ("Locking Flow %x %x %x %x %x %s %d",
			     pFilterSpecData->pPsb->pRsb->RsbKey.Session.Dest,
			     pFilterSpecData->pPsb->pRsb->RsbKey.Session.
			     TunnelId,
			     pFilterSpecData->pPsb->pRsb->RsbKey.Session.
			     ExtTunelId, pFilterSpecData->FilterSpec.IpAddr,
			     pFilterSpecData->FilterSpec.LspId, __FILE__,
			     __LINE__);
		  pFilterSpecData->pPsb->TE_InProcess = TRUE;
		  PrepareAndSendMsg2TE4FF (pRsb,
					   pFilterList->pFilterSpecData);
		}
	      if (pFilterListPrev == NULL)
		{
		  pRsvpPkt->pFilterList = pFilterListNext;
		}
	      else
		{
		  pFilterListPrev->next = pFilterListNext;
		}
	      ItemExtracted = TRUE;
	      RsvpStatistics.NewFiltersCount++;
	    }
	}
    outer_loop_cont:
      if (ItemExtracted == FALSE)
	{
	  pFilterListPrev = pFilterList;
	}
      pFilterList = pFilterListNext;
    }
  if (Shared)
    {
      if (ProcessEffectiveFlows (pRsb) != E_OK)
	{
	  zlog_err ("an error on process effective flows");
	  return E_ERR;
	}
    }
  zlog_info ("leaving ProcessReceivedFilterSpecs");
  return E_OK;
}

static E_RC
BuildRRSubObj (FILTER_SPEC_DATA * pFilterSpecData)
{
  PSB *pPsb;


  pPsb = pFilterSpecData->pPsb;
  if ((pFilterSpecData->pPHopResvRefreshList->pAddedRro =
       (RR_SUBOBJ *) XMALLOC (MTYPE_RSVP, sizeof (RR_SUBOBJ))) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  else
    {
      IPV4_ADDR IpAddr;
      uns8 LabelRecordingDesired = 0;
      memset (pFilterSpecData->pPHopResvRefreshList->pAddedRro, 0,
	      sizeof (RR_SUBOBJ));
      pFilterSpecData->pPHopResvRefreshList->pAddedRro->SubObjHdr.Type =
	RRO_SUBTYPE_IPV4;
      pFilterSpecData->pPHopResvRefreshList->pAddedRro->SubObjHdr.Length = 8;
      pFilterSpecData->pPHopResvRefreshList->pAddedRro->u.Ipv4.PrefixLen = 32;
      zlog_info ("inside of BuildRRSubObj %s %d...", __FILE__, __LINE__);
      if (IpAddrGetByIfIndex (pPsb->InIfIndex, &IpAddr) != E_OK)
	{
	  zlog_err ("Cannot set RSVP HOP %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pFilterSpecData->pPHopResvRefreshList->pAddedRro->u.Ipv4.IpAddr =
	IpAddr;
      if (pPsb->OldPacket.SessionAttributes.CType ==
	  SESSION_ATTRIBUTES_RA_IPV4_CTYPE)
	{
	  if (pPsb->OldPacket.SessionAttributes.u.SessAttrRa.
	      Flags & LABEL_RECORDING_DESIRED)
	    {
	      LabelRecordingDesired = 1;
	    }
	}
      else if (pPsb->OldPacket.SessionAttributes.CType ==
	       SESSION_ATTRIBUTES_IPV4_CTYPE)
	{
	  if (pPsb->OldPacket.SessionAttributes.u.SessAttr.
	      Flags & LABEL_RECORDING_DESIRED)
	    {
	      LabelRecordingDesired = 1;
	    }
	}
      if (LabelRecordingDesired == 1)
	{
	  zlog_info ("inside of BuildRRSubObj %s %d...", __FILE__, __LINE__);
	  if ((pFilterSpecData->pPHopResvRefreshList->pAddedRro->next =
	       (RR_SUBOBJ *) XMALLOC (MTYPE_RSVP,
				      sizeof (RR_SUBOBJ))) == NULL)
	    {
	      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }
	  else
	    {
	      memset (pFilterSpecData->pPHopResvRefreshList->pAddedRro->next,
		      0, sizeof (RR_SUBOBJ));
	      pFilterSpecData->pPHopResvRefreshList->pAddedRro->next->
		SubObjHdr.Type = RRO_SUBTYPE_LABEL;
	      pFilterSpecData->pPHopResvRefreshList->pAddedRro->next->
		SubObjHdr.Length = 8;
	      pFilterSpecData->pPHopResvRefreshList->pAddedRro->next->u.Label.
		CType = COMMON_CTYPE;
	      pFilterSpecData->pPHopResvRefreshList->pAddedRro->next->u.Label.
		Flags = 0x01;
	      pFilterSpecData->pPHopResvRefreshList->pAddedRro->next->u.Label.
		Label = pFilterSpecData->SentLabel.Label;
	    }
	}
    }
  return E_OK;
}

E_RC
ProcessPHopFilterSpecLists (RSB * pRsb, uns8 Shared)
{
  PHOP_RESV_REFRESH_LIST *pPHopResvRefreshList;
  FILTER_LIST *pFilterList;
  int FlowCount = 0;
  zlog_info ("entering ProcessPHopFilterSpecLists");
  pPHopResvRefreshList = pRsb->pPHopResvRefreshList;
  while (pPHopResvRefreshList != NULL)
    {
      if (pPHopResvRefreshList->MustBeProcessed)
	{
	  if (Shared)
	    {
	      memset (&pPHopResvRefreshList->FwdFlowSpec, 0,
		      sizeof (FLOW_SPEC_OBJ));
	    }

	  pFilterList = pPHopResvRefreshList->pFilterList;

	  while (pFilterList != NULL)
	    {
	      if ((pFilterList->pFilterSpecData->Blocked == TRUE) &&
		  (FlowSpec1GreaterThanFlowSpec2
		   (&pFilterList->pFilterSpecData->BlockadeFlowSpec,
		    &pFilterList->pFilterSpecData->FlowSpec) == FALSE))
		{
		  pFilterList = pFilterList->next;
		  continue;
		}
	      else if (pFilterList->pFilterSpecData->Blocked == TRUE)
		{
		  if (StopBlocadeTimer
		      (&pFilterList->pFilterSpecData->BlocadeTimer) != E_OK)
		    {
		      zlog_err ("Cannot delete timer %s %d", __FILE__,
				__LINE__);
		    }
		  pFilterList->pFilterSpecData->Blocked = FALSE;
		}
	      if (Shared)
		{
		  if (pPHopResvRefreshList->FwdFlowSpec.ServHdr.ServHdr == 0)
		    {
		      pPHopResvRefreshList->FwdFlowSpec.ServHdr.ServHdr =
			pFilterList->pFilterSpecData->NewFlowSpec.ServHdr.
			ServHdr;
		    }

		  CheckAndSetFlowSpecObj (pFilterList->pFilterSpecData->pPsb,
					  &pFilterList->pFilterSpecData->
					  FlowSpec,
					  &pPHopResvRefreshList->FwdFlowSpec);
		}
	      FlowCount++;
	      pFilterList = pFilterList->next;
	    }
	  if (FlowCount)
	    {
	      if (ResvRefreshProc (pRsb, pPHopResvRefreshList) != E_OK)
		{
		  zlog_err ("an error on resv refresh proc");
		}
	    }
	  pPHopResvRefreshList->MustBeProcessed = 0;
	}
      pPHopResvRefreshList = pPHopResvRefreshList->next;
    }

  zlog_info ("leaving ProcessPHopFilterSpecLists");
  return E_OK;
}

E_RC
ProcessForwardedSEFilterSpecsByIfIndex (RSB * pRsb, uns32 IfIndex)
{
  FILTER_LIST *pFilterList;
  PSB *pPsb;
  uns8 Ingress = FALSE;
  EFFECTIVE_FLOW *pEffectiveFlow = pRsb->pEffectiveFlow;
  zlog_info ("entering ProcessForwardedSEFilterSpecsByIfIndex");
  while (pEffectiveFlow != NULL)
    {
      if (pEffectiveFlow->IfIndex == IfIndex)
	{
	  break;
	}
      pEffectiveFlow = pEffectiveFlow->next;
    }
  if (pEffectiveFlow == NULL)
    {
      zlog_err ("Cannot find effective flow");
      return E_ERR;
    }
  pEffectiveFlow->CurrentFlowSpec = pEffectiveFlow->NewFlowSpec;
  pFilterList = pEffectiveFlow->pFilterList;
  pEffectiveFlow->TE_InProcess = FALSE;
  while (pFilterList != NULL)
    {
      FILTER_SPEC_DATA *pFilterSpecData = pFilterList->pFilterSpecData;

      if (pFilterSpecData != NULL)
	{
	  if ((pFilterSpecData->Blocked == TRUE) &&
	      (FlowSpec1GreaterThanFlowSpec2
	       (&pFilterSpecData->BlockadeFlowSpec,
		&pFilterSpecData->FlowSpec) == FALSE))
	    {
	      pFilterList = pFilterList->next;
	      continue;
	    }
	  else if (pFilterSpecData->Blocked == TRUE)
	    {
	      if (StopBlocadeTimer (&pFilterSpecData->BlocadeTimer) != E_OK)
		{
		  zlog_err ("Cannot delete timer %s %d", __FILE__, __LINE__);
		}
	      pFilterSpecData->Blocked = FALSE;
	    }
	  pPsb = pFilterSpecData->pPsb;
	  if (pFilterSpecData->NewFlowSpecValid)
	    {
	      pFilterSpecData->FlowSpec = pFilterSpecData->NewFlowSpec;
	      pFilterSpecData->NewFlowSpecValid = 0;
	      if (StartFilterAgeOutTimer (pFilterSpecData->AgeOutValue,
					  &pFilterSpecData->AgeOutTimer,
					  pFilterSpecData) != E_OK)
		{
		  zlog_err ("Cannot start timer %s %d", __FILE__, __LINE__);
		}

	      if (pFilterSpecData->pPsb->InIfIndex == 0)
		{
		  zlog_info ("Congratulations: RESV has reached Ingress!!");
		  Ingress = TRUE;
		}
	    }

	  if (pFilterSpecData->pPsb->InIfIndex == 0)
	    {
	      pFilterList = pFilterList->next;
	      continue;
	    }
	  if (LinkFilter2PHopList (pFilterSpecData) != E_OK)
	    {
	      zlog_err ("An error on LinkFilter2PHopList %s %d", __FILE__,
			__LINE__);
	      goto outer_loop_cont;
	    }
	}
    outer_loop_cont:
      pFilterList = pFilterList->next;
    }
  if (Ingress == FALSE)
    {
      return ProcessPHopFilterSpecLists (pRsb, 1);
    }
  return E_OK;
}

E_RC
ProcessFailedSEFilterSpecsByIfIndex (RSB * pRsb, uns32 IfIndex)
{
  FILTER_LIST *pFilterList;
  uns8 Ingress = FALSE;
  EFFECTIVE_FLOW *pEffectiveFlow = pRsb->pEffectiveFlow;
  RSVP_PKT RsvpPkt;
  IPV4_ADDR NHop = 0;
  zlog_info ("entering ProcessFailedSEFilterSpecsByIfIndex");
  memset (&RsvpPkt, 0, sizeof (RSVP_PKT));
  RsvpPkt.Session = pRsb->RsbKey.Session;
  RsvpPkt.Style = pRsb->OldPacket.Style;
  RsvpPkt.ErrorSpec.IpAddr = GetRouterId ();
  RsvpPkt.ErrorSpec.ErrCode = ADMISSION_CTRL_FAILURE_ERR_CODE;
  RsvpPkt.ErrorSpec.ErrVal = BW_UNAVAILABLE;
  RsvpPkt.SentRsvpHop.LIH = IfIndex;
  RsvpPkt.SentRsvpHop.PHop = GetRouterId ();
  while (pEffectiveFlow != NULL)
    {
      if (pEffectiveFlow->IfIndex == IfIndex)
	{
	  break;
	}
      pEffectiveFlow = pEffectiveFlow->next;
    }
  if (pEffectiveFlow == NULL)
    {
      zlog_err ("Cannot find effective flow");
      return E_ERR;
    }
  pEffectiveFlow->CurrentFlowSpec = pEffectiveFlow->NewFlowSpec;
  pFilterList = pEffectiveFlow->pFilterList;
  pEffectiveFlow->TE_InProcess = FALSE;
  while (pFilterList != NULL)
    {
      FILTER_SPEC_DATA *pFilterSpecData = pFilterList->pFilterSpecData;

      if (pFilterSpecData != NULL)
	{
	  if (pFilterSpecData->NewFlowSpecValid)
	    {
	      if (StartBlocadeTimer (pFilterSpecData->BlocadeValue,
				     &pFilterSpecData->BlocadeTimer,
				     pFilterSpecData) != E_OK)
		{
		  zlog_err ("Cannot start blocade timer %s %d", __FILE__,
			    __LINE__);
		}
	      else
		{
		  pFilterSpecData->Blocked = TRUE;
		}
	      memset (&pFilterSpecData->NewFlowSpec, 0,
		      sizeof (FLOW_SPEC_OBJ));
	      pFilterSpecData->NewFlowSpecValid = 0;
	      if (StartFilterAgeOutTimer (pFilterSpecData->AgeOutValue,
					  &pFilterSpecData->AgeOutTimer,
					  pFilterSpecData) != E_OK)
		{
		  zlog_err ("Cannot start timer %s %d", __FILE__, __LINE__);
		}

	      if (pFilterSpecData->pPsb->InIfIndex == 0)
		{
		  Ingress = TRUE;
		}
	      NHop = pFilterSpecData->pPsb->NextHop;
	      if (NewFilterListNode (&RsvpPkt.pFilterList, pFilterSpecData) !=
		  E_OK)
		{
		  zlog_err ("Cannot add filter to filter list %s %d",
			    __FILE__, __LINE__);
		}

	      if (pFilterSpecData->pPsb->InIfIndex == 0)
		{
		  pFilterList = pFilterList->next;
		  continue;
		}

	      if (LinkFilter2PHopList (pFilterSpecData) != E_OK)
		{
		  zlog_err ("An error on LinkFilter2PHopList %s %d", __FILE__,
			    __LINE__);
		  goto outer_loop_cont;
		}
	    }
	}
    outer_loop_cont:
      pFilterList = pFilterList->next;
    }
  if (EncodeAndSendRsvpResvErrMessage (&RsvpPkt, NHop, IfIndex, 255) != E_OK)
    {
      zlog_err ("Cannot encode/send ResvErr message %s %d", __FILE__,
		__LINE__);
    }
  pFilterList = RsvpPkt.pFilterList;
  while (pFilterList != NULL)
    {
      FILTER_LIST *pNext = pFilterList->next;
      XFREE (MTYPE_RSVP, pFilterList);
      pFilterList = pNext;
    }
  if (Ingress == FALSE)
    {
      return ProcessPHopFilterSpecLists (pRsb, 1);
    }
  return E_OK;
}

E_RC
ProcessForwardedFFFilterSpec (RSB * pRsb, FILTER_SPEC_OBJ * pFilterSpecObj)
{
  PSB *pPsb;
  FILTER_SPEC_DATA *pFilterSpecData = NULL;
  FILTER_LIST *pFilterList = pRsb->OldPacket.pFilterList;
  zlog_info ("entering ProcessForwardedFFFilterSpec");
  while (pFilterList != NULL)
    {
      if ((pFilterSpecData = pFilterList->pFilterSpecData) != NULL)
	{
	  if (memcmp (&pFilterSpecData->FilterSpec,
		      pFilterSpecObj, sizeof (FILTER_SPEC_OBJ)) == 0)
	    {
	      break;
	    }
	}
      pFilterSpecData = NULL;
      pFilterList = pFilterList->next;
    }
  if (pFilterSpecData != NULL)
    {
      pFilterSpecData->pPsb->TE_InProcess = FALSE;

      if ((pFilterSpecData->Blocked == TRUE) &&
	  (FlowSpec1GreaterThanFlowSpec2 (&pFilterSpecData->BlockadeFlowSpec,
					  &pFilterSpecData->FlowSpec) ==
	   FALSE))
	{
	  return E_OK;
	}
      else if (pFilterSpecData->Blocked == TRUE)
	{
	  if (StopBlocadeTimer (&pFilterSpecData->BlocadeTimer) != E_OK)
	    {
	      zlog_err ("Cannot delete timer %s %d", __FILE__, __LINE__);
	    }
	  pFilterSpecData->Blocked = FALSE;
	}
      pPsb = pFilterSpecData->pPsb;
      if (pFilterSpecData->NewFlowSpecValid)
	{
	  pFilterSpecData->FlowSpec = pFilterSpecData->NewFlowSpec;
	  pFilterSpecData->NewFlowSpecValid = 0;
	  if (StartFilterAgeOutTimer (pFilterSpecData->AgeOutValue,
				      &pFilterSpecData->AgeOutTimer,
				      pFilterSpecData) != E_OK)
	    {
	      zlog_err ("Cannot start timer %s %d", __FILE__, __LINE__);
	    }
	}
      if (pFilterSpecData->pPsb->InIfIndex == 0)
	{
	  return E_OK;
	}
      if (LinkFilter2PHopList (pFilterSpecData) != E_OK)
	{
	  zlog_err ("An error on LinkFilter2PHopList %s %d", __FILE__,
		    __LINE__);
	}
      return ProcessPHopFilterSpecLists (pRsb, 0);
    }
  zlog_info ("leaving ProcessForwardedFFFilterSpec");
  return E_ERR;
}

E_RC
ProcessFailedFFFilterSpec (RSB * pRsb, FILTER_SPEC_OBJ * pFilterSpecObj)
{
  FILTER_SPEC_DATA *pFilterSpecData = NULL;
  FILTER_LIST *pFilterList = pRsb->OldPacket.pFilterList;
  zlog_info ("entering ProcessFailedFFFilterSpec");
  while (pFilterList != NULL)
    {
      if ((pFilterSpecData = pFilterList->pFilterSpecData) != NULL)
	{
	  if (memcmp (&pFilterSpecData->FilterSpec,
		      pFilterSpecObj, sizeof (FILTER_SPEC_OBJ)) == 0)
	    {
	      break;
	    }
	}
      pFilterSpecData = NULL;
      pFilterList = pFilterList->next;
    }
  if (pFilterSpecData != NULL)
    {
      pFilterSpecData->pPsb->TE_InProcess = FALSE;
      if (StartBlocadeTimer (pFilterSpecData->BlocadeValue,
			     &pFilterSpecData->BlocadeTimer,
			     pFilterSpecData) != E_OK)
	{
	  zlog_err ("Cannot start blocade timer %s %d", __FILE__, __LINE__);
	}
      else
	{
	  pFilterSpecData->Blocked = TRUE;
	}

      if (pFilterSpecData->NewFlowSpecValid)
	{
	  memset (&pFilterSpecData->NewFlowSpec, 0, sizeof (FLOW_SPEC_OBJ));
	  pFilterSpecData->NewFlowSpecValid = 0;
	  if (StartFilterAgeOutTimer (pFilterSpecData->AgeOutValue,
				      &pFilterSpecData->AgeOutTimer,
				      pFilterSpecData) != E_OK)
	    {
	      zlog_err ("Cannot start timer %s %d", __FILE__, __LINE__);
	    }
	}
      if (GenerateResvErr4SingleFilterSpec (pFilterSpecData,
					    pRsb,
					    pFilterSpecData->pPsb->NextHop,
					    pFilterSpecData->pPsb->OutIfIndex,
					    ADMISSION_CTRL_FAILURE_ERR_CODE,
					    BW_UNAVAILABLE) != E_OK)
	{
	  zlog_err ("Cannot generate ResvErr message %s %d", __FILE__,
		    __LINE__);
	}
      if (pFilterSpecData->pPsb->InIfIndex == 0)
	{
	  return E_OK;
	}
      if (LinkFilter2PHopList (pFilterSpecData) != E_OK)
	{
	  zlog_err ("An error on LinkFilter2PHopList %s %d", __FILE__,
		    __LINE__);
	}
      return ProcessPHopFilterSpecLists (pRsb, 0);
    }
  zlog_info ("leaving ProcessFailedFFFilterSpec");
  return E_ERR;
}

E_RC
ProcessRsvpResvMessage (RSVP_PKT * pRsvpPkt)
{
  RSB *pRsb;
  RSB_KEY RsbKey;
  zlog_info ("entering ProcessRsvpResvMessage");
  RsvpStatistics.ResvMsgCount++;
  memset (&RsbKey, 0, sizeof (RSB_KEY));
  RsbKey.Session = pRsvpPkt->Session;

  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x",
	     RsbKey.Session.Dest,
	     RsbKey.Session.TunnelId, RsbKey.Session.ExtTunelId);

  if ((pRsb = FindRsb (&RsbKey)) == NULL)
    {
      if ((pRsb = NewRSB (&RsbKey)) == NULL)
	{
	  return E_ERR;
	}
      pRsb->OldPacket.Session = pRsvpPkt->Session;
      pRsb->OldPacket.Style = pRsvpPkt->Style;
    }
  else
    {
      if (memcmp (&pRsb->OldPacket.Style,
		  &pRsvpPkt->Style, sizeof (STYLE_OBJ)))
	{
	  RSVP_PKT RsvpPkt;
	  zlog_err ("Style object differs");

	  memset (&RsvpPkt, 0, sizeof (RSVP_PKT));
	  RsvpPkt.Session = pRsb->RsbKey.Session;
	  RsvpPkt.Style = pRsb->OldPacket.Style;
	  RsvpPkt.pFilterList = pRsvpPkt->pFilterList;
	  RsvpPkt.ErrorSpec.IpAddr = GetRouterId ();
	  RsvpPkt.ErrorSpec.ErrCode = CONFLICTING_RESV_STYLES_ERR_CODE;
	  RsvpPkt.SentRsvpHop.LIH = pRsvpPkt->SentRsvpHop.LIH;
	  if (IpAddrGetByIfIndex
	      (RsvpPkt.SentRsvpHop.LIH, &RsvpPkt.SentRsvpHop.PHop) != E_OK)
	    {
	      zlog_err ("Cannot get IP address by IfIndex");
	      return E_ERR;
	    }
	  if (EncodeAndSendRsvpResvErrMessage
	      (&RsvpPkt, pRsvpPkt->ReceivedRsvpHop.PHop,
	       RsvpPkt.SentRsvpHop.LIH, 255) != E_OK)
	    {
	      zlog_err ("An error on encode/send %s %d", __FILE__, __LINE__);
	    }
	  return E_ERR;
	}
    }
  pRsb->OldPacket.ReceivedRsvpHop = pRsvpPkt->ReceivedRsvpHop;
  pRsb->OldPacket.pIntegrityObj = pRsvpPkt->pIntegrityObj;
  pRsvpPkt->pIntegrityObj = NULL;
  pRsb->OldPacket.pPolicyDataObj = pRsvpPkt->pPolicyDataObj;
  pRsvpPkt->pPolicyDataObj = NULL;
  pRsb->OldPacket.pOpaqueObjList = pRsvpPkt->pOpaqueObjList;
  pRsvpPkt->pOpaqueObjList = NULL;
  pRsb->OldPacket.ResvConf = pRsvpPkt->ResvConf;
  pRsb->OldPacket.TimeValues = pRsvpPkt->TimeValues;

  if (ProcessReceivedFilterSpecs (pRsb, pRsvpPkt) != E_OK)
    {
      zlog_err ("An error on ProceessReceivedFilterSpecs");
      return E_ERR;
    }
  if (pRsb->OldPacket.pFilterList == NULL)
    {
      FreeRSB (pRsb);
      pRsb = NULL;
    }
  FreeRsvpPkt (pRsvpPkt);
  zlog_info ("leaving ProcessRsvpResvMessage");
  return E_OK;
}

static void
PrepareAndSendMsg2TE4SE (RSB * pRsb, EFFECTIVE_FLOW * pEffectiveFlow)
{
  TE_API_MSG msg;
  FILTER_LIST *pFilterList;
  int i;
  FILTER_LIST *pFilterListHead = pEffectiveFlow->pFilterList;

  memset (&msg, 0, sizeof (msg));
  msg.NotificationType = RESV_MSG_NOTIFICATION;
  msg.u.ResvNotification.RsbKey = pRsb->RsbKey;
  msg.u.ResvNotification.SharedExplicit = 1;
  msg.u.ResvNotification.u.FilterDataSE.IfIndex = pEffectiveFlow->IfIndex;
  msg.u.ResvNotification.PleaseReply = pEffectiveFlow->TE_InProcess;

  if (pFilterListHead != NULL)
    {
      if (pFilterListHead->pFilterSpecData != NULL)
	{
	  msg.u.ResvNotification.Ingress =
	    (pFilterListHead->pFilterSpecData->pPsb->InIfIndex == 0);

	  if (pFilterListHead->pFilterSpecData->pPsb->OldPacket.
	      SessionAttributes.CType == SESSION_ATTRIBUTES_RA_IPV4_CTYPE)
	    {
	      msg.u.ResvNotification.u.FilterDataSE.HoldPrio
		=
		pFilterListHead->pFilterSpecData->pPsb->OldPacket.
		SessionAttributes.u.SessAttrRa.HoldPrio;
	      msg.u.ResvNotification.u.FilterDataSE.SetupPrio =
		pFilterListHead->pFilterSpecData->pPsb->OldPacket.
		SessionAttributes.u.SessAttrRa.SetPrio;
	    }
	  else if (pFilterListHead->pFilterSpecData->pPsb->OldPacket.
		   SessionAttributes.CType == SESSION_ATTRIBUTES_IPV4_CTYPE)
	    {
	      msg.u.ResvNotification.u.FilterDataSE.HoldPrio
		=
		pFilterListHead->pFilterSpecData->pPsb->OldPacket.
		SessionAttributes.u.SessAttr.HoldPrio;
	      msg.u.ResvNotification.u.FilterDataSE.SetupPrio =
		pFilterListHead->pFilterSpecData->pPsb->OldPacket.
		SessionAttributes.u.SessAttr.SetPrio;
	    }
	  else
	    {
	      msg.u.ResvNotification.u.FilterDataSE.HoldPrio =
		msg.u.ResvNotification.u.FilterDataSE.SetupPrio = 4;
	    }
	}
    }
  if (pEffectiveFlow->NewFlowSpec.ServHdr.ServHdr ==
      FLOW_SPEC_CTRL_LOAD_SERV_NUMBER)
    {
      msg.u.ResvNotification.u.FilterDataSE.BW =
	pEffectiveFlow->NewFlowSpec.u.CtrlLoad.PeakDataRate;
    }
  else if (pEffectiveFlow->NewFlowSpec.ServHdr.ServHdr ==
	   FLOW_SPEC_GUAR_SERV_NUMBER)
    {
      msg.u.ResvNotification.u.FilterDataSE.BW =
	pEffectiveFlow->NewFlowSpec.u.Guar.CtrlLoad.PeakDataRate;
    }
  for (i = 0, pFilterList = pFilterListHead; pFilterList != NULL;
       pFilterList = pFilterList->next)
    {
      FILTER_SPEC_DATA *pFilterSpecData = pFilterList->pFilterSpecData;
      if (pFilterSpecData != NULL)
	{
	  if ((pFilterSpecData->NewFlowSpecValid) &&
	      (pFilterSpecData->pPsb->TE_InProcess == FALSE))
	    {
	      msg.u.ResvNotification.u.FilterDataSE.FilterDataArraySE[i].
		FilterSpec = pFilterSpecData->FilterSpec;

	      msg.u.ResvNotification.u.FilterDataSE.FilterDataArraySE[i].
		ReceivedLabel = pFilterSpecData->ReceivedLabel.Label;
	      msg.u.ResvNotification.u.FilterDataSE.FilterDataArraySE[i].
		AllocatedLabel = pFilterSpecData->pPsb->Label;
	      i++;
	      zlog_info ("Locking Flow %x %x %x %x %x %s %d",
			 pFilterSpecData->pPsb->pRsb->RsbKey.Session.Dest,
			 pFilterSpecData->pPsb->pRsb->RsbKey.Session.TunnelId,
			 pFilterSpecData->pPsb->pRsb->RsbKey.Session.
			 ExtTunelId, pFilterSpecData->FilterSpec.IpAddr,
			 pFilterSpecData->FilterSpec.LspId, __FILE__,
			 __LINE__);
	      pFilterSpecData->pPsb->TE_InProcess = TRUE;
	    }
	}
    }
  msg.u.ResvNotification.u.FilterDataSE.FilterSpecNumber = i;
  zlog_info ("sending message to TE upon RESV");
  rsvp_send_msg (&msg, sizeof (msg));
}

static void
PrepareAndSendMsg2TE4FF (RSB * pRsb, FILTER_SPEC_DATA * pFilterSpecData)
{
  TE_API_MSG msg;
  FLOW_SPEC_OBJ *pFlowSpecObj;
  memset (&msg, 0, sizeof (msg));
  msg.NotificationType = RESV_MSG_NOTIFICATION;
  msg.u.ResvNotification.RsbKey = pRsb->RsbKey;
  msg.u.ResvNotification.SharedExplicit = 0;
  msg.u.ResvNotification.u.FilterDataFF.IfIndex =
    pFilterSpecData->pPsb->OutIfIndex;
  msg.u.ResvNotification.PleaseReply = pFilterSpecData->pPsb->TE_InProcess;
  if (pFilterSpecData == NULL)
    {
      zlog_err ("pFilterSpecData == NULL %s %d", __FILE__, __LINE__);
      return;
    }
  msg.u.ResvNotification.Ingress = (pFilterSpecData->pPsb->InIfIndex == 0);
  pFlowSpecObj =
    (pFilterSpecData->NewFlowSpecValid) ? &pFilterSpecData->
    NewFlowSpec : &pFilterSpecData->FlowSpec;
  msg.u.ResvNotification.u.FilterDataFF.FilterSpec =
    pFilterSpecData->FilterSpec;
  if (pFilterSpecData->NewFlowSpec.ServHdr.ServHdr ==
      FLOW_SPEC_CTRL_LOAD_SERV_NUMBER)
    {
      msg.u.ResvNotification.u.FilterDataFF.BW =
	pFlowSpecObj->u.CtrlLoad.PeakDataRate;
    }
  else if (pFilterSpecData->NewFlowSpec.ServHdr.ServHdr ==
	   FLOW_SPEC_GUAR_SERV_NUMBER)
    {
      msg.u.ResvNotification.u.FilterDataFF.BW =
	pFlowSpecObj->u.Guar.CtrlLoad.PeakDataRate;
    }
  msg.u.ResvNotification.u.FilterDataFF.ReceivedLabel =
    pFilterSpecData->ReceivedLabel.Label;
  if (pFilterSpecData->pPsb->OldPacket.SessionAttributes.CType ==
      SESSION_ATTRIBUTES_RA_IPV4_CTYPE)
    {
      msg.u.ResvNotification.u.FilterDataFF.HoldPrio
	=
	pFilterSpecData->pPsb->OldPacket.SessionAttributes.u.SessAttrRa.
	HoldPrio;
      msg.u.ResvNotification.u.FilterDataFF.SetupPrio =
	pFilterSpecData->pPsb->OldPacket.SessionAttributes.u.SessAttrRa.
	SetPrio;
    }
  else if (pFilterSpecData->pPsb->OldPacket.SessionAttributes.CType ==
	   SESSION_ATTRIBUTES_IPV4_CTYPE)
    {
      msg.u.ResvNotification.u.FilterDataFF.HoldPrio
	=
	pFilterSpecData->pPsb->OldPacket.SessionAttributes.u.SessAttr.
	HoldPrio;
      msg.u.ResvNotification.u.FilterDataFF.SetupPrio =
	pFilterSpecData->pPsb->OldPacket.SessionAttributes.u.SessAttr.SetPrio;
    }
  zlog_info ("sending message to TE upon RESV FF");
  rsvp_send_msg (&msg, sizeof (msg));
}

void
RsbDequeueAndInvokeMessages (RSB * pRsb)
{
  FILTER_LIST *pFilterList;
  RSVP_PKT_QUEUE *pQueuedItem;
  if (!pRsb)
    return;
  pFilterList = pRsb->OldPacket.pFilterList;
  while (pFilterList != NULL)
    {
      while ((pFilterList->pFilterSpecData->pPsb->TE_InProcess == FALSE) &&
	     (((pFilterList->pFilterSpecData->pEffectiveFlow != NULL)
	       && (pFilterList->pFilterSpecData->pEffectiveFlow->
		   TE_InProcess == FALSE))
	      || (pFilterList->pFilterSpecData->pEffectiveFlow == NULL))
	     &&
	     ((pQueuedItem =
	       DequeueRsvpPacket (&pFilterList->pFilterSpecData->pPsb->
				  packet_queue)) != NULL))
	{
	  RSVP_PKT *pRsvpPkt;
	  uns8 MsgType;
	  uns32 InIfIndex = pQueuedItem->InIfIndex;
	  IPV4_ADDR SourceIp = pQueuedItem->SourceIp;
	  uns8 ttl = pQueuedItem->ttl;
	  pRsvpPkt = pQueuedItem->pRsvpPkt;
	  MsgType = pQueuedItem->MsgType;
	  XFREE (MTYPE_RSVP, pQueuedItem);
	  if (MsgType == PATH_MSG)
	    {
	      ProcessRsvpPathMessage (pRsvpPkt, InIfIndex, SourceIp, ttl);
	    }
	  else if (MsgType == PATH_TEAR_MSG)
	    {
	      ProcessRsvpPathTearMessage (pRsvpPkt, InIfIndex, SourceIp, ttl);
	      return;
	    }
	  else if (MsgType == RESV_MSG)
	    {
	      ProcessRsvpResvMessage (pRsvpPkt);
	    }
	  else if (MsgType == RESV_TEAR_MSG)
	    {
	      ProcessRsvpResvTearMessage (pRsvpPkt);
	    }
	  else if (MsgType == RESV_ERR_MSG)
	    {
	      ProcessRsvpResvErrMessage (pRsvpPkt);
	    }
	  else
	    zlog_err ("Unknown message type %d %s %d", MsgType, __FILE__,
		      __LINE__);
	}
      pFilterList = pFilterList->next;
    }
}

E_RC
ResvTeMsgProc (TE_API_MSG * pMsg)
{
  RSB_KEY RsbKey;
  RSB *pRsb;
  FILTER_LIST *pFilterList;
  int i;
  zlog_info ("response from TE");
  memset (&RsbKey, 0, sizeof (RSB_KEY));
  RsbKey = pMsg->u.ResvNotification.RsbKey;
  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x",
	     RsbKey.Session.Dest,
	     RsbKey.Session.TunnelId, RsbKey.Session.ExtTunelId);
  if ((pRsb =
       (RSB *) patricia_tree_get (&ResbTree, (const uns8 *) &RsbKey)) == NULL)
    {
      zlog_err ("Cannot get RSB %x %x %x %s %d",
		RsbKey.Session.Dest,
		RsbKey.Session.TunnelId,
		RsbKey.Session.ExtTunelId, __FILE__, __LINE__);
      return E_ERR;
    }
  if (pMsg->u.ResvNotification.SharedExplicit)
    {
      for (i = 0;
	   i < pMsg->u.ResvNotification.u.FilterDataSE.FilterSpecNumber; i++)
	{
	  pFilterList = pRsb->OldPacket.pFilterList;
	  while (pFilterList != NULL)
	    {
	      if (memcmp (&pFilterList->pFilterSpecData->FilterSpec,
			  &pMsg->u.ResvNotification.u.FilterDataSE.
			  FilterDataArraySE[i].FilterSpec,
			  sizeof (FILTER_SPEC_OBJ)) == 0)
		{
		  zlog_info ("Found FilterSpec %x %x",
			     pFilterList->pFilterSpecData->FilterSpec.IpAddr,
			     pFilterList->pFilterSpecData->FilterSpec.LspId);
		  break;
		}
	      pFilterList = pFilterList->next;
	    }
	  if ((pFilterList != NULL)
	      && (pFilterList->pFilterSpecData->pPsb->TE_InProcess == TRUE))
	    {
	      zlog_info ("Unlocking FilterSpec %x %x",
			 pFilterList->pFilterSpecData->FilterSpec.IpAddr,
			 pFilterList->pFilterSpecData->FilterSpec.LspId);
	      pFilterList->pFilterSpecData->pPsb->TE_InProcess = FALSE;
	    }
	}
    }
  if (pMsg->u.ResvNotification.rc == FALSE)
    {
      if (pMsg->u.ResvNotification.SharedExplicit)
	{
	  if (ProcessFailedSEFilterSpecsByIfIndex
	      (pRsb, pMsg->u.ResvNotification.u.FilterDataSE.IfIndex) != E_OK)
	    {
	      zlog_err
		("An error on ProcessForwardedSEFilterSpecsByIfIndex %s %d",
		 __FILE__, __LINE__);
	      return E_ERR;
	    }
	}
      else
	{
	  if (ProcessFailedFFFilterSpec
	      (pRsb,
	       &pMsg->u.ResvNotification.u.FilterDataFF.FilterSpec) != E_OK)
	    {
	      zlog_err ("An error on ProcessForwardedFFFilterSpec %s %d",
			__FILE__, __LINE__);
	      return E_ERR;
	    }
	}
      return E_OK;
    }
  if (pMsg->u.ResvNotification.SharedExplicit)
    {
      if (ProcessForwardedSEFilterSpecsByIfIndex
	  (pRsb, pMsg->u.ResvNotification.u.FilterDataSE.IfIndex) != E_OK)
	{
	  zlog_err
	    ("An error on ProcessForwardedSEFilterSpecsByIfIndex %s %d",
	     __FILE__, __LINE__);
	  return E_ERR;
	}
    }
  else
    {
      if (ProcessForwardedFFFilterSpec
	  (pRsb, &pMsg->u.ResvNotification.u.FilterDataFF.FilterSpec) != E_OK)
	{
	  zlog_err ("An error on ProcessForwardedFFFilterSpec %s %d",
		    __FILE__, __LINE__);
	  return E_ERR;
	}
    }
  RsbDequeueAndInvokeMessages (pRsb);
  zlog_info ("done...");
  return E_OK;
}

E_RC
FilterShutDown (FILTER_SPEC_DATA * pFilterSpecData, int Shared)
{
  uns8 Priority;
  zlog_info ("entering FilterShutDown");
  if (pFilterSpecData == NULL)
    {
      zlog_err ("pFilterSpecData == NULL %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  {
    char buffer[80];
    RSB *pRsb;
    pRsb = pFilterSpecData->pPsb->pRsb;
    sprintf (buffer, "Dest %x tunnel %x ext tunnel %x src %x lsp %x",
	     pRsb->RsbKey.Session.Dest,
	     pRsb->RsbKey.Session.TunnelId,
	     pRsb->RsbKey.Session.ExtTunelId,
	     pFilterSpecData->FilterSpec.IpAddr,
	     pFilterSpecData->FilterSpec.LspId);
    zlog_info ("Session and filter: %s", buffer);
  }
  if (StopFilterAgeOutTimer (&pFilterSpecData->AgeOutTimer) != E_OK)
    {
      zlog_err ("Cannot delete timer %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  if (StopBlocadeTimer (&pFilterSpecData->BlocadeTimer) != E_OK)
    {
      zlog_err ("Cannot delete timer %s %d", __FILE__, __LINE__);
      return E_ERR;
    }

  if ((pFilterSpecData->pPsb->InIfIndex != 0) &&
      (pFilterSpecData->pPHopResvRefreshList != NULL))
    {
      zlog_info ("Not Ingress...");

      pFilterSpecData->pPHopResvRefreshList->MustBeProcessed = 1;
      if (pFilterSpecData->pPHopResvRefreshList->pSentBuffer != NULL)
	{
	  XFREE (MTYPE_RSVP,
		 pFilterSpecData->pPHopResvRefreshList->pSentBuffer);
	  pFilterSpecData->pPHopResvRefreshList->pSentBuffer = NULL;
	  pFilterSpecData->pPHopResvRefreshList->SentBufferLen = 0;
	}

      DeleteFilterListNode (&pFilterSpecData->pPHopResvRefreshList->
			    pFilterList, pFilterSpecData);

      if (StopPHopResvRefreshTimer
	  (&pFilterSpecData->pPHopResvRefreshList->ResvRefreshTimer) != E_OK)
	{
	  zlog_err ("Cannot delete timer %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}

      if (pFilterSpecData->pPHopResvRefreshList->pFilterList == NULL)
	{
	  if (DeletePHopResvRefreshList (pFilterSpecData->pPsb->pRsb,
					 pFilterSpecData->
					 pPHopResvRefreshList) != E_OK)
	    {
	      zlog_err ("Cannot delete PHopResvRefreshList item");
	    }
	}
    }
#if 0
  else if (pFilterSpecData->pPsb->InIfIndex != 0)
#else
  else if (pFilterSpecData->pPsb->pRsb != NULL)
#endif
    {
      zlog_info
	("PHopFilterList is NULL while not Ingress (TE may be in progress)");
      PrepareAndSendResvTearNotificationMsg2TE (pFilterSpecData->pPsb->pRsb,
						&pFilterSpecData->FilterSpec);
    }
  if (pFilterSpecData->pPsb->OutIfIndex != 0)
    {
      zlog_info ("Not Egress...");
      if (Shared)
	{
	  if (DeleteFilterListNode
	      (&pFilterSpecData->pEffectiveFlow->pFilterList,
	       pFilterSpecData) != E_OK)
	    {
	      zlog_err
		("Cannot delete filter from effective flow filter list");
	      return E_ERR;
	    }
	  if (pFilterSpecData->pEffectiveFlow->pFilterList == NULL)
	    {
	      if (pFilterSpecData->pPsb->OldPacket.SessionAttributes.CType ==
		  SESSION_ATTRIBUTES_RA_CLASS_TYPE)
		{
		  Priority =
		    pFilterSpecData->pPsb->OldPacket.SessionAttributes.u.
		    SessAttrRa.HoldPrio;
		}
	      else if (pFilterSpecData->pPsb->OldPacket.SessionAttributes.
		       CType == SESSION_ATTRIBUTES_CLASS_TYPE)
		{
		  Priority =
		    pFilterSpecData->pPsb->OldPacket.SessionAttributes.u.
		    SessAttr.HoldPrio;
		}
	      else
		{
		  Priority = 4;
		}
	      PrepareAndSendBWReleaseMsg2TE (pFilterSpecData->pPsb,
					     Priority,
					     pFilterSpecData->pEffectiveFlow->
					     IfIndex, Shared);
	      if (DeleteEffectiveFlow
		  (pFilterSpecData->pPsb->pRsb,
		   pFilterSpecData->pEffectiveFlow) != E_OK)
		{
		  zlog_err ("Cannot delete effective flow list item");
		}
	    }
	  else
	    {
	      pFilterSpecData->pEffectiveFlow->MustBeProcessed = 1;
	    }
	}
      else
	{
	  if (pFilterSpecData->pPsb->OldPacket.SessionAttributes.CType ==
	      SESSION_ATTRIBUTES_RA_CLASS_TYPE)
	    {
	      Priority =
		pFilterSpecData->pPsb->OldPacket.SessionAttributes.u.
		SessAttrRa.HoldPrio;
	    }
	  else if (pFilterSpecData->pPsb->OldPacket.SessionAttributes.CType ==
		   SESSION_ATTRIBUTES_CLASS_TYPE)
	    {
	      Priority =
		pFilterSpecData->pPsb->OldPacket.SessionAttributes.u.SessAttr.
		HoldPrio;
	    }
	  else
	    {
	      Priority = 4;
	    }
	  /* update TE (BW release) */
	  PrepareAndSendBWReleaseMsg2TE (pFilterSpecData->pPsb,
					 Priority,
					 pFilterSpecData->pPsb->OutIfIndex,
					 Shared);
	}
    }
  pFilterSpecData->pPsb->pRsb = NULL;
  pFilterSpecData->pPsb->pFilterSpecData = NULL;
  FreeFilterSpecData (&pFilterSpecData);
  zlog_info ("leaving FilterShutDown");
  return E_OK;
}

E_RC
ForwardResvTearMsg (RSB * pRsb)
{
  RSVP_PKT RsvpPkt;
  PHOP_RESV_REFRESH_LIST *pPHopResvRefreshList = pRsb->pPHopResvRefreshList;

  zlog_info ("entering ForwardResvTearMsg");

  memset (&RsvpPkt, 0, sizeof (RSVP_PKT));

  RsvpPkt.Session = pRsb->RsbKey.Session;
  RsvpPkt.pIntegrityObj = pRsb->OldPacket.pIntegrityObj;
  RsvpPkt.pPolicyDataObj = pRsb->OldPacket.pPolicyDataObj;
  RsvpPkt.Style = pRsb->OldPacket.Style;
  while (pPHopResvRefreshList != NULL)
    {
      if (pPHopResvRefreshList->MustBeProcessed)
	{
	  FILTER_LIST *pFilterList =
	    pPHopResvRefreshList->pFilterList, *pFilterListPrev = NULL;
	  while (pFilterList != NULL)
	    {
	      if (pFilterList->pFilterSpecData != NULL)
		{
		  if (pFilterList->pFilterSpecData->ToBeDeleted)
		    {
		      if (pFilterListPrev == NULL)
			{
			  pPHopResvRefreshList->pFilterList =
			    pPHopResvRefreshList->pFilterList->next;
			}
		      else
			{
			  pFilterListPrev->next = pFilterList->next;
			}
		      pFilterList->next = RsvpPkt.pFilterList;
		      RsvpPkt.pFilterList = pFilterList;
		    }
		  else
		    {
		      pFilterListPrev = pFilterList;
		    }
		}
	      pFilterList = pFilterList->next;
	    }
	  if (RsvpPkt.pFilterList != NULL)
	    {
	      if (pPHopResvRefreshList->InIfIndex != 0)
		{
		  if (IpAddrGetByIfIndex
		      (pPHopResvRefreshList->InIfIndex,
		       &RsvpPkt.SentRsvpHop.PHop) != E_OK)
		    {
		      zlog_err ("Cannot set RSVP HOP %s %d", __FILE__,
				__LINE__);
		      return E_ERR;
		    }
		  RsvpPkt.SentRsvpHop.LIH = pPHopResvRefreshList->PHop.LIH;
		  if (EncodeAndSendRsvpResvTearMessage (&RsvpPkt,
							pPHopResvRefreshList->
							PHop.PHop,
							pPHopResvRefreshList->
							InIfIndex, 1) != E_OK)
		    {
		      zlog_err ("cannot encode/send RESV_TEAR message");
		    }
		}
	      else
		{
		  zlog_info ("%s %d", __FILE__, __LINE__);
		}
	      memset (&RsvpPkt.SentRsvpHop, 0, sizeof (RSVP_HOP_OBJ));
	      pFilterListPrev = RsvpPkt.pFilterList;
	      while (pFilterListPrev != NULL)
		{
		  pFilterList = pFilterListPrev->next;
		  XFREE (MTYPE_RSVP, pFilterListPrev);
		  pFilterListPrev = pFilterList;
		}
	      RsvpPkt.pFilterList = NULL;
	    }
	  //pPHopResvRefreshList->MustBeProcessed = 1;
	}
      pPHopResvRefreshList = pPHopResvRefreshList->next;
    }
  zlog_info ("leaving ForwardResvTearMsg");
  return E_OK;
}

E_RC
ProcessRsvpResvTearMessage (RSVP_PKT * pRsvpPkt)
{
  RSB *pRsb;
  RSB_KEY RsbKey;
  FILTER_SPEC_DATA *pFilterSpecData, *pFilterSpecData2;
  FILTER_LIST *pFilterList, *pFilterListPrev =
    NULL, *pFilterList2, *pFilterList2BeDeleted =
    NULL, *pFilterListPrev2, *pFilterListNext;
  uns8 ItemExtracted;
  int Shared = 0;
  zlog_info ("entering ProcessRsvpResvTearMessage");
  RsvpStatistics.ResvTearMsgCount++;
  memset (&RsbKey, 0, sizeof (RSB_KEY));
  RsbKey.Session = pRsvpPkt->Session;

  if ((pRsb = FindRsb (&RsbKey)) == NULL)
    {
      zlog_info ("leaving ProcessRsvpResvTearMessage");
      FreeRsvpPkt (pRsvpPkt);
      return E_OK;
    }

  if ((pRsb->OldPacket.Style.OptionVector2 & 0x001F) == SE_STYLE_BITS)
    {
      Shared = 1;
    }
  /* First - for the list of FILTER_SPECs to be deleted */
  zlog_info ("Determining FilterSpecs to be deleted...");
  pFilterList = pRsvpPkt->pFilterList;
  while (pFilterList != NULL)
    {
      pFilterSpecData = pFilterList->pFilterSpecData;
      pFilterListNext = pFilterList->next;
      ItemExtracted = FALSE;
      if (pFilterSpecData != NULL)
	{
	  zlog_info ("FilterSpec %x %x", pFilterSpecData->FilterSpec.IpAddr,
		     pFilterSpecData->FilterSpec.LspId);
	  pFilterList2 = pRsb->OldPacket.pFilterList;
	  pFilterListPrev2 = NULL;
	  while (pFilterList2 != NULL)
	    {
	      pFilterSpecData2 = pFilterList2->pFilterSpecData;
	      if (pFilterSpecData2 != NULL)
		{
		  zlog_info ("FilterSpec2 %x %x",
			     pFilterSpecData2->FilterSpec.IpAddr,
			     pFilterSpecData2->FilterSpec.LspId);
		  if (memcmp
		      (&pFilterSpecData->FilterSpec,
		       &pFilterSpecData2->FilterSpec,
		       sizeof (FILTER_SPEC_OBJ)) == 0)
		    {
		      if ((pFilterSpecData2->pPsb->TE_InProcess == TRUE) ||
			  ((pFilterSpecData2->pEffectiveFlow)
			   && (pFilterSpecData2->pEffectiveFlow->
			       TE_InProcess)))
			{
			  RSVP_PKT_QUEUE *pQueuedItem;
			  RSVP_PKT *pSavedRsvpPkt;
			  if (pFilterListPrev == NULL)
			    {
			      pRsvpPkt->pFilterList = pFilterListNext;
			    }
			  else
			    {
			      pFilterListPrev->next = pFilterListNext;
			    }
			  ItemExtracted = TRUE;
			  if ((pSavedRsvpPkt =
			       (RSVP_PKT *) XMALLOC (MTYPE_RSVP,
						     sizeof (RSVP_PKT))) ==
			      NULL)
			    {
			      zlog_err ("memory allocation failed %s %d",
					__FILE__, __LINE__);
			      return E_ERR;
			    }
			  memcpy (pSavedRsvpPkt, pRsvpPkt, sizeof (RSVP_PKT));
			  pSavedRsvpPkt->pFilterList = pFilterList;
			  pSavedRsvpPkt->pFilterList->next = NULL;
			  pSavedRsvpPkt->pIntegrityObj = NULL;	/* temp. */
			  pSavedRsvpPkt->pPolicyDataObj = NULL;	/* temp. */
			  pSavedRsvpPkt->pOpaqueObjList = NULL;	/* temp. */
			  pSavedRsvpPkt->ReceivedRro.rr = NULL;	/* TEMP!!! */
			  if ((pQueuedItem =
			       (RSVP_PKT_QUEUE *) XMALLOC (MTYPE_RSVP,
							   sizeof
							   (RSVP_PKT_QUEUE)))
			      == NULL)
			    {
			      zlog_err ("memory allocation failed %s %d",
					__FILE__, __LINE__);
			      return E_ERR;
			    }

			  pQueuedItem->MsgType = RESV_TEAR_MSG;
			  pQueuedItem->pRsvpPkt = pSavedRsvpPkt;
			  pQueuedItem->next = NULL;
			  if (EnqueueRsvpPacket
			      (pQueuedItem,
			       &pFilterSpecData2->pPsb->packet_queue) != E_OK)
			    {
			      zlog_err ("Cannot enqueue packet %s %d",
					__FILE__, __LINE__);
			      return E_ERR;
			    }
			  zlog_info ("Queued...");
			  break;
			}
		      if (pFilterSpecData2->pPHopResvRefreshList != 0)
			{
			  pFilterSpecData2->ToBeDeleted = 1;
			  pFilterSpecData2->pPHopResvRefreshList->
			    MustBeProcessed = 1;
			}

		      if (pFilterListPrev2 == NULL)
			{
			  pRsb->OldPacket.pFilterList =
			    pRsb->OldPacket.pFilterList->next;
			}
		      else
			{
			  pFilterListPrev2->next = pFilterList2->next;
			}
		      pFilterList2->next = pFilterList2BeDeleted;
		      pFilterList2BeDeleted = pFilterList2;
		      zlog_info ("Inserted to deletion list...");
		      break;
		    }
		}
	      else
		{
		  zlog_info ("FilterSpec - FlowSpecData2 is NULL!!!");
		}
	      pFilterListPrev2 = pFilterList2;
	      pFilterList2 = pFilterList2->next;
	    }
	}
      else
	{
	  zlog_info ("FilterSpec - FlowSpecData is NULL!!!");
	}
      if (ItemExtracted == FALSE)
	{
	  pFilterListPrev = pFilterList;
	}
      pFilterList = pFilterListNext;
    }

  if (ForwardResvTearMsg (pRsb) != E_OK)
    {
      zlog_err ("an error on ForwardResvTearMsg");
    }

  pFilterListPrev = pFilterList2BeDeleted;
  while (pFilterListPrev != NULL)
    {
      PSB *pPsb;
      pFilterList = pFilterListPrev->next;
      pFilterSpecData = pFilterListPrev->pFilterSpecData;
      pPsb = pFilterSpecData->pPsb;
      if (FilterShutDown (pFilterSpecData, Shared) != E_OK)
	{
	  zlog_err ("An error in FilterShutDown %s %d", __FILE__, __LINE__);
	}
      XFREE (MTYPE_RSVP, pFilterListPrev);
      pFilterListPrev = pFilterList;
    }

  if ((pRsb->OldPacket.pFilterList == NULL) &&
      ((pRsb->pEffectiveFlow != NULL) ||
       (pRsb->pPHopResvRefreshList != NULL)))
    {
      zlog_err ("Cleanup was not completed properly %s %d", __FILE__,
		__LINE__);
    }

  if (pRsb->OldPacket.pFilterList != NULL)
    {
      if (Shared)
	{
	  if (ProcessEffectiveFlows (pRsb) != E_OK)
	    {
	      zlog_err ("An error in ProcessEffectiveFlows %s %d", __FILE__,
			__LINE__);
	    }
	}
      /* update TE (BW release) */
      if (ProcessPHopFilterSpecLists (pRsb, Shared) != E_OK)
	{
	  zlog_err ("An error in ProcessPHopFilterSpecLists %s %d", __FILE__,
		    __LINE__);
	}
    }
  else
    {
      FreeRSB (pRsb);
    }
  FreeRsvpPkt (pRsvpPkt);
  zlog_info ("leaving ProcessRsvpResvTearMessage");
  return E_OK;
}

typedef struct IfList
{
  uns32 IfIndex;
  IPV4_ADDR NHop;
  uns8 ttl;
  FILTER_LIST *pFilterList;
  struct IfList *next;
} IF_LIST;

E_RC
ProcessRsvpResvErrMessage (RSVP_PKT * pRsvpPkt)
{
  RSB *pRsb;
  RSB_KEY RsbKey;
  FILTER_LIST *pFilterList, *pFilterList2, *pFilterListNext,
    *pFilterListPrev = NULL;
  IF_LIST *pIfList = NULL, *pIfListEntry, *pIfListEntryPrev = NULL;
  uns8 Shared = 0;
  uns8 ItemExtracted;
  RSVP_PKT RsvpPkt;
  zlog_info ("entering ProcessRsvpResvErrMessage");
  RsvpStatistics.ResvErrMsgCount++;
  memset (&RsbKey, 0, sizeof (RSB_KEY));

  RsbKey.Session = pRsvpPkt->Session;

  if ((pRsb = FindRsb (&RsbKey)) == NULL)
    {
      zlog_err ("Cannot find RSB");
      FreeRsvpPkt (pRsvpPkt);
      return E_ERR;
    }
  if ((pRsb->OldPacket.Style.OptionVector2 & 0x001F) == SE_STYLE_BITS)
    {
      Shared = 1;
    }

  pFilterList = pRsvpPkt->pFilterList;
  while (pFilterList != NULL)
    {
      FILTER_SPEC_DATA *pFilterSpecData = pFilterList->pFilterSpecData;
      pFilterListNext = pFilterList->next;
      ItemExtracted = FALSE;
      if (pFilterSpecData == NULL)
	{
	  pFilterList = pFilterList->next;
	  continue;
	}
      pFilterList2 = pRsb->OldPacket.pFilterList;
      while (pFilterList2 != NULL)
	{
	  if (pFilterList2->pFilterSpecData == NULL)
	    {
	      pFilterList2 = pFilterList2->next;
	      continue;
	    }
	  if ((pFilterSpecData->FilterSpec.IpAddr ==
	       pFilterList2->pFilterSpecData->FilterSpec.IpAddr)
	      && (pFilterSpecData->FilterSpec.LspId ==
		  pFilterList2->pFilterSpecData->FilterSpec.LspId))
	    {
	      if ((pFilterList2->pFilterSpecData->pPsb->TE_InProcess == TRUE)
		  || ((pFilterList2->pFilterSpecData->pEffectiveFlow)
		      && (pFilterList2->pFilterSpecData->pEffectiveFlow->
			  TE_InProcess == TRUE)))
		{
		  RSVP_PKT_QUEUE *pQueuedItem;
		  RSVP_PKT *pSavedRsvpPkt;
		  if (pFilterListPrev == NULL)
		    {
		      pRsvpPkt->pFilterList = pFilterListNext;
		    }
		  else
		    {
		      pFilterListPrev->next = pFilterListNext;
		    }
		  ItemExtracted = TRUE;
		  if ((pSavedRsvpPkt =
		       (RSVP_PKT *) XMALLOC (MTYPE_RSVP,
					     sizeof (RSVP_PKT))) == NULL)
		    {
		      zlog_err ("memory allocation failed %s %d", __FILE__,
				__LINE__);
		      return E_ERR;
		    }
		  memcpy (pSavedRsvpPkt, pRsvpPkt, sizeof (RSVP_PKT));
		  pSavedRsvpPkt->pFilterList = pFilterList;
		  pSavedRsvpPkt->pFilterList->next = NULL;
		  pSavedRsvpPkt->pIntegrityObj = NULL;	/* temp. */
		  pSavedRsvpPkt->pPolicyDataObj = NULL;	/* temp. */
		  pSavedRsvpPkt->pOpaqueObjList = NULL;	/* temp. */
		  pSavedRsvpPkt->ReceivedRro.rr = NULL;	/* TEMP!!! */
		  if ((pQueuedItem =
		       (RSVP_PKT_QUEUE *) XMALLOC (MTYPE_RSVP,
						   sizeof (RSVP_PKT_QUEUE)))
		      == NULL)
		    {
		      zlog_err ("memory allocation failed %s %d", __FILE__,
				__LINE__);
		      return E_ERR;
		    }
		  pQueuedItem->MsgType = RESV_ERR_MSG;
		  pQueuedItem->pRsvpPkt = pSavedRsvpPkt;
		  pQueuedItem->next = NULL;
		  if (EnqueueRsvpPacket
		      (pQueuedItem,
		       &pFilterList2->pFilterSpecData->pPsb->packet_queue) !=
		      E_OK)
		    {
		      zlog_err ("Cannot enqueue packet %s %d", __FILE__,
				__LINE__);
		      return E_ERR;
		    }
		  pFilterList2 = NULL;
		}
	      break;
	    }
	  pFilterList2 = pFilterList2->next;
	}
      if (pFilterList2 != NULL)
	{
	  uns32 IfIndex = pFilterList2->pFilterSpecData->pPsb->OutIfIndex;
	  IPV4_ADDR NHop = pFilterList2->pFilterSpecData->pPsb->NextHop;
	  uns8 ttl = pFilterList2->pFilterSpecData->pPsb->ttl;
	  if (IfIndex != 0)
	    {
	      pIfListEntry = pIfList;
	      while (pIfListEntry != NULL)
		{
		  if (pIfListEntry->IfIndex == IfIndex)
		    {
		      break;
		    }
		  pIfListEntryPrev = pIfListEntry;
		  pIfListEntry = pIfListEntry->next;
		}
	      if (pIfListEntry == NULL)
		{
		  if ((pIfListEntry =
		       (IF_LIST *) XMALLOC (MTYPE_RSVP,
					    sizeof (IF_LIST))) == NULL)
		    {
		      zlog_err ("Cannot allocate memory %s %d", __FILE__,
				__LINE__);
		      FreeRsvpPkt (pRsvpPkt);
		      return E_ERR;
		    }
		  memset (pIfListEntry, 0, sizeof (IF_LIST));
		  pIfListEntry->IfIndex = IfIndex;
		  pIfListEntry->NHop = NHop;
		  pIfListEntry->ttl = ttl;
		  if (pIfListEntryPrev == NULL)
		    {
		      pIfList = pIfListEntry;
		    }
		  else
		    {
		      pIfListEntryPrev->next = pIfListEntry;
		    }
		}
	      if (NewFilterListNode
		  (&pIfListEntry->pFilterList, pFilterSpecData) != E_OK)
		{
		  zlog_err ("An error on NewFilterListNode");
		  FreeRsvpPkt (pRsvpPkt);
		  return E_ERR;
		}
	      if ((Shared) &&
		  (pRsvpPkt->ErrorSpec.ErrCode ==
		   ADMISSION_CTRL_FAILURE_ERR_CODE))
		{
		  pFilterList2->pFilterSpecData->pEffectiveFlow->
		    MustBeProcessed = 1;
		}
	    }
	  if (pRsvpPkt->ErrorSpec.ErrCode == ADMISSION_CTRL_FAILURE_ERR_CODE)
	    {
	      if (StartBlocadeTimer
		  (pFilterList2->pFilterSpecData->BlocadeValue,
		   &pFilterList2->pFilterSpecData->BlocadeTimer,
		   pFilterList2->pFilterSpecData) != E_OK)
		{
		  zlog_err ("Cannot add timer");
		  FreeRsvpPkt (pRsvpPkt);
		  return E_ERR;
		}
	      pFilterList2->pFilterSpecData->Blocked = TRUE;
	      memcpy (&pFilterList2->pFilterSpecData->BlockadeFlowSpec,
		      &pFilterList->pFilterSpecData->NewFlowSpec,
		      sizeof (FLOW_SPEC_OBJ));
	      if (pFilterList2->pFilterSpecData->pPsb->InIfIndex != 0)
		{
		  pFilterList2->pFilterSpecData->pPHopResvRefreshList->
		    MustBeProcessed = 1;
		}
	    }
	}
      if (ItemExtracted == FALSE)
	{
	  pFilterListPrev = pFilterList;
	}
      pFilterList = pFilterListNext;
    }
  if (pRsvpPkt->ErrorSpec.ErrCode == ADMISSION_CTRL_FAILURE_ERR_CODE)
    {
      if (Shared)
	{
	  if (ProcessEffectiveFlows (pRsb) != E_OK)
	    {
	      zlog_err ("An error on ProcessEffectiveFlows %s %d", __FILE__,
			__LINE__);
	    }
	}
      else
	{
	  pFilterList = pRsvpPkt->pFilterList;
	  while (pFilterList != NULL)
	    {
	      uns8 Priority;
	      if (pFilterList->pFilterSpecData->pPsb->OldPacket.
		  SessionAttributes.CType == SESSION_ATTRIBUTES_RA_CLASS_TYPE)
		{
		  Priority =
		    pFilterList->pFilterSpecData->pPsb->OldPacket.
		    SessionAttributes.u.SessAttrRa.HoldPrio;
		}
	      else if (pFilterList->pFilterSpecData->pPsb->OldPacket.
		       SessionAttributes.CType ==
		       SESSION_ATTRIBUTES_CLASS_TYPE)
		{
		  Priority =
		    pFilterList->pFilterSpecData->pPsb->OldPacket.
		    SessionAttributes.u.SessAttr.HoldPrio;
		}
	      else
		{
		  Priority = 4;
		}
	      PrepareAndSendBWReleaseMsg2TE (pFilterList->pFilterSpecData->
					     pPsb, Priority,
					     pFilterList->pFilterSpecData->
					     pPsb->OutIfIndex, Shared);
	      pFilterList = pFilterList->next;
	    }
	}
      if (ProcessPHopFilterSpecLists (pRsb, Shared) != E_OK)
	{
	  zlog_err ("An error on ProcessPHopFilterSpecLists %s %d", __FILE__,
		    __LINE__);
	}
    }

  pIfListEntry = pIfList;
  memset (&RsvpPkt, 0, sizeof (RSVP_PKT));
  RsvpPkt.Session = RsbKey.Session;
  RsvpPkt.Style = pRsb->OldPacket.Style;
  RsvpPkt.ErrorSpec = pRsvpPkt->ErrorSpec;
  while (pIfListEntry != NULL)
    {
      RsvpPkt.SentRsvpHop.LIH = pIfListEntry->IfIndex;
      if (IpAddrGetByIfIndex
	  (pIfListEntry->IfIndex, &RsvpPkt.SentRsvpHop.PHop) != E_OK)
	{
	  zlog_err ("Cannot get IP address by IfIndex");
	  pIfListEntry = pIfListEntry->next;
	  continue;
	}
      RsvpPkt.pFilterList = pIfListEntry->pFilterList;
      if (EncodeAndSendRsvpResvErrMessage
	  (&RsvpPkt, pIfListEntry->NHop, pIfListEntry->IfIndex,
	   pIfListEntry->ttl) != E_OK)
	{
	  zlog_err ("An error on encode/send %s %d", __FILE__, __LINE__);
	}
      pFilterList = pIfListEntry->pFilterList;
      while (pFilterList != NULL)
	{
	  pFilterList2 = pFilterList->next;
	  XFREE (MTYPE_RSVP, pFilterList);
	  pFilterList = pFilterList2;
	}
      pIfList = pIfListEntry->next;
      XFREE (MTYPE_RSVP, pIfListEntry);
      pIfListEntry = pIfList;
    }
  FreeRsvpPkt (pRsvpPkt);
  zlog_info ("leaving ProcessRsvpResvErrMessage");
  return E_OK;
}

static void
PrepareAndSendBWReleaseMsg2TE (PSB * pPsb, uns8 Priority, uns32 IfIndex,
			       uns8 Shared)
{
  TE_API_MSG msg;

  memset (&msg, 0, sizeof (msg));
  msg.NotificationType = BW_RELEASE_NOTIFICATION;
  if (Shared)
    {
      msg.u.BwRelease.PsbKey.Session = pPsb->PsbKey.Session;
    }
  else
    {
      msg.u.BwRelease.PsbKey = pPsb->PsbKey;
    }
  msg.u.BwRelease.IfIndex = IfIndex;
  msg.u.BwRelease.HoldPrio = Priority;	/*pFilterSpecData->pPsb->OldPacket.SessionAttributes.u.SessAttrRa.HoldPrio */
  zlog_info ("sending message to TE upon RESV");
  rsvp_send_msg (&msg, sizeof (msg));
}

static void
PrepareAndSendResvTearNotificationMsg2TE (RSB * pRsb,
					  FILTER_SPEC_OBJ * pFilterSpec)
{
  TE_API_MSG msg;

  memset (&msg, 0, sizeof (msg));
  msg.NotificationType = RESV_TEAR_NOTIFICATION;
  msg.u.ResvTearNotification.RsbKey = pRsb->RsbKey;
  msg.u.ResvTearNotification.FilterSpec = *pFilterSpec;
  zlog_info ("sending message to TE upon RESV");
  rsvp_send_msg (&msg, sizeof (msg));
}

void
PreemptFlow (TE_API_MSG * pMsg)
{
  RSB *pRsb;
  PSB *pPsb;
  RSB_KEY RsbKey;
  FILTER_LIST *pFilterList, *pFilterList2BeDeleted = NULL, *pFilterListPrev =
    NULL;
  RSVP_PKT RsvpPkt;
  FILTER_SPEC_DATA *pFilterSpecData;
  int Shared = 0;
  IF_LIST *pIfList = NULL, *pIfListEntry, *pIfListEntryPrev = NULL;

  zlog_info ("entering PreemptFlow");

  memset (&RsbKey, 0, sizeof (RSB_KEY));
  RsbKey = pMsg->u.PreemptFlow.RsbKey;
  if ((pRsb = FindRsb (&RsbKey)) == NULL)
    {
      zlog_err ("Cannot find RSB %s %d", __FILE__, __LINE__);
      return;
    }
  if ((pRsb->OldPacket.Style.OptionVector2 & 0x1F) == SE_STYLE_BITS)
    {
      Shared = 1;
    }
  memset (&RsvpPkt, 0, sizeof (RSVP_PKT));
  RsvpPkt.Session = RsbKey.Session;
  RsvpPkt.ErrorSpec.IpAddr = GetRouterId ();
  RsvpPkt.ErrorSpec.ErrCode = ADMISSION_CTRL_FAILURE_ERR_CODE;
  RsvpPkt.ErrorSpec.ErrVal = BW_UNAVAILABLE;
  pFilterList = pRsb->OldPacket.pFilterList;
  if (!pMsg->u.PreemptFlow.FilterSpecValid)
    {
      pFilterList2BeDeleted = pFilterList;
      pRsb->OldPacket.pFilterList = NULL;
    }
  while (pFilterList != NULL)
    {
      pFilterSpecData = pFilterList->pFilterSpecData;
      if (((pMsg->u.PreemptFlow.FilterSpecValid) &&
	   (memcmp (&pFilterSpecData->FilterSpec,
		    &pMsg->u.PreemptFlow.FilterSpec,
		    sizeof (FILTER_SPEC_OBJ)) == 0)) ||
	  (!pMsg->u.PreemptFlow.FilterSpecValid))
	{
	  uns32 IfIndex = pFilterSpecData->pPsb->OutIfIndex;
	  IPV4_ADDR NHop = pFilterSpecData->pPsb->NextHop;
	  uns8 ttl = pFilterSpecData->pPsb->ttl;

	  if (IfIndex != 0)
	    {
	      pIfListEntry = pIfList;
	      while (pIfListEntry != NULL)
		{
		  if (pIfListEntry->IfIndex == IfIndex)
		    break;
		  pIfListEntryPrev = pIfListEntry;
		  pIfListEntry = pIfListEntry->next;
		}
	      if (pIfListEntry == NULL)
		{
		  if ((pIfListEntry =
		       (IF_LIST *) XMALLOC (MTYPE_RSVP,
					    sizeof (IF_LIST))) == NULL)
		    {
		      zlog_err ("Cannot allocate memory %s %d", __FILE__,
				__LINE__);
		      return;
		    }
		  memset (pIfListEntry, 0, sizeof (IF_LIST));
		  pIfListEntry->IfIndex = IfIndex;
		  pIfListEntry->NHop = NHop;
		  pIfListEntry->ttl = ttl;
		  if (NewFilterListNode
		      (&pIfListEntry->pFilterList, pFilterSpecData) != E_OK)
		    {
		      zlog_err ("An error on NewFilterListNode");
		      return;
		    }
		  if (pIfListEntryPrev == NULL)
		    {
		      pIfList = pIfListEntry;
		    }
		  else
		    {
		      pIfListEntryPrev->next = pIfListEntry;
		    }
		}
	      if (Shared)
		{
		  pFilterSpecData->pEffectiveFlow->MustBeProcessed = 1;
		}
	    }

	  if (pFilterSpecData->pPsb->InIfIndex != 0)
	    {
	      if (GeneratePathErrMessage
		  (pFilterSpecData->pPsb, POLICY_CTRL_FAILURE_ERR_CODE,
		   0) != E_OK)
		{
		  zlog_err ("Cannot encode/send PathErr message %s %d",
			    __FILE__, __LINE__);
		}
	      pFilterSpecData->pPHopResvRefreshList->MustBeProcessed = 1;
	    }

	  if (pMsg->u.PreemptFlow.FilterSpecValid)
	    {
	      if (pFilterListPrev == NULL)
		{
		  pRsb->OldPacket.pFilterList =
		    pRsb->OldPacket.pFilterList->next;
		}
	      else
		{
		  pFilterListPrev->next = pFilterList->next;
		}
	      pFilterList->next = pFilterList2BeDeleted;
	      pFilterList2BeDeleted = pFilterList;
	      break;
	    }
	}
      pFilterListPrev = pFilterList;
      pFilterList = pFilterList->next;
    }
  memset (&RsvpPkt, 0, sizeof (RSVP_PKT));
  RsvpPkt.Session = RsbKey.Session;
  RsvpPkt.Style = pRsb->OldPacket.Style;
  pIfListEntry = pIfList;
  while (pIfListEntry != NULL)
    {
      RsvpPkt.pFilterList = pIfListEntry->pFilterList;
      if (EncodeAndSendRsvpResvErrMessage (&RsvpPkt,
					   pIfListEntry->NHop,
					   pIfListEntry->IfIndex,
					   pIfListEntry->ttl) != E_OK)
	{
	  zlog_err ("Cannot encode/send ResvErr message %s %d", __FILE__,
		    __LINE__);
	}
      pIfListEntry = pIfListEntry->next;
    }
  pIfListEntry = pIfList;
  while (pIfListEntry != NULL)
    {
      pFilterListPrev = pIfListEntry->pFilterList;
      while (pFilterListPrev != NULL)
	{
	  pFilterList = pFilterListPrev->next;
	  XFREE (MTYPE_RSVP, pFilterListPrev);
	  pFilterListPrev = pFilterList;
	}
      pIfList = pIfListEntry->next;
      XFREE (MTYPE_RSVP, pIfListEntry);
      pIfListEntry = pIfList;
    }
  pFilterListPrev = pFilterList2BeDeleted;
  while (pFilterListPrev != NULL)
    {
      pFilterList = pFilterListPrev->next;
      pFilterSpecData = pFilterListPrev->pFilterSpecData;
      pPsb = pFilterSpecData->pPsb;
      if (FilterShutDown (pFilterSpecData, Shared) != E_OK)
	{
	  zlog_err ("An error in FilterShutDown %s %d", __FILE__, __LINE__);
	}
      if (DeletePsb (pPsb) != E_OK)
	{
	  zlog_err ("Cannot delete PSB %s %d", __FILE__, __LINE__);
	}
      XFREE (MTYPE_RSVP, pFilterListPrev);
      pFilterListPrev = pFilterList;
    }

  if (pRsb->OldPacket.pFilterList != NULL)
    {
      if (Shared)
	{
	  if (ProcessEffectiveFlows (pRsb) != E_OK)
	    {
	      zlog_err ("An error in ProcessEffectiveFlows %s %d", __FILE__,
			__LINE__);
	    }
	}
      /* update TE (BW release) */
      if (ProcessPHopFilterSpecLists (pRsb, Shared) != E_OK)
	{
	  zlog_err ("An error in ProcessPHopFilterSpecLists %s %d", __FILE__,
		    __LINE__);
	}
    }
  else
    {
      FreeRSB (pRsb);
    }
  zlog_info ("leaving PreemptFlow");
}
