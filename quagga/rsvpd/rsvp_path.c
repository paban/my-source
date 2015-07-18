/* Module:   rsvp_path.c
   Contains: RSVP PATH, PATH TEAR and PATH ERROR message 
   processing functions.
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "rsvp.h"
#include "thread.h"

uns32 PathRefreshInterval = 30;	/* sec */
uns32 RefreshMultiple = /*3 */ 12;

extern RSVP_STATISTICS RsvpStatistics;
extern struct thread_master *master;

static PATRICIA_TREE PsbTree;

static void PrepareAndSendMsg2TE (PSB * pPsb);
static E_RC StartPathAgeOutTimer (uns32 time, struct thread **pTimerId,
				  void *data);
static E_RC StopPathAgeOutTimer (struct thread **pTimerId);
static E_RC StartPathRefreshTimer (uns32 time, struct thread **pTimerId,
				   void *data);
static E_RC StopPathRefreshTimer (struct thread **pTimerId);
static void PrepareAndSendLabelReleaseMsg2TE (PSB * pPsb);
static void PrepareAndSendPathErrNotificationMsg2TE (PSB * pPsb,
						     ERR_SPEC_OBJ *
						     pErrSpecObj);

E_RC
InitRsvpPathMessageProcessing ()
{
  PATRICIA_PARAMS params;

  memset (&params, 0, sizeof (PATRICIA_PARAMS));
  params.key_size = sizeof (PSB_KEY);
  if (patricia_tree_init (&PsbTree, &params) != E_OK)
    {
      zlog_err ("Cannot initiate PSB tree");
      return E_ERR;
    }
  return E_OK;
}

PSB *
GetNextPSB (PSB_KEY * pPsbKey)
{
  return (PSB *) patricia_tree_getnext (&PsbTree, (const uns8 *) pPsbKey);
}

PSB *
FindPsb (PSB_KEY * pPsbKey)
{
  return (PSB *) patricia_tree_get (&PsbTree, (uns8 *) pPsbKey);
}

PSB *
NewPsb (PSB_KEY * pPsbKey)
{
  PSB *pPsb = (PSB *) XMALLOC (MTYPE_RSVP, sizeof (PSB));

  if (pPsb == NULL)
    return NULL;
  memset (pPsb, 0, sizeof (PSB));
  pPsb->PsbKey = *pPsbKey;
  pPsb->Node.key_info = (uns8 *) & pPsb->PsbKey;
  if (patricia_tree_add (&PsbTree, &pPsb->Node) != E_OK)
    {
      XFREE (MTYPE_RSVP, pPsb);
      zlog_err ("Cannot add node to patricia tree %s %d", __FILE__, __LINE__);
      return NULL;
    }
  RsvpStatistics.NewPsbCount++;
  return pPsb;
}

E_RC
RemovePsb (PSB_KEY * pPsbKey)
{
  PSB *pPsb = FindPsb (pPsbKey);

  if (pPsb == NULL)
    {
      zlog_err ("Cannot get PSB %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  if (patricia_tree_del (&PsbTree, &pPsb->Node) != E_OK)
    {
      zlog_err ("Cannot delete node from patricia %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  return E_OK;
}

void
PsbDequeueAndInvokeMessages (PSB * pPsb)
{
  RSVP_PKT_QUEUE *pQueuedItem;
  if (!pPsb)
    return;

  while ((pPsb->TE_InProcess == FALSE) &&
	 (((pPsb->pFilterSpecData != NULL) &&
	   (pPsb->pFilterSpecData->pEffectiveFlow != NULL) &&
	   (pPsb->pFilterSpecData->pEffectiveFlow->TE_InProcess == FALSE)) ||
	  ((pPsb->pFilterSpecData != NULL)
	   && (pPsb->pFilterSpecData->pEffectiveFlow == NULL))
	  || (pPsb->pFilterSpecData == NULL))
	 && ((pQueuedItem = DequeueRsvpPacket (&pPsb->packet_queue)) != NULL))
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
}

static int RsvpPathRefreshTimer (struct thread *);

E_RC
RsvpPathRefresh (PSB * pPsb)
{
  E_RC rc = E_OK;
  zlog_info ("entering RsvpPathRefresh");
  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x .Src %x .LspId %x",
	     pPsb->PsbKey.Session.Dest,
	     pPsb->PsbKey.Session.TunnelId,
	     pPsb->PsbKey.Session.ExtTunelId,
	     pPsb->PsbKey.SenderTemplate.IpAddr,
	     pPsb->PsbKey.SenderTemplate.LspId);
  if ((pPsb->pSentBuffer == NULL) || (pPsb->SentBufferLen == 0))
    {
      if (EncodeAndSendRsvpPathMessage (&pPsb->OldPacket,
					pPsb->NextHop,
					pPsb->OutIfIndex,
					pPsb->ttl - 1,
					&pPsb->pSentBuffer,
					&pPsb->SentBufferLen) != E_OK)
	{
	  zlog_err ("Cannot encode/send message");
	  rc = E_ERR;
	}
    }
  else
    {
      if (SendRawData
	  (pPsb->pSentBuffer, pPsb->SentBufferLen, pPsb->NextHop,
	   pPsb->OutIfIndex, pPsb->ttl - 1, TRUE) != E_OK)
	{
	  zlog_err ("Cannot send raw data %s %d", __FILE__, __LINE__);
	  rc = E_ERR;
	}
    }
  if (StopPathRefreshTimer (&pPsb->PathRefreshTimer) != E_OK)
    {
      zlog_err ("Cannot stop PathRefreshTimer %s %d", __FILE__, __LINE__);
      return E_ERR;
    }

  if (StartPathRefreshTimer
      (pPsb->RefreshValue, &pPsb->PathRefreshTimer, pPsb) != E_OK)
    {
      zlog_err ("Cannot add timer %s %d", __FILE__, __LINE__);
      rc = E_ERR;
    }
  zlog_info ("leaving RsvpPathRefresh");
  return rc;
}

static int
RsvpPathRefreshTimer (struct thread *thread)
{
  PSB *pPsb = THREAD_ARG (thread);
  if (pPsb == NULL)
    {
      zlog_err ("pPsb is NULL %s %d", __FILE__, __LINE__);
      return;
    }
  zlog_info ("entering RsvpPathRefreshTimer");
  memset (&pPsb->PathRefreshTimer, 0, sizeof (struct thread *));
  if (RsvpPathRefresh (pPsb) != E_OK)
    {
      zlog_err ("an error o RsvpPathRefresh");
    }
  zlog_info ("leaving RsvpPathRefreshTimer");
}

E_RC
RsvpPathPopERO (RSVP_PKT * pRsvpPkt)
{
  ER_SUBOBJ *pErSubObj, *pErSubObjPrev = NULL, *pErSubObjNext;
  uns8 ExitFlag = FALSE;

  pErSubObj = pRsvpPkt->ReceivedEro.er;
  while (pErSubObj != NULL)
    {
      switch (pErSubObj->SubObjHdr.LType & 0x7F)
	{
	case ERO_SUBTYPE_IPV4:
	  zlog_info ("checking for abstract node %x",
		     pErSubObj->u.Ipv4.IpAddress);
	  if (IsAbstractNode
	      (pErSubObj->u.Ipv4.IpAddress,
	       pErSubObj->u.Ipv4.PrefixLength) == TRUE)
	    {
	      zlog_info ("FOUND...");
	      if (pErSubObjPrev == NULL)
		{
		  pRsvpPkt->ReceivedEro.er = pRsvpPkt->ReceivedEro.er->next;
		  pErSubObjNext = pRsvpPkt->ReceivedEro.er;
		}
	      else
		{
		  pErSubObjPrev->next = pErSubObj->next;
		  pErSubObjNext = pErSubObj->next;
		}
	      XFREE (MTYPE_RSVP, pErSubObj);
	      pErSubObj = pErSubObjNext;
	    }
	  else
	    ExitFlag = TRUE;
	  break;
	default:
	  ExitFlag = TRUE;
	}
      if (ExitFlag == TRUE)
	break;
    }
  return E_OK;
}

uns8
CompareERO (ER_SUBOBJ * pErSubObj1, ER_SUBOBJ * pErSubObj2, uns16 HopsNum)
{
  while ((pErSubObj1 != NULL) && (pErSubObj2 != NULL))
    {
      if (memcmp (&pErSubObj1->SubObjHdr,
		  &pErSubObj2->SubObjHdr, sizeof (ER_SUBOBJ_HDR)) == 0)
	{
	  switch (pErSubObj1->SubObjHdr.LType & 0x7F)
	    {
	    case ERO_SUBTYPE_IPV4:
	      if (memcmp (&pErSubObj1->u.Ipv4,
			  &pErSubObj2->u.Ipv4, sizeof (ER_IPV4_SUBOBJ)) != 0)
		{
		  zlog_info ("IP address differs %x %x...",
			     pErSubObj1->u.Ipv4.IpAddress,
			     pErSubObj2->u.Ipv4.IpAddress);
		  return TRUE;
		}
	      break;
	    case ERO_SUBTYPE_AS:
	      if (memcmp (&pErSubObj1->u.AS,
			  &pErSubObj2->u.AS, sizeof (ER_AS_SUBOBJ)) != 0)
		{
		  return TRUE;
		}
	      break;
	    default:
	      return FALSE;
	    }
	}
      if (HopsNum == 1)
	{
	  return FALSE;
	}
      pErSubObj1 = pErSubObj1->next;
      pErSubObj2 = pErSubObj2->next;
    }

  if (((pErSubObj1 == NULL) &&
       (pErSubObj2 != NULL)) ||
      ((pErSubObj1 != NULL) && (pErSubObj2 == NULL)))
    {
      zlog_info ("Number of elements differs...");
      return TRUE;
    }
  return FALSE;
}

static int
RsvpPathAgeOut (struct thread *thread)
{
  PSB *pPsb = THREAD_ARG (thread);

  zlog_info ("entering RsvpPathAgeOut");

  // jleu: timer is not rescheduled
  memset (&pPsb->AgeOutTimer, 0, sizeof (struct thread *));

  if (pPsb->OutIfIndex != 0)
    {
      if (EncodeAndSendRsvpPathTearMessage
	  (&pPsb->OldPacket, pPsb->NextHop, pPsb->OutIfIndex,
	   pPsb->ttl - 1) != E_OK)
	{
	  zlog_err ("an error on EncodeAndSendRsvpPathTearMessage %s %d",
		    __FILE__, __LINE__);
	}
    }
  if (DeleteSender (pPsb) != E_OK)
    {
      zlog_err ("an error on DeleteSender %s %d", __FILE__, __LINE__);
    }
  RsvpStatistics.PsbAgeOutCount++;
  zlog_info ("leaving RsvpPathAgeOut");
}

uns8
IsEgress (PSB * pPsb)
{
  return IsAbstractNode (pPsb->OldPacket.Session.Dest, 32);
}

E_RC
ProcessRsvpPathMessage (RSVP_PKT * pRsvpPkt, uns32 IfIndex,
			IPV4_ADDR SrcIpAddr, uns8 ttl)
{
  PSB *pPsb;
  PSB_KEY PsbKey;
  RSVP_PKT_QUEUE *pQueuedItem;
  uns8 ApplicationTrapFlag = FALSE;
  zlog_info ("entering ProcessRsvpPathMessage");
  RsvpStatistics.PathMsgCount++;
  memset (&PsbKey, 0, sizeof (PSB_KEY));

  PsbKey.Session = pRsvpPkt->Session;
  PsbKey.SenderTemplate = pRsvpPkt->SenderTemplate;
  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x .Src %x .LspId %x",
	     PsbKey.Session.Dest,
	     PsbKey.Session.TunnelId,
	     PsbKey.Session.ExtTunelId,
	     PsbKey.SenderTemplate.IpAddr, PsbKey.SenderTemplate.LspId);
  if ((pPsb = FindPsb (&PsbKey)) == NULL)
    {
      if ((pPsb = NewPsb (&PsbKey)) == NULL)
	{
	  zlog_err ("Cannot create PSB");
	  FreeRsvpPkt (pRsvpPkt);
	  return E_ERR;
	}
      ApplicationTrapFlag = TRUE;
      memcpy (&pPsb->OldPacket.Session, &pRsvpPkt->Session,
	      sizeof (SESSION_OBJ));
      memcpy (&pPsb->OldPacket.SenderTemplate, &pRsvpPkt->SenderTemplate,
	      sizeof (SENDER_TEMPLATE_OBJ));
      memcpy (&pPsb->OldPacket.LabelRequest, &pRsvpPkt->LabelRequest,
	      sizeof (LABEL_REQUEST_OBJ));
      pPsb->RefreshValue =
	PathRefreshInterval + RefreshRandomize (PathRefreshInterval);
    }
  else
    {
      if (StopPathAgeOutTimer (&pPsb->AgeOutTimer) != E_OK)
	{
	  zlog_err ("Cannot stop Ageout timer");
	}
      if (pPsb->TE_InProcess == TRUE)
	{
	  if ((pQueuedItem =
	       (RSVP_PKT_QUEUE *) XMALLOC (MTYPE_RSVP,
					   sizeof (RSVP_PKT_QUEUE))) == NULL)
	    {
	      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }
	  pQueuedItem->MsgType = PATH_MSG;
	  pQueuedItem->InIfIndex = IfIndex;
	  pQueuedItem->pRsvpPkt = pRsvpPkt;
	  pQueuedItem->SourceIp = SrcIpAddr;
	  pQueuedItem->ttl = ttl;
	  pQueuedItem->next = NULL;
	  if (EnqueueRsvpPacket (pQueuedItem, &pPsb->packet_queue) != E_OK)
	    {
	      zlog_err ("Cannot enqueue Path");
	    }
	  return E_OK;
	}
    }
  pPsb->InIfIndex = IfIndex;
  pPsb->PrevHop = pRsvpPkt->ReceivedRsvpHop.PHop /*SrcIpAddr */ ;
  pPsb->ttl = ttl;
  if (CheckRRO4Loop (pRsvpPkt->ReceivedRro.rr) != E_OK)
    {
      zlog_err ("Loop detected");
      if (GeneratePathErrMessage
	  (pPsb, ROUTING_PROBLEM_ERR_CODE,
	   RRO_INIDICATED_ROUTING_LOOP) != E_OK)
	{
	  zlog_err ("Cannot generate PAthErr message %s %d", __FILE__,
		    __LINE__);
	}
      if (DeleteSender (pPsb) != E_OK)
	{
	  zlog_err ("An error on DeleteSender %s %d", __FILE__, __LINE__);
	}
      FreeRsvpPkt (pRsvpPkt);
      return E_ERR;
    }
  if (memcmp
      (&pRsvpPkt->TimeValues, &pPsb->OldPacket.TimeValues,
       sizeof (TIME_VALUES_OBJ)) != 0)
    {
      uns32 val;
      memcpy (&pPsb->OldPacket.TimeValues, &pRsvpPkt->TimeValues,
	      sizeof (TIME_VALUES_OBJ));

      val = (uns32) pPsb->OldPacket.TimeValues.TimeValues / 10000;
      /* 3*R: */
      val *= 3;
      /* (2M+1) * (3*R): */
      val = (2 * RefreshMultiple + 1) * val;
      /* and divide by 4 to get (M + 0.5) * (1.5 * R) */
      pPsb->AgeOutValue = val >> 2;
      zlog_info ("AgeOut value %d", pPsb->AgeOutValue);
    }

  if (memcmp (&pRsvpPkt->ReceivedRsvpHop,
	      &pPsb->OldPacket.ReceivedRsvpHop, sizeof (RSVP_HOP_OBJ)) != 0)
    {
      memcpy (&pPsb->OldPacket.ReceivedRsvpHop, &pRsvpPkt->ReceivedRsvpHop,
	      sizeof (RSVP_HOP_OBJ));
      pPsb->PathRefreshFlag = TRUE;
      pPsb->ResvRefreshFlag = TRUE;
    }
  if (memcmp (&pRsvpPkt->SenderTSpec,
	      &pPsb->OldPacket.SenderTSpec, sizeof (SENDER_TSPEC_OBJ)) != 0)
    {
      memcpy (&pPsb->OldPacket.SenderTSpec, &pRsvpPkt->SenderTSpec,
	      sizeof (SENDER_TSPEC_OBJ));
      ApplicationTrapFlag = TRUE;
    }
  zlog_info ("popping ERO...");
  if (RsvpPathPopERO (pRsvpPkt) != E_OK)
    {
      zlog_err ("Cannot pop ERO");
      FreeRsvpPkt (pRsvpPkt);
      return E_ERR;
    }
  zlog_info ("comparing ERO...");
  if (CompareERO (pPsb->OldPacket.ReceivedEro.er,
		  pRsvpPkt->ReceivedEro.er, 0) == TRUE)
    {
      zlog_info ("not equal...");
      pPsb->PathRefreshFlag = TRUE;
    }
  zlog_info ("comparing ERO...");
  if (CompareERO (pPsb->OldPacket.ReceivedEro.er,
		  pRsvpPkt->ReceivedEro.er, 1) == TRUE)
    {
      zlog_info ("not equal...");
      ApplicationTrapFlag = TRUE;
    }
  if (pPsb->OldPacket.SessionAttributes.CType ==
      SESSION_ATTRIBUTES_RA_CLASS_TYPE)
    {
      if (pPsb->OldPacket.SessionAttributes.u.SessAttrRa.SessionName != NULL)
	{
	  XFREE (MTYPE_RSVP,
		 pPsb->OldPacket.SessionAttributes.u.SessAttrRa.SessionName);
	  pPsb->OldPacket.SessionAttributes.u.SessAttrRa.SessionName = NULL;
	  pPsb->OldPacket.SessionAttributes.u.SessAttrRa.NameLength = 0;
	}
    }
  else if (pPsb->OldPacket.SessionAttributes.CType ==
	   SESSION_ATTRIBUTES_CLASS_TYPE)
    {
      if (pPsb->OldPacket.SessionAttributes.u.SessAttr.SessionName != NULL)
	{
	  XFREE (MTYPE_RSVP,
		 pPsb->OldPacket.SessionAttributes.u.SessAttr.SessionName);
	  pPsb->OldPacket.SessionAttributes.u.SessAttr.SessionName = NULL;
	  pPsb->OldPacket.SessionAttributes.u.SessAttr.NameLength = 0;
	}
    }
  if (pPsb->OldPacket.SessionAttributes.CType !=
      pRsvpPkt->SessionAttributes.CType)
    {
      memcpy (&pPsb->OldPacket.SessionAttributes,
	      &pRsvpPkt->SessionAttributes, sizeof (SESSION_ATTRIBUTES_OBJ));
      if (pRsvpPkt->SessionAttributes.CType ==
	  SESSION_ATTRIBUTES_RA_CLASS_TYPE)
	{
	  pRsvpPkt->SessionAttributes.u.SessAttrRa.SessionName = NULL;
	  pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength = 0;
	}
      else if (pRsvpPkt->SessionAttributes.CType ==
	       SESSION_ATTRIBUTES_CLASS_TYPE)
	{
	  pRsvpPkt->SessionAttributes.u.SessAttr.SessionName = NULL;
	  pRsvpPkt->SessionAttributes.u.SessAttr.NameLength = 0;
	}
      ApplicationTrapFlag = TRUE;
    }
  else if (pPsb->OldPacket.SessionAttributes.CType ==
	   SESSION_ATTRIBUTES_RA_CLASS_TYPE)
    {
      pPsb->OldPacket.SessionAttributes.u.SessAttrRa.NameLength =
	pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength;
      pPsb->OldPacket.SessionAttributes.u.SessAttrRa.SessionName =
	pRsvpPkt->SessionAttributes.u.SessAttrRa.SessionName;
      pRsvpPkt->SessionAttributes.u.SessAttrRa.SessionName = NULL;
      pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength = 0;
      if ((pPsb->OldPacket.SessionAttributes.u.SessAttrRa.Flags !=
	   pRsvpPkt->SessionAttributes.u.SessAttrRa.Flags)
	  || (pPsb->OldPacket.SessionAttributes.u.SessAttrRa.SetPrio !=
	      pRsvpPkt->SessionAttributes.u.SessAttrRa.SetPrio)
	  || (pPsb->OldPacket.SessionAttributes.u.SessAttrRa.HoldPrio !=
	      pRsvpPkt->SessionAttributes.u.SessAttrRa.HoldPrio)
	  || (pPsb->OldPacket.SessionAttributes.u.SessAttrRa.ExcludeAny !=
	      pRsvpPkt->SessionAttributes.u.SessAttrRa.ExcludeAny)
	  || (pPsb->OldPacket.SessionAttributes.u.SessAttrRa.IncludeAny !=
	      pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAny)
	  || (pPsb->OldPacket.SessionAttributes.u.SessAttrRa.IncludeAll !=
	      pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAll))
	{
	  pPsb->OldPacket.SessionAttributes.u.SessAttrRa.Flags =
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.Flags;
	  pPsb->OldPacket.SessionAttributes.u.SessAttrRa.HoldPrio =
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.HoldPrio;
	  pPsb->OldPacket.SessionAttributes.u.SessAttrRa.SetPrio =
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.SetPrio;

	  pPsb->OldPacket.SessionAttributes.u.SessAttrRa.ExcludeAny =
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.ExcludeAny;
	  pPsb->OldPacket.SessionAttributes.u.SessAttrRa.IncludeAny =
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAny;
	  pPsb->OldPacket.SessionAttributes.u.SessAttrRa.IncludeAll =
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAll;
	  ApplicationTrapFlag = TRUE;
	}
    }
  else if (pPsb->OldPacket.SessionAttributes.CType ==
	   SESSION_ATTRIBUTES_CLASS_TYPE)
    {
      pPsb->OldPacket.SessionAttributes.u.SessAttr.NameLength =
	pRsvpPkt->SessionAttributes.u.SessAttr.NameLength;
      pPsb->OldPacket.SessionAttributes.u.SessAttr.SessionName =
	pRsvpPkt->SessionAttributes.u.SessAttr.SessionName;
      pRsvpPkt->SessionAttributes.u.SessAttr.SessionName = NULL;
      pRsvpPkt->SessionAttributes.u.SessAttr.NameLength = 0;
      if ((pPsb->OldPacket.SessionAttributes.u.SessAttr.Flags !=
	   pRsvpPkt->SessionAttributes.u.SessAttr.Flags)
	  || (pPsb->OldPacket.SessionAttributes.u.SessAttr.SetPrio !=
	      pRsvpPkt->SessionAttributes.u.SessAttr.SetPrio)
	  || (pPsb->OldPacket.SessionAttributes.u.SessAttr.HoldPrio !=
	      pRsvpPkt->SessionAttributes.u.SessAttr.HoldPrio))
	{
	  pPsb->OldPacket.SessionAttributes.u.SessAttr.Flags =
	    pRsvpPkt->SessionAttributes.u.SessAttr.Flags;
	  pPsb->OldPacket.SessionAttributes.u.SessAttr.HoldPrio =
	    pRsvpPkt->SessionAttributes.u.SessAttr.HoldPrio;
	  pPsb->OldPacket.SessionAttributes.u.SessAttr.SetPrio =
	    pRsvpPkt->SessionAttributes.u.SessAttr.SetPrio;

	  ApplicationTrapFlag = TRUE;
	}
    }
  FreeERO (&pPsb->OldPacket.ReceivedEro);
  pPsb->OldPacket.ReceivedEro = pRsvpPkt->ReceivedEro;
  pRsvpPkt->ReceivedEro.er = NULL;
  FreeRRO (&pPsb->OldPacket.ReceivedRro);
  pPsb->OldPacket.ReceivedRro = pRsvpPkt->ReceivedRro;
  pRsvpPkt->ReceivedRro.rr = NULL;
  if ((ApplicationTrapFlag == TRUE) ||
      ((IsEgress (pPsb) == TRUE) && (pPsb->pRsb == NULL)))
    {
      if (IsEgress (pPsb) == TRUE)
	{
	  if (pPsb->OldPacket.ReceivedEro.er != NULL)
	    {
	      zlog_err ("Reaching Egress with non-empty ERO!!!");
	    }
	  else
	    {
	      zlog_info ("Egress reached");
	      if (StartPathAgeOutTimer
		  (pPsb->AgeOutValue, &pPsb->AgeOutTimer, pPsb) != E_OK)
		{
		  zlog_err ("Cannot start AgeOut timer ");
		}
	      FreeRsvpPkt (pRsvpPkt);
	      return NewModifiedPath (pPsb);
	    }
	}
      else
	{
	  if (StopPathRefreshTimer (&pPsb->PathRefreshTimer) != E_OK)
	    {
	      zlog_err ("Cannot stop PathRefresh timer");
	    }
	  zlog_info ("Locking Flow %s %d", __FILE__, __LINE__);
	  pPsb->TE_InProcess = TRUE;
	  pPsb->PathRefreshFlag = FALSE;
	  PrepareAndSendMsg2TE (pPsb);
	}
    }
  else
    {
      if (StartPathAgeOutTimer (pPsb->AgeOutValue, &pPsb->AgeOutTimer, pPsb)
	  != E_OK)
	{
	  zlog_err ("Cannot start AgeOut timer ");
	}
      if (pPsb->PathRefreshFlag == TRUE)
	{
	  if (pPsb->OutIfIndex != 0)
	    {
	      if (RsvpPathRefresh (pPsb) != E_OK)
		{
		  zlog_err ("an error on PathRefresh %s %d", __FILE__,
			    __LINE__);
		  FreeRsvpPkt (pRsvpPkt);
		  return E_ERR;
		}
	    }
	  pPsb->PathRefreshFlag = FALSE;
	}
    }
  if (pPsb->ResvRefreshFlag == TRUE)
    {
      zlog_info ("RESV refresh will be called here");
      pPsb->ResvRefreshFlag = FALSE;
    }
  FreeRsvpPkt (pRsvpPkt);
  zlog_info ("leaving ProcessRsvpPathMessage");
  return E_OK;
}

E_RC
ProcessTEMsgUponPath (TE_API_MSG * pMsg)
{
  PSB_KEY PsbKey;
  PSB *pPsb;

  uns8 FrwChangeFlag = FALSE;
  zlog_info ("entering ProcessTEMsgUponPath");
  memset (&PsbKey, 0, sizeof (PSB_KEY));
  PsbKey = pMsg->u.PathNotification.PsbKey;

  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x .Src %x .LspId %x",
	     PsbKey.Session.Dest,
	     PsbKey.Session.TunnelId,
	     PsbKey.Session.ExtTunelId,
	     PsbKey.SenderTemplate.IpAddr, PsbKey.SenderTemplate.LspId);

  if ((pPsb = FindPsb (&PsbKey)) != NULL)
    {
      zlog_info ("UnLocking Flow %s %d", __FILE__, __LINE__);
      pPsb->TE_InProcess = FALSE;
      if (pMsg->u.PathNotification.rc != PATH_PROC_OK)
	{
	  uns8 ErrCode;
	  uns16 ErrVal = 0;
	  switch (pMsg->u.PathNotification.rc)
	    {
	    case BW_UNAVAIL:
	      ErrCode = POLICY_CTRL_FAILURE_ERR_CODE;
	      break;
	    case NO_ROUTE:
	      ErrCode = ROUTING_PROBLEM_ERR_CODE;
	      if (pPsb->OldPacket.ReceivedEro.er != NULL)
		{
		  if (pPsb->OldPacket.ReceivedEro.er->SubObjHdr.LType & 0x80)
		    ErrVal = BAD_LOOSE_NODE;
		  else
		    ErrVal = BAD_STRICT_NODE;
		}
	      else
		{
		  ErrVal = NO_ROUTE_AVAILABLE;
		}
	      break;
	    case LABEL_ALLOC_FAILURE:
	      ErrCode = ROUTING_PROBLEM_ERR_CODE;
	      ErrVal = LABEL_ALLOCATION_FAILURE;
	      break;
	    case UNSUP_L3PID:
	      ErrCode = ROUTING_PROBLEM_ERR_CODE;
	      ErrVal = UNSUPPORTED_L3PID;
	      break;
	    default:
	      zlog_err ("Unknown return code, forcing to NO_ROUTE %s %d",
			__FILE__, __LINE__);
	      ErrCode = ROUTING_PROBLEM_ERR_CODE;
	      ErrVal = NO_ROUTE_AVAILABLE;
	    }
	  if (GeneratePathErrMessage (pPsb, ErrCode, ErrVal) != E_OK)
	    {
	      zlog_err ("Cannot generate PathErr message");
	    }

	  if (DeleteSender (pPsb) != E_OK)
	    {
	      zlog_err ("An error on DeleteSender %s %d", __FILE__, __LINE__);
	    }
	  return E_OK;
	}
      pPsb->Label = pMsg->u.PathNotification.Label;
      if (pPsb->NextHop != pMsg->u.PathNotification.NextHop)
	{
	  pPsb->NextHop = pMsg->u.PathNotification.NextHop;
	  FrwChangeFlag = TRUE;
	}
      if (pPsb->OutIfIndex != pMsg->u.PathNotification.OutIfIndex)
	{
	  pPsb->OutIfIndex = pMsg->u.PathNotification.OutIfIndex;
	  FrwChangeFlag = TRUE;
	}
      if (FrwChangeFlag == TRUE)
	{
	  if (pPsb->OldPacket.ReceivedRro.rr != NULL)
	    {
	      if (pPsb->OldPacket.AddedRro.rr == NULL)
		{
		  if ((pPsb->OldPacket.AddedRro.rr =
		       (RR_SUBOBJ *) XMALLOC (MTYPE_RSVP,
					      sizeof (RR_SUBOBJ))) == NULL)
		    {
		      zlog_err ("Cannotallocate memory %s %d", __FILE__,
				__LINE__);
		      return E_ERR;
		    }
		  memset (pPsb->OldPacket.AddedRro.rr, 0, sizeof (RR_SUBOBJ));
		}
	      pPsb->OldPacket.AddedRro.rr->SubObjHdr.Type = RRO_SUBTYPE_IPV4;
	      pPsb->OldPacket.AddedRro.rr->SubObjHdr.Length = 8;
	      if (IpAddrGetByIfIndex
		  (pPsb->OutIfIndex,
		   &pPsb->OldPacket.AddedRro.rr->u.Ipv4.IpAddr) == E_OK)
		{
		  pPsb->OldPacket.AddedRro.rr->u.Ipv4.PrefixLen = 32;
		}
	      else
		{
		  zlog_err ("Cannot get IP address by IfIndex");
		  XFREE (MTYPE_RSVP, pPsb->OldPacket.AddedRro.rr);
		  pPsb->OldPacket.AddedRro.rr = NULL;
		}
	    }
	  pPsb->OldPacket.SentRsvpHop.LIH = pPsb->OutIfIndex;
	  if (IpAddrGetByIfIndex
	      (pPsb->OutIfIndex, &pPsb->OldPacket.SentRsvpHop.PHop) != E_OK)
	    {
	      zlog_err ("Cannot get IP address by IfIndex");
	    }
	  else
	    {
	      zlog_info ("NHOP %x", pPsb->OldPacket.SentRsvpHop.PHop);
	    }
	  if (pPsb->pSentBuffer)
	    {
	      XFREE (MTYPE_RSVP, pPsb->pSentBuffer);
	      pPsb->pSentBuffer = NULL;
	      pPsb->SentBufferLen = 0;
	    }
	  pPsb->Label = pMsg->u.PathNotification.Label;
	}
      if (StartPathAgeOutTimer (pPsb->AgeOutValue, &pPsb->AgeOutTimer, pPsb)
	  != E_OK)
	{
	  zlog_err ("Cannot start AgeOut timer ");
	}
      RsvpPathRefresh (pPsb);
      PsbDequeueAndInvokeMessages (pPsb);
      zlog_info ("leaving ProcessTEMsgUponPath+");
      return E_OK;
    }
  else
    {
      zlog_debug ("cannot find PSB");
    }
  zlog_info ("leaving ProcessTEMsgUponPath-");
  return E_ERR;
}

uns16
ErHopsCount (PSB * pPsb)
{
  ER_SUBOBJ *pErSubObj = pPsb->OldPacket.ReceivedEro.er;
  uns16 Count = 0;
  while (pErSubObj != NULL)
    {
      if (pErSubObj->SubObjHdr.LType != ERO_SUBTYPE_IPV4)
	{
	  break;
	}
      else if (pErSubObj->SubObjHdr.LType & 0x80)
	{
	  return (Count + 1);
	}
      Count++;
      pErSubObj = pErSubObj->next;
    }
  return Count;
}

static void
PrepareAndSendMsg2TE (PSB * pPsb)
{
  TE_API_MSG msg;
  memset (&msg, 0, sizeof (msg));
  msg.NotificationType = PATH_MSG_NOTIFICATION;
  msg.u.PathNotification.PsbKey = pPsb->PsbKey;
  msg.u.PathNotification.BW = pPsb->OldPacket.SenderTSpec.PeakDataRate;
  if (pPsb->OldPacket.SessionAttributes.CType ==
      SESSION_ATTRIBUTES_RA_CLASS_TYPE)
    {
      msg.u.PathNotification.RA_Valid = 1;
      msg.u.PathNotification.ExcludeAny =
	pPsb->OldPacket.SessionAttributes.u.SessAttrRa.ExcludeAny;
      msg.u.PathNotification.IncludeAny =
	pPsb->OldPacket.SessionAttributes.u.SessAttrRa.IncludeAny;
      msg.u.PathNotification.IncludeAll =
	pPsb->OldPacket.SessionAttributes.u.SessAttrRa.IncludeAll;
      msg.u.PathNotification.HoldPrio =
	pPsb->OldPacket.SessionAttributes.u.SessAttrRa.HoldPrio;
      msg.u.PathNotification.SetupPrio =
	pPsb->OldPacket.SessionAttributes.u.SessAttrRa.SetPrio;
      if (pPsb->OldPacket.SessionAttributes.u.SessAttrRa.
	  Flags & LOCAL_PROTECTION_DESIRED)
	{
	  msg.u.PathNotification.LocalProtection = 1;
	}
      if (pPsb->OldPacket.SessionAttributes.u.SessAttrRa.
	  Flags & SE_STYLE_DESIRED)
	{
	  msg.u.PathNotification.SharedExplicit = 1;
	}
    }
  else if (pPsb->OldPacket.SessionAttributes.CType ==
	   SESSION_ATTRIBUTES_CLASS_TYPE)
    {
      msg.u.PathNotification.HoldPrio =
	pPsb->OldPacket.SessionAttributes.u.SessAttr.HoldPrio;
      msg.u.PathNotification.SetupPrio =
	pPsb->OldPacket.SessionAttributes.u.SessAttr.SetPrio;
      if (pPsb->OldPacket.SessionAttributes.u.SessAttr.
	  Flags & LOCAL_PROTECTION_DESIRED)
	{
	  msg.u.PathNotification.LocalProtection = 1;
	}
      if (pPsb->OldPacket.SessionAttributes.u.SessAttr.
	  Flags & SE_STYLE_DESIRED)
	{
	  msg.u.PathNotification.SharedExplicit = 1;
	}
    }
  else
    {
      msg.u.PathNotification.HoldPrio = 4;	/* default */
      msg.u.PathNotification.SetupPrio = 4;
    }
  msg.u.PathNotification.ErHopNumber = ErHopsCount (pPsb);
  if (msg.u.PathNotification.ErHopNumber > 0)
    {
      ER_SUBOBJ *pErSubObj = pPsb->OldPacket.ReceivedEro.er;
      int i;
      if (!(pErSubObj->SubObjHdr.LType & 0x80))
	{
	  msg.u.PathNotification.FirstErHopStrict = 1;
	}
      for (i = 0; i < msg.u.PathNotification.ErHopNumber;
	   i++, pErSubObj = pErSubObj->next)
	{
	  msg.u.PathNotification.ErHops[i] = pErSubObj->u.Ipv4.IpAddress;
	}
    }
  rsvp_send_msg (&msg, sizeof (msg));
}

E_RC
DeletePsb (PSB * pPsb)
{
  if (StopPathAgeOutTimer (&pPsb->AgeOutTimer) != E_OK)
    {
      zlog_err ("Cannot stop Ageout timer");
      return E_ERR;
    }
  if (StopPathRefreshTimer (&pPsb->PathRefreshTimer) != E_OK)
    {
      zlog_err ("Cannot stop PathRefresh timer");
      return E_ERR;
    }
  if (pPsb->InIfIndex != 0)
    {
      PrepareAndSendLabelReleaseMsg2TE (pPsb);
    }
  FreePSB (pPsb);
  return E_OK;
}

E_RC
DeleteSender (PSB * pPsb)
{
  RSB *pRsb;
  FILTER_LIST *pFilterList, *pFilterListPrev = NULL;
  FILTER_SPEC_DATA *pFilterSpecData = NULL;
  int Shared = 0;
  zlog_info ("entering DeleteSender");
  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x .Src %x .LspId %x",
	     pPsb->PsbKey.Session.Dest,
	     pPsb->PsbKey.Session.TunnelId,
	     pPsb->PsbKey.Session.ExtTunelId,
	     pPsb->PsbKey.SenderTemplate.IpAddr,
	     pPsb->PsbKey.SenderTemplate.LspId);
  zlog_info ("pPsb %x pRsb %x", pPsb, pPsb->pRsb);
  if ((pRsb = pPsb->pRsb) == NULL)
    {
      RSB_KEY RsbKey;
      memset (&RsbKey, 0, sizeof (RSB_KEY));
      RsbKey.Session = pPsb->PsbKey.Session;
      pRsb = FindRsb (&RsbKey);
    }
  if (pRsb != NULL)
    {
      if ((pRsb->OldPacket.Style.OptionVector2 & 0x001F) == SE_STYLE_BITS)
	{
	  Shared = 1;
	  zlog_info ("Shared %s %d", __FILE__, __LINE__);
	}
      else
	{
	  zlog_info ("Not Shared %s %d", __FILE__, __LINE__);
	}
      pFilterList = pRsb->OldPacket.pFilterList;
      zlog_info ("searching for filter data");
      while (pFilterList != NULL)
	{
	  if ((pFilterSpecData = pFilterList->pFilterSpecData) != NULL)
	    {
	      zlog_info ("%x %x %x %x",
			 pPsb->PsbKey.SenderTemplate.IpAddr,
			 pPsb->PsbKey.SenderTemplate.LspId,
			 pFilterSpecData->FilterSpec.IpAddr,
			 pFilterSpecData->FilterSpec.LspId);
	      if (memcmp (&pPsb->PsbKey.SenderTemplate,
			  &pFilterSpecData->FilterSpec,
			  sizeof (FILTER_SPEC_OBJ)) == 0)
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
		  if (pPsb->InIfIndex != 0)
		    {
		      pFilterSpecData->ToBeDeleted = 1;
		      if (pFilterSpecData->pPHopResvRefreshList != NULL)
			pFilterSpecData->pPHopResvRefreshList->
			  MustBeProcessed = 1;
		    }
		  XFREE (MTYPE_RSVP, pFilterList);
		  break;
		}
	      pFilterSpecData = NULL;
	    }
	  pFilterListPrev = pFilterList;
	  pFilterList = pFilterList->next;
	}
      if (ForwardResvTearMsg (pRsb) != E_OK)
	{
	  zlog_err ("An error on ForwardResvTearMsg");
	}
      if (FilterShutDown (pFilterSpecData, Shared) != E_OK)
	{
	  zlog_err ("An error on FilterShutDown");
	}
      if (ProcessEffectiveFlows (pRsb) != E_OK)
	{
	  zlog_err ("an error on ProcessEffectiveFlows %s %d", __FILE__,
		    __LINE__);
	}
      if (pRsb->OldPacket.pFilterList != NULL)
	{
	  if (ProcessPHopFilterSpecLists (pRsb, Shared) != E_OK)
	    {
	      zlog_err ("an error on ProcessPHopFilterSpecLists %s %d",
			__FILE__, __LINE__);
	    }
	}
      else
	{
	  /* delete RSB */
	  FreeRSB (pRsb);
	}
    }
  if (DeletePsb (pPsb) != E_OK)
    {
      zlog_info ("Cannot delete PSB %s %d", __FILE__, __LINE__);
      zlog_info ("leaving DeleteSender-");
      return E_ERR;
    }
  zlog_info ("leaving DeleteSender+");
  return E_OK;
}

E_RC
ProcessRsvpPathTearMessage (RSVP_PKT * pRsvpPkt, uns32 IfIndex,
			    IPV4_ADDR SrcIpAddr, uns8 ttl)
{
  PSB *pPsb;
  PSB_KEY PsbKey;
  RSVP_PKT_QUEUE *pQueuedItem;
  zlog_info ("entering ProcessRsvpPathTearMessage");

  RsvpStatistics.PathTearMsgCount++;
  memset (&PsbKey, 0, sizeof (PSB_KEY));

  PsbKey.Session = pRsvpPkt->Session;
  PsbKey.SenderTemplate = pRsvpPkt->SenderTemplate;

  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x .Src %x .LspId %x",
	     PsbKey.Session.Dest,
	     PsbKey.Session.TunnelId,
	     PsbKey.Session.ExtTunelId,
	     PsbKey.SenderTemplate.IpAddr, PsbKey.SenderTemplate.LspId);

  if ((pPsb = FindPsb (&PsbKey)) == NULL)
    {
      zlog_info ("leaving ProcessRsvpPathTearMessage");
      FreeRsvpPkt (pRsvpPkt);
      return E_OK;
    }
  if (pPsb->OutIfIndex != 0)
    {
      if (EncodeAndSendRsvpPathTearMessage
	  (pRsvpPkt, pPsb->NextHop, pPsb->OutIfIndex, pPsb->ttl - 1) != E_OK)
	{
	  zlog_err ("An error on EncodeAndSendRsvpPathTearMessage");
	}
    }
  if ((pPsb->TE_InProcess == TRUE) ||
      ((pPsb->pFilterSpecData != NULL) &&
       (pPsb->pFilterSpecData->pEffectiveFlow != NULL) &&
       (pPsb->pFilterSpecData->pEffectiveFlow->TE_InProcess == TRUE)))
    {
      if ((pQueuedItem =
	   (RSVP_PKT_QUEUE *) XMALLOC (MTYPE_RSVP,
				       sizeof (RSVP_PKT_QUEUE))) == NULL)
	{
	  zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	}
      pQueuedItem->MsgType = PATH_TEAR_MSG;
      pQueuedItem->InIfIndex = IfIndex;
      pQueuedItem->pRsvpPkt = pRsvpPkt;
      pQueuedItem->SourceIp = SrcIpAddr;
      pQueuedItem->ttl = ttl;
      pQueuedItem->next = NULL;
      if (EnqueueRsvpPacket (pQueuedItem, &pPsb->packet_queue) != E_OK)
	{
	  zlog_err ("Cannot enqueue packet %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      return E_OK;
    }
  FreeRsvpPkt (pRsvpPkt);

  if (DeleteSender (pPsb) != E_OK)
    {
      zlog_err ("an error on DeleteSender");
    }
  return E_OK;
}

E_RC
ProcessRsvpPathErrMessage (RSVP_PKT * pRsvpPkt, uns32 IfIndex,
			   IPV4_ADDR SrcIpAddr, uns8 ttl)
{
  PSB *pPsb;
  PSB_KEY PsbKey;

  zlog_info ("entering ProcessRsvpPathErrMessage");
  RsvpStatistics.PathErrMsgCount++;
  memset (&PsbKey, 0, sizeof (PSB_KEY));

  PsbKey.Session = pRsvpPkt->Session;
  PsbKey.SenderTemplate = pRsvpPkt->SenderTemplate;

  zlog_info ("Session.Dest %x .TunnelId %x .ExtTunnelId %x .Src %x .LspId %x",
	     PsbKey.Session.Dest,
	     PsbKey.Session.TunnelId,
	     PsbKey.Session.ExtTunelId,
	     PsbKey.SenderTemplate.IpAddr, PsbKey.SenderTemplate.LspId);

  if ((pPsb = FindPsb (&PsbKey)) == NULL)
    {
      FreeRsvpPkt (pRsvpPkt);
      return E_ERR;
    }
  if (pPsb->InIfIndex == 0)
    {
      zlog_info ("Ingress: PathErr received");
      PrepareAndSendPathErrNotificationMsg2TE (pPsb, &pRsvpPkt->ErrorSpec);
    }
  else
    if (EncodeAndSendRsvpPathErrMessage
	(pRsvpPkt, pPsb->PrevHop, pPsb->InIfIndex, pPsb->ttl - 1) != E_OK)
    {
      zlog_err ("An error in EncodeAndSendRsvpPathErrMessage %s %d", __FILE__,
		__LINE__);
      FreeRsvpPkt (pRsvpPkt);
      return E_ERR;
    }
  FreeRsvpPkt (pRsvpPkt);
  return E_OK;
}

static E_RC
StartPathAgeOutTimer (uns32 time, struct thread **pTimerId, void *data)
{
  zlog_info ("entering StartPathAgeOutTimer");
  *pTimerId = thread_add_timer (master, RsvpPathAgeOut, data, time);
  THREAD_VAL (*pTimerId) = time;
  zlog_info ("leaving StartPathAgeOutTimer");
  return E_OK;
}

static E_RC
StopPathAgeOutTimer (struct thread **pTimerId)
{
  zlog_info ("entering StopPathAgeOutTimer");
  thread_cancel (*pTimerId);
  *pTimerId = NULL;
  zlog_info ("leaving StopPathAgeOutTimer");
  return E_OK;
}

static E_RC
StartPathRefreshTimer (uns32 time, struct thread **pTimerId, void *data)
{
  zlog_info ("entering StartPathRefreshTimer");
  *pTimerId = thread_add_timer (master, RsvpPathRefreshTimer, data, time);
  zlog_info ("leaving StartPathRefreshTimer");
  return E_OK;
}

static E_RC
StopPathRefreshTimer (struct thread **pTimerId)
{
  zlog_info ("entering StopPathRefreshTimer");
  thread_cancel (*pTimerId);
  *pTimerId = NULL;
  zlog_info ("leaving StopPathRefreshTimer");
  return E_OK;
}

static void
PrepareAndSendLabelReleaseMsg2TE (PSB * pPsb)
{
  TE_API_MSG msg;

  memset (&msg, 0, sizeof (msg));
  msg.NotificationType = LABEL_RELEASE_NOTIFICATION;
  msg.u.LabelRelease.PsbKey = pPsb->PsbKey;
  msg.u.LabelRelease.Label = pPsb->Label;
  zlog_info ("sending message to TE upon RESV");
  rsvp_send_msg (&msg, sizeof (msg));
}

static void
PrepareAndSendPathErrNotificationMsg2TE (PSB * pPsb,
					 ERR_SPEC_OBJ * pErrSpecObj)
{
  TE_API_MSG msg;

  memset (&msg, 0, sizeof (msg));
  msg.NotificationType = PATH_ERR_NOTIFICATION;
  msg.u.PathErrNotification.PsbKey = pPsb->PsbKey;
  msg.u.PathErrNotification.ErrSpec = *pErrSpecObj;
  zlog_info ("sending message to TE upon RESV");
  rsvp_send_msg (&msg, sizeof (msg));
}

E_RC
GeneratePathErrMessage (PSB * pPsb, uns8 ErrCode, uns16 ErrVal)
{
  RSVP_PKT RsvpPkt;
  memset (&RsvpPkt, 0, sizeof (RSVP_PKT));
  RsvpPkt.Session = pPsb->PsbKey.Session;
  RsvpPkt.SenderTemplate = pPsb->PsbKey.SenderTemplate;
  RsvpPkt.SenderTSpec = pPsb->OldPacket.SenderTSpec;
  RsvpPkt.ErrorSpec.IpAddr = GetRouterId ();
  RsvpPkt.ErrorSpec.ErrCode = ErrCode;
  RsvpPkt.ErrorSpec.ErrVal = ErrVal;
  if (EncodeAndSendRsvpPathErrMessage
      (&RsvpPkt, pPsb->PrevHop, pPsb->InIfIndex, 255) != E_OK)
    {
      zlog_err ("Cannot encode/send PathErr message %s %d", __FILE__,
		__LINE__);
      return E_ERR;
    }
  return E_OK;
}
