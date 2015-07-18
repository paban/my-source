/* Module:   rsvp_utilities.c
   Contains: RSVP utilities - object allocation and freeing,
   dump etc.
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "rsvp.h"


#define LOG1(a1) \
{\
   if(vty) \
   {\
       vty_out(vty,a1);\
       vty_out(vty,"%s",VTY_NEWLINE);\
   }\
   else \
   {\
       zlog_info(a1);\
   }\
}

#define LOG2(a1,a2) \
{\
   if(vty) \
   {\
       vty_out(vty,a1,a2);\
       vty_out(vty,"%s",VTY_NEWLINE);\
   }\
   else \
   {\
       zlog_info(a1,a2);\
   }\
}

#define LOG3(a1,a2,a3) \
{\
   if(vty) \
   {\
       vty_out(vty,a1,a2,a3);\
       vty_out(vty,"%s",VTY_NEWLINE);\
   }\
   else \
   {\
       zlog_info(a1,a2,a3);\
   }\
}

#define LOG4(a1,a2,a3,a4) \
{\
   if(vty) \
   {\
       vty_out(vty,a1,a2,a3,a4);\
       vty_out(vty,"%s",VTY_NEWLINE);\
   }\
   else \
   {\
       zlog_info(a1,a2,a3,a4);\
   }\
}

#define LOG5(a1,a2,a3,a4,a5) \
{\
   if(vty) \
   {\
       vty_out(vty,a1,a2,a3,a4,a5);\
       vty_out(vty,"%s",VTY_NEWLINE);\
   }\
   else \
   {\
       zlog_info(a1,a2,a3,a4,a5);\
   }\
}

#define LOG6(a1,a2,a3,a4,a5,a6) \
{\
   if(vty) \
   {\
       vty_out(vty,a1,a2,a3,a4,a5,a6);\
       vty_out(vty,"%s",VTY_NEWLINE);\
   }\
   else \
   {\
       zlog_info(a1,a2,a3,a4,a5,a6);\
   }\
}

#define LOG7(a1,a2,a3,a4,a5,a6,a7) \
{\
   if(vty) \
   {\
       vty_out(vty,a1,a2,a3,a4,a5,a6,a7);\
       vty_out(vty,"%s",VTY_NEWLINE);\
   }\
   else \
   {\
       zlog_info(a1,a2,a3,a4,a5,a6,a7);\
   }\
}

#define LOG8(a1,a2,a3,a4,a5,a6,a7,a8) \
{\
   if(vty) \
   {\
       vty_out(vty,a1,a2,a3,a4,a5,a6,a7,a8);\
       vty_out(vty,"%s",VTY_NEWLINE);\
   }\
   else \
   {\
       zlog_info(a1,a2,a3,a4,a5,a6,a7,a8);\
   }\
}

RSVP_STATISTICS RsvpStatistics = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

typedef struct
{
  PATRICIA_NODE Node;
  IPV4_ADDR IfIpAddress;
  uns8 PrefixLen;
} IF_IP_NODE;

static PATRICIA_TREE IfIpAddressesTree;

E_RC
IfIpAdd (IPV4_ADDR IfIpAddress, uns8 PrefixLen)
{
  IF_IP_NODE *pIfIpNode;

  if ((pIfIpNode =
       (IF_IP_NODE *) XMALLOC (MTYPE_RSVP, sizeof (IF_IP_NODE))) == NULL)
    {
      zlog_err ("cannot allocate memory %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  memset (pIfIpNode, 0, sizeof (IF_IP_NODE));
  pIfIpNode->IfIpAddress = IfIpAddress;
  pIfIpNode->PrefixLen = PrefixLen;
  pIfIpNode->Node.key_info = (uns8 *) & pIfIpNode->IfIpAddress;
  if (patricia_tree_add (&IfIpAddressesTree, &pIfIpNode->Node) != E_OK)
    {
      zlog_err ("cannot add node to patricia");
      return E_ERR;
    }
  return E_OK;
}

E_RC
IfIpAddrDel (IPV4_ADDR IfIpAddress, uns8 PrefixLen)
{
  IF_IP_NODE *pIfIpNode;

  if ((pIfIpNode =
       (IF_IP_NODE *) patricia_tree_get (&IfIpAddressesTree,
					 (const uns8 *) &IfIpAddress)) !=
      NULL)
    {
      if (patricia_tree_del (&IfIpAddressesTree, &pIfIpNode->Node) != E_OK)
	{
	  zlog_err ("Cannot delete from patricia %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      return E_OK;
    }
  zlog_err ("IfIp entry is not found %s %d", __FILE__, __LINE__);
  return E_ERR;
}

IPV4_ADDR
GetRouterId ()
{
  IPV4_ADDR key = 0, SelectedIpAddr = 0;
  IF_IP_NODE *pIfIpNode;

  while ((pIfIpNode =
	  (IF_IP_NODE *) patricia_tree_getnext (&IfIpAddressesTree,
						(const uns8 *) &key)) != NULL)
    {
      if (pIfIpNode->IfIpAddress > SelectedIpAddr)
	{
	  SelectedIpAddr = pIfIpNode->IfIpAddress;
	}
      key = pIfIpNode->IfIpAddress;
    }
  return SelectedIpAddr;
}

uns8
IsAbstractNode (IPV4_ADDR IpAddress, uns8 PrefixLen)
{
  IF_IP_NODE *pIfIpNode;
  if (PrefixLen > 32)
    {
      zlog_warn ("PrefixLen is %d. Forcing to 32", PrefixLen);
      PrefixLen = 32;
    }
  if ((pIfIpNode =
       (IF_IP_NODE *) patricia_tree_get (&IfIpAddressesTree,
					 (const uns8 *) &IpAddress)) == NULL)
    {
      return FALSE;
    }
  return TRUE;
}

E_RC
InitInterfaceIpAdressesDB ()
{
  PATRICIA_PARAMS params;

  memset (&params, 0, sizeof (PATRICIA_PARAMS));
  params.key_size = sizeof (IPV4_ADDR);
  if (patricia_tree_init (&IfIpAddressesTree, &params) != E_OK)
    {
      zlog_err ("cannot initiate I/F patricia tree");
      return E_ERR;
    }
  return E_OK;
}

E_RC
CheckRRO4Loop (RR_SUBOBJ * pRrSubObj)
{
  RR_SUBOBJ *pRrSub = pRrSubObj;

  while (pRrSub != NULL)
    {
      if (pRrSub->SubObjHdr.Type == RRO_SUBTYPE_IPV4)
	{
	  if (IsAbstractNode (pRrSub->u.Ipv4.IpAddr, pRrSub->u.Ipv4.PrefixLen)
	      == TRUE)
	    {
	      return E_ERR;
	    }
	}
      pRrSub = pRrSub->next;
    }
  return E_OK;
}

void
FreeRRO (RR_OBJ * pRrObj)
{
  RR_SUBOBJ *pRrSubObj, *pRrSubObjNext;

  pRrSubObj = pRrObj->rr;
  while (pRrSubObj != NULL)
    {
      pRrSubObjNext = pRrSubObj->next;
      XFREE (MTYPE_RSVP, pRrSubObj);
      pRrSubObj = pRrSubObjNext;
    }
  pRrObj->rr = NULL;
}

void
FreeERO (ER_OBJ * pErObj)
{
  ER_SUBOBJ *pErSubObj, *pErSubObjNext;

  pErSubObj = pErObj->er;
  while (pErSubObj != NULL)
    {
      pErSubObjNext = pErSubObj->next;
      XFREE (MTYPE_RSVP, pErSubObj);
      pErSubObj = pErSubObjNext;
    }
  pErObj->er = NULL;
}

void
FreeSessionAttributes (SESSION_ATTRIBUTES_OBJ * pSessAttr)
{
  if (pSessAttr->CType == SESSION_ATTRIBUTES_RA_IPV4_CTYPE)
    {
      if (pSessAttr->u.SessAttrRa.SessionName != NULL)
	{
	  XFREE (MTYPE_RSVP, pSessAttr->u.SessAttrRa.SessionName);
	}
    }
  else if (pSessAttr->CType == SESSION_ATTRIBUTES_IPV4_CTYPE)
    {
      if (pSessAttr->u.SessAttr.SessionName != NULL)
	{
	  XFREE (MTYPE_RSVP, pSessAttr->u.SessAttr.SessionName);
	}
    }
}

void
FreeOpaqueObj (OPAQUE_OBJ_LIST * pOpaqueObjListHead)
{
  OPAQUE_OBJ_LIST *pOpaqueObjList = pOpaqueObjListHead, *pOpaqueObjListNext;

  while (pOpaqueObjList != NULL)
    {
      pOpaqueObjListNext = pOpaqueObjList->next;
      if (pOpaqueObjList->pData)
	XFREE (MTYPE_RSVP, pOpaqueObjList->pData);
      XFREE (MTYPE_RSVP, pOpaqueObjList);
      pOpaqueObjList = pOpaqueObjListNext;
    }
}

void
FreeFilterSpecData (FILTER_SPEC_DATA ** ppFilterSpecData)
{
  FILTER_SPEC_DATA *pFilterSpecData = *ppFilterSpecData;
  zlog_info ("entering FreeFilterSpecData");
  FreeRRO (&pFilterSpecData->Rro);
  XFREE (MTYPE_RSVP, *ppFilterSpecData);
  *ppFilterSpecData = NULL;
  zlog_info ("leaving FreeFilterSpecData");
}

void
FreeRsvpPkt (RSVP_PKT * pRsvpPkt)
{
  FILTER_LIST *pFilterList, *pFilterList2;
  zlog_info ("entering FreeRsvpPkt");
  FreeRRO (&pRsvpPkt->AddedRro);
  FreeRRO (&pRsvpPkt->ReceivedRro);
  FreeERO (&pRsvpPkt->ReceivedEro);
  FreeERO (&pRsvpPkt->SentEro);
  FreeSessionAttributes (&pRsvpPkt->SessionAttributes);
  FreeOpaqueObj (pRsvpPkt->pIntegrityObj);
  FreeOpaqueObj (pRsvpPkt->pPolicyDataObj);
  FreeOpaqueObj (pRsvpPkt->pOpaqueObjList);
  pFilterList = pRsvpPkt->pFilterList;
  while (pFilterList != NULL)
    {
      FILTER_SPEC_DATA *pFilterSpecData = pFilterList->pFilterSpecData;
      pFilterList2 = pFilterList->next;
      if (DeleteFilterListNode (&pRsvpPkt->pFilterList,
				pFilterSpecData) != E_OK)
	{
	  zlog_err ("cannot delete filter list node %s %d", __FILE__,
		    __LINE__);
	}
      FreeFilterSpecData (&pFilterSpecData);
      pFilterList = pFilterList2;
    }
  XFREE (MTYPE_RSVP, pRsvpPkt);
  zlog_info ("leaving FreeRsvpPkt");
}

E_RC
EnqueueRsvpPacket (RSVP_PKT_QUEUE * pItem, RSVP_PKT_QUEUE ** ppQueueHead)
{
  RSVP_PKT_QUEUE *pQueue;
  zlog_info ("entering EnqueueRsvpPacket");

  if ((*ppQueueHead) == NULL)
    {
      (*ppQueueHead) = pItem;
      zlog_info ("leaving EnqueueRsvpPacket");
      return E_OK;
    }
  pQueue = (*ppQueueHead);
  while (pQueue->next != NULL)
    pQueue = pQueue->next;
  pQueue->next = pItem;
  zlog_info ("leaving EnqueueRsvpPacket");
  return E_OK;
}

RSVP_PKT_QUEUE *
DequeueRsvpPacket (RSVP_PKT_QUEUE ** ppQueueHead)
{
  RSVP_PKT_QUEUE *pTemp;
  zlog_info ("entering DequeueRsvpPacket");
  if ((*ppQueueHead) == NULL)
    {
      return NULL;
    }
  pTemp = (*ppQueueHead);
  (*ppQueueHead) = (*ppQueueHead)->next;
  zlog_info ("leaving DequeueRsvpPacket");
  return pTemp;
}

void
FreePSB (PSB * pPsb)
{
  RSVP_PKT_QUEUE *pQueueItem;
  zlog_info ("entering FreePSB");
  if (pPsb->pSentBuffer)
    {
      XFREE (MTYPE_RSVP, pPsb->pSentBuffer);
      pPsb->pSentBuffer = NULL;
    }
  if (RemovePsb (&pPsb->PsbKey) == E_OK)
    {
      if (pPsb->OldPacket.SessionAttributes.CType ==
	  SESSION_ATTRIBUTES_CLASS_TYPE)
	{
	  if (pPsb->OldPacket.SessionAttributes.u.SessAttr.SessionName !=
	      NULL)
	    {
	      XFREE (MTYPE_RSVP,
		     pPsb->OldPacket.SessionAttributes.u.SessAttr.
		     SessionName);
	    }
	}
      else if (pPsb->OldPacket.SessionAttributes.CType ==
	       SESSION_ATTRIBUTES_RA_CLASS_TYPE)
	{
	  if (pPsb->OldPacket.SessionAttributes.u.SessAttrRa.SessionName !=
	      NULL)
	    {
	      XFREE (MTYPE_RSVP,
		     pPsb->OldPacket.SessionAttributes.u.SessAttrRa.
		     SessionName);
	    }
	}
      FreeRRO (&pPsb->OldPacket.AddedRro);
      FreeRRO (&pPsb->OldPacket.ReceivedRro);
      FreeERO (&pPsb->OldPacket.ReceivedEro);
      FreeERO (&pPsb->OldPacket.SentEro);
      FreeOpaqueObj (pPsb->OldPacket.pIntegrityObj);
      FreeOpaqueObj (pPsb->OldPacket.pPolicyDataObj);
      FreeOpaqueObj (pPsb->OldPacket.pOpaqueObjList);
      while ((pQueueItem = DequeueRsvpPacket (&pPsb->packet_queue)) != NULL)
	{
	  FreeRsvpPkt (pQueueItem->pRsvpPkt);
	}
      XFREE (MTYPE_RSVP, pPsb);
    }
  else
    {
      zlog_err ("Freeing os PSB was not completed");
    }
  RsvpStatistics.DeletePsbCount++;
  zlog_info ("leaving FreePSB");
}

void
FreeRSB (RSB * pRsb)
{
  zlog_info ("entering FreeRSB");
  if (RemoveRSB (&pRsb->RsbKey) == E_OK)
    {
      FreeOpaqueObj (pRsb->OldPacket.pIntegrityObj);
      FreeOpaqueObj (pRsb->OldPacket.pPolicyDataObj);
      FreeOpaqueObj (pRsb->OldPacket.pOpaqueObjList);
      XFREE (MTYPE_RSVP, pRsb);
    }
  else
    {
      zlog_err ("Cannot free RSB");
    }
  RsvpStatistics.DeleteRsbCount++;
  zlog_info ("leaving FreeRSB");
}

E_RC
InsertERO (ER_OBJ * pEro, ER_HOP * Path, uns16 HopNum)
{
  int i;
  ER_SUBOBJ *pErSubObjTail = pEro->er, *pErSubObjNew;

  if (pErSubObjTail != NULL)
    {
      while (pErSubObjTail->next != NULL)
	{
	  pErSubObjTail = pErSubObjTail->next;
	}
    }
  for (i = 0; i < HopNum; i++)
    {
      pErSubObjNew = (ER_SUBOBJ *) XMALLOC (MTYPE_RSVP, sizeof (ER_SUBOBJ));
      if (pErSubObjNew == NULL)
	{
	  zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      if (pErSubObjTail == NULL)
	{
	  pEro->er = pErSubObjNew;
	  pErSubObjTail = pErSubObjNew;
	}
      else
	{
	  pErSubObjTail->next = pErSubObjNew;
	  pErSubObjTail = pErSubObjTail->next;
	}
      memset (pErSubObjTail, 0, sizeof (ER_SUBOBJ));
      pErSubObjTail->SubObjHdr.LType = ERO_SUBTYPE_IPV4;
      pErSubObjTail->SubObjHdr.Length = 8;
      pErSubObjTail->u.Ipv4.IpAddress = Path[i].IpAddr;
      pErSubObjTail->u.Ipv4.PrefixLength = Path[i].PrefixLength;
      if (Path[i].Loose)
	pErSubObjTail->SubObjHdr.LType |= 0x80;
    }
  return E_OK;
}

E_RC
InsertRRO (RSVP_PKT * pRsvpPkt)
{
  RR_SUBOBJ *pRrSub = pRsvpPkt->AddedRro.rr, *pRrSubNew;

  pRrSubNew = XMALLOC (MTYPE_RSVP, sizeof (RR_SUBOBJ));
  if (!pRrSubNew)
    {
      return E_ERR;
    }
  pRrSubNew->SubObjHdr.Length = 8;
  pRrSubNew->SubObjHdr.Type = RRO_SUBTYPE_IPV4;
  pRrSubNew->u.Ipv4.Flags = 0;
  pRrSubNew->u.Ipv4.IpAddr = GetRouterId ();
  pRrSubNew->u.Ipv4.PrefixLen = 32;
  if (pRrSub)
    {
      pRrSub = pRsvpPkt->AddedRro.rr;
      while (pRrSub->next != NULL)
	{
	  pRrSub = pRrSub->next;
	}
      pRrSub->next = pRrSubNew;
    }
  else
    {
      pRsvpPkt->AddedRro.rr = pRrSubNew;
    }
  return E_OK;
}

void
DumpSession (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  LOG4 ("SESSION: Dest %x Tunnel %x ExtTunnel %x",
	pRsvpPkt->Session.Dest,
	pRsvpPkt->Session.TunnelId, pRsvpPkt->Session.ExtTunelId);
}

void
DumpSenderTemplate (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  LOG3 ("SENDER_TEMPLATE: SrcIp %x LSP %x",
	pRsvpPkt->SenderTemplate.IpAddr, pRsvpPkt->SenderTemplate.LspId);
}

void
DumpSenderTSPec (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  LOG6
    ("SENDER_TSPEC: TockenBucketRate %f TockenBucketSize %f PeakDataRate %f MinPolicedUnit %x MaxPacketSize %x",
     pRsvpPkt->SenderTSpec.TockenBucketRate,
     pRsvpPkt->SenderTSpec.TockenBucketSize,
     pRsvpPkt->SenderTSpec.PeakDataRate, pRsvpPkt->SenderTSpec.MinPolicedUnit,
     pRsvpPkt->SenderTSpec.MaxPacketSize);
}

void
DumpRsvpHop (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  RSVP_HOP_OBJ RsvpHop;
  memset (&RsvpHop, 0, sizeof (RSVP_HOP_OBJ));
  if (memcmp (&pRsvpPkt->SentRsvpHop, &RsvpHop, sizeof (RSVP_HOP_OBJ)) != 0)
    {
      LOG3 ("RSVP_HOP: IP %x LIH %x",
	    pRsvpPkt->SentRsvpHop.PHop, pRsvpPkt->SentRsvpHop.LIH);
    }
  else
    {
      LOG3 ("RSVP_HOP: IP %x LIH %x",
	    pRsvpPkt->ReceivedRsvpHop.PHop, pRsvpPkt->ReceivedRsvpHop.LIH);
    }
}

void
DumpSessionAttr (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  if (pRsvpPkt->SessionAttributes.CType == SESSION_ATTRIBUTES_RA_IPV4_CTYPE)
    {
      LOG1 ("SESSION_ATTRIBUTES with RA");
      LOG4 ("%x %x %x",
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.ExcludeAny,
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAny,
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAll);
      LOG4 ("Flags: %x HoldPrio %x SetPrio %x",
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.Flags,
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.HoldPrio,
	    pRsvpPkt->SessionAttributes.u.SessAttrRa.SetPrio);
      if ((pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength != 0) &&
	  (pRsvpPkt->SessionAttributes.u.SessAttrRa.SessionName != NULL))
	{
	  LOG2 ("SessionName %s",
		pRsvpPkt->SessionAttributes.u.SessAttrRa.SessionName);
	}
    }
  else if (pRsvpPkt->SessionAttributes.CType == SESSION_ATTRIBUTES_IPV4_CTYPE)
    {
      LOG1 ("SESSION_ATTRIBUTES w/o RA");
      LOG4 ("Flags: %x HoldPrio %x SetPrio %x",
	    pRsvpPkt->SessionAttributes.u.SessAttr.Flags,
	    pRsvpPkt->SessionAttributes.u.SessAttr.HoldPrio,
	    pRsvpPkt->SessionAttributes.u.SessAttr.SetPrio);
      if ((pRsvpPkt->SessionAttributes.u.SessAttr.NameLength != 0) &&
	  (pRsvpPkt->SessionAttributes.u.SessAttr.SessionName != NULL))
	{
	  LOG2 ("SessionName %s",
		pRsvpPkt->SessionAttributes.u.SessAttr.SessionName);
	}
    }
}

void
DumpTimeValues (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  LOG2 ("TIME_VALUES %x", pRsvpPkt->TimeValues.TimeValues);
}

void
DumpAdSpec (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  LOG1 ("ADSPEC");
  if (pRsvpPkt->SentAdSpec.CType != 0)
    {
      LOG5 ("ComposedMTU %x IS_HopCount %x MinPathLatency %x PathBW %f",
	    pRsvpPkt->SentAdSpec.AdSpecGen.ComposedMTU,
	    pRsvpPkt->SentAdSpec.AdSpecGen.IS_HopCount,
	    pRsvpPkt->SentAdSpec.AdSpecGen.MinPathLatency,
	    pRsvpPkt->SentAdSpec.AdSpecGen.PathBW);
    }
  else if (pRsvpPkt->ReceivedAdSpec.CType != 0)
    {
      LOG5 ("ComposedMTU %x IS_HopCount %x MinPathLatency %x PathBW %f",
	    pRsvpPkt->ReceivedAdSpec.AdSpecGen.ComposedMTU,
	    pRsvpPkt->ReceivedAdSpec.AdSpecGen.IS_HopCount,
	    pRsvpPkt->ReceivedAdSpec.AdSpecGen.MinPathLatency,
	    pRsvpPkt->ReceivedAdSpec.AdSpecGen.PathBW);
    }
}

void
DumpRRO (RR_SUBOBJ * pRrSubObj, struct vty *vty)
{
  LOG1 ("RRO");
  while (pRrSubObj != NULL)
    {
      switch (pRrSubObj->SubObjHdr.Type)
	{
	case RRO_SUBTYPE_IPV4:
	  LOG4 ("IP %x PrefixLen %x Flags %x",
		pRrSubObj->u.Ipv4.IpAddr,
		pRrSubObj->u.Ipv4.PrefixLen, pRrSubObj->u.Ipv4.Flags);
	  break;
	case RRO_SUBTYPE_LABEL:
	  LOG3 ("LABEL %x Flags %x",
		pRrSubObj->u.Label.Label, pRrSubObj->u.Label.Flags);
	  break;
	default:
	  LOG2 ("RR subobject of unknown type %x", pRrSubObj->SubObjHdr.Type);
	}
      pRrSubObj = pRrSubObj->next;
    }
}

void
DumpERO (ER_SUBOBJ * pErSubObj, struct vty *vty)
{
  LOG1 ("ERO");
  while (pErSubObj != NULL)
    {
      if (pErSubObj->SubObjHdr.LType & 0x80)
	{
	  LOG1 ("LOOSE");
	}
      switch (pErSubObj->SubObjHdr.LType & 0x7F)
	{
	case ERO_SUBTYPE_IPV4:
	  LOG3 ("IP %x PrefixLen %x", pErSubObj->u.Ipv4.IpAddress,
		pErSubObj->u.Ipv4.PrefixLength);
	  break;
	case ERO_SUBTYPE_AS:
	  LOG2 ("AS %x", pErSubObj->u.AS.AsNumber);
	  break;
	default:
	  LOG2 ("ER subobject of unknown type %x",
		(pErSubObj->SubObjHdr.LType & 0x7F));
	}
      pErSubObj = pErSubObj->next;
    }
}

void
DumpPathMsg (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  DumpSession (pRsvpPkt, vty);
  DumpSenderTemplate (pRsvpPkt, vty);
  DumpSenderTSPec (pRsvpPkt, vty);
  DumpRsvpHop (pRsvpPkt, vty);
  DumpSessionAttr (pRsvpPkt, vty);
  DumpTimeValues (pRsvpPkt, vty);
  DumpAdSpec (pRsvpPkt, vty);
  DumpERO (pRsvpPkt->ReceivedEro.er, vty);
  DumpERO (pRsvpPkt->SentEro.er, vty);
  DumpRRO (pRsvpPkt->ReceivedRro.rr, vty);
  DumpRRO (pRsvpPkt->AddedRro.rr, vty);
}

void
DumpFilterSpec (FILTER_SPEC_OBJ * pFilterSpec, struct vty *vty)
{
  LOG3 ("IP %x LSP %x", pFilterSpec->IpAddr, pFilterSpec->LspId);
}

void
DumpFlowSpec (FLOW_SPEC_OBJ * pFlowSpec, struct vty *vty)
{
  if (pFlowSpec->ServHdr.ServHdr == FLOW_SPEC_CTRL_LOAD_SERV_NUMBER)
    {
      LOG6
	("TockenBucketRate %f TockenBucketSize %f PeakDataRate %f MinPolicedUnit %f MaxPacketSize %f",
	 pFlowSpec->u.CtrlLoad.TockenBucketRate,
	 pFlowSpec->u.CtrlLoad.TockenBucketSize,
	 pFlowSpec->u.CtrlLoad.PeakDataRate,
	 pFlowSpec->u.CtrlLoad.MinPolicedUnit,
	 pFlowSpec->u.CtrlLoad.MaxPacketSize);
    }
  else if (pFlowSpec->ServHdr.ServHdr == FLOW_SPEC_GUAR_SERV_NUMBER)
    {
      LOG6
	("TockenBucketRate %f TockenBucketSize %f PeakDataRate %f MinPolicedUnit %f MaxPacketSize %f",
	 pFlowSpec->u.Guar.CtrlLoad.TockenBucketRate,
	 pFlowSpec->u.Guar.CtrlLoad.TockenBucketSize,
	 pFlowSpec->u.Guar.CtrlLoad.PeakDataRate,
	 pFlowSpec->u.Guar.CtrlLoad.MinPolicedUnit,
	 pFlowSpec->u.Guar.CtrlLoad.MaxPacketSize);
      LOG3 ("Rate %f SlackTerm %x", pFlowSpec->u.Guar.Rate,
	    pFlowSpec->u.Guar.SlackTerm);
    }
}

void
DumpFlowDescr (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  FILTER_LIST *pFilterList = pRsvpPkt->pFilterList;
  while (pFilterList != NULL)
    {
      FILTER_SPEC_DATA *pFilterSpecData;
      if ((pFilterSpecData = pFilterList->pFilterSpecData) == NULL)
	{
	  pFilterList = pFilterList->next;
	  continue;
	}
      DumpFilterSpec (&pFilterSpecData->FilterSpec, vty);
      DumpFlowSpec (&pFilterSpecData->FlowSpec, vty);
      LOG2 ("Label %x", pFilterSpecData->ReceivedLabel.Label);
      DumpRRO (pFilterSpecData->Rro.rr, vty);
      pFilterList = pFilterList->next;
    }
}

void
DumpStyle (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  LOG2 ("STYLE %x", pRsvpPkt->Style.OptionVector2);
}

void
DumpResvMsg (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  DumpSession (pRsvpPkt, vty);
  DumpTimeValues (pRsvpPkt, vty);
  DumpRsvpHop (pRsvpPkt, vty);
  DumpStyle (pRsvpPkt, vty);
  DumpFlowDescr (pRsvpPkt, vty);
}

void
DumpErrSpec (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  LOG5 ("Error code %x Error value %x IP %x flags %x",
	pRsvpPkt->ErrorSpec.ErrCode,
	pRsvpPkt->ErrorSpec.ErrVal,
	pRsvpPkt->ErrorSpec.IpAddr, pRsvpPkt->ErrorSpec.Flags);
}

void
DumpPathErrMsg (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  DumpSession (pRsvpPkt, vty);
  DumpErrSpec (pRsvpPkt, vty);
  DumpSenderTemplate (pRsvpPkt, vty);
  DumpSenderTSPec (pRsvpPkt, vty);
}

void
DumpResvErrMsg (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  DumpSession (pRsvpPkt, vty);
  DumpRsvpHop (pRsvpPkt, vty);
  DumpErrSpec (pRsvpPkt, vty);
  DumpStyle (pRsvpPkt, vty);
  DumpFlowDescr (pRsvpPkt, vty);
}

void
DumpPathTearMsg (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  DumpSession (pRsvpPkt, vty);
  DumpRsvpHop (pRsvpPkt, vty);
  DumpSenderTemplate (pRsvpPkt, vty);
  DumpSenderTSPec (pRsvpPkt, vty);
}

void
DumpResvTearMsg (RSVP_PKT * pRsvpPkt, struct vty *vty)
{
  DumpSession (pRsvpPkt, vty);
  DumpRsvpHop (pRsvpPkt, vty);
  DumpStyle (pRsvpPkt, vty);
  DumpFlowDescr (pRsvpPkt, vty);
}

void
DumpPSB (PSB_KEY * pPsbKey, struct vty *vty)
{
  PSB_KEY PsbKey;
  PSB *pPsb;

  memset (&PsbKey, 0, sizeof (PSB_KEY));

  if (memcmp (pPsbKey, &PsbKey, sizeof (PSB_KEY)) == 0)
    {
      while ((pPsb = GetNextPSB (&PsbKey)) != NULL)
	{
	  LOG8
	    ("InIfIndex %x Label %x NextHop %x OutIfIndex %x TTL %x PrevHop %x TE_InProcess %x",
	     pPsb->InIfIndex, pPsb->Label, pPsb->NextHop, pPsb->OutIfIndex,
	     pPsb->ttl, pPsb->PrevHop, pPsb->TE_InProcess);
	  LOG5
	    ("AgeOutValue %x AgeOutTimer %s RefreshValue %x RefreshTimer %s",
	     pPsb->AgeOutValue,
	     (pPsb->AgeOutTimer == (uns32) NULL) ? "stopped" : "running",
	     pPsb->RefreshValue,
	     (pPsb->PathRefreshTimer ==
	      (uns32) NULL) ? "stopped" : "running");
	  LOG3 ("%s %s",
		(pPsb->pSentBuffer ==
		 NULL) ? "hasn't already encoded buffer (for refresh)" :
		"has encoded buffer for refresh",
		(pPsb->pRsb == NULL) ? "hasn't RSB" : "has RSB");
	  DumpPathMsg (&pPsb->OldPacket, vty);
	  PsbKey = pPsb->PsbKey;
	}
    }
  else
    {
      if ((pPsb = FindPsb (pPsbKey)) != NULL)
	{
	  LOG8
	    ("InIfIndex %x Label %x NextHop %x OutIfIndex %x TTL %x PrevHop %x TE_InProcess %x",
	     pPsb->InIfIndex, pPsb->Label, pPsb->NextHop, pPsb->OutIfIndex,
	     pPsb->ttl, pPsb->PrevHop, pPsb->TE_InProcess);
	  LOG5
	    ("AgeOutValue %x AgeOutTimer %s RefreshValue %x RefreshTimer %s",
	     pPsb->AgeOutValue,
	     (pPsb->AgeOutTimer == (uns32) NULL) ? "stopped" : "running",
	     pPsb->RefreshValue,
	     (pPsb->PathRefreshTimer ==
	      (uns32) NULL) ? "stopped" : "running");
	  LOG3 ("%s %s",
		(pPsb->pSentBuffer ==
		 NULL) ? "has already encoded buffer (for refresh)" :
		"hasn't encoded buffer for refresh",
		(pPsb->pRsb == NULL) ? "hasn't RSB" : "has RSB");
	  DumpPathMsg (&pPsb->OldPacket, vty);
	}
    }
}


void
DumpSingleRSB (RSB * pRsb, struct vty *vty)
{
  FILTER_LIST *pFilterList = pRsb->OldPacket.pFilterList;

  while (pFilterList != NULL)
    {
      FILTER_SPEC_DATA *pFilterSpecData = pFilterList->pFilterSpecData;
      if (pFilterSpecData == NULL)
	{
	  pFilterList = pFilterList->next;
	  continue;
	}
      DumpFilterSpec (&pFilterSpecData->FilterSpec, vty);
      if (pFilterSpecData->NewFlowSpecValid)
	{
	  DumpFlowSpec (&pFilterSpecData->NewFlowSpec, vty);
	}
      DumpFlowSpec (&pFilterSpecData->FlowSpec, vty);
      LOG2 ("Label %x", pFilterSpecData->ReceivedLabel.Label);
      DumpRRO (pFilterSpecData->Rro.rr, vty);
      if (pFilterSpecData->pEffectiveFlow != NULL)
	{
	  LOG3 ("IfIndex %x %s",
		pFilterSpecData->pEffectiveFlow->IfIndex,
		(pFilterSpecData->pEffectiveFlow->MustBeProcessed ==
		 1) ? "MustBeProcessed" : "");
	  DumpFlowSpec (&pFilterSpecData->pEffectiveFlow->CurrentFlowSpec,
			vty);
	  DumpFlowSpec (&pFilterSpecData->pEffectiveFlow->NewFlowSpec, vty);
	}
      if (pFilterSpecData->pPHopResvRefreshList != NULL)
	{
	  LOG8
	    ("PHOP IP %x PHOP LIH %x InIfIndex %x %s RefreshValue %x %s %s",
	     pFilterSpecData->pPHopResvRefreshList->PHop.PHop,
	     pFilterSpecData->pPHopResvRefreshList->PHop.LIH,
	     pFilterSpecData->pPHopResvRefreshList->InIfIndex,
	     (pFilterSpecData->pPHopResvRefreshList->MustBeProcessed ==
	      1) ? "MustBeProcessed" : "",
	     pFilterSpecData->pPHopResvRefreshList->RefreshValue,
	     (pFilterSpecData->pPHopResvRefreshList->ResvRefreshTimer ==
	      (uns32) NULL) ? "refresh timer is stopped" :
	     "refresh timer is running",
	     (pFilterSpecData->pPHopResvRefreshList->pSentBuffer ==
	      NULL) ? "hasn't encoded buffer for refresh" :
	     "has encoded buffer for refresh");
	  DumpRRO (pFilterSpecData->pPHopResvRefreshList->pAddedRro, vty);
	  DumpFlowSpec (&pFilterSpecData->pPHopResvRefreshList->FwdFlowSpec,
			vty);
	}
      LOG3 ("AgeOut value %x %s",
	    pFilterSpecData->AgeOutValue,
	    (pFilterSpecData->AgeOutTimer ==
	     (uns32) NULL) ? "age out timer is not running" :
	    "age out timer is running");
      pFilterList = pFilterList->next;
    }
}

void
DumpRSB (RSB_KEY * pRsbKey, struct vty *vty)
{
  RSB_KEY RsbKey;
  RSB *pRsb;

  memset (&RsbKey, 0, sizeof (RSB_KEY));

  if (memcmp (&RsbKey, pRsbKey, sizeof (RSB_KEY)) == 0)
    {
      while ((pRsb = GetNextRSB (&RsbKey)) != NULL)
	{
	  DumpSingleRSB (pRsb, vty);
	  RsbKey = pRsb->RsbKey;
	}
    }
  else
    {
      if ((pRsb = FindRsb (pRsbKey)) != NULL)
	{
	  DumpSingleRSB (pRsb, vty);
	}
    }
}

void
DumpRsvpStatistics (struct vty *vty)
{
  LOG7
    ("PathMsg %d ResvMsg %d PathTearMsg %d ResvTearMsg %d PathErrMsg %d ResvErrMsg %d",
     RsvpStatistics.PathMsgCount, RsvpStatistics.ResvMsgCount,
     RsvpStatistics.PathTearMsgCount, RsvpStatistics.ResvTearMsgCount,
     RsvpStatistics.PathErrMsgCount, RsvpStatistics.ResvErrMsgCount);
  LOG6 ("NewPsb %d DeletedPsb %d NewRsb %d DeletedRsb %d NewFilters %d",
	RsvpStatistics.NewPsbCount, RsvpStatistics.DeletePsbCount,
	RsvpStatistics.NewRsbCount, RsvpStatistics.DeleteRsbCount,
	RsvpStatistics.NewFiltersCount);
  LOG3 ("PathAgeOut %d FilterAgeOut %d", RsvpStatistics.PsbAgeOutCount,
	RsvpStatistics.FilterAgeOutCount);
}

int
RefreshRandomize (uns32 RefreshTimeBase)
{
  uns32 Range = RefreshTimeBase / 10;
  int k = rand ();
  while (k > Range)
    k = k / 3;
  return (k % 2) ? k : -k;
}
