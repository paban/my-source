/* Module:   rsvp_api.c
   Contains: RSVP in-process API functions
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */

#include "rsvp.h"

void
RsvpPathSendCmd (TE_API_MSG * pMsg)
{
  if (IngressPathSend (&pMsg->u.IngressApi) != E_OK)
    {
      zlog_err ("Cannot invoke PATH");
    }
}

void
RsvpPathTearCmd (TE_API_MSG * pMsg)
{
  if (IngressPathTear (&pMsg->u.IngressApi) != E_OK)
    {
      zlog_err ("Cannot invoke PATH_TEAR");
    }
}
extern uns32 PathRefreshInterval;
E_RC
IngressPathSend (INGRESS_API * pIngressApi)
{
  PSB_KEY PsbKey;
  PSB *pPsb;
  RSVP_PKT *pRsvpPkt;
  memset (&PsbKey, 0, sizeof (PSB_KEY));
  PsbKey.Session.Dest = pIngressApi->Egress;
  PsbKey.Session.TunnelId = pIngressApi->TunnelId;
  PsbKey.Session.ExtTunelId = pIngressApi->src_ip;
  PsbKey.SenderTemplate.IpAddr = PsbKey.Session.ExtTunelId;
  PsbKey.SenderTemplate.LspId = pIngressApi->LspId;
  if ((pPsb = FindPsb (&PsbKey)) != NULL)
    {
      zlog_err ("RSVP LSP exists in this tunnel");
      return E_ERR;
    }
  if ((pPsb = NewPsb (&PsbKey)) == NULL)
    {
      zlog_err ("Cannot create PSB");
    }
  pRsvpPkt = &pPsb->OldPacket;
  pRsvpPkt->Session = PsbKey.Session;
  pRsvpPkt->SenderTemplate = PsbKey.SenderTemplate;
  pRsvpPkt->SentRsvpHop.LIH = pIngressApi->OutIfIndex;
  pPsb->NextHop = pIngressApi->NextHop;
  pPsb->OutIfIndex = pIngressApi->OutIfIndex;
  pPsb->RefreshValue = PathRefreshInterval;
  pPsb->ttl = 255;
  if (IpAddrGetByIfIndex (pPsb->OutIfIndex, &pRsvpPkt->SentRsvpHop.PHop) !=
      E_OK)
    {
      zlog_err ("Cannot get IP address by IfIndex %x", pPsb->OutIfIndex);
      return E_ERR;
    }
  else
    {
      pPsb->OldPacket.SentRsvpHop.PHop = pPsb->OldPacket.SentRsvpHop.PHop;
      zlog_info ("NHOP %x", pPsb->NextHop);
    }
  pRsvpPkt->LabelRequest.L3Pid = 0x800;
  pRsvpPkt->TimeValues.TimeValues = PathRefreshInterval * 1000;
  pRsvpPkt->SenderTSpec.MessageHdr.VersionResvd = 0;
  pRsvpPkt->SenderTSpec.MessageHdr.MessageLength = 7;
  pRsvpPkt->SenderTSpec.ServHdr.ServHdr = 1;
  pRsvpPkt->SenderTSpec.ServHdr.ServLength = 6;
  pRsvpPkt->SenderTSpec.ParamHdr.ParamID = 127;
  pRsvpPkt->SenderTSpec.ParamHdr.ParamLength = 5;
  pRsvpPkt->SenderTSpec.MaxPacketSize = 1500;
  pRsvpPkt->SenderTSpec.PeakDataRate = pIngressApi->BW;
  pRsvpPkt->SenderTSpec.MinPolicedUnit = 40;
  pRsvpPkt->SenderTSpec.TockenBucketRate = pIngressApi->BW;
  pRsvpPkt->SenderTSpec.TockenBucketSize = 1;
  if (pIngressApi->HopNum > 0)
    {
      zlog_info ("calling InsertERO %d", pIngressApi->HopNum);
      if (InsertERO
	  (&pRsvpPkt->SentEro, pIngressApi->Path,
	   pIngressApi->HopNum) != E_OK)
	{
	  FreeERO (&pRsvpPkt->SentEro);
	  zlog_err ("Cannot allocate ERO");
	  return E_ERR;
	}
    }

  if (pIngressApi->LabelRecordingDesired)
    {
      if (InsertRRO (pRsvpPkt) != E_OK)
	{
	  FreeRRO (&pRsvpPkt->AddedRro);
	  zlog_err ("Cannot allocate RRO");
	  return E_ERR;
	}
    }

  if (pIngressApi->RaValid)
    {
      pRsvpPkt->SessionAttributes.CType = SESSION_ATTRIBUTES_RA_IPV4_CTYPE;
      pRsvpPkt->SessionAttributes.u.SessAttrRa.ExcludeAny =
	pIngressApi->ExcludeAny;
      pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAll =
	pIngressApi->IncludeAll;
      pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAny =
	pIngressApi->IncludeAny;
      pRsvpPkt->SessionAttributes.u.SessAttrRa.SetPrio = pIngressApi->SetPrio;
      pRsvpPkt->SessionAttributes.u.SessAttrRa.HoldPrio =
	pIngressApi->HoldPrio;
      if (pIngressApi->Shared)
	pRsvpPkt->SessionAttributes.u.SessAttrRa.Flags |= SE_STYLE_DESIRED;
      if (pIngressApi->FrrDesired)
	pRsvpPkt->SessionAttributes.u.SessAttrRa.Flags |=
	  LOCAL_PROTECTION_DESIRED;
      if (pIngressApi->LabelRecordingDesired)
	pRsvpPkt->SessionAttributes.u.SessAttrRa.Flags |=
	  LABEL_RECORDING_DESIRED;
      if ((pRsvpPkt->SessionAttributes.u.SessAttrRa.SessionName =
	   (char *) XMALLOC (MTYPE_RSVP, strlen ("VADIM SURAEV   "))) != NULL)
	{
	  strcpy (pRsvpPkt->SessionAttributes.u.SessAttrRa.SessionName,
		  "VADIM SURAEV   ");
	  pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength =
	    strlen ("VADIM SURAEV   ");
	}
    }
  else
    {
      pRsvpPkt->SessionAttributes.CType = SESSION_ATTRIBUTES_IPV4_CTYPE;
      pRsvpPkt->SessionAttributes.u.SessAttr.SetPrio = pIngressApi->SetPrio;
      pRsvpPkt->SessionAttributes.u.SessAttr.HoldPrio = pIngressApi->HoldPrio;

      if (pIngressApi->Shared)
	pRsvpPkt->SessionAttributes.u.SessAttr.Flags |= SE_STYLE_DESIRED;
      if (pIngressApi->FrrDesired)
	pRsvpPkt->SessionAttributes.u.SessAttr.Flags |=
	  LOCAL_PROTECTION_DESIRED;
      if (pIngressApi->LabelRecordingDesired)
	pRsvpPkt->SessionAttributes.u.SessAttr.Flags |=
	  LABEL_RECORDING_DESIRED;
      if ((pRsvpPkt->SessionAttributes.u.SessAttr.SessionName =
	   (char *) XMALLOC (MTYPE_RSVP,
			     strlen ("VADIM SURAEV    ") + 1)) != NULL)
	{
	  strcpy (pRsvpPkt->SessionAttributes.u.SessAttr.SessionName,
		  "VADIM SURAEV    ");
	  pRsvpPkt->SessionAttributes.u.SessAttr.NameLength =
	    strlen ("VADIM SURAEV    ");
	}
    }

  return RsvpPathRefresh (pPsb);
}

E_RC
IngressPathTear (INGRESS_API * pIngressApi)
{
  PSB_KEY PsbKey;
  PSB *pPsb;

  memset (&PsbKey, 0, sizeof (PSB_KEY));
  PsbKey.Session.Dest = pIngressApi->Egress;
  PsbKey.Session.TunnelId = pIngressApi->TunnelId;
  PsbKey.Session.ExtTunelId = pIngressApi->src_ip;
  PsbKey.SenderTemplate.IpAddr = PsbKey.Session.ExtTunelId;
  PsbKey.SenderTemplate.LspId = pIngressApi->LspId;
  if ((pPsb = FindPsb (&PsbKey)) == NULL)
    {
      zlog_err ("RSVP LSP %x does not exist in this tunnel %x %x %x",
		pIngressApi->LspId, pIngressApi->Egress,
		pIngressApi->TunnelId, pIngressApi->src_ip);
      return E_ERR;
    }
  if (EncodeAndSendRsvpPathTearMessage
      (&pPsb->OldPacket, pPsb->NextHop, pPsb->OutIfIndex,
       pPsb->ttl - 1) != E_OK)
    {
      zlog_err ("Cannot encode/send RSVP PathTear %s %d", __FILE__, __LINE__);
    }
  if (DeleteSender (pPsb) != E_OK)
    {
      zlog_err ("An error on DeleteSender %s %d", __FILE__, __LINE__);
    }
  return E_OK;
}

E_RC
DebugSendResvTear (TE_API_MSG * pMsg)
{
  DEBUG_SEND_RESV_TEAR *pDbgResvTear = &pMsg->u.DebugSendResvTear;
  RSB *pRsb;
  RSB_KEY RsbKey;
  RSVP_PKT *pRsvpPkt;
  int i;

  RsbKey = pDbgResvTear->RsbKey;
  if ((pRsb = FindRsb (&RsbKey)) == NULL)
    {
      zlog_err ("Cannot find RSB %x %x %x %s %d",
		RsbKey.Session.Dest,
		RsbKey.Session.TunnelId,
		RsbKey.Session.ExtTunelId, __FILE__, __LINE__);
      return E_ERR;
    }
  if ((pRsvpPkt =
       (RSVP_PKT *) XMALLOC (MTYPE_RSVP, sizeof (RSVP_PKT))) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  memset (pRsvpPkt, 0, sizeof (RSVP_PKT));
  pRsvpPkt->Session = RsbKey.Session;
  pRsvpPkt->Style = pRsb->OldPacket.Style;
  for (i = 0; i < pDbgResvTear->FilterSpecNumber; i++)
    {
      FILTER_SPEC_DATA *pFilterSpecData;
      if ((pFilterSpecData =
	   (FILTER_SPEC_DATA *) XMALLOC (MTYPE_RSVP,
					 sizeof (FILTER_SPEC_DATA))) == NULL)
	{
	  zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	  FreeRsvpPkt (pRsvpPkt);
	  return E_ERR;
	}
      memset (pFilterSpecData, 0, sizeof (FILTER_SPEC_DATA));
      pFilterSpecData->FilterSpec = pDbgResvTear->FilterSpecs[i];
      if (NewFilterListNode (&pRsvpPkt->pFilterList, pFilterSpecData) != E_OK)
	{
	  zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	  FreeRsvpPkt (pRsvpPkt);
	  return E_ERR;
	}
    }
  return ProcessRsvpResvTearMessage (pRsvpPkt);
}
