/* Module:   rsvp_decode.c
   Contains: RSVP packet decoding functions which parse
   the received packet.
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "rsvp.h"

uns32
decode_24bit (uns8 ** stream)
{

  uns32 val = 0;		/* Accumulator */


  val = (uns32) * (*stream)++ << 16;
  val |= (uns32) * (*stream)++ << 8;
  val |= (uns32) * (*stream)++;

  return (val & 0x00FFFFFF);

}

uns32
decode_32bit (uns8 ** stream)
{

  uns32 val = 0;		/* Accumulator */


  val = (uns32) * (*stream)++ << 24;
  val |= (uns32) * (*stream)++ << 16;
  val |= (uns32) * (*stream)++ << 8;
  val |= (uns32) * (*stream)++;

  return val;
}

uns16
decode_16bit (uns8 ** stream)
{

  uns32 val = 0;		/* Accumulator */


  val = (uns32) * (*stream)++ << 8;
  val |= (uns32) * (*stream)++;

  return (uns16) (val & 0x0000FFFF);
}

uns8
decode_8bit (uns8 ** stream)
{

  uns32 val = 0;		/* Accumulator */

  val = (uns32) * (*stream)++;

  return (uns8) (val & 0x000000FF);
}

#define DECODE_FLOAT(n, dec) {\
                                                            *((uns32 *) (dec)) = (n); \
                                                         }

float
decode_float (uns8 ** stream)
{
  uns32 val;
  float ret_val;

  val = (uns32) * (*stream)++ << 24;
  val |= (uns32) * (*stream)++ << 16;
  val |= (uns32) * (*stream)++ << 8;
  val |= (uns32) * (*stream)++;
  DECODE_FLOAT (val, &ret_val) return ret_val;
}

#define DECODE_COMMON_HDR \
{\
    RsvpCommonHdr.VersionFlags = decode_8bit((uns8 **)&pData);\
    RsvpCommonHdr.MsgType = decode_8bit((uns8 **)&pData);\
    RsvpCommonHdr.CheckSum = decode_16bit((uns8 **)&pData);\
    RsvpCommonHdr.SendTTL = decode_8bit((uns8 **)&pData);\
    RsvpCommonHdr.Resvd = decode_8bit((uns8 **)&pData);\
    RsvpCommonHdr.RsvpLength = decode_16bit((uns8 **)&pData);\
}

#define DECODE_OBJ_HDR \
{\
    pObjHdr = *ppData;\
    pObjHdr->Length = decode_16bit((uns8 **)ppData);\
    pObjHdr->ClassNum = decode_8bit((uns8 **)ppData);\
    pObjHdr->CType = decode_8bit((uns8 **)ppData);\
}

typedef struct
{
  E_RC (*pObjDecoder) (void **, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
		       uns32 RemainingLen);
} DECODE_HANDLER;

#define MAX_OBJS 300

DECODE_HANDLER DecodeHandlers[MAX_OBJS];

E_RC
SessionDecoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
		uns32 RemainingLen)
{
  pRsvpPkt->Session.Dest = decode_32bit ((uns8 **) ppData);
  pRsvpPkt->Session.Resvd = decode_16bit ((uns8 **) ppData);
  pRsvpPkt->Session.TunnelId = decode_16bit ((uns8 **) ppData);
  pRsvpPkt->Session.ExtTunelId = decode_32bit ((uns8 **) ppData);
  zlog_info ("Dest %x TunnelId %x ExtTunnelId %x",
	     pRsvpPkt->Session.Dest,
	     pRsvpPkt->Session.TunnelId, pRsvpPkt->Session.ExtTunelId);
  return E_OK;
}

E_RC
RsvpHopDecoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
		uns32 RemainingLen)
{
  pRsvpPkt->ReceivedRsvpHop.PHop = decode_32bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedRsvpHop.LIH = decode_32bit ((uns8 **) ppData);
  zlog_info ("RSVP HOP %x %x", pRsvpPkt->ReceivedRsvpHop.PHop,
	     pRsvpPkt->ReceivedRsvpHop.LIH);
  return E_OK;
}

E_RC
TimeValuesDecoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
		   uns32 RemainingLen)
{
  pRsvpPkt->TimeValues.TimeValues = decode_32bit ((uns8 **) ppData);
  zlog_info ("Time Values %x", pRsvpPkt->TimeValues.TimeValues);
  return E_OK;
}

E_RC
SenderTemplateDecoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
		       uns32 RemainingLen)
{
  pRsvpPkt->SenderTemplate.IpAddr = decode_32bit ((uns8 **) ppData);
  pRsvpPkt->SenderTemplate.Resvd = decode_16bit ((uns8 **) ppData);
  pRsvpPkt->SenderTemplate.LspId = decode_16bit ((uns8 **) ppData);
  zlog_info ("IP %x LSP ID %x", pRsvpPkt->SenderTemplate.IpAddr,
	     pRsvpPkt->SenderTemplate.LspId);
  return E_OK;
}

E_RC
LabelReqDecoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
		 uns32 RemainingLen)
{
  pRsvpPkt->LabelRequest.Resvd = decode_16bit ((uns8 **) ppData);
  pRsvpPkt->LabelRequest.L3Pid = decode_16bit ((uns8 **) ppData);
  zlog_info ("Label Request");
  return E_OK;
}

E_RC
ERO_Decoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
	     uns32 RemainingLen)
{
  int Count;
  ER_SUBOBJ *pErSubObj, *pPrev = NULL;
  int Len = pObjHdr->Length - sizeof (OBJ_HDR);
  zlog_info ("entering ERO_Decoder");
  if (Len % 8)
    {
      zlog_err (" the length is not 8-alligned");
    }
  Count = Len / 8;
  while (Len > 0)
    {
      if ((pErSubObj =
	   (ER_SUBOBJ *) XMALLOC (MTYPE_RSVP, sizeof (ER_SUBOBJ))) == NULL)
	{
	  zlog_err (" malloc failed ");
	  return E_ERR;
	}
      memset (pErSubObj, 0, sizeof (ER_SUBOBJ));
      if (pRsvpPkt->ReceivedEro.er == NULL)
	{
	  pRsvpPkt->ReceivedEro.er = pErSubObj;
	}
      else
	{
	  pPrev->next = pErSubObj;
	}
      pErSubObj->SubObjHdr.LType = decode_8bit ((uns8 **) ppData);
      pErSubObj->SubObjHdr.Length = decode_8bit ((uns8 **) ppData);
      Len -= 8;
      if (pErSubObj->SubObjHdr.Length != 8)
	{
	  zlog_err (" the length of subobject is not 8!!!");
	  return E_ERR;
	}
      switch (pErSubObj->SubObjHdr.LType & 0x7F)
	{
	case ERO_SUBTYPE_IPV4:
	  pErSubObj->u.Ipv4.IpAddress = decode_32bit ((uns8 **) ppData);
	  pErSubObj->u.Ipv4.PrefixLength = decode_8bit ((uns8 **) ppData);
	  pErSubObj->u.Ipv4.Resvd = decode_8bit ((uns8 **) ppData);
	  zlog_info ("ERO subobject: IP %x prefix length %x",
		     pErSubObj->u.Ipv4.IpAddress,
		     pErSubObj->u.Ipv4.PrefixLength);
	  break;
	default:
	  zlog_err ("the type %d of subobject is unknown %s %d",
		    (pErSubObj->SubObjHdr.LType & 0x7F), __FILE__, __LINE__);
	  return E_ERR;
	}
      pPrev = pErSubObj;
    }
  zlog_info ("leaving ERO_Decoder");
  return E_OK;
}

E_RC
SessionAttrDecoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
		    uns32 RemainingLen)
{
  char *pP;

  pRsvpPkt->SessionAttributes.CType = pObjHdr->CType;
  if (pObjHdr->CType == SESSION_ATTRIBUTES_CLASS_TYPE)
    {
      pRsvpPkt->SessionAttributes.u.SessAttr.SetPrio =
	decode_8bit ((uns8 **) ppData);
      pRsvpPkt->SessionAttributes.u.SessAttr.HoldPrio =
	decode_8bit ((uns8 **) ppData);
      pRsvpPkt->SessionAttributes.u.SessAttr.Flags =
	decode_8bit ((uns8 **) ppData);
      pRsvpPkt->SessionAttributes.u.SessAttr.NameLength =
	decode_8bit ((uns8 **) ppData);
      if ((pRsvpPkt->SessionAttributes.u.SessAttr.NameLength % 4)
	  && (pRsvpPkt->SessionAttributes.u.SessAttr.NameLength))
	{
	  zlog_err ("Session name length is %d must be multiple of 4",
		    pRsvpPkt->SessionAttributes.u.SessAttr.NameLength);
	  return E_ERR;
	}
      if (pRsvpPkt->SessionAttributes.u.SessAttr.NameLength < 8)
	{
	  zlog_err ("Session name length is %d must be at least 8",
		    pRsvpPkt->SessionAttributes.u.SessAttr.NameLength);
	  //return E_ERR; currently, ignore
	}
      if (pRsvpPkt->SessionAttributes.u.SessAttr.NameLength != 0)
	{
	  pP = *ppData;
	  if ((pRsvpPkt->SessionAttributes.u.SessAttr.SessionName =
	       (char *) XMALLOC (MTYPE_RSVP,
				 sizeof (char) *
				 pRsvpPkt->SessionAttributes.u.SessAttr.
				 NameLength)) == NULL)
	    {
	      zlog_err ("cannot allocate memory %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }
	  memset (pRsvpPkt->SessionAttributes.u.SessAttr.SessionName, 0,
		  sizeof (char) *
		  pRsvpPkt->SessionAttributes.u.SessAttr.NameLength);
	  strncpy (pRsvpPkt->SessionAttributes.u.SessAttr.SessionName, pP,
		   pRsvpPkt->SessionAttributes.u.SessAttr.NameLength);
	  pP += pRsvpPkt->SessionAttributes.u.SessAttr.NameLength;
	  *ppData = pP;
	}
    }
  else if (pObjHdr->CType == SESSION_ATTRIBUTES_RA_CLASS_TYPE)
    {
      pRsvpPkt->SessionAttributes.u.SessAttrRa.ExcludeAny =
	decode_32bit ((uns8 **) ppData);
      pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAny =
	decode_32bit ((uns8 **) ppData);
      pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAll =
	decode_32bit ((uns8 **) ppData);
      pRsvpPkt->SessionAttributes.u.SessAttrRa.SetPrio =
	decode_8bit ((uns8 **) ppData);
      pRsvpPkt->SessionAttributes.u.SessAttrRa.HoldPrio =
	decode_8bit ((uns8 **) ppData);
      pRsvpPkt->SessionAttributes.u.SessAttrRa.Flags =
	decode_8bit ((uns8 **) ppData);
      pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength =
	decode_8bit ((uns8 **) ppData);
      if (pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength % 4)
	{
	  zlog_err ("Session name length is %d must be multiple of 4",
		    pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength);
	  return E_ERR;
	}
      if (pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength < 8)
	{
	  zlog_err ("Session name length is %d must be at least 8",
		    pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength);
	  //return E_ERR;currently, ingnore
	}
      if (pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength != 0)
	{
	  pP = *ppData;
	  if ((pRsvpPkt->SessionAttributes.u.SessAttrRa.SessionName =
	       (char *) XMALLOC (MTYPE_RSVP,
				 sizeof (char) *
				 pRsvpPkt->SessionAttributes.u.SessAttrRa.
				 NameLength)) == NULL)
	    {
	      zlog_err ("cannot allocate memory %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }
	  memset (pRsvpPkt->SessionAttributes.u.SessAttrRa.SessionName, 0,
		  sizeof (char) *
		  pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength);
	  strncpy (pRsvpPkt->SessionAttributes.u.SessAttrRa.SessionName, pP,
		   pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength);
	  pP += pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength;
	  *ppData = pP;
	}
    }
  else
    {
      zlog_err ("unknown session attributes object class type %d",
		pObjHdr->CType);
      return E_ERR;
    }
  zlog_debug ("Session Attributes");
  return E_OK;
}

E_RC
SenderTSpecDecoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
		    uns32 RemainingLen)
{
  pRsvpPkt->SenderTSpec.MessageHdr.VersionResvd =
    decode_16bit ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.MessageHdr.MessageLength =
    decode_16bit ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.ServHdr.ServHdr = decode_8bit ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.ServHdr.Resvd = decode_8bit ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.ServHdr.ServLength = decode_16bit ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.ParamHdr.ParamID = decode_8bit ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.ParamHdr.ParamFlags = decode_8bit ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.ParamHdr.ParamLength =
    decode_16bit ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.TockenBucketRate = decode_float ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.TockenBucketSize = decode_float ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.PeakDataRate = decode_float ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.MinPolicedUnit = decode_32bit ((uns8 **) ppData);
  pRsvpPkt->SenderTSpec.MaxPacketSize = decode_32bit ((uns8 **) ppData);
  zlog_info ("Sender TSPEC %f %f %f %x %x",
	     pRsvpPkt->SenderTSpec.PeakDataRate,
	     pRsvpPkt->SenderTSpec.TockenBucketRate,
	     pRsvpPkt->SenderTSpec.TockenBucketSize,
	     pRsvpPkt->SenderTSpec.MinPolicedUnit,
	     pRsvpPkt->SenderTSpec.MaxPacketSize);
  return E_OK;
}

E_RC
RRO_Decoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
	     uns32 RemainingLen)
{
  int Count;
  RR_SUBOBJ *pRrSubObj, *pPrev = NULL;
  int Len = pObjHdr->Length - sizeof (OBJ_HDR);
  if (Len % 8)
    {
      zlog_err (" the length is not 8-alligned");
    }
  Count = Len / 8;
  while (Len > 0)
    {
      if ((pRrSubObj =
	   (RR_SUBOBJ *) XMALLOC (MTYPE_RSVP, sizeof (RR_SUBOBJ))) == NULL)
	{
	  zlog_err (" malloc failed ");
	  return E_ERR;
	}
      memset (pRrSubObj, 0, sizeof (RR_SUBOBJ));
      if (pRsvpPkt->ReceivedRro.rr == NULL)
	{
	  pRsvpPkt->ReceivedRro.rr = pRrSubObj;
	}
      else
	{
	  pPrev->next = pRrSubObj;
	}
      pRrSubObj->SubObjHdr.Type = decode_8bit ((uns8 **) ppData);
      pRrSubObj->SubObjHdr.Length = decode_8bit ((uns8 **) ppData);
      Len -= 8;
      if (pRrSubObj->SubObjHdr.Length != 8)
	{
	  zlog_err (" the length of subobject is not 8!!!");
	  return E_ERR;
	}
      switch (pRrSubObj->SubObjHdr.Type)
	{
	case RRO_SUBTYPE_IPV4:
	  pRrSubObj->u.Ipv4.IpAddr = decode_32bit ((uns8 **) ppData);
	  pRrSubObj->u.Ipv4.PrefixLen = decode_8bit ((uns8 **) ppData);
	  pRrSubObj->u.Ipv4.Flags = decode_8bit ((uns8 **) ppData);
	  zlog_info ("RRO subobject: IP %x prefix length %x",
		     pRrSubObj->u.Ipv4.IpAddr, pRrSubObj->u.Ipv4.PrefixLen);
	  break;
	case RRO_SUBTYPE_LABEL:
	  pRrSubObj->u.Label.Flags = decode_8bit ((uns8 **) ppData);
	  pRrSubObj->u.Label.CType = decode_8bit ((uns8 **) ppData);
	  pRrSubObj->u.Label.Label = decode_32bit ((uns8 **) ppData);
	  zlog_info ("RRO subobject: Flags %x CType %x Label %x",
		     pRrSubObj->u.Label.Flags, pRrSubObj->u.Label.CType,
		     pRrSubObj->u.Label.Label);
	  break;
	default:
	  zlog_err ("the type %d of subobject is unknown %s %d",
		    pRrSubObj->SubObjHdr.Type, __FILE__, __LINE__);
	  return E_ERR;
	}
      pPrev = pRrSubObj;
    }
  return E_OK;
}

E_RC
AdSpecDecoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
	       uns32 RemainingLen)
{
  pRsvpPkt->ReceivedAdSpec.Resvd = decode_16bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.MsgLen = decode_16bit ((uns8 **) ppData);

  pRsvpPkt->ReceivedAdSpec.AdSpecGen.PerServHdr.PerServHdr =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.PerServHdr.BreakBitAndResvd =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.PerServHdr.Length =
    decode_16bit ((uns8 **) ppData);

  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param4Hdr.ParamID =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param4Hdr.ParamFlags =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param4Hdr.ParamLength =
    decode_16bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.IS_HopCount =
    decode_32bit ((uns8 **) ppData);

  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param6Hdr.ParamID =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param6Hdr.ParamFlags =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param6Hdr.ParamLength =
    decode_16bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.PathBW = decode_float ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param8Hdr.ParamID =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param8Hdr.ParamFlags =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param8Hdr.ParamLength =
    decode_16bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.MinPathLatency =
    decode_32bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param10Hdr.ParamID =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param10Hdr.ParamFlags =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param10Hdr.ParamLength =
    decode_16bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.AdSpecGen.ComposedMTU =
    decode_32bit ((uns8 **) ppData);

  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.PerServHdr.PerServHdr =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.PerServHdr.BreakBitAndResvd =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.PerServHdr.Length =
    decode_16bit ((uns8 **) ppData);

  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param133Hdr.ParamID =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param133Hdr.ParamFlags =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param133Hdr.ParamLength =
    decode_16bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Ctot = decode_32bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param134Hdr.ParamID =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param134Hdr.ParamFlags =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param134Hdr.ParamLength =
    decode_16bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Dtot = decode_32bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param135Hdr.ParamID =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param135Hdr.ParamFlags =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param135Hdr.ParamLength =
    decode_16bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Csum = decode_32bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param136Hdr.ParamID =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param136Hdr.ParamFlags =
    decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param136Hdr.ParamLength =
    decode_16bit ((uns8 **) ppData);
  pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Dsum = decode_32bit ((uns8 **) ppData);
  return E_OK;
}

E_RC
OpaqueObjDecoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
		  uns32 RemainingLen)
{
  zlog_warn ("inside of OpaqueObjDecoder");
  if (pObjHdr->ClassNum == INTEGRITY_CLASS)
    {
      if ((pRsvpPkt->pIntegrityObj =
	   (INTEGRITY_OBJ *) XMALLOC (MTYPE_RSVP,
				      sizeof (OPAQUE_OBJ_LIST))) == NULL)
	{
	  return E_ERR;
	}
      memset (pRsvpPkt->pIntegrityObj, 0, sizeof (OPAQUE_OBJ_LIST));
      pRsvpPkt->pIntegrityObj->ObjHdr = *pObjHdr;
      if ((pRsvpPkt->pIntegrityObj->pData =
	   (void *) XMALLOC (MTYPE_RSVP,
			     pObjHdr->Length - sizeof (OBJ_HDR))) == NULL)
	{
	  XFREE (MTYPE_RSVP, pRsvpPkt->pIntegrityObj);
	  return E_ERR;
	}
      memcpy (pRsvpPkt->pIntegrityObj->pData, *ppData,
	      pObjHdr->Length - sizeof (OBJ_HDR));
      (*((uns8 *) ppData)) += pObjHdr->Length - sizeof (OBJ_HDR);
    }
  else if (pObjHdr->ClassNum == POLICY_DATA_CLASS)
    {
      if ((pRsvpPkt->pPolicyDataObj =
	   (POLICY_DATA_OBJ *) XMALLOC (MTYPE_RSVP,
					sizeof (OPAQUE_OBJ_LIST))) == NULL)
	{
	  return E_ERR;
	}
      memset (pRsvpPkt->pPolicyDataObj, 0, sizeof (OPAQUE_OBJ_LIST));
      pRsvpPkt->pPolicyDataObj->ObjHdr = *pObjHdr;
      if ((pRsvpPkt->pPolicyDataObj->pData =
	   (void *) XMALLOC (MTYPE_RSVP,
			     pObjHdr->Length - sizeof (OBJ_HDR))) == NULL)
	{
	  XFREE (MTYPE_RSVP, pRsvpPkt->pPolicyDataObj);
	  return E_ERR;
	}
      memcpy (pRsvpPkt->pPolicyDataObj->pData, *ppData,
	      pObjHdr->Length - sizeof (OBJ_HDR));
      ((*(uns8 *) ppData)) += pObjHdr->Length - sizeof (OBJ_HDR);
    }
  else if ((pObjHdr->ClassNum != 0) && (pObjHdr->Length != 0))
    {
      OPAQUE_OBJ_LIST *pOpaqueObjTail =
	pRsvpPkt->pOpaqueObjList, *pOpaqueObjPrev = NULL;
      if (pOpaqueObjTail != NULL)
	{
	  while (pOpaqueObjTail->next != NULL)
	    {
	      pOpaqueObjTail = pOpaqueObjTail->next;
	    }
	}
      if (pOpaqueObjTail != NULL)
	{
	  if ((pOpaqueObjTail->next =
	       (OPAQUE_OBJ_LIST *) XMALLOC (MTYPE_RSVP,
					    sizeof (OPAQUE_OBJ_LIST))) ==
	      NULL)
	    {
	      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }
	  pOpaqueObjPrev = pOpaqueObjTail;
	  pOpaqueObjTail = pOpaqueObjTail->next;
	}
      else
	{
	  pOpaqueObjTail = pRsvpPkt->pOpaqueObjList =
	    (OPAQUE_OBJ_LIST *) XMALLOC (MTYPE_RSVP,
					 sizeof (OPAQUE_OBJ_LIST));
	  if (pOpaqueObjTail == NULL)
	    {
	      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }
	}
      memset (pOpaqueObjTail, 0, sizeof (OPAQUE_OBJ_LIST));
      pOpaqueObjTail->ObjHdr = *pObjHdr;
      if ((pOpaqueObjTail->pData =
	   (void *) XMALLOC (MTYPE_RSVP,
			     pObjHdr->Length - sizeof (OBJ_HDR))) == NULL)
	{
	  if (pOpaqueObjPrev == NULL)
	    {
	      pRsvpPkt->pOpaqueObjList = NULL;
	    }
	  else
	    {
	      pOpaqueObjPrev->next = NULL;
	    }
	  zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	  XFREE (MTYPE_RSVP, pOpaqueObjTail);
	  return E_ERR;
	}
      memcpy (pOpaqueObjTail->pData, *ppData,
	      pObjHdr->Length - sizeof (OBJ_HDR));
      ((*(uns8 *) ppData)) += pObjHdr->Length - sizeof (OBJ_HDR);
    }
  return E_OK;
}

E_RC
FlowSpecDecoder (void **ppData, FLOW_SPEC_OBJ * pFlowSpec)
{
  pFlowSpec->MsgHdr.VersionResvd = decode_16bit ((uns8 **) ppData);
  pFlowSpec->MsgHdr.MessageLength = decode_16bit ((uns8 **) ppData);
  pFlowSpec->ServHdr.ServHdr = decode_8bit ((uns8 **) ppData);
  pFlowSpec->ServHdr.Resvd = decode_8bit ((uns8 **) ppData);
  pFlowSpec->ServHdr.ServLength = decode_16bit ((uns8 **) ppData);
  pFlowSpec->ParamHdr.ParamID = decode_8bit ((uns8 **) ppData);
  pFlowSpec->ParamHdr.ParamFlags = decode_8bit ((uns8 **) ppData);
  pFlowSpec->ParamHdr.ParamLength = decode_16bit ((uns8 **) ppData);
  if (pFlowSpec->ServHdr.ServHdr == FLOW_SPEC_CTRL_LOAD_SERV_NUMBER)
    {
      pFlowSpec->u.CtrlLoad.TockenBucketRate =
	decode_float ((uns8 **) ppData);
      pFlowSpec->u.CtrlLoad.TockenBucketSize =
	decode_float ((uns8 **) ppData);
      pFlowSpec->u.CtrlLoad.PeakDataRate = decode_float ((uns8 **) ppData);
      zlog_info ("FLOW_SPEC - data rate %f",
		 pFlowSpec->u.CtrlLoad.PeakDataRate);
      pFlowSpec->u.CtrlLoad.MinPolicedUnit = decode_float ((uns8 **) ppData);
      pFlowSpec->u.CtrlLoad.MaxPacketSize = decode_float ((uns8 **) ppData);
    }
  else if (pFlowSpec->ServHdr.ServHdr == FLOW_SPEC_GUAR_SERV_NUMBER)
    {
      pFlowSpec->u.Guar.CtrlLoad.TockenBucketRate =
	decode_float ((uns8 **) ppData);
      pFlowSpec->u.Guar.CtrlLoad.TockenBucketSize =
	decode_float ((uns8 **) ppData);
      pFlowSpec->u.Guar.CtrlLoad.PeakDataRate =
	decode_float ((uns8 **) ppData);
      zlog_info ("FLOW_SPEC1 - data rate %f",
		 pFlowSpec->u.Guar.CtrlLoad.PeakDataRate);
      pFlowSpec->u.Guar.CtrlLoad.MinPolicedUnit =
	decode_float ((uns8 **) ppData);
      pFlowSpec->u.Guar.CtrlLoad.MaxPacketSize =
	decode_float ((uns8 **) ppData);
      pFlowSpec->u.Guar.GuarSpecificParamHdr.ParamID =
	decode_8bit ((uns8 **) ppData);
      pFlowSpec->u.Guar.GuarSpecificParamHdr.ParamFlags =
	decode_8bit ((uns8 **) ppData);
      pFlowSpec->u.Guar.GuarSpecificParamHdr.ParamLength =
	decode_16bit ((uns8 **) ppData);
      pFlowSpec->u.Guar.Rate = decode_float ((uns8 **) ppData);
      pFlowSpec->u.Guar.SlackTerm = decode_32bit ((uns8 **) ppData);
    }
  else
    {
      zlog_err ("Unknown FlowSpec %d", pFlowSpec->ServHdr.ServHdr);
      return E_ERR;
    }
  return E_OK;
}

E_RC
FilterSpecDecoder (void **ppData, FILTER_SPEC_OBJ * pFilterSpec)
{
  pFilterSpec->IpAddr = decode_32bit ((uns8 **) ppData);
  pFilterSpec->Resvd = decode_16bit ((uns8 **) ppData);
  pFilterSpec->LspId = decode_16bit ((uns8 **) ppData);
  zlog_info ("FILTER_SPEC %x %x", pFilterSpec->IpAddr, pFilterSpec->LspId);
  return E_OK;
}

E_RC
LabelDecoder (void **ppData, LABEL_OBJ * pLabelObj)
{
  pLabelObj->Label = decode_32bit ((uns8 **) ppData);
  zlog_info ("label decoded %x", pLabelObj->Label);
  return E_OK;
}

E_RC
FlowDescriptorDecoder (void **ppData, RSVP_PKT * pRsvpPkt, uns32 RemainingLen)
{
  FLOW_SPEC_OBJ *pFlowSpecObj, FlowSpec;
  FILTER_LIST *pFilterListTail = NULL, *pFilterListNew;
  FILTER_SPEC_DATA *pFilterSpecData = NULL;
  OBJ_HDR *pObjHdr;
  enum FlowDescrDecodeStates
  {
    FLOW_SPEC_DECODED,
    FILTER_SPEC_DECODED,
    LABEL_DECODED,
    OPAQ_DECODED
  } State;

  memset (&FlowSpec, 0, sizeof (FLOW_SPEC_OBJ));
  pFlowSpecObj = &FlowSpec;

  DECODE_OBJ_HDR if (pObjHdr->ClassNum != FLOW_SPEC_CLASS)
    {
      if (pObjHdr->ClassNum == FILTER_SPEC_CLASS)
	{
	  (*(char *) ppData) -= sizeof (OBJ_HDR);
	  goto flow_spec_missing;
	}
      zlog_err ("Expected flowspec is not found");
      return E_ERR;
    }
  if (FlowSpecDecoder (ppData, pFlowSpecObj) != E_OK)
    {
      zlog_err ("Cannot decode FlowSpec");
      return E_ERR;
    }
flow_spec_missing:

  State = FLOW_SPEC_DECODED;
  RemainingLen -= pObjHdr->Length;
  while (RemainingLen)
    {
      DECODE_OBJ_HDR switch (pObjHdr->ClassNum)
	{
	case FILTER_SPEC_CLASS:
	  if (State == OPAQ_DECODED)
	    {
	      zlog_err ("FILTER_SPEC after OPAQ");
	      return E_ERR;
	    }
	  if ((pFilterListNew =
	       (FILTER_LIST *) XMALLOC (MTYPE_RSVP,
					sizeof (FILTER_LIST))) == NULL)
	    {
	      zlog_err ("Memory allocation failed %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }
	  if ((pFilterSpecData =
	       (FILTER_SPEC_DATA *) XMALLOC (MTYPE_RSVP,
					     sizeof (FILTER_SPEC_DATA))) ==
	      NULL)
	    {
	      zlog_err ("Memory allocation failed %s %d", __FILE__, __LINE__);
	      XFREE (MTYPE_RSVP, pFilterListNew);
	      return E_ERR;
	    }
	  pFilterListNew->pFilterSpecData = pFilterSpecData;
	  if (FilterSpecDecoder (ppData, &pFilterSpecData->FilterSpec) !=
	      E_OK)
	    {
	      zlog_err ("Cannot decode filter spec");
	      XFREE (MTYPE_RSVP, pFilterSpecData);
	      XFREE (MTYPE_RSVP, pFilterListNew);
	      return E_ERR;
	    }
	  memcpy (&pFilterSpecData->NewFlowSpec, pFlowSpecObj,
		  sizeof (FLOW_SPEC_OBJ));
	  pFilterSpecData->NewFlowSpecValid = 1;
	  if (pFilterListTail == NULL)
	    {
	      pFilterListTail = pRsvpPkt->pFilterList = pFilterListNew;
	    }
	  else
	    {
	      pFilterListTail->next = pFilterListNew;
	      pFilterListTail = pFilterListTail->next;
	    }
	  State = FILTER_SPEC_DECODED;
	  break;
	case LABEL_CLASS:
	  if (State != FILTER_SPEC_DECODED)
	    {
	      zlog_err ("Label is not after FILTER_SPEC");
	      return E_ERR;
	    }
	  if (LabelDecoder (ppData, &pFilterSpecData->ReceivedLabel) != E_OK)
	    {
	      zlog_err ("Cannot decode Label");
	      return E_ERR;
	    }
	  State = LABEL_DECODED;
	  break;
	case RECORDED_ROUTE_CLASS:
	  if (State != LABEL_DECODED)
	    {
	      zlog_err ("RRO is not after LABEL");
	      return E_ERR;
	    }
	  if (RRO_Decoder (ppData, pRsvpPkt, pObjHdr, RemainingLen) != E_OK)
	    {
	      zlog_err ("Cannot decode RRO");
	      return E_ERR;
	    }
	  pFilterSpecData->Rro.rr = pRsvpPkt->ReceivedRro.rr;
	  pRsvpPkt->ReceivedRro.rr = NULL;
	  break;
	case FLOW_SPEC_CLASS:
	  if (State == FLOW_SPEC_DECODED)
	    {
	      zlog_err ("FLOW_SPEC is after FLOW_SPEC");
	      return E_ERR;
	    }
	  if (pRsvpPkt->Style.OptionVector2 != FF_STYLE_BITS)
	    {
	      zlog_err ("while SE style, FLOW_SPEC is already decoded");
	      return E_ERR;
	    }
	  if (FlowSpecDecoder (ppData, pFlowSpecObj) != E_OK)
	    {
	      zlog_err ("Cannot decode FlowSpec");
	      return E_ERR;
	    }
	  State = FLOW_SPEC_DECODED;
	  break;
	default:
	  zlog_err ("object of unknown type %x %s %d", pObjHdr->ClassNum,
		    __FILE__, __LINE__);
	  (*(uns8 *) ppData) -= 4;
	  return E_OK;
	  /*if(OpaqueObjDecoder(ppData,pRsvpPkt,pObjHdr) != E_OK)
	     {
	     zlog_err("Cannot decode OPAQUE object");
	     return E_ERR;
	     }
	     State = OPAQ_DECODED; */
	}
      RemainingLen -= pObjHdr->Length;
    }
  return E_OK;
}

E_RC
StyleDecoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
	      uns32 RemainingLen)
{
  pRsvpPkt->Style.Flags = decode_8bit ((uns8 **) ppData);
  pRsvpPkt->Style.OptionVector1 = decode_8bit ((uns8 **) ppData);
  pRsvpPkt->Style.OptionVector2 = decode_16bit ((uns8 **) ppData);
  zlog_info ("Style %x %x %x", pRsvpPkt->Style.Flags,
	     pRsvpPkt->Style.OptionVector1, pRsvpPkt->Style.OptionVector2);
  return FlowDescriptorDecoder (ppData, pRsvpPkt, RemainingLen - 4);
}

E_RC
ErrSpecDecoder (void **ppData, RSVP_PKT * pRsvpPkt, OBJ_HDR * pObjHdr,
		uns32 RemainingLen)
{
  pRsvpPkt->ErrorSpec.IpAddr = decode_32bit ((uns8 **) ppData);
  pRsvpPkt->ErrorSpec.Flags = decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ErrorSpec.ErrCode = decode_8bit ((uns8 **) ppData);
  pRsvpPkt->ErrorSpec.ErrVal = decode_16bit ((uns8 **) ppData);
  return E_OK;
}

void
InitRsvpDecoder ()
{
  memset (DecodeHandlers, 0, sizeof (DECODE_HANDLER) * (MAX_OBJS));
  DecodeHandlers[SESSION_CLASS].pObjDecoder = SessionDecoder;
  DecodeHandlers[RSVP_HOP_CLASS].pObjDecoder = RsvpHopDecoder;
  DecodeHandlers[TIME_VALUES_CLASS].pObjDecoder = TimeValuesDecoder;
  DecodeHandlers[SENDER_TEMPLATE_CLASS].pObjDecoder = SenderTemplateDecoder;
  DecodeHandlers[LABEL_REQUEST_CLASS].pObjDecoder = LabelReqDecoder;
  DecodeHandlers[EXPLICIT_ROUTE_CLASS].pObjDecoder = ERO_Decoder;
  DecodeHandlers[SESSION_ATTRIBUTE_CLASS].pObjDecoder = SessionAttrDecoder;
  DecodeHandlers[SENDER_TSPEC_CLASS].pObjDecoder = SenderTSpecDecoder;
  DecodeHandlers[RECORDED_ROUTE_CLASS].pObjDecoder = RRO_Decoder;
  DecodeHandlers[ADSPEC_CLASS].pObjDecoder = AdSpecDecoder;
  DecodeHandlers[STYLE_CLASS].pObjDecoder = StyleDecoder;
  DecodeHandlers[POLICY_DATA_CLASS].pObjDecoder = OpaqueObjDecoder;
  DecodeHandlers[INTEGRITY_CLASS].pObjDecoder = OpaqueObjDecoder;
  DecodeHandlers[ERR_SPEC_CLASS].pObjDecoder = ErrSpecDecoder;
}

E_RC
DecodeAndProcessRsvpMsg (void *pPkt, int PktLen, uns32 IfIndex,
			 IPV4_ADDR SrcIpAddr)
{
  RSVP_COMMON_HDR RsvpCommonHdr;
  RSVP_PKT *pRsvpPkt;
  uns8 *pData = pPkt;
  void **ppData;
  OBJ_HDR *pObjHdr;
  uns32 InitialAddress = (uns32) pData;
  uns16 CheckSum = 0;

  if ((pRsvpPkt =
       (RSVP_PKT *) XMALLOC (MTYPE_RSVP, sizeof (RSVP_PKT))) == NULL)
    {
      zlog_err ("memory allocation failed %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  memset (pRsvpPkt, 0, sizeof (RSVP_PKT));

  DECODE_COMMON_HDR if ((RsvpCommonHdr.VersionFlags & 0xF0) != RSVP_VERSION)
    {
      zlog_err (" wrong RSVP version %d %d", RsvpCommonHdr.VersionFlags,
		RsvpCommonHdr.MsgType);
    }
  else
    {
      zlog_debug ("RSVP message of right version");
      rsvp_calc_pkt_cksum (pPkt, PktLen, &CheckSum);
      if (RsvpCommonHdr.CheckSum != CheckSum)
	{
	  printf ("received checksum %x calculated %x\n",
		  RsvpCommonHdr.CheckSum, CheckSum);
	}
      else
	{
	  //zlog_info("received checksum is OK");
	}
    }
  //PktLen -= sizeof(RSVP_COMMON_HDR);

  while (((uns32) pData - InitialAddress) < PktLen)
    {
      ppData = (void **) &pData;
      DECODE_OBJ_HDR
	if (DecodeHandlers[pObjHdr->ClassNum].pObjDecoder != NULL)
	{
	  if (DecodeHandlers[pObjHdr->ClassNum].pObjDecoder (ppData,
							     pRsvpPkt,
							     pObjHdr,
							     (PktLen -
							      ((uns32) pData -
							       InitialAddress)))
	      != E_OK)
	    {
	      zlog_err ("Object decoding failed");
	    }
	  else
	    {
	      //zlog_debug("Object decoded");
	    }
	}
      else
	{
	  //zlog_warn("The object of class type %d is not supported %d",pObjHdr->ClassNum,pObjHdr->Length);
	  //((char *)pData) += pObjHdr->Length;
	  OpaqueObjDecoder (ppData, pRsvpPkt, pObjHdr,
			    (PktLen - ((uns32) pData - InitialAddress)));
	}
    }
  switch (RsvpCommonHdr.MsgType)
    {
    case PATH_MSG:
      DumpPathMsg (pRsvpPkt, NULL);
      if (ProcessRsvpPathMessage
	  (pRsvpPkt, IfIndex, SrcIpAddr, RsvpCommonHdr.SendTTL) != E_OK)
	{
	  zlog_err ("RSVP PATH message processing failed");
	}
      break;
    case RESV_MSG:
      DumpResvMsg (pRsvpPkt, NULL);
      if (ProcessRsvpResvMessage (pRsvpPkt) != E_OK)
	{
	  zlog_err ("An error on RESV processing");
	}
      break;
    case PATH_ERR_MSG:
      DumpPathErrMsg (pRsvpPkt, NULL);
      if (ProcessRsvpPathErrMessage
	  (pRsvpPkt, IfIndex, SrcIpAddr, RsvpCommonHdr.SendTTL) != E_OK)
	{
	  zlog_err ("An error on PATH_ERR processing");
	}
      break;
    case RESV_ERR_MSG:
      DumpResvErrMsg (pRsvpPkt, NULL);
      if (ProcessRsvpResvErrMessage (pRsvpPkt) != E_OK)
	{
	  zlog_err ("An error on RESV ERR message processing");
	}
      break;
    case PATH_TEAR_MSG:
      DumpPathTearMsg (pRsvpPkt, NULL);
      if (ProcessRsvpPathTearMessage
	  (pRsvpPkt, IfIndex, SrcIpAddr, RsvpCommonHdr.SendTTL) != E_OK)
	{
	  zlog_err ("An error on PATH_TEAR processing");
	}
      break;
    case RESV_TEAR_MSG:
      DumpResvTearMsg (pRsvpPkt, NULL);
      if (ProcessRsvpResvTearMessage (pRsvpPkt) != E_OK)
	{
	  zlog_err ("An error on RESV_TEAR processing");
	}
      break;
    case RESV_CONF_MSG:
      zlog_warn ("RESV Conf message is not supported");
      break;
    default:
      zlog_err ("RSVP message of unknown type is received");
    }
  //FreeRsvpPkt(&RsvpPkt);
  return E_OK;
}
