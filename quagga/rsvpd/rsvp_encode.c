/* Module:   rsvp_encode.c
   Contains: RSVP packet encoding functions which make
   the packet ready to send.
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */

#include "rsvp.h"

void
encode_32bit (uns8 ** stream, uns32 val)
{
  *(*stream)++ = (uns8) (val >> 24);
  *(*stream)++ = (uns8) (val >> 16);
  *(*stream)++ = (uns8) (val >> 8);
  *(*stream)++ = (uns8) (val);
}

void
encode_24bit (uns8 ** stream, uns32 val)
{
  *(*stream)++ = (uns8) (val >> 16);
  *(*stream)++ = (uns8) (val >> 8);
  *(*stream)++ = (uns8) (val);
}


void
encode_16bit (uns8 ** stream, uns32 val)
{
  *(*stream)++ = (uns8) (val >> 8);
  *(*stream)++ = (uns8) (val);
}


void
encode_8bit (uns8 ** stream, uns32 val)
{
  *(*stream)++ = (uns8) (val);
}

void
encode_float (uns8 ** stream, float f)
{
  *((uns32 *) (*stream)) = htonl (*((uns32 *) & (f)));
  (*stream) += 4;
}

void
rsvp_calc_pkt_cksum (char *u, unsigned int PktLen, uns16 * const pCksum)
{
  uns32 Cksum32;
  unsigned int Offset;

  uns8 *p8;

  Cksum32 = 0;
  Offset = 0;
  while (PktLen > 1)
    {
      p8 = (uns8 *) (u + Offset);

      if (Offset != 2)		/* Offset 2 is the checksum word.  We don't add this in */
	{
	  Cksum32 += (uns32) ntohs (*((uns16 *) p8));
	  if ((Cksum32 & 0x80000000) != 0)
	    Cksum32 = (Cksum32 & 0xFFFF) + (Cksum32 >> 16);
	}
      Offset += 2;
      PktLen -= 2;
    }

  if (PktLen > 0)		/* Odd length? */
    {
      p8 = (uns8 *) (u + Offset);

      Cksum32 += (uns32) * p8;
    }

  while ((Cksum32 >> 16) != 0)
    Cksum32 = (Cksum32 & 0xFFFF) + (Cksum32 >> 16);

  *pCksum = (uns16) (~Cksum32);
}

static char BigBuffer[1500];

#define ENCODE_COMMON_HDR(VersionFlags,MsgType,CheckSum,SendTTL,Resvd,RsvpLength) \
{\
    encode_8bit((uns8 **)ppData,VersionFlags); /* VersionFlags */ \
    encode_8bit((uns8 **)ppData,MsgType);/* MsgType */ \
    pCheckSum = (uns16 *)(*ppData); \
    encode_16bit((uns8 **)ppData,CheckSum);/* CheckSum */ \
    encode_8bit((uns8 **)ppData,SendTTL);/* SendTTL */ \
    encode_8bit((uns8 **)ppData,Resvd);/* Resvd */ \
    pRsvpLength = (uns16*)(*ppData); \
    encode_16bit((uns8 **)ppData,RsvpLength);/* RsvpLength */\
    PktLen += 8; \
}

#define ENCODE_OBJ_HDR(Length,ClassNum,CType) \
{\
    pVariableLengthObj = (uns16 *)*ppData; \
    encode_16bit((uns8 **)ppData,Length); /* Length */\
    encode_8bit((uns8 **)ppData,ClassNum);/* ClassNum */\
    encode_8bit((uns8 **)ppData,CType);/* CType */\
    zlog_info("obj %d ctype %d len %d",ClassNum,CType,Length);\
    PktLen += 4; \
}

#define ENCODE_SESSION \
{\
    encode_32bit((uns8 **)ppData,pRsvpPkt->Session.Dest);\
    encode_16bit((uns8 **)ppData,pRsvpPkt->Session.Resvd);\
    encode_16bit((uns8 **)ppData,pRsvpPkt->Session.TunnelId);\
    encode_32bit((uns8 **)ppData,pRsvpPkt->Session.ExtTunelId);\
    PktLen += 12; \
}

#define ENCODE_RSVP_HOP \
{\
    encode_32bit((uns8 **)ppData,pRsvpPkt->SentRsvpHop.PHop); \
    encode_32bit((uns8 **)ppData,pRsvpPkt->SentRsvpHop.LIH); \
    PktLen += 8; \
}

#define ENCODE_TIME_VALUES \
{ \
    encode_32bit((uns8 **)ppData,pRsvpPkt->TimeValues.TimeValues); \
    PktLen += 4; \
}

#define ENCODE_STYLE \
{ \
   encode_8bit((uns8 **)ppData,pRsvpPkt->Style.Flags); \
   encode_8bit((uns8 **)ppData,pRsvpPkt->Style.OptionVector1); \
   encode_16bit((uns8 **)ppData,pRsvpPkt->Style.OptionVector2); \
   PktLen += 4; \
}

#define ENCODE_SENDER_TEMPLATE \
{ \
    encode_32bit((uns8 **)ppData,pRsvpPkt->SenderTemplate.IpAddr); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->SenderTemplate.Resvd); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->SenderTemplate.LspId); \
    PktLen += 8; \
}

#define ENCODE_LABEL_REQUEST \
{ \
    encode_16bit((uns8 **)ppData,pRsvpPkt->LabelRequest.Resvd); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->LabelRequest.L3Pid); \
    PktLen += 4; \
}

#define ENCODE_ERO \
{ \
    ER_SUBOBJ *pErSubObj = pRsvpPkt->ReceivedEro.er;\
    VariableLengthObj = sizeof(OBJ_HDR); /* for obj header */ \
    while(pErSubObj != NULL) \
    { \
        zlog_info("encoding of %x",pErSubObj->u.Ipv4.IpAddress);\
        encode_8bit((uns8 **)ppData,pErSubObj->SubObjHdr.LType);\
        encode_8bit((uns8 **)ppData,pErSubObj->SubObjHdr.Length);\
        PktLen += 2; \
        VariableLengthObj += 2; \
        switch(pErSubObj->SubObjHdr.LType & 0x7F) \
        {\
        case ERO_SUBTYPE_IPV4:\
            encode_32bit((uns8 **)ppData,pErSubObj->u.Ipv4.IpAddress);\
            encode_8bit((uns8 **)ppData,pErSubObj->u.Ipv4.PrefixLength);\
            encode_8bit((uns8 **)ppData,pErSubObj->u.Ipv4.Resvd);\
            VariableLengthObj += 6; \
            PktLen += 6; \
            break;\
        default:\
            zlog_err("the type %d of subobject is unknown %s %d",(pErSubObj->SubObjHdr.LType & 0x7F),__FILE__,__LINE__);\
            return E_ERR;\
        }\
        pErSubObj = pErSubObj->next; \
    }\
    pErSubObj = pRsvpPkt->SentEro.er;\
    while(pErSubObj != NULL)\
    {\
        zlog_info("encoding2 of %x",pErSubObj->u.Ipv4.IpAddress);\
        encode_8bit((uns8 **)ppData,pErSubObj->SubObjHdr.LType);\
        encode_8bit((uns8 **)ppData,pErSubObj->SubObjHdr.Length);\
        PktLen += 2; \
        VariableLengthObj += 2; \
        switch(pErSubObj->SubObjHdr.LType & 0x7F)\
        {\
        case ERO_SUBTYPE_IPV4:\
            encode_32bit((uns8 **)ppData,pErSubObj->u.Ipv4.IpAddress);\
            encode_8bit((uns8 **)ppData,pErSubObj->u.Ipv4.PrefixLength);\
            encode_8bit((uns8 **)ppData,pErSubObj->u.Ipv4.Resvd);\
            PktLen += 6; \
            VariableLengthObj += 6; \
            break;\
        default:\
            zlog_err("the type %d of subobject is unknown %s %d",(pErSubObj->SubObjHdr.LType & 0x7F),__FILE__,__LINE__);\
            return E_ERR;\
        }\
        pErSubObj = pErSubObj->next; \
    }\
}

#define ENCODE_SESSION_ATTRIBUTES \
{ \
    VariableLengthObj = sizeof(OBJ_HDR); /* for obj header */ \
    if(pRsvpPkt->SessionAttributes.CType == SESSION_ATTRIBUTES_CLASS_TYPE) \
    { \
        encode_8bit((uns8 **)ppData,pRsvpPkt->SessionAttributes.u.SessAttr.SetPrio); \
        encode_8bit((uns8 **)ppData,pRsvpPkt->SessionAttributes.u.SessAttr.HoldPrio); \
        encode_8bit((uns8 **)ppData,pRsvpPkt->SessionAttributes.u.SessAttr.Flags); \
        encode_8bit((uns8 **)ppData,pRsvpPkt->SessionAttributes.u.SessAttr.NameLength); \
        PktLen += 4; \
        VariableLengthObj += 4; \
        if(pRsvpPkt->SessionAttributes.u.SessAttr.NameLength % 4) \
        { \
            zlog_err("Session name length is %d must be multiple of 4",pRsvpPkt->SessionAttributes.u.SessAttr.NameLength); \
        } \
        if(pRsvpPkt->SessionAttributes.u.SessAttr.NameLength < 8) \
        { \
            zlog_err("Session name length is %d must be at least 8",pRsvpPkt->SessionAttributes.u.SessAttr.NameLength); \
        }\
        if(pRsvpPkt->SessionAttributes.u.SessAttr.NameLength != 0) \
        { \
            char *pP = *ppData; \
            strncpy(pP,pRsvpPkt->SessionAttributes.u.SessAttr.SessionName,pRsvpPkt->SessionAttributes.u.SessAttr.NameLength); \
            PktLen += pRsvpPkt->SessionAttributes.u.SessAttr.NameLength; \
            pP += pRsvpPkt->SessionAttributes.u.SessAttr.NameLength; \
            *ppData = pP; \
            VariableLengthObj += pRsvpPkt->SessionAttributes.u.SessAttr.NameLength; \
        } \
    } \
    else if(pRsvpPkt->SessionAttributes.CType == SESSION_ATTRIBUTES_RA_CLASS_TYPE) \
    { \
        encode_32bit((uns8 **)ppData,pRsvpPkt->SessionAttributes.u.SessAttrRa.ExcludeAny); \
        encode_32bit((uns8 **)ppData,pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAny); \
        encode_32bit((uns8 **)ppData,pRsvpPkt->SessionAttributes.u.SessAttrRa.IncludeAll); \
        encode_8bit((uns8 **)ppData,pRsvpPkt->SessionAttributes.u.SessAttrRa.SetPrio); \
        encode_8bit((uns8 **)ppData,pRsvpPkt->SessionAttributes.u.SessAttrRa.HoldPrio); \
        encode_8bit((uns8 **)ppData,pRsvpPkt->SessionAttributes.u.SessAttrRa.Flags); \
        encode_8bit((uns8 **)ppData,pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength); \
        PktLen += 16; \
        VariableLengthObj += 16; \
        if(pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength % 4) \
        { \
            zlog_err("Session name length is %d must be multiple of 4",pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength); \
        } \
        if(pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength < 8) \
        { \
            zlog_err("Session name length is %d must be at least 8",pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength); \
        } \
        if(pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength != 0) \
        { \
            char *pP = *ppData; \
            strncpy(pP,pRsvpPkt->SessionAttributes.u.SessAttrRa.SessionName,pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength); \
            PktLen += pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength; \
            pP += pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength; \
            *ppData = pP; \
            VariableLengthObj += pRsvpPkt->SessionAttributes.u.SessAttrRa.NameLength; \
        } \
    } \
    else \
    { \
        zlog_err("unknown session attributes object class type %d",pRsvpPkt->SessionAttributes.CType); \
    } \
    zlog_debug("Session Attributes"); \
}

#define ENCODE_SENDER_TSPEC \
{ \
    encode_16bit((uns8 **)ppData,pRsvpPkt->SenderTSpec.MessageHdr.VersionResvd); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->SenderTSpec.MessageHdr.MessageLength); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->SenderTSpec.ServHdr.ServHdr); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->SenderTSpec.ServHdr.Resvd); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->SenderTSpec.ServHdr.ServLength); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->SenderTSpec.ParamHdr.ParamID); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->SenderTSpec.ParamHdr.ParamFlags); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->SenderTSpec.ParamHdr.ParamLength); \
    encode_float((uns8 **)ppData,pRsvpPkt->SenderTSpec.TockenBucketRate); \
    encode_float((uns8 **)ppData,pRsvpPkt->SenderTSpec.TockenBucketSize); \
    encode_float((uns8 **)ppData,pRsvpPkt->SenderTSpec.PeakDataRate); \
    encode_32bit((uns8 **)ppData,pRsvpPkt->SenderTSpec.MinPolicedUnit); \
    encode_32bit((uns8 **)ppData,pRsvpPkt->SenderTSpec.MaxPacketSize); \
    PktLen += 32; \
}

#define ENCODE_RRO \
{ \
    RR_SUBOBJ *pRrSubObj = pRsvpPkt->ReceivedRro.rr; \
    VariableLengthObj = sizeof(OBJ_HDR); /* for obj header */ \
    while(pRrSubObj != NULL) \
    { \
        encode_8bit((uns8 **)ppData,pRrSubObj->SubObjHdr.Type); \
        encode_8bit((uns8 **)ppData,pRrSubObj->SubObjHdr.Length); \
        PktLen += 2; \
        VariableLengthObj += 2; \
        if(pRrSubObj->SubObjHdr.Length != 8) \
        { \
            zlog_err(" the length of subobject is not 8!!!"); \
        } \
        switch(pRrSubObj->SubObjHdr.Type) \
        { \
        case RRO_SUBTYPE_IPV4: \
            encode_32bit((uns8 **)ppData,pRrSubObj->u.Ipv4.IpAddr); \
            encode_8bit((uns8 **)ppData,pRrSubObj->u.Ipv4.PrefixLen); \
            encode_8bit((uns8 **)ppData,pRrSubObj->u.Ipv4.Flags); \
            zlog_info("RRO sub - IP: %x",pRrSubObj->u.Ipv4.IpAddr);\
            PktLen += 6; \
            VariableLengthObj += 6; \
            break; \
        case RRO_SUBTYPE_LABEL:\
            encode_8bit((uns8 **)ppData,pRrSubObj->u.Label.Flags); \
            encode_8bit((uns8 **)ppData,pRrSubObj->u.Label.CType); \
            encode_32bit((uns8 **)ppData,pRrSubObj->u.Label.Label); \
            zlog_info("RRO sub - Label: %x",pRrSubObj->u.Label.Label);\
            PktLen += 6; \
            VariableLengthObj += 6; \
            break; \
        default: \
            zlog_err("the type %d of subobject is unknown %s %d",pRrSubObj->SubObjHdr.Type,__FILE__,__LINE__); \
            return E_ERR;\
        } \
        pRrSubObj = pRrSubObj->next; \
    } \
    pRrSubObj = pRsvpPkt->AddedRro.rr; \
    while(pRrSubObj != NULL) \
    { \
        encode_8bit((uns8 **)ppData,pRrSubObj->SubObjHdr.Type); \
        encode_8bit((uns8 **)ppData,pRrSubObj->SubObjHdr.Length); \
        PktLen += 2; \
        VariableLengthObj += 2; \
        if(pRrSubObj->SubObjHdr.Length != 8) \
        { \
            zlog_err(" the length of subobject is not 8!!!"); \
        } \
        switch(pRrSubObj->SubObjHdr.Type) \
        { \
        case RRO_SUBTYPE_IPV4: \
            encode_32bit((uns8 **)ppData,pRrSubObj->u.Ipv4.IpAddr); \
            encode_8bit((uns8 **)ppData,pRrSubObj->u.Ipv4.PrefixLen); \
            encode_8bit((uns8 **)ppData,pRrSubObj->u.Ipv4.Flags); \
            zlog_info(" RRO sub - IP: %x",pRrSubObj->u.Ipv4.IpAddr);\
            PktLen += 6; \
            VariableLengthObj += 6; \
            break; \
        case RRO_SUBTYPE_LABEL:\
            encode_8bit((uns8 **)ppData,pRrSubObj->u.Label.Flags); \
            encode_8bit((uns8 **)ppData,pRrSubObj->u.Label.CType); \
            encode_32bit((uns8 **)ppData,pRrSubObj->u.Label.Label); \
            zlog_info(" RRO sub - Label: %x",pRrSubObj->u.Label.Label);\
            PktLen += 6; \
            VariableLengthObj += 6; \
            break; \
        default: \
            zlog_err("the type %d of subobject is unknown %s %d",pRrSubObj->SubObjHdr.Type,__FILE__,__LINE__); \
            return E_ERR;\
        } \
        pRrSubObj = pRrSubObj->next; \
    } \
}

#define ENCODE_ADSPEC \
{ \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.Resvd); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.MsgLen); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.PerServHdr.PerServHdr); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.PerServHdr.BreakBitAndResvd); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.PerServHdr.Length); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param4Hdr.ParamID); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param4Hdr.ParamFlags); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param4Hdr.ParamLength); \
    encode_32bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.IS_HopCount); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param6Hdr.ParamID); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param6Hdr.ParamFlags); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param6Hdr.ParamLength); \
    encode_float((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.PathBW); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param8Hdr.ParamID); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param8Hdr.ParamFlags); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param8Hdr.ParamLength); \
    encode_32bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.MinPathLatency); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param10Hdr.ParamID); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param10Hdr.ParamFlags); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.Param10Hdr.ParamLength); \
    encode_32bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.AdSpecGen.ComposedMTU); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.PerServHdr.PerServHdr); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.PerServHdr.BreakBitAndResvd); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.PerServHdr.Length); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param133Hdr.ParamID); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param133Hdr.ParamFlags); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param133Hdr.ParamLength); \
    encode_32bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Ctot); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param134Hdr.ParamID); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param134Hdr.ParamFlags); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param134Hdr.ParamLength); \
    encode_32bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Dtot); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param135Hdr.ParamID); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param135Hdr.ParamFlags); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param135Hdr.ParamLength); \
    encode_32bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Csum); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param136Hdr.ParamID); \
    encode_8bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param136Hdr.ParamFlags); \
    encode_16bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Param136Hdr.ParamLength); \
    encode_32bit((uns8 **)ppData,pRsvpPkt->ReceivedAdSpec.GuarAdSpec.Dsum); \
    PktLen += 76; \
}

#define ENCODE_ERR_SPEC \
{ \
   encode_32bit((uns8 **)ppData,pRsvpPkt->ErrorSpec.IpAddr); \
   encode_8bit((uns8 **)ppData,pRsvpPkt->ErrorSpec.Flags); \
   encode_8bit((uns8 **)ppData,pRsvpPkt->ErrorSpec.ErrCode); \
   encode_16bit((uns8 **)ppData,pRsvpPkt->ErrorSpec.ErrVal); \
}

#define ENCODE_FLOW_SPEC \
{ \
    if(pFlowSpecObj->ServHdr.ServHdr == FLOW_SPEC_CTRL_LOAD_SERV_NUMBER) \
    { \
       ENCODE_OBJ_HDR(sizeof(MSG_HDR)+sizeof(SERV_HDR)+sizeof(PARAM_HDR)+sizeof(CTRL_LOAD_FLOW_SPEC)+sizeof(OBJ_HDR),\
                      FLOW_SPEC_CLASS,\
                      FLOW_SPEC_INTSERV_CTYPE)\
    } \
    else if(pFlowSpecObj->ServHdr.ServHdr == FLOW_SPEC_GUAR_SERV_NUMBER)\
    { \
       ENCODE_OBJ_HDR(sizeof(MSG_HDR)+sizeof(SERV_HDR)+sizeof(PARAM_HDR)+sizeof(GUAR_FLOW_SPEC)+sizeof(OBJ_HDR),\
                      FLOW_SPEC_CLASS,\
                      FLOW_SPEC_INTSERV_CTYPE) \
    } \
    else \
    { \
       zlog_err("FlowSpec of unknown type"); \
    } \
    encode_16bit((uns8 **)ppData,pFlowSpecObj->MsgHdr.VersionResvd); \
    encode_16bit((uns8 **)ppData,pFlowSpecObj->MsgHdr.MessageLength); \
    encode_8bit((uns8 **)ppData,pFlowSpecObj->ServHdr.ServHdr); \
    encode_8bit((uns8 **)ppData,pFlowSpecObj->ServHdr.Resvd); \
    encode_16bit((uns8 **)ppData,pFlowSpecObj->ServHdr.ServLength); \
    encode_8bit((uns8 **)ppData,pFlowSpecObj->ParamHdr.ParamID); \
    encode_8bit((uns8 **)ppData,pFlowSpecObj->ParamHdr.ParamFlags); \
    encode_16bit((uns8 **)ppData,pFlowSpecObj->ParamHdr.ParamLength); \
    PktLen += 12; \
    if(pFlowSpecObj->ServHdr.ServHdr == FLOW_SPEC_CTRL_LOAD_SERV_NUMBER) \
    { \
       encode_float((uns8 **)ppData,pFlowSpecObj->u.CtrlLoad.TockenBucketRate);\
       encode_float((uns8 **)ppData,pFlowSpecObj->u.CtrlLoad.TockenBucketSize);\
       encode_float((uns8 **)ppData,pFlowSpecObj->u.CtrlLoad.PeakDataRate);\
       encode_float((uns8 **)ppData,pFlowSpecObj->u.CtrlLoad.MinPolicedUnit);\
       encode_float((uns8 **)ppData,pFlowSpecObj->u.CtrlLoad.MaxPacketSize);\
       PktLen += 20;\
    }\
    else if(pFlowSpecObj->ServHdr.ServHdr == FLOW_SPEC_GUAR_SERV_NUMBER)\
    {\
      encode_float((uns8 **)ppData,pFlowSpecObj->u.Guar.CtrlLoad.TockenBucketRate);\
      encode_float((uns8 **)ppData,pFlowSpecObj->u.Guar.CtrlLoad.TockenBucketSize);\
      encode_float((uns8 **)ppData,pFlowSpecObj->u.Guar.CtrlLoad.PeakDataRate);\
      encode_float((uns8 **)ppData,pFlowSpecObj->u.Guar.CtrlLoad.MinPolicedUnit);\
      encode_float((uns8 **)ppData,pFlowSpecObj->u.Guar.CtrlLoad.MaxPacketSize);\
      encode_8bit((uns8 **)ppData,pFlowSpecObj->u.Guar.GuarSpecificParamHdr.ParamID);\
      encode_8bit((uns8 **)ppData,pFlowSpecObj->u.Guar.GuarSpecificParamHdr.ParamFlags);\
      encode_16bit((uns8 **)ppData,pFlowSpecObj->u.Guar.GuarSpecificParamHdr.ParamLength);\
      encode_float((uns8 **)ppData,pFlowSpecObj->u.Guar.Rate);\
      encode_32bit((uns8 **)ppData,pFlowSpecObj->u.Guar.SlackTerm);\
      PktLen += 32;\
    }\
}

#define ENCODE_FILTER_SPEC \
{\
  pFilterSpecData = pFilterList->pFilterSpecData;\
  ENCODE_OBJ_HDR(sizeof(FILTER_SPEC_OBJ)+sizeof(OBJ_HDR),FILTER_SPEC_CLASS,FILTER_SPEC_LSP_IPV4_CTYPE)\
  encode_32bit((uns8 **)ppData,pFilterSpecData->FilterSpec.IpAddr);\
  encode_16bit((uns8 **)ppData,pFilterSpecData->FilterSpec.Resvd);\
  encode_16bit((uns8 **)ppData,pFilterSpecData->FilterSpec.LspId);\
  zlog_info("encoding FILTER_SPEC %x %x",pFilterSpecData->FilterSpec.IpAddr,pFilterSpecData->FilterSpec.LspId);\
  PktLen += 8;\
  ENCODE_OBJ_HDR(sizeof(LABEL_OBJ)+sizeof(OBJ_HDR),LABEL_CLASS,COMMON_CTYPE)\
  encode_32bit((uns8 **)ppData,pFilterSpecData->SentLabel.Label);\
  PktLen += 4;\
  pRsvpPkt->ReceivedRro.rr = pFilterSpecData->Rro.rr;\
  if((pRsvpPkt->ReceivedRro.rr != NULL)||\
     (pRsvpPkt->AddedRro.rr != NULL))\
  {\
     ENCODE_OBJ_HDR(0,RECORDED_ROUTE_CLASS,COMMON_CTYPE)\
     ENCODE_RRO\
     encode_16bit((uns8 **)&pVariableLengthObj,(uns32)VariableLengthObj);\
  }\
  pRsvpPkt->ReceivedRro.rr = NULL;\
}


E_RC
EncodeAndSendRsvpPathMessage (RSVP_PKT * pRsvpPkt,
			      IPV4_ADDR DestIpAddr,
			      uns32 OutIf,
			      uns8 ttl,
			      char **ppSentBuffer, uns16 * pSentBufferLen)
{
  uns16 PktLen = 0;
  uns8 VersionFlags = RSVP_VERSION;
  uns16 *pCheckSum, CheckSum = 0;
  uns16 *pRsvpLength;
  uns8 *pData = BigBuffer;
  uns8 **ppData = &pData;
  uns16 *pVariableLengthObj;
  uns16 VariableLengthObj;
  zlog_info ("entering EncodeAndSendRsvpPathMessage");
  memset (BigBuffer, 0, 1500);

  ENCODE_COMMON_HDR (VersionFlags, PATH_MSG, 0 /* CheckSum */ , ttl,
		     0 /* resvd */ , 0 /* RsvpLength */ )
    ENCODE_OBJ_HDR (sizeof (SESSION_OBJ) + sizeof (OBJ_HDR), SESSION_CLASS,
		    SESSION_CTYPE) ENCODE_SESSION
    ENCODE_OBJ_HDR (sizeof (RSVP_HOP_OBJ) + sizeof (OBJ_HDR), RSVP_HOP_CLASS,
		    COMMON_CTYPE) ENCODE_RSVP_HOP
    ENCODE_OBJ_HDR (sizeof (TIME_VALUES_OBJ) + sizeof (OBJ_HDR),
		    TIME_VALUES_CLASS,
		    COMMON_CTYPE) ENCODE_TIME_VALUES if ((pRsvpPkt->
							  ReceivedEro.er !=
							  NULL)
							 || (pRsvpPkt->
							     SentEro.er !=
							     NULL))
    {
      ENCODE_OBJ_HDR (0, EXPLICIT_ROUTE_CLASS, COMMON_CTYPE)
	ENCODE_ERO
	encode_16bit ((uns8 **) & pVariableLengthObj,
		      (uns32) VariableLengthObj);
    }
  ENCODE_OBJ_HDR (sizeof (LABEL_REQUEST_OBJ) + sizeof (OBJ_HDR),
		  LABEL_REQUEST_CLASS,
		  COMMON_CTYPE) ENCODE_LABEL_REQUEST if (pRsvpPkt->
							 SessionAttributes.
							 CType ==
							 SESSION_ATTRIBUTES_RA_CLASS_TYPE)
    {
      ENCODE_OBJ_HDR (0, SESSION_ATTRIBUTE_CLASS,
		      pRsvpPkt->SessionAttributes.
		      CType) ENCODE_SESSION_ATTRIBUTES encode_16bit ((uns8 **)
								     &
								     pVariableLengthObj,
								     (uns32)
								     VariableLengthObj);
    }
  else if (pRsvpPkt->SessionAttributes.CType == SESSION_ATTRIBUTES_CLASS_TYPE)
    {
      ENCODE_OBJ_HDR (0, SESSION_ATTRIBUTE_CLASS,
		      pRsvpPkt->SessionAttributes.
		      CType) ENCODE_SESSION_ATTRIBUTES encode_16bit ((uns8 **)
								     &
								     pVariableLengthObj,
								     (uns32)
								     VariableLengthObj);
    }
  ENCODE_OBJ_HDR (sizeof (SENDER_TEMPLATE_OBJ) + sizeof (OBJ_HDR),
		  SENDER_TEMPLATE_CLASS,
		  SENDER_TEMPLATE_CTYPE) ENCODE_SENDER_TEMPLATE
    ENCODE_OBJ_HDR (sizeof (SENDER_TSPEC_OBJ) + sizeof (OBJ_HDR),
		    SENDER_TSPEC_CLASS,
		    SENDER_TSPEC_CTYPE) ENCODE_SENDER_TSPEC if (pRsvpPkt->
								SentAdSpec.
								CType != 0)
    {
    ENCODE_OBJ_HDR (sizeof (ADSPEC_OBJ) + sizeof (OBJ_HDR), ADSPEC_CLASS,
		      COMMON_CTYPE) ENCODE_ADSPEC}
  if ((pRsvpPkt->ReceivedRro.rr != NULL) || (pRsvpPkt->AddedRro.rr != NULL))
    {
      ENCODE_OBJ_HDR (0, RECORDED_ROUTE_CLASS, COMMON_CTYPE)
	ENCODE_RRO
	encode_16bit ((uns8 **) & pVariableLengthObj,
		      (uns32) VariableLengthObj);
    }
  encode_16bit ((uns8 **) & pRsvpLength, PktLen);
  rsvp_calc_pkt_cksum (BigBuffer, PktLen, &CheckSum);
  encode_16bit ((uns8 **) & pCheckSum, CheckSum);
  if (((*ppSentBuffer) = (char *) XMALLOC (MTYPE_RSVP, PktLen)) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
    }
  else
    {
      *pSentBufferLen = PktLen;
      memcpy ((*ppSentBuffer), BigBuffer, *pSentBufferLen);
    }
  return SendRawData (BigBuffer, PktLen, DestIpAddr, OutIf, ttl, TRUE);
}

E_RC
EncodeAndSendRsvpResvMessage (RSVP_PKT * pRsvpPkt,
			      IPV4_ADDR DestIpAddr,
			      uns32 OutIf,
			      uns8 ttl,
			      char **ppSentBuffer, uns16 * pSentBufferLen)
{
  uns16 PktLen = 0;
  uns8 VersionFlags = RSVP_VERSION;
  uns16 *pCheckSum, CheckSum = 0;
  uns16 *pRsvpLength;
  uns8 *pData = BigBuffer;
  uns8 **ppData = &pData;
  uns16 *pVariableLengthObj;
  uns16 VariableLengthObj;
  FILTER_LIST *pFilterList;
  FILTER_SPEC_DATA *pFilterSpecData;
  FLOW_SPEC_OBJ *pFlowSpecObj;

  zlog_info ("entering EncodeAndSendRsvpResvMessage");
  memset (BigBuffer, 0, 1500);

  ENCODE_COMMON_HDR (VersionFlags, RESV_MSG, 0 /* CheckSum */ , ttl,
		     0 /* resvd */ , 0 /* RsvpLength */ )
    ENCODE_OBJ_HDR (sizeof (SESSION_OBJ) + sizeof (OBJ_HDR), SESSION_CLASS,
		    SESSION_CTYPE) ENCODE_SESSION
    ENCODE_OBJ_HDR (sizeof (RSVP_HOP_OBJ) + sizeof (OBJ_HDR), RSVP_HOP_CLASS,
		    COMMON_CTYPE) ENCODE_RSVP_HOP
    ENCODE_OBJ_HDR (sizeof (TIME_VALUES_OBJ) + sizeof (OBJ_HDR),
		    TIME_VALUES_CLASS,
		    COMMON_CTYPE) ENCODE_TIME_VALUES
    ENCODE_OBJ_HDR (sizeof (STYLE_OBJ) + sizeof (OBJ_HDR), STYLE_CLASS,
		    COMMON_CTYPE) ENCODE_STYLE pFilterList =
    pRsvpPkt->pFilterList;
  if (pRsvpPkt->Style.OptionVector2 == SE_STYLE_BITS)
    {
      if ((pFilterList == NULL) || (pFilterList->pFilterSpecData == NULL))
	{
	  zlog_err ("an error at %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pFilterSpecData = pFilterList->pFilterSpecData;
      pFlowSpecObj = &pFilterSpecData->pPHopResvRefreshList->FwdFlowSpec;
      ENCODE_FLOW_SPEC while (pFilterList != NULL)
	{
	  pFilterSpecData = pFilterList->pFilterSpecData;
	  ENCODE_FILTER_SPEC pFilterList = pFilterList->next;
	}
    }
  else
    {
      while (pFilterList != NULL)
	{
	  pFilterSpecData = pFilterList->pFilterSpecData;
	  pFlowSpecObj = &pFilterSpecData->FlowSpec;
	  ENCODE_FLOW_SPEC ENCODE_FILTER_SPEC pFilterList = pFilterList->next;
	}
    }
#if 0
  pRsvpPkt->AddedRro.rr = NULL;
#endif

  encode_16bit ((uns8 **) & pRsvpLength, PktLen);
  rsvp_calc_pkt_cksum (BigBuffer, PktLen, &CheckSum);
  encode_16bit ((uns8 **) & pCheckSum, CheckSum);
  if (((*ppSentBuffer) = (char *) XMALLOC (MTYPE_RSVP, PktLen)) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
    }
  else
    {
      *pSentBufferLen = PktLen;
      memcpy ((*ppSentBuffer), BigBuffer, *pSentBufferLen);
    }
  return SendRawData (BigBuffer, PktLen, DestIpAddr, OutIf, ttl, FALSE);
}

E_RC
EncodeAndSendRsvpPathErrMessage (RSVP_PKT * pRsvpPkt, IPV4_ADDR DestIpAddr,
				 uns32 OutIf, uns8 ttl)
{
  uns16 PktLen = 0;
  uns8 VersionFlags = RSVP_VERSION;
  uns16 *pCheckSum, CheckSum = 0;
  uns16 *pRsvpLength;
  uns8 *pData = BigBuffer;
  uns8 **ppData = &pData;
  uns16 *pVariableLengthObj;

  zlog_info ("entering EncodeAndSendRsvpPathErrMessage");
  memset (BigBuffer, 0, 1500);

  ENCODE_COMMON_HDR (VersionFlags, PATH_ERR_MSG, 0 /* CheckSum */ , ttl,
		     0 /* resvd */ , 0 /* RsvpLength */ )
    ENCODE_OBJ_HDR (sizeof (SESSION_OBJ) + sizeof (OBJ_HDR), SESSION_CLASS,
		    SESSION_CTYPE) ENCODE_SESSION
    ENCODE_OBJ_HDR (sizeof (ERR_SPEC_OBJ) + sizeof (OBJ_HDR), ERR_SPEC_CLASS,
		    COMMON_CTYPE) ENCODE_ERR_SPEC
    ENCODE_OBJ_HDR (sizeof (SENDER_TEMPLATE_OBJ) + sizeof (OBJ_HDR),
		    SENDER_TEMPLATE_CLASS,
		    SENDER_TEMPLATE_CTYPE) ENCODE_SENDER_TEMPLATE
    ENCODE_OBJ_HDR (sizeof (SENDER_TSPEC_OBJ) + sizeof (OBJ_HDR),
		    SENDER_TSPEC_CLASS,
		    SENDER_TSPEC_CTYPE) ENCODE_SENDER_TSPEC if (pRsvpPkt->
								SentAdSpec.
								CType != 0)
    {
    ENCODE_OBJ_HDR (sizeof (ADSPEC_OBJ) + sizeof (OBJ_HDR), ADSPEC_CLASS,
		      COMMON_CTYPE) ENCODE_ADSPEC}
  encode_16bit ((uns8 **) & pRsvpLength, PktLen);
  rsvp_calc_pkt_cksum (BigBuffer, PktLen, &CheckSum);
  encode_16bit ((uns8 **) & pCheckSum, CheckSum);
  return SendRawData (BigBuffer, PktLen, DestIpAddr, OutIf, ttl, TRUE);
}

E_RC
EncodeAndSendRsvpPathTearMessage (RSVP_PKT * pRsvpPkt, IPV4_ADDR DestIpAddr,
				  uns32 OutIf, uns8 ttl)
{
  uns16 PktLen = 0;
  uns8 VersionFlags = RSVP_VERSION;
  uns16 *pCheckSum, CheckSum = 0;
  uns16 *pRsvpLength;
  uns8 *pData = BigBuffer;
  uns8 **ppData = &pData;
  uns16 *pVariableLengthObj;

  zlog_info ("entering EncodeAndSendRsvpPathTearMessage");
  memset (BigBuffer, 0, 1500);

  ENCODE_COMMON_HDR (VersionFlags, PATH_TEAR_MSG, 0 /* CheckSum */ , ttl,
		     0 /* resvd */ , 0 /* RsvpLength */ )
    ENCODE_OBJ_HDR (sizeof (SESSION_OBJ) + sizeof (OBJ_HDR), SESSION_CLASS,
		    SESSION_CTYPE) ENCODE_SESSION
    ENCODE_OBJ_HDR (sizeof (RSVP_HOP_OBJ) + sizeof (OBJ_HDR), RSVP_HOP_CLASS,
		    COMMON_CTYPE) ENCODE_RSVP_HOP
    ENCODE_OBJ_HDR (sizeof (SENDER_TEMPLATE_OBJ) + sizeof (OBJ_HDR),
		    SENDER_TEMPLATE_CLASS,
		    SENDER_TEMPLATE_CTYPE) ENCODE_SENDER_TEMPLATE
    ENCODE_OBJ_HDR (sizeof (SENDER_TSPEC_OBJ) + sizeof (OBJ_HDR),
		    SENDER_TSPEC_CLASS,
		    SENDER_TSPEC_CTYPE) ENCODE_SENDER_TSPEC if (pRsvpPkt->
								SentAdSpec.
								CType != 0)
    {
    ENCODE_OBJ_HDR (sizeof (ADSPEC_OBJ) + sizeof (OBJ_HDR), ADSPEC_CLASS,
		      COMMON_CTYPE) ENCODE_ADSPEC}
  encode_16bit ((uns8 **) & pRsvpLength, PktLen);
  rsvp_calc_pkt_cksum (BigBuffer, PktLen, &CheckSum);
  encode_16bit ((uns8 **) & pCheckSum, CheckSum);
  return SendRawData (BigBuffer, PktLen, DestIpAddr, OutIf, ttl, TRUE);
}

E_RC
EncodeAndSendRsvpResvErrMessage (RSVP_PKT * pRsvpPkt, IPV4_ADDR DestIpAddr,
				 uns32 OutIf, uns8 ttl)
{
  uns16 PktLen = 0;
  uns8 VersionFlags = RSVP_VERSION;
  uns16 *pCheckSum, CheckSum = 0;
  uns16 *pRsvpLength;
  uns8 *pData = BigBuffer;
  uns8 **ppData = &pData;
  uns16 *pVariableLengthObj;
  uns16 VariableLengthObj;
  FILTER_LIST *pFilterList;
  FILTER_SPEC_DATA *pFilterSpecData;
  FLOW_SPEC_OBJ *pFlowSpecObj;

  zlog_info ("entering EncodeAndSendRsvpResvErrMessage");
  memset (BigBuffer, 0, 1500);

  ENCODE_COMMON_HDR (VersionFlags, RESV_ERR_MSG, 0 /* CheckSum */ , ttl,
		     0 /* resvd */ , 0 /* RsvpLength */ )
    ENCODE_OBJ_HDR (sizeof (SESSION_OBJ) + sizeof (OBJ_HDR), SESSION_CLASS,
		    SESSION_CTYPE) ENCODE_SESSION
    ENCODE_OBJ_HDR (sizeof (RSVP_HOP_OBJ) + sizeof (OBJ_HDR), RSVP_HOP_CLASS,
		    COMMON_CTYPE) ENCODE_RSVP_HOP
    ENCODE_OBJ_HDR (sizeof (ERR_SPEC_OBJ) + sizeof (OBJ_HDR), ERR_SPEC_CLASS,
		    COMMON_CTYPE) ENCODE_ERR_SPEC
    ENCODE_OBJ_HDR (sizeof (STYLE_OBJ) + sizeof (OBJ_HDR), STYLE_CLASS,
		    COMMON_CTYPE) ENCODE_STYLE pFilterList =
    pRsvpPkt->pFilterList;
  if (pRsvpPkt->Style.OptionVector2 == SE_STYLE_BITS)
    {
      if ((pFilterList == NULL) || (pFilterList->pFilterSpecData == NULL))
	{
	  zlog_err ("an error at %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pFilterSpecData = pFilterList->pFilterSpecData;
      pFlowSpecObj =
	(pFilterSpecData->NewFlowSpecValid) ? &pFilterSpecData->
	NewFlowSpec : &pFilterSpecData->FlowSpec;
      ENCODE_FLOW_SPEC while (pFilterList != NULL)
	{
	  pFilterSpecData = pFilterList->pFilterSpecData;
	  ENCODE_FILTER_SPEC pFilterList = pFilterList->next;
	}
    }
  else
    {
      while (pFilterList != NULL)
	{
	  pFilterSpecData = pFilterList->pFilterSpecData;
	  pFlowSpecObj = &pFilterSpecData->FlowSpec;
	  ENCODE_FLOW_SPEC ENCODE_FILTER_SPEC pFilterList = pFilterList->next;
	}
    }
  pRsvpPkt->AddedRro.rr = NULL;

  encode_16bit ((uns8 **) & pRsvpLength, PktLen);
  rsvp_calc_pkt_cksum (BigBuffer, PktLen, &CheckSum);
  encode_16bit ((uns8 **) & pCheckSum, CheckSum);
  return SendRawData (BigBuffer, PktLen, DestIpAddr, OutIf, ttl, TRUE);
}

E_RC
EncodeAndSendRsvpResvTearMessage (RSVP_PKT * pRsvpPkt, IPV4_ADDR DestIpAddr,
				  uns32 OutIf, uns8 ttl)
{
  uns16 PktLen = 0;
  uns8 VersionFlags = RSVP_VERSION;
  uns16 *pCheckSum, CheckSum = 0;
  uns16 *pRsvpLength;
  uns8 *pData = BigBuffer;
  uns8 **ppData = &pData;
  uns16 *pVariableLengthObj;
  uns16 VariableLengthObj;
  FILTER_LIST *pFilterList;
  FILTER_SPEC_DATA *pFilterSpecData;
  FLOW_SPEC_OBJ *pFlowSpecObj;

  zlog_info ("entering EncodeAndSendRsvpResvTearMessage");
  memset (BigBuffer, 0, 1500);

  ENCODE_COMMON_HDR (VersionFlags, RESV_TEAR_MSG, 0 /* CheckSum */ , ttl,
		     0 /* resvd */ , 0 /* RsvpLength */ )
    ENCODE_OBJ_HDR (sizeof (SESSION_OBJ) + sizeof (OBJ_HDR), SESSION_CLASS,
		    SESSION_CTYPE) ENCODE_SESSION
    ENCODE_OBJ_HDR (sizeof (RSVP_HOP_OBJ) + sizeof (OBJ_HDR), RSVP_HOP_CLASS,
		    COMMON_CTYPE) ENCODE_RSVP_HOP
    ENCODE_OBJ_HDR (sizeof (STYLE_OBJ) + sizeof (OBJ_HDR), STYLE_CLASS,
		    COMMON_CTYPE) ENCODE_STYLE pFilterList =
    pRsvpPkt->pFilterList;
  if (pRsvpPkt->Style.OptionVector2 == SE_STYLE_BITS)
    {
      if ((pFilterList == NULL) || (pFilterList->pFilterSpecData == NULL))
	{
	  zlog_err ("an error at %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pFilterSpecData = pFilterList->pFilterSpecData;
      pFlowSpecObj = &pFilterSpecData->pPHopResvRefreshList->FwdFlowSpec;
      ENCODE_FLOW_SPEC while (pFilterList != NULL)
	{
	  pFilterSpecData = pFilterList->pFilterSpecData;
	  ENCODE_FILTER_SPEC pFilterList = pFilterList->next;
	}
    }
  else
    {
      while (pFilterList != NULL)
	{
	  pFilterSpecData = pFilterList->pFilterSpecData;
	  pFlowSpecObj = &pFilterSpecData->FlowSpec;
	  ENCODE_FLOW_SPEC ENCODE_FILTER_SPEC pFilterList = pFilterList->next;
	}
    }
  pRsvpPkt->AddedRro.rr = NULL;

  encode_16bit ((uns8 **) & pRsvpLength, PktLen);
  rsvp_calc_pkt_cksum (BigBuffer, PktLen, &CheckSum);
  encode_16bit ((uns8 **) & pCheckSum, CheckSum);
  return SendRawData (BigBuffer, PktLen, DestIpAddr, OutIf, ttl, TRUE);
}
