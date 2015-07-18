#ifndef __RSVP_PSB__
#define __RSVP_PSB__


typedef struct _psb_
{
  PATRICIA_NODE Node;
  PSB_KEY PsbKey;
  RSVP_PKT OldPacket;
  int InIfIndex;
  IPV4_ADDR PrevHop;
  uns8 ttl;
  int OutIfIndex;
  uns32 Label;
  IPV4_ADDR NextHop;
  uns32 RefreshValue;
  struct thread *PathRefreshTimer;
  uns32 AgeOutValue;
  struct thread *AgeOutTimer;
  uns8 PathRefreshFlag;
  uns8 ResvRefreshFlag;
  uns8 TE_InProcess;
  char *pSentBuffer;
  uns16 SentBufferLen;
  struct _rsb_ *pRsb;
  FILTER_SPEC_DATA *pFilterSpecData;
  struct _rsvp_pkt_queue_ *packet_queue;
} PSB;

struct _te_api_msg_;

E_RC DeleteSender (PSB * pPsb);
E_RC ProcessRsvpPathMessage (RSVP_PKT * pRsvpPkt, uns32 IfIndex,
			     IPV4_ADDR SrcIpAddr, uns8 ttl);
E_RC ProcessRsvpPathErrMessage (RSVP_PKT * pRsvpPkt, uns32 IfIndex,
				IPV4_ADDR SrcIpAddr, uns8 ttl);
E_RC ProcessRsvpPathTearMessage (RSVP_PKT * pRsvpPkt, uns32 IfIndex,
				 IPV4_ADDR SrcIpAddr, uns8 ttl);
E_RC GeneratePathErrMessage (PSB * pPsb, uns8 ErrCode, uns16 ErrVal);
PSB *GetNextPSB (PSB_KEY * pPsbKey);
PSB *FindPsb (PSB_KEY * pPsbKey);
PSB *NewPsb (PSB_KEY * pPsbKey);
E_RC RsvpPathRefresh (PSB * pPsb);
E_RC InitRsvpPathMessageProcessing ();
E_RC ProcessTEMsgUponPath (struct _te_api_msg_ *pMsg);
E_RC RemovePsb (PSB_KEY * pPsbKey);
E_RC DeletePsb (PSB * pPsb);

#endif
