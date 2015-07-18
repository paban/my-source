
#ifndef __RSVP_RSB_H_
#define __RSVP_RSB_H_

typedef struct _phop_resv_refresh_list_
{
  RSVP_HOP_OBJ PHop;
  uns32 InIfIndex;
  uns32 RefreshValue;
  struct thread *ResvRefreshTimer;
  FILTER_LIST *pFilterList;
  RR_SUBOBJ *pAddedRro;
  FLOW_SPEC_OBJ FwdFlowSpec;	/* for SE only */
  uns8 MustBeProcessed;
  char *pSentBuffer;
  uns16 SentBufferLen;
  struct _phop_resv_refresh_list_ *next;
} PHOP_RESV_REFRESH_LIST;

typedef struct _effective_flow_
{
  uns32 IfIndex;
  FLOW_SPEC_OBJ CurrentFlowSpec;
  uns8 MustBeProcessed;		/* indicates that list of corresponding filters was changed */
  FLOW_SPEC_OBJ NewFlowSpec;
  FILTER_LIST *pFilterList;
  uns8 TE_InProcess;
  struct _effective_flow_ *next;
} EFFECTIVE_FLOW;

typedef struct _rsb_
{
  PATRICIA_NODE Node;
  RSB_KEY RsbKey;
  RSVP_PKT OldPacket;
  uns8 ResvRefreshFlag;
  PHOP_RESV_REFRESH_LIST *pPHopResvRefreshList;
  EFFECTIVE_FLOW *pEffectiveFlow;	/* for SE only */
} RSB;

struct _te_api_msg_;

RSB *FindRsb (RSB_KEY * pRsbKey);
RSB *GetNextRSB (RSB_KEY * pRsbKey);
E_RC ProcessEffectiveFlows (RSB * pRsb);
E_RC ProcessPHopFilterSpecLists (RSB * pRsb, uns8 Shared);
E_RC FilterShutDown (FILTER_SPEC_DATA * pFilterSpecData, int Shared);
E_RC ProcessRsvpResvTearMessage (RSVP_PKT * pRsvpPkt);
E_RC ProcessRsvpResvErrMessage (RSVP_PKT * pRsvpPkt);
E_RC ProcessRsvpResvMessage (RSVP_PKT * pRsvpPkt);
E_RC NewFilterListNode (FILTER_LIST ** ppFilterListHead,
			FILTER_SPEC_DATA * pFilterSpecData);
E_RC ForwardResvTearMsg (RSB * pRsb);
E_RC NewModifiedPath (PSB * pPsb);
E_RC InitResvProcessing ();
E_RC ResvTeMsgProc (struct _te_api_msg_ *pMsg);
void PreemptFlow (struct _te_api_msg_ *pMsg);
E_RC RemoveRSB (RSB_KEY * pRsbKey);
E_RC DeleteFilterListNode (FILTER_LIST ** ppFilterList,
			   FILTER_SPEC_DATA * pFilterSpecData);

#endif
