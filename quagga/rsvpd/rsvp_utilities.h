
#ifndef _RSVP_UTILITIES_H_
#define _RSVP_UTILITIES_H_

typedef struct _rsvp_statistics_
{
  uns32 NewPsbCount;
  uns32 DeletePsbCount;
  uns32 NewRsbCount;
  uns32 DeleteRsbCount;
  uns32 NewFiltersCount;
  uns32 PsbAgeOutCount;
  uns32 FilterAgeOutCount;
  uns32 PathMsgCount;
  uns32 ResvMsgCount;
  uns32 PathTearMsgCount;
  uns32 ResvTearMsgCount;
  uns32 PathErrMsgCount;
  uns32 ResvErrMsgCount;
} RSVP_STATISTICS;


E_RC EnqueueRsvpPacket (RSVP_PKT_QUEUE * pItem,
			RSVP_PKT_QUEUE ** ppQueueHead);
RSVP_PKT_QUEUE *DequeueRsvpPacket (RSVP_PKT_QUEUE ** ppQueueHead);

int RefreshRandomize (uns32 RefreshTimeBase);

E_RC InsertRRO (RSVP_PKT * pRsvpPkt);

E_RC InsertERO (ER_OBJ * pEro, ER_HOP * Path, uns16 HopNum);

void FreeRSB (RSB * pRsb);

void FreePSB (PSB * pPsb);

void FreeRsvpPkt (RSVP_PKT * pRsvpPkt);

void FreeERO (ER_OBJ *);
void FreeRRO (RR_OBJ *);
void FreeFilterSpecData (FILTER_SPEC_DATA ** ppFilterSpecData);

E_RC IfIpAdd (IPV4_ADDR IfIpAddress, uns8 PrefixLen);
E_RC IfIpAddrDel (IPV4_ADDR IfIpAddress, uns8 PrefixLen);

void DumpResvTearMsg (RSVP_PKT * pRsvpPkt, struct vty *vty);
void DumpResvMsg (RSVP_PKT * pRsvpPkt, struct vty *vty);
void DumpPathErrMsg (RSVP_PKT * pRsvpPkt, struct vty *vty);
void DumpResvErrMsg (RSVP_PKT * pRsvpPkt, struct vty *vty);
void DumpPathMsg (RSVP_PKT * pRsvpPkt, struct vty *vty);
void DumpPathTearMsg (RSVP_PKT * pRsvpPkt, struct vty *vty);
IPV4_ADDR GetRouterId ();
E_RC CheckRRO4Loop (RR_SUBOBJ * pRrSubObj);
uns8 IsAbstractNode (IPV4_ADDR IpAddress, uns8 PrefixLen);
E_RC InitInterfaceIpAdressesDB ();
void DumpRSB (RSB_KEY * pRsbKey, struct vty *vty);
void DumpPSB (PSB_KEY * pPsbKey, struct vty *vty);
void DumpRsvpStatistics (struct vty *vty);
#endif
