
#ifndef _BW_MAN_H_
#define _BW_MAN_H_

uns32 DoPreBwAllocation (PSB_KEY * key,
			 uns32 TeLinkId,
			 COMPONENT_LINK * pComponentLink,
			 float BW, uns8 HoldPriority);
uns32 CalcActualAlloc (PSB_KEY * key,
		       uns32 TeLinkId,
		       COMPONENT_LINK * pComponentLink,
		       float *BW,
		       uns8 SetupPriority,
		       uns8 HoldPriority, uns8 * PreemptedPriority);
uns32 TE_RSVPTE_API_DoAllocation (PSB_KEY * key,
				  uns32 TeLinkId,
				  uns32 OutIfIndex,
				  float BW,
				  uns8 SetupPriority,
				  uns8 HoldPriority,
				  float *MaximumPossibleBW);
uns32 DoRelease (PSB_KEY * key, uns32 TeLinkId, uns32 OutIfIndex,
		 uns8 Priority);
void BwOwnersDump ();
void IfBwOwnersDump ();

void TE_RSVPTE_API_BwReleaseMessage (TE_API_MSG * dmsg);
void BwUpdateRequest2Igp (TE_LINK * pTeLink);

#endif
