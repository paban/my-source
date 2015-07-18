#ifndef __RSVP_DECODE_H_
#define __RSVP_DECODE_H_

E_RC DecodeAndProcessRsvpMsg (void *pPkt, int PktLen, uns32 IfIndex,
			      IPV4_ADDR SrcIpAddr);
void InitRsvpDecoder ();
#endif
