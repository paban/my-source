#ifndef __RSVP_ENCODE_H_
#define __RSVP_ENCODE_H_

E_RC EncodeAndSendRsvpPathTearMessage (RSVP_PKT * pRsvpPkt,
				       IPV4_ADDR DestIpAddr,
				       uns32 OutIf, uns8 ttl);
E_RC EncodeAndSendRsvpPathErrMessage (RSVP_PKT * pRsvpPkt,
				      IPV4_ADDR DestIpAddr,
				      uns32 OutIf, uns8 ttl);

E_RC EncodeAndSendRsvpPathMessage (RSVP_PKT * pRsvpPkt,
				   IPV4_ADDR DestIpAddr,
				   uns32 OutIf,
				   uns8 ttl,
				   char **ppSentBuffer,
				   uns16 * pSentBufferLen);

E_RC EncodeAndSendRsvpResvErrMessage (RSVP_PKT * pRsvpPkt,
				      IPV4_ADDR DestIpAddr,
				      uns32 OutIf, uns8 ttl);

E_RC EncodeAndSendRsvpResvMessage (RSVP_PKT * pRsvpPkt,
				   IPV4_ADDR DestIpAddr,
				   uns32 OutIf,
				   uns8 ttl,
				   char **ppSentBuffer,
				   uns16 * pSentBufferLen);

E_RC EncodeAndSendRsvpResvTearMessage (RSVP_PKT * pRsvpPkt,
				       IPV4_ADDR DestIpAddr,
				       uns32 OutIf, uns8 ttl);

void rsvp_calc_pkt_cksum (char *u, unsigned int PktLen, uns16 * const pCksum);

#endif
