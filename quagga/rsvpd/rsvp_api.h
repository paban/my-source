#ifndef _RSVP_API_H_
#define _RSVP_API_H_

E_RC IngressPathSend (INGRESS_API * pIngressApi);
E_RC IngressPathTear (INGRESS_API * pIngressApi);
E_RC DebugSendResvTear (TE_API_MSG * pMsg);
void RsvpPathSendCmd (TE_API_MSG * pMsg);
void RsvpPathTearCmd (TE_API_MSG * pMsg);
#endif
