
#ifndef __RSVP_SOCKET_H_
#define __RSVP_SOCKET_H_

E_RC EnableRsvpOnInterface (uns32 IfIndex);
E_RC EnableRsvpOnInterface2 (int IfIndex);
E_RC DisableRsvpOnInterface (int IfIndex);
int ProcessRsvpMsg (struct thread *pThread);
E_RC IpAddrGetByIfIndex (uns32 IfIndex, IPV4_ADDR * pIpAddr);
E_RC IpAddrSetByIfIndex (uns32 IfIndex, IPV4_ADDR IpAddr);
E_RC IsRsvpEnabledOnIf (int IfIndex);
E_RC SendRawData (char *buffer,
		  uns32 Len,
		  IPV4_ADDR remote_addr,
		  uns32 IfIndex, uns8 ttl, uns8 RouterAlert);
E_RC InitInterfaceDB ();
#endif
