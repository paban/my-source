
#ifndef _CSPF_REQ_H_
#define _CSPF_REQ_H_

#define CSPF_REQ             1
#define BW_UPDATE_REQ        2
#define HELLO_REQ            3
#define REMOTE_BW_UPDATE_REQ 4

typedef struct
{
  struct in_addr LocalIp;
  struct in_addr RemoteIp;
  float Bw;
} LINK_BW;

typedef struct
{
  struct in_addr Destination;
  int Priority;
  int ExcludeColorMask;
  int IncludeAnyColorMask;
  int IncludeColorMask;
  int HopCountLimit;
  float Bw;
  int LinkBwCount;
  int Hops2AvoidCount;
  int Hops2ExcludeCount;
  LINK_BW *pLinkBw;
  struct in_addr *Hops2Avoid;
  struct in_addr *Hops2Exclude;
  void *handle;
} CSPF_REQUEST;

typedef struct
{
  int IfIndex;
  float MaxResBw;
  float ResBw[8];
} BW_UPDATE_REQUEST;

typedef struct
{
  struct in_addr RouterId;
  struct in_addr LocalIp;
  struct in_addr RemoteIp;
  float ResBw[8];
} REMOTE_BW_UPDATE_REQUEST;

#endif
