/* Module:   rsvp_socket.c
   Contains: RSVP socket routines
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "rsvp.h"
#include "if.h"

typedef struct
{
  PATRICIA_NODE Node;
  uns32 IfIndex;
  int IfSocket;
  IPV4_ADDR IpAddr;
  IPV4_ADDR Peer;
  char IfName[20];
  struct thread *pThread;
} IF_NODE;

PATRICIA_TREE IfTree;

char BigBuf[1024];

extern struct thread_master *master;


E_RC
IpAddrGetByIfIndex (uns32 IfIndex, IPV4_ADDR * pIpAddr)
{
  IF_NODE *pIfNode;

  if ((pIfNode =
       (IF_NODE *) patricia_tree_get (&IfTree,
				      (const uns8 *) &IfIndex)) == NULL)
    {
      zlog_err ("cannot get a node from patricia tree %s %d", __FILE__,
		__LINE__);
      return E_ERR;
    }
  *pIpAddr = pIfNode->IpAddr;
  return E_OK;
}

E_RC
IpAddrSetByIfIndex (uns32 IfIndex, IPV4_ADDR IpAddr)
{
  IF_NODE *pIfNode;

  if ((pIfNode =
       (IF_NODE *) patricia_tree_get (&IfTree,
				      (const uns8 *) &IfIndex)) == NULL)
    {
      if ((pIfNode =
	   (IF_NODE *) XMALLOC (MTYPE_RSVP, sizeof (IF_NODE))) == NULL)
	{
	  zlog_err ("cannot allocate memory %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      memset (pIfNode, 0, sizeof (IF_NODE));
      pIfNode->IfIndex = IfIndex;
      pIfNode->Node.key_info = (uns8 *) & pIfNode->IfIndex;
      if (patricia_tree_add (&IfTree, (PATRICIA_NODE *) & pIfNode->Node) !=
	  E_OK)
	{
	  zlog_err ("cannot add node to patricia");
	  return E_ERR;
	}
    }
  pIfNode->IpAddr = IpAddr;
  return E_OK;
}

E_RC
InitInterfaceDB ()
{
  PATRICIA_PARAMS params;

  memset (&params, 0, sizeof (PATRICIA_PARAMS));
  params.key_size = sizeof (uns32);
  if (patricia_tree_init (&IfTree, &params) != E_OK)
    {
      zlog_err ("cannot initiate I/F patricia tree");
      return E_ERR;
    }
  return E_OK;
}

E_RC
SetRouterAlert (int sock)
{
#if defined(IPOPT_RA)
  static const char ra_opt[4] = { IPOPT_RA, 4, 0, 0 };


  if (setsockopt (sock, IPPROTO_IP, IP_OPTIONS, ra_opt, sizeof (ra_opt)))
    {
      zlog_err ("Cannot set router alert %s %s %d", strerror (errno),
		__FILE__, __LINE__);
      return E_ERR;
    }
#endif /* defined(IPOPT_RA) */
  return E_OK;
}

E_RC
SetTtl (int sock, uns16 ttl)
{
  uns16 multicast = (uns16) (ttl & 0x8000);	/* most significant bit indicates multicast */
  int set_ttl = (int) (ttl & 0x00FF);

  /* specify the ttl value for subsequent datagrams sent out on this socket */

#ifdef IP_TTL
  {
    if (multicast == 0)
      if (setsockopt
	  (sock, IPPROTO_IP, IP_TTL, (char *) &set_ttl,
	   sizeof (set_ttl)) != 0)
	{
	  zlog_err ("Cannot set ttl %s %s %d", strerror (errno), __FILE__,
		    __LINE__);
	  return E_ERR;
	}
  }
#endif


  /* specify the ttl for multicast messages sent out on this socket */

#ifdef IP_MULTICAST_TTL
  {
    if (multicast == 0x8000)
      if (setsockopt
	  (sock, IPPROTO_IP, IP_MULTICAST_TTL, (char *) &set_ttl,
	   sizeof (set_ttl)) != 0)
	{
	  zlog_err ("Cannot set ttl %s %s %d", strerror (errno), __FILE__,
		    __LINE__);
	  return E_ERR;
	}
  }
#endif

  return E_OK;
}

E_RC
SendRawData (char *buffer, uns32 Len, IPV4_ADDR remote_addr, uns32 IfIndex,
	     uns8 ttl, uns8 RouterAlert)
{
  struct sockaddr_in saddr;
  int bytes_sent;
  IF_NODE *pIfNode;
  zlog_info ("entering SendRawData");
  if ((pIfNode =
       (IF_NODE *) patricia_tree_get (&IfTree,
				      (const uns8 *) &IfIndex)) == NULL)
    {
      zlog_err ("Cannot get node from patricia tree, IfIndex %d %s %d",
		IfIndex, __FILE__, __LINE__);
      return E_ERR;
    }

  memset ((char *) &saddr, 0x00, sizeof (saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = remote_addr;


  if (SetTtl (pIfNode->IfSocket, ttl) != E_OK)
    {
      zlog_err ("Cannot set ttl");
    }

  if (RouterAlert == TRUE)
    {
      if (SetRouterAlert (pIfNode->IfSocket) != E_OK)
	{
	  zlog_err ("Cannot set router alert");
	}
    }

  bytes_sent =
    sendto (pIfNode->IfSocket, buffer, Len, 0, (struct sockaddr *) &saddr,
	    sizeof (saddr));
  if (bytes_sent == -1)
    {
      zlog_err ("an error occured on sendto %s", strerror (errno));
      return E_ERR;
    }
  else if (bytes_sent < Len)
    {
      zlog_err ("tried to send %d bytes, actually sent %d", Len, bytes_sent);
      return E_ERR;
    }
  zlog_info ("leaving SendRawData");
  return E_OK;
}

int
ProcessRsvpMsg (struct thread *pThread)
{
  int FromLen, PktLen;
  IF_NODE *pIfNode;
  struct sockaddr_in from;
  uns8 *pIpHdr;

  pIfNode = pThread->arg;

  memset (&from, 0, sizeof (struct sockaddr_in));
  FromLen = sizeof (struct sockaddr_in);
  from.sin_family = AF_INET;

  if (ioctl (pIfNode->IfSocket, FIONREAD, &PktLen) < 0)
    {
      zlog_err (" an error %s on ioctl %s %d", strerror (errno), __FILE__,
		__LINE__);
    }
  zlog_info ("message received on %d %s", pIfNode->IfIndex, pIfNode->IfName);
  memset (BigBuf, 0, 1000);
  if ((PktLen =
       recvfrom (pIfNode->IfSocket, BigBuf, 1000, 0,
		 (struct sockaddr *) &from, &FromLen)) < 0)
    {
      zlog_err ("an error occured on recvfrom %s %s",
		pIfNode->IfName, strerror (errno));
    }
  else
    {
      zlog_info ("From %x", from.sin_addr.s_addr);
      pIpHdr = BigBuf;
      PktLen -= (unsigned int) 4 *(*pIpHdr & 0xf);
      DecodeAndProcessRsvpMsg (&BigBuf[(unsigned int) 4 * (*pIpHdr & 0xf)],
			       PktLen, pIfNode->IfIndex, 0);
    }
  pIfNode->pThread =
    thread_add_read (master, ProcessRsvpMsg, pIfNode, pIfNode->IfSocket);
  return 0;
}

E_RC
IsRsvpEnabledOnIf (int IfIndex)
{
  IF_NODE *pIfNode;

  if ((pIfNode =
       (IF_NODE *) patricia_tree_get (&IfTree,
				      (const uns8 *) &IfIndex)) == NULL)
    {
      zlog_err ("Cannot get node from patricia tree, IfIndex %d %s %d",
		IfIndex, __FILE__, __LINE__);
      return E_ERR;
    }
  if (pIfNode->IfSocket)
    {
      return E_OK;
    }
  return E_ERR;
}

E_RC
EnableRsvpOnInterface2 (int IfIndex)
{
  struct sockaddr_in saddr;
  IF_NODE *pIfNode;

  if ((pIfNode =
       (IF_NODE *) patricia_tree_get (&IfTree,
				      (const uns8 *) &IfIndex)) == NULL)
    {
      zlog_err ("cannot get a node from patricia");
      return E_ERR;
    }

  memset (&saddr, 0x00, sizeof (saddr));
  saddr.sin_family = AF_INET;
  /*saddr.sin_port        = htons(0); */
  saddr.sin_addr.s_addr = htonl (pIfNode->IpAddr);
  if (bind
      (pIfNode->IfSocket, (struct sockaddr *) &saddr,
       sizeof (struct sockaddr_in)) < 0)
    {
      zlog_err ("cannot bind socket (%s) for %s %s %d",
		strerror (errno), pIfNode->IfName, __FILE__, __LINE__);
      return E_ERR;
    }
  {
    char str1[16];
    sprintf (str1, "%x", pIfNode->IpAddr);
    zlog_info ("Upon enabling RSVP on I/F %s %s %d",
	       pIfNode->IfName, str1, pIfNode->IfSocket);
  }
  if (pIfNode->pThread == NULL)
    pIfNode->pThread =
      thread_add_read (master, ProcessRsvpMsg, pIfNode, pIfNode->IfSocket);
  return E_OK;
}

E_RC
EnableRsvpOnInterface (uns32 IfIndex)
{
  static const unsigned int bio = 1;
  static const int smode = 1;
  IF_NODE *pIfNode;
  struct interface *ifp = NULL;

  int sock = socket (AF_INET, SOCK_RAW, RSVP_IP_PROTOCOL);

  if ((pIfNode =
       (IF_NODE *) patricia_tree_get (&IfTree,
				      (const uns8 *) &IfIndex)) == NULL)
    {
      if ((pIfNode =
	   (IF_NODE *) XMALLOC (MTYPE_RSVP, sizeof (IF_NODE))) == NULL)
	{
	  zlog_err ("cannot allocate memory %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      memset (pIfNode, 0, sizeof (IF_NODE));
      pIfNode->IfIndex = IfIndex;
      pIfNode->Node.key_info = (uns8 *) & pIfNode->IfIndex;
      if (patricia_tree_add (&IfTree, (PATRICIA_NODE *) & pIfNode->Node) !=
	  E_OK)
	{
	  zlog_err ("cannot add node to patricia");
	  return E_ERR;
	}
    }

  if (sock < 0)
    {
      zlog_err ("cannot open socket %s %s %d", strerror (errno), __FILE__,
		__LINE__);
      return E_ERR;
    }

  if (ioctl (sock, FIONBIO, &bio) < 0)
    {
      zlog_err ("cannot set non blocking mode for I/F %d %s %d", IfIndex,
		__FILE__, __LINE__);
      return E_ERR;
    }

  if (setsockopt
      (sock, SOL_SOCKET, SO_REUSEADDR, (char *) &smode, sizeof (smode)))
    {
      zlog_err ("cannot set reuse address option for I/F %d %s %d", IfIndex,
		__FILE__, __LINE__);
      return E_ERR;
    }
  ifp = if_lookup_by_index (IfIndex);
  strncpy (pIfNode->IfName, ifp->name, INTERFACE_NAMSIZ);
#if 1
  {
	/** Build a ifreq to get mapping of device index to name,
         ** since the  bind to device sockopt operates on name.
         **/
    struct ifreq ifr;
    memset (&ifr, '\0', sizeof ifr);

    strcpy (ifr.ifr_name, pIfNode->IfName);

    if (setsockopt
	(sock, SOL_SOCKET, SO_BINDTODEVICE, ifr.ifr_name, IFNAMSIZ))
      {
	zlog_err ("cannot set bind to device option for %s %s %d",
		  pIfNode->IfName, __FILE__, __LINE__);
	return E_ERR;
      }
  }
#endif
#if 0
  {
    int ra = 0, Len = sizeof (ra);
    static const int ra_true = 1;
    if (setsockopt
	(sock, /*IPPROTO_IP */ SOL_SOCKET, IP_ROUTER_ALERT, &ra_true,
	 sizeof (ra_true)) != 0)
      {
	zlog_err ("cannot set router alert option for %s %s %d", IfName,
		  __FILE__, __LINE__);
	return E_ERR;
      }
    if (getsockopt (sock, SOL_SOCKET, IP_ROUTER_ALERT, &ra, &Len) != 0)
      {
	zlog_err ("cannot get router alert option for %s error %s %s %d",
		  IfName, strerror (errno), __FILE__, __LINE__);
	return E_ERR;
      }
    else
      {
	printf ("ROUTER ALERT %x\n", ra);
      }
  }
#endif

  pIfNode->IfSocket = sock;
  if (pIfNode->IpAddr != 0)
    {
      return EnableRsvpOnInterface2 (IfIndex);
    }
  else
    {
      return E_OK;
    }
}

E_RC
DisableRsvpOnInterface (int IfIndex)
{
  IF_NODE *pIfNode;

  if ((pIfNode =
       (IF_NODE *) patricia_tree_get (&IfTree,
				      (const uns8 *) &IfIndex)) == NULL)
    {
      zlog_err ("cannot get a node from patricia");
      return E_ERR;
    }
  if (pIfNode->pThread)
    thread_cancel (pIfNode->pThread);
  pIfNode->pThread = NULL;
  close (pIfNode->IfSocket);
  if (patricia_tree_del (&IfTree, (PATRICIA_NODE *) & pIfNode->Node) != E_OK)
    {
      zlog_err ("cannot del node from patricia");
      return E_ERR;
    }
  XFREE (MTYPE_RSVP, pIfNode);
  return E_OK;
}
