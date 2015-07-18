/* Module:   api.c
   Contains: TE application in-process API functions
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "te.h"

#define MAX_FLOAT 40000000000.0

void
TE_RSVPTE_API_TransitReqAPI (TE_API_MSG * dmsg)
{
  SM_T *pNewSm;
  PATH_NOTIFICATION *pTransitRequest;
  PSB_KEY PsbKey;
  SM_CALL_T *pCall;

  if ((pTransitRequest =
       (PATH_NOTIFICATION *) XMALLOC (MTYPE_TE,
				      sizeof (PATH_NOTIFICATION))) == NULL)
    {
      zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
      return;
    }

  memcpy (pTransitRequest, &dmsg->u.PathNotification,
	  sizeof (PATH_NOTIFICATION));

  PsbKey = pTransitRequest->PsbKey;

  pNewSm = sm_gen_alloc (0, TRANSIT_LSP_SM);
  if (pNewSm == NULL)
    {
      zlog_err ("fatal %s %d\n", __FILE__, __LINE__);
      return;
    }
  if ((pCall =
       sm_gen_sync_event_send (pNewSm, TRANSIT_REQ_EVENT,
			       pTransitRequest)) == NULL)
    {
      zlog_err ("\ncan not invoke sm %s %d", __FILE__, __LINE__);
      return;
    }
  sm_call (pCall);
  return;
}

void
TE_IGP_API_PathAdd (void *pBuf, int Len)
{
  char *p;
  PATH *pPath;
  IPV4_ADDR dest_ip;
  TE_HOP *er_hops;
  float PathMinReservableBW[8], PathMaxBW = MAX_FLOAT, PathMaxReservableBW = MAX_FLOAT;	/*FIXME!! */
  int hop_count, i, j, SumTeMetric = 0;
  zlog_info ("PathAdd");


  pBuf += sizeof (EVENTS_E);
  Len -= sizeof (EVENTS_E);
  p = pBuf;
  dest_ip = *((int *) p);
  p += sizeof (int);
  Len -= sizeof (int);
  if (Len % 56)
    {
      zlog_err
	("The payload after destination field is not %d-alligned %d %d",
	 Len % 56, Len, sizeof (TE_HOP));
      return;
    }
  hop_count = Len / sizeof (TE_HOP);
  pPath = (PATH *) XMALLOC (MTYPE_TE, sizeof (PATH));
  if (pPath == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return;
    }
  memset (pPath, 0, sizeof (PATH));
  er_hops = (TE_HOP *) XMALLOC (MTYPE_TE, sizeof (TE_HOP) * hop_count);
  if (er_hops == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return;
    }
  for (i = 0; i < 8; i++)
    {
      PathMinReservableBW[i] = MAX_FLOAT;
    }

  for (i = 0; i < hop_count; i++)
    {
      er_hops[i].local_ip = *((int *) p);
      p += sizeof (int);
      er_hops[i].remote_ip = *((int *) p);
      p += sizeof (int);
      er_hops[i].MaxReservableBW = *((float *) p);
      p += sizeof (float);
      for (j = 0; j < 8; j++)
	{
	  er_hops[i].ReservableBW[j] = *((float *) p);
	  p += sizeof (float);
	}
      er_hops[i].MaxLspBW = *((float *) p);
      if (er_hops[i].MaxLspBW < PathMaxBW)
	PathMaxBW = er_hops[i].MaxLspBW;
      p += sizeof (float);

      for (j = 0; j < 8; j++)
	{
	  if (er_hops[i].ReservableBW[j] < PathMinReservableBW[j])
	    PathMinReservableBW[j] = er_hops[i].ReservableBW[j];
	}
      er_hops[i].te_metric = *((int *) p);
      p += sizeof (int);
      SumTeMetric += er_hops[i].te_metric;
      er_hops[i].ColorMask = *((int *) p);
      p += sizeof (int);
      if (er_hops[i].MaxReservableBW < PathMaxReservableBW)
	PathMaxReservableBW = er_hops[i].MaxReservableBW;
    }
  if (hop_count == 0)
    er_hops = NULL;
  pPath->u.er_hops = er_hops;
  pPath->PathProperties.PathType = PSC_PATH;
  pPath->PathProperties.PathHopCount = hop_count;
  pPath->PathProperties.PathMaxLspBW = PathMaxBW;
  pPath->PathProperties.PathMaxReservableBW = PathMaxReservableBW;

  for (j = 0; j < 8; j++)
    pPath->PathProperties.PathReservableBW[j] = PathMinReservableBW[j];

  pPath->PathProperties.PathSumTeMetric = SumTeMetric;
  pPath->destination = dest_ip;
  if (rdb_add_mod_path (dest_ip, pPath) != E_OK)
    {
      zlog_err ("Cannot add path");
    }
}

void
TE_IGP_API_ReadPathCash (void *pBuf, int Len)
{
  IPV4_ADDR IpAddr;
  int handle;
  char *p;

  pBuf += sizeof (EVENTS_E);
  Len -= sizeof (EVENTS_E);
  p = pBuf;

  IpAddr = *((int *) p);
  p += sizeof (int);
  handle = *((int *) p);
  p += sizeof (int);
  CspfReply (IpAddr, (void *) handle);
}
