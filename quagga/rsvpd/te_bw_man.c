/* Module:   bw_man.c
   Contains: TE application bandwidth manager
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "te.h"
#include "te_cspf.h"

extern PATRICIA_TREE BwOwnersTree[8];
extern PATRICIA_TREE IfBwOwnersTree[8];
extern struct zclient *zclient;

typedef struct
{
  uns32 IfIndex;
  PSB_KEY PsbKey;
} IF_BW_KEY;

typedef struct
{
  PATRICIA_NODE Node;
  IF_BW_KEY if_bw_key;
  float BW;
} IF_BW_DATA;

static void CancelBwAllocAtHigherPriorities (PSB_KEY * key,
					     uns32 TeLinkId,
					     COMPONENT_LINK * pComponentLink,
					     uns8 Priority);
static void CancelBwAllocAtLowerPriorities (PSB_KEY * key,
					    uns32 TeLinkId,
					    COMPONENT_LINK * pComponentLink,
					    uns8 Priority);
static void CancelBwAllocAtOtherPriorities (PSB_KEY * key,
					    uns32 TeLinkId,
					    COMPONENT_LINK * pComponentLink,
					    uns8 Priority);
static float PreemptTunnel (uns32 TeLinkId,
			    COMPONENT_LINK * pComponentLink,
			    uns8 Priority, uns8 PreemptorPrio, PSB_KEY * key);
static void GetEfficientBwAtHigherPriorities (PSB_KEY * key,
					      uns32 TeLinkId,
					      COMPONENT_LINK * pComponentLink,
					      uns8 Priority, float *BW);
static uns32 UpdateIfBwOwnerStructure (uns32 IfIndex, PSB_KEY * key, float BW,
				       uns8 Priority);
static BOOL BwPreemptionUseful (uns32 IfIndex, uns8 SetupPriority,
				float RequiredBW, uns8 * PreemptedPriority,
				float *MaximumPossibleBW);
static void AllocateBW (TE_LINK * pTeLink, COMPONENT_LINK * pComponentLink,
			uns8 Priority, float BW);
static void ReleaseBW (TE_LINK * pTeLink, COMPONENT_LINK * pComponentLink,
		       uns8 Priority, float BW);
static void PreemptBW (COMPONENT_LINK * pComponentLink,
		       uns8 PreemptorPriority, uns8 PreemptedPriority,
		       float BW);

typedef struct
{
  int Event;
  BW_UPDATE_REQUEST BwUpdateReq;
} BW_UPDATE_MSG;

void
BwUpdateRequest2Igp (TE_LINK * pTeLink)
{
#if 0
  struct zapi_te_link link;
  int i;

  memset(&link, 0, sizeof(struct zapi_te_link));
  link.linkid = pTeLink->te_link_id;
  link.max_res_bw = pTeLink->te_link_properties.MaxReservableBW;
  
  for (i = 0; i < 8; i++)
    link.reservable_bw[i] = pTeLink->te_link_properties.ReservableBW[i];

  zapi_te_link_update(zclient, &link);
#endif
}

static void
CancelBwAllocAtHigherPriorities (PSB_KEY * key,
				 uns32 TeLinkId,
				 COMPONENT_LINK * pComponentLink,
				 uns8 Priority)
{
  BW_OWNER_ENTRY *pBwOwnerEntry;
  BW_OWNER_DATA *pBwOwnerData, *pBwOwnerDataPrev = NULL;
  TE_LINK *pTeLink;
  int j;

  if (Priority == 0)
    return;

  if (rdb_get_te_link (TeLinkId, &pTeLink) != E_OK)
    {
      zlog_err ("\ncannot get TE link %s %d", __FILE__, __LINE__);
      return;
    }
  for (j = 0; j < Priority; j++)
    {
      if ((pBwOwnerEntry =
	   (BW_OWNER_ENTRY *) patricia_tree_get (&BwOwnersTree[j],
						 (const uns8 *) key)) != NULL)
	{
	  pBwOwnerData = pBwOwnerEntry->pBwOwnerData;
	  while (pBwOwnerData != NULL)
	    {
	      if ((pBwOwnerData->TeLinkId == TeLinkId) &&
		  (pBwOwnerData->OutIf == pComponentLink->oifIndex))
		{
		  ReleaseBW (pTeLink, pComponentLink, Priority,
			     pBwOwnerData->BW + pBwOwnerData->PreAllocBW);
		  if (pBwOwnerEntry->pBwOwnerData == pBwOwnerData)
		    pBwOwnerEntry->pBwOwnerData =
		      pBwOwnerEntry->pBwOwnerData->next;
		  else
		    pBwOwnerDataPrev->next = pBwOwnerData->next;
		  XFREE (MTYPE_TE, pBwOwnerData);
		  if (pBwOwnerEntry->pBwOwnerData == NULL)
		    {
		      zlog_info ("\nBW Owners Entry will be deleted2");
		      if (patricia_tree_del
			  (&BwOwnersTree[j], &pBwOwnerEntry->Node) != E_OK)
			{
			  zlog_err
			    ("\ncannot delete node from patricia %s %d",
			     __FILE__, __LINE__);
			}
		      else
			XFREE (MTYPE_TE, pBwOwnerEntry);
		    }
		  break;
		}
	      pBwOwnerData = pBwOwnerData->next;
	    }
	}
    }
}

static void
CancelBwAllocAtLowerPriorities (PSB_KEY * key,
				uns32 TeLinkId,
				COMPONENT_LINK * pComponentLink,
				uns8 Priority)
{
  BW_OWNER_ENTRY *pBwOwnerEntry;
  BW_OWNER_DATA *pBwOwnerData, *pBwOwnerDataPrev = NULL;
  TE_LINK *pTeLink;
  int j;

  if (rdb_get_te_link (TeLinkId, &pTeLink) != E_OK)
    {
      zlog_err ("\ncannot get TE link %s %d", __FILE__, __LINE__);
      return;
    }
  for (j = Priority + 1; j < 8; j++)
    {
      if ((pBwOwnerEntry =
	   (BW_OWNER_ENTRY *) patricia_tree_get (&BwOwnersTree[j],
						 (const uns8 *) key)) != NULL)
	{
	  pBwOwnerData = pBwOwnerEntry->pBwOwnerData;
	  while (pBwOwnerData != NULL)
	    {
	      if ((pBwOwnerData->TeLinkId == TeLinkId) &&
		  (pBwOwnerData->OutIf == pComponentLink->oifIndex))
		{
		  ReleaseBW (pTeLink, pComponentLink, Priority,
			     pBwOwnerData->BW + pBwOwnerData->PreAllocBW);
		  if (pBwOwnerEntry->pBwOwnerData == pBwOwnerData)
		    pBwOwnerEntry->pBwOwnerData =
		      pBwOwnerEntry->pBwOwnerData->next;
		  else
		    pBwOwnerDataPrev->next = pBwOwnerData->next;
		  XFREE (MTYPE_TE, pBwOwnerData);
		  if (pBwOwnerEntry->pBwOwnerData == NULL)
		    {
		      zlog_info ("\nBW Owners Entry will be deleted2");
		      if (patricia_tree_del
			  (&BwOwnersTree[j], &pBwOwnerEntry->Node) != E_OK)
			{
			  zlog_err
			    ("\ncannot delete node from patricia %s %d",
			     __FILE__, __LINE__);
			}
		      else
			XFREE (MTYPE_TE, pBwOwnerEntry);
		    }
		  break;
		}
	      pBwOwnerData = pBwOwnerData->next;
	    }
	}
    }
}

static void
CancelBwAllocAtOtherPriorities (PSB_KEY * key,
				uns32 TeLinkId,
				COMPONENT_LINK * pComponentLink,
				uns8 Priority)
{
  CancelBwAllocAtHigherPriorities (key, TeLinkId, pComponentLink, Priority);
  CancelBwAllocAtLowerPriorities (key, TeLinkId, pComponentLink, Priority);
  return;
}

static void
GetEfficientBwAtHigherPriorities (PSB_KEY * key,
				  uns32 TeLinkId,
				  COMPONENT_LINK * pComponentLink,
				  uns8 Priority, float *BW)
{
  BW_OWNER_ENTRY *pBwOwnerEntry;
  BW_OWNER_DATA *pBwOwnerData;
  int j, i, k;
  float AllocBW[8], AllocatedBW[8][8], ReservableBW[8], ReleasedBW = 0;

  memset (AllocBW, 0, sizeof (AllocBW));
  memcpy (AllocatedBW, pComponentLink->AllocatedBW, sizeof (AllocatedBW));
  memcpy (ReservableBW, pComponentLink->ReservableBW, sizeof (ReservableBW));

  for (j = 0; j < Priority; j++)
    {
      if ((pBwOwnerEntry =
	   (BW_OWNER_ENTRY *) patricia_tree_get (&BwOwnersTree[j],
						 (const uns8 *) key)) != NULL)
	{
	  pBwOwnerData = pBwOwnerEntry->pBwOwnerData;

	  while (pBwOwnerData != NULL)
	    {
	      if ((pBwOwnerData->TeLinkId == TeLinkId) &&
		  (pBwOwnerData->OutIf == pComponentLink->oifIndex))
		{
		  AllocBW[j] = pBwOwnerData->BW + pBwOwnerData->PreAllocBW;
		  break;
		}
	      pBwOwnerData = pBwOwnerData->next;
	    }
	}
    }
  for (k = 0; k < 8; k++)
    {
      for (i = 0; (i < 8) && (BW > 0); i++)
	{
	  if (AllocatedBW[i][i] > 0)
	    {
	      ReleasedBW = 0;
	      if (AllocBW[k] >= AllocatedBW[i][i])
		{
		  ReleasedBW = AllocatedBW[i][i];
		  ReservableBW[i] += AllocatedBW[i][i];
		  AllocBW[k] -= AllocatedBW[i][i];
		  AllocatedBW[i][i] = 0;
		}
	      else
		{
		  ReleasedBW = AllocBW[k];
		  ReservableBW[i] += AllocBW[k];
		  AllocatedBW[i][i] -= AllocBW[k];
		  AllocBW[k] = 0;
		}
	      for (j = i + 1; (j < 8) && (ReleasedBW > 0); j++)
		{
		  if (AllocatedBW[i][j] > 0)
		    {
		      if (ReleasedBW >= AllocatedBW[i][j])
			{
			  AllocatedBW[j][j] += AllocatedBW[i][j];
			  ReleasedBW -= AllocatedBW[i][j];
			  AllocatedBW[i][j] = 0;
			}
		      else
			{
			  AllocatedBW[j][j] += ReleasedBW;
			  AllocatedBW[i][j] -= ReleasedBW;
			  ReleasedBW = 0;
			}
		    }
		}
	    }
	}
      if (ReleasedBW > 0)
	{
	  for (; i < 8; i++)
	    {
	      if (AllocatedBW[i][i] > 0)
		{
		  break;
		}
	      if (pComponentLink->ConfiguredReservableBW[i] > ReservableBW[i])
		{
		  if ((ReservableBW[i] + ReleasedBW) <=
		      pComponentLink->ConfiguredReservableBW[i])
		    {
		      ReservableBW[i] += ReleasedBW;
		    }
		  else
		    {
		      ReservableBW[i] =
			pComponentLink->ConfiguredReservableBW[i];
		    }
		}
	    }
	}
    }
  if (ReservableBW[Priority] >= pComponentLink->ReservableBW[Priority])
    {
      *BW = ReservableBW[Priority] - pComponentLink->ReservableBW[Priority];
    }
  else
    {
      *BW = 0;
    }
  return;
}

static float
PreemptTunnel (uns32 TeLinkId,
	       COMPONENT_LINK * pComponentLink,
	       uns8 Priority, uns8 PreemptorPrio, PSB_KEY * key)
{
  IF_BW_KEY if_bw_key;
  IF_BW_DATA *pIfBwEntry;
  PSB_KEY PsbKey;
  TE_API_MSG Msg;
  float BW = 0;
  memset (&if_bw_key, 0, sizeof (IF_BW_KEY));
  if_bw_key.IfIndex = pComponentLink->oifIndex;
  if ((pIfBwEntry =
       (IF_BW_DATA *) patricia_tree_getnext (&IfBwOwnersTree[Priority],
					     (const uns8 *) &if_bw_key)) !=
      NULL)
    {
      PsbKey = pIfBwEntry->if_bw_key.PsbKey;
      BW = pIfBwEntry->BW;
      if (patricia_tree_del (&IfBwOwnersTree[Priority], &pIfBwEntry->Node) !=
	  E_OK)
	{
	  zlog_err ("\ncannot delete node %s %d", __FILE__, __LINE__);
	}
      else
	{
	  XFREE (MTYPE_TE, pIfBwEntry);
	}
      if (memcmp (&PsbKey, key, sizeof (PSB_KEY)) != 0)
	{
	  Msg.NotificationType = PREEMPT_FLOW_CMD;
	  Msg.u.PreemptFlow.RsbKey.Session = PsbKey.Session;
	  if ((PsbKey.SenderTemplate.IpAddr != 0) ||
	      (PsbKey.SenderTemplate.LspId != 0))
	    {
	      Msg.u.PreemptFlow.FilterSpecValid = 1;
	      Msg.u.PreemptFlow.FilterSpec = PsbKey.SenderTemplate;
	    }
	  else
	    {
	      Msg.u.PreemptFlow.FilterSpecValid = 0;
	    }
	  PreemptBW (pComponentLink, PreemptorPrio, Priority, BW);
	}
    }
  return BW;
}

static uns32
UpdateIfBwOwnerStructure (uns32 IfIndex, PSB_KEY * key, float BW,
			  uns8 Priority)
{
  IF_BW_KEY if_bw_key;
  IF_BW_DATA *pIfBwEntry;
  memset (&if_bw_key, 0, sizeof (IF_BW_KEY));
  if_bw_key.IfIndex = IfIndex;
  if_bw_key.PsbKey = *key;
  if ((pIfBwEntry =
       (IF_BW_DATA *) patricia_tree_get (&IfBwOwnersTree[Priority],
					 (const uns8 *) &if_bw_key)) == NULL)
    {
      if ((pIfBwEntry =
	   (IF_BW_DATA *) XMALLOC (MTYPE_TE, sizeof (IF_BW_DATA))) == NULL)
	{
	  zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pIfBwEntry->if_bw_key.IfIndex = IfIndex;
      pIfBwEntry->if_bw_key.PsbKey = *key;
      pIfBwEntry->BW = BW;
      pIfBwEntry->Node.key_info = (uns8 *) & pIfBwEntry->if_bw_key;
      if (patricia_tree_add (&IfBwOwnersTree[Priority], &pIfBwEntry->Node) !=
	  E_OK)
	{
	  zlog_err ("\ncannot add node to patricia tree %s %d", __FILE__,
		    __LINE__);
	  return E_ERR;
	}
    }
  else
    {
      pIfBwEntry->BW = BW;
    }
  return E_OK;
}

static BOOL
BwPreemptionUseful (uns32 IfIndex, uns8 SetupPriority, float RequiredBW,
		    uns8 * PreemptedPriority, float *MaximumPossibleBW)
{
  IF_BW_KEY if_bw_key;
  IF_BW_DATA *pIfBwEntry;
  int j;
  zlog_info ("entering BwPreemptionUseful");
  (*MaximumPossibleBW) = 0;
  memset (&if_bw_key, 0, sizeof (IF_BW_KEY));
  if_bw_key.IfIndex = IfIndex;
  for (j = SetupPriority + 1; j < 8; j++)
    {
      while ((pIfBwEntry =
	      (IF_BW_DATA *) patricia_tree_getnext (&IfBwOwnersTree[j],
						    (const uns8 *)
						    &if_bw_key)) != NULL)
	{
	  (*MaximumPossibleBW) += pIfBwEntry->BW;
	  if ((*MaximumPossibleBW) >= RequiredBW)
	    {
	      *PreemptedPriority = j;
	      zlog_info ("leaving BwPreemptionUseful+");
	      return TRUE;
	    }
	  if_bw_key = pIfBwEntry->if_bw_key;
	}
    }
  zlog_info ("leaving BwPreemptionUseful-");
  return FALSE;
}

void
TE_RSVPTE_API_BwReleaseMessage (TE_API_MSG * dmsg)
{
  zlog_info
    ("\nBW release If %x dest %x tunnel id %x ext tunnel id %x Priority %x",
     dmsg->u.BwRelease.IfIndex, dmsg->u.BwRelease.PsbKey.Session.Dest,
     dmsg->u.BwRelease.PsbKey.Session.TunnelId,
     dmsg->u.BwRelease.PsbKey.Session.ExtTunelId, dmsg->u.BwRelease.HoldPrio);

  if (DoRelease (&dmsg->u.BwRelease.PsbKey,
		 dmsg->u.BwRelease.IfIndex /* temporary */ ,
		 dmsg->u.BwRelease.IfIndex,
		 dmsg->u.BwRelease.HoldPrio /*??? */ ) != E_OK)
    {
      zlog_info ("\nBW release failed %s %d", __FILE__, __LINE__);
    }
  zlog_info ("\nAfter release...........");
  return;
}

uns32
DoPreBwAllocation (PSB_KEY * key,
		   uns32 TeLinkId,
		   COMPONENT_LINK * pComponentLink,
		   float BW, uns8 HoldPriority)
{
  BW_OWNER_ENTRY *pBwOwnerEntry;
  BW_OWNER_DATA *pBwOwnerData;

  /* First - register an allocation on the BW owners tree 
     BW owner is the session if SE reservation style or 
     Session and Sender if FF reservation style 
     BW owners tree serves for the prevention of the double accounting
     Upon the Path message, existing reservations are found
     Additional BW is attempted to be allocated on the links,
     where reservation already exists */
  zlog_info ("inside of DoPreAlloc Hold %x BW %f Dest %x TunnelId %x Src %x",
	     HoldPriority, BW, key->Session.Dest, key->Session.TunnelId,
	     key->Session.ExtTunelId, key->SenderTemplate.IpAddr,
	     key->SenderTemplate.LspId);
  if ((pBwOwnerEntry =
       (BW_OWNER_ENTRY *) patricia_tree_get (&BwOwnersTree[HoldPriority],
					     (const uns8 *) key)) == NULL)
    {
      if ((pBwOwnerEntry =
	   (BW_OWNER_ENTRY *) XMALLOC (MTYPE_TE,
				       sizeof (BW_OWNER_ENTRY))) == NULL)
	{
	  zlog_err ("\nFailed to allocate memory %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pBwOwnerEntry->key = *key;
      zlog_info ("\nBW owner entry creation %x %x %x %x %x...",
		 pBwOwnerEntry->key.Session.Dest,
		 pBwOwnerEntry->key.Session.TunnelId,
		 pBwOwnerEntry->key.Session.ExtTunelId,
		 pBwOwnerEntry->key.SenderTemplate.IpAddr,
		 pBwOwnerEntry->key.SenderTemplate.LspId);
      pBwOwnerEntry->Node.key_info = (uns8 *) & pBwOwnerEntry->key;
      zlog_info ("\ninside of DoPreAlloc adding to %x", HoldPriority);
      if (patricia_tree_add (&BwOwnersTree[HoldPriority],
			     &pBwOwnerEntry->Node) != E_OK)
	{
	  zlog_err ("\nFailed to allocate memory %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
    }
  else
    zlog_info ("\nBW owner entry found %x %x %x %x %x...",
	       key->Session.Dest,
	       key->Session.TunnelId,
	       key->Session.ExtTunelId,
	       key->SenderTemplate.IpAddr, key->SenderTemplate.LspId);
  /* however, pBwOwnerEntry points on new or existing BW entry now 
     find the existing reservation */
  pBwOwnerData = pBwOwnerEntry->pBwOwnerData;
  while (pBwOwnerData != NULL)
    {
      if ((pBwOwnerData->TeLinkId == TeLinkId) &&
	  (pBwOwnerData->OutIf == pComponentLink->oifIndex))
	{
	  if (pBwOwnerData->BW <= BW)
	    {
	      if ((pBwOwnerData->PreAllocBW + pBwOwnerData->BW) >= BW)
		{
		  if (pBwOwnerData->PreAllocBW <= BW)
		    {
		      te_stop_timer (&pBwOwnerData->BwHoldTimer);
		      pBwOwnerData->BwHoldTimer.data.bw_hold_data.BW +=
			(BW - pBwOwnerData->PreAllocBW);
		      pBwOwnerData->PreAllocBW +=
			(BW - pBwOwnerData->PreAllocBW);
		      if (te_start_timer
			  (&pBwOwnerData->BwHoldTimer, BW_HOLD_EXPIRY,
			   30) != E_OK)
			{
			  zlog_err ("\ncannot start BW hold timer %s %d",
				    __FILE__, __LINE__);
			}
		    }
		  else
		    {		/* just resttart the timer */
		      te_stop_timer (&pBwOwnerData->BwHoldTimer);
		      if (te_start_timer
			  (&pBwOwnerData->BwHoldTimer, BW_HOLD_EXPIRY,
			   30) != E_OK)
			{
			  zlog_err ("\ncannot start BW hold timer %s %d",
				    __FILE__, __LINE__);
			}
		    }
		}
	      else
		{
		  if (BW <=
		      (pComponentLink->ReservableBW[HoldPriority] +
		       (pBwOwnerData->PreAllocBW + pBwOwnerData->BW)))
		    {
		      float delta;
		      delta =
			BW - (pBwOwnerData->PreAllocBW + pBwOwnerData->BW);

		      te_stop_timer (&pBwOwnerData->BwHoldTimer);

		      pBwOwnerData->PreAllocBW += delta;
		      pBwOwnerData->BwHoldTimer.data.bw_hold_data.BW += delta;

		      if (te_start_timer
			  (&pBwOwnerData->BwHoldTimer, BW_HOLD_EXPIRY,
			   30) != E_OK)
			{
			  zlog_err ("\ncannot start BW hold timer %s %d",
				    __FILE__, __LINE__);
			}
		      else
			{
			  TE_LINK *pTeLink = NULL;

			  if (rdb_get_te_link (TeLinkId, &pTeLink) != E_OK)
			    {
			      zlog_err ("\ncannot get TE link %s %d",
					__FILE__, __LINE__);
			      return E_ERR;
			    }
			  AllocateBW (pTeLink, pComponentLink, HoldPriority,
				      delta);
			  rdb_te_link_max_lsp_bw_calc (pTeLink);
			  BwUpdateRequest2Igp (pTeLink);
			}
		    }
		  else
		    {
		      zlog_err
			("CALCULATION ERROR: expected to find BW %f %f !!!",
			 BW, pComponentLink->ReservableBW[HoldPriority]);
		      zlog_err
			("TE link id %x OutIf %x dest %x tunnel %x ext tunnel %x lsp id %x",
			 TeLinkId, pComponentLink->oifIndex,
			 key->Session.Dest, key->Session.TunnelId,
			 key->Session.ExtTunelId, key->SenderTemplate.LspId);
		      return E_ERR;
		    }
		}
	    }
	  if (UpdateIfBwOwnerStructure (pComponentLink->oifIndex,
					key,
					pBwOwnerData->PreAllocBW +
					pBwOwnerData->BW,
					HoldPriority) != E_OK)
	    {
	      zlog_err ("\ncannot update IfBwOwnerStrucutre %s %d", __FILE__,
			__LINE__);
	      return E_ERR;
	    }
	  zlog_info ("\ninside of %x...", pComponentLink->oifIndex);
	  return E_OK;
	}
      pBwOwnerData = pBwOwnerData->next;
    }
  if (pComponentLink->ReservableBW[HoldPriority] < BW)
    {
      zlog_err ("\nCALCULATION ERROR: expected to find BW %f %f !!!",
		BW, pComponentLink->ReservableBW[HoldPriority]);
      zlog_err
	("\nTE link id %x OutIf %x dest %x tunnel %x ext tunnel %x lsp id %x",
	 TeLinkId, pComponentLink->oifIndex, key->Session.Dest,
	 key->Session.TunnelId, key->Session.ExtTunelId,
	 key->SenderTemplate.LspId);
      return E_ERR;
    }
  /* BW reservation does not exist on the particular TE link and If */
  if ((pBwOwnerData =
       (BW_OWNER_DATA *) XMALLOC (MTYPE_TE, sizeof (BW_OWNER_DATA))) == NULL)
    {
      zlog_err ("\nFailed to allocate memory %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  pBwOwnerData->next = pBwOwnerEntry->pBwOwnerData;
  pBwOwnerEntry->pBwOwnerData = pBwOwnerData;
  pBwOwnerData->BW = 0;
  pBwOwnerData->PreAllocBW = BW;
  pBwOwnerData->OutIf = pComponentLink->oifIndex;
  pBwOwnerData->TeLinkId = TeLinkId;

  pBwOwnerData->BwHoldTimer.data.bw_hold_data.key = *key;
  pBwOwnerData->BwHoldTimer.data.bw_hold_data.handle = (uns32) pBwOwnerData;
  pBwOwnerData->BwHoldTimer.data.bw_hold_data.TeLinkId = TeLinkId;
  pBwOwnerData->BwHoldTimer.data.bw_hold_data.OutIf =
    pComponentLink->oifIndex;
  pBwOwnerData->BwHoldTimer.data.bw_hold_data.BW = BW;
  pBwOwnerData->BwHoldTimer.data.bw_hold_data.Priority = HoldPriority;
  if (te_start_timer (&pBwOwnerData->BwHoldTimer, BW_HOLD_EXPIRY, 30) != E_OK)
    {
      zlog_err ("\ncannot start BW hold timer %s %d", __FILE__, __LINE__);
    }
  else
    {
      TE_LINK *pTeLink = NULL;

      if (rdb_get_te_link (TeLinkId, &pTeLink) != E_OK)
	{
	  zlog_err ("\ncannot get TE link %s %d", __FILE__, __LINE__);
	}
      zlog_info ("calling ALLOCATE");
      AllocateBW (pTeLink, pComponentLink, HoldPriority, BW);
      rdb_te_link_max_lsp_bw_calc (pTeLink);
      BwUpdateRequest2Igp (pTeLink);
    }
  if (UpdateIfBwOwnerStructure
      (pComponentLink->oifIndex, key, BW, HoldPriority) != E_OK)
    {
      zlog_err ("cannot update IfBwOwnerStructure %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  return E_OK;
}

uns32
CalcActualAlloc (PSB_KEY * key,
		 uns32 TeLinkId,
		 COMPONENT_LINK * pComponentLink,
		 float *BW,
		 uns8 SetupPriority,
		 uns8 HoldPriority, uns8 * PreemptedPriority)
{
  BW_OWNER_ENTRY *pBwOwnerEntry;
  BW_OWNER_DATA *pBwOwnerData;
  float BwAtHigherPriority;

  GetEfficientBwAtHigherPriorities (key, TeLinkId, pComponentLink,
				    HoldPriority, &BwAtHigherPriority);

  zlog_info ("\n%x %x %x %x %f",
	     key->Session.Dest,
	     key->Session.TunnelId,
	     key->Session.ExtTunelId,
	     key->SenderTemplate.LspId, BwAtHigherPriority);

  if ((pBwOwnerEntry =
       (BW_OWNER_ENTRY *) patricia_tree_get (&BwOwnersTree[HoldPriority],
					     (const uns8 *) key)) != NULL)
    {
      pBwOwnerData = pBwOwnerEntry->pBwOwnerData;
      while (pBwOwnerData != NULL)
	{
	  if ((pBwOwnerData->TeLinkId == TeLinkId) &&
	      (pBwOwnerData->OutIf == pComponentLink->oifIndex))
	    {
	      if ((pBwOwnerData->PreAllocBW + pBwOwnerData->BW +
		   BwAtHigherPriority) >= *BW)
		{
		  zlog_info ("Additional allocation is not required: %f %f",
			     pBwOwnerData->PreAllocBW + pBwOwnerData->BW,
			     *BW);
		  *BW = 0;
		  return E_OK;
		}
	      else if ((pComponentLink->ReservableBW[SetupPriority] +
			pBwOwnerData->PreAllocBW + pBwOwnerData->BW +
			BwAtHigherPriority) >= *BW)
		{
		  zlog_info
		    ("Reservable#%f, alloc %f and higher prio alloc %f",
		     pComponentLink->ReservableBW[SetupPriority],
		     pBwOwnerData->PreAllocBW + pBwOwnerData->BW,
		     BwAtHigherPriority);
		  *BW =
		    *BW - (pBwOwnerData->PreAllocBW + pBwOwnerData->BW +
			   BwAtHigherPriority);
		  return E_OK;
		}
	      else
		{
		  float RequiredBW =
		    *BW - (pComponentLink->ReservableBW[SetupPriority] +
			   pBwOwnerData->PreAllocBW + pBwOwnerData->BW);
		  uns8 Preempted;
		  float MaximumPossibleBW;
		  /* checking for bumping possibilities */
		  if (BwPreemptionUseful
		      (pComponentLink->oifIndex, SetupPriority, RequiredBW,
		       &Preempted, &MaximumPossibleBW) == TRUE)
		    {
		      zlog_info
			("Preemption is useful. Priority2BePreempted %x Currently %x",
			 Preempted, *PreemptedPriority);
		      if (*PreemptedPriority <= Preempted)
			{
			  *PreemptedPriority = Preempted;
			}
		      *BW = pComponentLink->ReservableBW[SetupPriority];
		      return E_OK;
		    }
		  else
		    {
		      zlog_info ("Preemption will not help %s %d", __FILE__,
				 __LINE__);
		      return E_ERR;
		    }
		}
	    }
	  pBwOwnerData = pBwOwnerData->next;
	}
    }
  else
    zlog_info ("First time pre-allocation...");

  if ((pComponentLink->ReservableBW[SetupPriority] + BwAtHigherPriority) >=
      *BW)
    {
      if (*BW > BwAtHigherPriority)
	{
	  zlog_info ("Reservable#%f BW at Higher priority#%f, required %f",
		     pComponentLink->ReservableBW[SetupPriority],
		     BwAtHigherPriority, *BW);
	  *BW -= BwAtHigherPriority;
	}
      else
	{
	  zlog_info
	    ("Reservable#%f BW at Lower priority#%f, required %f (actually 0)",
	     pComponentLink->ReservableBW[SetupPriority], BwAtHigherPriority,
	     *BW);
	  *BW = 0;
	}
      return E_OK;
    }
  else
    {
      float RequiredBW = *BW - pComponentLink->ReservableBW[SetupPriority];
      uns8 Preempted;
      float MaximumPossibleBW = 0;
      /* checking for bumping possibilities */
      if (BwPreemptionUseful
	  (pComponentLink->oifIndex, SetupPriority, RequiredBW, &Preempted,
	   &MaximumPossibleBW) == TRUE)
	{
	  zlog_info ("Preemption will help: Required#%f PreemptedPrio %x %f",
		     RequiredBW, Preempted,
		     pComponentLink->ReservableBW[SetupPriority]);
	  if (*PreemptedPriority <= Preempted)
	    {
	      *PreemptedPriority = Preempted;
	    }
	  *BW = pComponentLink->ReservableBW[SetupPriority];
	  return E_OK;
	}
      else
	return E_ERR;
    }
  return E_ERR;
}

uns32
TE_RSVPTE_API_DoAllocation (PSB_KEY * key,
			    uns32 TeLinkId,
			    uns32 OutIfIndex,
			    float BW,
			    uns8 SetupPriority,
			    uns8 HoldPriority, float *MaximumPossibleBW)
{
  BW_OWNER_ENTRY *pBwOwnerEntry;
  BW_OWNER_DATA *pBwOwnerData;
  COMPONENT_LINK *pComponentLink = NULL;
  TE_LINK *pTeLink = NULL;
  float BwAtHigherPriority;

  zlog_info
    ("inside of DoAllocation BW %f Dest %x tunnel %x source %x %x LSP %x HoldPrio %x SetupPrio %x ...",
     BW, key->Session.Dest, key->Session.TunnelId, key->Session.ExtTunelId,
     key->SenderTemplate.IpAddr, key->SenderTemplate.LspId, HoldPriority,
     SetupPriority);
  zlog_info ("TE Link ID %d OutIfIndex %d", TeLinkId, OutIfIndex);

  /* First - register an allocation on the BW owners tree 
     BW owner is the session if SE reservation style or 
     Session and Sender if FF reservation style 
     BW owners tree serves for the prevention of the double accounting
     Upon the Path message, existing reservations are found
     Additional BW is attempted to be allocated on the links,
     where reservation already exists */
  if (rdb_get_component_link (TeLinkId, OutIfIndex, &pComponentLink) != E_OK)
    {
      zlog_err ("\ncannot get component link %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  if (rdb_get_te_link (TeLinkId, &pTeLink) != E_OK)
    {
      zlog_err ("\ncannot get TE link %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  if ((pBwOwnerEntry =
       (BW_OWNER_ENTRY *) patricia_tree_get (&BwOwnersTree[HoldPriority],
					     (const uns8 *) key)) != NULL)
    {
      pBwOwnerData = pBwOwnerEntry->pBwOwnerData;
      while (pBwOwnerData != NULL)
	{
	  if ((pBwOwnerData->TeLinkId == TeLinkId) &&
	      (pBwOwnerData->OutIf == OutIfIndex))
	    {
	      te_stop_timer (&pBwOwnerData->BwHoldTimer);
	      zlog_info
		("BW %f pBwOwnerData->BW %f pBwOwnerData->PreAlloc %f SetupPrio %x HoldPrio %x %s %d",
		 BW, pBwOwnerData->BW, pBwOwnerData->PreAllocBW,
		 SetupPriority, HoldPriority, __FILE__, __LINE__);
	      if (pBwOwnerData->BW > BW)	/* is this BW decrease ? */
		{
		  zlog_info ("res BW %f updt BW %f resbl BW %f",
			     pBwOwnerData->BW, BW,
			     pComponentLink->ReservableBW[HoldPriority]);

		  ReleaseBW (pTeLink, pComponentLink, HoldPriority,
			     pBwOwnerData->BW - BW);
		  pBwOwnerData->BW = BW;
		  pBwOwnerData->PreAllocBW = 0;
		}
	      else
		{
		  if (BW >= (pBwOwnerData->PreAllocBW + pBwOwnerData->BW))
		    {
		      float DeltaBW =
			BW - (pBwOwnerData->PreAllocBW + pBwOwnerData->BW);
		      zlog_info ("DeltaBW %f PreAlloc %f Alloc %f BW %f",
				 DeltaBW, pBwOwnerData->PreAllocBW,
				 pBwOwnerData->BW, BW);

		      zlog_info
			("Required BW#%f  is greater than allocated#%f", BW,
			 (pBwOwnerData->PreAllocBW + pBwOwnerData->BW));
		      GetEfficientBwAtHigherPriorities (key, TeLinkId,
							pComponentLink,
							HoldPriority,
							&BwAtHigherPriority);
		      zlog_info ("At higher priorities #%x",
				 BwAtHigherPriority);
		      if (DeltaBW < BwAtHigherPriority)
			{
			  zlog_info
			    ("It is enough to release own BW at higher priorities");
			  CancelBwAllocAtHigherPriorities (key, TeLinkId,
							   pComponentLink,
							   HoldPriority);
			  AllocateBW (pTeLink, pComponentLink, HoldPriority,
				      DeltaBW);
			}
		      else if ((DeltaBW + BwAtHigherPriority) <=
			       pComponentLink->ReservableBW[HoldPriority])
			{
			  zlog_info
			    ("Releasing own BW at higher priorities, allocating#%x",
			     DeltaBW - BwAtHigherPriority);
			  DeltaBW -= BwAtHigherPriority;
			  /* cancel BW allocations at lower priorities */
			  CancelBwAllocAtHigherPriorities (key, TeLinkId,
							   pComponentLink,
							   HoldPriority);
			  /* now take remaining BW from this priority should be sufficient */
			  AllocateBW (pTeLink, pComponentLink, HoldPriority,
				      DeltaBW);
			}
		      else
			{
			  uns8 PreemptedPriority;
			  zlog_info
			    ("BW can be allocated if only preemption helps");
			  /* try to get BW from lowest priority */
			  if (BwPreemptionUseful
			      (pComponentLink->oifIndex, SetupPriority,
			       DeltaBW, &PreemptedPriority,
			       MaximumPossibleBW) == TRUE)
			    {
			      uns8 Prio = 7;
			      zlog_info
				("Preemption will help. Trying to release #%f",
				 DeltaBW);
			      while (DeltaBW > 0)
				{
				  float FoundBW;

				  if ((FoundBW = PreemptTunnel (TeLinkId,
								pComponentLink,
								Prio,
								HoldPriority,
								key)) == 0)
				    {
				      if (Prio == (SetupPriority + 1))
					{
					  zlog_err ("Algorithmic error %s %d",
						    __FILE__, __LINE__);
					  return E_ERR;
					}
				      else
					{
					  Prio--;
					}
				    }
				  DeltaBW -= FoundBW;
				}
			    }
			  else
			    {
			      (*MaximumPossibleBW) +=
				pBwOwnerData->PreAllocBW + pBwOwnerData->BW;
			      zlog_err ("cannot get enough BW %s %d",
					__FILE__, __LINE__);
			      return E_ERR;
			    }
			}
		      pBwOwnerData->PreAllocBW = 0;
		      pBwOwnerData->BW = BW;
		    }
		  else
		    {
		      zlog_info
			("BW, allocated#%f and pre-allocated#%f is greater than required#%f",
			 pBwOwnerData->BW, pBwOwnerData->PreAllocBW, BW);
		      pBwOwnerData->PreAllocBW =
			(pBwOwnerData->PreAllocBW + pBwOwnerData->BW) - BW;
		      pBwOwnerData->BwHoldTimer.data.bw_hold_data.BW =
			pBwOwnerData->PreAllocBW;
		      if (te_start_timer
			  (&pBwOwnerData->BwHoldTimer, BW_HOLD_EXPIRY,
			   30) != E_OK)
			{
			  zlog_err ("\ncannot start BW hold timer %s %d",
				    __FILE__, __LINE__);
			}
		      pBwOwnerData->BW = BW;
		    }
		}
	      /* if we're here, allocation succeeded */
	      /* cancel BW allocation at other priorities */
	      CancelBwAllocAtOtherPriorities (key, TeLinkId, pComponentLink,
					      HoldPriority);
	      rdb_te_link_max_lsp_bw_calc (pTeLink);
	      BwUpdateRequest2Igp (pTeLink);
	      /* Update If-BW owners structure */
	      if (UpdateIfBwOwnerStructure
		  (pComponentLink->oifIndex, key, BW, HoldPriority) != E_OK)
		{
		  zlog_err ("\ncannot update IfBwOwnerStructure %s %d",
			    __FILE__, __LINE__);
		  return E_ERR;
		}
	      return E_OK;
	    }
	  pBwOwnerData = pBwOwnerData->next;
	}
      zlog_info ("Expected BW owner data is not found.");

      if (pComponentLink->ReservableBW[SetupPriority] < BW)
	{
	  uns8 Preempted;
	  if (BwPreemptionUseful
	      (pComponentLink->oifIndex, SetupPriority, BW, &Preempted,
	       MaximumPossibleBW) == FALSE)
	    {
	      zlog_info ("cannot allocate BW exhausted %s %d", __FILE__,
			 __LINE__);
	      return E_ERR;
	    }
	}
    }
  else
    {
      zlog_info
	("expected BW owner (Session) %x %x %x Prio %x is not found on the patricia tree %s %d",
	 key->Session.Dest, key->Session.TunnelId, key->Session.ExtTunelId,
	 HoldPriority, __FILE__, __LINE__);

      if (pComponentLink->ReservableBW[SetupPriority] < BW)
	{
	  /* try to get BW from lowest priority */
	  uns8 Preempted;
	  if (BwPreemptionUseful
	      (pComponentLink->oifIndex, SetupPriority, BW, &Preempted,
	       MaximumPossibleBW) == FALSE)
	    {
	      zlog_info ("cannot allocate, BW exhausted %s %d", __FILE__,
			 __LINE__);
	      return E_ERR;
	    }
	}
      if ((pBwOwnerEntry =
	   (BW_OWNER_ENTRY *) XMALLOC (MTYPE_TE,
				       sizeof (BW_OWNER_ENTRY))) == NULL)
	{
	  zlog_err ("\nFailed to allocate memory %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pBwOwnerEntry->key = *key;
      pBwOwnerEntry->Node.key_info = (uns8 *) & pBwOwnerEntry->key;
      if (patricia_tree_add
	  (&BwOwnersTree[HoldPriority], &pBwOwnerEntry->Node) != E_OK)
	{
	  zlog_err ("\nFailed to allocate memory %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
    }
  /* BW reservation does not exist on the particular TE link and If */
  if ((pBwOwnerData =
       (BW_OWNER_DATA *) XMALLOC (MTYPE_TE, sizeof (BW_OWNER_DATA))) == NULL)
    {
      zlog_err ("\nFailed to allocate memory %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  pBwOwnerData->next = pBwOwnerEntry->pBwOwnerData;
  pBwOwnerEntry->pBwOwnerData = pBwOwnerData;
  pBwOwnerData->BW = BW;
  pBwOwnerData->OutIf = OutIfIndex;
  pBwOwnerData->TeLinkId = TeLinkId;

  if (pComponentLink->ReservableBW[SetupPriority] < BW)
    {
      float TempBW = BW;
      uns32 Prio = 7;
      while (TempBW > 0)
	{
	  float FoundBW;

	  if ((FoundBW = PreemptTunnel (TeLinkId,
					pComponentLink,
					Prio, HoldPriority, key)) == 0)
	    {
	      if (Prio == (SetupPriority + 1))
		{
		  zlog_err ("Algorithmic error %s %d", __FILE__, __LINE__);
		  return E_ERR;
		}
	      else
		{
		  Prio--;
		}
	    }
	  TempBW -= FoundBW;
	}
    }
  /* if we're here, allocation succeeded */
  /* cancel BW allocation at other priorities */
  CancelBwAllocAtOtherPriorities (key, TeLinkId, pComponentLink,
				  HoldPriority);

  rdb_te_link_max_lsp_bw_calc (pTeLink);

  BwUpdateRequest2Igp (pTeLink);

  /* Update If-BW owners structure */
  if (UpdateIfBwOwnerStructure
      (pComponentLink->oifIndex, key, BW, HoldPriority) != E_OK)
    {
      zlog_err ("cannot update IfBwOwnerStructure %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  return E_OK;
}

uns32
DoRelease (PSB_KEY * key, uns32 TeLinkId, uns32 OutIfIndex, uns8 Priority)
{
  BW_OWNER_ENTRY *pBwOwnerEntry;
  BW_OWNER_DATA *pBwOwnerData, *pBwOwnerDataPrev;
  COMPONENT_LINK *pComponentLink = NULL;
  TE_LINK *pTeLink = NULL;
  float Released = 0;
  zlog_info ("inside of DoRelease..");
  if ((pBwOwnerEntry =
       (BW_OWNER_ENTRY *) patricia_tree_get (&BwOwnersTree[Priority],
					     (const uns8 *) key)) != NULL)
    {
      pBwOwnerDataPrev = pBwOwnerData = pBwOwnerEntry->pBwOwnerData;
      while (pBwOwnerData != NULL)
	{
	  if ((pBwOwnerData->TeLinkId == TeLinkId) &&
	      (pBwOwnerData->OutIf == OutIfIndex))
	    {
	      Released = pBwOwnerData->BW + pBwOwnerData->PreAllocBW;
	      zlog_info ("pBwOwnerData->BW %f, PreallocBW %f",
			 pBwOwnerData->BW, pBwOwnerData->PreAllocBW);
	      if (rdb_get_component_link
		  (TeLinkId, OutIfIndex, &pComponentLink) != E_OK)
		{
		  zlog_info ("\ncannot get componentl link %x %x %s %x",
			     TeLinkId, OutIfIndex, __FILE__, __LINE__);
		  return E_ERR;
		}

	      if (rdb_get_te_link (TeLinkId, &pTeLink) != E_OK)
		{
		  zlog_err ("\ncannot get TE link %s %d", __FILE__, __LINE__);
		}
	      ReleaseBW (pTeLink, pComponentLink, Priority, Released);
	      rdb_te_link_max_lsp_bw_calc (pTeLink);
	      BwUpdateRequest2Igp (pTeLink);
	      zlog_info ("BW Owners Entry will be deleted");
	      te_stop_timer (&pBwOwnerData->BwHoldTimer);
	      if (pBwOwnerEntry->pBwOwnerData == pBwOwnerData)
		pBwOwnerEntry->pBwOwnerData =
		  pBwOwnerEntry->pBwOwnerData->next;
	      else
		pBwOwnerDataPrev->next = pBwOwnerData->next;
	      XFREE (MTYPE_TE, pBwOwnerData);
	      if (pBwOwnerEntry->pBwOwnerData == NULL)
		{
		  if (patricia_tree_del
		      (&BwOwnersTree[Priority], &pBwOwnerEntry->Node) != E_OK)
		    {
		      zlog_err ("\ncannot delete node from patricia %s %d",
				__FILE__, __LINE__);
		    }
		  else
		    {
		      XFREE (MTYPE_TE, pBwOwnerEntry);
		    }
		}
	      if (UpdateIfBwOwnerStructure
		  (pComponentLink->oifIndex, key, Released, Priority) != E_OK)
		{
		  zlog_err ("\ncannot update IfBwOwnerStructure %s %d",
			    __FILE__, __LINE__);
		  return E_ERR;
		}
	      return E_OK;
	    }
	  pBwOwnerDataPrev = pBwOwnerData;
	  pBwOwnerData = pBwOwnerData->next;
	}
    }
  else
    {
      zlog_err ("\ncannot get entry from BW owners patricia tree %s %d",
		__FILE__, __LINE__);
      return E_ERR;
    }
  return E_OK;
}

static void
AllocateBW (TE_LINK * pTeLink, COMPONENT_LINK * pComponentLink, uns8 Priority,
	    float BW)
{
  int j;

  if (pComponentLink->ReservableBW[Priority] >= BW)
    {
      pComponentLink->ReservableBW[Priority] -= BW;
      pTeLink->te_link_properties.ReservableBW[Priority] -= BW;
      pComponentLink->AllocatedBW[Priority][Priority] += BW;
    }
  else
    {
      pComponentLink->ReservableBW[Priority] = 0;
    }

  for (j = Priority + 1; j < 8; j++)
    {
      if (pComponentLink->ReservableBW[j] >= BW)
	{
	  pComponentLink->ReservableBW[j] -= BW;
	  pTeLink->te_link_properties.ReservableBW[j] -= BW;
	}
      else
	{
	  pComponentLink->ReservableBW[j] = 0;
	}
    }
}

static void
ReleaseBW (TE_LINK * pTeLink, COMPONENT_LINK * pComponentLink, uns8 Priority,
	   float BW)
{
  int i, j;
  float ReleasedBW = 0;
  /* Find highest priority where BW remains to be allocated */
  for (i = 0; (i < 8) && (BW > 0); i++)
    {
      if (pComponentLink->AllocatedBW[i][i] > 0)
	{
	  ReleasedBW = 0;
	  if (BW >= pComponentLink->AllocatedBW[i][i])
	    {
	      ReleasedBW = pComponentLink->AllocatedBW[i][i];
	      pComponentLink->ReservableBW[i] +=
		pComponentLink->AllocatedBW[i][i];
	      pTeLink->te_link_properties.ReservableBW[i] +=
		pComponentLink->AllocatedBW[i][i];
	      BW -= pComponentLink->AllocatedBW[i][i];
	      pComponentLink->AllocatedBW[i][i] = 0;
	    }
	  else
	    {
	      ReleasedBW = BW;
	      pComponentLink->ReservableBW[i] += BW;
	      pTeLink->te_link_properties.ReservableBW[i] += BW;
	      pComponentLink->AllocatedBW[i][i] -= BW;
	      BW = 0;
	    }
	  for (j = i + 1; (j < 8) && (ReleasedBW > 0); j++)
	    {
	      if (pComponentLink->AllocatedBW[i][j] > 0)
		{
		  if (ReleasedBW >= pComponentLink->AllocatedBW[i][j])
		    {
		      pComponentLink->AllocatedBW[j][j] +=
			pComponentLink->AllocatedBW[i][j];
		      ReleasedBW -= pComponentLink->AllocatedBW[i][j];
		      pComponentLink->AllocatedBW[i][j] = 0;
		    }
		  else
		    {
		      pComponentLink->AllocatedBW[j][j] += ReleasedBW;
		      pComponentLink->AllocatedBW[i][j] -= ReleasedBW;
		      ReleasedBW = 0;
		    }
		}
	    }
	}
    }
  if (ReleasedBW > 0)
    {
      for (; i < 8; i++)
	{
	  if (pComponentLink->AllocatedBW[i][i] > 0)
	    {
	      break;
	    }
	  if (pComponentLink->ConfiguredReservableBW[i] >
	      pComponentLink->ReservableBW[i])
	    {
	      if ((pComponentLink->ReservableBW[i] + ReleasedBW) <=
		  pComponentLink->ConfiguredReservableBW[i])
		{
		  pComponentLink->ReservableBW[i] += ReleasedBW;
		  pTeLink->te_link_properties.ReservableBW[i] += ReleasedBW;
		}
	      else
		{
		  pTeLink->te_link_properties.ReservableBW[i] =
		    (pComponentLink->ConfiguredReservableBW[i] -
		     pComponentLink->ReservableBW[i]);
		  pComponentLink->ReservableBW[i] =
		    pComponentLink->ConfiguredReservableBW[i];
		}
	    }
	}
    }
}

static void
PreemptBW (COMPONENT_LINK * pComponentLink,
	   uns8 PreemptorPriority, uns8 PreemptedPriority, float BW)
{
  int i;
  if (PreemptedPriority == 0)
    {
      zlog_err ("\nBUG: Preempted priority is 0!!!");
      return;
    }
  for (i = 7; (i >= PreemptedPriority) && (BW > 0); i--)
    {
      if (pComponentLink->AllocatedBW[PreemptedPriority][i] > 0)
	{
	  if (pComponentLink->AllocatedBW[PreemptedPriority][i] >= BW)
	    {
	      pComponentLink->AllocatedBW[PreemptedPriority][i] -= BW;
	      pComponentLink->AllocatedBW[PreemptorPriority][i] += BW;
	      return;
	    }
	  else
	    {
	      pComponentLink->AllocatedBW[PreemptorPriority][i] +=
		pComponentLink->AllocatedBW[PreemptedPriority][i];
	      BW -= pComponentLink->AllocatedBW[PreemptedPriority][i];
	      pComponentLink->AllocatedBW[PreemptedPriority][i] = 0;
	    }
	}
    }
  if (BW > 0)
    {
      zlog_err ("\nBUG: BW > 0 %s %d", __FILE__, __LINE__);
    }
}

void
BwOwnersDump ()
{
  BW_OWNER_ENTRY *pBwOwnerEntry;
  BW_OWNER_DATA *pBwOwnerData;
  PSB_KEY PsbKey;
  int j;

  for (j = 0; j < 8; j++)
    {
      memset (&PsbKey, 0, sizeof (PSB_KEY));
      zlog_debug ("Priority# %x", j);
      while ((pBwOwnerEntry =
	      (BW_OWNER_ENTRY *) patricia_tree_getnext (&BwOwnersTree[j],
							(const uns8 *)
							&PsbKey)) != NULL)
	{
	  zlog_debug
	    ("owner dest %x tunnel id %x ext tunnel id %x sender ip %x lsp id %x",
	     pBwOwnerEntry->key.Session.Dest,
	     pBwOwnerEntry->key.Session.TunnelId,
	     pBwOwnerEntry->key.Session.ExtTunelId,
	     pBwOwnerEntry->key.SenderTemplate.IpAddr,
	     pBwOwnerEntry->key.SenderTemplate.LspId);
	  pBwOwnerData = pBwOwnerEntry->pBwOwnerData;
	  while (pBwOwnerData != NULL)
	    {
	      zlog_debug ("TE Link ID %x Out IF %x BW %f PreAlloc BW %f",
			  pBwOwnerData->BW,
			  pBwOwnerData->TeLinkId,
			  pBwOwnerData->OutIf, pBwOwnerData->PreAllocBW);
	      pBwOwnerData = pBwOwnerData->next;
	    }
	  PsbKey = pBwOwnerEntry->key;
	}
    }
  return;
}

void
IfBwOwnersDump ()
{
  IF_BW_KEY if_bw_key;
  IF_BW_DATA *pIfBwEntry;
  int j;

  memset (&if_bw_key, 0, sizeof (IF_BW_KEY));

  for (j = 0; j < 8; j++)
    {
      zlog_debug ("Priority#%x", j);
      while ((pIfBwEntry =
	      (IF_BW_DATA *) patricia_tree_getnext (&IfBwOwnersTree[j],
						    (const uns8 *)
						    &if_bw_key)) != NULL)
	{
	  zlog_debug ("IF#%x Dest #%x Tunnel #%x Source #%x BW #%f",
		      pIfBwEntry->if_bw_key.IfIndex,
		      pIfBwEntry->if_bw_key.PsbKey.Session.Dest,
		      pIfBwEntry->if_bw_key.PsbKey.Session.TunnelId,
		      pIfBwEntry->if_bw_key.PsbKey.Session.ExtTunelId,
		      pIfBwEntry->BW);
	  if_bw_key = pIfBwEntry->if_bw_key;
	}
    }
  return;
}
