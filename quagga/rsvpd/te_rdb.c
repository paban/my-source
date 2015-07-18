/* Module:   rdb.c
   Contains: TE application route DB and pach cache
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "te.h"
#include "te_cspf.h"

extern struct zclient *zclient;

/***********************************************************************************
 ***********************************************************************************
 *                                                                                 *
 *                                                                                 *
 *                             Routing Database Manager                            *
 *                                                                                 *
 *                                                                                 *
 ***********************************************************************************
 **********************************************************************************/

/** This is an Routing  Table Entry, created via rdb_add_route wrapper
 **/

/** This is an IfAddr Table Entry, created via rdb_add_ifaddr
 **/
typedef struct rdb_ifaddr_tag
{
  struct rdb_ifaddr_tag *next;
  IPV4_ADDR ip_addr;
  uns32 ifIndex;
} SYSF_RDB_IFADDR;

typedef struct
{
  PATRICIA_NODE Node;
  IPV4_ADDR dest;
  PATH_L_LIST *PathLList;
  uns32 LListItemsCount;
} RDB_PATH;

typedef struct
{
  PATRICIA_NODE Node;
  IPV4_ADDR dest;
  TE_LINK_L_LIST *TELinkLList;
  uns32 LListItemsCount;
} RDB_NEXT_HOP;

typedef struct
{
  PATRICIA_NODE Node;
  IPV4_ADDR neighbor;
} TE_LINK_NEXT_HOP;

typedef struct
{
  PATRICIA_NODE Node;
  IPV4_ADDR dest;
  ABRS_L_LIST *AbrsLList;
  uns32 LListItemsCount;
} RDB_ABRS;

/** This is the Routing Database, created via rdb_create wrapper.
 **/
SYSF_RDB_IFADDR *ifaddr_anchor;
PATRICIA_TREE ASBorderTree;
PATRICIA_TREE AreaBorderTree;
PATRICIA_TREE NextHopTree;
TE_LINK_L_LIST *TeLinkLListHead;
PATRICIA_TREE RemoteLinkTree[MAX_PATH_TYPE - 1];
PATRICIA_TREE Link2RouterIdTree;
STATIC_PATH *StaticPathHead;
IPV4_ADDR RouterID = 0;

static uns32 compare_er_hops (ER_HOP_L_LIST * er_hops1, TE_HOP * er_hops2,
			      uns8 hop_count);

static void copy_te_link (TE_LINK * te_link1, TE_LINK * te_link2);

static void delete_te_link (TE_LINK * te_link);

static void delete_abr (ABR * pAbr);
static void delete_component_link (COMPONENT_LINK * pComponentLink);

uns32
AmIDestination (IPV4_ADDR dest, uns32 * pDestIf)
{
  SYSF_RDB_IFADDR *ifaddr;

  *pDestIf = 0xFFFFFFFF;

  for (ifaddr = ifaddr_anchor; ifaddr != NULL; ifaddr = ifaddr->next)
    {
      if (ifaddr->ip_addr == dest)
	{
	  *pDestIf = ifaddr->ifIndex;
	  break;
	}
    }
  return E_OK;
}

uns32
IsDestinationNextHop (IPV4_ADDR dest, TE_LINK_L_LIST ** ppTeLinks)
{
  RDB_NEXT_HOP *next_hop_entry;


  if ((next_hop_entry =
       (RDB_NEXT_HOP *) patricia_tree_get (&NextHopTree,
					   (const uns8 *) &dest)) != NULL)
    {
      *ppTeLinks = next_hop_entry->TELinkLList;
    }
  else
    {
      *ppTeLinks = NULL;
    }
  return E_OK;
}

uns32
IsDestinationIntraArea (IPV4_ADDR dest, PATH_L_LIST ** ppPaths)
{
  RDB_PATH *path_entry;

  if ((path_entry =
       (RDB_PATH *) patricia_tree_get (&AreaBorderTree,
				       (const uns8 *) &dest)) != NULL)
    {
      *ppPaths = path_entry->PathLList;
    }
  else
    {
      *ppPaths = NULL;
    }
  return E_OK;
}

uns32
GetPathNumber (IPV4_ADDR dest)
{
  RDB_PATH *path_entry;

  if ((path_entry =
       (RDB_PATH *) patricia_tree_get (&AreaBorderTree,
				       (const uns8 *) &dest)) != NULL)
    {
      return path_entry->LListItemsCount;
    }
  return 0;
}

uns32
IsDestinationASBorder (IPV4_ADDR dest, ABRS_L_LIST ** ppAbrs)
{
  RDB_ABRS *abr_entry;

  if ((abr_entry =
       (RDB_ABRS *) patricia_tree_get (&ASBorderTree,
				       (const uns8 *) &dest)) != NULL)
    {
      *ppAbrs = abr_entry->AbrsLList;
    }
  else
    {
      *ppAbrs = NULL;
    }
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:   rdb_create

  DESCRIPTION:

  Creates a routing database.

*****************************************************************************/
E_RC
rdb_create ()
{
  PATRICIA_PARAMS params;
  int i;
  memset (&params, 0, sizeof (params));
  params.key_size = sizeof (IPV4_ADDR);
  params.info_size = 0;

  TeLinkLListHead = NULL;
  ifaddr_anchor = NULL;

  if (patricia_tree_init (&AreaBorderTree, &params) != E_OK)
    {
      return E_ERR;
    }
  if (patricia_tree_init (&ASBorderTree, &params) != E_OK)
    {
      return E_ERR;
    }
  if (patricia_tree_init (&NextHopTree, &params) != E_OK)
    {
      return E_ERR;
    }

  if (patricia_tree_init (&Link2RouterIdTree, &params) != E_OK)
    {
      return E_ERR;
    }

  params.key_size = sizeof (IPV4_ADDR) + sizeof (IPV4_ADDR);
  params.info_size = 0;

  for (i = 0; i < (MAX_PATH_TYPE - 1); i++)
    {
      if (patricia_tree_init (&(RemoteLinkTree[i]), &params) != E_OK)
	{
	  return E_ERR;
	}
    }

  StaticPathHead = NULL;

  return E_OK;
}


/*****************************************************************************

  PROCEDURE NAME:    rdb_destroy

  DESCRIPTION:


*****************************************************************************/
uns32
rdb_destroy ()
{
  RDB_PATH *path_entry;
  RDB_NEXT_HOP *next_hop_entry;
  RDB_ABRS *abr_entry;
  IPV4_ADDR key_ip;

  key_ip = 0;
  while ((abr_entry =
	  (RDB_ABRS *) patricia_tree_getnext (&ASBorderTree,
					      (const uns8 *) &key_ip)) !=
	 NULL)
    {
      while (abr_entry->AbrsLList != NULL)
	{
	  ABRS_L_LIST *pAbrLl = abr_entry->AbrsLList->next;
	  XFREE (MTYPE_TE, abr_entry->AbrsLList->Abr->SummaryProperties);
	  XFREE (MTYPE_TE, abr_entry->AbrsLList->Abr);
	  XFREE (MTYPE_TE, abr_entry->AbrsLList);
	  abr_entry->AbrsLList = pAbrLl;
	}
      key_ip = abr_entry->dest;
      if (patricia_tree_del (&ASBorderTree, &abr_entry->Node) != E_OK)
	{
	  zlog_err ("\ncannot delete ASBR");
	}
    }
  patricia_tree_destroy (&ASBorderTree);
  key_ip = 0;
  while ((path_entry =
	  (RDB_PATH *) patricia_tree_getnext (&AreaBorderTree,
					      (const uns8 *) &key_ip)) !=
	 NULL)
    {
      while (path_entry->PathLList != NULL)
	{
	  PATH_L_LIST *pPathLl = path_entry->PathLList->next;
	  XFREE (MTYPE_TE, path_entry->PathLList->pPath->u.er_hops);
	  XFREE (MTYPE_TE, path_entry->PathLList->pPath);
	  XFREE (MTYPE_TE, path_entry->PathLList);
	  path_entry->PathLList = pPathLl;
	}
      key_ip = path_entry->dest;
      if (patricia_tree_del (&AreaBorderTree, &path_entry->Node) != E_OK)
	{
	  zlog_err ("\ncannot delete ASBR");
	}
    }
  patricia_tree_destroy (&AreaBorderTree);
  key_ip = 0;
  while ((next_hop_entry =
	  (RDB_NEXT_HOP *) patricia_tree_getnext (&NextHopTree,
						  (const uns8 *) &key_ip)) !=
	 NULL)
    {
      while (next_hop_entry->TELinkLList != NULL)
	{
	  TE_LINK_L_LIST *pTeLinkLl = next_hop_entry->TELinkLList->next;
	  XFREE (MTYPE_TE, next_hop_entry->TELinkLList);
	  next_hop_entry->TELinkLList = pTeLinkLl;
	}
      key_ip = next_hop_entry->dest;
      if (patricia_tree_del (&NextHopTree, &next_hop_entry->Node) != E_OK)
	{
	  zlog_err ("\ncannot delete ASBR");
	}
    }
  patricia_tree_destroy (&NextHopTree);
  return E_OK;
}

uns32
compare_er_hops (ER_HOP_L_LIST * er_hops1, TE_HOP * er_hops2, uns8 hop_count)
{
  int i;
  for (i = 0; i < hop_count; i++)
    {
      if ((er_hops1->er_hop->local_ip != er_hops2->local_ip) ||
	  (er_hops1->er_hop->remote_ip != er_hops2->remote_ip))
	return FALSE;
      er_hops1 = er_hops1->next;
      er_hops2++;
    }
  return TRUE;
}

void
copy_te_link (TE_LINK * te_link1, TE_LINK * te_link2)
{
  COMPONENT_LINK *pComponentLink1, *pComponentLink2, *pTemp;
  int j;

  te_link1->te_link_id = te_link2->te_link_id;
  te_link1->Status = te_link2->Status;
  te_link1->type = te_link2->type;
  memcpy (&te_link1->te_link_properties, &te_link2->te_link_properties,
	  sizeof (TE_LINK_PROPERTIES));
  pComponentLink1 = te_link1->component_links;
  pComponentLink2 = te_link2->component_links;
  while ((pComponentLink1 != NULL) && (pComponentLink2 != NULL))
    {
      pComponentLink1->oifIndex = pComponentLink2->oifIndex;
//              pComponentLink1->vcard_id = pComponentLink2->vcard_id;
      for (j = 0; j < 8; j++)
	{
	  pComponentLink1->ReservableBW[j] = pComponentLink2->ReservableBW[j];
	  pComponentLink1->ConfiguredReservableBW[j] =
	    pComponentLink2->ConfiguredReservableBW[j];
	}
      pComponentLink1 = pComponentLink1->next;
      pComponentLink2 = pComponentLink2->next;
    }
  if ((pComponentLink1 == NULL) && (pComponentLink2 != NULL))
    {
      while (pComponentLink2 != NULL)
	{
	  pTemp = pComponentLink2->next;
	  pComponentLink2->next = te_link1->component_links;
	  te_link1->component_links = pComponentLink2;
	  pComponentLink2 = pTemp;
	}
    }
  else if ((pComponentLink1 != NULL) && (pComponentLink2 == NULL))
    {
      while (pComponentLink1 != NULL)
	{
	  pTemp = pComponentLink1->next;
	  delete_component_link (pComponentLink1);
	  pComponentLink1 = pTemp;
	}
    }

}

void
delete_component_link (COMPONENT_LINK * pComponentLink)
{
  XFREE (MTYPE_TE, pComponentLink);
}

void
delete_te_link (TE_LINK * te_link)
{
  COMPONENT_LINK *pComponentLink;

  while (te_link->component_links != NULL)
    {
      pComponentLink = te_link->component_links->next;
      delete_component_link (te_link->component_links);
      te_link->component_links = pComponentLink;
    }
  XFREE (MTYPE_TE, te_link);
}

void
delete_abr (ABR * pAbr)
{
  XFREE (MTYPE_TE, pAbr->SummaryProperties);
  XFREE (MTYPE_TE, pAbr);
  return;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_add_component_link

  DESCRIPTION:  The routine adds a new TE link into TE links linked links.
  
  PARAMETERS:   rdb_handle - Routing Data Base handler
                pTeLink - pointer to TE Link's properties (may span component links).
  IMPORTANT NOTE: The memory for pTeLink MUST be allocated from HEAP (not on the stack!!!).

*****************************************************************************/

uns32
rdb_add_component_link (uns32 TeLinkId, COMPONENT_LINK * pComponentLink)
{
  TE_LINK_L_LIST *pTeLinks;
  COMPONENT_LINK *pTemp;
  int j;
  float MaxReservableBW = 0;

  pTeLinks = TeLinkLListHead;
  while (pTeLinks != NULL)
    {
      if (pTeLinks->te_link->te_link_id == TeLinkId)
	{
	  while (pComponentLink != NULL)
	    {
	      pTemp = pComponentLink->next;
	      pComponentLink->next = pTeLinks->te_link->component_links;
	      pTeLinks->te_link->component_links = pComponentLink;
	      for (j = 0; j < 8; j++)
		{
		  pTeLinks->te_link->te_link_properties.ReservableBW[j] +=
		    pComponentLink->ReservableBW[j];
		  if (pComponentLink->ReservableBW[j] > MaxReservableBW)
		    MaxReservableBW = pComponentLink->ReservableBW[j];
		}
	      pComponentLink = pTemp;
	    }
	  break;
	}
      pTeLinks = pTeLinks->next;
    }
  if (pTeLinks == NULL)
    {
      zlog_err ("\nTE link was not found");
      return E_ERR;
    }
  if (pTeLinks->te_link->te_link_properties.MaxReservableBW < MaxReservableBW)
    pTeLinks->te_link->te_link_properties.MaxReservableBW = MaxReservableBW;
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_delete_component_link

  DESCRIPTION:  The routine adds a new TE link into TE links linked links.
  
  PARAMETERS:   rdb_handle - Routing Data Base handler
                pTeLink - pointer to TE Link's properties (may span component links).
  IMPORTANT NOTE: The memory for pTeLink MUST be allocated from HEAP (not on the stack!!!).

*****************************************************************************/

uns32
rdb_delete_component_link (uns32 TeLinkId, uns32 oIfIndex)
{
  TE_LINK_L_LIST *pTeLinks;
  COMPONENT_LINK *pComponentLink, *pComponentLinkPrev;
  BOOL delete_te_link = 0;
  int j;

  pTeLinks = TeLinkLListHead;
  while (pTeLinks != NULL)
    {
      if (pTeLinks->te_link->te_link_id == TeLinkId)
	{
	  pComponentLink = pComponentLinkPrev =
	    pTeLinks->te_link->component_links;
	  while (pComponentLink != NULL)
	    {
	      if (pComponentLink->oifIndex == oIfIndex)
		{
		  for (j = 0; j < 8; j++)
		    pTeLinks->te_link->te_link_properties.ReservableBW[j] -=
		      pComponentLink->ReservableBW[j];
		  if (pComponentLink == pTeLinks->te_link->component_links)
		    pTeLinks->te_link->component_links =
		      pTeLinks->te_link->component_links->next;
		  else
		    pComponentLinkPrev->next = pComponentLink->next;
		  delete_component_link (pComponentLink);
		  if (pTeLinks->te_link->component_links == NULL)
		    delete_te_link = 1;
		  break;
		}
	      pComponentLinkPrev = pComponentLink;
	      pComponentLink = pComponentLink->next;
	    }
	  break;
	}
      pTeLinks = pTeLinks->next;
    }
  if (pTeLinks == NULL)
    {
      zlog_err ("\nTE link was not found");
      return E_ERR;
    }
  if (!delete_te_link)
    {
      rdb_te_link_max_lsp_bw_calc (pTeLinks->te_link);
    }
  if (delete_te_link)
    return rdb_del_te_link (TeLinkId);
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_get_te_link

  DESCRIPTION:  The routine gets a component link with IfIndex, belonging to TE Link with TeLinkId.
  
  PARAMETERS:   rdb_handle - Routing Data Base handler
                ppTeLink - pointer to TE Link.
                                TeLinkId - TE Link identifier.
                                IfIndex - If index.
  IMPORTANT NOTE: The memory for pTeLink MUST be allocated from HEAP (not on the stack!!!).

*****************************************************************************/

uns32
rdb_get_component_link (uns32 TeLinkId, uns32 IfIndex,
			COMPONENT_LINK ** ppCompLink)
{
  TE_LINK_L_LIST *pTeLinks;
  COMPONENT_LINK *pComponentLinks;
  zlog_info ("entering rdb_get_component_link");
  *ppCompLink = NULL;
  pTeLinks = TeLinkLListHead;
  while (pTeLinks != NULL)
    {
      if (pTeLinks->te_link->te_link_id == TeLinkId)
	{
	  pComponentLinks = pTeLinks->te_link->component_links;
	  while (pComponentLinks != NULL)
	    {
	      if (pComponentLinks->oifIndex == IfIndex)
		{
		  *ppCompLink = pComponentLinks;
		  zlog_info ("leaving rdb_get_component_link+");
		  return E_OK;
		}
	      pComponentLinks = pComponentLinks->next;
	    }
	}
      pTeLinks = pTeLinks->next;
    }
  zlog_info ("leaving rdb_get_component_link-");
  return E_ERR;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_get_te_link

  DESCRIPTION:  The routine gets a component link with IfIndex, belonging to TE Link with TeLinkId.
  
  PARAMETERS:   rdb_handle - Routing Data Base handler
                ppTeLink - pointer to TE Link.
                                TeLinkId - TE Link identifier.
                                IfIndex - If index.
  IMPORTANT NOTE: The memory for pTeLink MUST be allocated from HEAP (not on the stack!!!).

*****************************************************************************/

uns32
rdb_get_te_link (uns32 TeLinkId, TE_LINK ** ppTeLink)
{
  TE_LINK_L_LIST *pTeLinks;

  *ppTeLink = NULL;

  pTeLinks = TeLinkLListHead;
  while (pTeLinks != NULL)
    {
      if (pTeLinks->te_link->te_link_id == TeLinkId)
	{
	  *ppTeLink = pTeLinks->te_link;
	  return E_OK;
	}
      pTeLinks = pTeLinks->next;
    }
  return E_ERR;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_add_te_link

  DESCRIPTION:  The routine adds a new TE link into TE links linked links.
  
  PARAMETERS:   rdb_handle - Routing Data Base handler
                pTeLink - pointer to TE Link's properties (may span component links).
  IMPORTANT NOTE: The memory for pTeLink MUST be allocated from HEAP (not on the stack!!!).

*****************************************************************************/

void
rdb_te_link_max_lsp_bw_calc (TE_LINK * pTeLink)
{
  float MaxReservableBW = 0;
  int j;
  COMPONENT_LINK *pComponentLink = pTeLink->component_links;
  while (pComponentLink != NULL)
    {
      for (j = 0; j < 8; j++)
	{
	  if (pComponentLink->ReservableBW[j] > MaxReservableBW)
	    MaxReservableBW = pComponentLink->ReservableBW[j];
	}
      pComponentLink = pComponentLink->next;
    }
  pTeLink->te_link_properties.MaxReservableBW = MaxReservableBW;
  return;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_add_te_link

  DESCRIPTION:  The routine adds a new TE link into TE links linked links.
  
  PARAMETERS:   rdb_handle - Routing Data Base handler
                pTeLink - pointer to TE Link's properties (may span component links).
  IMPORTANT NOTE: The memory for pTeLink MUST be allocated from HEAP (not on the stack!!!).

*****************************************************************************/

uns32
rdb_add_te_link (TE_LINK * pTeLink)
{
  TE_LINK_L_LIST *pTeLinks, *pTeLinksPrev = NULL, *pNew;
  PATRICIA_PARAMS params;

  zlog_info
    ("entering rdb_add_te_link: TE link ID %x Metric %d Colors %x BW %f",
     pTeLink->te_link_id, pTeLink->te_link_properties.TeMetric,
     pTeLink->te_link_properties.color_mask,
     pTeLink->te_link_properties.MaxLspBW);

  if ((pNew =
       (TE_LINK_L_LIST *) XMALLOC (MTYPE_TE,
				   sizeof (TE_LINK_L_LIST))) == NULL)
    {
      delete_te_link (pTeLink);
      return E_ERR;
    }
  pNew->te_link = pTeLink;
  pNew->next = NULL;

  memset (&params, 0, sizeof (params));
  params.key_size = sizeof (IPV4_ADDR);
  params.info_size = 0;

  if (patricia_tree_init (&pTeLink->NeighborsTree, &params) != E_OK)
    {
      XFREE (MTYPE_TE, pNew);
      return E_ERR;
    }

  if (TeLinkLListHead == NULL)
    {
      TeLinkLListHead = pNew;
      zlog_info ("leaving rdb_add_te_link1");
      return E_OK;
    }
  else
    {
      pTeLinks = TeLinkLListHead;
      while (pTeLinks != NULL)
	{
	  if (pTeLinks->te_link->te_link_id > pTeLink->te_link_id)
	    {
	      if (pTeLinks == TeLinkLListHead)
		{
		  pNew->next = TeLinkLListHead;
		  TeLinkLListHead = pNew;
		}
	      else
		{
		  pTeLinksPrev->next = pNew;
		  pNew->next = pTeLinks;
		}
	      zlog_info ("leaving rdb_add_te_link2");
	      return E_OK;
	    }
	  else if (pTeLinks->te_link->te_link_id == pTeLink->te_link_id)
	    {
	      copy_te_link (pTeLinks->te_link, pTeLink);
	      delete_te_link (pTeLink);
	      XFREE (MTYPE_TE, pNew);
	      zlog_info ("leaving rdb_add_te_link3");
	      return E_OK;
	    }
	  pTeLinksPrev = pTeLinks;
	  pTeLinks = pTeLinks->next;
	}
      pTeLinksPrev->next = pNew;
      zlog_info ("leaving rdb_add_te_link4");
      return E_OK;
    }
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_del_te_link

  DESCRIPTION: The routine deletes the TE link with ID - te_link_id from the
  TE link's linked list.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              te_link_id - TE link ID, by which TE link is found and deleted.

*****************************************************************************/

uns32
rdb_del_te_link (uns32 te_link_id)
{
  TE_LINK_L_LIST *pTeLink, *pPrev;
  TE_LINK_NEXT_HOP *pTeLinkNextHop;
  uns32 key = 0;

  zlog_info ("entering rdb_del_te_link: TE link ID %x", te_link_id);

  pPrev = pTeLink = TeLinkLListHead;
  while (pTeLink != NULL)
    {
      if (pTeLink->te_link->te_link_id == te_link_id)
	break;
      pPrev = pTeLink;
      pTeLink = pTeLink->next;
    }
  if (pTeLink == NULL)
    {
      return E_ERR;
    }

  if (pPrev == pTeLink)
    {
      TeLinkLListHead = TeLinkLListHead->next;
    }
  else
    {
      pPrev->next = pTeLink->next;
    }
  while ((pTeLinkNextHop =
	  (TE_LINK_NEXT_HOP *) patricia_tree_getnext (&pTeLink->te_link->
						      NeighborsTree,
						      (uns8 *) & key)) !=
	 NULL)
    {
      key = pTeLinkNextHop->neighbor;
      rdb_del_next_hop (pTeLinkNextHop->neighbor,
			pTeLink->te_link->te_link_id);
    }
  delete_te_link (pTeLink->te_link);
  XFREE (MTYPE_TE, pTeLink);
  zlog_info ("leaving rdb_del_te_link");
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_add_next_hop

  DESCRIPTION: The routine associates the TE link with ID - te_link_id with
  the next hop next_hop.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              next_hop - Next Hop's IP address.
              TeLinkId - TE link ID, by which TE link is found and associated.

*****************************************************************************/

uns32
rdb_add_next_hop (IPV4_ADDR next_hop, uns32 TeLinkId)
{
  RDB_NEXT_HOP *next_hop_entry;
  TE_LINK_L_LIST *pPrevTeLink, *pTeLinkLList, *pNew, *pTeLinkLList2;
  TE_LINK_NEXT_HOP *pTeLinkNextHop;

  zlog_info ("entering rdb_add_next_hop: next hop %x TE link ID %x", next_hop,
	     TeLinkId);

  pTeLinkLList = TeLinkLListHead;
  while (pTeLinkLList != NULL)
    {
      if (pTeLinkLList->te_link->te_link_id == TeLinkId)
	break;
      pTeLinkLList = pTeLinkLList->next;
    }
  if (pTeLinkLList == NULL)
    {
      zlog_err ("an error at %s %d", __FILE__, __LINE__);
      return E_ERR;
    }

  if ((pNew =
       (TE_LINK_L_LIST *) XMALLOC (MTYPE_TE,
				   sizeof (TE_LINK_L_LIST))) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  pNew->te_link = pTeLinkLList->te_link;

  if ((pTeLinkNextHop =
       (TE_LINK_NEXT_HOP *) XMALLOC (MTYPE_TE,
				     sizeof (TE_LINK_NEXT_HOP))) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      XFREE (MTYPE_TE, pNew);
      return E_ERR;
    }
  pTeLinkNextHop->neighbor = next_hop;
  pTeLinkNextHop->Node.key_info = (uns8 *) & pTeLinkNextHop->neighbor;
  if (patricia_tree_add (&pNew->te_link->NeighborsTree, &pTeLinkNextHop->Node)
      != E_OK)
    {
      XFREE (MTYPE_TE, pNew);
      XFREE (MTYPE_TE, pTeLinkNextHop);
      zlog_err ("an error at %s %d", __FILE__, __LINE__);
      return E_ERR;
    }

  if ((next_hop_entry =
       (RDB_NEXT_HOP *) patricia_tree_get (&NextHopTree,
					   (const uns8 *) &next_hop)) == NULL)
    {
      if ((next_hop_entry =
	   (RDB_NEXT_HOP *) XMALLOC (MTYPE_TE,
				     sizeof (RDB_NEXT_HOP))) == NULL)
	{
	  zlog_err ("an error at %s %d", __FILE__, __LINE__);
	  XFREE (MTYPE_TE, pNew);
	  return E_ERR;
	}

      next_hop_entry->dest = next_hop;
      next_hop_entry->Node.key_info = (uns8 *) & next_hop_entry->dest;

      next_hop_entry->TELinkLList = pNew;
      next_hop_entry->LListItemsCount = 1;

      if (patricia_tree_add (&NextHopTree, &next_hop_entry->Node) != E_OK)
	{
	  XFREE (MTYPE_TE, next_hop_entry->TELinkLList);
	  XFREE (MTYPE_TE, next_hop_entry);
	  XFREE (MTYPE_TE, pNew);
	  zlog_err ("an error at %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      zlog_info ("leaving rdb_add_next_hop1+");
      return E_OK;
    }
  else
    {
      pTeLinkLList2 = next_hop_entry->TELinkLList;
      pPrevTeLink = pTeLinkLList2;
      while (pTeLinkLList2 != NULL)
	{
	  if (pTeLinkLList2->te_link->te_link_id == TeLinkId)
	    {
	      if (patricia_tree_del
		  (&pNew->te_link->NeighborsTree,
		   &pTeLinkNextHop->Node) != E_OK)
		{
		  zlog_err ("an error at %s %d", __FILE__, __LINE__);
		  return E_ERR;
		}
	      XFREE (MTYPE_TE, pTeLinkNextHop);
	      XFREE (MTYPE_TE, pNew);
	      zlog_info ("leaving rdb_add_next_hop2+");
	      return E_OK;
	    }
	  else if (pTeLinkLList2->te_link->te_link_id > TeLinkId)
	    {
	      if (pTeLinkLList2 == pPrevTeLink)
		{
		  next_hop_entry->TELinkLList = pNew;
		  pNew->next = pTeLinkLList2;
		}
	      else
		{
		  pNew->next = pTeLinkLList2;
		  pPrevTeLink->next = pNew;
		}
	      next_hop_entry->LListItemsCount++;
	      zlog_info ("leaving rdb_add_next_hop3+");
	      return E_OK;
	    }
	  pPrevTeLink = pTeLinkLList2;
	  pTeLinkLList2 = pTeLinkLList2->next;
	}			/* of while */

      /* if this point is reached, TE link is new and should be inserted */
      pPrevTeLink->next = pNew;
      next_hop_entry->LListItemsCount++;
      zlog_info ("leaving rdb_add_next_hop4+");
      return E_OK;
    }
  /* should not be reached */
  zlog_err ("an error at %s %d", __FILE__, __LINE__);
  XFREE (MTYPE_TE, pNew);
  return E_ERR;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_local_link_down

  DESCRIPTION: The routine deletes the association of TE link with ID - TeLinkId with
  it's next hop.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              TeLinkId - TE link ID, by which TE link is found.

*****************************************************************************/

uns32
rdb_local_link_status_change (uns32 TeLinkId, uns8 Status)
{
  TE_LINK_L_LIST *pTeLinkLList;
  zlog_info ("entering rdb_local_link_status_change: TE link ID %x status %x",
	     TeLinkId, Status);
  pTeLinkLList = TeLinkLListHead;
  while (pTeLinkLList != NULL)
    {
      if (pTeLinkLList->te_link->te_link_id == TeLinkId)
	break;
      pTeLinkLList = pTeLinkLList->next;
    }
  if (pTeLinkLList == NULL)
    {
      return E_ERR;
    }

  pTeLinkLList->te_link->Status = Status;
  zlog_info ("leaving rdb_local_link_status_change");
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_del_next_hop

  DESCRIPTION: The routine deletes the next hop next_hop.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              next_hop - Next Hop's IP address.

*****************************************************************************/

uns32
rdb_del_next_hop (IPV4_ADDR next_hop, uns32 te_link_id)
{
  RDB_NEXT_HOP *next_hop_entry;
  TE_LINK_L_LIST *pTeLink, *pTeLinkPrev = NULL;
  TE_LINK_NEXT_HOP *pTeLinkNextHop;

  zlog_info ("entering rdb_del_next_hop: next hop %x TE link ID %x", next_hop,
	     te_link_id);

  if ((next_hop_entry =
       (RDB_NEXT_HOP *) patricia_tree_get (&NextHopTree,
					   (const uns8 *) &next_hop)) == NULL)
    {
      return E_ERR;
    }
  pTeLink = TeLinkLListHead;
  while (pTeLink != NULL)
    {
      if (pTeLink->te_link->te_link_id == te_link_id)
	{
	  break;
	}
      pTeLink = pTeLink->next;
    }
  if (pTeLink != NULL)
    {
      if ((pTeLinkNextHop =
	   (TE_LINK_NEXT_HOP *) patricia_tree_get (&pTeLink->te_link->
						   NeighborsTree,
						   (const uns8 *) &next_hop))
	  != NULL)
	{
	  if (patricia_tree_del
	      (&pTeLink->te_link->NeighborsTree,
	       &pTeLinkNextHop->Node) == E_OK)
	    {
	      XFREE (MTYPE_TE, pTeLinkNextHop);
	    }
	}
    }
  pTeLink = next_hop_entry->TELinkLList;
  while (pTeLink != NULL)
    {
      if (pTeLink->te_link->te_link_id == te_link_id)
	{
	  if (pTeLinkPrev == NULL)
	    {
	      next_hop_entry->TELinkLList = next_hop_entry->TELinkLList->next;
	    }
	  else
	    {
	      pTeLinkPrev->next = pTeLink->next;
	    }
	  XFREE (MTYPE_TE, pTeLink);
	  break;
	}
      pTeLink = pTeLink->next;
    }
  if (next_hop_entry->TELinkLList == NULL)
    {
      if (patricia_tree_del (&NextHopTree, &next_hop_entry->Node) != E_OK)
	{
	  return E_ERR;
	}
      XFREE (MTYPE_TE, next_hop_entry);
    }
  zlog_info ("leaving rdb_del_next_hop");
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_add_mod_summary

  DESCRIPTION: The routine adds the summary advertisement to AS border router asbr_ip.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              asbr_ip - AS border's IP address.
                          *pAbr - pointer to Area Border structure, which contains Area Border's IP
                          and summary attributes to AS border.

*****************************************************************************/
uns32
rdb_add_mod_summary (IPV4_ADDR asbr_ip, ABR * pAbr)
{
  RDB_ABRS *abr_entry;
  ABRS_L_LIST *pAbrsLList, *pAbrsLListPrev, *pNew;

  if ((pNew =
       (ABRS_L_LIST *) XMALLOC (MTYPE_TE, sizeof (ABRS_L_LIST))) == NULL)
    {
      delete_abr (pAbr);
      zlog_err ("\nFatal at %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  pNew->Abr = pAbr;
  pNew->next = NULL;

  if ((abr_entry =
       (RDB_ABRS *) patricia_tree_get (&ASBorderTree,
				       (const uns8 *) &asbr_ip)) == NULL)
    {
      if ((abr_entry =
	   (RDB_ABRS *) XMALLOC (MTYPE_TE, sizeof (RDB_ABRS))) == NULL)
	{
	  delete_abr (pAbr);
	  return E_ERR;
	}

      /* Initialize new ASBR */
      abr_entry->dest = asbr_ip;
      abr_entry->Node.key_info = (uns8 *) & abr_entry->dest;

      abr_entry->LListItemsCount = 1;

      /* Initialize new and first ABR to ASBR */
      abr_entry->AbrsLList = pNew;
      if (patricia_tree_add (&ASBorderTree, &abr_entry->Node) != E_OK)
	{
	  XFREE (MTYPE_TE, abr_entry->AbrsLList);
	  XFREE (MTYPE_TE, abr_entry);
	  XFREE (MTYPE_TE, pNew);
	  return E_ERR;
	}
      return E_OK;
    }
  /* There is such ASBR */
  else
    {
      if ((pAbrsLList = abr_entry->AbrsLList) == NULL)
	{
	  patricia_tree_del (&ASBorderTree, &abr_entry->Node);
	  XFREE (MTYPE_TE, abr_entry);
	  XFREE (MTYPE_TE, pNew);
	  zlog_err ("\nFatal at %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      /* Lookup for the ABR in ABR's Linked List  */
      pAbrsLListPrev = pAbrsLList;
      while (pAbrsLList != NULL)
	{
	  /* if summaries are equal */
	  if (pAbrsLList->Abr->AbrIpAddr == pAbr->AbrIpAddr)
	    {
	      /* free the unneeded memory */
	      delete_abr (pAbrsLList->Abr);
	      pAbrsLList->Abr = pAbr;
	      XFREE (MTYPE_TE, pNew);
	      return E_OK;
	    }			/* if this is the ABR ? */
	  else if (pAbrsLList->Abr->AbrIpAddr > pAbr->AbrIpAddr)
	    {
	      /* insert to the head */
	      if (pAbrsLList == abr_entry->AbrsLList)
		{
		  pNew->next = abr_entry->AbrsLList;
		  abr_entry->AbrsLList = pNew;
		}
	      /* insert to the middle */
	      else
		{
		  pAbrsLListPrev->next = pNew;
		  pNew->next = pAbrsLList;
		}
	      abr_entry->LListItemsCount++;
	      return E_OK;
	    }
	  pAbrsLListPrev = pAbrsLList;
	  pAbrsLList = pAbrsLList->next;
	}			/* while pAbrsLList != NULL */

      /* If this point is reached, ABR should be inserted to the ABR's list */
      pAbrsLListPrev->next = pNew;
      pNew->next = pAbrsLList;
      abr_entry->LListItemsCount++;
      return E_OK;
    }
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_delete_asbr

  DESCRIPTION: When Area Border abr_ip does not longer advertise the reachability
  information to AS border asbr_ip, the Area Border's summary to the AS border
  is deleted.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              asbr_ip - AS border's IP address.
                          abr_ip - Area border's IP address.

*****************************************************************************/
uns32
rdb_delete_asbr (IPV4_ADDR asbr_ip, IPV4_ADDR abr_ip)
{
  RDB_ABRS *abr_entry;
  ABRS_L_LIST *pAbrsLList, *pAbrsLListPrev = NULL;

  if ((abr_entry = (RDB_ABRS *) patricia_tree_get (&ASBorderTree,
						   (const uns8 *) &asbr_ip))
      == NULL)
    {
      return E_ERR;
    }
  else
    {
      pAbrsLList = abr_entry->AbrsLList;
      while (pAbrsLList != NULL)
	{
	  if (pAbrsLList->Abr->AbrIpAddr == abr_ip)
	    {
	      delete_abr (pAbrsLList->Abr);

	      if (abr_entry->AbrsLList == pAbrsLList)
		{
		  abr_entry->AbrsLList = abr_entry->AbrsLList->next;
		  XFREE (MTYPE_TE, pAbrsLList);
		  abr_entry->LListItemsCount--;
		  if (abr_entry->AbrsLList == NULL)
		    {
		      if (patricia_tree_del (&ASBorderTree, &abr_entry->Node)
			  != E_OK)
			{
			  return E_ERR;
			}
		      XFREE (MTYPE_TE, abr_entry);
		    }
		}
	      else
		{
		  pAbrsLListPrev->next = pAbrsLList->next;
		  abr_entry->LListItemsCount--;
		  XFREE (MTYPE_TE, pAbrsLList);

		}
	      return E_OK;
	    }
	  else
	    {
	      pAbrsLListPrev = pAbrsLList;
	      pAbrsLList = pAbrsLList->next;
	    }
	}
    }
  return E_ERR;
}


/*****************************************************************************

  PROCEDURE NAME:    rdb_create_static_path

  DESCRIPTION: Adds a new path *pPath to destination dest_ip.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              dest_ip - Path destination's IP address.
                          *pPath - pointer to the path description (path's summary propertieslist of hops
                          and hops' properties).

*****************************************************************************/
uns32
rdb_create_static_path (char *StaticPathName)
{
  STATIC_PATH *pStaticPath;

  if (rdb_get_static_path (StaticPathName, &pStaticPath) == E_OK)
    {
      zlog_err ("Static path with the name %s already exists %s %d",
		StaticPathName, __FILE__, __LINE__);
      return E_ERR;
    }

  if ((pStaticPath =
       (STATIC_PATH *) XMALLOC (MTYPE_TE, sizeof (STATIC_PATH))) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  memset (pStaticPath, 0, sizeof (STATIC_PATH));
  strcpy (pStaticPath->PathName, StaticPathName);

  if (StaticPathHead == NULL)
    {
      StaticPathHead = pStaticPath;
      StaticPathHead->next = NULL;
    }
  else
    {
      pStaticPath->next = StaticPathHead;
      StaticPathHead = pStaticPath;
    }
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_delete_static_path

  DESCRIPTION: Adds a new path *pPath to destination dest_ip.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              dest_ip - Path destination's IP address.
                          *pPath - pointer to the path description (path's summary propertieslist of hops
                          and hops' properties).

*****************************************************************************/
uns32
rdb_delete_static_path (char *StaticPathName)
{
  IPV4_HOP *HopsList, *HopsListNext;
  STATIC_PATH *pTemp = StaticPathHead, *pPrev = NULL;

  while (pTemp != NULL)
    {
      if (strcmp (pTemp->PathName, StaticPathName) == 0)
	{
	  HopsList = pTemp->HopList;
	  while (HopsList != NULL)
	    {
	      HopsListNext = HopsList->next;
	      XFREE (MTYPE_TE, HopsList);
	      HopsList = HopsListNext;
	    }
	  if (pPrev == NULL)
	    {
	      StaticPathHead = StaticPathHead->next;
	    }
	  else
	    {
	      pPrev->next = pTemp->next;
	    }
	  XFREE (MTYPE_TE, pTemp);
	  return E_OK;
	}
      pPrev = pTemp;
      pTemp = pTemp->next;
    }
  return E_ERR;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_get_static_path

  DESCRIPTION: Adds a new path *pPath to destination dest_ip.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              dest_ip - Path destination's IP address.
                          *pPath - pointer to the path description (path's summary propertieslist of hops
                          and hops' properties).

*****************************************************************************/
uns32
rdb_get_static_path (char *pName, STATIC_PATH ** ppStaticPath)
{
  if (StaticPathHead == NULL)
    {
      *ppStaticPath = NULL;
    }
  else
    {
      STATIC_PATH *pTemp = StaticPathHead;
      while (pTemp != NULL)
	{
	  if (strcmp (pTemp->PathName, pName) == 0)
	    {
	      *ppStaticPath = pTemp;
	      return E_OK;
	    }
	  pTemp = pTemp->next;
	}
    }
  return E_ERR;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_static_path_add_hop

  DESCRIPTION: Adds a new path *pPath to destination dest_ip.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              dest_ip - Path destination's IP address.
                          *pPath - pointer to the path description (path's summary propertieslist of hops
                          and hops' properties).

*****************************************************************************/
uns32
rdb_static_path_add_hop (char *StaticPathName, IPV4_ADDR IpAddr, int Loose)
{
  STATIC_PATH *pStaticPath;
  IPV4_HOP *HopsList, *HopsListNew;

  if (rdb_get_static_path (StaticPathName, &pStaticPath) != E_OK)
    {
      zlog_err ("Cannot find a path with name %s %s %d", StaticPathName,
		__FILE__, __LINE__);
      return E_ERR;
    }
  if ((HopsListNew =
       (IPV4_HOP *) XMALLOC (MTYPE_TE, sizeof (IPV4_HOP))) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  memset (HopsListNew, 0, sizeof (IPV4_HOP));
  HopsListNew->IpAddr = IpAddr;
  HopsListNew->Loose = Loose;
  if (pStaticPath->HopList == NULL)
    {
      pStaticPath->HopList = HopsListNew;
    }
  else
    {
      HopsList = pStaticPath->HopList;
      while (HopsList->next != NULL)
	HopsList = HopsList->next;
      HopsList->next = HopsListNew;
    }
  pStaticPath->HopCount++;
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_static_path_add_hop_by_index

  DESCRIPTION: Adds a new path *pPath to destination dest_ip.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              dest_ip - Path destination's IP address.
                          *pPath - pointer to the path description (path's summary propertieslist of hops
                          and hops' properties).

*****************************************************************************/
uns32
rdb_static_path_add_hop_by_index (char *StaticPathName, IPV4_ADDR IpAddr,
				  int Loose, int index)
{
  STATIC_PATH *pStaticPath;
  IPV4_HOP *HopsList, *HopsListNew, *HopsListPrev = NULL;
  int i = 0;

  if (index == 0)
    {
      zlog_err ("invalid parameter (index == 0) %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  index--;
  if (rdb_get_static_path (StaticPathName, &pStaticPath) != E_OK)
    {
      zlog_err ("Cannot find a path %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  zlog_info ("Index %d", index);
  HopsList = pStaticPath->HopList;
  while ((HopsList != NULL) && (i < index))
    {
      HopsListPrev = HopsList;
      HopsList = HopsList->next;
      i++;
    }
  if (i != index)
    {
      zlog_err ("There is no such index %d %s %d", index, __FILE__, __LINE__);
      return E_ERR;
    }

  if (HopsList)
    {
      HopsList->IpAddr = IpAddr;
      HopsList->Loose = Loose;
    }
  else
    {
      if ((HopsListNew =
	   (IPV4_HOP *) XMALLOC (MTYPE_TE, sizeof (IPV4_HOP))) == NULL)
	{
	  zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      memset (HopsListNew, 0, sizeof (IPV4_HOP));
      HopsListNew->IpAddr = IpAddr;
      HopsListNew->Loose = Loose;
      if (HopsListPrev == NULL)
	{
	  pStaticPath->HopList = HopsListNew;
	}
      else
	{
	  HopsListPrev->next = HopsListNew;
	  HopsListNew = HopsList;
	}
      pStaticPath->HopCount++;
    }
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_static_path_add_hop_after_index

  DESCRIPTION: Adds a new path *pPath to destination dest_ip.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              dest_ip - Path destination's IP address.
                          *pPath - pointer to the path description (path's summary propertieslist of hops
                          and hops' properties).

*****************************************************************************/
uns32
rdb_static_path_add_hop_after_index (char *StaticPathName, IPV4_ADDR IpAddr,
				     int Loose, int index)
{
  STATIC_PATH *pStaticPath;
  IPV4_HOP *HopsList, *HopsListNew, *HopsListPrev = NULL;
  int i = 0;

  if (index == 0)
    {
      zlog_err ("invalid parameter (index == 0) %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  zlog_info ("Index %d", index);
  if (rdb_get_static_path (StaticPathName, &pStaticPath) != E_OK)
    {
      zlog_err ("Cannot find a path %s %d", __FILE__, __LINE__);
      return E_ERR;
    }

  HopsList = pStaticPath->HopList;
  while ((HopsList != NULL) && (i < index))
    {
      HopsListPrev = HopsList;
      HopsList = HopsList->next;
      i++;
    }
  if (i != index)
    {
      zlog_err ("There is no such index %d %s %d", index, __FILE__, __LINE__);
      return E_ERR;
    }

  if ((HopsListNew =
       (IPV4_HOP *) XMALLOC (MTYPE_TE, sizeof (IPV4_HOP))) == NULL)
    {
      zlog_err ("Cannot allocate memory %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  memset (HopsListNew, 0, sizeof (IPV4_HOP));
  HopsListNew->IpAddr = IpAddr;
  HopsListNew->Loose = Loose;
  HopsListPrev->next = HopsListNew;
  HopsListNew->next = HopsList;
  pStaticPath->HopCount++;
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_static_path_del_hop

  DESCRIPTION: Adds a new path *pPath to destination dest_ip.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              dest_ip - Path destination's IP address.
                          *pPath - pointer to the path description (path's summary propertieslist of hops
                          and hops' properties).

*****************************************************************************/
uns32
rdb_static_path_del_hop (char *StaticPathName, IPV4_ADDR IpAddr)
{
  STATIC_PATH *pStaticPath;
  IPV4_HOP *HopsList, *HopsListPrev = NULL;

  if (rdb_get_static_path (StaticPathName, &pStaticPath) != E_OK)
    {
      zlog_err ("Cannot find a path %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  HopsList = pStaticPath->HopList;
  while (HopsList != NULL)
    {
      if (HopsList->IpAddr == IpAddr)
	break;
      HopsListPrev = HopsList;
      HopsList = HopsList->next;
    }

  if (HopsList == NULL)
    {
      zlog_err ("Hop %x is not found %s %d", IpAddr, __FILE__, __LINE__);
      return E_ERR;
    }

  if (HopsListPrev == NULL)
    {
      pStaticPath->HopList = pStaticPath->HopList->next;
    }
  else
    {
      HopsListPrev->next = HopsList->next;
    }
  XFREE (MTYPE_TE, HopsList);
  pStaticPath->HopCount--;
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_static_path_del_hop_by_index

  DESCRIPTION: Adds a new path *pPath to destination dest_ip.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              dest_ip - Path destination's IP address.
                          *pPath - pointer to the path description (path's summary propertieslist of hops
                          and hops' properties).

*****************************************************************************/
uns32
rdb_static_path_del_hop_by_index (char *StaticPathName, int index)
{
  STATIC_PATH *pStaticPath;
  IPV4_HOP *HopsList, *HopsListPrev = NULL;
  int i = 0;

  if (index == 0)
    {
      zlog_err ("invalid parameter (index == 0) %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  index--;
  if (rdb_get_static_path (StaticPathName, &pStaticPath) != E_OK)
    {
      zlog_err ("Cannot find a path %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  zlog_info ("Index %d", index);
  HopsList = pStaticPath->HopList;
  while ((HopsList != NULL) && (i < index))
    {
      HopsListPrev = HopsList;
      HopsList = HopsList->next;
      i++;
    }
  if (i != index)
    {
      zlog_err ("There is no such index %d %s %d", index, __FILE__, __LINE__);
      return E_ERR;
    }
  if (HopsListPrev == NULL)
    {
      pStaticPath->HopList = pStaticPath->HopList->next;
    }
  else
    {
      HopsListPrev->next = HopsList->next;
    }
  XFREE (MTYPE_TE, HopsList);
  pStaticPath->HopCount--;
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_add_mod_path

  DESCRIPTION: Adds a new path *pPath to destination dest_ip.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              dest_ip - Path destination's IP address.
                          *pPath - pointer to the path description (path's summary propertieslist of hops
                          and hops' properties).

*****************************************************************************/
uns32
rdb_add_mod_path (IPV4_ADDR dest_ip, PATH * pPath)
{
  RDB_PATH *path_entry;
  PATH_L_LIST *pPathLList, *pPathLListPrev, *pErHopPathList;

  PATH_L_LIST *pNewPath;
  TE_HOP *pKxErHop;
  ER_HOP_L_LIST *pKxErHopsLList;
  TE_HOP *pErHops, *pErHops2Free;
  link_key_t link_key;
  int i, j;


  if ((pPath->PathProperties.PathType <= EMPTY_PATH)
      || (pPath->PathProperties.PathType >= MAX_PATH_TYPE))
    {
      zlog_err ("Invalid path type %d", pPath->PathProperties.PathType);
      return E_ERR;
    }

  if ((pNewPath =
       (PATH_L_LIST *) XMALLOC (MTYPE_TE, sizeof (PATH_L_LIST))) == NULL)
    {
      XFREE (MTYPE_TE, pPath->u.er_hops);
      XFREE (MTYPE_TE, pPath);
      zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  pNewPath->pPath = pPath;
  pNewPath->next = NULL;

  if ((path_entry =
       (RDB_PATH *) patricia_tree_get (&AreaBorderTree,
				       (const uns8 *) &dest_ip)) == NULL)
    {
      if ((path_entry =
	   (RDB_PATH *) XMALLOC (MTYPE_TE, sizeof (RDB_PATH))) == NULL)
	{
	  XFREE (MTYPE_TE, pNewPath);
	  zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      /* Initialize new ABR */
      path_entry->dest = dest_ip;
      path_entry->Node.key_info = (uns8 *) & path_entry->dest;
      path_entry->PathLList = pNewPath;

      path_entry->LListItemsCount = 1;

      if (patricia_tree_add (&AreaBorderTree, &path_entry->Node) != E_OK)
	{
	  XFREE (MTYPE_TE, path_entry);
	  XFREE (MTYPE_TE, pNewPath);
	  XFREE (MTYPE_TE, pPath->u.er_hops);
	  XFREE (MTYPE_TE, pPath);
	  zlog_err ("cannot add node to patricia %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
    }
  /* There is no such ABR */
  else
    {
      /* Initialize new Path to ABR */
      if ((pPathLList = path_entry->PathLList) == NULL)
	{
	  patricia_tree_del (&AreaBorderTree, &path_entry->Node);
	  XFREE (MTYPE_TE, path_entry);
	  XFREE (MTYPE_TE, pNewPath);
	  XFREE (MTYPE_TE, pPath->u.er_hops);
	  XFREE (MTYPE_TE, pPath);
	  zlog_err ("Fatal at %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      /* Lookup for the Path in Path's Linked List  */
      pPathLListPrev = pPathLList;
      while (pPathLList != NULL)
	{
	  /* if path vectors are equal */
	  if ((pPathLList->pPath->PathProperties.PathType ==
	       pPath->PathProperties.PathType)
	      && (pPathLList->pPath->PathProperties.PathHopCount ==
		  pPath->PathProperties.PathHopCount)
	      &&
	      (compare_er_hops
	       (pPathLList->pPath->u.er_hops_l_list, pPath->u.er_hops,
		pPath->PathProperties.PathHopCount) == TRUE))
	    {
	      /* if path properties are equal, nothing to do */
	      memcpy (&pPathLList->pPath->PathProperties,
		      &pPath->PathProperties, sizeof (PATH_PROPERTIES));

	      pErHops = pPath->u.er_hops;

	      for (i = 0; i < pPath->PathProperties.PathHopCount;
		   i++, pErHops++)
		{
		  LINK_PROPERTIES link_prop;

		  memset (&link_prop, 0, sizeof (link_prop));

		  link_prop.LinkType = PSC_PATH;
		  link_prop.LinkMaxLspBW = pErHops->MaxLspBW;
		  link_prop.LinkMaxReservableBW = pErHops->MaxReservableBW;
		  link_prop.LinkTeMetric = pErHops->te_metric;
		  for (j = 0; j < 8; j++)
		    {
		      link_prop.LinkReservableBW[j] =
			pErHops->ReservableBW[j];
		    }
		  link_prop.LinkColorMask = pErHops->ColorMask;
		  rdb_link_state_update (pErHops->local_ip,
					 pErHops->remote_ip, &link_prop);
		}
	      XFREE (MTYPE_TE, pPath->u.er_hops);
	      XFREE (MTYPE_TE, pPath);
	      XFREE (MTYPE_TE, pNewPath);
	      zlog_info ("paths are equal %s %d", __FILE__, __LINE__);
	      return E_OK;
	    }			/* if er hops equal */
	  pPathLListPrev = pPathLList;
	  pPathLList = pPathLList->next;
	}			/* while */

      /* If this point is reached, path should be inserted to the path list */
      /* insert to the head */
      pNewPath->next = path_entry->PathLList;
      path_entry->PathLList = pNewPath;
      path_entry->LListItemsCount++;
    }				/* ABR already exists */

  /* now, check for existence of links to remote links and set if required */
  pErHops2Free = pPath->u.er_hops;	/* to free after the loop */

  pErHops = pPath->u.er_hops;

  pNewPath->pPath->u.er_hops_l_list = pKxErHopsLList = NULL;

  for (i = 0; i < pPath->PathProperties.PathHopCount; i++, pErHops++)
    {
      link_key.local_ip = pErHops->local_ip;
      link_key.remote_ip = pErHops->remote_ip;

      if ((pErHopPathList =
	   (PATH_L_LIST *) XMALLOC (MTYPE_TE, sizeof (PATH_L_LIST))) == NULL)
	{
	  zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pErHopPathList->pPath = pPath;

      if ((pKxErHop =
	   (TE_HOP *)
	   patricia_tree_get (&
			      (RemoteLinkTree
			       [pPath->PathProperties.PathType - 1]),
			      (const uns8 *) &link_key)) == NULL)
	{
	  if ((pKxErHop =
	       (TE_HOP *) XMALLOC (MTYPE_TE, sizeof (TE_HOP))) == NULL)
	    {
	      zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }

	  pKxErHop->pPathList = pErHopPathList;
	  pKxErHop->pPathList->next = NULL;
	  pKxErHop->local_ip = link_key.local_ip;
	  pKxErHop->remote_ip = link_key.remote_ip;
	  pKxErHop->MaxLspBW = pErHops->MaxLspBW;
	  pKxErHop->MaxReservableBW = pErHops->MaxReservableBW;
	  for (j = 0; j < 8; j++)
	    pKxErHop->ReservableBW[j] = pErHops->ReservableBW[j];
	  pKxErHop->te_metric = pErHops->te_metric;
	  pKxErHop->ColorMask = pErHops->ColorMask;

	  pKxErHop->Node.key_info = (uns8 *) & pKxErHop->local_ip;
	  zlog_info
	    ("Creation of new remote link: local %x remote %x MaxBw %f MaxResBw %f %x",
	     pKxErHop->local_ip, pKxErHop->remote_ip, pKxErHop->MaxLspBW,
	     pKxErHop->MaxReservableBW, pKxErHop->te_metric);
	  if (patricia_tree_add
	      (&(RemoteLinkTree[pPath->PathProperties.PathType - 1]),
	       &pKxErHop->Node) != E_OK)
	    {
	      zlog_err ("cannot add node to patricia %s %d", __FILE__,
			__LINE__);
	      return E_ERR;
	    }
	}
      else
	{
	  pErHopPathList->next = pKxErHop->pPathList;
	  pKxErHop->pPathList = pErHopPathList;
	}

      if (pNewPath->pPath->u.er_hops_l_list == NULL)
	{
	  if ((pKxErHopsLList =
	       (ER_HOP_L_LIST *) XMALLOC (MTYPE_TE,
					  sizeof (ER_HOP_L_LIST))) == NULL)
	    {
	      zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }
	  pNewPath->pPath->u.er_hops_l_list = pKxErHopsLList;
	}
      else
	{
	  if ((pKxErHopsLList->next =
	       (ER_HOP_L_LIST *) XMALLOC (MTYPE_TE,
					  sizeof (ER_HOP_L_LIST))) == NULL)
	    {
	      zlog_err ("malloc failed %s %d", __FILE__, __LINE__);
	      return E_ERR;
	    }
	  pKxErHopsLList = pKxErHopsLList->next;
	}

      pKxErHopsLList->next = NULL;

      pKxErHopsLList->er_hop = pKxErHop;
    }

  XFREE (MTYPE_TE, pErHops2Free);

  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_connectivity_broken

  DESCRIPTION: When IGP receives a Link Advertisement (LSA or LSP), which says there is no
  connectivity from the node from_node to the node to_node for path type path_type (packet switch,
  lambda switch, fiber switch, TDM switch), such path is deleted.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              from_node - IP address of the node, from which connectivity is broken.
                          to_node - IP address of the node, to which connectivity is broken.
                          path_type - connectivity of which type is broken.
                          
  IMPORTANT NOTE: This API is not intended for indication of own link failures.

*****************************************************************************/

uns32
rdb_connectivity_broken (IPV4_ADDR from_node, IPV4_ADDR to_node,
			 PATH_TYPE path_type)
{
  RDB_PATH *path_entry;
  TE_HOP *pKxErHop;
  link_key_t link_key;
  PATH *pPath, *pSavedPath;

  if ((path_type <= EMPTY_PATH) || (path_type >= MAX_PATH_TYPE))
    return E_ERR;
  link_key.local_ip = from_node;
  link_key.remote_ip = to_node;

  /* first, find the remote link */
  if ((pKxErHop =
       (TE_HOP *) patricia_tree_get (&(RemoteLinkTree[path_type - 1]),
				     (const uns8 *) &link_key)) != NULL)
    {
      PATH_L_LIST *pPathList, *pPathListNext, *pPathList2, *pPathListPrev2;
      zlog_info ("connectivity broken event upon reception of TE LSA: %x %x",
		 from_node, to_node);
      pPathList = pKxErHop->pPathList;
      /* for each path, passing through this remote link */
      while (pPathList != NULL)
	{
	  pPathListNext = pPathList->next;
	  pSavedPath = pPathList->pPath;
	  /* find path's destination */
	  zlog_info ("Path's destination %x", pPathList->pPath->destination);
	  if ((path_entry = (RDB_PATH *) patricia_tree_get (&AreaBorderTree,
							    (const uns8 *)
							    &pPathList->
							    pPath->
							    destination)) !=
	      NULL)
	    {
	      zlog_info
		("Delete path from the list, hold by destination entry");
	      pPathListPrev2 = pPathList2 = path_entry->PathLList;
	      /* find the path in the path destination's path list */
	      while (pPathList2 != NULL)
		{
		  /* path is found ? */
		  if (pPathList2->pPath == pPathList->pPath)
		    {
		      zlog_info ("path found on the destination's list ...");
		      /* extract the path from the path destination's path list
		         without freing the memory */
		      if (pPathList2 == pPathListPrev2)
			path_entry->PathLList = path_entry->PathLList->next;
		      else
			pPathListPrev2->next = pPathList2->next;

		      path_entry->LListItemsCount--;
		      /* if ocausionally, path destination's path list became empty, 
		         delete the destination from the patricia tree 
		         and free the destination's memory */
		      if (path_entry->PathLList == NULL)
			{
			  patricia_tree_del (&AreaBorderTree,
					     &path_entry->Node);
			  XFREE (MTYPE_TE, path_entry);
			}
		      /* free the destination's path list item memory */
		      XFREE (MTYPE_TE, pPathList2);
		      break;
		    }		/* path found on the path's destination's path list */
		  pPathListPrev2 = pPathList2;
		  pPathList2 = pPathList2->next;
		}		/* of while (through the path list of path's destination */
	    }
	  /* now, the memory of the remote link's path list item and 
	     path's itself memory remain. Check if path references remote links,
	     which are referenced by this path only. If such links are discovered,
	     remove them. */
	  zlog_info ("now, delete the path from the lists, hold by TE links");

	  pPath = pPathList->pPath;
	  while (pPath->u.er_hops_l_list != NULL)
	    {
	      ER_HOP_L_LIST *pTemp = pPath->u.er_hops_l_list->next;
	      if (pPath->u.er_hops_l_list->er_hop != NULL)
		{
		  pPathListPrev2 = pPathList2 =
		    pPath->u.er_hops_l_list->er_hop->pPathList;
		  while (pPathList2 != NULL)
		    {
		      if (pPathList2->pPath == pPath)
			{
			  if (pPathListPrev2 == pPathList2)
			    {
			      pPath->u.er_hops_l_list->er_hop->pPathList =
				pPath->u.er_hops_l_list->er_hop->pPathList->
				next;
			    }
			  else
			    {
			      pPathListPrev2->next = pPathList2->next;
			    }
			  XFREE (MTYPE_TE, pPathList2);
			  break;
			}
		      pPathListPrev2 = pPathList2;
		      pPathList2 = pPathList2->next;
		    }
		}
	      if (pPath->u.er_hops_l_list->er_hop->pPathList == NULL)
		{
		  zlog_info
		    ("All paths, passed through the TE link are removed from the path list of this TE link %x %x",
		     pPath->u.er_hops_l_list->er_hop->local_ip,
		     pPath->u.er_hops_l_list->er_hop->remote_ip);
		  patricia_tree_del (&(RemoteLinkTree[0]),
				     &pPath->u.er_hops_l_list->er_hop->Node);
		  XFREE (MTYPE_TE, pPath->u.er_hops_l_list->er_hop);
		}
	      XFREE (MTYPE_TE, pPath->u.er_hops_l_list);
	      pPath->u.er_hops_l_list = pTemp;
	    }


	  zlog_info ("all er hop list items cleaned. delete the path");

	  XFREE (MTYPE_TE, pSavedPath);

	  pPathList = pPathListNext;
	}
    }
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_link_state_update

  DESCRIPTION: When IGP receives a Link Advertisement (LSA or LSP), which says that TE link properties
  are updated, this routine is called to update paths' properties for each path, pass the pair
  from_node->to_node.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              from_node - Local IP address of the TE link.
                          to_node - Remote IP address of the TE link.
                          path_type - TE link type (there may be TE links of different packet switch capacity between
                          the two nodes).
                          
  IMPORTANT NOTE: The IGP instance may aggregate the two or more TE links between the same nodes as well
  as some node aggregates the component links into one TE link. The conditions are: same IGP and TE 
  costs of the TE links.
  This routine is for Link State Updates of remote links only.

*****************************************************************************/

uns32
rdb_link_state_update (IPV4_ADDR from_node, IPV4_ADDR to_node,
		       LINK_PROPERTIES * pLinkProperties)
{
  TE_HOP *pKxErHop;
  link_key_t link_key;
  int i, recalculate = 0;
  float PathReservableBW[8], PathMaxLspBW, PathMaxReservableBW, delta;
  int ColorMask, j;

  if ((pLinkProperties->LinkType <= EMPTY_PATH)
      || (pLinkProperties->LinkType >= MAX_PATH_TYPE))
    return E_ERR;
  link_key.local_ip = from_node;
  link_key.remote_ip = to_node;

  /* first, find the remote link */
  if ((pKxErHop =
       (TE_HOP *)
       patricia_tree_get (&(RemoteLinkTree[pLinkProperties->LinkType - 1]),
			  (const uns8 *) &link_key)) != NULL)
    {
      PATH_L_LIST *pPathList;

      pPathList = pKxErHop->pPathList;
      zlog_info ("Path Cash update upon updated TE LSA %x %x", from_node,
		 to_node);
      /* for each path, passes over this remote link */
      while (pPathList != NULL)
	{
	  PATH *pPath;
	  PATH_PROPERTIES *pProperties = &(pPathList->pPath->PathProperties);
	  ER_HOP_L_LIST *pErHopLList;

	  recalculate = 0;

	  if (pLinkProperties->LinkMaxLspBW <= pProperties->PathMaxLspBW)
	    pProperties->PathMaxLspBW = pLinkProperties->LinkMaxLspBW;
	  else
	    recalculate = 1;

	  if (pLinkProperties->LinkMaxReservableBW <=
	      pProperties->PathMaxReservableBW)
	    pProperties->PathMaxReservableBW =
	      pLinkProperties->LinkMaxReservableBW;
	  else
	    recalculate = 1;

	  for (j = 0; j < 8; j++)
	    {
	      if (pLinkProperties->LinkReservableBW[j] <=
		  pProperties->PathReservableBW[j])
		pProperties->PathReservableBW[j] =
		  pLinkProperties->LinkReservableBW[j];
	      else
		{
		  recalculate = 1;
		  break;
		}
	    }

	  if (pKxErHop->ColorMask != pLinkProperties->LinkColorMask)
	    recalculate = 1;

	  delta = pKxErHop->te_metric - pLinkProperties->LinkTeMetric;
	  pProperties->PathSumTeMetric -= delta;

	  pPath = pPathList->pPath;
	  pErHopLList = pPath->u.er_hops_l_list;

	  if (recalculate)
	    {
	      for (j = 0; j < 8; j++)
		PathReservableBW[j] = pLinkProperties->LinkReservableBW[j];
	      PathMaxLspBW = pLinkProperties->LinkMaxLspBW;
	      PathMaxReservableBW = pLinkProperties->LinkMaxReservableBW;
	      ColorMask = pLinkProperties->LinkColorMask;
	      for (i = 0; i < pPath->PathProperties.PathHopCount; i++)
		{
		  if (pErHopLList->er_hop != pKxErHop)
		    {
		      if (pErHopLList->er_hop->MaxLspBW < PathMaxLspBW)
			PathMaxLspBW = pErHopLList->er_hop->MaxLspBW;
		      if (pErHopLList->er_hop->MaxReservableBW <
			  PathMaxReservableBW)
			PathMaxReservableBW =
			  pErHopLList->er_hop->MaxReservableBW;
		      for (j = 0; j < 8; j++)
			if (pErHopLList->er_hop->ReservableBW[j] <
			    PathReservableBW[j])
			  PathReservableBW[j] =
			    pErHopLList->er_hop->ReservableBW[j];
		      ColorMask |= pErHopLList->er_hop->ColorMask;
		    }
		  pErHopLList = pErHopLList->next;
		}
	      pProperties->PathColorMask = ColorMask;
	      pProperties->PathMaxLspBW = PathMaxLspBW;
	      pProperties->PathMaxReservableBW = PathMaxReservableBW;
	      for (j = 0; j < 8; j++)
		pProperties->PathReservableBW[j] = PathReservableBW[j];
	    }

	  pPathList = pPathList->next;
	}

      pKxErHop->ColorMask = pLinkProperties->LinkColorMask;
      pKxErHop->MaxLspBW = pLinkProperties->LinkMaxLspBW;
      pKxErHop->MaxReservableBW = pLinkProperties->LinkMaxReservableBW;
      for (j = 0; j < 8; j++)
	pKxErHop->ReservableBW[j] = pLinkProperties->LinkReservableBW[j];
      pKxErHop->te_metric = pLinkProperties->LinkTeMetric;
    }
  else
    {
//        zlog_info("Link %x %x is not in the TE DB",from_node,to_node);
    }
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_remote_link_bw_update

  DESCRIPTION: When new RSVP LSP is created, if BW is expected to be allocated (according to rules - RSVP styles),
  this routine must be called to maintain the path cash.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              from_node - Local IP address of the TE link.
                          to_node - Remote IP address of the TE link.
                          BW2Decrease - BW to be subtrackted from the remote link's reservable BW.
              LinkSwitchCap - link's switching capability.
              
  IMPORTANT NOTE: This routine should be called on the case when BW is to be decreased only and
   not in the case, when BW is to be increased - we wait for IGP's update.
                          
*****************************************************************************/

uns32
rdb_remote_link_bw_update (IPV4_ADDR from_node,
			   IPV4_ADDR to_node,
			   float BW2Decrease,
			   uns8 Priority, PATH_TYPE LinkSwitchCap)
{
  TE_HOP *pKxErHop;
  link_key_t link_key;
  int i, recalculate = 0;
  float PathMaxReservableBW, HopMaxReservableBW;

  link_key.local_ip = from_node;
  link_key.remote_ip = to_node;

  /* first, find the remote link */
  if ((pKxErHop =
       (TE_HOP *) patricia_tree_get (&(RemoteLinkTree[LinkSwitchCap - 1]),
				     (const uns8 *) &link_key)) != NULL)
    {
      PATH_L_LIST *pPathList;

      pPathList = pKxErHop->pPathList;

      if ((BW2Decrease > pKxErHop->ReservableBW[Priority]) ||
	  (BW2Decrease > pKxErHop->MaxLspBW))
	{
	  zlog_err
	    ("\nBW to decrease is larger than MaxLspBW or Reservable BW %s %d",
	     __FILE__, __LINE__);
	  return E_ERR;
	}
      for (i = Priority; i < 8; i++)
	{
	  if (pKxErHop->ReservableBW[i] >= BW2Decrease)
	    {
	      /*zlog_info("\nDecreasing %x BW from %x %x with %x BW",BW2Decrease,pKxErHop->local_ip,pKxErHop->remote_ip,pKxErHop->ReservableBW[i]); */
	      pKxErHop->ReservableBW[i] -= BW2Decrease;	/* what with MaxLspBW ? -:) */
	    }
	  else
	    pKxErHop->ReservableBW[i] = 0;
	}
      HopMaxReservableBW = 0;
      for (i = 0; i < 8; i++)
	{
	  if (pKxErHop->ReservableBW[i] > HopMaxReservableBW)
	    HopMaxReservableBW = pKxErHop->ReservableBW[i];
	}
      pKxErHop->MaxReservableBW = HopMaxReservableBW;

      {
#if 0
	REMOTE_BW_UPDATE_REQUEST *pRemoteBwUpdateReq;
	struct zapi_te_remote_link link;
	memset(&link, 0, sizeof(struct zapi_te_remote_link));

	rdb_remote_link_router_id_get (pKxErHop->local_ip,
				       &link.routerid.s_addr);
	link.from_node.s_addr = pKxErHop->local_ip;
	link.to_node.s_addr = pKxErHop->remote_ip;
	for (i = 0; i < 8; i++)
	  link.reservable_bw[i] = pKxErHop->ReservableBW[i];
	zapi_te_remote_link_update(zclient, &link);
#endif
      }

      /* for each path, passes over this remote link */
      while (pPathList != NULL)
	{
	  PATH_PROPERTIES *pProperties = &(pPathList->pPath->PathProperties);
	  recalculate = 0;

	  if (BW2Decrease > pProperties->PathReservableBW[Priority])
	    {
	      zlog_info
		("\nBW to decrease is larger than MaxLspBW or Reservable BW %s %d",
		 __FILE__, __LINE__);
	      pPathList = pPathList->next;
	      continue;
	    }
	  for (i = Priority; i < 8; i++)
	    {
	      if (pKxErHop->ReservableBW[i] <
		  pProperties->PathReservableBW[i])
		{
		  /*zlog_info("\nForcing path BW to %x (prev - %x BW) Path's dest %x",pKxErHop->ReservableBW[i],pProperties->PathReservableBW[i],pPathList->pPath->destination); */
		  pProperties->PathReservableBW[i] =
		    pKxErHop->ReservableBW[i];
		}
	    }
	  PathMaxReservableBW = 0;
	  for (i = 0; i < 8; i++)
	    {
	      if (pProperties->PathReservableBW[i] > PathMaxReservableBW)
		PathMaxReservableBW = pProperties->PathReservableBW[i];
	    }
	  pProperties->PathMaxReservableBW = PathMaxReservableBW;
	  pPathList = pPathList->next;
	}
    }
  else
    {
      zlog_err
	("\nSomething wrong - expected remote link %x %x is not found %s %d",
	 from_node, to_node, __FILE__, __LINE__);
    }
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_remote_link_2_router_id_mapping

  DESCRIPTION: This function is called to map a link to the router ID.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              link_id - Local IP address of the TE link.
              router_id - Router ID, to which this link belongs.
                          
*****************************************************************************/

uns32
rdb_remote_link_2_router_id_mapping (IPV4_ADDR link_id, IPV4_ADDR router_id)
{
  LINK_2_ROUTER_ID *pLink2RouterId;

  if ((pLink2RouterId =
       (LINK_2_ROUTER_ID *) patricia_tree_get (&Link2RouterIdTree,
					       (const uns8 *) &link_id)) ==
      NULL)
    {
      if ((pLink2RouterId =
	   (LINK_2_ROUTER_ID *) XMALLOC (MTYPE_TE,
					 sizeof (LINK_2_ROUTER_ID))) == NULL)
	{
	  zlog_err ("\nmalloc failed %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
      pLink2RouterId->link_id = link_id;
      pLink2RouterId->router_id = router_id;
      pLink2RouterId->Node.key_info = (uns8 *) & pLink2RouterId->link_id;
      if (patricia_tree_add (&Link2RouterIdTree, &pLink2RouterId->Node) !=
	  E_OK)
	{
	  zlog_err ("\ncannot add node to patricia %s %d...", __FILE__,
		    __LINE__);
	  return E_ERR;
	}
    }
  else
    {
      pLink2RouterId->router_id = router_id;
    }
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_remote_link_2_router_id_mapping_withdraw

  DESCRIPTION: This function is called to remove a mapping of the link to the router ID.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              link_id - Local IP address of the TE link.
              router_id - Router ID, to which this link belongs.
                          
*****************************************************************************/

uns32
rdb_remote_link_2_router_id_mapping_withdraw (IPV4_ADDR link_id)
{
  LINK_2_ROUTER_ID *pLink2RouterId;

  if ((pLink2RouterId =
       (LINK_2_ROUTER_ID *) patricia_tree_get (&Link2RouterIdTree,
					       (const uns8 *) &link_id)) !=
      NULL)
    {
      if (patricia_tree_del (&Link2RouterIdTree, &pLink2RouterId->Node) !=
	  E_OK)
	{
	  zlog_err ("\ncannot add node to patricia %s %d...", __FILE__,
		    __LINE__);
	  return E_ERR;
	}
    }
  return E_OK;
}

uns32
rdb_set_router_id (IPV4_ADDR IpAddr)
{
  RouterID = IpAddr;
  return E_OK;
}

IPV4_ADDR
rdb_get_router_id ()
{
  return RouterID;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_remote_link_router_id_get

  DESCRIPTION: This function is called to determine that link belongs to certain router.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              from_node - Local IP address of the TE link.
              router_id - Router ID, to which this link belongs.
                          
*****************************************************************************/

uns32
rdb_remote_link_router_id_get (IPV4_ADDR from_node, IPV4_ADDR * router_id)
{
  LINK_2_ROUTER_ID *pLink2RouterId;

  /* first, find the remote link */
  if ((pLink2RouterId =
       (LINK_2_ROUTER_ID *) patricia_tree_get (&Link2RouterIdTree,
					       (const uns8 *) &from_node)) !=
      NULL)
    {
      *router_id = pLink2RouterId->router_id;
      return E_OK;
    }
  return E_ERR;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_igp_hello

  DESCRIPTION: This function is called upon reception of Hello message from IGP in order to update it with already existing allocations.
  
  PARAMETERS: 
                          
*****************************************************************************/

uns32
rdb_igp_hello ()
{
  TE_LINK_L_LIST *pTeLinks;

  pTeLinks = TeLinkLListHead;
  while (pTeLinks != NULL)
    {
      BwUpdateRequest2Igp (pTeLinks->te_link);
      /* component links are not processed yet */
      pTeLinks = pTeLinks->next;
    }
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_remote_link_router_id_get

  DESCRIPTION: This function is called to determine that link belongs to certain router.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              from_node - Local IP address of the TE link.
              router_id - Router ID, to which this link belongs.
                          
*****************************************************************************/

uns32
rdb_remote_link_router_id_mapping_dump (struct vty * vty)
{
  LINK_2_ROUTER_ID *pLink2RouterId;
  IPV4_ADDR key = 0;

  vty_out (vty, "%s", VTY_NEWLINE);

  while ((pLink2RouterId =
	  (LINK_2_ROUTER_ID *) patricia_tree_getnext (&Link2RouterIdTree,
						      (const uns8 *) &key)) !=
	 NULL)
    {
      vty_out (vty, "LinkID %x RouterID %x%s", pLink2RouterId->link_id,
	       pLink2RouterId->router_id, VTY_NEWLINE);
      key = pLink2RouterId->link_id;
    }
  vty_out (vty, "%s", VTY_NEWLINE);
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_te_links_dump

  DESCRIPTION:           Displays TE links.


*****************************************************************************/
uns32
rdb_te_links_dump (struct vty * vty)
{
  TE_LINK_L_LIST *pTeLinks;
  COMPONENT_LINK *pComponentLink;
  int j, i;

  pTeLinks = TeLinkLListHead;
  vty_out (vty, "%s", VTY_NEWLINE);
  while (pTeLinks != NULL)
    {
      vty_out (vty,
	       "TE LINK ID %x type %x MaxLspBW %f MaxReservableBW %f TE metric %x color mask %x%s",
	       pTeLinks->te_link->te_link_id, pTeLinks->te_link->type,
	       pTeLinks->te_link->te_link_properties.MaxLspBW,
	       pTeLinks->te_link->te_link_properties.MaxReservableBW,
	       pTeLinks->te_link->te_link_properties.TeMetric,
	       pTeLinks->te_link->te_link_properties.color_mask, VTY_NEWLINE);
      vty_out (vty, "ReservableBW (0-7):%s", VTY_NEWLINE);
      for (j = 0; j < 8; j++)
	vty_out (vty, "  %f",
		 pTeLinks->te_link->te_link_properties.ReservableBW[j]);

      vty_out (vty, "%s", VTY_NEWLINE);

      pComponentLink = pTeLinks->te_link->component_links;
      while (pComponentLink != NULL)
	{
	  vty_out (vty, "Out IF %x%s", pComponentLink->oifIndex, VTY_NEWLINE);
	  vty_out (vty, "ConfiguredReservable BW (0 -7):%s", VTY_NEWLINE);
	  for (j = 0; j < 8; j++)
	    vty_out (vty, "  %f", pComponentLink->ConfiguredReservableBW[j]);
	  vty_out (vty, "Reservable BW (0 -7):%s", VTY_NEWLINE);
	  for (j = 0; j < 8; j++)
	    vty_out (vty, "  %f", pComponentLink->ReservableBW[j]);
	  vty_out (vty, "ALLOCATED:");
	  for (j = 0; j < 8; j++)
	    {
	      vty_out (vty, "%s", VTY_NEWLINE);
	      for (i = 0; i < 8; i++)
		{
		  vty_out (vty, "  %f", pComponentLink->AllocatedBW[j][i]);
		}
	    }
	  vty_out (vty, "%s", VTY_NEWLINE);
	  pComponentLink = pComponentLink->next;
	}
      pTeLinks = pTeLinks->next;
    }
  return E_OK;
}


/*****************************************************************************

  PROCEDURE NAME:    rdb_next_hop_dump

  DESCRIPTION:           Displays Next Hops.


*****************************************************************************/
uns32
rdb_next_hop_dump (struct vty * vty)
{
  RDB_NEXT_HOP *next_hop_entry;
  IPV4_ADDR key_ip;
  int j;

  vty_out (vty, "%s", VTY_NEWLINE);

  key_ip = 0;

  while ((next_hop_entry =
	  (RDB_NEXT_HOP *) patricia_tree_getnext (&NextHopTree,
						  (const uns8 *) &key_ip)) !=
	 NULL)
    {
      TE_LINK_L_LIST *pTeLink;
      COMPONENT_LINK *pComponentLink;

      pTeLink = next_hop_entry->TELinkLList;
      vty_out (vty, "Next Hop %x%s", next_hop_entry->dest, VTY_NEWLINE);
      while (pTeLink != NULL)
	{
	  switch (pTeLink->te_link->type)
	    {
	    case PSC_PATH:
	      vty_out (vty, "TE LINK ID %x%s", pTeLink->te_link->te_link_id,
		       VTY_NEWLINE);
	      vty_out (vty,
		       "MaxLspBW %f MaxReservableBW %f TE metric %x Color Mask %x%s",
		       pTeLink->te_link->te_link_properties.MaxLspBW,
		       pTeLink->te_link->te_link_properties.MaxReservableBW,
		       pTeLink->te_link->te_link_properties.TeMetric,
		       pTeLink->te_link->te_link_properties.color_mask,
		       VTY_NEWLINE);
	      vty_out (vty, "ReservableBW (0-7):%s", VTY_NEWLINE);
	      for (j = 0; j < 8; j++)
		vty_out (vty, "  %f",
			 pTeLink->te_link->te_link_properties.
			 ReservableBW[j]);
	      break;
	    default:
	      zlog_info ("\nIS not supported %s %d", __FILE__, __LINE__);
	    }
	  pComponentLink = pTeLink->te_link->component_links;
	  while (pComponentLink != NULL)
	    {
	      vty_out (vty, "Out IF %x%s", pComponentLink->oifIndex,
		       VTY_NEWLINE);
	      vty_out (vty, "ReservableBW (0-7):%s", VTY_NEWLINE);
	      for (j = 0; j < 8; j++)
		vty_out (vty, "  %f", pComponentLink->ReservableBW[j]);
	      pComponentLink = pComponentLink->next;
	    }
	  pTeLink = pTeLink->next;
	}
      key_ip = next_hop_entry->dest;
    }
    /** Ok do the ifaddr list now.
     **/
  vty_out (vty, "%s", VTY_NEWLINE);
  return E_OK;

}

/*****************************************************************************

  PROCEDURE NAME:    rdb_summary_dump

  DESCRIPTION:           Displays summary advertisements.


*****************************************************************************/
uns32
rdb_summary_dump ()
{
  RDB_ABRS *abr_entry;
  IPV4_ADDR key_ip;
  int j;

  zlog_debug ("\n\n");

  key_ip = 0;

  while ((abr_entry = (RDB_ABRS *) patricia_tree_getnext (&ASBorderTree,
							  (const uns8 *)
							  &key_ip)) != NULL)
    {
      ABRS_L_LIST *pAbrsList;
      int i;

      pAbrsList = abr_entry->AbrsLList;
      zlog_debug ("\nASBR %x", abr_entry->dest);
      while (pAbrsList != NULL)
	{
	  SUMMARY_PROPERTIES *pProperties = pAbrsList->Abr->SummaryProperties;
	  zlog_debug ("\nABR %x", pAbrsList->Abr->AbrIpAddr);
	  for (i = 0; i < pAbrsList->Abr->NumberOfSummaries; i++)
	    {
	      zlog_debug ("\nMaxLspBW %f", pProperties->SummaryMaxLspBW);
	      zlog_debug ("\nMaxReservableBW %f",
			  pProperties->SummaryMaxReservableBW);
	      zlog_debug ("\nReservableBW (0-7):");
	      for (j = 0; j < 8; j++)
		zlog_debug ("  %f", pProperties->SummaryReservableBW[j]);
	      pProperties++;
	    }
	  pAbrsList = pAbrsList->next;
	}
      key_ip = abr_entry->dest;
    }

    /** Ok do the ifaddr list now.
     **/
  zlog_debug ("\n\n");
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_path_dump

  DESCRIPTION:       Displays the paths.


*****************************************************************************/
uns32
rdb_path_dump (struct vty * vty)
{
  RDB_PATH *path_entry;
  IPV4_ADDR key_ip;
  int j;

  key_ip = 0;
  vty_out (vty, "%s", VTY_NEWLINE);
  while ((path_entry = (RDB_PATH *) patricia_tree_getnext (&AreaBorderTree,
							   (const uns8 *)
							   &key_ip)) != NULL)
    {
      PATH_L_LIST *pPathList;
      int i;

      pPathList = path_entry->PathLList;
      vty_out (vty, "Path to ABR %x%s", path_entry->dest, VTY_NEWLINE);
      while (pPathList != NULL)
	{
	  ER_HOP_L_LIST *er_hop_l_list;
	  er_hop_l_list = pPathList->pPath->u.er_hops_l_list;
	  switch (pPathList->pPath->PathProperties.PathType)
	    {
	    case PSC_PATH:
	    case LSC_PATH:
	    case FSC_PATH:
	    case TSC_PATH:
	      for (i = 0;
		   i < (pPathList->pPath->PathProperties.PathHopCount) &&
		   (er_hop_l_list != NULL); i++)
		{
		  vty_out (vty, "%x %x -->", er_hop_l_list->er_hop->local_ip,
			   er_hop_l_list->er_hop->remote_ip);
		  er_hop_l_list = er_hop_l_list->next;
		}
	      break;

	    default:
	      zlog_info ("This path type %d is not supported",
			 pPathList->pPath->PathProperties.PathType);
	    }
	  vty_out (vty,
		   "MaxLspBW %f MaxReservableBW %f TE metric %x Hop count %x Color Mask %x%s",
		   pPathList->pPath->PathProperties.PathMaxLspBW,
		   pPathList->pPath->PathProperties.PathMaxReservableBW,
		   pPathList->pPath->PathProperties.PathSumTeMetric,
		   pPathList->pPath->PathProperties.PathHopCount,
		   pPathList->pPath->PathProperties.PathColorMask,
		   VTY_NEWLINE);
	  vty_out (vty, "ReservableBW (0-7):%s", VTY_NEWLINE);
	  for (j = 0; j < 8; j++)
	    vty_out (vty, "  %f",
		     pPathList->pPath->PathProperties.PathReservableBW[j]);

	  pPathList = pPathList->next;
	}
      key_ip = path_entry->dest;
    }
  vty_out (vty, "%s", VTY_NEWLINE);
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_remote_link_dump

  DESCRIPTION:       Displays the remote links.


*****************************************************************************/

uns32
rdb_remote_link_dump (struct vty * vty)
{
  TE_HOP *pKxErHop;
  link_key_t link_key;
  int i, j;

  vty_out (vty, "%s", VTY_NEWLINE);

  link_key.local_ip = 0;
  link_key.remote_ip = 0;

  for (i = 0; i < (MAX_PATH_TYPE - 1); i++)
    {
      while ((pKxErHop =
	      (TE_HOP *) patricia_tree_getnext (&(RemoteLinkTree[i - 1]),
						(const uns8 *) &link_key)) !=
	     NULL)
	{
	  vty_out (vty, "Link %x->%x%s", pKxErHop->local_ip,
		   pKxErHop->remote_ip, VTY_NEWLINE);

	  vty_out (vty,
		   "MaxLspBW %f MaxReservableBW %f TE metric %x ColorMask %x %s",
		   pKxErHop->MaxLspBW, pKxErHop->MaxReservableBW,
		   pKxErHop->te_metric, pKxErHop->ColorMask, VTY_NEWLINE);
	  vty_out (vty, "ReservableBW (0-7):%s", VTY_NEWLINE);
	  for (j = 0; j < 8; j++)
	    vty_out (vty, "  %f", pKxErHop->ReservableBW[j]);
#if 0
	  pPathList = pKxErHop->pPathList;
	  while (pPathList != NULL)
	    {
	      ER_HOP_L_LIST *er_hop_l_list;
	      er_hop_l_list = pPathList->pPath->u.er_hops_l_list;
	      if ((i + 1) != pPathList->pPath->PathProperties.PathType)
		{
		  zlog_info ("expected path type %d, existing %d",
			     (i + 1),
			     pPathList->pPath->PathProperties.PathType);
		}
	      zlog_info ("");
	      for (j = 0;
		   j < (pPathList->pPath->PathProperties.PathHopCount) &&
		   (er_hop_l_list != NULL); j++)
		{
		  zlog_info ("%x %x -->", er_hop_l_list->er_hop->local_ip,
			     er_hop_l_list->er_hop->remote_ip);
		  er_hop_l_list = er_hop_l_list->next;
		}
	      zlog_info
		("MaxLspBW %f MaxReservableBW %f TE metric %x Hop count %x Color Mask %x",
		 pPathList->pPath->PathProperties.PathMaxLspBW,
		 pPathList->pPath->PathProperties.PathMaxReservableBW,
		 pPathList->pPath->PathProperties.PathSumTeMetric,
		 pPathList->pPath->PathProperties.PathHopCount,
		 pPathList->pPath->PathProperties.PathColorMask);
	      zlog_info ("ReservableBW (0-7):");
	      for (j = 0; j < 8; j++)
		zlog_info ("  %f",
			   pPathList->pPath->PathProperties.
			   PathReservableBW[j]);
	      pPathList = pPathList->next;
	    }
#endif
	  link_key.local_ip = pKxErHop->local_ip;
	  link_key.remote_ip = pKxErHop->remote_ip;
	}
    }
  vty_out (vty, "%s", VTY_NEWLINE);
  return E_OK;
}

/*****************************************************************************

  PROCEDURE NAME:    rdb_static_path_dump

  DESCRIPTION: Adds a new path *pPath to destination dest_ip.
  
  PARAMETERS: rdb_handle - Routing Data Base handle.
              dest_ip - Path destination's IP address.
                          *pPath - pointer to the path description (path's summary propertieslist of hops
                          and hops' properties).

*****************************************************************************/
uns32
rdb_static_path_dump (char *pName, struct vty * vty)
{
  STATIC_PATH *pStaticPath;
  IPV4_HOP *pHops;

  vty_out (vty, "%s", VTY_NEWLINE);
  pStaticPath = StaticPathHead;
  while (pStaticPath != NULL)
    {
      if (pName)
	{
	  if (strcmp (pName, pStaticPath->PathName) != 0)
	    {
	      pStaticPath = pStaticPath->next;
	      continue;
	    }
	}
      vty_out (vty, "Path %s%s", pStaticPath->PathName, VTY_NEWLINE);
      vty_out (vty, "Hops (%d): %s", pStaticPath->HopCount, VTY_NEWLINE);
      for (pHops = pStaticPath->HopList; pHops; pHops = pHops->next)
	{
	  vty_out (vty, " Loose %x IP Address %x %s",
		   pHops->Loose, pHops->IpAddr, VTY_NEWLINE);
	}
      if (pName)
	{
	  if (strcmp (pName, pStaticPath->PathName) == 0)
	    {
	      break;
	    }
	}
      pStaticPath = pStaticPath->next;
    }
  vty_out (vty, "%s", VTY_NEWLINE);
  return E_OK;
}
