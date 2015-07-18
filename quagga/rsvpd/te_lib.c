/* Module:   te_config_data_plane.c
   Contains: TE application data plane configuration
   functions. Called when an tunnel is established.
   For the transit tunnels (LSR) - when corresponding
   RESV received.
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "te.h"

void
mplsTePolicy (char *PolicyName, char *LabelEntryKey, int opcode)
{
}

void
mplsTeInOutLabel (unsigned int AllocatedLabel,
		  unsigned int ReceivedLabelMapping, unsigned int OutIfIndex)
{
}

/* A data plane configuration for the Ingress tunnels (only outgoing label) */
void
mplsTeOutLabel (int *OutLabels, int OutLabelsCount, char *key, int NextHop,
		int opcode)
{
}

/* Module:   label_man.c
   Contains: TE application label manager
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */

extern PATRICIA_TREE PlatformWideFreeLabels;
extern PATRICIA_TREE LineCard2LabelsTree;

LABEL_ENTRY PlatformWideLabelSpace[LABEL_SPACE_SIZE];

uns32
LabelAllocate (unsigned int *Label, LABEL_POLICY_E policy, PSB_KEY * pKey,
	       uns32 IfIndex)
{
  uns8 key = 0;
  LABEL_ENTRY *p_label_entry;
  if ((p_label_entry = (LABEL_ENTRY *)
       patricia_tree_getnext (&PlatformWideFreeLabels,
			      (const uns8 *) &key)) == NULL)
    {
      zlog_err ("\ncannot allocate label %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  if (((p_label_entry->label % 2) && (policy == EVEN_LABELS)) ||
      ((!(p_label_entry->label % 2)) && (policy == ODD_LABELS)))
    {
      key = p_label_entry->label;
      if ((p_label_entry = (LABEL_ENTRY *)
	   patricia_tree_getnext (&PlatformWideFreeLabels,
				  (const uns8 *) &key)) == NULL)
	{
	  zlog_err ("\ncannot allocate label %s %d", __FILE__, __LINE__);
	  return E_ERR;
	}
    }
  if (patricia_tree_del (&PlatformWideFreeLabels, &p_label_entry->Node) !=
      E_OK)
    {
      zlog_err ("\nfatal: cannot remove entry from patricia tree %s %d",
		__FILE__, __LINE__);
      return E_ERR;
    }

  p_label_entry->IfIndex = IfIndex;	/* needed for FRR */

  *Label = p_label_entry->label;
  zlog_info ("\nLabel allocation performed: label %x \
dest %x tunnel id %x ext tunnel id %x lsp id %x ", *Label, pKey->Session.Dest, pKey->Session.TunnelId, pKey->Session.ExtTunelId, pKey->SenderTemplate.LspId);
  return E_OK;
}

uns32
TE_RSVPTE_API_LabelRelease (TE_API_MSG * dmsg)
{
  LABEL_ENTRY *p_label_entry;
#ifdef FRR_SM_DEFINED
  FrrLabelRelease (dmsg->u.LabelRelease.Label);
#endif
  if ((dmsg->u.LabelRelease.Label <= 0)
      || (dmsg->u.LabelRelease.Label >= LABEL_SPACE_SIZE))
    {
      zlog_err ("Invalid label %x %s %d", dmsg->u.LabelRelease.Label,
		__FILE__, __LINE__);
      return E_ERR;
    }
  p_label_entry = &PlatformWideLabelSpace[dmsg->u.LabelRelease.Label - 1];

  if (patricia_tree_add (&PlatformWideFreeLabels, &p_label_entry->Node) !=
      E_OK)
    {
      zlog_err ("\ncannot return label %s %d", __FILE__, __LINE__);
      return E_ERR;
    }
  return E_OK;
}


int
LSRLabelMappingReceived (unsigned int AllocatedLabel,
			 unsigned int ReceivedLabelMapping,
			 unsigned int OutIfIndex)
{
  if ((AllocatedLabel >= LABEL_SPACE_SIZE) || (AllocatedLabel < 1))
    {
      zlog_err ("\ninvalid AllocatedLabel (out of range) %s %d", __FILE__,
		__LINE__);
      return E_ERR;
    }
  if (patricia_tree_get
      (&PlatformWideFreeLabels, (const uns8 *) &AllocatedLabel) != NULL)
    {
      zlog_err ("\nAllocated Label is not really allocated %s %d...",
		__FILE__, __LINE__);
      return E_ERR;
    }
  PlatformWideLabelSpace[AllocatedLabel - 1].ReceivedOutLabel =
    ReceivedLabelMapping;
  PlatformWideLabelSpace[AllocatedLabel - 1].OutIf = OutIfIndex;
  mplsTeInOutLabel (AllocatedLabel, ReceivedLabelMapping, OutIfIndex);
  return E_OK;
}

void
IngressLabelMappingReceived (unsigned int ReceivedLabelMapping,
			     unsigned int OutIfIndex, PSB_KEY * pKey)
{
#if DATA_PLANE
  {
    char key[23];
    IPV4_ADDR next_hop = 0;
    RSVP_TUNNEL_PROPERTIES *pTunnel;
    RSVP_LSP_PROPERTIES *pRsvpLsp;
    USER_LSP *pUserLsp;
    if (FindTunnel (pKey, &pTunnel, ALL_TRUNKS) != TRUE)
      {
	return;
      }
    pUserLsp = UserLspGet (pTunnel->UserLspName);
    if ((pUserLsp) && (pUserLsp->pUserLspTunnels == NULL))
      {
	return;
      }
/* commented in order to configure the label of the backup LSP in the data plane 
        if((pUserLsp->pUserLspTunnels->TunnelId != pTunnel->TunnelId)&&
           (pUserLsp->BackupTunnelId != pTunnel->TunnelId))
        {
            return;
        }*/
    if ((pRsvpLsp = GetWorkingRsvpLsp (pTunnel)) == NULL)
      {
	return;
      }
    if ((pRsvpLsp->tunneled == FALSE)
	&& (pRsvpLsp->forw_info.path.HopCount != 0))
      {
	next_hop = pRsvpLsp->forw_info.path.pErHopsList[0];
      }
    sprintf (key, "%x%d%x%d", pKey->Session.Dest, pTunnel->TunnelId,
	     pKey->Session.ExtTunelId, pRsvpLsp->LspId);
    zlog_info ("create label %x next hop %x \nkey %s\nUserLspName %s\n",
	       pRsvpLsp->Label, next_hop, key, pTunnel->UserLspName);
    mplsTeOutLabel (&pRsvpLsp->Label, 1, key, next_hop, 1);
    if ((pUserLsp != NULL) && (pUserLsp->params.PolicyName[0] != '\0'))
      {
	if ((pUserLsp->pUserLspTunnels->TunnelId == pTunnel->TunnelId) &&
	    (pUserLsp->BackupTunnelId))
	  {
	    char key1[23];
	    PSB_KEY PsbKey;

	    memset (&PsbKey, 0, sizeof (PSB_KEY));
	    PsbKey.Session.Dest = pKey->Session.Dest;
	    PsbKey.Session.ExtTunelId = pKey->Session.ExtTunelId;
	    PsbKey.Session.TunnelId = pUserLsp->BackupTunnelId;
	    if (FindTunnel (&PsbKey, &pTunnel, ALL_TRUNKS) != TRUE)
	      {
		return;
	      }
	    if ((pRsvpLsp = GetWorkingRsvpLsp (pTunnel)) == NULL)
	      {
		return;
	      }
	    sprintf (key1, "%x%d%x%d", pKey->Session.Dest, pTunnel->TunnelId,
		     pKey->Session.ExtTunelId, pRsvpLsp->LspId);
	    mplsTePolicy (pUserLsp->params.PolicyName, key1, 0);
	    pUserLsp->BackupTunnelId = 0;
	  }
	zlog_info ("PolicyName %s", pUserLsp->params.PolicyName);
	mplsTePolicy (pUserLsp->params.PolicyName, key, 1);
      }
  }
#endif
  return;
}

void
AssignedLabelsDump ()
{
  uns32 key = 0, i;
  LABEL_ENTRY *p_label_entry;
  for (i = 0; i < LABEL_SPACE_SIZE; i++)
    {
      key = i + 1;
      if ((p_label_entry = (LABEL_ENTRY *)
	   patricia_tree_get (&PlatformWideFreeLabels,
			      (const uns8 *) &key)) != NULL)
	zlog_info ("\nlabel %x", p_label_entry->label);
    }
  return;
}


/* Module:   lsr.c
   Contains: TE application transit RESV message processing
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */



void
TE_RSVPTE_API_TransitResv (TE_API_MSG * dmsg)
{
  PSB_KEY key;
  int i;
  float MaximumPossibleBW = 0;
  memset (&key, 0, sizeof (PSB_KEY));
  key.Session = dmsg->u.ResvNotification.RsbKey.Session;
  if (TE_RSVPTE_API_DoAllocation (&key,
				  dmsg->u.ResvNotification.u.FilterDataSE.
				  IfIndex /* temporary */ ,
				  dmsg->u.ResvNotification.u.FilterDataSE.
				  IfIndex,
				  dmsg->u.ResvNotification.u.FilterDataSE.BW,
				  dmsg->u.ResvNotification.u.FilterDataSE.
				  SetupPrio,
				  dmsg->u.ResvNotification.u.FilterDataSE.
				  HoldPrio, &MaximumPossibleBW) != E_OK)
    {
      zlog_info ("\nBW allocation failed %s %d", __FILE__, __LINE__);
      dmsg->u.ResvNotification.u.FilterDataSE.BW = MaximumPossibleBW;
      dmsg->u.ResvNotification.rc = FALSE;
    }
  else
    {
      zlog_info ("BW allocation succeeded. Updating LSR's table...");
      for (i = 0;
	   i < dmsg->u.ResvNotification.u.FilterDataSE.FilterSpecNumber; i++)
	{
	  if (LSRLabelMappingReceived
	      (dmsg->u.ResvNotification.u.FilterDataSE.FilterDataArraySE[i].
	       AllocatedLabel,
	       dmsg->u.ResvNotification.u.FilterDataSE.FilterDataArraySE[i].
	       ReceivedLabel,
	       dmsg->u.ResvNotification.u.FilterDataSE.IfIndex) != E_OK)
	    {
	    }
	}
      dmsg->u.ResvNotification.rc = TRUE;
    }
  zlog_info ("Sending reply to TE");
  rsvp_send_msg (dmsg, sizeof (TE_API_MSG));
  return;
}
