#include <zebra.h>
#include <stdlib.h>

#include "general.h"
#include "thread.h"
#include "workqueue.h"
#include "memory.h"
#include "log.h"

#include "rsvp.h"
#include "te.h"

struct mesg_block
{
  void *data;
  int size;
};

extern struct thread_master *master;

static struct work_queue *rsvp2te = NULL;
static struct work_queue *te2rsvp = NULL;
static struct work_queue *te2te = NULL;

static int
RSVP_ProcessTeMsg (void *data, int Length)
{
  TE_API_MSG Msg, *pMsg = data;
  int ret = 0;

  switch (pMsg->NotificationType)
    {
    case PATH_MSG_NOTIFICATION:
      ret = ProcessTEMsgUponPath (pMsg);
      break;
    case RESV_MSG_NOTIFICATION:
      ret = ResvTeMsgProc (pMsg);
      break;
    case PATH_SEND_CMD:
      RsvpPathSendCmd (pMsg);
      break;
    case PATH_TEAR_CMD:
      RsvpPathTearCmd (pMsg);
      break;
    case PREEMPT_FLOW_CMD:
      PreemptFlow (pMsg);
      break;
    case DEBUG_SEND_RESV_TEAR_CMD:
      ret = DebugSendResvTear (pMsg);
      break;
    default:
      printf ("TE-->RSVP: unknown message type %d %s %d\n",
	      pMsg->NotificationType, __FILE__, __LINE__);
    }
  return ret;
}

static int
TE_ProcessTeMsg (void *data, int Len)
{
  void *pBuf = data;
  EVENTS_E *pEvent = data;
  TE_MSG *pMsg;

  switch (*pEvent)
    {
    case EVENT_TE_SM:
      pMsg = pBuf;
      sm_call (pMsg->u.te_sm_event.data);
      break;
    case EVENT_CREATE_TE_PATH:
      TE_IGP_API_PathAdd (pBuf, Len);
      break;
    case EVENT_READ_PATH_CASH:
      TE_IGP_API_ReadPathCash (pBuf, Len);
      break;
#if FRR_SM_DEFINED
    case EVENT_RRO_CHANGED:
      RRO_ChangedMsg (&dmsg->u.rro_changed_hook);
      break;
    case EVENT_BYPASS_TUNNEL_RETRY_EXPIRY:
      BypassTunnelRetryExpiry (dmsg);
      break;
    case EVENT_FRR_INFO_SET:
      SetFrrData (dmsg);
      break;
#endif
    default:
      zlog_err ("\nBUG: Default case %s %d", __FILE__, __LINE__);
    }
}

static int
TE_ProcessRsvpMsg (void *data, int Len)
{
  TE_API_MSG *pTeApiMsg = data;
  char *buffer = data;

  switch (pTeApiMsg->NotificationType)
    {
    case PATH_MSG_NOTIFICATION:
      TE_RSVPTE_API_TransitReqAPI (pTeApiMsg);
      break;
    case RESV_MSG_NOTIFICATION:
      if (pTeApiMsg->u.ResvNotification.Ingress)
	{
	  PSB_KEY key;
	  float MaximumPossibleBW = 0;
	  memset (&key, 0, sizeof (PSB_KEY));
	  key.Session = pTeApiMsg->u.ResvNotification.RsbKey.Session;
	  if (pTeApiMsg->u.ResvNotification.SharedExplicit)
	    {
	      if (TE_RSVPTE_API_DoAllocation (&key,
					      pTeApiMsg->u.ResvNotification.u.
					      FilterDataSE.
					      IfIndex /* temporary */ ,
					      pTeApiMsg->u.ResvNotification.u.
					      FilterDataSE.IfIndex,
					      pTeApiMsg->u.ResvNotification.u.
					      FilterDataSE.BW,
					      pTeApiMsg->u.ResvNotification.u.
					      FilterDataSE.SetupPrio,
					      pTeApiMsg->u.ResvNotification.u.
					      FilterDataSE.HoldPrio,
					      &MaximumPossibleBW) != E_OK)
		{
		  zlog_info ("\nBW allocation failed %s %d", __FILE__,
			     __LINE__);
		  pTeApiMsg->u.ResvNotification.u.FilterDataSE.BW =
		    MaximumPossibleBW;
		  pTeApiMsg->u.ResvNotification.rc = FALSE;
		}
	      else
		{
		  pTeApiMsg->u.ResvNotification.rc = TRUE;
		  TE_RSVPTE_API_RsvpTunnelEstablished (&pTeApiMsg->u.
						       ResvNotification);
		}
	    }
	  else
	    {
	      key.SenderTemplate =
		pTeApiMsg->u.ResvNotification.u.FilterDataFF.FilterSpec;
	      if (TE_RSVPTE_API_DoAllocation
		  (&key,
		   pTeApiMsg->u.ResvNotification.u.FilterDataFF.
		   IfIndex /* temporary */ ,
		   pTeApiMsg->u.ResvNotification.u.FilterDataFF.IfIndex,
		   pTeApiMsg->u.ResvNotification.u.FilterDataFF.BW,
		   pTeApiMsg->u.ResvNotification.u.FilterDataFF.SetupPrio,
		   pTeApiMsg->u.ResvNotification.u.FilterDataFF.HoldPrio,
		   &MaximumPossibleBW) != E_OK)
		{
		  zlog_info ("\nBW allocation failed %s %d", __FILE__,
			     __LINE__);
		  pTeApiMsg->u.ResvNotification.u.FilterDataFF.BW =
		    MaximumPossibleBW;
		  pTeApiMsg->u.ResvNotification.rc = FALSE;
		}
	      else
		{
		  pTeApiMsg->u.ResvNotification.rc = TRUE;
		  TE_RSVPTE_API_RsvpTunnelEstablished (&pTeApiMsg->u.
						       ResvNotification);
		}

	    }
	  if (pTeApiMsg->u.ResvNotification.PleaseReply)
	    {
	      te_send_msg (pTeApiMsg, sizeof (TE_API_MSG));
	    }
	}
      else
	TE_RSVPTE_API_TransitResv (pTeApiMsg);
      break;
    case BW_RELEASE_NOTIFICATION:
      TE_RSVPTE_API_BwReleaseMessage (pTeApiMsg);
      break;
    case LABEL_RELEASE_NOTIFICATION:
      TE_RSVPTE_API_LabelRelease (pTeApiMsg);
      break;
    case RESV_TEAR_NOTIFICATION:
      TE_RSVPTE_API_RsvpResvTear (&pTeApiMsg->u.ResvTearNotification);
      break;
    case PATH_ERR_NOTIFICATION:
      TE_RSVPTE_API_RsvpPathErr (&pTeApiMsg->u.PathErrNotification);
      break;
    default:
      zlog_err ("\ndefault case (%d) reached %s %d",
		pTeApiMsg->NotificationType, __FILE__, __LINE__);
      {
	int i;
	for (i = 0; i < 40; i++)
	  {
	    if (!(i % 8))
	      {
		zlog_info ("\n");
	      }
	    zlog_info ("%x  ", buffer[i]);
	  }
      }
    }
  return 0;
}

void
SetFrrData (TE_MSG * pMsg)
{
#if 0
  PSB_KEY psb_key;
  PSB *pUpPsb;

  memset (&psb_key, '\0', sizeof (psb_key));
  psb_key.Session.Dest = htonl (pMsg->u.frr_data_set.PsbKey.Session.Dest);
  psb_key.Session.TunnelId = pMsg->u.frr_data_set.PsbKey.Session.TunnelId;
  psb_key.Session.ExtTunelId = pMsg->u.frr_data_set.PsbKey.Session.ExtTunelId;
  psb_key.SenderTemplate.LspId =
    pMsg->u.frr_data_set.PsbKey.SenderTemplate.LspId;
  psb_key.SenderTemplate.IpAddr =
    pMsg->u.frr_data_set.PsbKey.SenderTemplate.IpAddr;

  if ((pUpPsb =
       (RSVP_UP_PSB *) patricia_tree_getnext (&intf->info.lms.UpPsbToIntfTree,
					      (const uns8 *) &psb_key)) !=
      NULL)
    {
      zlog_info ("\nsetting FRR data %x %x %x for %x %x %x %x %x on IF#%x",
		 pMsg->u.frr_data_set.BackupOutIf,
		 pMsg->u.frr_data_set.BackupVcardId,
		 pMsg->u.frr_data_set.MergeNodeIp,
		 psb_key.Session.Dest,
		 psb_key.Session.TunnelId,
		 psb_key.Session.ExtTunelId,
		 psb_key.SenderTemplate.LspId,
		 psb_key.SenderTemplate.IpAddr, pMsg->u.frr_data_set.IfIndex);
      /* set here the FRR data */
    }
  else
    {
      zlog_info ("\ncannot find PSB by key %x %x %x %x %x %s %d",
		 psb_key.Session.Dest,
		 psb_key.Session.TunnelId,
		 psb_key.Session.ExtTunelId,
		 psb_key.SenderTemplate.LspId,
		 psb_key.SenderTemplate.IpAddr, __FILE__, __LINE__);
    }
#endif
}

static wq_item_status
rsvp_te_process (struct work_queue *wq, void *data)
{
  struct mesg_block *blk = data;
  TE_ProcessRsvpMsg(blk->data, blk->size);
  XFREE (MTYPE_TMP, data);
  return WQ_SUCCESS;
}

static wq_item_status
te_rsvp_process (struct work_queue *wq, void *data)
{
  struct mesg_block *blk = data;
  RSVP_ProcessTeMsg(blk->data, blk->size);
  XFREE (MTYPE_TMP, data);
  return WQ_SUCCESS;
}

static wq_item_status
te_te_process (struct work_queue *wq, void *data)
{
  struct mesg_block *blk = data;
  TE_ProcessTeMsg(blk->data, blk->size);
  XFREE (MTYPE_TMP, data);
  return WQ_SUCCESS;
}

void
rsvp_te_comm_init()
{
  if (! (rsvp2te = work_queue_new (master, "rsvp->te mesg passing")))
    {
      zlog_err ("%s: could not initialise work queue!", __func__);
      return;
    }

  if (! (te2rsvp = work_queue_new (master, "te->rsvp mesg passing")))
    {
      zlog_err ("%s: could not initialise work queue!", __func__);
      return;
    }

  if (! (te2te = work_queue_new (master, "te->te mesg passing")))
    {
      zlog_err ("%s: could not initialise work queue!", __func__);
      return;
    }

  rsvp2te->spec.workfunc = &rsvp_te_process;
  rsvp2te->spec.errorfunc = NULL;
  rsvp2te->spec.max_retries = 3;
  rsvp2te->spec.hold = 1;

  te2rsvp->spec.workfunc = &te_rsvp_process;
  te2rsvp->spec.errorfunc = NULL;
  te2rsvp->spec.max_retries = 3;
  te2rsvp->spec.hold = 1;

  te2te->spec.workfunc = &te_te_process;
  te2te->spec.errorfunc = NULL;
  te2te->spec.max_retries = 3;
  te2te->spec.hold = 1;

  return;
}

E_RC
rsvp_send_msg (void *pMsg, int size)
{
  struct mesg_block *blk = NULL;
  blk = XMALLOC (MTYPE_TMP, sizeof(struct mesg_block) + size);
  blk->data = &blk[1];
  blk->size = size;
  memcpy(blk->data, pMsg, size);

  work_queue_add (rsvp2te, blk);
  return E_OK;
}

E_RC
te_send_msg (void *pMsg, int size)
{
  struct mesg_block *blk = NULL;
  blk = XMALLOC (MTYPE_TMP, sizeof(struct mesg_block) + size);
  blk->data = &blk[1];
  blk->size = size;
  memcpy(blk->data, pMsg, size);

  work_queue_add (te2rsvp, blk);
  return E_OK;
}

E_RC
te2te_send_msg (void *pMsg, int size)
{
  struct mesg_block *blk = NULL;
  blk = XMALLOC (MTYPE_TMP, sizeof(struct mesg_block) + size);
  blk->data = &blk[1];
  blk->size = size;
  memcpy(blk->data, pMsg, size);

  work_queue_add (te2te, blk);
  return E_OK;
}
