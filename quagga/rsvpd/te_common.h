
#ifndef __COMMON_PROC_H__
#define __COMMON_PROC_H__

typedef enum
{
  LSP_SM,
  TRANSIT_LSP_SM,
  CONSTRAINT_ROUTE_RESOLUTION_SM,
  FAST_REROUTE_SM,
  MAX_SM
} SM_E;

typedef enum
{
  USER_LSP_REQUEST_EVENT,
  INGRESS_LSP_REQUEST_EVENT,
  INGRESS_LSP_DELETE_REQUEST_EVENT,
  INGRESS_LSP_OPERATION_COMPLETE_EVENT,
  INGRESS_LSP_OPERATION_FAILED_EVENT,
  TRANSIT_REQ_EVENT,
  SLA_USER_REQUEST_EVENT,
  SLA_DELETE_USER_REQUEST_EVENT,
  CONSTRAINT_ROUTE_RESOLUTION_REQ_EVENT,
  CONSTRAINT_ROUTE_RESOLVED_EVENT,
  CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT,
  CSPF_REPLY_EVENT,
  DYNAMIC_ADAPTATION_REQ_EVENT,
  SLA_ADAPTATION_REQ_EVENT,
  SLA_ADAPTATION_COMPLETE_EVENT,
  SLA_ADAPTATION_FAILED_EVENT,
  MPLS_SIGNALING_INGRESS_ESTABLISHED_NOTIFICATION_EVENT,
  MPLS_SIGNALING_INGRESS_FAILED_NOTIFICATION_EVENT,
  LSP_SETUP_TIMER_EXPIRY,
  ADAPTIVITY_TIMER_EXPIRY,
  RETRY_TIMER_EXPIRY,
  BYPASS_SETUP_REQ_EVENT,
  RRO_CHANGED_EVENT,
  CSPF_RETRY_EVENT,
  SM_MAX_EVENT
} SM_EVENT_E;

typedef struct
{
  SM_EVENT_E event;
  void *data;
} SM_EVENT_T;

typedef struct _sm_t_
{
  SM_E sm_type;
  int state;
  struct _sm_t_ *caller;
  void *data;
} SM_T;

typedef struct
{
  SM_T *sm;
  SM_EVENT_T *sm_data;
} SM_CALL_T;


#define INIT_STATE  1

typedef void (*LSP_LOOP_CALLBACK_T) (USER_LSP *, void *);

INGRESS_API *CreateRequest2Signalling (IPV4_ADDR dest,
				       uns16 tunnel_id,
				       uns32 ErHopsNumber,
				       ER_HOP * pErHops,
				       float BW,
				       uns8 SetupPriority,
				       uns8 HoldPriority,
				       uns8 Flags,
				       uns32 ExcludeAny,
				       uns32 IncludeAny, uns32 IncludeAll);
BOOL RightPathCheaper (PATH_PROPERTIES * pLeftPathProp,
		       PATH_PROPERTIES * pRightPathProp, uns8 Priority);
uns16 GetPimaryTunnelId (char *pLspName);
uns32 UserLspDelete (char *pLspName);
USER_LSP *UserLspGet (char *pLspName);
uns32 UserLspAdd (USER_LSP * pUserLsp);
uns16 NewTunnelId (PSB_KEY * PsbKey);
PATH *GetLspPath (RSVP_LSP_PROPERTIES * pRsvpLsp);
BOOL PathsEqual (ER_HOP_L_LIST * pErHopsLList, IPV4_ADDR * pIpAddr,
		 int HopCount);
TRUNK_ENTRY *NewTunnelsTrunk (TRUNK_KEY * trunk_key);
TRUNK_ENTRY *GetTunnelsTrunk (TRUNK_KEY * trunk_key);
void TE_RSVPTE_API_RsvpPathErr (PATH_ERR_NOTIF * pPathErrNotif);
void TE_RSVPTE_API_RsvpResvTear (RESV_TEAR_NOTIF * pResvTearNotif);
//void UserLspsDump(char *pName,int PortNum);
void RsvpTunnelsDump ();
void TE_RSVPTE_API_RsvpTunnelEstablished (RESV_NOTIFICATION * resv_notif);
uns32 DeleteTunnel (PSB_KEY * PsbKey, TRUNK_TYPE trunk_type);
uns32 NewTunnel (PSB_KEY * PsbKey, RSVP_TUNNEL_PROPERTIES ** ppNewTunnel,
		 TRUNK_TYPE trunk_type);
uns32 NewRsvpLsp (RSVP_TUNNEL_PROPERTIES * pTunnel,
		  RSVP_LSP_PROPERTIES ** ppRsvpLsp);
BOOL FindTunnel (PSB_KEY * PsbKey, RSVP_TUNNEL_PROPERTIES ** ppTunnel,
		 TRUNK_TYPE trunk_type);
uns32 TeApplicationInit ();
void te_stop_timer (TE_TMR * tmr);
uns32 te_start_timer (TE_TMR * tmr, TE_TMR_E type, uns32 period);
void sm_call (SM_CALL_T * sm_packet);
void sm_gen_free (SM_T * sm);
SM_T *sm_gen_alloc (SM_T * caller, SM_E sm_type);
SM_CALL_T *sm_gen_sync_event_send (SM_T * sm, SM_EVENT_E event, void *data);
int sm_gen_async_event_send (SM_T * sm, SM_EVENT_E event, void *data);
void sm_gen_event_trace (SM_E event);
void UserLspLoop (void (*CallBackFunc) (USER_LSP *, void *), void *data);
void UserLspsDump (char *pName, struct vty *vty);
uns32 NewTunnelIfId (IPV4_ADDR dest, uns32 IfIndex);

#endif
