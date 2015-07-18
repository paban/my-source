#ifndef _RSVP_API_STRUCT_H_
#define _RSVP_API_STRUCT_H_

#include "rsvp_packet.h"

typedef struct
{
  SESSION_OBJ Session;
  SENDER_TEMPLATE_OBJ SenderTemplate;
} PSB_KEY;

typedef struct
{
  SESSION_OBJ Session;
} RSB_KEY;

#define TE_PATH_RESPONSE 1
#define TE_RESV_RESPONSE 2

typedef enum
{
  PATH_MSG_NOTIFICATION,
  RESV_MSG_NOTIFICATION,
  PATH_ERR_NOTIFICATION,
  RESV_TEAR_NOTIFICATION,
  RRO_CHANGED_NOTIFICATION,
  LABEL_RELEASE_NOTIFICATION,
  BW_RELEASE_NOTIFICATION,
  PREEMPT_FLOW_CMD,
  ENABLE_RSVP_ON_IF,
  DISABLE_RSVP_ON_IF,
  SET_PEER,
  IP_ADDR_ADD,
  IP_ADDR_DEL,
  PATH_SEND_CMD,
  PATH_TEAR_CMD,
  DEBUG_SEND_RESV_TEAR_CMD
} TE_NOTIFICATION_E;

typedef enum
{
  PATH_PROC_OK,
  BW_UNAVAIL,
  NO_ROUTE,
  LABEL_ALLOC_FAILURE,
  UNSUP_L3PID
} PATH_PROC_E;


typedef struct
{
  PSB_KEY PsbKey;
  /* resource affinity info valid, if set to 1 */
  uns8 RA_Valid;
  uns32 ExcludeAny;
  uns32 IncludeAll;
  uns32 IncludeAny;
  /* set to default if received PATH does not contain SESSION_ATTRIBUTES */
  uns8 HoldPrio;
  /* set to default if received PATH does not contain SESSION_ATTRIBUTES */
  uns8 SetupPrio;
  /* RSVP-TE -> TE-APP: received ER HOPS, TE-APP -> RSVP-TE - inserted ER HOPS */
  /*(if first - loose, before first, otherwise - after the last */
  uns16 ErHopNumber;
  /* if set to 1 - first ER HOP is strict */
  uns8 FirstErHopStrict;
  IPV4_ADDR ErHops[100];
  /* if set to 1, local protection desired */
  uns8 LocalProtection;
  /* shared explicit style, if set to 1 */
  uns8 SharedExplicit;
  /* allocated label */
  uns32 Label;
  /* requested BW */
  float BW;
  /* TE output - OutIfIndex and Next Hop */
  uns32 OutIfIndex;
  IPV4_ADDR NextHop;
  uns8 LabelRecordingDesired;
  PATH_PROC_E rc;
} PATH_NOTIFICATION;

typedef struct
{
  FILTER_SPEC_OBJ FilterSpec;

  uns32 IfIndex;		/* where BW should be allocated. */
  /* extracted from PSB */
  uns8 HoldPrio;
  /* extracted from PSB */
  uns8 SetupPrio;
  /* received label */
  uns32 ReceivedLabel;
  /* allocated label */
  uns32 AllocatedLabel;
  /* requested BW */
  float BW;			/* could be different for each FILTER_SPEC if FF, same for each FILTER_SPEC if SE */
} FILTER_DATA_FF;

typedef struct
{
  FILTER_SPEC_OBJ FilterSpec;
  /* received label */
  uns32 ReceivedLabel;
  /* allocated label */
  uns32 AllocatedLabel;
} FILTER_DATA_ARRAY_SE;

typedef struct
{
  /* requested BW */
  float BW;			/* could be different for each FILTER_SPEC if FF, same for each FILTER_SPEC if SE */
  /* extracted from PSB */
  uns8 HoldPrio;
  /* extracted from PSB */
  uns8 SetupPrio;
  /* Where to allocate */
  uns32 IfIndex;
  uns16 FilterSpecNumber;
  FILTER_DATA_ARRAY_SE FilterDataArraySE[100];
} FILTER_DATA_SE;

typedef struct
{
  RSB_KEY RsbKey;
  /* If set, Ingress is reached */
  uns8 Ingress;
  uns8 PleaseReply;
  uns8 rc;			/* FALSE or TRUE */
  /* if set to 1, shared explicit reservation style */
  uns8 SharedExplicit;

  union
  {
    FILTER_DATA_SE FilterDataSE;
    FILTER_DATA_FF FilterDataFF;
  } u;
} RESV_NOTIFICATION;


typedef struct
{
  RSB_KEY RsbKey;
  uns16 FilterSpecNumber;
  FILTER_SPEC_OBJ FilterSpecs[100];
} DEBUG_SEND_RESV_TEAR;

typedef struct
{
  PSB_KEY PsbKey;
  uns32 Label;
} LABEL_RELEASE;

typedef struct
{
  PSB_KEY PsbKey;
  uns32 IfIndex;
  uns8 HoldPrio;
} BW_RELEASE;

typedef struct
{
  RSB_KEY RsbKey;
  FILTER_SPEC_OBJ FilterSpec;
} RESV_TEAR_NOTIF;

typedef struct
{
  PSB_KEY PsbKey;
  ERR_SPEC_OBJ ErrSpec;
} PATH_ERR_NOTIF;

typedef struct
{
  RSB_KEY RsbKey;
  uns8 FilterSpecValid;
  FILTER_SPEC_OBJ FilterSpec;
} PREEMPT_FLOW;

typedef struct
{
  uns32 IfIndex;
} IF_CMD;

typedef struct
{
  char IfName[20];
  IPV4_ADDR PeerAddr;
} SET_PEER_CMD;

typedef struct
{
  IPV4_ADDR IpAddress;
  uns8 PrefixLen;
  uns32 IfIndex;
} IP_ADDR_ADD_DEL_CMD;

typedef struct
{
  IPV4_ADDR Egress;
  uns16 TunnelId;
  uns16 LspId;
  uns8 RaValid;
  uns32 ExcludeAny;
  uns32 IncludeAny;
  uns32 IncludeAll;
  uns8 HoldPrio;
  uns8 SetPrio;
  uns8 Shared;
  uns8 FrrDesired;
  uns8 LabelRecordingDesired;
  uns16 HopNum;
  ER_HOP Path[100];
  float BW;
  IPV4_ADDR NextHop;
  uns32 OutIfIndex;
  IPV4_ADDR src_ip;
  uns32 sm_handle;
  IPV4_ADDR ErHops2Exclude[10];
} INGRESS_API;

typedef struct _te_api_msg_
{
  TE_NOTIFICATION_E NotificationType;
  union
  {
    PATH_NOTIFICATION PathNotification;
    RESV_NOTIFICATION ResvNotification;
    LABEL_RELEASE LabelRelease;
    BW_RELEASE BwRelease;
    RESV_TEAR_NOTIF ResvTearNotification;
    PATH_ERR_NOTIF PathErrNotification;
    PREEMPT_FLOW PreemptFlow;
    IF_CMD IfCmd;
    SET_PEER_CMD SetPeer;
    IP_ADDR_ADD_DEL_CMD IpAddrAddDel;
    INGRESS_API IngressApi;
    DEBUG_SEND_RESV_TEAR DebugSendResvTear;
  } u;
} TE_API_MSG;

#endif
#ifndef __LIB_API_MSG_H_
#define __LIB_API_MSG_H_

void rsvp_te_comm_init ();
E_RC rsvp_send_msg (void *pBuf, int pSize);
E_RC te_send_msg (void *pBuf, int pSize);

#endif

#ifndef __TE_API_STRUCT_H__
#define __TE_API_STRUCT_H__

#include "thread.h"

#define LSP_NAME_TYPE                 1
#define LSP_DEST_TYPE                 2
#define LSP_SRC_TYPE                  3
#define LSP_REMOVE_TYPE               4
#define ADAPTIVITY_TYPE               5
#define BW_TYPE                       6
#define COS_TYPE                      7
#define HOP_LIMIT_TYPE                8
#define OPTIMIZE_TIMER_TYPE           9
#define PREFERENCE_TYPE               10
#define PRIO_TYPE                     11
#define RECORD_TYPE                   12
#define STANDBY_TYPE                  13
#define FRR_TYPE                      14
#define METRIC_TYPE                   15
#define NO_DECREMENT_TTL_TYPE         16
#define BW_POLICY_TYPE                17
#define RETRY_TIMER_TYPE              18
#define RETRY_LIMIT_TYPE              19
#define PRIMARY_PATH_NAME_TYPE        20
#define SECONDARY_PATH_NAME_TYPE      21
#define EXPLICIT_PATH_NAME            22
#define NH_INDEX                      23
#define NH_LOOSE                      24
#define NH_IP_ADDRESS                 25
#define NO_FORM                       26
#define AFFINITY_TYPE                 27

typedef struct
{
  int Type;
  int Length;
} TL_HEADER;

typedef struct
{
  TL_HEADER tl_header;
  char data[1];
} TLV;

typedef enum
{
  EVENT_NEXT_HOP_ADD,
  EVENT_NEXT_HOP_DEL,
  EVENT_NEXT_HOP_DUMP,
  EVENT_TE_LINK_ADD,
  EVENT_TE_LINK_DEL,
  EVENT_TE_LINK_STATUS_CHANGE,
  EVENT_TE_LINK_DUMP,
  EVENT_CREATE_TE_PATH,
  EVENT_REMOTE_LS_UPDATE,
  EVENT_CONNECTIVITY_BROKEN,
  EVENT_OPEN_RSVP_LSP,
  EVENT_LSP_USER_SETUP,
  EVENT_CLOSE_RSVP_LSP,
  EVENT_ADD_IF_ADDR,
  EVENT_ENABLE_RSVP,
  EVENT_DISABLE_RSVP,
  EVENT_TE_LOG_CFG,
  EVENT_RSVP_LOG_CFG,
  EVENT_TE_SM,
  EVENT_RRO_CHANGED,
  EVENT_FRR_INFO_SET,
  EVENT_SET_ROUTER_ID,
  EVENT_READ_PATH_CASH,
  EVENT_CSPF_RETRY_EXPIRY,
  EVENT_LINK_2_RTR_ID_MAPPING,
  EVENT_LINK_2_RTR_ID_WITHDRAW,
  EVENT_IGP_HELLO,
  EVENT_DEL_IF_ADDR,
  EVENT_MAX = EVENT_DEL_IF_ADDR
} EVENTS_E;

typedef struct
{
  uns32 IfIndex;
  uns32 BackupOutIf;
//    V_CARD_ID    BackupVcardId;
  IPV4_ADDR MergeNodeIp;
  PSB_KEY PsbKey;
} FRR_DATA_SET;

typedef struct
{
  PSB_KEY PsbKey;
  uns32 IfIndex;
} BUMP_TUNNEL_T;

typedef struct
{
  IPV4_ADDR merge_node;
  uns32 OutIfIndex;
  IPV4_ADDR protected_node;
  IPV4_ADDR prohibited_penultimate_node;
} FRR_SM_KEY;

typedef struct _tunnel_id_list_
{
  IPV4_ADDR dest;
  uns16 tunnel_id;
  IPV4_ADDR source;
  struct _tunnel_id_list_ *next;
} TUNNEL_ID_LIST;

typedef struct _lsp_path_shared_params_
{
  BOOL disable;
  float BW;
  uns32 class_of_service;
  uns32 affinity_properties;
  uns32 affinity_mask;
  uns32 hop_limit;
  uns32 optimize_timer;
  uns32 preference;
  uns8 setup_priority;
  uns8 hold_priority;
  BOOL record;
  BOOL standby;
} LSP_PATH_SHARED_PARAMS;

typedef struct
{
  float BW;
  uns32 hop_limit;
  /* admin group */
} FAST_REROUTE;

typedef struct _secondary_path_list_
{
  char Secondary[16];
  LSP_PATH_SHARED_PARAMS *SecondaryPathParams;
  struct _secondary_path_list_ *next;
} SECONDARY_PATH_LIST;

typedef struct
{
  char LspName[32];
  IPV4_ADDR to;
  IPV4_ADDR from;
  LSP_PATH_SHARED_PARAMS lsp_params;
#if 0				/* Juniper's style */
  FAST_REROUTE *FastReroute;
#else
  BOOL FastReRoute;
#endif
  uns32 metric;
  BOOL no_decrement_ttl;
  uns32 bw_policy;
  uns32 retry_timer;
  uns32 retry_limit;
  uns32 retry_count;		/* NOT a User's parameter!!! */
  char Primary[16];
  LSP_PATH_SHARED_PARAMS *PrimaryPathParams;
  SECONDARY_PATH_LIST *SecondaryPaths;
  char PolicyName[32];
} USER_LSP_PARAMS;

typedef struct
{
  IPV4_ADDR dest_ip;
  float BW;
  uns16 sla_id;
} SLA_DATA;

typedef struct
{
  void *data;
} TE_SM_EVENT;

typedef struct
{
  uns32 IfIndex;
  uns32 IpAddr;
} INTERFACE_2_DESTINATION_T;

typedef struct
{
  uns32 OutIf;			/* Protected I/F */
  PSB_KEY PsbKey;		/* for Ingress LSPs */
  unsigned int Label;		/* IN label (0 if Ingress, use then PSB_KEY) */
  RR_SUBOBJ *pRro;
} RRO_CHANGED_HOOK;

typedef struct
{
  PSB_KEY key;
  uns32 handle;
  uns32 TeLinkId;
  uns32 OutIf;
  float BW;
  uns8 Priority;
} BW_HOLD_TIMER_DATA;

typedef struct
{
  PSB_KEY key;
} LSP_SETUP_TIMER_DATA;

typedef struct
{
  PSB_KEY key;
} ADAPTIVITY_TIMER_DATA;

typedef struct
{
  PSB_KEY key;
} LSP_SETUP_RETRY_TIMER_DATA;

typedef struct
{
  PSB_KEY key;
} CSPF_RETRY_TIMER_DATA;

typedef enum
{
  BW_HOLD_EXPIRY,
  LSP_SETUP_EXPIRY,
  ADAPTIVITY_EXPIRY,
  LSP_SETUP_RETRY_EXPIRY,
  BYPASS_TUNNEL_RETRY_EXPIRY,
  CSPF_RETRY_EXPIRY,
  MAX_TE_TMR
} TE_TMR_E;

typedef struct
{
  struct thread *thread;
  union
  {
    BW_HOLD_TIMER_DATA bw_hold_data;
    LSP_SETUP_TIMER_DATA lsp_setup_data;
    ADAPTIVITY_TIMER_DATA adaptivity_timer_data;
    LSP_SETUP_RETRY_TIMER_DATA lsp_setup_retry_data;
    FRR_SM_KEY bypass_retry_data;
    CSPF_RETRY_TIMER_DATA cspf_retry_data;
  } data;
  uns32 period;
  uns16 is_active;
  TE_TMR_E type;
} TE_TMR;

typedef struct
{
  IPV4_ADDR Dest;
  uns32 EgressIfId;
} TRUNK_KEY;

typedef struct
{
  unsigned int BypassTunnelsLabel;
  unsigned int MergeNodeLabel;
  uns32 OutIf;
  BOOL MergeNodeLabelValid;	/* In case of Merge Node is an Egress, MergeNodeLabel can be 0 */
  FRR_SM_KEY frr_key;		/* Who is FRR SM for this label/session */
  PSB_KEY PsbKey;		/* for searching the PSB on the LCC */
  IPV4_ADDR MergeNode;		/* for updating ERO */
} BACKUP_FORWARDING_INFORMATION;

typedef struct _rsvp_lsp_properties_
{
  float RequestedBW;		/* valid during modification */
  uns16 LspId;
//  uns32                        card;
  uns32 oIfIndex;
  uns32 Label;
  BOOL tunneled;
  union
  {
    struct
    {
      uns32 HopCount;
      IPV4_ADDR *pErHopsList;
      BACKUP_FORWARDING_INFORMATION BackupForwardingInformation;
    } path;
    PSB_KEY tunnel;
  } forw_info;
  uns8 SetupPriority;
  uns8 HoldPriority;
  uns32 ExcludeAny;
  uns32 IncludeAny;
  uns32 IncludeAll;
  uns8 FrrDesired;
  uns8 LabelRecordingDesired;
  struct _rsvp_lsp_properties_ *next;
} RSVP_LSP_PROPERTIES;

typedef struct _rsvp_tunnel_properties_
{
  uns16 TunnelId;
  uns16 LspId;			/* currrently used */
  float AllocatedBW;
  float RequiredBW;		/* for LSP modification */
  float ReservableBW;		/* for Tunnels & FA */
  void *sm_handle;		/* new ingress lsp or modified ingress lsp sm */
  uns32 Cost;			/* FA */
  uns32 ColorMask;		/* FA */
  BOOL ReRoute;			/* During recovery, to prevent multiple recovery */
  BOOL AdjustmentRequired;	/* For secondary tunnels only */
  uns16 LastInvokedLspId;	/* to pick up new RSVP LSP ID */
  struct _tunnel_id_list_ *pSecondaryTunnels;
  char UserLspName[32];
  char StaticPathName[16];
  TE_TMR lsp_setup_timer;
  TE_TMR adaptivity_timer;
  TE_TMR lsp_setup_retry_timer;
  TE_TMR cspf_retry_timer;
  void *up_sm_handle;
  void *pCrArgs;
  void *pOpenLspParams;
  RSVP_LSP_PROPERTIES *properties;
  struct _rsvp_tunnel_properties_ *next;
  struct _rsvp_tunnel_properties_ *next_user_lsp_tunnel;
} RSVP_TUNNEL_PROPERTIES;


typedef struct _user_lsp_
{
  USER_LSP_PARAMS params;
  char CurrentSecondaryPathName[16];
  uns16 BackupTunnelId;
  //TUNNEL_ID_LIST  *TunnelIdList;
  RSVP_TUNNEL_PROPERTIES *pUserLspTunnels;
} USER_LSP;

typedef struct _user_lsp_list_
{
  USER_LSP *lsp;
  struct _user_lsp_list_ *next;
} USER_LSP_LIST;

typedef struct
{
  IPV4_ADDR dest;
  uns16 sla_id;
} SLA_KEY;

typedef struct
{
  PATRICIA_NODE Node;
  SLA_KEY sla_key;
  float BW;
  struct _tunnels_list_ /*TUNNELS_LIST */ *pTunnelsList;
} SLA_ENTRY;

typedef struct
{
  float RequiredBW;
  float ActualBW;
  float UserRequiredBW;
  uns32 sm_handle;		/* adaptivity sm */
} TRUNK_DATA;

typedef struct
{
  PATRICIA_NODE Node;
  TRUNK_KEY trunk_key;
  RSVP_TUNNEL_PROPERTIES *Lsps;
  TRUNK_DATA *pTrunkData;
  uns32 TunnelsCounter;
} TRUNK_ENTRY;

typedef struct
{
  PATRICIA_NODE Node;
  unsigned int label;
  uns32 OutIf;
  unsigned int ReceivedOutLabel;
  //V_CARD_ID                     allocator; /* needed for FRR */
  uns32 IfIndex;		/* needed for FRR */
  BACKUP_FORWARDING_INFORMATION BackupForwardingInformation;
} LABEL_ENTRY;

typedef struct _bw_owner_data_
{
  uns32 TeLinkId;
  uns32 OutIf;
  //V_CARD_ID        vcard;
  float BW;
  float PreAllocBW;
  TE_TMR BwHoldTimer;
  struct _bw_owner_data_ *next;
} BW_OWNER_DATA;

typedef struct
{
  PATRICIA_NODE Node;
  PSB_KEY key;
  BW_OWNER_DATA *pBwOwnerData;
} BW_OWNER_ENTRY;

/**************************************************************************
 *                                                                        *
 *                                                                        *
 *            ANSI Function Prototypes for internal functions             *
 *                                                                        *
 *                                                                        *
 *                                                                        *
 *************************************************************************/

extern int ExitFlag;
extern int VcardId;

#ifdef FATAL_ERROR
#undef FATAL_ERROR
#endif

#define FATAL_ERROR(x)  if(x == NULL) \
{\
   LogMsg(ERROR_OUTPUT,"fatal error at %s %d",__FILE__,__LINE__);\
   return -1;\
}
extern char if_ip_addr_str[4][16];
extern char peer_ip_addr_str[5][16];
extern IPV4_ADDR peer_ip_addr[5];
extern int lsr_id_ifc;

typedef struct ip_addr_ll
{
  char *ip_addr;
  struct ip_addr_ll *next;
} tIpAddrLl;

typedef enum
{
  SEPARATE_NON_ADAPTIVE,
  SEPARATE_ADAPTIVE,
  NON_SEPARATE_SERVICE,
  NON_SEPARATE_SERVICE_BW_ADAPTIVE,
  NON_SEPARATE_TUNNELS,
  ALL_TRUNKS
} TRUNK_TYPE;

typedef struct
{
  EVENTS_E event;
  union
  {
    USER_LSP user_lsp;
    SLA_DATA sla_data;
    BW_HOLD_TIMER_DATA bw_hold_timer_expiry;
    LSP_SETUP_TIMER_DATA lsp_setup_timer_expiry;
    ADAPTIVITY_TIMER_DATA adaptivity_timer_expiry;
    LSP_SETUP_RETRY_TIMER_DATA lsp_setup_retry_timer_expiry;
    TE_SM_EVENT te_sm_event;
    INTERFACE_2_DESTINATION_T interface_2_destination;
//       FRR_SM_KEY bypass_retry_expiry;
    FRR_DATA_SET frr_data_set;
    CSPF_RETRY_TIMER_DATA cspf_retry_data;
  } u;
} TE_MSG;

#define DATA_PLANE 1
#define MPLS_TE_DB 1

#endif

