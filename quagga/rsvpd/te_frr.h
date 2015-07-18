#ifndef __FAST_REROUTE_H_
#define __FAST_REROUTE_H_

typedef enum
{
  FAST_REROUTE_SM_UP_STATE = INIT_STATE + 1,
  FAST_REROUTE_RETRY_STATE,
  FAST_REROUTE_SM_MAX_STATE
} FAST_REROUTE_SM_STATE_E;

typedef struct
{
  PATRICIA_NODE Node;
  unsigned int Label;
} FRR_LABEL_ENTRY;

typedef struct
{
  PATRICIA_NODE Node;
  PSB_KEY PsbKey;
} FRR_INGRESS_ENTRY;

typedef struct
{
  FRR_SM_KEY frr_key;
  PSB_KEY PsbKey;
  unsigned int Label;
  IPV4_ADDR MergeNode;
} FRR_SM_CALL;

typedef struct
{
  PATRICIA_NODE Node;
  FRR_SM_KEY frr_key;
  uns32 sm_handle;
  PATRICIA_TREE labels_tree;
  PATRICIA_TREE ingress_tree;
  uns16 BypassTunnelId;
  TE_TMR bypass_retry_timer;
} FRR_SM_ENTRY;

typedef struct
{
  FRR_SM_ENTRY FrrSmEntry;
  unsigned int BypassTunnelsLabel;
  uns32 BackupOutIf;
  //V_CARD_ID    card;
} FRR_SM_DATA;

SM_CALL_T *fast_reroute_sm_handler (HANDLE sm_handle, SM_EVENT_T * sm_data);

#endif
