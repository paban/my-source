
#ifndef __LSP_SM_H__
#define __LSP_SM_H__

typedef enum
{
  LSP_SM_MAX_STATE = INIT_STATE + 1
} LSP_SM_STATE_E;

typedef struct
{
  TUNNEL_ID_LIST *TunnelIdHead;
} LSP_SM_DATA;

typedef enum
{
  SETUP_COMPLETE_NOTIF,
  SETUP_FAILED_NOTIF,
  TEAR_DOWN_NOTIF
} LSP_NOTIF_E;

typedef struct
{
  uns32 Label;
  uns16 LspId;
} LSP_LABEL;

typedef struct
{
  uns32 NumberOfItems;
  float BW;
  LSP_LABEL *pLspLabel;
} SETUP_COMPLETE;

typedef struct
{
  uns16 LspId;
  IPV4_ADDR IpAddr;
} SETUP_FAILED;

typedef struct
{
  uns32 NumberOfItems;
  union
  {
    uns16 LspId;
    uns16 *pLsps;
  } Lsps;
} TUNNEL_DOWN_T;

typedef struct
{
  PSB_KEY PsbKey;
  LSP_NOTIF_E ingress_lsp_notif;
  union
  {
    SETUP_COMPLETE setup_complete;
    SETUP_FAILED setup_failed;
    TUNNEL_DOWN_T tunnel_down;
  } data;
} LSP_SM_NOTIF_DATA;

typedef struct
{
  IPV4_ADDR dest;
  uns16 tunnel_id;
} LSP_SM_REPLY;

SM_CALL_T *lsp_sm_handler (SM_T * pSm, SM_EVENT_T * sm_data);

SM_CALL_T *lsp_sm_sync_invoke (SM_T * caller, void *data, SM_EVENT_E event);

RSVP_LSP_PROPERTIES *GetWorkingRsvpLsp (RSVP_TUNNEL_PROPERTIES * pTunnel);
RSVP_LSP_PROPERTIES *CurrentPathHasAvBw (RSVP_TUNNEL_PROPERTIES * pTunnel,
					 float BW);

#endif
