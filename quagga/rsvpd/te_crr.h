
#ifndef __CONSTRAINT_ROUTE_RESOLUTION_SM_H__
#define __CONSTRAINT_ROUTE_RESOLUTION_SM_H__

typedef enum
{
  CONSTAINT_ROUTE_RESOLUTION_SM_ADAPTIVITY_STATE = INIT_STATE + 1,
  CONSTRAINT_ROUTE_RESOLUTION_SM_MAX_STATE
} CONSTRAINT_ROUTE_RESOLUTION_SM_STATE_E;

typedef enum
{
  LOCAL_IF_DEST,
  NEXT_HOP_DEST,
  INTRA_AREA_DEST,
  OUT_OF_AREA_DEST,
  UNKNOWN_DEST
} DESTINATION_TYPE_E;

typedef enum
{
  OUTPUT_EGRESS,
  OUTPUT_NEXT_HOP,
  OUTPUT_PATH,
  OUTPUT_LSP,
  OUTPUT_LSP_SETUP_PENDING,
  OUTPUT_UNREACHABLE,
  OUTPUT_CAC_FAILED
} CONSTRAINT_ROUTE_RESOLUTION_RC_E;

typedef struct
{
  IPV4_ADDR dest;		/* IN */
  float BW;			/* IN */
  uns32 ExclColorMask;		/* IN */
  uns32 InclAnyColorMask;	/* IN */
  uns32 InclColorMask;		/* IN */
  uns32 HopCount;		/* IN */
  PSB_KEY PsbKey;		/* IN */
  uns32 AvoidHopNumber;		/* IN */
  IPV4_ADDR *AvoidHopsArray;	/* IN */
  uns32 ExcludeHopNumber;	/* IN */
  IPV4_ADDR *ExcludeHopsArray;	/* IN */
  uns32 LinkBwNumber;		/* IN */
  void *pLinkBw;		/* IN */
  uns8 SetupPriority;		/* IN */
  uns8 HoldPriority;		/* IN */
  uns32 OutIf;			/* OUT */
  IPV4_ADDR OutNHop;		/* OUT */
  BOOL tunneled;
  union
  {
    struct
    {
      uns32 ErHopNumber;	/* OUT */
      IPV4_ADDR *pErHop;	/* OUT */
    } path;
    PSB_KEY tunnel;
  } data;
  CONSTRAINT_ROUTE_RESOLUTION_RC_E rc;
} CONSTRAINT_ROUTE_RESOLUTION_ARGS;

typedef struct cr_req_list
{
  void *pSm;
  void *pParentSm;
  struct cr_req_list *next;
} CR_REQUESTS_LIST;

typedef struct
{
  PATRICIA_NODE Node;
  IPV4_ADDR dest;
  CR_REQUESTS_LIST *pCrReqList;
} CR_REQ_NODE;

typedef struct
{
  int handle;
  int instance;
} CR_CLIENT_KEY;

typedef struct
{
  PATRICIA_NODE Node;
  CR_CLIENT_KEY key;
  IPV4_ADDR dest;
} CR_CLIENT_NODE;

typedef struct
{
  CONSTRAINT_ROUTE_RESOLUTION_ARGS *args;
} CONSTRAINT_ROUTE_RESOLUTION_SM_DATA;

extern PATRICIA_TREE ConstraintRouteResReqTree;
extern PATRICIA_TREE ConstraintRouteResClientsTree;
SM_CALL_T *constraint_route_resolution_sm_invoke (SM_T * caller, void *data);
SM_CALL_T *constraint_route_resolution_sm_handler (SM_T * pSm,
						   SM_EVENT_T * sm_data);

int SelectPath (PATH_L_LIST * pPaths,
		CONSTRAINT_ROUTE_RESOLUTION_ARGS * args, PATH ** ppPath);
int SelectOutIf (TE_LINK_L_LIST * pTeLinks,
		 uns32 * OutIf,
		 CONSTRAINT_ROUTE_RESOLUTION_ARGS * args,
		 BOOL PerformAllocation);
void CspfReply (IPV4_ADDR dest, void *handle);

void UnregisterClient (int handle, int TunnelId);

#endif
