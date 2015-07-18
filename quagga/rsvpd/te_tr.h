
#ifndef __TRANSIT_REQ_SM_H__
#define __TRANSIT_REQ_SM_H__

typedef enum
{
  TRANSIT_REQ_SM_CONSTRAINT_ROUTE_RESOLUTION_STATE = INIT_STATE + 1,
  TRANSIT_REQ_SM_MAX_STATE
} TRANSIT_REQ_SM_STATE_E;

typedef struct
{
  PATH_NOTIFICATION *pTransitReqParams;
} TRANSIT_REQ_SM_DATA;

SM_CALL_T *transit_req_sm_handler (SM_T * pSm, SM_EVENT_T * sm_data);

#endif
