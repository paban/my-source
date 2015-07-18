/* Module:   lsp_sm.c
   Contains: TE application LSP (tunnel) state machine
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */
#include "te.h"
#include "te_cspf.h"

typedef enum
{
    WORKING_LSP_FAILED,
    NEW_LSP_FAILED
}RECOVERY_TYPE_E;

void LspSmDestroy(SM_T *pSm);
void UserLspDestroy(USER_LSP *pUserLsp);
E_RC SetErHopList(STATIC_PATH *pStaticPath,ER_HOP **ppErHopsList);
SM_CALL_T *ProcessPrimaryLsp(USER_LSP *pCurrentUserLsp,
                             USER_LSP *pUserLsp,
                             SM_T *pSm,
                             char *PrimaryLspPathName);
RSVP_TUNNEL_PROPERTIES *GetSecondaryTunnel2Reroute(USER_LSP *pUserLsp,
                                                   USER_LSP *pCurrentUserLsp);
SM_CALL_T *ProcessSecondaryPaths(USER_LSP *pCurrentUserLsp,
                                 USER_LSP *pUserLsp,
                                 SM_T *pSm,
                                 char *PrimaryLspPathName,
                                 BOOL PrimaryLspOperation);
uns32 StartAdaptivityTimer(uns32 optimize_timer,
                           RSVP_TUNNEL_PROPERTIES *pTunnel);

void StopAdaptivityTimer(RSVP_TUNNEL_PROPERTIES *pTunnel);
uns32 StartLspSetupTimer(RSVP_TUNNEL_PROPERTIES *pTunnel);
void StopLspSetupTimer(RSVP_TUNNEL_PROPERTIES *pTunnel);
uns32 StartLspSetupRetryTimer(uns32 retry_timer,uns32 *retry_count,RSVP_TUNNEL_PROPERTIES *pTunnel);
void StopLspSetupRetryTimer(RSVP_TUNNEL_PROPERTIES *pTunnel);
SM_CALL_T *LspSetupExpiry(PSB_KEY *PsbKey,SM_T *pSm);
SM_CALL_T *AdaptivityExpiry(PSB_KEY *PsbKey,SM_T *pSm);
SM_CALL_T *LspSetupRetryExpiry(PSB_KEY *PsbKey,SM_T *pSm);
SM_CALL_T *CspfRetryExpiry(PSB_KEY *PsbKey,SM_T *pSm);
void TearDownAndRemoveSecondary(USER_LSP *pCurrentUserLsp,char *PathName);
void CalculateUnneededPathAndTearDown(USER_LSP *pUserLsp,USER_LSP *pCurrentUserLsp);
SM_CALL_T *PrepareAndIssueCrResolutionRequest(INGRESS_API *pOpenLspParams,
                                              uns32       AvoidHopNumber,
                                              IPV4_ADDR    *AvoidHopsArray,
                                              RSVP_TUNNEL_PROPERTIES *pTunnel,
                                              SM_T *pSm,
                                              LSP_PATH_SHARED_PARAMS *pParams);
SM_CALL_T *LspRequest(INGRESS_API *pOpenLspParams,
                      uns32       ExcludeHopNumber,
                      IPV4_ADDR   *ExcludeHopsArray,
                      SM_T    *pSm,
                      RSVP_TUNNEL_PROPERTIES **ppTunnel,
                      BOOL        ForceCrResolution,
                      LSP_PATH_SHARED_PARAMS *pParams);

BOOL NewRsvpLspRequired(RSVP_TUNNEL_PROPERTIES *pTunnel,INGRESS_API *pOpenLspParams);
RSVP_LSP_PROPERTIES *FindRsvpLspPathWithBW(RSVP_TUNNEL_PROPERTIES *pTunnel,float BW);
void NotifySatisfiedRequests(RSVP_TUNNEL_PROPERTIES *pTunnel);
void NotifyFailedRequests(RSVP_TUNNEL_PROPERTIES *pTunnel);
uns16 NewRsvpLspId(RSVP_TUNNEL_PROPERTIES *pTunnel);
uns32 CopyRsvpLspPath(RSVP_LSP_PROPERTIES *pRsvpLsp,INGRESS_API *pOpenRsvpLsp);
RSVP_LSP_PROPERTIES *GetWorkingRsvpLsp(RSVP_TUNNEL_PROPERTIES *pTunnel);
uns32 CopyWorkingPath(RSVP_LSP_PROPERTIES *pDestRsvpLsp,RSVP_LSP_PROPERTIES *pSourceRsvpLsp);
BOOL IdenticalRsvpLspExists(RSVP_TUNNEL_PROPERTIES *pTunnel,RSVP_LSP_PROPERTIES *pThisRsvpLsp,uns16 *LspDiffPathSameParams);
void UpdatePathBW(RSVP_TUNNEL_PROPERTIES *pTunnel,RSVP_LSP_PROPERTIES *pCurrentRsvpLsp,IPV4_ADDR dest);
uns32 CreateAndInvokeRsvpLsp(RSVP_TUNNEL_PROPERTIES *pTunnel,
                             RSVP_LSP_PROPERTIES *pRsvpLsp2TakePath,
                             BOOL tunneled,
                             PSB_KEY *PsbKey);
uns32 RsvpTunnelTearDown(RSVP_TUNNEL_PROPERTIES *pTunnel,IPV4_ADDR dest,IPV4_ADDR source);
void RemoveRsvpLsp(RSVP_TUNNEL_PROPERTIES *pTunnel,uns16 LspId,IPV4_ADDR dest,IPV4_ADDR source);
RSVP_LSP_PROPERTIES *FindRsvpLspByLspId(RSVP_TUNNEL_PROPERTIES *pTunnel,uns16 LspId);
void FindClosestRsvpLsp(RSVP_TUNNEL_PROPERTIES *pTunnel,
                        SETUP_COMPLETE *setup_complete,
                        float *BW,
                        uns16 *LspId);
SM_CALL_T *DetermineWorkingLspAndTearUnneeded(RSVP_TUNNEL_PROPERTIES *pTunnel,
                                              float BW,
                                              uns16 LspId,
                                              IPV4_ADDR dest,
                                              IPV4_ADDR source,
                                              SM_T *pSm);
RSVP_LSP_PROPERTIES *GetRsvpLspMaxBW(RSVP_TUNNEL_PROPERTIES *pTunnel,uns16 LspId,float MaxBw);
IPV4_ADDR GetLastErHop(RSVP_LSP_PROPERTIES *pRsvpLsp);
BOOL IsPathEqual(PATH *pPath,IPV4_ADDR *IpAddrList);
PATH *FindRsvpLspPath(PATH_L_LIST *pPaths,RSVP_LSP_PROPERTIES *pRsvpLsp);
uns16 GetSecondaryUserLspId(RSVP_TUNNEL_PROPERTIES *pTunnel,char *pSecondaryPathName);
uns32 AddSecondaryTunnel(USER_LSP *pUserLsp,RSVP_TUNNEL_PROPERTIES *pSecondaryTunnel);
void CleanSecodaryPaths(USER_LSP *pUserLsp);
void CleanUserLsp(USER_LSP *pUserLsp);
void CopyUserLsp(USER_LSP *pDestLsp,USER_LSP *pSrcLsp);
LSP_PATH_SHARED_PARAMS *PathParamsGet(USER_LSP *pUserLsp,char *PathName,uns8 IsPrimary);
RSVP_TUNNEL_PROPERTIES *StaticPathIsUsed(USER_LSP *pUserLsp,char *PathName);
SM_CALL_T *UserPrimaryLspRecovery(RSVP_TUNNEL_PROPERTIES *pTunnel,SM_T *pSm,RECOVERY_TYPE_E recovery_type,IPV4_ADDR exclude_node);
SM_CALL_T *UserSecondaryLspRecovery(RSVP_TUNNEL_PROPERTIES *pTunnel,SM_T *pSm,IPV4_ADDR exclude_node);
SM_CALL_T *UserLspFailed(RSVP_TUNNEL_PROPERTIES *pTunnel,SM_T *pSm,IPV4_ADDR exclude_node);
uns32 GetTunnelHops(RSVP_TUNNEL_PROPERTIES *pTunnel,uns32 *ErHopNumber,IPV4_ADDR **ppErHops);
BOOL TunnelsHaveSharedErHops(IPV4_ADDR *pFirstArray,
                             uns32 FirstArraySize,
                             IPV4_ADDR *pSecondArray,
                             uns32 SecondArraySize);
SM_CALL_T *ModifySecondary(RSVP_TUNNEL_PROPERTIES *pTunnel,
                           SM_T *pSm,
                           STATIC_PATH *pPrimaryStaticPath,
                           USER_LSP *pUserLsp);
SM_CALL_T *OptimizeSingleLsp(RSVP_TUNNEL_PROPERTIES *pTunnel,IPV4_ADDR dest,IPV4_ADDR source);
static void StopCspfRetryTimer(RSVP_TUNNEL_PROPERTIES *pTunnel);
static E_RC GetAlreadyAllocatedBW(RSVP_TUNNEL_PROPERTIES *pTunnel,void **ppLinkBw,uns32 *LinkBwNumber,float CommonBwValue);

int LspSetupTimeOut = 30;

static SM_CALL_T *lsp_sm_empty_handler(SM_T *pSm,SM_EVENT_T *sm_data)
{
    zlog_err("lsp_sm_empty_handler, state %d",pSm->state);
    return NULL;
}

static SM_CALL_T *lsp_sm_init(SM_T *pSm,SM_EVENT_T *sm_event)
{
    SM_CALL_T *pCall = NULL;
    RSVP_TUNNEL_PROPERTIES *pTunnel = NULL;
    PSB_KEY PsbKey;
    INGRESS_API *pOpenLspParams = NULL;
    USER_LSP *pUserLsp,*pCurrentUserLsp;
    LSP_SM_DATA *pLspSmData;
    CONSTRAINT_ROUTE_RESOLUTION_ARGS *pCrArgs;
    LSP_SM_NOTIF_DATA *pLspSmNotifData;
    uns16 LspId = 0;
    float BW = 0;
    int i;
    char PrimaryLspPathName[16];
    
    pLspSmData = pSm->data;

    switch(sm_event->event)
    {
    case USER_LSP_REQUEST_EVENT:
        sm_gen_event_trace(sm_event->event);
        pUserLsp = sm_event->data;
        if((pCurrentUserLsp = UserLspGet(pUserLsp->params.LspName)) == NULL)
        {
            if(pUserLsp->params.to == 0)
            {
                zlog_err("LSP's destination cannot be 0 %s %d",__FILE__,__LINE__);
                CleanSecodaryPaths(pUserLsp);
                CleanUserLsp(pUserLsp);
                XFREE(MTYPE_TE,pUserLsp);
                return NULL;
            }
            if(pUserLsp->params.lsp_params.disable == TRUE)
            {
                zlog_err("User LSP to be deleted is not found! %s %d",__FILE__,__LINE__);
                CleanSecodaryPaths(pUserLsp);
                CleanUserLsp(pUserLsp);
                XFREE(MTYPE_TE,pUserLsp);
                return NULL;
            }
            if(UserLspAdd(pUserLsp) != E_OK)
            {
                zlog_err("cannot add user LSP %s %d",__FILE__,__LINE__);
                return NULL;
            }
            pCurrentUserLsp = pUserLsp;
        }
        if(pUserLsp->params.lsp_params.disable == TRUE)
        {
            UserLspDestroy(pCurrentUserLsp);
            zlog_info("Cleaning up the UserLsp memory");
            if(pCurrentUserLsp != pUserLsp)
            {
                if(UserLspDelete(pCurrentUserLsp->params.LspName) != E_OK)
                {
                    zlog_err(
                           "A problem occured while deleting an User LSP %s %d",__FILE__,__LINE__);
                }
            }
            CleanSecodaryPaths(pUserLsp);
            CleanUserLsp(pUserLsp);
            XFREE(MTYPE_TE,pUserLsp);
            LspSmDestroy(pSm);
            return NULL;
        }
        pUserLsp->params.to = pCurrentUserLsp->params.to;
        if(pUserLsp != pCurrentUserLsp)
            CalculateUnneededPathAndTearDown(pUserLsp,pCurrentUserLsp);
        
        pCall = ProcessPrimaryLsp(pCurrentUserLsp,pUserLsp,pSm,PrimaryLspPathName);
        
        ProcessSecondaryPaths(pCurrentUserLsp,
                              pUserLsp,
                              pSm,
                              PrimaryLspPathName,
                              (pCall == NULL) ? FALSE : TRUE);
        zlog_info(
            "After secondary %s %s %s",
             PrimaryLspPathName,pCurrentUserLsp->params.Primary,pUserLsp->params.Primary);
        if(pCurrentUserLsp != pUserLsp)
        {
            if((pUserLsp->params.retry_timer != pCurrentUserLsp->params.retry_timer)||
               (pUserLsp->params.retry_limit != pCurrentUserLsp->params.retry_limit))
            {
               pCurrentUserLsp->params.retry_count = pUserLsp->params.retry_limit;
               if(pCurrentUserLsp->pUserLspTunnels != NULL)
               {
                  StartLspSetupRetryTimer(pUserLsp->params.retry_timer,
                                          &pCurrentUserLsp->params.retry_count,
                                          pCurrentUserLsp->pUserLspTunnels);
               }
            }
            CopyUserLsp(pCurrentUserLsp,pUserLsp);
            XFREE(MTYPE_TE,pUserLsp);
        }
        break;
    case INGRESS_LSP_REQUEST_EVENT:
        sm_gen_event_trace(sm_event->event);
        pOpenLspParams = sm_event->data;
        pCall = LspRequest(pOpenLspParams,0,NULL,pSm,&pTunnel,FALSE,NULL);
        break;
    case INGRESS_LSP_DELETE_REQUEST_EVENT:
        sm_gen_event_trace(sm_event->event);
        memset(&PsbKey,0,sizeof(PSB_KEY));
        pOpenLspParams = sm_event->data;
        PsbKey.Session.Dest = pOpenLspParams->Egress;
        PsbKey.Session.TunnelId = pOpenLspParams->TunnelId;
        PsbKey.Session.ExtTunelId = pOpenLspParams->src_ip;
        pOpenLspParams->BW = 0;
        if(FindTunnel(&PsbKey,&pTunnel,ALL_TRUNKS) == TRUE)
        {
            if(RsvpTunnelTearDown(pTunnel,pOpenLspParams->Egress,pOpenLspParams->src_ip) != E_OK)
            {
                zlog_err("can not complete RSVP tunnel tear down %s %d",__FILE__,__LINE__);
            }
            XFREE(MTYPE_TE,pOpenLspParams);
        }
        else
            zlog_err("Required RSVP tunnel is not found!!! %s %d",__FILE__,__LINE__);
        /*LspSmDestroy(pSm);*/
        break;
    case LSP_SETUP_TIMER_EXPIRY:
        sm_gen_event_trace(sm_event->event);
        pCall = LspSetupExpiry(sm_event->data,pSm);
        break;
    case ADAPTIVITY_TIMER_EXPIRY:
        pCall = AdaptivityExpiry(sm_event->data,pSm);
        break;
    case RETRY_TIMER_EXPIRY:
        sm_gen_event_trace(sm_event->event);
        pCall = LspSetupRetryExpiry(sm_event->data,pSm);
        break;
    case CSPF_RETRY_EVENT:
        sm_gen_event_trace(sm_event->event);
        pCall = CspfRetryExpiry(sm_event->data,pSm);
        break;
    case CONSTRAINT_ROUTE_RESOLVED_EVENT:
        sm_gen_event_trace(sm_event->event);

        pCrArgs = sm_event->data;

        if(FindTunnel(&pCrArgs->PsbKey,&pTunnel,ALL_TRUNKS) != TRUE)
        {
            zlog_err("cannot find tunnel Dest %x Tunnel %x %s %d",
                pCrArgs->PsbKey.Session.Dest,
                pCrArgs->PsbKey.Session.TunnelId,
                __FILE__,__LINE__);
            XFREE(MTYPE_TE,pCrArgs);
            return NULL;
        }
        if((pCrArgs->tunneled == FALSE)&&
           (pCrArgs->data.path.pErHop != NULL)&&
           (pCrArgs->data.path.ErHopNumber != 0))
        {                                                                                
            int i;
            zlog_info("Not tunneled, with path");
                              
            zlog_info("Insertion of returned ER hops...");
            for(i = 0;i < pCrArgs->data.path.ErHopNumber;i++)
            {
                ((INGRESS_API *)(pTunnel->pOpenLspParams))->Path[i].IpAddr = pCrArgs->data.path.pErHop[i];
                ((INGRESS_API *)(pTunnel->pOpenLspParams))->Path[i].PrefixLength = 32;
            }
            zlog_info("Insertion of received %d ER hops...",pCrArgs->data.path.ErHopNumber);
            for(i = pCrArgs->data.path.ErHopNumber;
                i < (((INGRESS_API *)(pTunnel->pOpenLspParams))->HopNum + pCrArgs->data.path.ErHopNumber);
                i++)
            {
                ((INGRESS_API *)(pTunnel->pOpenLspParams))->Path[i].IpAddr
                    = ((INGRESS_API *)(pTunnel->pOpenLspParams))->Path[i - pCrArgs->data.path.ErHopNumber].IpAddr;
                ((INGRESS_API *)(pTunnel->pOpenLspParams))->Path[i].PrefixLength = 32;
            }
            zlog_info("Done...");
            ((INGRESS_API *)(pTunnel->pOpenLspParams))->HopNum += pCrArgs->data.path.ErHopNumber;
        }
        else if(pCrArgs->tunneled == TRUE)
        {
            /*pRequest->pOpenLspParams*/
        }
        zlog_info("NextHop %x %s %d",pCrArgs->OutNHop,__FILE__,__LINE__);
        ((INGRESS_API *)(pTunnel->pOpenLspParams))->OutIfIndex = pCrArgs->OutIf;
        ((INGRESS_API *)(pTunnel->pOpenLspParams))->NextHop = pCrArgs->OutNHop;
        if(CreateAndInvokeRsvpLsp(pTunnel,
                                  NULL,
                                  pCrArgs->tunneled,
                                  (pCrArgs->tunneled == TRUE) ?
                                  &pCrArgs->data.tunnel : NULL) != E_OK)
        {
            zlog_err("cannot copy path for RSVP LSP %s %d",__FILE__,__LINE__);
            LspSmDestroy(pSm);
            return NULL;
        }
        if((pCrArgs->tunneled == FALSE)&&
           (pCrArgs->data.path.ErHopNumber != 0))
        {
            XFREE(MTYPE_TE,pCrArgs->data.path.pErHop);
        }
        if(pCrArgs->AvoidHopNumber != 0)
        {
            XFREE(MTYPE_TE,pCrArgs->AvoidHopsArray);
        }
        if(pCrArgs->ExcludeHopNumber != 0)
        {
            XFREE(MTYPE_TE,pCrArgs->ExcludeHopsArray);
        }
        if(pCrArgs->LinkBwNumber)
        {
            XFREE(MTYPE_TE,pCrArgs->pLinkBw);
            pCrArgs->pLinkBw = NULL;
            pCrArgs->LinkBwNumber = 0;
        }
        XFREE(MTYPE_TE,pCrArgs);
        pTunnel->pCrArgs = NULL;
        StopCspfRetryTimer(pTunnel);
//        return NULL;
        break;
    case CONSTRAINT_ROUTE_RESOLVE_FAILED_EVENT:
        sm_gen_event_trace(sm_event->event);
        break;
    case MPLS_SIGNALING_INGRESS_ESTABLISHED_NOTIFICATION_EVENT:
        sm_gen_event_trace(sm_event->event);
                
        pLspSmNotifData = sm_event->data;
       
        if(FindTunnel(&pLspSmNotifData->PsbKey,&pTunnel,ALL_TRUNKS) != TRUE)
        {
            zlog_err("cannot find tunnel Dest %x Tunnel %x %s %d",
                pLspSmNotifData->PsbKey.Session.Dest,
                pLspSmNotifData->PsbKey.Session.TunnelId,
                __FILE__,__LINE__);
            XFREE(MTYPE_TE,pLspSmNotifData);
            return NULL;
        }

        StopLspSetupTimer(pTunnel);

        if((pTunnel->properties != NULL)&&
            (pTunnel->properties->next == NULL)&&
            (pTunnel->properties->LspId == pTunnel->LspId))
        {
            if(pLspSmNotifData->data.setup_complete.pLspLabel)
            {
                XFREE(MTYPE_TE,pLspSmNotifData->data.setup_complete.pLspLabel);
            }
            XFREE(MTYPE_TE,pLspSmNotifData);
            return NULL;
        }
        
        FindClosestRsvpLsp(pTunnel,&pLspSmNotifData->data.setup_complete,&BW,&LspId);

        pCall = DetermineWorkingLspAndTearUnneeded(pTunnel,
                                                   BW,
                                                   LspId,
                                                   pLspSmNotifData->PsbKey.Session.Dest,
                                                   pLspSmNotifData->PsbKey.Session.ExtTunelId,
                                                   pSm);

                                
        pUserLsp = UserLspGet(pTunnel->UserLspName);
        if((pUserLsp != NULL)&&(pUserLsp->pUserLspTunnels != NULL)&&
            (pTunnel->TunnelId == pUserLsp->pUserLspTunnels->TunnelId))
        {
            if(strcmp(pTunnel->StaticPathName,pUserLsp->params.Primary) == 0)
            {
                if(strcmp(pUserLsp->CurrentSecondaryPathName,"") != 0)
                {
                    zlog_info("Current Secondary Path Name %s Primary Path Name %s",
                        pUserLsp->CurrentSecondaryPathName,pUserLsp->params.Primary);
                    pUserLsp->CurrentSecondaryPathName[0] = '\0';
                    
                    if(pUserLsp->params.retry_count != pUserLsp->params.retry_limit)
                        pUserLsp->params.retry_count = pUserLsp->params.retry_limit;
                    StopLspSetupRetryTimer(pTunnel);
                }
            }
        }
        
        if(pLspSmNotifData->data.setup_complete.pLspLabel)
        {
            XFREE(MTYPE_TE,pLspSmNotifData->data.setup_complete.pLspLabel);
        }
        XFREE(MTYPE_TE,pLspSmNotifData);
                
        NotifySatisfiedRequests(pTunnel);
        break;
    case MPLS_SIGNALING_INGRESS_FAILED_NOTIFICATION_EVENT:
        sm_gen_event_trace(sm_event->event);
         
        pLspSmNotifData = sm_event->data;

        if(FindTunnel(&pLspSmNotifData->PsbKey,&pTunnel,ALL_TRUNKS) != TRUE)
        {
            zlog_err("cannot find tunnel Dest %x Tunnel %x %s %d",
                pLspSmNotifData->PsbKey.Session.Dest,
                pLspSmNotifData->PsbKey.Session.TunnelId,
                __FILE__,__LINE__);
            XFREE(MTYPE_TE,pLspSmNotifData);
            return NULL;
        }
        
        switch(pLspSmNotifData->ingress_lsp_notif)
        {
        case SETUP_FAILED_NOTIF:
            RemoveRsvpLsp(pTunnel,
                          pLspSmNotifData->data.setup_failed.LspId,
                          pLspSmNotifData->PsbKey.Session.Dest,
                          pLspSmNotifData->PsbKey.Session.ExtTunelId);
            break;
        case TEAR_DOWN_NOTIF:
            if(pLspSmNotifData->data.tunnel_down.NumberOfItems == 1)
            {
                RemoveRsvpLsp(pTunnel,
                              pLspSmNotifData->data.tunnel_down.Lsps.LspId,
                              pLspSmNotifData->PsbKey.Session.Dest,
                              pLspSmNotifData->PsbKey.Session.ExtTunelId);
            }
            else
            {
                for(i = 0;i < pLspSmNotifData->data.tunnel_down.NumberOfItems;i++)
                {            
                    RemoveRsvpLsp(pTunnel,
                                  pLspSmNotifData->data.tunnel_down.Lsps.pLsps[i],
                                  pLspSmNotifData->PsbKey.Session.Dest,
                                  pLspSmNotifData->PsbKey.Session.ExtTunelId);
                }
            }
            break;
        default:
            zlog_err("default case %s %d",__FILE__,__LINE__);
        }
        if(pTunnel->UserLspName[0] != '\0')
        {
            IPV4_ADDR exclude_node = 0;
            if(pLspSmNotifData->ingress_lsp_notif == SETUP_FAILED_NOTIF)
            {
               exclude_node = pLspSmNotifData->data.setup_failed.IpAddr;
               rdb_remote_link_router_id_get(pLspSmNotifData->data.setup_failed.IpAddr,
                                                  &exclude_node);
            }
            pCall = UserLspFailed(pTunnel,pSm,exclude_node);
        }
        else
        {
            NotifyFailedRequests(pTunnel);
        }
        XFREE(MTYPE_TE,pLspSmNotifData); /* new!!! */
        break;
    default:
        zlog_err("unexpected event %d %s %d",
            sm_event->event,
            __FILE__,
            __LINE__);
        LspSmDestroy(pSm);
    }
    return pCall;
}

static SM_CALL_T* (*lsp_sm_event_handler[LSP_SM_MAX_STATE])(SM_T *pSm,SM_EVENT_T *sm_data) = 
{
    lsp_sm_empty_handler,
    lsp_sm_init
};

SM_CALL_T *lsp_sm_handler(SM_T *pSm,SM_EVENT_T *sm_data)
{
    if(sm_data == NULL)
    {
        zlog_err("fatal: sm_data is NULL %s %d",__FILE__,__LINE__);
        LspSmDestroy(pSm);
        return NULL;
    }
    if((pSm->state < INIT_STATE)||(pSm->state >= LSP_SM_MAX_STATE))
    {
        LspSmDestroy(pSm);
        return NULL;
    }
    return lsp_sm_event_handler[pSm->state](pSm,sm_data);
}

SM_CALL_T *lsp_sm_sync_invoke(SM_T *caller,void *data,SM_EVENT_E event)
{
    SM_T *pNewSm;
    SM_CALL_T *pEvent = NULL;
    LSP_SM_DATA *pLspSmData = NULL;
    PSB_KEY PsbKey;
    RSVP_TUNNEL_PROPERTIES *pTunnel;
    INGRESS_API *pOpenLspParams;
    USER_LSP        *pUserLsp;

    memset(&PsbKey,0,sizeof(PSB_KEY));

    if(event == USER_LSP_REQUEST_EVENT)
    {
        zlog_info("%s %d",__FILE__,__LINE__);
        pUserLsp = data;
        PsbKey.Session.Dest        = pUserLsp->params.to;
        PsbKey.Session.TunnelId         = GetPimaryTunnelId(pUserLsp->params.LspName);
        PsbKey.Session.ExtTunelId = pUserLsp->params.from;
        zlog_info("%s %d",__FILE__,__LINE__);
    }
    else
    {
        pOpenLspParams = data;
        pOpenLspParams->sm_handle = (uns32)caller;
        PsbKey.Session.Dest = pOpenLspParams->Egress;
        PsbKey.Session.TunnelId = pOpenLspParams->TunnelId;
        PsbKey.Session.ExtTunelId = pOpenLspParams->src_ip;
    }

    if(FindTunnel(&PsbKey,&pTunnel,ALL_TRUNKS) != TRUE)
    {
        zlog_info("%s %d",__FILE__,__LINE__);
        pNewSm = sm_gen_alloc(0,LSP_SM);
        if(pNewSm == NULL)
        {
            zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
            return NULL;
        }
        if((pLspSmData = (LSP_SM_DATA *)XMALLOC(MTYPE_TE,sizeof(LSP_SM_DATA))) == NULL)
        {
            zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
            sm_gen_free(pNewSm);
            return NULL;
        }
        pNewSm->data = pLspSmData;
    }
    else if(pTunnel->sm_handle == 0)
    {
        zlog_info("%s %d",__FILE__,__LINE__);
        pNewSm = sm_gen_alloc(0,LSP_SM);
        if(pNewSm == NULL)
        {
            zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
            return NULL;
        }

        if((pLspSmData = (LSP_SM_DATA *)XMALLOC(MTYPE_TE,sizeof(LSP_SM_DATA))) == NULL)
        {
            zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
            sm_gen_free(pNewSm);
            return NULL;
        }
        pNewSm->data = pLspSmData;
    }
    else
    {
        zlog_info("%s %d",__FILE__,__LINE__);
        pNewSm = (SM_T *)pTunnel->sm_handle;
    }
    zlog_info("%s %d",__FILE__,__LINE__);
    if((pEvent = sm_gen_sync_event_send(pNewSm,event,data)) == NULL)
    { 
        zlog_err("\ncan not invoke sm %s %d",__FILE__,__LINE__);
        XFREE(MTYPE_TE,pLspSmData);
        sm_gen_free(pNewSm);
    }
    zlog_info("%s %d",__FILE__,__LINE__);
    return pEvent;
}

void LspSmDestroy(SM_T *pSm)
{
    PSB_KEY PsbKey;
    RSVP_TUNNEL_PROPERTIES *pTunnel = NULL;
    LSP_SM_DATA *pLspSmData = pSm->data;
    TUNNEL_ID_LIST *pTunnelIdList = pLspSmData->TunnelIdHead,*pTunnelIdListNext;

    while(pTunnelIdList != NULL)
    {
        memset(&PsbKey,0,sizeof(PSB_KEY));
        PsbKey.Session.Dest = pTunnelIdList->dest;
        PsbKey.Session.TunnelId = pTunnelIdList->tunnel_id;
        PsbKey.Session.ExtTunelId = pTunnelIdList->source;
        if(FindTunnel(&PsbKey,&pTunnel,ALL_TRUNKS) == TRUE)
            pTunnel->sm_handle = 0;
        pTunnelIdListNext = pTunnelIdList->next;
        XFREE(MTYPE_TE,pTunnelIdList);
        pTunnelIdList = pTunnelIdListNext;
    }

    if(pLspSmData != NULL)
    {
        XFREE(MTYPE_TE,pLspSmData);
    }
    sm_gen_free(pSm);
}

void UserLspDestroy(USER_LSP *pUserLsp)
{
    RSVP_TUNNEL_PROPERTIES *pTunnel = pUserLsp->pUserLspTunnels,*pTunnelNext;
    
    if(pTunnel == NULL)
    {
        zlog_err("\nunexpected: tunnel id list empty %s %d",__FILE__,__LINE__);
        return;
    }
    while(pTunnel != NULL)
    {
        pTunnelNext = pTunnel->next_user_lsp_tunnel;
        if(RsvpTunnelTearDown(pTunnel,
                              pUserLsp->params.to,
                              pUserLsp->params.from) != E_OK)
        {
            zlog_err("\ncannot tear donw the tunnel %s %d",__FILE__,__LINE__);
        }
        pTunnel = pTunnelNext;
    }
    pUserLsp->pUserLspTunnels = NULL;
    return;
}


E_RC SetErHopList(STATIC_PATH *pStaticPath,ER_HOP **ppErHopsList)
{
    ER_HOP *pErHopsList;
    IPV4_HOP *pHops;
    int i;
    if(pStaticPath->HopCount == 0)
    {
        return E_OK;
    }
    if((pErHopsList = (ER_HOP *)XMALLOC(MTYPE_TE,sizeof(IPV4_HOP)*(pStaticPath->HopCount))) == NULL)
    {
        zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
        return E_ERR;
    }
    for(i = 0,pHops = pStaticPath->HopList;i < pStaticPath->HopCount;i++,pHops = pHops->next)
    {
        pErHopsList[i].IpAddr = pHops->IpAddr;
        pErHopsList[i].Loose = pHops->Loose;
        pErHopsList[i].PrefixLength = 32;
    }
    *ppErHopsList = pErHopsList;
    return E_OK;
}

SM_CALL_T *ProcessPrimaryLsp(USER_LSP *pCurrentUserLsp,
                             USER_LSP *pUserLsp,
                             SM_T *pSm,
                             char *PrimaryLspPathName)
{
    SM_CALL_T *pCall = NULL;
    INGRESS_API *pOpenLspParams = NULL;
    PSB_KEY PsbKey;
    RSVP_TUNNEL_PROPERTIES *pPrimaryTunnel;
    STATIC_PATH *pStaticPath = NULL;
    SECONDARY_PATH_LIST *pSecList;
    LSP_PATH_SHARED_PARAMS *pParams = NULL,*pParams2;
    BOOL OperationRequired = FALSE;
    uns8 Flags = 0;
    ER_HOP *pErHopsList = NULL;
    zlog_info("entering ProcessPrimaryLsp");
    zlog_info("LSP NAME %s",pCurrentUserLsp->params.LspName);

    if((pPrimaryTunnel = pCurrentUserLsp->pUserLspTunnels) == NULL)
    {
        memset(&PsbKey,0,sizeof(PSB_KEY));
        PsbKey.Session.Dest = pUserLsp->params.to;
        PsbKey.Session.TunnelId = NewTunnelId(&PsbKey);
        PsbKey.Session.ExtTunelId = pUserLsp->params.from = rdb_get_router_id();
        if(NewTunnel(&PsbKey,&pPrimaryTunnel,SEPARATE_NON_ADAPTIVE) != E_OK)
        {
            zlog_err("Cannot create new tunnel %s %d",__FILE__,__LINE__);
            return NULL;
        }
        pCurrentUserLsp->pUserLspTunnels = pPrimaryTunnel;
        zlog_info("New tunnel (Primary) created %x %s",pPrimaryTunnel->TunnelId,pPrimaryTunnel->StaticPathName);
        OperationRequired = TRUE;
    }
    strcpy(PrimaryLspPathName,pUserLsp->params.Primary);
    strcpy(pPrimaryTunnel->StaticPathName,PrimaryLspPathName);
    /* calculate the primary LSP parameters */
    if((!((pUserLsp->params.PrimaryPathParams)&&(!pUserLsp->params.PrimaryPathParams->disable)))||
       (rdb_get_static_path(pUserLsp->params.Primary,&pStaticPath) != E_OK))
    {
        zlog_info("No primary path...");
        pSecList = pUserLsp->params.SecondaryPaths;
        while(pSecList != NULL)
        {
            if(((pSecList->SecondaryPathParams)&&(pSecList->SecondaryPathParams->standby == 0))&&
               (rdb_get_static_path(pSecList->Secondary,&pStaticPath) == E_OK))
            {
                zlog_info("Processing secondary path %s",pSecList->Secondary);
                if(StaticPathIsUsed(pCurrentUserLsp,pSecList->Secondary) == NULL)
                {
                    zlog_info("\nSecondary path hasn't LSP");
                    pParams = PathParamsGet(pUserLsp,pSecList->Secondary,0);
                    Flags |= (pParams->record == TRUE) ? LABEL_RECORDING_DESIRED : 0;
                    /* for now the FRR is only boolean. However, in future it may be more complicated */
                    Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
                    if(SetErHopList(pStaticPath,&pErHopsList) != E_OK)
                    {
                        zlog_err("Cannot set ER hops list %s %d",__FILE__,__LINE__);
                        return NULL;
                    }
                    if((pOpenLspParams = CreateRequest2Signalling(pCurrentUserLsp->params.to,
                                                                  pPrimaryTunnel->TunnelId,
                                                                  pStaticPath->HopCount,
                                                                  pErHopsList,
                                                                  pParams->BW,
                                                                  pParams->setup_priority,
                                                                  pParams->hold_priority,
                                                                  Flags,
                                                                  (~(pParams->affinity_properties & pParams->affinity_mask)) & pParams->affinity_mask,
                                                                  0,
                                                                  pParams->affinity_properties & pParams->affinity_mask)) == NULL)
                    {
                        zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
                        if(pErHopsList != NULL)
                            XFREE(MTYPE_TE,pErHopsList);
                        return NULL;
                    }
                    strcpy(PrimaryLspPathName,pSecList->Secondary);
                    OperationRequired = TRUE;
                    break;
                }
                pStaticPath = NULL;
            }
            pSecList = pSecList->next;
        }
        if((pUserLsp->params.PrimaryPathParams != NULL)&&
           (!pUserLsp->params.PrimaryPathParams->disable))
        {
           pParams = pUserLsp->params.PrimaryPathParams;
        }
        else
        {
           pParams = &pUserLsp->params.lsp_params;
        }
        if(pCurrentUserLsp->params.PrimaryPathParams != NULL)
        {
           pParams2 = pCurrentUserLsp->params.PrimaryPathParams;
        }
        else
        {
           pParams2 = &pCurrentUserLsp->params.lsp_params;
        }
        if((pStaticPath == NULL)&&
           ((pParams->BW != pParams2->BW)||
            (pParams->class_of_service != pParams2->class_of_service)||
            (pParams->hold_priority != pParams2->hold_priority)||
            (pParams->setup_priority != pParams2->setup_priority)||
            (pParams->hop_limit != pParams2->hop_limit)||
            (pParams->record != pParams2->record)||
            (pUserLsp->params.FastReRoute != pCurrentUserLsp->params.FastReRoute)||
            (pUserLsp == pCurrentUserLsp)))
        {
            zlog_info("no paths provided");
            Flags |= (pUserLsp->params.lsp_params.record == TRUE) ? LABEL_RECORDING_DESIRED : 0;
                /* for now the FRR is only boolean. However, in future it may be more complicated */
            Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
            if((pOpenLspParams = CreateRequest2Signalling(pCurrentUserLsp->params.to,
                                                          pPrimaryTunnel->TunnelId, 
                                                          0,NULL,
                                                          pParams->BW,
                                                          pParams->setup_priority,
                                                          pParams->hold_priority,
                                                          Flags,
                                                          (~(pParams->affinity_properties & pParams->affinity_mask)) & pParams->affinity_mask,
                                                          0,
                                                          pParams->affinity_properties & pParams->affinity_mask)) == NULL)
            {
                zlog_err("\ncannot create request %s %d",__FILE__,__LINE__);
                return NULL;
            }
            OperationRequired = TRUE;
        }
        else if(pStaticPath == NULL)
        {
            if(pParams->optimize_timer != pParams2->optimize_timer)
            {
               StartAdaptivityTimer(pParams->optimize_timer,pPrimaryTunnel);
            }
        }
    }
    else
    {
        zlog_info(
               "\nCurrent Primary %s New Primary %s",
               pCurrentUserLsp->params.Primary,pUserLsp->params.Primary);
        if((pUserLsp->params.PrimaryPathParams != NULL)&&
           (!pUserLsp->params.PrimaryPathParams->disable))
        {
            pParams = pUserLsp->params.PrimaryPathParams;
        }
        else
        {
            pParams = &pUserLsp->params.lsp_params;
        }
        if(pCurrentUserLsp->params.PrimaryPathParams != NULL)
        {
            pParams2 = pCurrentUserLsp->params.PrimaryPathParams;
        }
        else
        {
            pParams2 = &pCurrentUserLsp->params.lsp_params;
        }
        if((pParams->BW != pParams2->BW)||
           (pParams->class_of_service != pParams2->class_of_service)||
           (pParams->hold_priority != pParams2->hold_priority)||
           (pParams->setup_priority != pParams2->setup_priority)||
           (pParams->hop_limit != pParams2->hop_limit)||
           (pParams->record != pParams2->record)||
           (pUserLsp->params.FastReRoute != pCurrentUserLsp->params.FastReRoute))
        {
            OperationRequired = TRUE;
        }
        
        if(strcmp(pCurrentUserLsp->params.Primary,pUserLsp->params.Primary) != 0)
        {
            OperationRequired = TRUE;
        }
           
        if(pCurrentUserLsp->params.FastReRoute != pUserLsp->params.FastReRoute)
        {
            OperationRequired = TRUE;
        }

        if(OperationRequired == TRUE)
        {
            zlog_info("Parameters have changed");
            pParams = PathParamsGet(pUserLsp,pUserLsp->params.Primary,1);
            Flags |= (pParams->record == TRUE) ? LABEL_RECORDING_DESIRED : 0;
            /* for now the FRR is only boolean. However, in future it may be more complicated */
            Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
            if(SetErHopList(pStaticPath,&pErHopsList) != E_OK)
            {
                zlog_err("Cannot set ER hops list %s %d",__FILE__,__LINE__);
                return NULL;
            }
            if((pOpenLspParams = CreateRequest2Signalling(pCurrentUserLsp->params.to,
                                                          pPrimaryTunnel->TunnelId,
                                                          pStaticPath->HopCount,
                                                          pErHopsList,
                                                          pParams->BW,
                                                          pParams->setup_priority,
                                                          pParams->hold_priority,
                                                          Flags,
                                                          (~(pParams->affinity_properties & pParams->affinity_mask)) & pParams->affinity_mask,
                                                          0,
                                                          pParams->affinity_properties & pParams->affinity_mask)) == NULL)
            {
                zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
                if(pErHopsList != NULL)
                    XFREE(MTYPE_TE,pErHopsList);
                return NULL;
            }
        }
        else
        {
            if(pParams->optimize_timer != pParams2->optimize_timer)
            {
               StartAdaptivityTimer(pParams->optimize_timer,pPrimaryTunnel);
            }
        }
    }
    if(OperationRequired == TRUE)
    {
        /* setup the primary LSP */
        pOpenLspParams->TunnelId = pPrimaryTunnel->TunnelId;
        zlog_info(
               "\nDEST %x SOURCE %x TUNNEL %x",
               pOpenLspParams->Egress,pOpenLspParams->src_ip,pOpenLspParams->TunnelId);
        pCall = LspRequest(pOpenLspParams,0,NULL,pSm,&pPrimaryTunnel,FALSE,pParams);
        pPrimaryTunnel->sm_handle = pSm;
        strcpy(pPrimaryTunnel->StaticPathName,PrimaryLspPathName);
        strcpy(pPrimaryTunnel->UserLspName,pUserLsp->params.LspName);
        zlog_info("\nPrimary Tunnel Name %s",pPrimaryTunnel->UserLspName);
    }
    zlog_info("leaving ProcessPrimaryLsp");
    return pCall;
}

RSVP_TUNNEL_PROPERTIES *GetSecondaryTunnel2Reroute(USER_LSP *pUserLsp,
                                                   USER_LSP *pCurrentUserLsp)
{
    RSVP_TUNNEL_PROPERTIES *pTunnel;
    SECONDARY_PATH_LIST *pSecList;
    BOOL Found;
    zlog_info("entering GetSecondaryTunnel2Reroute");
    if((pTunnel = pCurrentUserLsp->pUserLspTunnels) == NULL)
    {
        zlog_err(
               "\nBUG: first Tunnel ID is NULL %s %d %s",
               __FILE__,__LINE__,pCurrentUserLsp->params.LspName);
        return NULL;
    }
    pTunnel = pTunnel->next_user_lsp_tunnel;
    while(pTunnel != NULL)
    {
        pSecList = pUserLsp->params.SecondaryPaths;
        Found = FALSE;
        while(pSecList != NULL)
        {
            if((pSecList->SecondaryPathParams != NULL)&&
               (pSecList->SecondaryPathParams->standby == TRUE))
            {
                if(strcmp(pSecList->Secondary,pTunnel->StaticPathName) == 0)
                {
                    Found = TRUE;
                    break;
                }
            }
            pSecList = pSecList->next;
        }
        if(Found == FALSE)
        {
            /* should we do some clean up like stop the timers etc ??? */
            return pTunnel;
        }
        pTunnel = pTunnel->next_user_lsp_tunnel;
    }
    zlog_info("leaving GetSecondaryTunnel2Reroute");
    return NULL;
}

SM_CALL_T *ProcessSecondaryPaths(USER_LSP *pCurrentUserLsp,
                                 USER_LSP *pUserLsp,
                                 SM_T *pSm,
                                 char *PrimaryLspPathName,
                                 BOOL PrimaryLspOperation)
{
    SECONDARY_PATH_LIST *pSecList;
    BOOL OperationRequired;
    INGRESS_API *pOpenLspParams;
    RSVP_TUNNEL_PROPERTIES *pSecondaryTunnel,*pSecTunnel2Modify,*pSecReusedTunnel;
    STATIC_PATH *pStaticPath;
    PSB_KEY PsbKey;
    LSP_PATH_SHARED_PARAMS *pParams = NULL,*pParams2;
    uns8 Flags = 0;
    ER_HOP *pErHopsList = NULL;
    SM_CALL_T *pCall = NULL;

    zlog_info("entering ProcessSecondaryPaths");

    pSecList = pUserLsp->params.SecondaryPaths;
                
    /* find all the secondary LSPs (hot-standby) that must be established */
    while(pSecList != NULL)
    {
        OperationRequired = FALSE;
        pCall = NULL;
        pErHopsList = NULL;
        zlog_info("Secondary path...");
        if((pSecList->SecondaryPathParams != NULL)&&
           (pSecList->SecondaryPathParams->disable == FALSE)&&
           (pSecList->SecondaryPathParams->standby == TRUE))
        {
            zlog_info("Secondary path2...");
            if(rdb_get_static_path(pSecList->Secondary,
                                        &pStaticPath) != E_OK)
            {
               zlog_info("static path is not found in TE DB");
               pStaticPath = NULL; 
            }
            else
            {
                if(SetErHopList(pStaticPath,&pErHopsList) != E_OK)
                {
                    zlog_err("Cannot set ER hops list %s %d",__FILE__,__LINE__);
                    return NULL;
                }
            }
            pSecReusedTunnel = NULL;    
            pParams = PathParamsGet(pUserLsp,pSecList->Secondary,0);
            if((pSecTunnel2Modify = StaticPathIsUsed(pCurrentUserLsp,pSecList->Secondary)) == NULL)
            {
                zlog_info("Secondary path3 ...");
                   
                if((pSecReusedTunnel = GetSecondaryTunnel2Reroute(pUserLsp,pCurrentUserLsp)) != NULL)
                {
                    strcpy(pSecReusedTunnel->StaticPathName,pSecList->Secondary);
                }
                OperationRequired = TRUE;         
            }
            else
            {
                pParams2  = PathParamsGet(pCurrentUserLsp,pSecList->Secondary,0);
                pSecReusedTunnel = pSecTunnel2Modify;          
                if((pParams->BW != pParams2->BW)||
                   (pParams->class_of_service != pParams2->class_of_service)||
                   (pParams->hold_priority != pParams2->hold_priority)||
                   (pParams->setup_priority != pParams2->setup_priority)||
                   (pParams->hop_limit != pParams2->hop_limit)||
                   (pParams->record != pParams2->record)||
                   (pUserLsp->params.FastReRoute != pCurrentUserLsp->params.FastReRoute))
                {
                     OperationRequired = TRUE;
                }
                if(pCurrentUserLsp->params.FastReRoute != pUserLsp->params.FastReRoute)
                {
                    OperationRequired = TRUE;
                }
                if(OperationRequired == FALSE)
                {
                   if(pParams->optimize_timer != pParams2->optimize_timer)
                   {
                      StartAdaptivityTimer(pParams->optimize_timer,pSecReusedTunnel);
                   }
                }
            }
            if(OperationRequired == TRUE)
            {
                if((((pStaticPath != NULL)&&(pStaticPath->HopCount != 0))&&
                    ((pErHopsList != NULL)&&(pErHopsList[0].Loose == 0)))||
                    (PrimaryLspOperation == FALSE))
                {
                    uns32 ErHopNumber = 0;
                    IPV4_ADDR *pErHops = NULL;
                    if(!((pErHopsList != NULL)&&(pErHopsList[0].Loose == 0)))
                    {
                       if(GetTunnelHops(pCurrentUserLsp->pUserLspTunnels,
                                        &ErHopNumber,
                                        &pErHops) != E_OK)
                       {
                           zlog_info(
                                  "cannot get ER HOPs to be avoided %s %d",
                                  __FILE__,__LINE__);
                           ErHopNumber = 0;
                           pErHops = NULL;
                       }
                    }
                    memset(&PsbKey,0,sizeof(PSB_KEY));
                    PsbKey.Session.Dest = pUserLsp->params.to;
                    Flags |= pParams->record == TRUE ? LABEL_RECORDING_DESIRED : 0;
                    /* for now the FRR is only boolean. However, in future it may be more complicated */
                    Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
                    if((pOpenLspParams = CreateRequest2Signalling(pUserLsp->params.to,
                                                                  (pSecReusedTunnel == NULL) ? 
                                                                     NewTunnelId(&PsbKey) : pSecReusedTunnel->TunnelId,
                                                                  (pStaticPath == NULL) ? 0 : pStaticPath->HopCount,
                                                                  pErHopsList,
                                                                  pParams->BW,
                                                                  pParams->setup_priority,
                                                                  pParams->hold_priority,
                                                                  Flags,
                                                                  (~(pParams->affinity_properties & pParams->affinity_mask)) & pParams->affinity_mask,
                                                                  0,
                                                                  pParams->affinity_properties & pParams->affinity_mask)) == NULL)
                    {
                         zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
                         return NULL;
                    }
                    pCall = LspRequest(pOpenLspParams,
                                       ErHopNumber,
                                       pErHops,
                                       pSm,
                                       &pSecondaryTunnel,
                                       TRUE,
                                       pParams);
                    pSecondaryTunnel->sm_handle = pSm;
                    if(AddSecondaryTunnel(pCurrentUserLsp,
                                          pSecondaryTunnel) != E_OK)
                    {
                        zlog_err("\ncannot add secodary tunnel to the list %s %d",
                               __FILE__,__LINE__);
                        return NULL;
                    }
                }
                else
                {
                    uns16 TunnelId;
                    if(pSecReusedTunnel == NULL)
                    {
                        memset(&PsbKey,0,sizeof(PsbKey));
                        PsbKey.Session.Dest = pUserLsp->params.to;
                        PsbKey.Session.ExtTunelId = pUserLsp->params.from;
                        TunnelId = NewTunnelId(&PsbKey);
                        PsbKey.Session.TunnelId = TunnelId;
                        zlog_info("DEST %x TUNNEL %x SOURCE %x",
                               PsbKey.Session.Dest,
                               PsbKey.Session.TunnelId,
                               PsbKey.Session.ExtTunelId);
                        if(NewTunnel(&PsbKey,&pSecondaryTunnel,SEPARATE_NON_ADAPTIVE) != E_OK)
                        {
                            zlog_err("\ncannot create new tunnel's structure");
                            LspSmDestroy(pSm);
                            return NULL;
                        }
                    }
                    else
                    {
                        pSecondaryTunnel = pSecReusedTunnel;
                    }
                        
                    pSecondaryTunnel->RequiredBW = pParams->BW;
                    pSecondaryTunnel->sm_handle = pSm;
                    if(AddSecondaryTunnel(pCurrentUserLsp,
                                          pSecondaryTunnel) != E_OK)
                    {
                        zlog_err("\ncannot add secodary tunnel to the list %s %d",
                               __FILE__,__LINE__);
                        return NULL;
                    }
                    pSecondaryTunnel->AdjustmentRequired = TRUE;
                }
                zlog_info("after UserLSpRequest %s %d %x",__FILE__,__LINE__,pSecondaryTunnel->TunnelId);
                if(pSecondaryTunnel != NULL)
                {
                    strcpy(pSecondaryTunnel->StaticPathName,pSecList->Secondary);
                    strcpy(pSecondaryTunnel->UserLspName,pUserLsp->params.LspName);
                    zlog_info("pSecondaryTunnel->StaticPathName %s pSecondaryTunnel->UserLspName %s",
                           pSecondaryTunnel->StaticPathName,pSecondaryTunnel->UserLspName);
                }
                if(pCall)
                {
                   sm_call(pCall);
                   pCall = NULL;
                }
            }
        }
        pSecList = pSecList->next;
    }
    zlog_info("leaving ProcessSecondaryPaths");
    return NULL;
}

uns32 StartAdaptivityTimer(uns32 optimize_timer,
                           RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    zlog_info("entering StartAdaptivityTimer");

    if(pTunnel->adaptivity_timer.is_active == TRUE)
    {
        te_stop_timer(&pTunnel->adaptivity_timer);
    }
    zlog_info("triggering optimize timer for tunnel %x value %d",pTunnel->TunnelId,optimize_timer);
    if(optimize_timer != 0)
    {
        if(te_start_timer(&pTunnel->adaptivity_timer,
                          ADAPTIVITY_EXPIRY,
                          optimize_timer) != E_OK)
        {
             zlog_err("\ncannot start adaptivity timer %s %d",__FILE__,__LINE__);
             return E_ERR;
        }
    }
    else
    {
        zlog_info("\nOptimize timer is 0...");
    }
    zlog_info("leaving StartAdaptivityTimer");
    return E_OK;
}

void StopAdaptivityTimer(RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    zlog_info("entering StopAdaptivityTimer");
    te_stop_timer(&pTunnel->adaptivity_timer);
    zlog_info("leaving StopAdaptivityTimer");
}

uns32 StartLspSetupTimer(RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    zlog_info("entering StartLspSetupTimer");
    //return E_OK;
    if(pTunnel->lsp_setup_timer.is_active == TRUE)
    {
        te_stop_timer(&pTunnel->lsp_setup_timer);
    }
    if(te_start_timer(&pTunnel->lsp_setup_timer,
                      LSP_SETUP_EXPIRY,
                      LspSetupTimeOut) != E_OK)
    {
        zlog_err("\ncannot start te timer %s %d",__FILE__,__LINE__);
        return E_ERR;
    }
    zlog_info("leaving StartLspSetupTimer");
    return E_OK;
}

void StopLspSetupTimer(RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    zlog_info("entering StopLspSetupTimer");
    te_stop_timer(&pTunnel->lsp_setup_timer);
    zlog_info("leaving StopLspSetupTimer");
}

uns32 StartLspSetupRetryTimer(uns32 retry_timer,
                              uns32 *retry_count,
                              RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    zlog_info("entering StartLspSetupRetryTimer");
  
    if(*retry_count > 0)
    {
        if(retry_timer != 0)
        {
            if(pTunnel->lsp_setup_retry_timer.is_active == TRUE)
            {
                te_stop_timer(&pTunnel->lsp_setup_retry_timer);
            }
            zlog_info("\ninside of StartLspSetupRetryTimer %x %x %x",
                   pTunnel->lsp_setup_retry_timer.data.lsp_setup_retry_data.key.Session.Dest,
                   pTunnel->lsp_setup_retry_timer.data.lsp_setup_retry_data.key.Session.TunnelId,
                   pTunnel->lsp_setup_retry_timer.data.lsp_setup_retry_data.key.Session.ExtTunelId);
            if(te_start_timer(&pTunnel->lsp_setup_retry_timer,
                              LSP_SETUP_RETRY_EXPIRY,
                              retry_timer) != E_OK)
            {
                zlog_err("\ncannot start te timer %s %d",__FILE__,__LINE__);
                return E_ERR;
            }
        }
        (*retry_count)--;
    }
    zlog_info("leaving StartLspSetupRetryTimer");
    return E_OK;
}

void StopLspSetupRetryTimer(RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    zlog_info("entering StopLspSetupTimer");
    te_stop_timer(&pTunnel->lsp_setup_retry_timer);
    zlog_info("leaving StopLspSetupRetryTimer");
}

uns32 StartCspfRetryTimer(RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    int r,k;
    zlog_info("entering StartCspfRetryTimer");

    if(pTunnel->cspf_retry_timer.is_active == TRUE)
    {
        te_stop_timer(&pTunnel->cspf_retry_timer);
    }
    zlog_info("inside of StartCspfRetryTimer %x %x %x",
                       pTunnel->cspf_retry_timer.data.cspf_retry_data.key.Session.Dest,
                       pTunnel->cspf_retry_timer.data.cspf_retry_data.key.Session.TunnelId,
                       pTunnel->cspf_retry_timer.data.cspf_retry_data.key.Session.ExtTunelId);
    r = rand();
    r = r%30;
    k = rand();
    if(te_start_timer(&pTunnel->cspf_retry_timer,
                      CSPF_RETRY_EXPIRY,
                      /*(k%2) ? (300 + r) : (300 - r)*/5) != E_OK)
    {
        zlog_err("\ncannot start te timer %s %d",__FILE__,__LINE__);
        return E_ERR;
    }
    zlog_info("leaving StartCspfRetryTimer");
    return E_OK;
}

static void StopCspfRetryTimer(RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    zlog_info("entering StopCspfRetryTimer");
    te_stop_timer(&pTunnel->cspf_retry_timer);
    zlog_info("leaving StopCspfRetryTimer");
}

SM_CALL_T *CspfRetryExpiry(PSB_KEY *PsbKey,SM_T *pSm)
{
    RSVP_TUNNEL_PROPERTIES *pTunnel;
    SM_CALL_T *pCall = NULL;

    zlog_info("entering CspfRetryExpiry");
    
    if(FindTunnel(PsbKey,&pTunnel,ALL_TRUNKS) != TRUE)
    {
        zlog_info("leaving CspfRetryExpiry1-");
        return NULL;
    }

    if((pTunnel->pOpenLspParams)&&(pTunnel->pCrArgs))
    {
       ((INGRESS_API *)(pTunnel->pOpenLspParams))->ErHops2Exclude[0] = 0;
       ((INGRESS_API *)(pTunnel->pOpenLspParams))->ErHops2Exclude[1] = 0;
       UnregisterClient((int)pSm,
                        pTunnel->TunnelId);
       if((pCall = constraint_route_resolution_sm_invoke(pSm,
                                                         pTunnel->pCrArgs)) == NULL)
       {
           zlog_err("cannot invoke constraint route resolution");
           return NULL;
       }
    }
    StartCspfRetryTimer(pTunnel);
    zlog_info("leaving CspfRetryExpiry");
    return pCall;
}

SM_CALL_T *LspSetupExpiry(PSB_KEY *PsbKey,SM_T *pSm)
{
    RSVP_TUNNEL_PROPERTIES *pTunnel;
    RSVP_LSP_PROPERTIES *pRsvpLsp;
  
    zlog_info("entering LspSetupExpiry");
  
    if(FindTunnel(PsbKey,&pTunnel,ALL_TRUNKS) != TRUE)
    {
        zlog_err("\ncannot find tunnel %x %x %x %s %d",
            PsbKey->Session.Dest,
            PsbKey->Session.TunnelId,
            PsbKey->Session.ExtTunelId,__FILE__,__LINE__);
        return NULL;
    }
    pRsvpLsp = pTunnel->properties;
    while(pRsvpLsp != NULL)
    {
        if(pRsvpLsp->LspId != pTunnel->LspId)
        {
            RSVP_LSP_PROPERTIES *pTemp = pRsvpLsp->next;
            RemoveRsvpLsp(pTunnel,pRsvpLsp->LspId,PsbKey->Session.Dest,PsbKey->Session.ExtTunelId);
            pRsvpLsp = pTemp;
        }
        else
        {
            pRsvpLsp = pRsvpLsp->next;
        }
    }
    //pTunnel->ReRoute = FALSE;
    if(pTunnel->UserLspName[0] != '\0')
    {
        return UserLspFailed(pTunnel,pSm,0);
    }
    else
    {
        NotifyFailedRequests(pTunnel);
    }
    zlog_info("leaving LspSetupExpiry");
    return NULL;
}

SM_CALL_T *AdaptivityExpiry(PSB_KEY *PsbKey,SM_T *pSm)
{
    RSVP_TUNNEL_PROPERTIES *pTunnel;
    USER_LSP *pUserLsp;
    STATIC_PATH *pStaticPath;

    zlog_info("entering AdaptivityExpiry");
    
    if(FindTunnel(PsbKey,&pTunnel,ALL_TRUNKS) != TRUE)
    {
        zlog_err("\ncannot find tunnel %x %x %x %s %d",
            PsbKey->Session.Dest,
            PsbKey->Session.TunnelId,
            PsbKey->Session.ExtTunelId,
            __FILE__,__LINE__);
        return NULL;
    }
    
    if((pUserLsp = UserLspGet(pTunnel->UserLspName)) != 0)
    {
        LSP_PATH_SHARED_PARAMS *pParams = PathParamsGet(pUserLsp,
                                                        pTunnel->StaticPathName,
                                                        ((!strcmp(pUserLsp->params.Primary,pTunnel->StaticPathName))&&(pUserLsp->pUserLspTunnels->TunnelId == pTunnel->TunnelId)));
        
        if(pParams == NULL)
        {
            zlog_err("\ncannot get User Lsp PAth Params %s %d",__FILE__,__LINE__);
        }
        else
        {
            if(StartAdaptivityTimer(pParams->optimize_timer,pTunnel) != E_OK)
            {
                zlog_err("\ncannot start adaptivity timer %s %d",__FILE__,__LINE__);
            }
        }
        
        if(pTunnel->ReRoute == FALSE)
        {
            IPV4_ADDR dest = PsbKey->Session.Dest;

            if(rdb_get_static_path(pTunnel->StaticPathName,
                                        &pStaticPath) == E_OK)
            {
                if(pStaticPath->HopCount != 0)
                {
                    if(pStaticPath->HopList->Loose == 0)
                    {
                        return NULL;
                    }
                    else
                    {
                        dest = pStaticPath->HopList->IpAddr;
                    }
                }
            }
            return OptimizeSingleLsp(pTunnel,
                                     dest,
                                     PsbKey->Session.ExtTunelId);
        }
        else
        {
            zlog_info("\nDEBUG: No adaptation during reroute %x %x %x %s %d",
                PsbKey->Session.Dest,
                PsbKey->Session.TunnelId,
                PsbKey->Session.ExtTunelId,
                __FILE__,__LINE__);
        }
    }
    zlog_info("leaving AdaptivityExpiry");
    return NULL;
}

SM_CALL_T *LspSetupRetryExpiry(PSB_KEY *PsbKey,SM_T *pSm)
{
    RSVP_TUNNEL_PROPERTIES *pTunnel;
    USER_LSP *pUserLsp;
    STATIC_PATH *pStaticPath;
    INGRESS_API *pOpenLspParams;
    SM_CALL_T *pCall = NULL;
    uns32 ErHops2BeAvoidedNumber = 0;
    IPV4_ADDR *ErHops2BeAvoided = NULL;
    LSP_PATH_SHARED_PARAMS *pParams;
    ER_HOP *pErHopsList = NULL;
    uns8 Flags = 0;

    zlog_info("entering LspSetupRetryExpiry");

    if(FindTunnel(PsbKey,&pTunnel,ALL_TRUNKS) != TRUE)
    {
        zlog_err("\ncannot find tunnel %x %x %x %s %d",
            PsbKey->Session.Dest,
            PsbKey->Session.TunnelId,
            PsbKey->Session.ExtTunelId,
            __FILE__,__LINE__);
        return NULL;
    }
    if((pUserLsp = UserLspGet(pTunnel->UserLspName)) == NULL)
    {
        zlog_err("\ncannot get user lsp %s %d",__FILE__,__LINE__);
        return NULL;
    }
    if(rdb_get_static_path(pUserLsp->params.Primary,
                                &pStaticPath) != E_OK)
    {
        pStaticPath = NULL;
    }
    pParams = PathParamsGet(pUserLsp,pUserLsp->params.Primary,1);
    Flags |= (pParams->record == TRUE) ? LABEL_RECORDING_DESIRED : 0;
    /* for now the FRR is only boolean. However, in future it may be more complicated */
    Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
    if(pStaticPath)
    {
       if(SetErHopList(pStaticPath,&pErHopsList) != E_OK)
       {
           zlog_err("Cannot set ER hops list %s %d",__FILE__,__LINE__);
           return NULL;
       }
    }
    if((pOpenLspParams = CreateRequest2Signalling(pUserLsp->params.to,
                                                  pUserLsp->pUserLspTunnels->TunnelId,
                                                  (pStaticPath) ? pStaticPath->HopCount : 0,
                                                  pErHopsList,
                                                  pParams->BW,
                                                  pParams->setup_priority,
                                                  pParams->hold_priority,
                                                  Flags,
                                                  (~(pParams->affinity_properties & pParams->affinity_mask)) & pParams->affinity_mask,
                                                  0,
                                                  pParams->affinity_properties & pParams->affinity_mask)) == NULL)
    {
        zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
        XFREE(MTYPE_TE,pErHopsList);
        return NULL;
    }
    
#if 0
    if((pTunnelIdList = pUserLsp->TunnelIdList) == NULL)
    {
        zlog_info("\nUser's LSP tunnel ID list is empty...");
    }
    else
    {
        RSVP_TUNNEL_PROPERTIES *pTun;
        PSB_KEY rsvp_k;
        memset(&rsvp_k,0,sizeof(PSB_KEY));
        rsvp_k.Session.Dest = pTunnelIdList->dest;
        rsvp_k.Session.ExtTunelId = pTunnelIdList->source;
        pTunnelIdList = pTunnelIdList->next;
        while(pTunnelIdList != NULL)
        {
            rsvp_k.Session.TunnelId = pTunnelIdList->tunnel_id;
            if(FindTunnel(&rsvp_k,&pTun,ALL_TRUNKS) == TRUE)
            {
                if(strcmp(pUserLsp->CurrentSecondaryPathName,
                    pTun->StaticPathName) == 0)
                {
                    if(GetTunnelHops(pTunnelIdList,&ErHops2BeAvoidedNumber,&ErHops2BeAvoided) != E_OK)
                    {
                        zlog_err("\ncannot get tunnel's hops %x %x %x %s %d",
                            rsvp_k.Session.Dest,
                            pTunnelIdList->tunnel_id,
                            rsvp_k.Session.ExtTunelId,
                            __FILE__,__LINE__);
                        ErHops2BeAvoidedNumber = 0;
                        ErHops2BeAvoided = NULL;
                    }
                    break;
                }
            }
            else
            {
                zlog_err("\ncannot get Tunnel %x %x %x %s %d",
                    rsvp_k.Session.Dest,
                    pTunnelIdList->tunnel_id,
                    rsvp_k.Session.ExtTunelId,
                    __FILE__,__LINE__);
            }
            pTunnelIdList = pTunnelIdList->next;
        }
    }
#endif
    pCall = LspRequest(pOpenLspParams,ErHops2BeAvoidedNumber,ErHops2BeAvoided,pSm,&pTunnel,TRUE,pParams);
    strcpy(pTunnel->StaticPathName,pUserLsp->params.Primary);
    StartLspSetupRetryTimer(pUserLsp->params.retry_timer,&pUserLsp->params.retry_count,pTunnel);
    zlog_info("leaving LspSetupRetryExpiry");
    return pCall;
}

void TearDownAndRemoveSecondary(USER_LSP *pCurrentUserLsp,char *PathName)
{
    RSVP_TUNNEL_PROPERTIES *pTunnel = pCurrentUserLsp->pUserLspTunnels,*pTunnelPrev = NULL;

    zlog_info("entering TearDownAndRemoveSecondary");

    if(pTunnel == NULL)
    {
        zlog_err("\nTunnelIDList is empty %s %d",__FILE__,__LINE__);
        return;
    }
    pTunnelPrev = pTunnel;
    pTunnel = pTunnel->next_user_lsp_tunnel;
    while(pTunnel != NULL)
    {
        if(strcmp(pTunnel->StaticPathName,PathName) == 0)
        {
            pTunnelPrev->next_user_lsp_tunnel = pTunnel->next_user_lsp_tunnel;
            if(RsvpTunnelTearDown(pTunnel,
                                  pCurrentUserLsp->params.to,
                                  pCurrentUserLsp->params.from) != E_OK)
            {
                zlog_err("\ncannot tear donw the tunnel %s %d",__FILE__,__LINE__);
            }
            return;
        }
        pTunnelPrev = pTunnel;
        pTunnel = pTunnel->next_user_lsp_tunnel;
    }
    zlog_info("leaving TearDownAndRemoveSecondary");
}

void CalculateUnneededPathAndTearDown(USER_LSP *pUserLsp,USER_LSP *pCurrentUserLsp)
{
    SECONDARY_PATH_LIST *pSecList,*pSecList2,*pSecListPrev,*pSecListNext,*pSecListPrev2;
    uns32 SecTunnelsCount = 0,SecPathCount = 0,SecTunnels2BeTorn = 0;
    BOOL Found;
    RSVP_TUNNEL_PROPERTIES *pTunnel;
                
    zlog_info("entering CalculateUnneededPathAndTearDown");


    pSecList = pUserLsp->params.SecondaryPaths;
    pSecListPrev = NULL;
    while(pSecList != NULL)
    {
        zlog_info("Received: %s %s",pSecList->Secondary,(pSecList->SecondaryPathParams) ? ((pSecList->SecondaryPathParams->disable) ? "is disabled" : "") : "");
        pSecListNext = pSecList->next;
        if((pSecList->SecondaryPathParams != NULL)&&
           (pSecList->SecondaryPathParams->disable == TRUE))
        {
           pSecList2 = pCurrentUserLsp->params.SecondaryPaths;
           pSecListPrev2 = NULL;
           while(pSecList2 != NULL)
           {
              zlog_info("Exists: %s",pSecList2->Secondary);
              if(strcmp(pSecList2->Secondary,pSecList->Secondary) == 0)
              {
                 break;
              }
              pSecListPrev2 = pSecList2;
              pSecList2 = pSecList2->next;
           }
           if(pSecList2 != NULL)
           {
              if(pSecListPrev2 == NULL)
              {
                 pCurrentUserLsp->params.SecondaryPaths = pCurrentUserLsp->params.SecondaryPaths->next;
              }
              else
              {
                 pSecListPrev2->next = pSecList2->next;
              }
              XFREE(MTYPE_TE,pSecList2->SecondaryPathParams);
              XFREE(MTYPE_TE,pSecList2);
           }
           if(pSecListPrev == NULL)
           {
              pUserLsp->params.SecondaryPaths = pUserLsp->params.SecondaryPaths->next;
           }
           else
           {
              pSecListPrev->next = pSecList->next;
           }
           XFREE(MTYPE_TE,pSecList->SecondaryPathParams);
           XFREE(MTYPE_TE,pSecList);
        }
        else
        {
           pSecListPrev = pSecList;
        }
        pSecList = pSecListNext;
    }

    /* find all the secondary LSPs (hot-standby) that must be established */
    if(pCurrentUserLsp->pUserLspTunnels == NULL)
    {
        zlog_err("\nFirst Tunnel ID is NULL %s %d %s",__FILE__,__LINE__,pCurrentUserLsp->params.LspName);
        return;
    }
    pTunnel = pCurrentUserLsp->pUserLspTunnels->next_user_lsp_tunnel;
    /* First - count all the secondary tunnels */
    while(pTunnel != NULL)
    {
        SecTunnelsCount++;
        pTunnel = pTunnel->next_user_lsp_tunnel;
    }
    /* Second - count all the secondary hot-standby paths for new request */
    pSecList = pUserLsp->params.SecondaryPaths;
    while(pSecList != NULL)
    {
        if((pSecList->SecondaryPathParams != NULL)&&
           (pSecList->SecondaryPathParams->standby == TRUE))
        {
            SecPathCount++;
        }
        pSecList = pSecList->next;
    }
    
    if(SecPathCount >= SecTunnelsCount)
    {
        zlog_info("SecPathCount %d SecTunnelsCount %d",SecPathCount,SecTunnelsCount);
        return; /* There is no "spare" secondary tunnels */
    }

    /* How many tunnels should be torn down */
    SecTunnels2BeTorn = SecTunnelsCount - SecPathCount;

    /* set to the start of the list */
    pTunnel = pCurrentUserLsp->pUserLspTunnels->next_user_lsp_tunnel;

    /* Tear down the calculated number of tunnels */
    /* Keep tunnels, passing over secondary paths of the new request */
    while((pTunnel != NULL)&&(SecTunnels2BeTorn > 0))
    {
        pSecList = pUserLsp->params.SecondaryPaths;
        Found = FALSE;
        while(pSecList != NULL)
        {
            if((pSecList->SecondaryPathParams != NULL)&&
               (pSecList->SecondaryPathParams->standby == TRUE))
            {
                if(strcmp(pSecList->Secondary,pTunnel->StaticPathName) == 0)
                {
                   Found = TRUE;
                   break;
                }
            }
            pSecList = pSecList->next;
        }
        if(Found == FALSE)
        {
            TearDownAndRemoveSecondary(pCurrentUserLsp,pTunnel->StaticPathName);
            SecTunnels2BeTorn--;
        }
        pTunnel = pTunnel->next_user_lsp_tunnel;
    }
    zlog_info("leaving CalculateUnneededPathAndTearDown");
}

SM_CALL_T *PrepareAndIssueCrResolutionRequest(INGRESS_API *pOpenLspParams,
                                              uns32           AvoidHopNumber,
                                              IPV4_ADDR    *AvoidHopsArray,
                                              RSVP_TUNNEL_PROPERTIES *pTunnel,
                                              SM_T *pSm,
                                              LSP_PATH_SHARED_PARAMS *pParams)
{
    CONSTRAINT_ROUTE_RESOLUTION_ARGS *pCrArgs;
    SM_CALL_T *pCall = NULL;
    zlog_info("entering PrepareAndIssueCrResolutionRequest");
    if((pCrArgs = (CONSTRAINT_ROUTE_RESOLUTION_ARGS *)XMALLOC(MTYPE_TE,sizeof(CONSTRAINT_ROUTE_RESOLUTION_ARGS))) == NULL)
    {
        zlog_err("malloc failed %s %d",__FILE__,__LINE__);
        LspSmDestroy(pSm);
        return NULL;
    }
    pCrArgs->BW = pOpenLspParams->BW;
    pCrArgs->ExclColorMask = pOpenLspParams->ExcludeAny;
    pCrArgs->InclAnyColorMask = pOpenLspParams->IncludeAny;
    pCrArgs->InclColorMask = pOpenLspParams->IncludeAll;
    zlog_info("preparing CR request1");
    if(pOpenLspParams->HopNum != 0)
    {
        pCrArgs->dest = pOpenLspParams->Path[0].IpAddr;
    }
    else
        pCrArgs->dest = pOpenLspParams->Egress;
    zlog_info("preparing CR request2 dest %x hop %x %x",pCrArgs->dest,pOpenLspParams->HopNum,pOpenLspParams->Path[0].IpAddr);
    pCrArgs->PsbKey.Session.Dest = pOpenLspParams->Egress;
    pCrArgs->PsbKey.Session.TunnelId = pOpenLspParams->TunnelId;
    pCrArgs->PsbKey.Session.ExtTunelId = pOpenLspParams->src_ip;
    pCrArgs->AvoidHopNumber = AvoidHopNumber;
    pCrArgs->AvoidHopsArray = AvoidHopsArray;
    if(GetAlreadyAllocatedBW(pTunnel,&pCrArgs->pLinkBw,&pCrArgs->LinkBwNumber,pCrArgs->BW) != E_OK)
    {
        zlog_err("Cannot get Link BW");
    }
    if(pOpenLspParams->ErHops2Exclude[0] != 0)
    {
        if(pOpenLspParams->ErHops2Exclude[1] != 0)
        {
            pCrArgs->ExcludeHopNumber = 2;
        }
        else
        {
            pCrArgs->ExcludeHopNumber = 1;
        }
        
        if((pCrArgs->ExcludeHopsArray = (IPV4_ADDR *)XMALLOC(MTYPE_TE,sizeof(IPV4_ADDR)*(pCrArgs->ExcludeHopNumber))) != NULL)
        {
            memcpy(pCrArgs->ExcludeHopsArray,
                   pOpenLspParams->ErHops2Exclude,
                   sizeof(IPV4_ADDR)*(pCrArgs->ExcludeHopNumber));
        }
    }
    
    pCrArgs->SetupPriority = pOpenLspParams->SetPrio;
    pCrArgs->HoldPriority  = pOpenLspParams->HoldPrio;
    if(pParams != NULL)
    {
        pCrArgs->HopCount = pParams->hop_limit;
    }
    else
    {
        pCrArgs->HopCount = 0;
    }
    zlog_info("HOP COUNT#%d",pCrArgs->HopCount);
    if(pTunnel->pOpenLspParams != NULL)
    {
        zlog_info("%s %d",__FILE__,__LINE__);
        XFREE(MTYPE_TE,pTunnel->pOpenLspParams);
    }
    zlog_info("%s %d",__FILE__,__LINE__);
    pTunnel->pOpenLspParams = pOpenLspParams;
    if(pTunnel->pCrArgs != NULL)
    {
        if((((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->tunneled == FALSE)&&
           (((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->data.path.ErHopNumber != 0))
        {
            XFREE(MTYPE_TE,((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->data.path.pErHop);
        }
        if(((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->AvoidHopNumber != 0)
        {
            XFREE(MTYPE_TE,((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->AvoidHopsArray);
        }
        if(((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->ExcludeHopNumber != 0)
        {
            XFREE(MTYPE_TE,((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->ExcludeHopsArray);
        }
        if(((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->LinkBwNumber)
        {
            XFREE(MTYPE_TE,((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->pLinkBw);
        }
        XFREE(MTYPE_TE,pTunnel->pCrArgs);
    }
    pTunnel->pCrArgs = pCrArgs;

    if(StartCspfRetryTimer(pTunnel) != E_OK)
    {
        zlog_err("Cannot start CSPF retry timer");
    }
    UnregisterClient((int)pSm,pOpenLspParams->TunnelId);

    zlog_info("preparing CR request5");
    if((pCall = constraint_route_resolution_sm_invoke(pSm,
                                                      pCrArgs)) == NULL)
    {
        zlog_err("cannot invoke constraint route resolution");
        XFREE(MTYPE_TE,pCrArgs);
        LspSmDestroy(pSm);
        return NULL;
    }
    zlog_info("leaving PrepareAndIssueCrResolutionRequest");
    return pCall;
}

SM_CALL_T *LspRequest(INGRESS_API *pOpenLspParams,
                      uns32       ExcludeHopNumber,
                      IPV4_ADDR   *ExcludeHopsArray,
                      SM_T    *pSm,
                      RSVP_TUNNEL_PROPERTIES **ppTunnel,
                      BOOL        ForceCrResolution,
                      LSP_PATH_SHARED_PARAMS *pParams)
{
    SM_CALL_T *pCall = NULL;
    PSB_KEY PsbKey;
    RSVP_TUNNEL_PROPERTIES *pTunnel;
    
    zlog_info("entering LspRequest");

    memset(&PsbKey,0,sizeof(PSB_KEY));
    PsbKey.Session.Dest = pOpenLspParams->Egress;
    PsbKey.Session.TunnelId  = pOpenLspParams->TunnelId;
    PsbKey.Session.ExtTunelId = pOpenLspParams->src_ip;

    if(FindTunnel(&PsbKey,&pTunnel,ALL_TRUNKS) != TRUE)
    {
        TRUNK_TYPE trunk_type;
        if(pOpenLspParams->sm_handle != 0)
        {
            switch(((SM_T *)pOpenLspParams->sm_handle)->sm_type)
            {
            default:
                trunk_type = SEPARATE_NON_ADAPTIVE;
            }
        }
        else
        {
            trunk_type = SEPARATE_NON_ADAPTIVE;
        }
        if(NewTunnel(&PsbKey,&pTunnel,trunk_type) != E_OK)
        {
            zlog_err("cannot create new tunnel's structure");
            LspSmDestroy(pSm);
            return NULL;
        }
        if(pOpenLspParams->sm_handle != 0)
        {
            switch(((SM_T *)pOpenLspParams->sm_handle)->sm_type)
            {
            case FAST_REROUTE_SM:
                pTunnel->up_sm_handle = (void *)pOpenLspParams->sm_handle;
                break;
            default:
                ;
            }
        }
        *ppTunnel = pTunnel;
        pTunnel->RequiredBW = pOpenLspParams->BW;
        pTunnel->sm_handle = pSm;

        return PrepareAndIssueCrResolutionRequest(pOpenLspParams,
                                                  ExcludeHopNumber,
                                                  ExcludeHopsArray,
                                                  pTunnel,
                                                  pSm,
                                                  pParams);
    }
    else if(pOpenLspParams->HopNum != 0) /* Possible REROUTE */
    {
        *ppTunnel = pTunnel;
        pTunnel->RequiredBW = pOpenLspParams->BW;
        pTunnel->sm_handle = pSm;
        return PrepareAndIssueCrResolutionRequest(pOpenLspParams,
            ExcludeHopNumber,
            ExcludeHopsArray,
            pTunnel,
            pSm,
            pParams);
    }
    else
    {
        RSVP_LSP_PROPERTIES *pRsvpLsp = GetWorkingRsvpLsp(pTunnel);

        *ppTunnel = pTunnel;

        pTunnel->sm_handle = pSm;
           
        /* BW DECREASE OPERATION */
        if(pTunnel->RequiredBW > pOpenLspParams->BW)
        {
            /* For tunneled LSPs */
            if((pRsvpLsp != NULL)&&
                (pRsvpLsp->tunneled == TRUE))
            {
                /* invoke lsp sm for the tunnel */
            }

            NotifySatisfiedRequests(pTunnel);
                           
                  
            if(ForceCrResolution == TRUE)
            {
                pTunnel->RequiredBW = pOpenLspParams->BW;
                return PrepareAndIssueCrResolutionRequest(pOpenLspParams,
                    ExcludeHopNumber,
                    ExcludeHopsArray,
                    pTunnel,
                    pSm,
                    pParams);
            }
            else
            {
                if(NewRsvpLspRequired(pTunnel,pOpenLspParams) == TRUE)
                {
                    if(((pRsvpLsp != NULL)&&(pRsvpLsp->RequestedBW >= pOpenLspParams->BW))||(pRsvpLsp == NULL))
                    {
                        pTunnel->pOpenLspParams = pOpenLspParams;
                        if(CreateAndInvokeRsvpLsp(pTunnel,
                                                  pRsvpLsp,
                                                  FALSE,
                                                  NULL) != E_OK) 
                        {
                            zlog_err("cannot modify LSP %s %d",__FILE__,__LINE__);
                        }
                    }
                    else
                    {
                        RSVP_LSP_PROPERTIES *pRsvpLsp2TakePath;
                        if((pRsvpLsp2TakePath = FindRsvpLspPathWithBW(pTunnel,pOpenLspParams->BW)) == NULL)
                        {
                            zlog_err("unexpected: cannot find path with BW %s %d",__FILE__,__LINE__);
                            return NULL;
                        }
                        pTunnel->pOpenLspParams = pOpenLspParams;
                        if(CreateAndInvokeRsvpLsp(pTunnel,
                                                  pRsvpLsp2TakePath,
                                                  FALSE,
                                                  NULL) != E_OK) 
                        {
                            zlog_err("cannot modify LSP %s %d",__FILE__,__LINE__);
                        }
                    }
                    pTunnel->RequiredBW = pOpenLspParams->BW;
                }
            }
        }
        else /* BW INCREASE OPERATION */
        {
            RSVP_LSP_PROPERTIES *pWorkingRsvpLsp;

            if((pRsvpLsp != NULL)&&
               (pRsvpLsp->tunneled == TRUE))
            {
                return PrepareAndIssueCrResolutionRequest(pOpenLspParams,
                    ExcludeHopNumber,
                    ExcludeHopsArray,
                    pTunnel,
                    pSm,
                    pParams);
            }

            if(((pWorkingRsvpLsp = CurrentPathHasAvBw(pTunnel,pOpenLspParams->BW)) != NULL)&&
                (ForceCrResolution == FALSE))
            {
                int i;
                zlog_info("Path is extendable.");
                /* pRsvpLsp's path is choosen */
                pOpenLspParams->HopNum = pWorkingRsvpLsp->forw_info.path.HopCount;
                for(i = 0;i < pOpenLspParams->HopNum;i++)
                {
                    pOpenLspParams->Path[i].Loose = 0;
                    pOpenLspParams->Path[i].IpAddr = pWorkingRsvpLsp->forw_info.path.pErHopsList[i];
                    pOpenLspParams->Path[i].PrefixLength = 32;
                }
            }
            pTunnel->RequiredBW = pOpenLspParams->BW;
            zlog_info("Issuing CR Resolution request...");
            return PrepareAndIssueCrResolutionRequest(pOpenLspParams,
                ExcludeHopNumber,
                ExcludeHopsArray,
                pTunnel,
                pSm,
                pParams);
        }
    }
    return pCall;
}

BOOL NewRsvpLspRequired(RSVP_TUNNEL_PROPERTIES *pTunnel,INGRESS_API *pOpenLspParams)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties;

    zlog_info("entering NewRsvpLspRequired");

    while(pRsvpLsp != NULL)
    {
        if(pRsvpLsp->RequestedBW == pOpenLspParams->BW)
        {
            zlog_info("leaving NewRsvpLspRequired");
            return FALSE;
        }
        pRsvpLsp = pRsvpLsp->next;
    }
    zlog_info("leaving NewRsvpLspRequired");
    return TRUE;
}

RSVP_LSP_PROPERTIES *FindRsvpLspPathWithBW(RSVP_TUNNEL_PROPERTIES *pTunnel,float BW)
{
    float TempBW = 0xFFFFFFFF; /* FIXME*/
    RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties,*pSelectedRsvpLsp = NULL;

    zlog_info("entering FindRsvpLspPathWithBW");

    while(pRsvpLsp != NULL)
    {
        if(pRsvpLsp->RequestedBW >= BW)
        {
            if(pRsvpLsp->RequestedBW < TempBW)
            {
                pSelectedRsvpLsp = pRsvpLsp;
                TempBW = pRsvpLsp->RequestedBW;
            }
        }
        pRsvpLsp = pRsvpLsp->next;
    }
    zlog_info("leaving FindRsvpLspPathWithBW");
    return pSelectedRsvpLsp;
}

void NotifySatisfiedRequests(RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    zlog_info("entering NotifySatisfiedRequests");
    if(pTunnel->up_sm_handle != 0)
    {
        if(sm_gen_async_event_send(pTunnel->up_sm_handle,INGRESS_LSP_OPERATION_COMPLETE_EVENT,NULL) != 0)
        {
            zlog_err("\ncannot send async event %s %d",__FILE__,__LINE__);
        }
    }
    zlog_info("leaving NotifySatisfiedRequests");
}

void NotifyFailedRequests(RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    zlog_info("entering NotifyFailedRequests");

    if(pTunnel->up_sm_handle != 0)
    {
        if(sm_gen_async_event_send(pTunnel->up_sm_handle,INGRESS_LSP_OPERATION_FAILED_EVENT,NULL) != 0)
        {
            zlog_err("\ncannot send async event %s %d",__FILE__,__LINE__);
        }
    }
    zlog_info("leaving NotifyFailedRequests");
}

uns16 NewRsvpLspId(RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    if(pTunnel->LastInvokedLspId == 0xFFFF)
        pTunnel->LastInvokedLspId = 1;
    else
        pTunnel->LastInvokedLspId++;
    return pTunnel->LastInvokedLspId;
}

uns32 CopyRsvpLspPath(RSVP_LSP_PROPERTIES *pRsvpLsp,INGRESS_API *pOpenRsvpLsp)
{
    zlog_info("entering CopyRsvpLspPath");
    if(pOpenRsvpLsp->HopNum != 0)
    {
        IPV4_ADDR *pArray;
        int i;

        if((pArray = (IPV4_ADDR *)XMALLOC(MTYPE_TE,sizeof(IPV4_ADDR)*pOpenRsvpLsp->HopNum)) == NULL)
        {
            zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
            return E_ERR;
        }
          
        for(i = 0;i < pOpenRsvpLsp->HopNum;i++)
        {
            *(pArray + i) = pOpenRsvpLsp->Path[i].IpAddr;
        }
        pRsvpLsp->forw_info.path.pErHopsList = pArray;
    }
    else
        pRsvpLsp->forw_info.path.pErHopsList = NULL;
    pRsvpLsp->forw_info.path.HopCount = pOpenRsvpLsp->HopNum;
    pRsvpLsp->oIfIndex = pOpenRsvpLsp->OutIfIndex;
    zlog_info("leaving CopyRsvpLspPath");
    return E_OK;
}

RSVP_LSP_PROPERTIES *GetWorkingRsvpLsp(RSVP_TUNNEL_PROPERTIES *pTunnel)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties;

    zlog_info("entering GetWorkingRsvpLsp");

    while(pRsvpLsp != NULL)
    {
        if(pRsvpLsp->LspId == pTunnel->LspId)
            return pRsvpLsp;
        pRsvpLsp = pRsvpLsp->next;
    }
    zlog_info("leaving GetWorkingRsvpLsp");
    return NULL;
}

uns32 CopyWorkingPath(RSVP_LSP_PROPERTIES *pDestRsvpLsp,RSVP_LSP_PROPERTIES *pSourceRsvpLsp)
{
    IPV4_ADDR *pArray;
    int i;

    zlog_info("entering CopyWorkingPath");

    if((pArray = (IPV4_ADDR *)XMALLOC(MTYPE_TE,sizeof(IPV4_ADDR)*pSourceRsvpLsp->forw_info.path.HopCount)) == NULL)
    {
        zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
        return E_ERR;
    }
          
    for(i = 0;i < pSourceRsvpLsp->forw_info.path.HopCount;i++)
    {
        *(pArray + i) = pSourceRsvpLsp->forw_info.path.pErHopsList[i];
    }
    pDestRsvpLsp->forw_info.path.pErHopsList = pArray;
    pDestRsvpLsp->forw_info.path.HopCount = pSourceRsvpLsp->forw_info.path.HopCount;
//    pDestRsvpLsp->card = pSourceRsvpLsp->card;
    pDestRsvpLsp->oIfIndex = pSourceRsvpLsp->oIfIndex;
    zlog_info("leaving CopyWorkingPath");
    return E_OK;
}

BOOL IdenticalRsvpLspExists(RSVP_TUNNEL_PROPERTIES *pTunnel,RSVP_LSP_PROPERTIES *pThisRsvpLsp,uns16 *LspDiffPathSameParams)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties;

    zlog_info("entering IdenticalRsvpLspExists");

    while(pRsvpLsp != NULL)
    {
        if(pRsvpLsp->LspId != pThisRsvpLsp->LspId)
        {
            if((pRsvpLsp->RequestedBW == pThisRsvpLsp->RequestedBW)&&
                //(pRsvpLsp->card == pThisRsvpLsp->card)&&
                (pRsvpLsp->oIfIndex == pThisRsvpLsp->oIfIndex)&&
                (pRsvpLsp->SetupPriority == pThisRsvpLsp->SetupPriority)&&
                (pRsvpLsp->HoldPriority == pThisRsvpLsp->HoldPriority)&&
                (pRsvpLsp->ExcludeAny == pThisRsvpLsp->ExcludeAny)&&
                (pRsvpLsp->IncludeAny == pThisRsvpLsp->IncludeAny)&&
                (pRsvpLsp->IncludeAll == pThisRsvpLsp->IncludeAll)&&
                (pRsvpLsp->FrrDesired == pThisRsvpLsp->FrrDesired)&&
                (pRsvpLsp->LabelRecordingDesired == pThisRsvpLsp->LabelRecordingDesired))
            {
                *LspDiffPathSameParams = pRsvpLsp->LspId;
                if((pRsvpLsp->tunneled == FALSE)&&
                    (pThisRsvpLsp->tunneled == FALSE))
                {
                    if((pRsvpLsp->forw_info.path.HopCount == pThisRsvpLsp->forw_info.path.HopCount)&&
                        (memcmp(pRsvpLsp->forw_info.path.pErHopsList,
                                pThisRsvpLsp->forw_info.path.pErHopsList,
                                sizeof(IPV4_ADDR)*(pRsvpLsp->forw_info.path.HopCount)) == 0))
                    {
                        return TRUE;
                    }
                }
                else if((pRsvpLsp->tunneled == TRUE)&&
                    (pThisRsvpLsp->tunneled == TRUE))
                {
                    if(memcmp(&pRsvpLsp->forw_info.tunnel,&pThisRsvpLsp->forw_info.tunnel,sizeof(PSB_KEY)) == 0)
                    {
                        return TRUE;
                    }
                }
            }
        }
        pRsvpLsp = pRsvpLsp->next;
    }
    zlog_info("leaving IdenticalRsvpLspExists");
    return FALSE;
}

void UpdatePathBW(RSVP_TUNNEL_PROPERTIES *pTunnel,RSVP_LSP_PROPERTIES *pCurrentRsvpLsp,IPV4_ADDR dest)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties;
    uns16 LspId = pCurrentRsvpLsp->LspId;
    float *BWs;
    int lsp_hop_index,curr_lsp_hop_index,number_of_links,i;
    IPV4_ADDR lsp_local_ip,lsp_remote_ip,current_lsp_local_ip,current_lsp_remote_ip;

    zlog_info("entering UpdatePathBW");

    if(pRsvpLsp->tunneled == TRUE)
    {
        return;
    }
    number_of_links = pCurrentRsvpLsp->forw_info.path.HopCount / 2;
    if((BWs = (float *)XMALLOC(MTYPE_TE,sizeof(float)*(number_of_links))) == NULL)
    {
        zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
        return;
    }
    
    while(pRsvpLsp != NULL)
    {
        if((pRsvpLsp->LspId != LspId)&&
           (pRsvpLsp->tunneled == FALSE)&&
           (pRsvpLsp->HoldPriority <= pCurrentRsvpLsp->HoldPriority))
        {
            for(lsp_hop_index = 1;
                lsp_hop_index < pRsvpLsp->forw_info.path.HopCount;
                lsp_hop_index += 2)
            {
                for(curr_lsp_hop_index = 1,i = 0;
                    (curr_lsp_hop_index < (pCurrentRsvpLsp->forw_info.path.HopCount - 1))&&(i <  number_of_links);
                    curr_lsp_hop_index += 2,i++)
                {
                    lsp_local_ip = pRsvpLsp->forw_info.path.pErHopsList[lsp_hop_index];
                    current_lsp_local_ip = pCurrentRsvpLsp->forw_info.path.pErHopsList[curr_lsp_hop_index];
                    if(lsp_local_ip == current_lsp_local_ip)
                    {
                        lsp_remote_ip = pRsvpLsp->forw_info.path.pErHopsList[lsp_hop_index + 1];
                        current_lsp_remote_ip = pCurrentRsvpLsp->forw_info.path.pErHopsList[curr_lsp_hop_index + 1];
                        if(lsp_remote_ip == current_lsp_remote_ip)
                        {
                            if(BWs[i] < pRsvpLsp->RequestedBW)
                            {
                                BWs[i] = pRsvpLsp->RequestedBW;
                            }
                        }
                    }
                }
            }
        }
        pRsvpLsp = pRsvpLsp->next;
    }
    for(curr_lsp_hop_index = 1,i = 0;
        (curr_lsp_hop_index < (pCurrentRsvpLsp->forw_info.path.HopCount - 1))&&(i < number_of_links);
        curr_lsp_hop_index += 2,i++)
    {
        if(BWs[i] < pCurrentRsvpLsp->RequestedBW)
        {
            IPV4_ADDR *pIpAddrArray = pCurrentRsvpLsp->forw_info.path.pErHopsList;
            IPV4_ADDR remote_ip = pIpAddrArray[curr_lsp_hop_index + 1];
            if(pIpAddrArray[curr_lsp_hop_index] != remote_ip)
            {
                zlog_info("Updating BW#%f  Local IP#%x Remote IP#%x",
                       pCurrentRsvpLsp->RequestedBW - BWs[i],
                       pCurrentRsvpLsp->forw_info.path.pErHopsList[curr_lsp_hop_index],
                       pCurrentRsvpLsp->forw_info.path.pErHopsList[curr_lsp_hop_index + 1]);
                if(rdb_remote_link_bw_update(pCurrentRsvpLsp->forw_info.path.pErHopsList[curr_lsp_hop_index],
                                                  pCurrentRsvpLsp->forw_info.path.pErHopsList[curr_lsp_hop_index + 1],
                                                  pCurrentRsvpLsp->RequestedBW - BWs[i],
                                                  pCurrentRsvpLsp->HoldPriority, /* SHOULD BE CHECKED!!!*/
                                                  PSC_PATH) != E_OK)
                {
                    zlog_err("\ncannot update remote link %s %d",__FILE__,__LINE__);
                }
            }
        }
    }
    zlog_info("leaving UpdatePathBW");
    XFREE(MTYPE_TE,BWs);
}

static E_RC GetAlreadyAllocatedBW(RSVP_TUNNEL_PROPERTIES *pTunnel,void **ppLinkBw,uns32 *LinkBwNumber,float CommonBwValue)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp;
    LINK_BW *pLinkBw;
    int curr_lsp_hop_index,i,number_of_links;
    float Bw;
    zlog_info("entering GetAlreadyAllocatedBW");
    *ppLinkBw = NULL;
    if((pRsvpLsp = GetWorkingRsvpLsp(pTunnel)) == NULL)
    {
        return E_OK;
    }
    if(pRsvpLsp->tunneled)
    {
        return E_OK;
    }
    if(pRsvpLsp->forw_info.path.HopCount < 2)
    {
        return E_OK;
    }
    number_of_links = pRsvpLsp->forw_info.path.HopCount / 2;
    if((pLinkBw = XMALLOC(MTYPE_TE,sizeof(LINK_BW)*(number_of_links))) == NULL)
    {
        zlog_err("Memory allocation failed %s %d",__FILE__,__LINE__);
        return E_ERR;
    }
    if(pRsvpLsp->RequestedBW < CommonBwValue)
    {
        Bw = CommonBwValue - pRsvpLsp->RequestedBW;
    }
    else
    {
        Bw = 0;
    }
    for(curr_lsp_hop_index = 1,i = 0;
        (curr_lsp_hop_index < pRsvpLsp->forw_info.path.HopCount)&&(i < number_of_links);
        curr_lsp_hop_index += 2,i++)
    {
        pLinkBw[i].LocalIp.s_addr = pRsvpLsp->forw_info.path.pErHopsList[curr_lsp_hop_index];
        pLinkBw[i].RemoteIp.s_addr = pRsvpLsp->forw_info.path.pErHopsList[curr_lsp_hop_index + 1];
        pLinkBw[i].Bw = Bw;
    }
    *ppLinkBw = pLinkBw;
    *LinkBwNumber = number_of_links;
    zlog_info("leaving GetAlreadyAllocatedBW");
    return E_OK;
}

uns32 CreateAndInvokeRsvpLsp(RSVP_TUNNEL_PROPERTIES *pTunnel,
                             RSVP_LSP_PROPERTIES *pRsvpLsp2TakePath,
                             BOOL tunneled,
                             PSB_KEY *PsbKey)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp = NULL,*pRsvpWorkingLsp = NULL;
    uns16 LspId = 0;
    TE_API_MSG Msg;
    INGRESS_API *pOpenRsvpLsp;
    uns16 LspDiffPathSameParams = 0,RemoveLspAndExit = 0;
    USER_LSP *pUserLsp;
  
    zlog_info("entering CreateAndInvokeRsvpLsp");
      
    pOpenRsvpLsp = pTunnel->pOpenLspParams;

    LspId = NewRsvpLspId(pTunnel);

    if(NewRsvpLsp(pTunnel,&pRsvpLsp) != E_OK)
    {
        zlog_err("\ncannot create and invoke RSVP LSP %s %d",__FILE__,__LINE__);
        return E_ERR;
    }
    pRsvpLsp->RequestedBW = pOpenRsvpLsp->BW;

    pRsvpLsp->LspId = LspId;
    zlog_info("\nTunnel # %x LSP # %x",pTunnel->TunnelId,pRsvpLsp->LspId);
    pOpenRsvpLsp->LspId = LspId;

    pRsvpLsp->SetupPriority = pOpenRsvpLsp->SetPrio;
    pRsvpLsp->HoldPriority = pOpenRsvpLsp->HoldPrio;
    pRsvpLsp->ExcludeAny = pOpenRsvpLsp->ExcludeAny;
    pRsvpLsp->IncludeAny = pOpenRsvpLsp->IncludeAny;
    pRsvpLsp->IncludeAll = pOpenRsvpLsp->IncludeAll;
    pRsvpLsp->FrrDesired = pOpenRsvpLsp->FrrDesired;
    pRsvpLsp->LabelRecordingDesired = pOpenRsvpLsp->LabelRecordingDesired;

    if(pRsvpLsp2TakePath == NULL)
    {
        if(tunneled == TRUE)
        {
            pRsvpLsp->tunneled = TRUE;
            pRsvpLsp->forw_info.tunnel = *PsbKey;
            pRsvpLsp->oIfIndex = pOpenRsvpLsp->OutIfIndex;
            zlog_info("\nTunneled LSP: %x %x %x %x %x %x %x",
                pOpenRsvpLsp->Egress,
                pOpenRsvpLsp->TunnelId,
                pOpenRsvpLsp->src_ip,
                pOpenRsvpLsp->LspId,
                pOpenRsvpLsp->OutIfIndex,
                pOpenRsvpLsp->NextHop);
        }
        else if(CopyRsvpLspPath(pRsvpLsp,pOpenRsvpLsp) != E_OK)
        {
            zlog_err("\ncannot copy RSVP LSP path %s %d",__FILE__,__LINE__);
            return E_ERR;
        }
    }
    else
    {
        zlog_info("\ncopying working path");
        if(CopyWorkingPath(pRsvpLsp,pRsvpLsp2TakePath) != E_OK)
        {
            zlog_err("\ncannot copy RSVP LSP path %s %d",__FILE__,__LINE__);
            return E_ERR;
        }
        if(pRsvpLsp->tunneled == FALSE)
        {
            pOpenRsvpLsp->HopNum = pRsvpLsp->forw_info.path.HopCount;
            if(pRsvpLsp->forw_info.path.HopCount != 0)
            {
                int i;
                for(i = 0;i < pOpenRsvpLsp->HopNum;i++)
                {
                    pOpenRsvpLsp->Path[i].Loose = 0;
                    pOpenRsvpLsp->Path[i].PrefixLength = 32;
                    pOpenRsvpLsp->Path[i].IpAddr = pRsvpLsp->forw_info.path.pErHopsList[i];
                }
                pOpenRsvpLsp->NextHop = pRsvpLsp->forw_info.path.pErHopsList[0];
            }
            else
            {
                zlog_info("\nER hops list is empty %s %d",__FILE__,__LINE__);
            }
            pOpenRsvpLsp->NextHop = pRsvpLsp->forw_info.path.pErHopsList[0];
        }
        else
        {
            pOpenRsvpLsp->NextHop = pRsvpLsp->forw_info.tunnel.Session.Dest;
        }
        pOpenRsvpLsp->OutIfIndex = pRsvpLsp->oIfIndex;
    }
        
    UpdatePathBW(pTunnel,pRsvpLsp,pOpenRsvpLsp->Egress);
    
    if(IdenticalRsvpLspExists(pTunnel,pRsvpLsp,&LspDiffPathSameParams) == TRUE)
    {
        RemoveLspAndExit = 1;
    }
    else if(LspDiffPathSameParams)
    {
        if((pUserLsp = UserLspGet(pTunnel->UserLspName)) != NULL)
        {
            STATIC_PATH *pStaticPath;
            if((pUserLsp->pUserLspTunnels != NULL)&&
               (pTunnel->TunnelId != pUserLsp->pUserLspTunnels->TunnelId)&&
               (rdb_get_static_path(pTunnel->StaticPathName,&pStaticPath) != E_OK))
            {
                IPV4_ADDR *pPrimaryErHops;
                uns32 PrimaryErHopsNumber = 0;
                RSVP_LSP_PROPERTIES *pClone = pTunnel->properties;
                while(pClone != NULL)
                {
                    if(pClone->LspId == LspDiffPathSameParams)
                    {
                        break;
                    }
                    pClone = pClone->next;
                }
                if((pClone != NULL)&&(!pClone->tunneled)&&(!pRsvpLsp->tunneled))
                {
                   if(GetTunnelHops(pUserLsp->pUserLspTunnels,&PrimaryErHopsNumber,&pPrimaryErHops) == E_OK)
                   {
                      int i,j,ClonesSharedHopsCount = 0,ThisLspSharedHopsCount = 0;
                      if(pPrimaryErHops != NULL)
                      {
                          for(i = 0,j = 0;i < PrimaryErHopsNumber;i++,j += 2)
                          {
                              if(pPrimaryErHops[i] == pClone->forw_info.path.pErHopsList[j])
                              {
                                  ClonesSharedHopsCount++;
                              }
                          }
                          for(i = 0,j = 0;i < PrimaryErHopsNumber;i++,j += 2)
                          {
                              if(pPrimaryErHops[i] == pRsvpLsp->forw_info.path.pErHopsList[j])
                              {
                                  ThisLspSharedHopsCount++;
                              }
                          }
                          if(ThisLspSharedHopsCount >= ClonesSharedHopsCount)
                          {
                              RemoveLspAndExit = 1;
                          }
                          XFREE(MTYPE_TE,pPrimaryErHops);
                      }
                   }
                }
            }
        }
    }
    if(RemoveLspAndExit)
    {
        RSVP_LSP_PROPERTIES *pTemp = pTunnel->properties,*pRsvpLspPrev = NULL;
        while(pTemp != NULL)
        {
            if(pTemp == pRsvpLsp)
            {
                if(pTemp == pTunnel->properties)
                {
                    pTunnel->properties = pTunnel->properties->next;
                }
                else
                {
                    pRsvpLspPrev->next = pTemp->next;
                }
                if(pRsvpLsp->tunneled == FALSE)
                {
                    if(pRsvpLsp->forw_info.path.pErHopsList != NULL)
                    {
                        XFREE(MTYPE_TE,pRsvpLsp->forw_info.path.pErHopsList);
                    }
                }
                XFREE(MTYPE_TE,pRsvpLsp);
                if(pTunnel->adaptivity_timer.is_active == FALSE)
                {
                    if((pUserLsp = UserLspGet(pTunnel->UserLspName)) != NULL)
                    {
                        LSP_PATH_SHARED_PARAMS *pParams;
                        pParams = PathParamsGet(pUserLsp,
                                                pTunnel->StaticPathName,
                                                ((!strcmp(pUserLsp->params.Primary,pTunnel->StaticPathName))&&(pUserLsp->pUserLspTunnels->TunnelId == pTunnel->TunnelId)));
                        StartAdaptivityTimer(pParams->optimize_timer,pTunnel);
                    }
                }
                return E_OK;
            }
            pRsvpLspPrev = pTemp;
            pTemp = pTemp->next;
        }
    }
    if(pRsvpLsp->tunneled == FALSE)
    {
        int i;
        IPV4_ADDR  *pIpAddr = pRsvpLsp->forw_info.path.pErHopsList;
        zlog_info("\nPATH:");
        for(i = 0;i < pRsvpLsp->forw_info.path.HopCount;i++)
            zlog_info("\nER HOP#%d %x",i+1,pIpAddr[i]);
    }
    Msg.NotificationType = PATH_SEND_CMD;
    memcpy(&Msg.u.IngressApi,pOpenRsvpLsp,sizeof(INGRESS_API));
    if((pRsvpWorkingLsp = GetWorkingRsvpLsp(pTunnel)) != NULL)
    {
        if((pRsvpLsp->tunneled == FALSE)&&
            (pRsvpWorkingLsp->tunneled == FALSE))
        {
            if(!((pRsvpLsp->forw_info.path.HopCount == pRsvpWorkingLsp->forw_info.path.HopCount)&&
                (memcmp(pRsvpLsp->forw_info.path.pErHopsList,
                    pRsvpWorkingLsp->forw_info.path.pErHopsList,
                    sizeof(IPV4_ADDR)*(pRsvpLsp->forw_info.path.HopCount)) == 0)))
                pTunnel->ReRoute = TRUE;
        }
    }
    else
    {
        pTunnel->ReRoute = TRUE;
    }
    Msg.u.IngressApi.LspId = LspId;
    Msg.u.IngressApi.NextHop = htonl(Msg.u.IngressApi.NextHop);

    zlog_info("Next Hop %x OutIf %x %s %d",
           Msg.u.IngressApi.NextHop,Msg.u.IngressApi.OutIfIndex,__FILE__,__LINE__);

    te_send_msg(&Msg,sizeof(Msg));

    StartLspSetupTimer(pTunnel);

    if((pOpenRsvpLsp->FrrDesired)&&
        (pRsvpLsp->tunneled == FALSE)&&   /* if tunneled, the tunnel should be reestablished with local protection */
        (pOpenRsvpLsp->HopNum > 1))
    {
        FRR_SM_CALL frr_sm_call;
        int k;
        IPV4_ADDR protected_node_router_id = 0,merge_node_router_id = 0,after_merge_node_router_id = 0;

        memset(&frr_sm_call,0,sizeof(FRR_SM_CALL));
        frr_sm_call.frr_key.OutIfIndex = pOpenRsvpLsp->OutIfIndex;
        
        if(rdb_remote_link_router_id_get(pOpenRsvpLsp->NextHop,
            &protected_node_router_id) != E_OK)
        {
            protected_node_router_id = pOpenRsvpLsp->NextHop;
        }
        frr_sm_call.frr_key.protected_node = protected_node_router_id;
        for(k = 1;k < pOpenRsvpLsp->HopNum;k++)
        {
            rdb_remote_link_router_id_get(pOpenRsvpLsp->Path[k].IpAddr,
                &merge_node_router_id);
            if((merge_node_router_id != 0)&&
                (merge_node_router_id != protected_node_router_id))
            {
                frr_sm_call.frr_key.merge_node = merge_node_router_id;
                frr_sm_call.MergeNode = pOpenRsvpLsp->Path[k].IpAddr;
                break;
            }
        }
        if(frr_sm_call.frr_key.merge_node == 0)
        {
            merge_node_router_id = 
                frr_sm_call.frr_key.merge_node = 
                pOpenRsvpLsp->Path[1].IpAddr;
            frr_sm_call.MergeNode = pOpenRsvpLsp->Path[1].IpAddr;
        }
        for(;k < pOpenRsvpLsp->HopNum;k++)
        {
            rdb_remote_link_router_id_get(pOpenRsvpLsp->Path[k].IpAddr,
                &after_merge_node_router_id);
            if((after_merge_node_router_id != 0)&&
                (after_merge_node_router_id != merge_node_router_id))
            {
                frr_sm_call.frr_key.prohibited_penultimate_node = after_merge_node_router_id;
                break;
            }
        }
        
        zlog_info("\ncalling FRR SM with key %x %x %x %x",
            frr_sm_call.frr_key.protected_node,
            frr_sm_call.frr_key.OutIfIndex,
            frr_sm_call.frr_key.merge_node,
            frr_sm_call.frr_key.prohibited_penultimate_node);

        frr_sm_call.PsbKey.Session.Dest = pOpenRsvpLsp->Egress;
        frr_sm_call.PsbKey.Session.TunnelId = pOpenRsvpLsp->TunnelId;
        frr_sm_call.PsbKey.Session.ExtTunelId = pOpenRsvpLsp->src_ip;
        frr_sm_call.PsbKey.SenderTemplate.LspId = pOpenRsvpLsp->LspId;
#ifdef FRR_SM_DEFINED
        if((pCall = fast_reroute_sm_sync_invoke(&frr_sm_call,BYPASS_SETUP_REQ_EVENT)) != NULL)
        {
            zlog_info("\nOK...");
            sm_call(pCall);
        }
        else
        {
            zlog_err("\ncannot invoke FRR SM %s %d",__FILE__,__LINE__);
        }
#endif
    }
    XFREE(MTYPE_TE,pTunnel->pOpenLspParams);
    pTunnel->pOpenLspParams = NULL;
    zlog_info("leaving CreateAndInvokeRsvpLsp");
    return E_OK;
}

uns32 RsvpTunnelTearDown(RSVP_TUNNEL_PROPERTIES *pTunnel,IPV4_ADDR dest,IPV4_ADDR source)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties;
    TE_API_MSG TeApi;
    PSB_KEY PsbKey;
  
    zlog_info("entering RsvpTunnelTearDown");
      
    TeApi.NotificationType = PATH_TEAR_CMD;
    TeApi.u.IngressApi.Egress = dest;
    TeApi.u.IngressApi.TunnelId = pTunnel->TunnelId;
    TeApi.u.IngressApi.src_ip = source;

    memset(&PsbKey,0,sizeof(PSB_KEY));

    PsbKey.Session.Dest = dest;
    PsbKey.Session.TunnelId = pTunnel->TunnelId;
    PsbKey.Session.ExtTunelId = source;

    while(pRsvpLsp != NULL)
    {
        TeApi.u.IngressApi.LspId = pRsvpLsp->LspId;
        te_send_msg(&TeApi,sizeof(TeApi));
#if DATA_PLANE
        {
           char key[23];
           USER_LSP *pUserLsp;
           IPV4_ADDR next_hop = 0;
           if((pRsvpLsp->tunneled == FALSE)&&(pRsvpLsp->forw_info.path.HopCount != 0))
           {
              next_hop = pRsvpLsp->forw_info.path.pErHopsList[0];
           }
           sprintf(key,"%x%d%x%d",dest,pTunnel->TunnelId,source,pRsvpLsp->LspId);
           mplsTeOutLabel(&pRsvpLsp->Label,1,key,next_hop,0);
           if((pUserLsp = UserLspGet(pTunnel->UserLspName)) != NULL)
           {
               if(pUserLsp->params.PolicyName[0] != '\0')
               {
                  mplsTePolicy(pUserLsp->params.PolicyName,key,0);
               }
           }
        }
#endif
        PsbKey.SenderTemplate.LspId = pRsvpLsp->LspId;
#ifdef FRR_SM_DEFINED
        FrrIngressRelease(&PsbKey);
#endif
        pRsvpLsp = pRsvpLsp->next;
    }

    PsbKey.SenderTemplate.LspId = 0;
    StopAdaptivityTimer(pTunnel);
    StopLspSetupTimer(pTunnel);
    StopLspSetupRetryTimer(pTunnel);
    StopCspfRetryTimer(pTunnel);
    if(pTunnel->pCrArgs != NULL)
    {
        if((((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->tunneled == FALSE)&&
           (((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->data.path.ErHopNumber != 0))
        {
            XFREE(MTYPE_TE,((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->data.path.pErHop);
        }
        if(((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->AvoidHopNumber != 0)
        {
            XFREE(MTYPE_TE,((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->AvoidHopsArray);
        }
        if(((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->ExcludeHopNumber != 0)
        {
            XFREE(MTYPE_TE,((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->ExcludeHopsArray);
        }
        if(((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->LinkBwNumber)
        {
            XFREE(MTYPE_TE,((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->pLinkBw);
        }
        XFREE(MTYPE_TE,pTunnel->pCrArgs);
    }
    if(pTunnel->pOpenLspParams != NULL)
    {
        UnregisterClient((int)pTunnel->sm_handle,
                         ((INGRESS_API *)(pTunnel->pOpenLspParams))->TunnelId);
        XFREE(MTYPE_TE,pTunnel->pOpenLspParams);
    }
    
    if(DeleteTunnel(&PsbKey,SEPARATE_NON_ADAPTIVE) != E_OK)
    {
        zlog_err("\ncannot delete tunnel %s %d",__FILE__,__LINE__);
        return E_ERR;
    }
    zlog_info("\nTunnel %x deleted",PsbKey.Session.TunnelId);
    zlog_info("leaving RsvpTunnelTearDown");
    return E_OK;
}

void RemoveRsvpLsp(RSVP_TUNNEL_PROPERTIES *pTunnel,uns16 LspId,IPV4_ADDR dest,IPV4_ADDR source)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties,*pRsvpLspNext,*pRsvpLspPrev = NULL;
    TE_API_MSG TeApi;
    PSB_KEY PsbKey;

    zlog_info("entering RemoveRsvpLsp");

    memset(&PsbKey,0,sizeof(PSB_KEY));
    PsbKey.Session.Dest = dest;
    PsbKey.Session.TunnelId = pTunnel->TunnelId;
    PsbKey.Session.ExtTunelId = source;
    
    while(pRsvpLsp != NULL)
    {
        /* tear down all that in the range > Allocated */
        if(pRsvpLsp->LspId == LspId)
        {
            /* tear this lsp down */
            TeApi.NotificationType = PATH_TEAR_CMD;
            TeApi.u.IngressApi.Egress = dest;
            TeApi.u.IngressApi.TunnelId = pTunnel->TunnelId;
            TeApi.u.IngressApi.src_ip = source;
            TeApi.u.IngressApi.LspId = pRsvpLsp->LspId;
            /*                zlog_info("\nsending tear down request to %x for Dest %x Tunnel %d Source %x LSP %x",
                              pRsvpLsp->card,
                              dest,
                              pTunnel->TunnelId,
                              source,
                              pRsvpLsp->LspId);*/
            te_send_msg(&TeApi,sizeof(TeApi));
#if DATA_PLANE
            {
               char key[23];
               USER_LSP *pUserLsp;
               IPV4_ADDR next_hop = 0;
               if((pRsvpLsp->tunneled == FALSE)&&(pRsvpLsp->forw_info.path.HopCount != 0))
               {
                  next_hop = pRsvpLsp->forw_info.path.pErHopsList[0];
               }
               sprintf(key,"%x%d%x%d",dest,pTunnel->TunnelId,source,pRsvpLsp->LspId);
               mplsTeOutLabel(&pRsvpLsp->Label,1,key,next_hop,0);
               if((pUserLsp = UserLspGet(pTunnel->UserLspName)) != NULL)
               {
                  if(pUserLsp->params.PolicyName[0] != '\0')
                  {
                     mplsTePolicy(pUserLsp->params.PolicyName,key,0);
                  }
               }
            }
#endif
            PsbKey.SenderTemplate.LspId = pRsvpLsp->LspId;
#ifdef FRR_SM_DEFINED
            FrrIngressRelease(&PsbKey);
#endif
            if(pTunnel->LspId == LspId)
            {
                pTunnel->LspId = 0;
            }
            pRsvpLspNext = pRsvpLsp->next;
            if(pRsvpLsp->forw_info.path.pErHopsList != NULL)
            {
                XFREE(MTYPE_TE,pRsvpLsp->forw_info.path.pErHopsList);
            }
            if(pTunnel->properties == pRsvpLsp)
            {
                pTunnel->properties = pTunnel->properties->next;
            }
            else
            {
                pRsvpLspPrev->next = pRsvpLsp->next;
            }
            XFREE(MTYPE_TE,pRsvpLsp);
            pRsvpLsp = pRsvpLspNext;
        }
        else
        {
            pRsvpLspPrev = pRsvpLsp;
            pRsvpLsp = pRsvpLsp->next;
        }
    }
    zlog_info("leaving RemoveRsvpLsp");
}

RSVP_LSP_PROPERTIES *FindRsvpLspByLspId(RSVP_TUNNEL_PROPERTIES *pTunnel,uns16 LspId)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties;
    while(pRsvpLsp != NULL)
    {
        if(pRsvpLsp->LspId == LspId)
            return pRsvpLsp;
        pRsvpLsp = pRsvpLsp->next;
    }
    return pRsvpLsp;
}

void FindClosestRsvpLsp(RSVP_TUNNEL_PROPERTIES *pTunnel,
                        SETUP_COMPLETE *setup_complete,
                        float *BW,
                        uns16 *LspId)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp;
    int i;
    float Delta;
    RSVP_LSP_PROPERTIES *pSelectedRsvpLsp = NULL;
    BOOL GreaterThanRequired;

    zlog_info("entering FindClosestRsvpLsp");
  
    if(pTunnel->RequiredBW < setup_complete->BW)
    {
        Delta = setup_complete->BW - pTunnel->RequiredBW;
        GreaterThanRequired = TRUE;
    }
    else
    {
        Delta = pTunnel->RequiredBW - setup_complete->BW;
        GreaterThanRequired = FALSE;
    }
    for(i = 0;i < setup_complete->NumberOfItems;i++)
    {
        pRsvpLsp = FindRsvpLspByLspId(pTunnel,setup_complete->pLspLabel[i].LspId);
        if(pRsvpLsp == NULL)
        {
            continue;
        }
        pRsvpLsp->Label = setup_complete->pLspLabel[i].Label;
        if(GreaterThanRequired == TRUE)
        {
            if((pRsvpLsp->RequestedBW > pTunnel->RequiredBW)||
                ((pRsvpLsp->RequestedBW == pTunnel->RequiredBW)&&(pSelectedRsvpLsp == NULL)))
            {
                if((pRsvpLsp->RequestedBW - pTunnel->RequiredBW) <= Delta)
                {
                    Delta = pRsvpLsp->RequestedBW - pTunnel->RequiredBW;
                    pSelectedRsvpLsp = pRsvpLsp;
                }
            }
            else if(pRsvpLsp->RequestedBW == pTunnel->RequiredBW)
            {
                if(pSelectedRsvpLsp->LspId != 0xFFFF)
                {
                    if(pSelectedRsvpLsp->LspId < pRsvpLsp->LspId)
                    {
                        Delta = 0;
                        pSelectedRsvpLsp = pRsvpLsp;
                    }
                }
                else
                {
                    if(pSelectedRsvpLsp->LspId > pRsvpLsp->LspId)
                    {
                        Delta = 0;
                        pSelectedRsvpLsp = pRsvpLsp;
                    }
                }
            }
        }
        else
        {
            if((pTunnel->RequiredBW > pRsvpLsp->RequestedBW)||
                ((pTunnel->RequiredBW == pRsvpLsp->RequestedBW)&&(pSelectedRsvpLsp == NULL)))
            {
                if((pTunnel->RequiredBW - pRsvpLsp->RequestedBW) <= Delta)
                {
                    Delta = pTunnel->RequiredBW - pRsvpLsp->RequestedBW;
                    pSelectedRsvpLsp = pRsvpLsp;
                }
            }
            else if(pRsvpLsp->RequestedBW == pTunnel->RequiredBW)
            {
                if(pSelectedRsvpLsp->LspId != 0xFFFF)
                {
                    if(pSelectedRsvpLsp->LspId < pRsvpLsp->LspId)
                    {
                        Delta = 0;
                        pSelectedRsvpLsp = pRsvpLsp;
                    }
                }
                else
                {
                    if(pSelectedRsvpLsp->LspId > pRsvpLsp->LspId)
                    {
                        Delta = 0;
                        pSelectedRsvpLsp = pRsvpLsp;
                    }
                }
            }
        }
    }
    if(pSelectedRsvpLsp != NULL)
    {
        *BW    = pSelectedRsvpLsp->RequestedBW;
        *LspId = pSelectedRsvpLsp->LspId;
    }
    else
    {
        *BW = *LspId = 0;
    }
    zlog_info("leaving FindClosestRsvpLsp");
}

SM_CALL_T *DetermineWorkingLspAndTearUnneeded(RSVP_TUNNEL_PROPERTIES *pTunnel,
                                              float BW,
                                              uns16 LspId,
                                              IPV4_ADDR dest,
                                              IPV4_ADDR source,
                                              SM_T *pSm)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties,*pRsvpLspNext,*pRsvpLspPrev = NULL,*pWorkingRsvpLsp = NULL;
    TE_API_MSG TeApi;
    LSP_PATH_SHARED_PARAMS *pParams = NULL;
    PSB_KEY PsbKey;
    SM_CALL_T *pCall = NULL;

    zlog_info("entering DetermineWorkingLspAndTearUnneeded");

    if(BW == pTunnel->RequiredBW) /* modification complete */
    {
        memset(&PsbKey,0,sizeof(PSB_KEY));
        PsbKey.Session.Dest = dest;
        PsbKey.Session.TunnelId = pTunnel->TunnelId;
        PsbKey.Session.ExtTunelId = source;

        while(pRsvpLsp != NULL)
        {
            if(pRsvpLsp->LspId == LspId)
            {
                pWorkingRsvpLsp = pRsvpLsp;
            }
            if((pRsvpLsp->LspId != LspId)&&
                (!((pRsvpLsp->LspId > LspId)&&(pRsvpLsp->RequestedBW == pTunnel->RequiredBW))))
            {
                TeApi.NotificationType = PATH_TEAR_CMD;
                TeApi.u.IngressApi.Egress = dest;
                TeApi.u.IngressApi.TunnelId = pTunnel->TunnelId;
                TeApi.u.IngressApi.src_ip = source;
                TeApi.u.IngressApi.LspId = pRsvpLsp->LspId;

                zlog_info("\nsending tear down request1 for LSP %x tnl %x dest %x src %x bw %x",
                    pRsvpLsp->LspId,
                    pTunnel->TunnelId,
                    dest,
                    source,
                    pRsvpLsp->RequestedBW);

                te_send_msg(&TeApi,sizeof(TeApi));
#if DATA_PLANE
                {
                   char key[23];
                   USER_LSP *pUserLsp;
                   IPV4_ADDR next_hop = 0;
                   if((pRsvpLsp->tunneled == FALSE)&&(pRsvpLsp->forw_info.path.HopCount != 0))
                   {
                      next_hop = pRsvpLsp->forw_info.path.pErHopsList[0];
                   }
                   sprintf(key,"%x%d%x%d",dest,pTunnel->TunnelId,source,pRsvpLsp->LspId);
                   zlog_info("delete label %x next hop %x key %s\n",pRsvpLsp->Label,next_hop,key);
                   mplsTeOutLabel(&pRsvpLsp->Label,1,key,next_hop,0);
                   if((pUserLsp = UserLspGet(pTunnel->UserLspName)) != NULL)
                   {
                       if(pUserLsp->params.PolicyName[0] != '\0')
                       {
                           mplsTePolicy(pUserLsp->params.PolicyName,key,0);
                       }
                   }
                }
#endif
                PsbKey.SenderTemplate.LspId = pRsvpLsp->LspId;
#ifdef FRR_SM_DEFINED
                FrrIngressRelease(&PsbKey);
#endif

                pRsvpLspNext = pRsvpLsp->next;
                
                if(pTunnel->properties == pRsvpLsp)
                {
                    pTunnel->properties = pTunnel->properties->next;
                }
                else
                {
                    pRsvpLspPrev->next = pRsvpLsp->next;
                }
                                
                if((pRsvpLsp->tunneled == FALSE)&&
                    (pRsvpLsp->forw_info.path.pErHopsList != NULL))
                {
                    XFREE(MTYPE_TE,pRsvpLsp->forw_info.path.pErHopsList);
                }
                XFREE(MTYPE_TE,pRsvpLsp);
                
                pRsvpLsp = pRsvpLspNext;
            }
            else
            {
                pRsvpLspPrev = pRsvpLsp;
                pRsvpLsp = pRsvpLsp->next;
            }
        }
        if(pTunnel->LspId != LspId)
        {
            pTunnel->LspId = LspId;
            pTunnel->AllocatedBW = BW;
            memset(&PsbKey,0,sizeof(PSB_KEY));
            PsbKey.Session.Dest = dest;
            PsbKey.Session.TunnelId = pTunnel->TunnelId;
            PsbKey.Session.ExtTunelId = source;
            
            if(pWorkingRsvpLsp != NULL)
            {
                IngressLabelMappingReceived(pWorkingRsvpLsp->Label,pWorkingRsvpLsp->oIfIndex,&PsbKey);
            }
            else
            {
                zlog_err("\nBUG: pWorkingRsvpLsp is NULL %s %d",__FILE__,__LINE__);
            }
        }
    }
    else if(BW > pTunnel->RequiredBW)
    {
        if(pTunnel->AllocatedBW < pTunnel->RequiredBW) /* Allocated < RequiredBW < BW */
        {
            memset(&PsbKey,0,sizeof(PSB_KEY));
            PsbKey.Session.Dest = dest;
            PsbKey.Session.TunnelId = pTunnel->TunnelId;
            PsbKey.Session.ExtTunelId = source;

            while(pRsvpLsp != NULL)
            {
                if(pRsvpLsp->LspId == LspId)
                {
                    pWorkingRsvpLsp = pRsvpLsp;
                }
                /* tear down all that in the range Allocated < x < Required and > BW */
                /* In another words, only Required < x < BW remains */
                if((pRsvpLsp->LspId != LspId)&&
                    ((pRsvpLsp->RequestedBW < pTunnel->RequiredBW)||(pRsvpLsp->RequestedBW > BW)))
                {
                    TeApi.NotificationType = PATH_TEAR_CMD;
                    TeApi.u.IngressApi.Egress = dest;
                    TeApi.u.IngressApi.TunnelId = pTunnel->TunnelId;
                    TeApi.u.IngressApi.src_ip = source;
                    TeApi.u.IngressApi.LspId = pRsvpLsp->LspId;

                    zlog_info("\nsending tear down request2 for LSP %x tnl %x dest %x src %x bw %x",
                        pRsvpLsp->LspId,
                        pTunnel->TunnelId,
                        dest,
                        source,
                        pRsvpLsp->RequestedBW);

                    te_send_msg(&TeApi,sizeof(TeApi));
#if DATA_PLANE
                    {
                       char key[23];
                       USER_LSP *pUserLsp;
                       IPV4_ADDR next_hop = 0;
                       if((pRsvpLsp->tunneled == FALSE)&&(pRsvpLsp->forw_info.path.HopCount != 0))
                       {
                          next_hop = pRsvpLsp->forw_info.path.pErHopsList[0];
                       }
                       sprintf(key,"%x%d%x%d",dest,pTunnel->TunnelId,source,pRsvpLsp->LspId);
                       zlog_info("delete label %x next hop %x key %s\n",pRsvpLsp->Label,next_hop,key);
                       mplsTeOutLabel(&pRsvpLsp->Label,1,key,next_hop,0);
                       if((pUserLsp = UserLspGet(pTunnel->UserLspName)) != NULL)
                       {
                           if(pUserLsp->params.PolicyName[0] != '\0')
                           {
                              mplsTePolicy(pUserLsp->params.PolicyName,key,0);
                           }
                       }
                    }
#endif

                    PsbKey.SenderTemplate.LspId = pRsvpLsp->LspId;
#ifdef FRR_SM_DEFINED
                    FrrIngressRelease(&PsbKey);
#endif
                    pRsvpLspNext = pRsvpLsp->next;
                    if(pTunnel->properties == pRsvpLsp)
                        pTunnel->properties = pTunnel->properties->next;
                    else                                                                  
                        pRsvpLspPrev->next = pRsvpLsp->next;

                    if((pRsvpLsp->tunneled == FALSE)&&
                        (pRsvpLsp->forw_info.path.pErHopsList != NULL))
                    {
                        XFREE(MTYPE_TE,pRsvpLsp->forw_info.path.pErHopsList);
                    }
                    XFREE(MTYPE_TE,pRsvpLsp);
                                   
                    pRsvpLsp = pRsvpLspNext;
                }
                else
                {
                    pRsvpLspPrev = pRsvpLsp;
                    pRsvpLsp = pRsvpLsp->next;
                }
            }
            if(pTunnel->LspId != LspId)
            {
                pTunnel->LspId = LspId;
                pTunnel->AllocatedBW = BW;
                memset(&PsbKey,0,sizeof(PSB_KEY));
                PsbKey.Session.Dest = dest;
                PsbKey.Session.TunnelId = pTunnel->TunnelId;
                PsbKey.Session.ExtTunelId = source;
                if(pWorkingRsvpLsp != NULL)
                {
                    IngressLabelMappingReceived(pWorkingRsvpLsp->Label,pWorkingRsvpLsp->oIfIndex,&PsbKey);
                }
                else
                {
                    zlog_err("\nBUG: pWorkingRsvpLsp is NULL %s %d",__FILE__,__LINE__);
                }
            }
        }
        else /* Required <= Allocated < BW */
        {
            RemoveRsvpLsp(pTunnel,LspId,dest,source);
        }
    }
    else
    {
        if(BW > pTunnel->AllocatedBW) /* AllocatedBW < BW < RequiredBW */
        {
            memset(&PsbKey,0,sizeof(PSB_KEY));
            PsbKey.Session.Dest = dest;
            PsbKey.Session.TunnelId = pTunnel->TunnelId;
            PsbKey.Session.ExtTunelId = source;

            while(pRsvpLsp != NULL)
            {
                if(pRsvpLsp->LspId == LspId)
                {
                    pWorkingRsvpLsp = pRsvpLsp;
                }
                /* tear down all that < BW */
                if((pRsvpLsp->LspId != LspId)&&
                    (pRsvpLsp->RequestedBW < BW))
                {
                    TeApi.NotificationType = PATH_TEAR_CMD;
                    TeApi.u.IngressApi.Egress = dest;
                    TeApi.u.IngressApi.TunnelId = pTunnel->TunnelId;
                    TeApi.u.IngressApi.src_ip = source;
                    TeApi.u.IngressApi.LspId = pRsvpLsp->LspId;

                    zlog_info("\nsending tear down request3 for LSP %x tnl %x dest %x src %x bw %x",
                        pRsvpLsp->LspId,
                        pTunnel->TunnelId,
                        dest,
                        source,
                        pRsvpLsp->RequestedBW);

                    te_send_msg(&TeApi,sizeof(TeApi));
#if DATA_PLANE
                    {
                        char key[23];
                        USER_LSP *pUserLsp;
                        IPV4_ADDR next_hop = 0;
                        if((pRsvpLsp->tunneled == FALSE)&&(pRsvpLsp->forw_info.path.HopCount != 0))
                        {
                            next_hop = pRsvpLsp->forw_info.path.pErHopsList[0];
                        }
                        sprintf(key,"%x%d%x%d",dest,pTunnel->TunnelId,source,pRsvpLsp->LspId);
                        zlog_info("delete label %x next hop %x key %s\n",pRsvpLsp->Label,next_hop,key);
                        mplsTeOutLabel(&pRsvpLsp->Label,1,key,next_hop,0);
                        if((pUserLsp = UserLspGet(pTunnel->UserLspName)) != NULL)
                        {
                            if(pUserLsp->params.PolicyName[0] != '\0')
                            {
                                mplsTePolicy(pUserLsp->params.PolicyName,key,0);
                            }
                        }
                    }
#endif
                    PsbKey.SenderTemplate.LspId = pRsvpLsp->LspId;
#ifdef FRR_SM_DEFINED
                    FrrIngressRelease(&PsbKey);
#endif
                    pRsvpLspNext = pRsvpLsp->next;
                    if(pTunnel->properties == pRsvpLsp)
                        pTunnel->properties = pTunnel->properties->next;
                    else
                        pRsvpLspPrev->next = pRsvpLsp->next;
                                  
                    if((pRsvpLsp->tunneled == FALSE)&&
                        (pRsvpLsp->forw_info.path.pErHopsList != NULL))
                    {
                        XFREE(MTYPE_TE,pRsvpLsp->forw_info.path.pErHopsList);
                    }
                    XFREE(MTYPE_TE,pRsvpLsp);
                                  
                    pRsvpLsp = pRsvpLspNext;
                }
                else
                {
                    pRsvpLspPrev = pRsvpLsp;
                    pRsvpLsp = pRsvpLsp->next;
                }
            }
            if(pTunnel->LspId != LspId)
            {
                pTunnel->LspId = LspId;
                pTunnel->AllocatedBW = BW;
                memset(&PsbKey,0,sizeof(PSB_KEY));
                PsbKey.Session.Dest = dest;
                PsbKey.Session.TunnelId = pTunnel->TunnelId;
                PsbKey.Session.ExtTunelId = source;
                if(pWorkingRsvpLsp != NULL)
                {
                    IngressLabelMappingReceived(pWorkingRsvpLsp->Label,pWorkingRsvpLsp->oIfIndex,&PsbKey);
                }
                else
                {
                    zlog_err("\nBUG: pWorkingRsvpLsp is NULL %s %d",__FILE__,__LINE__);
                }
            }
        }
        else /* BW <= Allocated < Required */
        {
            RemoveRsvpLsp(pTunnel,LspId,dest,source);
        }
    }
    if(pTunnel->properties != NULL)
    {
        if(pTunnel->properties->next == NULL)
        {
            if(pTunnel->properties->LspId == pTunnel->LspId)
            {
                USER_LSP *pUserLsp;
                pTunnel->ReRoute = FALSE;
                if((pUserLsp = UserLspGet(pTunnel->UserLspName)) != NULL)
                {      
                    RSVP_TUNNEL_PROPERTIES *pTunnel1 = pUserLsp->pUserLspTunnels;
                    StopLspSetupTimer(pTunnel);
                    if((pUserLsp->pUserLspTunnels)&&(pUserLsp->pUserLspTunnels->TunnelId == pTunnel->TunnelId))
                    {
                        StopLspSetupRetryTimer(pTunnel);
                    }

                    if(pTunnel->AdjustmentRequired == TRUE)
                    {
                        zlog_info("Adjustment required for tunnel %x",pTunnel->TunnelId);
                        pTunnel->AdjustmentRequired = FALSE;
                        while(pTunnel1 != NULL)
                        {
                            if(pTunnel1->TunnelId == pTunnel->TunnelId)
                                break;
                            pTunnel1 = pTunnel1->next_user_lsp_tunnel;
                        }
                    }
                    else if(pTunnel1)
                    {
                        pTunnel1 = pTunnel1->next_user_lsp_tunnel;
                    }
                    if(pTunnel1 != NULL)
                    {
                        STATIC_PATH  *pStaticPath;
                           
                        if(rdb_get_static_path(pTunnel->StaticPathName,
                                                    &pStaticPath) != E_OK)
                        {
                            pStaticPath = NULL;
                        }
                        pCall = ModifySecondary(pTunnel1,
                                                pSm,
                                                pStaticPath,
                                                pUserLsp);
                    }
                    pParams = PathParamsGet(pUserLsp,
                                            pTunnel->StaticPathName,
                                            ((!strcmp(pUserLsp->params.Primary,pTunnel->StaticPathName))&&(pUserLsp->pUserLspTunnels->TunnelId == pTunnel->TunnelId)));
                    StartAdaptivityTimer(pParams->optimize_timer,pTunnel);
                }
            }
            else
            {
                zlog_err("\none RSVP LSP remains and it is not a working LSP!!! %s %d",__FILE__,__LINE__);
            }
        }
    }
    else
    {
        zlog_err("\npTunnel->properties is NULL %s %d",__FILE__,__LINE__);
    }
    zlog_info("leaving DetermineWorkingLspAndTearUnneeded");
    return pCall;
}

RSVP_LSP_PROPERTIES *GetRsvpLspMaxBW(RSVP_TUNNEL_PROPERTIES *pTunnel,uns16 LspId,float MaxBw)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp = pTunnel->properties,*pSelectedRsvpLsp = NULL;
    float MaxRsvpLspBW = 0;
    while(pRsvpLsp != NULL)
    {
        if((pRsvpLsp->RequestedBW <= MaxBw)&&
            (pRsvpLsp->LspId != LspId)&&
            (pRsvpLsp->RequestedBW > MaxRsvpLspBW))
            pSelectedRsvpLsp = pRsvpLsp;
        pRsvpLsp = pRsvpLsp->next;
    }
    return pSelectedRsvpLsp;
}

BOOL IsPathEqual(PATH *pPath,IPV4_ADDR *IpAddrList)
{
    ER_HOP_L_LIST *pErHopLList = pPath->u.er_hops_l_list;
    int i = 0;
    
    while(pErHopLList != NULL)
    {
        if(pErHopLList->er_hop->local_ip != IpAddrList[i])
            return FALSE;
        pErHopLList = pErHopLList->next;
        i++;
    }
    return TRUE;
}

PATH *FindRsvpLspPath(PATH_L_LIST *pPaths,RSVP_LSP_PROPERTIES *pRsvpLsp)
{
    while(pPaths != NULL)
    {
        PATH *pPath = pPaths->pPath;

        if((pPath->PathProperties.PathHopCount + 1) == pRsvpLsp->forw_info.path.HopCount)
        {
            if(IsPathEqual(pPath,pRsvpLsp->forw_info.path.pErHopsList) == TRUE)
                return pPath;
        }
        pPaths = pPaths->next;
    }
    return NULL;
}

RSVP_LSP_PROPERTIES *CurrentPathHasAvBw(RSVP_TUNNEL_PROPERTIES *pTunnel,float BW)
{
    RSVP_LSP_PROPERTIES *pRsvpLsp;
    PATH *pPath;
    float Delta;

    zlog_info("entering CurrentPathHasAvBw");

    if((pRsvpLsp = GetWorkingRsvpLsp(pTunnel)) != NULL)
    {
        if((pPath = GetLspPath(pRsvpLsp)) != NULL)
        {
            if(pPath->PathProperties.PathMaxLspBW >= BW)
            {
                if(pRsvpLsp->RequestedBW < BW)
                    Delta = BW - pRsvpLsp->RequestedBW;
                else
                    Delta = pRsvpLsp->RequestedBW - BW;
                                
                if(pPath->PathProperties.PathReservableBW[pRsvpLsp->SetupPriority] >= Delta)
                    return pRsvpLsp;
            }
        }
        else
            zlog_info("cannot get working lsp's path %s %d",__FILE__,__LINE__);
    }
    else
        zlog_info("cannot get working lsp %s %d",__FILE__,__LINE__);
    zlog_info("leaving CurrentPathHasAvBw");
    return NULL;
}

uns32 AddSecondaryTunnel(USER_LSP *pUserLsp,
                         RSVP_TUNNEL_PROPERTIES *pSecondaryTunnel)
{
    RSVP_TUNNEL_PROPERTIES *pTunnel,*pTunnelPrev = NULL;

    zlog_info("entering AddSecondaryTunnel");

    if((pTunnel = pUserLsp->pUserLspTunnels) == NULL)
    {
        zlog_err("\nFATAL at %s %d - TunnelIdList is empty",__FILE__,__LINE__);
        return E_ERR;
    }
    zlog_info("Primary: %x %s",pTunnel->TunnelId,pTunnel->StaticPathName);
    if(pTunnel->next_user_lsp_tunnel == NULL)
    {
        zlog_info("First secondary tunnel %s %d",__FILE__,__LINE__);
        pTunnel->next_user_lsp_tunnel = pSecondaryTunnel;
        return E_OK;
    }
    pTunnel = pTunnel->next_user_lsp_tunnel;
    while(pTunnel != NULL)
    {
        if(pTunnel->TunnelId == pSecondaryTunnel->TunnelId)
        {
            zlog_info("exists on the lists...");
            zlog_info("leaving AddSecondaryTunnel"); 
            return E_OK;
        }
        pTunnelPrev = pTunnel;
        pTunnel = pTunnel->next_user_lsp_tunnel;
    }
    pTunnelPrev->next_user_lsp_tunnel = pSecondaryTunnel;
    zlog_info("leaving AddSecondaryTunnel");      
    return E_OK;
}

void CleanSecodaryPaths(USER_LSP *pUserLsp)
{
    SECONDARY_PATH_LIST *pSecPathList = pUserLsp->params.SecondaryPaths,*pSecPathListNext;
    while(pSecPathList != NULL)
    {
        if(pSecPathList->SecondaryPathParams != NULL)
            XFREE(MTYPE_TE,pSecPathList->SecondaryPathParams);
        pSecPathListNext = pSecPathList->next;
        XFREE(MTYPE_TE,pSecPathList);
        pSecPathList = pSecPathListNext;
    }
}

void CleanUserLsp(USER_LSP *pUserLsp)
{
#if 0
    if(pUserLsp->params.FastReroute != NULL)
        XFREE(MTYPE_TE,pUserLsp->params.FastReroute);
#endif              
    if(pUserLsp->params.PrimaryPathParams != NULL)
        XFREE(MTYPE_TE,pUserLsp->params.PrimaryPathParams);
}

void CopyUserLsp(USER_LSP *pDestLsp,USER_LSP *pSrcLsp)
{
    SECONDARY_PATH_LIST *pDestSecondaryPathList,*pSrcSecondaryPathList,*pPrevSecPath;

    zlog_info("entering CopyUserLsp");

    strcpy(pDestLsp->params.LspName,pSrcLsp->params.LspName);

    if((pDestLsp->params.PrimaryPathParams)&&
       (((pSrcLsp->params.PrimaryPathParams)&&(pSrcLsp->params.PrimaryPathParams->disable))||
        (!pSrcLsp->params.PrimaryPathParams)))
    {
       zlog_info("removing primary %s %s %d",pDestLsp->params.Primary,__FILE__,__LINE__);
       XFREE(MTYPE_TE,pDestLsp->params.PrimaryPathParams);
       pDestLsp->params.PrimaryPathParams = NULL;
       pDestLsp->params.Primary[0] = '\0';
       if(pSrcLsp->params.PrimaryPathParams)
       {
          XFREE(MTYPE_TE,pSrcLsp->params.PrimaryPathParams);
          pSrcLsp->params.PrimaryPathParams = NULL;
       }
       pSrcLsp->params.Primary[0] = '\0';
    }
    strcpy(pDestLsp->params.Primary,pSrcLsp->params.Primary);
#if 0
    pDestLsp->params.FastReroute = pSrcLsp->params.FastReroute;
    pSrcLsp->params.FastReroute = NULL;
#endif
    if(pDestLsp->params.PrimaryPathParams != NULL)
    {
        XFREE(MTYPE_TE,pDestLsp->params.PrimaryPathParams);
    }
    pDestLsp->params.PrimaryPathParams = pSrcLsp->params.PrimaryPathParams;
    pSrcLsp->params.PrimaryPathParams = NULL;
    pDestSecondaryPathList = pDestLsp->params.SecondaryPaths;
    while(pDestSecondaryPathList != NULL)
    {
        pSrcSecondaryPathList = pSrcLsp->params.SecondaryPaths;
        pPrevSecPath = NULL;
        while(pSrcSecondaryPathList != NULL)
        {
            if(strcmp(pDestSecondaryPathList->Secondary,pSrcSecondaryPathList->Secondary) == 0)
            {
                if(pDestSecondaryPathList->SecondaryPathParams != NULL)
                {
                   XFREE(MTYPE_TE,pDestSecondaryPathList->SecondaryPathParams);
                }
                pDestSecondaryPathList->SecondaryPathParams = pSrcSecondaryPathList->SecondaryPathParams;
                pSrcSecondaryPathList->SecondaryPathParams = NULL;
                if(pPrevSecPath != NULL)
                {
                    pPrevSecPath->next = pSrcSecondaryPathList->next;
                }
                else
                {
                    pSrcLsp->params.SecondaryPaths = pSrcLsp->params.SecondaryPaths->next;
                }
                XFREE(MTYPE_TE,pSrcSecondaryPathList);
                break;
            }
            pPrevSecPath = pSrcSecondaryPathList;
            pSrcSecondaryPathList = pSrcSecondaryPathList->next;
        }
        if(pDestSecondaryPathList->next == NULL)
        {
            pDestSecondaryPathList->next = pSrcLsp->params.SecondaryPaths;
            break;
        }
        pDestSecondaryPathList = pDestSecondaryPathList->next;
    }
    if(pDestLsp->params.SecondaryPaths == NULL)
    {
        pDestLsp->params.SecondaryPaths = pSrcLsp->params.SecondaryPaths;
    }
    if(pDestLsp->params.FastReRoute != pSrcLsp->params.FastReRoute)
    {
       pDestLsp->params.FastReRoute = pSrcLsp->params.FastReRoute;
    }
    if(pDestLsp->params.bw_policy != pSrcLsp->params.bw_policy)
    {
       pDestLsp->params.bw_policy = pSrcLsp->params.bw_policy;
    }
    if(pDestLsp->params.metric != pSrcLsp->params.metric)
    {
       pDestLsp->params.metric = pSrcLsp->params.metric;
    }
    if(pDestLsp->params.no_decrement_ttl != pSrcLsp->params.no_decrement_ttl)
    {
       pDestLsp->params.no_decrement_ttl = pSrcLsp->params.no_decrement_ttl;
    }
    if(pDestLsp->params.retry_timer != pSrcLsp->params.retry_timer)
    {
       pDestLsp->params.retry_timer = pSrcLsp->params.retry_timer;
    }
    if(pDestLsp->params.retry_limit != pSrcLsp->params.retry_limit)
    {
       pDestLsp->params.retry_limit = pSrcLsp->params.retry_limit;
    }
    pDestLsp->params.retry_count = pSrcLsp->params.retry_limit;
    if(memcmp(&pDestLsp->params.lsp_params,&pSrcLsp->params.lsp_params,sizeof(LSP_PATH_SHARED_PARAMS)) != 0)
    {
       pDestLsp->params.lsp_params = pSrcLsp->params.lsp_params;
    }
    zlog_info("leaving CopyUserLsp");
}

LSP_PATH_SHARED_PARAMS *PathParamsGet(USER_LSP *pUserLsp,char *PathName,uns8 IsPrimary)
{
    zlog_info("entering PathParamsGet");

    if((IsPrimary)&&(strcmp(pUserLsp->params.Primary,PathName) == 0))
    {
        if(pUserLsp->params.PrimaryPathParams != NULL)
        {
            return pUserLsp->params.PrimaryPathParams;
        }
        else
        {
            return &pUserLsp->params.lsp_params;
        }
    }
    else if(!IsPrimary)
    {
        SECONDARY_PATH_LIST *pSecondaryPathList = pUserLsp->params.SecondaryPaths;
        while(pSecondaryPathList != NULL)
        {
            if(strcmp(pSecondaryPathList->Secondary,PathName) == 0)
            {
                if(pSecondaryPathList->SecondaryPathParams != NULL)
                {
                    return pSecondaryPathList->SecondaryPathParams;
                }
                else
                {
                    return &pUserLsp->params.lsp_params;
                }
            }
            pSecondaryPathList = pSecondaryPathList->next;
        }
    }
    zlog_info("leaving PathParamsGet");
    return &pUserLsp->params.lsp_params;
}

RSVP_TUNNEL_PROPERTIES *StaticPathIsUsed(USER_LSP *pUserLsp,char *PathName)
{
    RSVP_TUNNEL_PROPERTIES *pTunnel = pUserLsp->pUserLspTunnels;

    zlog_info("entering StaticPathIsUsed");

    if(pTunnel != NULL)
    {
        pTunnel = pTunnel->next_user_lsp_tunnel;
    }
    while(pTunnel != NULL)
    {
        if(strcmp(pTunnel->StaticPathName,PathName) == 0)
            return pTunnel;
        pTunnel = pTunnel->next_user_lsp_tunnel;
    }
    zlog_info("leaving StaticPathIsUsed");
    return NULL;
}

SM_CALL_T *UserPrimaryLspRecovery(RSVP_TUNNEL_PROPERTIES *pTunnel,
                                  SM_T *pSm,
                                  RECOVERY_TYPE_E recovery_type,
                                  IPV4_ADDR exclude_node)
{
    STATIC_PATH *pStaticPath;
    USER_LSP *pUserLsp;
    SECONDARY_PATH_LIST *pSecondaryPathList;
    INGRESS_API *pOpenLspParams;
    SM_CALL_T *pCall = NULL;
    RSVP_TUNNEL_PROPERTIES *pSavedTunnel = pTunnel;
    LSP_PATH_SHARED_PARAMS *pParams = NULL;
    uns8 Flags = 0;
    ER_HOP *pErHopsList = NULL;

    zlog_info("entering UserPrimaryLspRecovery");

    if((pUserLsp = UserLspGet(pTunnel->UserLspName)) == NULL)
    {
        zlog_err("\nerror: cannot get user lsp %s %d",__FILE__,__LINE__);
        return NULL;
    }
    pTunnel = pTunnel->next_user_lsp_tunnel;
    /* First - try to find secondary LSP (hot-standby), which is UP */
    if(recovery_type == WORKING_LSP_FAILED)
    {
        while(pTunnel != NULL)
        {
            RSVP_LSP_PROPERTIES *pRsvpLsp;
            if((pRsvpLsp = GetWorkingRsvpLsp(pTunnel)) != NULL)
            {
#if DATA_PLANE
                {
                   char key[23];
                   sprintf(key,"%x%d%x%d",pUserLsp->params.to,pTunnel->TunnelId,pUserLsp->params.from,pRsvpLsp->LspId);
                   if(pUserLsp->params.PolicyName[0] != '\0')
                   {
                       mplsTePolicy(pUserLsp->params.PolicyName,key,1);
                       pUserLsp->BackupTunnelId = pTunnel->TunnelId;
                   }
                }
#endif
                zlog_info("Protection switch to secondary hot-stanby tunnel Dest %x Tunnel %x  Source %x %s %s %x",
                        pUserLsp->params.to,
                        pTunnel->TunnelId,
                        pUserLsp->params.from,
                        pTunnel->StaticPathName,
                        __FILE__,__LINE__);
                    strcpy(pUserLsp->CurrentSecondaryPathName,pTunnel->StaticPathName);
                    if(StartLspSetupRetryTimer(pUserLsp->params.retry_timer,
                                               &pUserLsp->params.retry_count,
                                               pSavedTunnel) != E_OK)
                    {
                        zlog_err("cannot start lsp setup retry timer %s %d",__FILE__,__LINE__);
                    }
                    return NULL;
            }
            pTunnel = pTunnel->next_user_lsp_tunnel;
        }
    }
    
    /* if reached here, there is no hot-stanby tunnels UP. */
    pSecondaryPathList = pUserLsp->params.SecondaryPaths;
    /* if there is secondary path, which was used, spin up the secondary paths to get next secondary path */
    if(pUserLsp->CurrentSecondaryPathName[0] != 0)
    {
        while(pSecondaryPathList != NULL)
        {
            if(strcmp(pSecondaryPathList->Secondary,pUserLsp->CurrentSecondaryPathName) == 0)
            {
                pSecondaryPathList = pSecondaryPathList->next;
                break;
            }
            pSecondaryPathList = pSecondaryPathList->next;
        }
        if(pSecondaryPathList == NULL)
        {
            pSecondaryPathList = pUserLsp->params.SecondaryPaths;
        }
    }
    
    while(pSecondaryPathList != NULL)
    {
        if(strcmp(pSecondaryPathList->Secondary,pUserLsp->CurrentSecondaryPathName) == 0)
        {
            pSecondaryPathList = NULL;
            break;
        }
        if(StaticPathIsUsed(pUserLsp,pSecondaryPathList->Secondary) == NULL)
        {
            if(rdb_get_static_path(pSecondaryPathList->Secondary,
                                        &pStaticPath) == E_OK)
            {
                break;
            }
        }
        pSecondaryPathList = pSecondaryPathList->next;
    }
    
    if(pUserLsp->pUserLspTunnels == NULL)
    {
        zlog_err("\nSW ERROR %s %d",__FILE__,__LINE__);
        return NULL;
    }
    
    if(pSecondaryPathList != NULL)
    {
        pParams = PathParamsGet(pUserLsp,pSecondaryPathList->Secondary,0);
        Flags |= (pParams->record == TRUE) ? LABEL_RECORDING_DESIRED : 0;
        /* for now the FRR is only boolean. However, in future it may be more complicated */
        Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
        if(SetErHopList(pStaticPath,&pErHopsList) != E_OK)
        {
            zlog_err("Cannot set ER hops list %s %d",__FILE__,__LINE__);
            return NULL;
        }
        /* reroute primary LSP to the secondary path */
        if((pOpenLspParams = CreateRequest2Signalling(pUserLsp->params.to,
                                                      pUserLsp->pUserLspTunnels->TunnelId,
                                                      pStaticPath->HopCount,
                                                      pErHopsList,
                                                      pParams->BW,
                                                      pParams->setup_priority,
                                                      pParams->hold_priority,
                                                      Flags,
                                                      (~(pParams->affinity_properties & pParams->affinity_mask)) & pParams->affinity_mask,
                                                      0,
                                                      pParams->affinity_properties & pParams->affinity_mask)) == NULL)
        {
            zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
            XFREE(MTYPE_TE,pErHopsList);
            return NULL;
        }
        
        zlog_info("\nRerouting primary: Dest %x Tunnel %x Source %x New Path %s",
            pOpenLspParams->Egress,
            pOpenLspParams->TunnelId,
            pOpenLspParams->src_ip,
            pSecondaryPathList->Secondary);
        
        strcpy(pUserLsp->CurrentSecondaryPathName,pSecondaryPathList->Secondary);
        if(StartLspSetupRetryTimer(pUserLsp->params.retry_timer,&pUserLsp->params.retry_count,pSavedTunnel) != E_OK)
        {
            zlog_err("\ncannot start lsp setup retry timer %s %d",__FILE__,__LINE__);
        }
        pParams = PathParamsGet(pUserLsp,pStaticPath->PathName,0);
        if(pUserLsp->params.to != exclude_node)
          pOpenLspParams->ErHops2Exclude[0] = exclude_node;
        pCall = LspRequest(pOpenLspParams,0,NULL,pSm,&pSavedTunnel,TRUE,pParams);
        strcpy(pSavedTunnel->StaticPathName,pSecondaryPathList->Secondary);
        return pCall;
       
    }

    if(rdb_get_static_path(pSavedTunnel->StaticPathName,
                                &pStaticPath) != E_OK)
    {
        pStaticPath = NULL;
    }
    
    pParams = PathParamsGet(pUserLsp,
                            pSavedTunnel->StaticPathName,
                            ((!strcmp(pUserLsp->params.Primary,pSavedTunnel->StaticPathName))&&(pUserLsp->pUserLspTunnels->TunnelId == pSavedTunnel->TunnelId)));

    if(StartLspSetupRetryTimer(pUserLsp->params.retry_timer,&pUserLsp->params.retry_count,pSavedTunnel) != E_OK)
    {
        zlog_err("\ncannot start lsp setup retry timer %s %d",__FILE__,__LINE__);
    }

    if((pStaticPath != NULL)&&
        (pStaticPath->HopList != NULL)&&
        (pStaticPath->HopList->Loose == 1))
    {
        /* reroute primary LSP to the secondary path */
        if(SetErHopList(pStaticPath,&pErHopsList) != E_OK)
        {
            zlog_err("Cannot set ER hops list %s %d",__FILE__,__LINE__);
            return NULL;
        }
    }
    else
    {
        pStaticPath = NULL;
    }
    Flags |= (pParams->record == TRUE) ? LABEL_RECORDING_DESIRED : 0;
    /* for now the FRR is only boolean. However, in future it may be more complicated */
    Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
    if((pOpenLspParams = CreateRequest2Signalling(pUserLsp->params.to,
                                                  pUserLsp->pUserLspTunnels->TunnelId,
                                                  (pStaticPath == NULL) ? 0 : pStaticPath->HopCount,
                                                  pErHopsList,
                                                  pParams->BW,
                                                  pParams->setup_priority,
                                                  pParams->hold_priority,
                                                  Flags,
                                                  (~(pParams->affinity_properties & pParams->affinity_mask)) & pParams->affinity_mask,
                                                  0,
                                                  pParams->affinity_properties & pParams->affinity_mask)) == NULL)
    {
        zlog_err("malloc failed %s %d",__FILE__,__LINE__);
        return NULL;
    }
        
    zlog_info("Creation secondary - %x %x %s %d",pOpenLspParams->Egress,pOpenLspParams->src_ip,__FILE__,__LINE__);
    if(pUserLsp->params.to != exclude_node)
          pOpenLspParams->ErHops2Exclude[0] = exclude_node;
    return LspRequest(pOpenLspParams,0,NULL,pSm,&pSavedTunnel,TRUE,pParams);
}

SM_CALL_T *UserSecondaryLspRecovery(RSVP_TUNNEL_PROPERTIES *pTunnel,SM_T *pSm,IPV4_ADDR exclude_node)
{
    LSP_PATH_SHARED_PARAMS *pSecondaryPathParams;
    USER_LSP *pUserLsp;
    STATIC_PATH *pStaticPath;
    INGRESS_API *pOpenLspParams;
    uns32 ErHopNumber = 0;
    IPV4_ADDR *pErHops = NULL;
    uns8 Flags = 0;
    ER_HOP *pErHopsList = NULL;

    zlog_info("entering UserSecondaryLspRecovery");

    if((pUserLsp = UserLspGet(pTunnel->UserLspName)) == NULL)
    {
        zlog_err("\nerror: cannot get user lsp %s %d",__FILE__,__LINE__);
        return NULL;
    }
    if(pUserLsp->pUserLspTunnels == NULL)
    {
        zlog_err("\nTunnel ID list empty %s %d",__FILE__,__LINE__);
        return NULL;
    }
    pSecondaryPathParams = PathParamsGet(pUserLsp,pTunnel->StaticPathName,0);
    
    if(rdb_get_static_path(pTunnel->StaticPathName,
                                &pStaticPath) != E_OK)
    {
        Flags |= (pSecondaryPathParams->record == TRUE) ? LABEL_RECORDING_DESIRED : 0;
        /* for now the FRR is only boolean. However, in future it may be more complicated */
        Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
        
        /* reroute the secondary LSP inside of the path */
        if((pOpenLspParams = CreateRequest2Signalling(pUserLsp->params.to,
                                                      pTunnel->TunnelId,
                                                      0,
                                                      NULL,
                                                      pSecondaryPathParams->BW,
                                                      pSecondaryPathParams->setup_priority,
                                                      pSecondaryPathParams->hold_priority,
                                                      Flags,
                                                      (~(pSecondaryPathParams->affinity_properties & pSecondaryPathParams->affinity_mask)) & pSecondaryPathParams->affinity_mask,
                                                      0,
                                                      pSecondaryPathParams->affinity_properties & pSecondaryPathParams->affinity_mask)) == NULL)
        {
            zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
            return NULL;
        }
               
        if(GetTunnelHops(pUserLsp->pUserLspTunnels,&ErHopNumber,&pErHops) != E_OK)
        {
            zlog_err("\ncannot get ER HOPs to be avoided %s %d",__FILE__,__LINE__);
            ErHopNumber = 0;
            pErHops = NULL;
        }
        if(pUserLsp->params.to != exclude_node)
          pOpenLspParams->ErHops2Exclude[0] = exclude_node;
        return LspRequest(pOpenLspParams,ErHopNumber,pErHops,pSm,&pTunnel,TRUE,pSecondaryPathParams);
    }
    
    Flags |= (pSecondaryPathParams->record == TRUE) ? LABEL_RECORDING_DESIRED : 0;
    /* for now the FRR is only boolean. However, in future it may be more complicated */
    Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
    if(pStaticPath != NULL)
    {
       if(SetErHopList(pStaticPath,&pErHopsList) != E_OK)
       {
           zlog_err("Cannot set ER hops list %s %d",__FILE__,__LINE__);
           return NULL;
       }
    }
    /* reroute the secondary LSP inside of the path */
    if((pOpenLspParams = CreateRequest2Signalling(pUserLsp->params.to,
                                                  pTunnel->TunnelId,
                                                  pStaticPath->HopCount,
                                                  pErHopsList,
                                                  pSecondaryPathParams->BW,
                                                  pSecondaryPathParams->setup_priority,
                                                  pSecondaryPathParams->hold_priority,
                                                  Flags,
                                                  (~(pSecondaryPathParams->affinity_properties & pSecondaryPathParams->affinity_mask)) & pSecondaryPathParams->affinity_mask,
                                                  0,
                                                  pSecondaryPathParams->affinity_properties & pSecondaryPathParams->affinity_mask)) == NULL)
    {
        zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
        return NULL;
    }
    if(!((pErHopsList != NULL)&&(pErHopsList[0].Loose == 0)))
    {
        if(GetTunnelHops(pUserLsp->pUserLspTunnels,&ErHopNumber,&pErHops) != E_OK)
        {
           zlog_err("\ncannot get ER HOPs to be avoided %s %d",__FILE__,__LINE__);
           ErHopNumber = 0;
           pErHops = NULL;
        }
    }
    if(pUserLsp->params.to != exclude_node)
        pOpenLspParams->ErHops2Exclude[0] = exclude_node;
    return LspRequest(pOpenLspParams,ErHopNumber,pErHops,pSm,&pTunnel,TRUE,pSecondaryPathParams);
}

SM_CALL_T *UserLspFailed(RSVP_TUNNEL_PROPERTIES *pTunnel,SM_T *pSm,IPV4_ADDR exclude_node)
{
    USER_LSP *pUserLsp;
    RECOVERY_TYPE_E recovery_type = WORKING_LSP_FAILED;
   
    zlog_info("entering UserLspFailed");
    zlog_info("Exclude Node %x",exclude_node);
    if((pUserLsp = UserLspGet(pTunnel->UserLspName)) == NULL)
    {
        zlog_err("\nerror: cannot get user lsp %s %d",__FILE__,__LINE__);
        return NULL;
    }
    if(pUserLsp->pUserLspTunnels == NULL)
    {
        zlog_err("\nerror: tunnel id list empty %s %d",__FILE__,__LINE__);
        return NULL;
    }
        
    if(pUserLsp->pUserLspTunnels->TunnelId == pTunnel->TunnelId)
    {
        if(GetWorkingRsvpLsp(pTunnel)!= NULL)
        {
            if(pTunnel->ReRoute == TRUE)
            {
                recovery_type = NEW_LSP_FAILED;
            }
            else
            {
                zlog_info("\nLSP is not rerouted and having working lsp...");
                return NULL;
            }
        }
        else
        {
            if((pTunnel->ReRoute == TRUE)&&
                (pTunnel->properties != NULL))
            {
                zlog_info("\nLSP is not working lsp, reroute lasts...");
                return NULL;
            }
        }
        zlog_info("\nPrimary Tunnel failed Dest %x Tunnel ID %x Source %x recovery type %d",
            pUserLsp->params.to,pUserLsp->pUserLspTunnels->TunnelId,pUserLsp->params.from,recovery_type);
        return UserPrimaryLspRecovery(pTunnel,pSm,recovery_type,exclude_node);
        
    }
    else
    {
        if(GetWorkingRsvpLsp(pTunnel)== NULL)
        {
            if((pTunnel->ReRoute == TRUE)&&
                (pTunnel->properties != NULL))
            {
                return NULL;
            }
            else
            {
                zlog_info("\npTunnel->Reroute %d pTunnel->properties %x",pTunnel->ReRoute,pTunnel->properties);
            }
        }
        else if(pTunnel->ReRoute == FALSE)
        {
            return NULL;
        }
        zlog_info("\nSecondary Tunnel failed Dest %x Tunnel ID %x Source %x",
            pUserLsp->params.to,pTunnel->TunnelId,pUserLsp->params.from);
        return UserSecondaryLspRecovery(pTunnel,pSm,exclude_node);
    }
}

uns32 GetTunnelHops(RSVP_TUNNEL_PROPERTIES *pTunnel,uns32 *ErHopNumber,IPV4_ADDR **ppErHops)
{
    RSVP_LSP_PROPERTIES *pRsvpWorkingLsp;
    IPV4_ADDR *pWorkingRsvpLspErHops = NULL;
    uns32 WorkingRsvpLspHops = 0,i,j;

    zlog_info("entering GetTunnelHops");

    *ErHopNumber = 0;
    *ppErHops = NULL;
    if(pTunnel == NULL)
    {
        return E_ERR;
    }
    if((pRsvpWorkingLsp = GetWorkingRsvpLsp(pTunnel)) != NULL)
    {
        if(pRsvpWorkingLsp->tunneled == FALSE)
        {
            WorkingRsvpLspHops = pRsvpWorkingLsp->forw_info.path.HopCount;
            pWorkingRsvpLspErHops = pRsvpWorkingLsp->forw_info.path.pErHopsList;
#if 0
            if((pWorkingRsvpLspErHops)&&(pWorkingRsvpLspErHops[WorkingRsvpLspHops-1] == PsbKey.Session.Dest)
            {
                WorkingRsvpLspHops--;
            }
#endif
        }
        else
        {
            zlog_err("\nthis case is not supported %s %d",__FILE__,__LINE__);
        }
    }
    else
    {
        WorkingRsvpLspHops = 0;
    }
    /* now, fill in the array */
    if(WorkingRsvpLspHops != 0)
    {
        if((*ppErHops = (IPV4_ADDR *)XMALLOC(MTYPE_TE,sizeof(IPV4_ADDR)*(WorkingRsvpLspHops/2))) == NULL)
        {
            zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
            return E_ERR;
        }
        for(j = 0,i = 0;i < WorkingRsvpLspHops;i += 2,j++)
        {
           if(rdb_remote_link_router_id_get(pWorkingRsvpLspErHops[i],&((*ppErHops)[j])) != E_OK)
           {
               zlog_err("Cannot get router ID for %x %s %d",pWorkingRsvpLspErHops[i],__FILE__,__LINE__);
           }
        }
        *ErHopNumber = WorkingRsvpLspHops/2;
    }
    zlog_info("leaving GetTunnelHops");
    return E_OK;
}

BOOL TunnelsHaveSharedErHops(IPV4_ADDR *pFirstArray,
                             uns32 FirstArraySize,
                             IPV4_ADDR *pSecondArray,
                             uns32 SecondArraySize)
{
    int i,j;
    for(i = 0;i < FirstArraySize;i++)
    {
        for(j = 0;j < SecondArraySize;j++)
        {
            if(pFirstArray[i] == pSecondArray[j])
            {
                zlog_info("Hop %x is shared",pFirstArray[i]);
                return TRUE;
            }
        }
    }
    return FALSE;
}

SM_CALL_T *ModifySecondary(RSVP_TUNNEL_PROPERTIES *pSecTunnel,
                           SM_T *pSm,
                           STATIC_PATH *pPrimaryStaticPath,
                           USER_LSP *pUserLsp)
{
    INGRESS_API *pOpenLspParams = NULL;
    STATIC_PATH *pSecStaticPath;
    IPV4_ADDR *pSecondaryLspErHops;
    uns32 SecondaryLspErHopNumber;
    LSP_PATH_SHARED_PARAMS *pParams;
    ER_HOP *pErHopsList = NULL;
    IPV4_ADDR *pPrimaryLspErHops;
    uns32 PrimaryLspErHopNumber;
    uns8 Flags = 0;

    zlog_info("entering ModifySecondary");
    if(pSecTunnel == NULL)
    {
        return NULL;
    }
    if(pSecTunnel->ReRoute == TRUE)
    {
        pSecTunnel->AdjustmentRequired = TRUE;
        zlog_info("\nSecondary LSP adjustment is postponed...");
        return NULL;
    }
    if(rdb_get_static_path(pSecTunnel->StaticPathName,
                                &pSecStaticPath) == E_OK)
    {
        /* if checking for shared hops makes sense */
        if((((pSecStaticPath->HopList != NULL)&&
            (pSecStaticPath->HopList->Loose == 1))||
            (pSecStaticPath->HopList == NULL))||
            (((pPrimaryStaticPath != NULL)&&
                (pPrimaryStaticPath->HopList != NULL)&&
                (pPrimaryStaticPath->HopList->Loose == 1))||
                ((pPrimaryStaticPath == NULL)||
                    (pPrimaryStaticPath->HopList == NULL))))
        {
            if(GetTunnelHops(pSecTunnel,&SecondaryLspErHopNumber,&pSecondaryLspErHops) != E_OK)
            {
                SecondaryLspErHopNumber = 0;
                pSecondaryLspErHops = NULL;
                zlog_info("\ncannot get Secondary Tunnel's ER HOPS");
            }
            if(GetTunnelHops(pUserLsp->pUserLspTunnels,&PrimaryLspErHopNumber,&pPrimaryLspErHops) != E_OK)
            {
                PrimaryLspErHopNumber = 0;
                pPrimaryLspErHops = NULL;
                zlog_info("\ncannot get Primary tunnel's ER HOPs");
            }
            zlog_info("\nSecondary Tunnel's ER HOPS number %d",SecondaryLspErHopNumber);
            if((TunnelsHaveSharedErHops(pPrimaryLspErHops,
                                        PrimaryLspErHopNumber,
                                        pSecondaryLspErHops,
                                        SecondaryLspErHopNumber) == TRUE)||
               (GetWorkingRsvpLsp(pSecTunnel) == NULL))
            {
                zlog_info("\nSTEP1");
                pParams = PathParamsGet(pUserLsp,pSecStaticPath->PathName,0);
                Flags |= (pParams->record == TRUE) ? LABEL_RECORDING_DESIRED : 0;
                /* for now the FRR is only boolean. However, in future it may be more complicated */
                Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
                if(SetErHopList(pSecStaticPath,&pErHopsList) != E_OK)
                {
                    zlog_err("Cannot set ER hops list %s %d",__FILE__,__LINE__);
                    return NULL;
                }
                if((pOpenLspParams = CreateRequest2Signalling(pUserLsp->params.to,
                                                              pSecTunnel->TunnelId,
                                                              pSecStaticPath->HopCount,
                                                              pErHopsList,
                                                              pSecTunnel->RequiredBW,
                                                              pParams->setup_priority,
                                                              pParams->hold_priority,
                                                              Flags,
                                                              (~(pParams->affinity_properties & pParams->affinity_mask)) & pParams->affinity_mask,
                                                              0,
                                                              pParams->affinity_properties & pParams->affinity_mask)) == NULL)
                {
                    zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
                    XFREE(MTYPE_TE,pErHopsList);
                    return NULL;
                }
                
                return LspRequest(pOpenLspParams,PrimaryLspErHopNumber,pPrimaryLspErHops,pSm,&pSecTunnel,TRUE,pParams);
            }
            else
            {
                zlog_info("Tunnels do not have shared hops");
            }
            XFREE(MTYPE_TE,pSecondaryLspErHops);
        }
        else
        {
            zlog_info("\nRoute re-resolution doesn't makes sense %s %x %x",
                pSecStaticPath->PathName,
                pPrimaryStaticPath,pSecStaticPath);
            if((pPrimaryStaticPath != NULL)&&
                (pPrimaryStaticPath->HopList != NULL))
                zlog_info("\nLoose (primary) %d",pPrimaryStaticPath->HopList->Loose);
            if(pSecStaticPath->HopList != NULL)
                zlog_info("\nLoose (secondary) %d",pSecStaticPath->HopList->Loose);
        }
    }
    else
    {
        if(GetTunnelHops(pSecTunnel,&SecondaryLspErHopNumber,&pSecondaryLspErHops) != E_OK)
        {
            SecondaryLspErHopNumber = 0;
            pSecondaryLspErHops = NULL;
            zlog_info("\ncannot get Secondary Tunnel's ER HOPS");
        }
        if(GetTunnelHops(pUserLsp->pUserLspTunnels,&PrimaryLspErHopNumber,&pPrimaryLspErHops) != E_OK)
        {
            PrimaryLspErHopNumber = 0;
            pPrimaryLspErHops = NULL;
            zlog_info("\ncannot get Primary tunnel's ER HOPs");
        }
        zlog_info("\nSecondary Tunnel's ER HOPS number %d",SecondaryLspErHopNumber);
        if((TunnelsHaveSharedErHops(pPrimaryLspErHops,
                                    PrimaryLspErHopNumber,
                                    pSecondaryLspErHops,
                                    SecondaryLspErHopNumber) == TRUE)||
           (GetWorkingRsvpLsp(pSecTunnel) == NULL))
        {
            zlog_info("\nSTEP1`");
            pParams = PathParamsGet(pUserLsp,pSecTunnel->StaticPathName,0);
            Flags |= (pParams->record == TRUE) ? LABEL_RECORDING_DESIRED : 0;
            /* for now the FRR is only boolean. However, in future it may be more complicated */
            Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
            
            if((pOpenLspParams = CreateRequest2Signalling(pUserLsp->params.to,
                                                          pSecTunnel->TunnelId,
                                                          0,
                                                          NULL,
                                                          pSecTunnel->RequiredBW,
                                                          pParams->setup_priority,
                                                          pParams->hold_priority,
                                                          Flags,
                                                          (~(pParams->affinity_properties & pParams->affinity_mask)) & pParams->affinity_mask,
                                                          0,
                                                          pParams->affinity_properties & pParams->affinity_mask)) == NULL)
            {
                 zlog_err("\nmalloc failed %s %d",__FILE__,__LINE__);
                 return NULL;
            }
                
            return LspRequest(pOpenLspParams,PrimaryLspErHopNumber,pPrimaryLspErHops,pSm,&pSecTunnel,TRUE,pParams);
        }
        else
        {
            zlog_info("\nTunnels do not have shared hops");
        }
        XFREE(MTYPE_TE,pSecondaryLspErHops);
    }
    return NULL;
}

SM_CALL_T *OptimizeSingleLsp(RSVP_TUNNEL_PROPERTIES *pTunnel,IPV4_ADDR dest,IPV4_ADDR source)
{
    SM_CALL_T *pCall = NULL;
    LSP_PATH_SHARED_PARAMS *pParams;
    USER_LSP *pUserLsp;
    STATIC_PATH *pStaticPath = NULL;
    uns8 Flags = 0;
    ER_HOP *pErHopsList = NULL;
    RSVP_TUNNEL_PROPERTIES *pDummyTunnel;
    SM_T *pSm;
    INGRESS_API *pOpenLspParams;
    RSVP_LSP_PROPERTIES *pRsvpLsp;

    zlog_info("entering OptimizeSingleLsp");
    pSm = pTunnel->sm_handle;
    UnregisterClient((int)pSm,pTunnel->TunnelId);
    if(pTunnel->pOpenLspParams)
    {
        XFREE(MTYPE_TE,pTunnel->pOpenLspParams);
        pTunnel->pOpenLspParams = NULL;
    }
    if(pTunnel->pCrArgs)
    {
        if((((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->tunneled == FALSE)&&
             (((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->data.path.ErHopNumber))
        {
            XFREE(MTYPE_TE,((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->data.path.pErHop);
            ((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->data.path.pErHop = NULL;
            ((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->data.path.ErHopNumber = 0;
        }
        if(((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->AvoidHopNumber)
        {
            XFREE(MTYPE_TE,((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->AvoidHopsArray);
            ((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->AvoidHopsArray = NULL;
            ((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->AvoidHopNumber = 0;
        }
        if(((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->LinkBwNumber)
        {
            XFREE(MTYPE_TE,((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->pLinkBw);
            ((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->pLinkBw = NULL;
            ((CONSTRAINT_ROUTE_RESOLUTION_ARGS *)(pTunnel->pCrArgs))->LinkBwNumber = 0;
        }
        XFREE(MTYPE_TE,pTunnel->pCrArgs);
    }

    if((pUserLsp = UserLspGet(pTunnel->UserLspName)) != NULL)
    {
        pParams = PathParamsGet(pUserLsp,
                                pTunnel->StaticPathName,
                                ((!strcmp(pUserLsp->params.Primary,pTunnel->StaticPathName))&&(pUserLsp->pUserLspTunnels->TunnelId == pTunnel->TunnelId)));
        if(rdb_get_static_path(pTunnel->StaticPathName,
                                    &pStaticPath) != E_OK)
        {
           pStaticPath = NULL; 
        }
        if(pStaticPath)
        {
            if(SetErHopList(pStaticPath,&pErHopsList) != E_OK)
            {
                zlog_err("Cannot set ER hops list %s %d",__FILE__,__LINE__);
                return NULL;
            }
        }
        if((pErHopsList != NULL)&&(pErHopsList[0].Loose == 0)) /* nothing to optimize */
        {
           XFREE(MTYPE_TE,pErHopsList);
           return NULL;
        }
        if((pUserLsp->pUserLspTunnels->TunnelId == pTunnel->TunnelId)||(pTunnel->ReRoute == 0))
        {
            uns32 ErHopNumber;
            IPV4_ADDR *pErHops;
            if(pUserLsp->pUserLspTunnels->TunnelId != pTunnel->TunnelId)
            {
               if(GetTunnelHops(pUserLsp->pUserLspTunnels,
                                &ErHopNumber,
                                &pErHops) != E_OK)
               {
                   zlog_info(
                          "cannot get ER HOPs to be avoided %s %d",
                          __FILE__,__LINE__);
                   ErHopNumber = 0;
                   pErHops = NULL;
               }
            }
            else
            {
               ErHopNumber = 0;
               pErHops = NULL;
            }
            Flags |= pParams->record == TRUE ? LABEL_RECORDING_DESIRED : 0;
            /* for now the FRR is only boolean. However, in future it may be more complicated */
            Flags |= (pUserLsp->params.FastReRoute == TRUE) ? LOCAL_PROTECTION_DESIRED : 0;
            if((pStaticPath != NULL)&&(SetErHopList(pStaticPath,&pErHopsList) != E_OK))
            {
                zlog_err("Cannot set ER hops list %s %d",__FILE__,__LINE__);
                return NULL;
            }
            if((pOpenLspParams = CreateRequest2Signalling(pUserLsp->params.to,
                                                          pTunnel->TunnelId,
                                                          (pStaticPath == NULL) ? 0 : pStaticPath->HopCount,
                                                          pErHopsList,
                                                          pParams->BW,
                                                          pParams->setup_priority,
                                                          pParams->hold_priority,
                                                          Flags,
                                                          (~(pParams->affinity_properties & pParams->affinity_mask)) & pParams->affinity_mask,
                                                          0,
                                                          pParams->affinity_properties & pParams->affinity_mask)) == NULL)
            {
                zlog_err("malloc failed %s %d",__FILE__,__LINE__);
                return NULL;
            }
            return LspRequest(pOpenLspParams,
                              ErHopNumber,
                              pErHops,
                              pSm,
                              &pDummyTunnel,
                              TRUE,
                              pParams);
        }
    }
    else if((pRsvpLsp = GetWorkingRsvpLsp(pTunnel)) != NULL)
    {
        Flags |= LABEL_RECORDING_DESIRED;
        /* for now the FRR is only boolean. However, in future it may be more complicated */
        Flags |= LOCAL_PROTECTION_DESIRED;
        if((pOpenLspParams = CreateRequest2Signalling(dest,
                                                      pTunnel->TunnelId,
                                                      0,
                                                      NULL,
                                                      pTunnel->RequiredBW,
                                                      pRsvpLsp->SetupPriority,
                                                      pRsvpLsp->HoldPriority,
                                                      Flags,
                                                      0,0,0)) == NULL)
        {
            zlog_err("malloc failed %s %d",__FILE__,__LINE__);
            return NULL;
        }
        return LspRequest(pOpenLspParams,
                          0,
                          NULL,
                          pSm,
                          &pDummyTunnel,
                          TRUE,
                          NULL);
    }
    StartCspfRetryTimer(pTunnel);
    zlog_info("leaving OptimizeSingleLsp");
    return pCall;
}


