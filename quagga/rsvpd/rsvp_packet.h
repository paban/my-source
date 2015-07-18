#ifndef _RSVP_PACKET_H_
#define _RSVP_PACKET_H_

#define RSVP_IP_PROTOCOL 46

#define COMMON_CTYPE   1

#define SESSION_CLASS             1
#define RSVP_HOP_CLASS            3
#define INTEGRITY_CLASS           4
#define TIME_VALUES_CLASS         5
#define ERR_SPEC_CLASS            6
#define SCOPE_CLASS               7
#define STYLE_CLASS               8
#define FLOW_SPEC_CLASS           9
#define FILTER_SPEC_CLASS         10
#define SENDER_TEMPLATE_CLASS     11
#define SENDER_TSPEC_CLASS        12
#define ADSPEC_CLASS              13
#define POLICY_DATA_CLASS         14
#define RESV_CONF_CLASS           15
#define LABEL_CLASS               16
#define LABEL_REQUEST_CLASS       19
#define EXPLICIT_ROUTE_CLASS      20
#define RECORDED_ROUTE_CLASS      21
#define SESSION_ATTRIBUTE_CLASS   207

#define SESSION_CTYPE 7
#define SENDER_TEMPLATE_CTYPE 7
#define SENDER_TSPEC_CTYPE 2

#define FLOW_SPEC_INTSERV_CTYPE 2

#define SESSION_ATTRIBUTES_RA_CLASS_TYPE 1
#define SESSION_ATTRIBUTES_CLASS_TYPE 7



#define SESSION_LSP_IPV4_CTYPE             7
#define SENDER_TEMPLATE_LSP_IPV4_CTYPE     7
#define FILTER_SPEC_LSP_IPV4_CTYPE         7
#define SESSION_ATTRIBUTES_IPV4_CTYPE      7
#define SESSION_ATTRIBUTES_RA_IPV4_CTYPE   1

#define RSVP_VERSION (1 << 4)

#define LOCAL_PROTECTION_DESIRED   0x01
#define LABEL_RECORDING_DESIRED    0x02
#define SE_STYLE_DESIRED           0x04

typedef struct
{
  uns8 VersionFlags;
  uns8 MsgType;
  uns16 CheckSum;
  uns8 SendTTL;
  uns8 Resvd;
  uns16 RsvpLength;
} RSVP_COMMON_HDR;

#define PATH_MSG         1
#define RESV_MSG         2
#define PATH_ERR_MSG     3
#define RESV_ERR_MSG     4
#define PATH_TEAR_MSG    5
#define RESV_TEAR_MSG    6
#define RESV_CONF_MSG    7

typedef struct
{
  uns16 Length;
  uns8 ClassNum;
  uns8 CType;
} OBJ_HDR;


typedef struct
{
  IPV4_ADDR Dest;
  uns16 Resvd;
  uns16 TunnelId;
  IPV4_ADDR ExtTunelId;
} SESSION_OBJ;

typedef struct
{
  IPV4_ADDR PHop;
  uns32 LIH;
} RSVP_HOP_OBJ;

typedef struct
{
  uns32 TimeValues;
} TIME_VALUES_OBJ;

typedef struct
{
  uns32 IpAddrNumber;
  IPV4_ADDR *Addresses;
} SCOPE_OBJ;


typedef struct
{
  uns8 Flags;
  uns8 OptionVector1;
  uns16 OptionVector2;
} STYLE_OBJ;

#define SE_STYLE_BITS 0x12
#define FF_STYLE_BITS 0x0A

typedef struct
{
  uns16 VersionResvd;
  uns16 MessageLength;
} MSG_HDR;

typedef struct
{
  uns8 ServHdr;
  uns8 Resvd;
  uns16 ServLength;
} SERV_HDR;

typedef struct
{
  uns8 ParamID;
  uns8 ParamFlags;
  uns16 ParamLength;
} PARAM_HDR;

typedef struct
{
  float TockenBucketRate;
  float TockenBucketSize;
  float PeakDataRate;
  float MinPolicedUnit;
  float MaxPacketSize;
} CTRL_LOAD_FLOW_SPEC;

typedef struct
{
  CTRL_LOAD_FLOW_SPEC CtrlLoad;
  PARAM_HDR GuarSpecificParamHdr;
  float Rate;
  uns32 SlackTerm;
} GUAR_FLOW_SPEC;

typedef struct
{
  MSG_HDR MsgHdr;
  SERV_HDR ServHdr;
  PARAM_HDR ParamHdr;
  union
  {
    CTRL_LOAD_FLOW_SPEC CtrlLoad;
    GUAR_FLOW_SPEC Guar;
  } u;
} FLOW_SPEC_OBJ;

typedef struct
{
  IPV4_ADDR IpAddr;
  uns16 Resvd;
  uns16 LspId;
} SENDER_TEMPLATE_OBJ;

typedef SENDER_TEMPLATE_OBJ FILTER_SPEC_OBJ;

#define SENDER_TSPEC_MSG_FORMAT             0
#define SENDER_TSPEC_MSG_LENGTH             7
#define SENDER_TSPEC_SERV_NUMBER            5
#define SENDER_TSPEC_DATA_LENGTH            6
#define SENDER_TSPEC_TOCKEN_BUCKET_PARAM_ID 127
#define SENDER_TSPEC_TOCKEN_BUCKET_PARAM_LENGTH 5

#define FLOW_SPEC_MSG_FORMAT             0
#define FLOW_SPEC_MSG_LENGTH             7
#define FLOW_SPEC_GUAR_SERV_NUMBER       2
#define FLOW_SPEC_CTRL_LOAD_SERV_NUMBER  5
#define FLOW_SPEC_DATA_LENGTH            6
#define FLOW_SPEC_TOCKEN_BUCKET_PARAM_ID 127
#define FLOW_SPEC_TOCKEN_BUCKET_PARAM_LENGTH 5

typedef struct
{
  MSG_HDR MessageHdr;
  SERV_HDR ServHdr;
  PARAM_HDR ParamHdr;
  float TockenBucketRate;
  float TockenBucketSize;
  float PeakDataRate;
  uns32 MinPolicedUnit;
  uns32 MaxPacketSize;
} SENDER_TSPEC_OBJ;

typedef struct
{
  uns32 Label;
} LABEL_OBJ;

typedef struct
{
  uns16 Resvd;
  uns16 L3Pid;
} LABEL_REQUEST_OBJ;

typedef struct
{
  uns8 LType;
  uns8 Length;
} ER_SUBOBJ_HDR;

typedef struct
{
  IPV4_ADDR IpAddress;
  uns8 PrefixLength;
  uns8 Resvd;
} ER_IPV4_SUBOBJ;

typedef struct
{
  uns32 AsNumber;
} ER_AS_SUBOBJ;

typedef struct _er_subobj_
{
  ER_SUBOBJ_HDR SubObjHdr;
  union
  {
    ER_IPV4_SUBOBJ Ipv4;
    ER_AS_SUBOBJ AS;
  } u;
  struct _er_subobj_ *next;
} ER_SUBOBJ;

typedef struct
{
  uns8 SubObjNumber;
  ER_SUBOBJ *er;
} ER_OBJ;

typedef struct
{
  uns8 Type;
  uns8 Length;
} RR_SUBOBJ_HDR;

typedef struct
{
  IPV4_ADDR IpAddr;
  uns8 PrefixLen;
  uns8 Flags;
} RR_IPV4_SUBOBJ;

typedef struct
{
  uns8 Flags;
  uns8 CType;
  uns32 Label;
} RR_LABEL_SUBOBJ;

typedef struct _rr_subobj_
{
  RR_SUBOBJ_HDR SubObjHdr;
  union
  {
    RR_IPV4_SUBOBJ Ipv4;
    RR_LABEL_SUBOBJ Label;
  } u;
  struct _rr_subobj_ *next;
} RR_SUBOBJ;

typedef struct
{
  RR_SUBOBJ *rr;
} RR_OBJ;

typedef struct
{
  uns8 SetPrio;
  uns8 HoldPrio;
  uns8 Flags;
  uns8 NameLength;
  char *SessionName;
} SESSION_ATTR;

typedef struct
{
  uns32 ExcludeAny;
  uns32 IncludeAny;
  uns32 IncludeAll;
  uns8 SetPrio;
  uns8 HoldPrio;
  uns8 Flags;
  uns8 NameLength;
  char *SessionName;
} SESSION_ATTR_RA;

typedef struct
{
  uns8 CType;
  union
  {
    SESSION_ATTR SessAttr;
    SESSION_ATTR_RA SessAttrRa;
  } u;
} SESSION_ATTRIBUTES_OBJ;

typedef struct
{
  uns8 PerServHdr;
  uns8 BreakBitAndResvd;
  uns16 Length;
} PER_SERV_HDR;

typedef struct
{
  PER_SERV_HDR PerServHdr;
  PARAM_HDR Param4Hdr;
  uns32 IS_HopCount;
  PARAM_HDR Param6Hdr;
  float PathBW;
  PARAM_HDR Param8Hdr;
  uns32 MinPathLatency;
  PARAM_HDR Param10Hdr;
  uns32 ComposedMTU;
} ADSPEC_GEN;

typedef struct
{
  PER_SERV_HDR PerServHdr;
  PARAM_HDR Param133Hdr;
  uns32 Ctot;
  PARAM_HDR Param134Hdr;
  uns32 Dtot;
  PARAM_HDR Param135Hdr;
  uns32 Csum;
  PARAM_HDR Param136Hdr;
  uns32 Dsum;
} GUAR_ADSPEC;

typedef struct
{
  uns8 CType;
  uns16 Resvd;
  uns16 MsgLen;
  ADSPEC_GEN AdSpecGen;
  GUAR_ADSPEC GuarAdSpec;
} ADSPEC_OBJ;

typedef struct
{
  IPV4_ADDR IpAddr;
} RESV_CONF_OBJ;

typedef struct
{
  IPV4_ADDR IpAddr;
  uns8 Flags;
  uns8 ErrCode;
  uns16 ErrVal;
} ERR_SPEC_OBJ;

#define  CONFIRMATION_ERR_CODE             0
#define  ADMISSION_CTRL_FAILURE_ERR_CODE   1
#define  POLICY_CTRL_FAILURE_ERR_CODE      2
#define  NO_PATH_INFO_4_RESV_ERR_CODE      3
#define  NO_SENDER_INFO_4_RESV             4
#define  CONFLICTING_RESV_STYLES_ERR_CODE  5
#define  UNKNOWN_RESV_STYLE_ERR_CODE       6
#define  CONFLICTING_DEST_PORTS_ERR_CODE   7
#define  CONFLICTING_SENDER_PORTS_ERR_CODE 8
#define  SERVICE_PREEMPTED_ERR_CODE        12
#define  UNKNOWN_OBJ_CLASS_ERR_CODE        13
#define  UNKNOWN_OBJ_CTYPE_ERR_CODE        14
#define  API_ERR_CODE                      20
#define  TRAFFIC_CTRL_ERR_CODE             21
#define  TRAFFIC_CTRL_SYSTEM_ERR_CODE      22
#define  RSVP_SYSTEM_ERR_CODE              23
#define  ROUTING_PROBLEM_ERR_CODE          24
#define  NOTIFY_ERR_CODE                   25

#define  GLB_DEFINED_SUB_CODE_FLAG         0x0000
#define  ORG_SPECIFIC_SUB_CODE_FLAG        0x8000
#define  SRV_SPECIFIC_SUB_CODE_FLAG        0xC000
#define  LOCAL_STATE_MAY_BE_UPDATED_FLAG   0x1000

#define  DELAY_BOUND_CANNOT_BE_MET         0x0001
#define  BW_UNAVAILABLE                    0x0002
#define  MTU_UNAVAILABLE                   0x0003

#define  SERVICE_CONFLICT                  0x0001
#define  SERVICE_UNSUPPORTED               0x0002
#define  BAD_FLOW_SPEC_VAL                 0x0003
#define  BAD_TSPEC_VAL                     0x0004
#define  BAD_ADSPEC_VAL                    0x0005

#define  BAD_EXPLICIT_ROUTE_OBJ            0x0001
#define  BAD_STRICT_NODE                   0x0002
#define  BAD_LOOSE_NODE                    0x0003
#define  BAD_INITIAL_SUBOBJ                0x0004
#define  NO_ROUTE_AVAILABLE                0x0005
#define  UNACCEPTABLE_LABEL_VAL            0x0006
#define  RRO_INIDICATED_ROUTING_LOOP       0x0007
#define  NON_RSVP_ROUTER_IN_PATH           0x0008
#define  LABEL_ALLOCATION_FAILURE          0x0009
#define  UNSUPPORTED_L3PID                 0x000A

#define  RRO_TOO_LARGE_4_MTU               0x0001
#define  RRO_NOTIFICATION                  0x0002
#define  TUNNEL_LOCALLY_REPAIRED           0x0003

typedef struct _opaque_obj_list_
{
  OBJ_HDR ObjHdr;
  void *pData;
  struct _opaque_obj_list_ *next;
} OPAQUE_OBJ_LIST;

typedef OPAQUE_OBJ_LIST POLICY_DATA_OBJ;
typedef OPAQUE_OBJ_LIST INTEGRITY_OBJ;

//typedef SENDER_TEMPLATE_OBJ FILTER_SPEC_OBJ;
//typedef struct SENDER_TSPEC FLOW_SPEC_OBJ;

struct _phop_resv_refresh_list_;
struct _rsb_;

typedef struct
{
  FILTER_SPEC_OBJ FilterSpec;
  LABEL_OBJ ReceivedLabel;	/* received with RESV */
  LABEL_OBJ SentLabel;		/* sent with RESV (allocated upon PATH) */
  RR_OBJ Rro;
  uns32 AgeOutValue;
  struct thread *AgeOutTimer;
  FLOW_SPEC_OBJ FlowSpec;
  uns8 NewFlowSpecValid;
  FLOW_SPEC_OBJ NewFlowSpec;
  FLOW_SPEC_OBJ BlockadeFlowSpec;
  struct _phop_resv_refresh_list_ *pPHopResvRefreshList;
  struct _effective_flow_ *pEffectiveFlow;	/* for SE only */
  struct _psb_ *pPsb;
  uns8 ToBeDeleted;
  uns32 BlocadeValue;
  struct thread *BlocadeTimer;
  uns8 Blocked;
} FILTER_SPEC_DATA;

typedef struct _filter_list_
{
  FILTER_SPEC_DATA *pFilterSpecData;
  struct _filter_list_ *next;
} FILTER_LIST;

typedef struct
{
  SESSION_OBJ Session;
  RSVP_HOP_OBJ ReceivedRsvpHop;
  RSVP_HOP_OBJ SentRsvpHop;
  TIME_VALUES_OBJ TimeValues;
  ER_OBJ ReceivedEro;
  ER_OBJ SentEro;
  LABEL_REQUEST_OBJ LabelRequest;
  SESSION_ATTRIBUTES_OBJ SessionAttributes;
  SENDER_TEMPLATE_OBJ SenderTemplate;
  SENDER_TSPEC_OBJ SenderTSpec;
  ADSPEC_OBJ ReceivedAdSpec;
  ADSPEC_OBJ SentAdSpec;
  RR_OBJ ReceivedRro;
  RR_OBJ AddedRro;
  RESV_CONF_OBJ ResvConf;
  STYLE_OBJ Style;
  FILTER_LIST *pFilterList;
  INTEGRITY_OBJ *pIntegrityObj;
  POLICY_DATA_OBJ *pPolicyDataObj;
  OPAQUE_OBJ_LIST *pOpaqueObjList;
  ERR_SPEC_OBJ ErrorSpec;
} RSVP_PKT;

#define ERO_SUBTYPE_IPV4 1
#define ERO_SUBTYPE_AS   32

#define RRO_SUBTYPE_IPV4  1
#define RRO_SUBTYPE_LABEL 3

typedef struct _rsvp_pkt_queue_
{
  uns8 MsgType;
  RSVP_PKT *pRsvpPkt;
  uns32 InIfIndex;
  IPV4_ADDR SourceIp;
  uns8 ttl;
  struct _rsvp_pkt_queue_ *next;
} RSVP_PKT_QUEUE;

#endif /* !defined (_RSVP_PKT_H_) */
