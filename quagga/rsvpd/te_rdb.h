#ifndef RDB_H
#define RDB_H

typedef enum
{
  EMPTY_PATH,
  PSC_PATH,
  LSC_PATH,
  FSC_PATH,
  TSC_PATH,
  PSC_LSP,
  LSC_LSP,
  FSC_LSP,
  TSC_LSP,
  MAX_PATH_TYPE
} PATH_TYPE;

typedef struct _link_properties_
{
  PATH_TYPE LinkType;
  uns32 LinkCost;
  float LinkMaxReservableBW;
  float LinkReservableBW[8];
  float LinkMaxLspBW;
  uns32 LinkTeMetric;
  uns32 LinkColorMask;
} LINK_PROPERTIES;

typedef struct _path_properties_
{
  PATH_TYPE PathType;
  uns32 PathCost;
  float PathMaxReservableBW;
  float PathReservableBW[8];
  float PathMaxLspBW;
  uns32 PathSumTeMetric;
  uns32 PathColorMask;
  uns8 PathHopCount;
} PATH_PROPERTIES;

#if 0
typedef struct
{
  IPV4_ADDR local_ip_addr;
  IPV4_ADDR remote_ip_addr;
  float MaxReservableBW;
  float ReservableBW[8];
  float MaxLspBW;
  uns32 te_metric;
  uns32 ColorMask;
} TE_HOP;
#else
typedef struct _path_l_list_
{
  struct _path_ *pPath;
  struct _path_l_list_ *next;
} PATH_L_LIST;

typedef struct
{
  PATRICIA_NODE Node;
  IPV4_ADDR local_ip;
  IPV4_ADDR remote_ip;
  IPV4_ADDR adv_router_id;
  float MaxReservableBW;
  float ReservableBW[8];
  float MaxLspBW;
  uns32 te_metric;
  uns32 ColorMask;
  uns32 Cost;
  PATH_L_LIST *pPathList;
} TE_HOP;
#endif

typedef struct
{
  IPV4_ADDR local_ip;
  IPV4_ADDR remote_ip;
} link_key_t;

typedef struct
{
  PATH_TYPE SummaryPathType;
  float SummaryMaxLspBW;
  float SummaryMaxReservableBW;
  float SummaryReservableBW[8];
  uns32 SummaryCost;
} SUMMARY_PROPERTIES;

typedef struct _abr_
{
  IPV4_ADDR AbrIpAddr;
  uns8 NumberOfSummaries;
  SUMMARY_PROPERTIES *SummaryProperties;
} ABR;

typedef struct _te_link_properties_
{
  float MaxReservableBW;
  float ReservableBW[8];
  float MaxLspBW;
  uns32 TeMetric;
  uns32 color_mask;
} TE_LINK_PROPERTIES;

typedef struct _component_link_
{
  uns32 oifIndex;
  float ReservableBW[8];
  float ConfiguredReservableBW[8];
  float AllocatedBW[8][8];
  PATRICIA_TREE ProtectionTree;
  PATRICIA_TREE IngressProtectionTree;
  struct _component_link_ *next;
} COMPONENT_LINK;

typedef struct _te_link_
{
  uns32 te_link_id;
  uns8 Status;
  PATH_TYPE type;
  TE_LINK_PROPERTIES te_link_properties;
  PATRICIA_TREE NeighborsTree;
  COMPONENT_LINK *component_links;
} TE_LINK;


typedef struct
{
  PATRICIA_NODE Node;
  IPV4_ADDR link_id;
  IPV4_ADDR router_id;
} LINK_2_ROUTER_ID;

typedef struct _er_hop_l_list_
{
  TE_HOP *er_hop;
  struct _er_hop_l_list_ *next;
} ER_HOP_L_LIST;

typedef struct _path_
{
  IPV4_ADDR destination;
  PATH_PROPERTIES PathProperties;
  union
  {
    ER_HOP_L_LIST *er_hops_l_list;
    TE_HOP *er_hops;
  } u;
} PATH;

typedef struct _abrs_l_list_
{
  ABR *Abr;
  struct _abrs_l_list_ *next;
} ABRS_L_LIST;

typedef struct _te_link_l_list_
{
  TE_LINK *te_link;
  struct _te_link_l_list_ *next;
} TE_LINK_L_LIST;

typedef struct _ipv4_hop_
{
  IPV4_ADDR IpAddr;
  int Loose;
  struct _ipv4_hop_ *next;
} IPV4_HOP;

typedef struct _static_path_l_list_
{
  char PathName[32];
  int HopCount;
  IPV4_HOP *HopList;
  struct _static_path_l_list_ *next;
} STATIC_PATH;

uns32 AmIDestination (IPV4_ADDR dest, uns32 * pDestIf);
uns32 IsDestinationNextHop (IPV4_ADDR dest, TE_LINK_L_LIST ** ppTeLinks);
uns32 IsDestinationIntraArea (IPV4_ADDR dest, PATH_L_LIST ** ppPaths);
uns32 GetPathNumber (IPV4_ADDR dest);
uns32 IsDestinationASBorder (IPV4_ADDR dest, ABRS_L_LIST ** ppAbrs);
E_RC rdb_create ();
uns32 rdb_destroy ();
uns32 rdb_add_component_link (uns32 TeLinkId,
			      COMPONENT_LINK * pComponentLink);
uns32 rdb_delete_component_link (uns32 TeLinkId, uns32 oIfIndex);
uns32 rdb_get_component_link (uns32 TeLinkId, uns32 IfIndex,
			      COMPONENT_LINK ** ppCompLink);
uns32 rdb_add_mod_path (IPV4_ADDR dest_ip, PATH * pPath);
uns32 rdb_connectivity_broken (IPV4_ADDR from_node, IPV4_ADDR to_node,
			       PATH_TYPE path_type);
uns32 rdb_link_state_update (IPV4_ADDR from_node, IPV4_ADDR to_node,
			     LINK_PROPERTIES * pLinkProperties);
uns32 rdb_remote_link_bw_update (IPV4_ADDR from_node, IPV4_ADDR to_node,
				 float BW2Decrease, uns8 Priority,
				 PATH_TYPE LinkSwitchCap);
uns32 rdb_remote_link_2_router_id_mapping (IPV4_ADDR link_id,
					   IPV4_ADDR router_id);
uns32 rdb_remote_link_2_router_id_mapping_withdraw (IPV4_ADDR link_id);
uns32 rdb_set_router_id (IPV4_ADDR IpAddr);
IPV4_ADDR rdb_get_router_id ();
uns32 rdb_remote_link_router_id_get (IPV4_ADDR from_node,
				     IPV4_ADDR * router_id);
uns32 rdb_static_path_del_hop_by_index (char *StaticPathName, int index);
uns32 rdb_static_path_del_hop (char *StaticPathName, IPV4_ADDR IpAddr);
uns32 rdb_static_path_add_hop_by_index (char *StaticPathName,
					IPV4_ADDR IpAddr, int Loose,
					int index);
uns32 rdb_static_path_add_hop_after_index (char *StaticPathName,
					   IPV4_ADDR IpAddr, int Loose,
					   int index);
uns32 rdb_static_path_add_hop (char *StaticPathName, IPV4_ADDR IpAddr,
			       int Loose);
uns32 rdb_get_static_path (char *pName, STATIC_PATH ** ppStaticPath);
uns32 rdb_create_static_path (char *StaticPathName);
uns32 rdb_delete_static_path (char *StaticPathName);
uns32 rdb_delete_asbr (IPV4_ADDR asbr_ip, IPV4_ADDR abr_ip);
uns32 rdb_add_mod_summary (IPV4_ADDR asbr_ip, ABR * pAbr);
uns32 rdb_del_next_hop (IPV4_ADDR next_hop, uns32 te_link_id);
uns32 rdb_local_link_status_change (uns32 TeLinkId, uns8 Status);
uns32 rdb_add_next_hop (IPV4_ADDR next_hop, uns32 TeLinkId);
uns32 rdb_del_te_link (uns32 te_link_id);
uns32 rdb_add_te_link (TE_LINK * pTeLink);
void rdb_te_link_max_lsp_bw_calc (TE_LINK * pTeLink);
uns32 rdb_get_te_link (uns32 TeLinkId, TE_LINK ** ppTeLink);

uns32 rdb_next_hop_dump (struct vty *vty);
uns32 rdb_summary_dump ();
uns32 rdb_path_dump (struct vty *vty);
uns32 rdb_remote_link_dump (struct vty *vty);
uns32 rdb_static_path_dump (char *, struct vty *vty);
uns32 rdb_te_links_dump (struct vty *vty);
uns32 rdb_remote_link_router_id_mapping_dump (struct vty *vty);
uns32 rdb_igp_hello ();

#endif
