
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */  
  
#ifndef _PDU_SETUP_
#define _PDU_SETUP_
  
#include "ldp_struct.h"
#include "ldp_nortel.h"



  unsigned int msgId);


  int holdTime);



  unsigned char holdPrio, unsigned short res);

  unsigned short type); 



  uint8_t adv_discp, 
  uint32_t remote_lsraddr, uint16_t remote_labelspace, 

  unsigned int minvci, unsigned int maxvpi, unsigned int maxvci);

  unsigned int len, unsigned int mindlci, unsigned int resmax,

  unsigned int maxdlci);





#if 0
  mplsFecElement_t * createFecElemFromFecType(struct mpls_fec *fec);




  mplsLdpLblMapMsg_t * lblMap);


  struct mpls_label *label);


  struct mpls_label *label);


  struct mpls_label *label); 
#endif /* 
int addFecElem2FecTlv(mplsLdpFecTlv_t * fecTlv, mplsFecElement_t * elem);

  unsigned int vpi, unsigned int vci);


  unsigned int dlci);







  int status, unsigned int msgId, int msgType);


  mplsLdpHeader_t * hdr, void *data);


  void *data);

  unsigned int localCrlspId, unsigned int routerId);

  unsigned char res, unsigned char weight, float pdr, float pbs, float cdr,
  float cbs, float ebs);



#endif /* 