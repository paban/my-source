#ifndef __TE_CONFIG_DATA_PLANE_H_
#define __TE_CONFIG_DATA_PLANE_H_

void mplsTePolicy (char *PolicyName, char *LabelEntryKey, int opcode);
void mplsTeInOutLabel (unsigned int AllocatedLabel,
		       unsigned int ReceivedLabelMapping,
		       unsigned int OutIfIndex);
void mplsTeOutLabel (int *OutLabels, int OutLabelsCount, char *key,
		     int NextHop, int opcode);

#endif

#ifndef __LABEL_MAN_H_
#define __LABEL_MAN_H_


typedef enum
{
  ODD_LABELS,
  EVEN_LABELS,
  ALL_LABELS,
  MAX_LABELS
} LABEL_POLICY_E;

#define LABEL_SPACE_SIZE  0x2000

uns32 TE_RSVPTE_API_LabelRelease (TE_API_MSG * dmsg);
uns32 LabelAllocate (unsigned int *Label,
		     LABEL_POLICY_E policy, PSB_KEY * pKey, uns32 IfIndex);
void IngressLabelMappingReceived (unsigned int ReceivedLabelMapping,
				  unsigned int OutIfIndex, PSB_KEY * pKey);

int LSRLabelMappingReceived (unsigned int AllocatedLabel,
			     unsigned int ReceivedLabelMapping,
			     unsigned int OutIfIndex);

#endif

#ifndef __LSR_H__
#define __LSR_H__

void TE_RSVPTE_API_TransitResv (TE_API_MSG * dmsg);

#endif
