#include "general.h"
#include <zebra.h>
#include "patricia.h"
#include "memory.h"

const static uns8 BitMasks[9] = {
  0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
};

static int
KeyBitMatch (const uns8 * p1, const uns8 * p2, unsigned int bitcount)
{
  while (bitcount > 8)
    {
      if (*p1 != *p2)
	{
	  return (((int) *p1) - ((int) *p2));
	}
      p1++;
      p2++;
      bitcount -= 8;
    }

  return (((int) (*p1 & BitMasks[bitcount])) -
	  ((int) (*p2 & BitMasks[bitcount])));

}

static PATRICIA_NODE *
search (const PATRICIA_TREE * const pTree, const uns8 * const key)
{
  PATRICIA_NODE *pNode;
  PATRICIA_NODE *pPrevNode;

  pNode = (PATRICIA_NODE *) & pTree->root_node;

  do
    {
      pPrevNode = pNode;

      if (m_GET_BIT (key, pNode->bit) == 0)
	{
	  pNode = pNode->left;
	}
      else
	{
	  pNode = pNode->right;
	}

    }
  while (pNode->bit > pPrevNode->bit);

  return pNode;
}

unsigned int
patricia_tree_init (PATRICIA_TREE * const pTree,
		    const PATRICIA_PARAMS * const pParams)
{
  if (pParams == NULL)
    return E_ERR;

  if ((pParams->key_size < 1) || (pParams->key_size > PATRICIA_MAX_KEY_SIZE))
    return E_ERR;

  pTree->params = *pParams;

  /* Initialize the root node, which is actually part of the tree structure. */
  pTree->root_node.key_info = (uns8 *) 0;
  pTree->root_node.bit = -1;
  pTree->root_node.left = pTree->root_node.right = &pTree->root_node;
  if ((pTree->root_node.key_info =
       (uns8 *) XMALLOC (0, pTree->params.key_size)) == NULL)
    {
      return E_ERR;
    }

  memset (pTree->root_node.key_info, '\0', (uns32) pTree->params.key_size);
  pTree->n_nodes = 0;

  return E_OK;
}


unsigned int
patricia_tree_destroy (PATRICIA_TREE * const pTree)
{
  patricia_tree_clear (pTree);
  XFREE (0, pTree->root_node.key_info);
  return E_OK;
}


void
patricia_tree_clear (PATRICIA_TREE * const pTree)
{

  pTree->root_node.left = pTree->root_node.right = &pTree->root_node;
  pTree->n_nodes = 0;

}

unsigned int
patricia_tree_add (PATRICIA_TREE * const pTree, PATRICIA_NODE * const pNode)
{
  PATRICIA_NODE *pSrch;
  PATRICIA_NODE *pTmpNode;
  PATRICIA_NODE *pPrevNode;
  int bit;

  pTmpNode = search (pTree, pNode->key_info);
  if (m_KEY_CMP (pTree, pNode->key_info, pTmpNode->key_info) == 0)
    {
      return E_ERR;		/* duplicate!. */
    }

  bit = 0;

  while (m_GET_BIT (pNode->key_info, bit) ==
	 ((pTmpNode->bit < 0) ? 0 : m_GET_BIT (pTmpNode->key_info, bit)))
    {
      bit++;
    }

  pSrch = &pTree->root_node;

  do
    {
      pPrevNode = pSrch;
      if (m_GET_BIT (pNode->key_info, pSrch->bit) == 0)
	pSrch = pSrch->left;
      else
	pSrch = pSrch->right;
    }
  while ((pSrch->bit < bit) && (pSrch->bit > pPrevNode->bit));

  pNode->bit = bit;

  if (m_GET_BIT (pNode->key_info, bit) == 0)
    {
      pNode->left = pNode;
      pNode->right = pSrch;
    }
  else
    {
      pNode->left = pSrch;
      pNode->right = pNode;
    }

  if (m_GET_BIT (pNode->key_info, pPrevNode->bit) == 0)
    {
      pPrevNode->left = pNode;
    }
  else
    {
      pPrevNode->right = pNode;
    }

  pTree->n_nodes++;
  return E_OK;
}


unsigned int
patricia_tree_del (PATRICIA_TREE * const pTree, PATRICIA_NODE * const pNode)
{
  PATRICIA_NODE *pNextNode;
  PATRICIA_NODE **pLegDownToNode;
  PATRICIA_NODE *pDelNode;
  PATRICIA_NODE **pPrevLeg;
  PATRICIA_NODE **pNextLeg;
  int UpWentRight;

  UpWentRight = 0;


  /* Start left of root (there is no right). */
  pNextNode = &pTree->root_node;
  pLegDownToNode = &pNextNode->left;

  while ((pDelNode = *pLegDownToNode) != pNode)
    {
      if (pDelNode->bit <= pNextNode->bit)
	{
	  return E_ERR;		/* Key not found. */
	}

      pNextNode = pDelNode;
      pLegDownToNode = ((m_GET_BIT (pNode->key_info, pNextNode->bit) != 0) ?
			&pNextNode->right : &pNextNode->left);

    }

  /* pDelNode points to the one to delete.
   * pLegDownToNode points to the down-pointer which points to it.
   */

  pPrevLeg = pLegDownToNode;
  pNextNode = pNode;

  /* keep going 'down' until we find the one which 
   * points back to pNode as an up-pointer. 
   */

  while (1)
    {
      UpWentRight = (m_GET_BIT (pNode->key_info, pNextNode->bit) != 0);
      pNextLeg = ((UpWentRight) ? &pNextNode->right : &pNextNode->left);
      pDelNode = *pNextLeg;

      if (pDelNode == pNode)
	break;

      if (pDelNode->bit <= pNextNode->bit)
	{
	  return E_ERR;		/* panic??? */
	}

      /* loop around again. */
      pNextNode = pDelNode;
      pPrevLeg = pNextLeg;
    }

  /* At this point, 
   * pNextNode is the one pointing UP to the one to delete. 
   * pPrevLeg points to the down-leg which points to pNextNode
   * UpWentRight is the direction which pNextNode took (in the UP
   *      direction) to get to the one to delete.)
   */

  /* We need to rearrange the tree.
   * BE CAREFUL.  The order of the following statements
   * is critical.
   */
  pNextNode->bit = pNode->bit;	/* it gets the 'bit' value of the evacuee. */
  *pLegDownToNode = pNextNode;

  *pPrevLeg = ((UpWentRight) ? pNextNode->left : pNextNode->right);
  pNextNode->right = pNode->right;
  pNextNode->left = pNode->left;

  pTree->n_nodes--;

  return E_OK;
}


PATRICIA_NODE *
patricia_tree_get (const PATRICIA_TREE * const pTree, const uns8 * const pKey)
{
  PATRICIA_NODE *pNode;

  /*
   * See if last getNext happened to be same key.
   *
   * Important assumtion: lastNode will be set to NULL if any
   * nodes are deleted from the tree.
   */

  pNode = search (pTree, pKey);

  if ((pNode == &pTree->root_node) ||
      (m_KEY_CMP (pTree, pNode->key_info, pKey) != 0))
    {
      pNode = PATRICIA_NODE_NULL;
    }

  return pNode;
}


PATRICIA_NODE *
patricia_tree_getnext (PATRICIA_TREE * const pTree, const uns8 * const pKey)
{
  uns8 Target[PATRICIA_MAX_KEY_SIZE];
  PATRICIA_NODE *pSrch;
  PATRICIA_NODE *pPrev;
  register uns8 *p1;
  register uns8 *p2;
  register int bit;

  if (pKey == (const uns8 *) 0)
    {
      /* Start at root of tree. */
      memset (Target, '\0', pTree->params.key_size);
    }
  else
    {
      memcpy (Target, pKey, pTree->params.key_size);
    }

  p1 = Target + pTree->params.key_size - 1;	/* point to last byte of key */
  while (p1 >= Target)
    {
      *p1 += 1;
      if (*p1 != '\0')
	{
	  break;
	}
      p1--;
    }
  if (p1 < Target)
    {
      return PATRICIA_NODE_NULL;
    }

  pSrch = &pTree->root_node;

  do
    {
      pPrev = pSrch;

      if (m_GET_BIT (Target, pSrch->bit) == 0)
	{
	  pSrch = pSrch->left;
	}
      else
	{
	  pSrch = pSrch->right;
	}

      if (pSrch->bit <= pPrev->bit)
	{
	  if ((memcmp (Target, pSrch->key_info, pTree->params.key_size) <= 0)
	      && (KeyBitMatch (Target, pSrch->key_info, 1 + pPrev->bit) == 0))
	    {
	      return pSrch;
	    }

	  do
	    {
	      if (pSrch == pPrev->left)
		{
		  /* We went left to get here */
		  if (pPrev->bit < 0)
		    {
		      return PATRICIA_NODE_NULL;
		    }
		  pSrch = pPrev;

		  p1 = pSrch->key_info;
		  p2 = Target;

		  for (bit = pSrch->bit; bit >= 8; bit -= 8)
		    {
		      *p2++ = *p1++;
		    }
		  /* Bring over SOME of the bits from pSrch. */
		  *p2 = (uns8) (*p1 & ((uns8) (BitMasks[bit])));

		  *p2 |= (uns8) (0x80 >> bit);

		  p2++;

		  while (p2 < (Target + pTree->params.key_size))
		    {
		      *p2++ = '\0';
		    }
		  break;
		}
	      else
		{
		  /* We went right to get here */
		  if (pPrev->bit <= 0)
		    {
		      return PATRICIA_NODE_NULL;
		    }

		  p1 = pPrev->key_info;
		  p2 = Target;

		  for (bit = pPrev->bit; bit >= 8; bit -= 8)
		    {
		      *p2++ = *p1++;
		    }
		  if (bit > 0)
		    {
		      *p2 = (uns8) (*p1 & BitMasks[bit]);
		    }
		  *p2 |= (uns8) (0xff >> bit);
		  for (p1 = p2 + 1; p1 < (Target + pTree->params.key_size);
		       p1++)
		    {
		      *p1 = '\0';
		    }
		  do
		    {
		      ++*p2;
		      if (*p2 != '\0')
			{
			  break;
			}
		    }
		  while (--p2 >= Target);

		  if (p2 < Target)
		    {
		      return PATRICIA_NODE_NULL;
		    }

		  pSrch = pPrev;

		  pPrev = &pTree->root_node;
		  do
		    {
		      if (m_GET_BIT (pSrch->key_info, pPrev->bit) == 0)
			{
			  if (pPrev->left == pSrch)
			    {
			      break;
			    }
			  pPrev = pPrev->left;
			}
		      else
			{
			  if (pPrev->right == pSrch)
			    {
			      break;
			    }
			  pPrev = pPrev->right;
			}

		    }
		  while (TRUE);

		  if (KeyBitMatch (Target, pSrch->key_info, 1 + pSrch->bit) ==
		      0)
		    {
		      break;
		    }
		}

	    }
	  while (TRUE);

	}			/* if (pSrch->bit <= pPrev->bit) */
      else
	{
	  /* We're still going 'down'... but make sure we haven't gone down too far. */
	  bit = KeyBitMatch (Target, pSrch->key_info, pSrch->bit);

	  if (bit < 0)
	    {
	      p1 = pSrch->key_info;
	      p2 = Target;
	      for (bit = pSrch->bit; bit >= 8; bit -= 8)
		{
		  *p2++ = *p1++;
		}
	      if (bit != 0)
		{
		  *p2++ = ((uns8) (*p1 & BitMasks[bit]));
		}
	      while (p2 < Target + pTree->params.key_size)
		{
		  *p2++ = '\0';
		}
	    }
	  else if (bit > 0)
	    {

	      do
		{
		  if (pSrch == pPrev->left)
		    {
		      /* We went left to get here */
		      if (pPrev->bit < 0)
			{
			  return PATRICIA_NODE_NULL;
			}
		      pSrch = pPrev;

		      p1 = pSrch->key_info;
		      p2 = Target;

		      for (bit = pSrch->bit; bit >= 8; bit -= 8)
			{
			  *p2++ = *p1++;
			}
		      /* Bring over SOME of the bits from pSrch. */
		      *p2 = (uns8) (*p1 & ((uns8) (BitMasks[bit])));

		      *p2 |= (uns8) (0x80 >> bit);

		      p2++;

		      while (p2 < (Target + pTree->params.key_size))
			{
			  *p2++ = '\0';
			}
		      break;
		    }
		  else
		    {
		      /* We went right to get here */
		      if (pPrev->bit <= 0)
			{
			  return PATRICIA_NODE_NULL;
			}

		      p1 = pPrev->key_info;
		      p2 = Target;

		      for (bit = pPrev->bit; bit >= 8; bit -= 8)
			{
			  *p2++ = *p1++;
			}
		      if (bit > 0)
			{
			  *p2 = (uns8) (*p1 & BitMasks[bit]);
			}
		      *p2 |= (uns8) (0xff >> bit);
		      for (p1 = p2 + 1;
			   p1 < (Target + pTree->params.key_size); p1++)
			{
			  *p1 = '\0';
			}
		      do
			{
			  ++*p2;
			  if (*p2 != '\0')
			    {
			      break;
			    }
			}
		      while (--p2 >= Target);

		      if (p2 < Target)
			{
			  return PATRICIA_NODE_NULL;
			}

		      pSrch = pPrev;

		      pPrev = &pTree->root_node;
		      do
			{
			  if (m_GET_BIT (pSrch->key_info, pPrev->bit) == 0)
			    {
			      if (pPrev->left == pSrch)
				{
				  break;
				}
			      pPrev = pPrev->left;
			    }
			  else
			    {
			      if (pPrev->right == pSrch)
				{
				  break;
				}
			      pPrev = pPrev->right;
			    }

			}
		      while (TRUE);

		      if (KeyBitMatch
			  (Target, pSrch->key_info, 1 + pSrch->bit) == 0)
			{
			  break;
			}
		    }

		}
	      while (TRUE);
	    }
	}
    }
  while (TRUE);
}


int
patricia_tree_size (const PATRICIA_TREE * const pTree)
{
  return pTree->n_nodes;
}
