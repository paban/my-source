
#ifndef _PATRICIA_H_
#define _PATRICIA_H_

#include "general.h"

typedef struct patricia_params
{
  int key_size;			/* 1..PATRICIA_MAX_KEY_SIZE - in OCTETS */
  int info_size;		/* NOT USED!  Present for backward-compatibility only! */
  int actual_key_size;		/* NOT USED!  Present for backward-compatibility only! */
  int node_size;		/* NOT USED!  Present for backward compatibitity only! */
} PATRICIA_PARAMS;

#define PATRICIA_MAX_KEY_SIZE	256	/* # octets */


typedef struct patricia_node
{
  int bit;			/* must be signed type (bits start at -1) */
  struct patricia_node *left;
  struct patricia_node *right;
  uns8 *key_info;
} PATRICIA_NODE;

#define PATRICIA_NODE_NULL ((PATRICIA_NODE *)0)

typedef uns8 PATRICIA_LEXICAL_STACK;	/* ancient history... */

typedef struct patricia_tree
{
  PATRICIA_NODE root_node;	/* A tree always has a root node. */
  PATRICIA_PARAMS params;
  unsigned int n_nodes;
} PATRICIA_TREE;


#define m_KEY_CMP(t, k1, k2) memcmp(k1, k2, (size_t)(t)->params.key_size)
#define m_GET_BIT(key, bit)  ((bit < 0) ? 0 : ((int)((*((key) + (bit >> 3))) >> (7 - (bit & 0x07))) & 0x01))

unsigned int patricia_tree_init (PATRICIA_TREE * const pTree,
				 const PATRICIA_PARAMS * const pParams);
unsigned int patricia_tree_destroy (PATRICIA_TREE * const pTree);
void patricia_tree_clear (PATRICIA_TREE * const pTree);
unsigned int patricia_tree_add (PATRICIA_TREE * const pTree,
				PATRICIA_NODE * const pNode);
unsigned int patricia_tree_del (PATRICIA_TREE * const pTree,
				PATRICIA_NODE * const pNode);
PATRICIA_NODE *patricia_tree_get (const PATRICIA_TREE * const pTree,
				  const uns8 * const pKey);
PATRICIA_NODE *patricia_tree_get_best (const PATRICIA_TREE * const pTree, const uns8 * const pKey, uns16 KeyLen);	/* Length of key (in BITS) */
PATRICIA_NODE *patricia_tree_getnext (PATRICIA_TREE * const pTree, const uns8 * const pKey);	/* NULL means get 1st */

int patricia_tree_size (const PATRICIA_TREE * const pTree);

#endif
