/****************************************************************************
 *
 * Copyright (C) 2006-2011 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/

/*
 * @file    sflc_trie.c
 * @author  Adam Keeton <akeeton@sourcefire.com>
 * @date    Thu July 20 10:16:26 EDT 2006
 *
 * @brief   LC-trie wrapper for lookup table. Calls Stefan Nillson's LC-trie
 *          library routines.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfrt.h"
#include "sfrt_lctrie.h"
#include "sfrt_trie.h"

/* Build the routing table */
static routtable_t lct_buildrouttable(entry_t s[], int size,
                           double fillfact, int rootbranch,
                           int verbose);

/* Dispose of the routing table */
static void lct_disposerouttable(routtable_t t);

/* Perform a lookup. */
static policy_t lct_find(word s, routtable_t t);

/* Print the routing table. (For debugging) */
static void writerouttable(routtable_t t);

/* Print statistics about the routing table */
static void routtablestat(routtable_t t, int verbose);


/* Create new LC-trie, */
lc_table_t *sfrt_lct_new(int max) {
    lc_table_t *t;

    t = (lc_table_t*)malloc(sizeof(lc_table_t));

    if(!t) {
        return NULL;
    }

    t->dirty = TRUE;
    t->lct = NULL;
    t->size = max;
    t->num_ent = 0;
    t->entries = (entry_t*)malloc(sizeof(entry_t) * t->size);

    if(!t->entries) {
        return NULL;
    }

    return t;
}

void sfrt_lct_free(void *tbl) {
    lc_table_t *table = (lc_table_t*)tbl;

    if(!table) {
        /*  What are you calling me for? */
        return;
    }

    if(!table->entries) {
        /* This really really should not have happened */
    } else {
        unsigned int index;

        for(index = 0; index < table->num_ent; index++) {
            free(table->entries[index]);
        }

        free(table->entries);
    }

    if(table->lct) {
        lct_disposerouttable(table->lct);
    }

    free(table);
}

inline tuple_t sfrt_lct_lookup(IP ip, void *tbl)
{
    tuple_t ret;
    lc_table_t* table = (lc_table_t*)tbl;

    if(!table) {
        ret.index = ret.length = 0;
        return ret;
    }

    if(!table->lct || table->dirty) {
        sfrt_lct_compile(table);
    }

    ret.index = lct_find(ip, table->lct);

    /* Length is not stored with the lc_trie. */
    ret.length = 0;

    return ret;
}

int sfrt_lct_insert(IP ip, int len, uint32_t policy, int behavior, void *tbl)
{
    lc_table_t* table = (lc_table_t*)tbl;

    if(!table || !table->entries) {
        /* Error message here? */
        return LCT_INSERT_FAILURE;
    }

    table->dirty = TRUE;

    if(table->num_ent+1 > table->size) {
        return RT_POLICY_TABLE_EXCEEDED;
    }

    table->entries[ table->num_ent ] =
		(entry_t)malloc(sizeof(struct entryrec));

    if( !table->entries[ table->num_ent ]) {
        return LCT_INSERT_FAILURE;
    }

    table->entries[ table->num_ent ]->data = ip >> (32 - len) << (32 - len);
    table->entries[ table->num_ent ]->len = len;
    table->entries[ table->num_ent ]->policy = (word)policy;

    table->num_ent++;

    return RT_SUCCESS;
}

int sfrt_lct_compile(lc_table_t *table)
{
    if(!table) {
        return LCT_COMPILE_FAILURE;
    }

    if(table->dirty && table->lct) {
        lct_disposerouttable(table->lct);
    }

    table->lct = lct_buildrouttable(table->entries,
							table->num_ent, 0.5, 16, 0);

    table->dirty = FALSE;

    return RT_SUCCESS;
}

uint32_t sfrt_lct_usage(void *table) {
    /* Not presently applicable */
    return 0;
}

/*
   A routing table for wordsized (32 bits) bitstrings implemented as
   a static level- and pathcompressed trie. For details please consult

      Stefan Nilsson and Gunnar Karlsson. Fast Address Look-Up
      for Internet Routers. International Conference of Broadband
      Communications (BC'97).

      http://www.hut.fi/~sni/papers/router/router.html

   The code presented in this file has been tested with care but
   is not guaranteed for any purpose. The writer does not offer
   any warranties nor does he accept any liabilities with respect
   to the code.

   Stefan Nilsson, 4 nov 1997.

   Laboratory of Information Processing Science
   Helsinki University of Technology
   Stefan.Nilsson@hut.fi
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <float.h>

static int ROOTBRANCH = 16;     // The branching factor at the root
static double FILLFACT = 0.50;  // The trie fill factor

/* Compare two routing table entries. This is used by qsort */
static int pstrcmp(const void* ii, const void* jj)
{
   /* This pointer nonsense is to defeat the compiler warning
    * and prevent a lot of typecasting below */
   const entry_t *i = (entry_t *)ii;
   const entry_t *j = (entry_t *)jj;

   if ((*i)->data < (*j)->data)
      return -1;
   else if ((*i)->data > (*j)->data)
      return 1;
   else if ((*i)->len < (*j)->len)
      return -1;
   else if ((*i)->len > (*j)->len)
      return 1;
   else
      return 0;
}

/* Compare two netxhop addresses. This is used by qsort */
static int ppolicycmp(const void* ii, const void *jj)
{
   /* This pointer nonsense is to defeat the compiler warning
    * and prevent a lot of typecasting below */
   const policy_t *i = ii;
   const policy_t *j = jj;

   if (*i < *j)
      return -1;
   else if (*i > *j)
      return 1;
   else
      return 0;
}

/*
   Compute the branch and skip value for the root of the
   tree that covers the base array from position 'first' to
   'first + n - 1'. Disregard the first 'prefix' characters.
   We assume that n >= 2 and base[first] != base[first+n-1].
*/
static void computebranch(base_t base[], int prefix, int first, int n,
                   int *branch, int *newprefix)
{
   word low, high;
   int i, pat, b;
   boolean patfound;
   int count;

   /* Compute the new prefix */
   high = REMOVE(prefix, base[first]->str);
   low = REMOVE(prefix, base[first+n-1]->str);
   i = prefix;
   while (EXTRACT(i, 1, low) == EXTRACT(i, 1, high))
      i++;
   *newprefix = i;

   /* Always use branching factor 2 for two elements */
   if (n == 2) {
      *branch = 1;
      return;
   }

   /* Use a large branching factor at the root */
   if (ROOTBRANCH > 0 && prefix == 0  && first == 0) {
      *branch = ROOTBRANCH;
      return;
   }

   /* Compute the number of bits that can be used for branching.
      We have at least two branches. Therefore we start the search
      at 2^b = 4 branches. */
   b = 1;
   do {
      b++;
      if (n < FILLFACT*(1<<b) ||
          *newprefix + b > ADRSIZE)
         break;
      i = first;
      pat = 0;
      count = 0;
      while (pat < 1<<b) {
         patfound = FALSE;
         while (i < first + n &&
                pat == (int)EXTRACT(*newprefix, b, base[i]->str)) {
            i++;
            patfound = TRUE;
         }
         if (patfound)
            count++;
         pat++;
      }
   } while (count >= FILLFACT*(1<<b));
   *branch = b - 1;
}

/*
   Build a tree that covers the base array from position
   'first' to 'first + n - 1'. Disregard the first 'prefix'
   characters. 'pos' is the position for the root of this
   tree and 'nextfree' is the first position in the array
   that hasn't yet been reserved.
*/
static void build(base_t base[], pre_t pre[], int prefix, int first, int n,
           int pos, int *nextfree, node_t *tree)
{
   int branch, newprefix;
   int k, p, adr, bits;
   word bitpat;

   if (n == 1)
      tree[pos] = first; /* branch and skip are 0 */
   else {
      computebranch(base, prefix, first, n, &branch, &newprefix);
      adr = *nextfree;
      tree[pos] = SETBRANCH(branch) |
                  SETSKIP(newprefix-prefix) |
                  SETADR(adr);
      *nextfree += 1<<branch;
      p = first;
      /* Build the subtrees */
      for (bitpat = 0; bitpat < (word)(1<<branch); bitpat++) {
         k = 0;
         while (p+k < first+n &&
                EXTRACT(newprefix, branch, base[p+k]->str) == bitpat)
            k++;

         if (k == 0) {
	   /* The leaf should have a pointer either to p-1 or p,
              whichever has the longest matching prefix */
            int match1 = 0, match2 = 0;

            /* Compute the longest prefix match for p - 1 */
            if (p > first) {
               int prep, len;
               prep =  base[p-1]->pre;
               while (prep != NOPRE && match1 == 0) {
                  len = pre[prep]->len;
                  if (len > newprefix &&
                      EXTRACT(newprefix, len - newprefix, base[p-1]->str) ==
                      EXTRACT(32 - branch, len - newprefix, bitpat))
                     match1 = len;
                  else
                     prep = pre[prep]->pre;
               }
	    }

            /* Compute the longest prefix match for p */
            if (p < first + n) {
               int prep, len;
               prep =  base[p]->pre;
               while (prep != NOPRE && match2 == 0) {
                  len = pre[prep]->len;
                  if (len > newprefix &&
                      EXTRACT(newprefix, len - newprefix, base[p]->str) ==
                      EXTRACT(32 - branch, len - newprefix, bitpat))
                     match2 = len;
                  else
                     prep = pre[prep]->pre;
               }
	    }

            if ((match1 > match2 && p > first) || p == first + n)
               build(base, pre, newprefix+branch, p-1, 1,
                     adr + bitpat, nextfree, tree);
            else
               build(base, pre, newprefix+branch, p, 1,
                     adr + bitpat, nextfree, tree);
         } else if (k == 1 && base[p]->len - newprefix < branch) {
            word i;
            bits = branch - base[p]->len + newprefix;
            for (i = bitpat; i < bitpat + (1<<bits); i++)
               build(base, pre, newprefix+branch, p, 1,
                     adr + i, nextfree, tree);
            bitpat += (1<<bits) - 1;
         } else
            build(base, pre, newprefix+branch, p, k,
                  adr + bitpat, nextfree, tree);
         p += k;
      }
   }
}

/* Is the string s a prefix of the string t? */
static int isprefix(entry_t s, entry_t t)
{
   return s != NULL &&
          (s->len == 0 ||   /* EXTRACT() can't handle 0 bits */
           (s->len <= t->len &&
           EXTRACT(0, s->len, s->data) ==
           EXTRACT(0, s->len, t->data)));
}

static int binsearch(policy_t x, policy_t v[], unsigned int n)
{
   int low, high, mid;

   low = 0;
   high = n - 1;
   while (low <= high) {
      mid = (low+high) / 2;
      if (x < v[mid])
         high = mid - 1;
      else if (x > v[mid])
         low = mid + 1;
      else
         return mid;
   }
   return -1;
}

static policy_t *buildpolicytable(entry_t entry[],
								  int nentries, int *policysize)
{
   policy_t *policy, *nexttemp;
   int count, i;

   /* Extract the policy addresses from the entry array */
   nexttemp = (policy_t *) malloc(nentries * sizeof(policy_t));
   for (i = 0; i < nentries; i++)
      nexttemp[i] = entry[i]->policy;

   //quicksort((char *) nexttemp, nentries,
   qsort((char *) nexttemp, nentries,
             sizeof(policy_t), ppolicycmp);

   /* Remove duplicates */
   count = nentries > 0 ? 1 : 0;
   for (i = 1; i < nentries; i++)
      if (ppolicycmp(&nexttemp[i-1], &nexttemp[i]) != 0)
         nexttemp[count++] = nexttemp[i];

   /* Move the elements to an array of proper size */
   policy = (policy_t *) malloc(count * sizeof(policy_t));
   for (i = 0; i < count; i++) {
      policy[i] = nexttemp[i];
   }
   free(nexttemp);

   *policysize = count;
   return policy;
}

static routtable_t lct_buildrouttable(entry_t entry[], int nentries,
                           double fillfact, int rootbranch,
                           int verbose)
{
   policy_t *policy; /* policy table */
   int npolicys;

   int size;           /* Size after dublicate removal */

   node_t *t;          /* We first build a big data structure... */
   base_t *b, btemp;
   pre_t *p, ptemp;

   node_t *trie;       /* ...and then we store it efficiently */
   comp_base_t *base;
   comp_pre_t *pre;

   routtable_t table;  /* The complete data structure */

   /* Auxiliary variables */
   int i, j, nprefs = 0, nbases = 0;
   int nextfree = 1;

   FILLFACT = fillfact;
   ROOTBRANCH = rootbranch;

   policy = buildpolicytable(entry, nentries, &npolicys);

   qsort((char *) entry, nentries, sizeof(entry_t), pstrcmp);
   /* Remove duplicates */
   size = nentries > 0 ? 1 : 0;
   for (i = 1; i < nentries; i++)
      if (pstrcmp(&entry[i-1], &entry[i]) != 0)
         entry[size++] = entry[i];

   /* The number of internal nodes in the tree can't be larger
      than the number of entries. */
   t = (node_t *) malloc((2 * size + 2000000) * sizeof(node_t));
   b = (base_t *) malloc(size * sizeof(base_t));
   p = (pre_t *) malloc(size * sizeof(pre_t));

   /* Initialize pre-pointers */
   for (i = 0; i < size; i++)
      entry[i]->pre = NOPRE;

   /* Go through the entries and put the prefixes in p
      and the rest of the strings in b */
   for (i = 0; i < size; i++)
      if (i < size-1 && isprefix(entry[i], entry[i+1])) {
         ptemp = (pre_t) malloc(sizeof(struct prerec));
         ptemp->len = entry[i]->len;
         ptemp->pre = entry[i]->pre;
         /* Update 'pre' for all entries that have this prefix */
         for (j = i + 1; j < size && isprefix(entry[i], entry[j]); j++)
            entry[j]->pre = nprefs;
         ptemp->policy = binsearch(entry[i]->policy, policy, npolicys);
         p[nprefs++] = ptemp;
      } else {
         btemp = (base_t) malloc(sizeof(struct baserec));
         btemp->len = entry[i]->len;
         btemp->str = entry[i]->data;
         btemp->pre = entry[i]->pre;
         btemp->policy = binsearch(entry[i]->policy, policy, npolicys);
         b[nbases++] = btemp;
      }

   /* Build the trie structure */
   build(b, p, 0, 0, nbases, 0, &nextfree, t);

   /* At this point we now how much memory to allocate */
   trie = (node_t *) malloc(nextfree * sizeof(node_t));
   base = (comp_base_t *) malloc(nbases * sizeof(comp_base_t));
   pre = (comp_pre_t *) malloc(nprefs * sizeof(comp_pre_t));

   for (i = 0; i < nextfree; i++) {
      trie[i] = t[i];
   }
   free(t);

   for (i = 0; i < nbases; i++) {
      base[i].str = b[i]->str;
      base[i].len = b[i]->len;
      base[i].pre = b[i]->pre;
      base[i].policy = b[i]->policy;
      free(b[i]);
   }
   free(b);

   for (i = 0; i < nprefs; i++) {
      pre[i].len = p[i]->len;
      pre[i].pre = p[i]->pre;
      pre[i].policy = p[i]->policy;
      free(p[i]);
   }
   free(p);

   table = (routtable_t) malloc(sizeof(struct routtablerec));
   table->trie = trie;
   table->triesize = nextfree;
   table->base = base;
   table->basesize = nbases;
   table->pre = pre;
   table->presize = nprefs;
   table->policy = policy;
   table->policysize = npolicys;

   return table;
}

static void lct_disposerouttable(routtable_t t)
{
   free(t->pre);
   free(t->trie);
   free(t->base);
   free(t->policy);
   free(t);
}

/* Return a policy or 0 if not found */
static policy_t lct_find(word s, routtable_t t)
{
   node_t node;
   int pos, branch, adr;
   word bitmask;
   int preadr;

   /* Traverse the trie */
   node = t->trie[0];
   pos = GETSKIP(node);
   branch = GETBRANCH(node);
   adr = GETADR(node);
   while (branch != 0) {
      node = t->trie[adr + EXTRACT(pos, branch, s)];
      pos += branch + GETSKIP(node);
      branch = GETBRANCH(node);
      adr = GETADR(node);
   }

   /* Was this a hit? */
   bitmask = t->base[adr].str ^ s;
   if (EXTRACT(0, t->base[adr].len, bitmask) == 0)
      return t->policy[t->base[adr].policy];

   /* If not, look in the prefix tree */
   preadr = t->base[adr].pre;
   while (preadr != NOPRE) {
      if (EXTRACT(0, t->pre[preadr].len, bitmask) == 0)
         return t->policy[t->pre[preadr].policy];
      preadr = t->pre[preadr].pre;
   }

   return 0; /* Not found */
}

static void traverse(routtable_t t, node_t r, int depth,
              int *totdepth, int *maxdepth, int depths[])
{
   int i;

   if (GETBRANCH(r) == 0) { /* leaf */
      *totdepth += depth;
      if (depth > *maxdepth)
         *maxdepth = depth;
      depths[depth]++;
   } else
      for (i = 0; i < 1<<GETBRANCH(r); i++)
         traverse(t, t->trie[GETADR(r)+i], depth+1,
                  totdepth, maxdepth, depths);
}

