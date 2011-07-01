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
 * @file    sflc_trie.h
 * @author  Adam Keeton <akeeton@sourcefire.com>
 * @date    Thu July 20 10:16:26 EDT 2006
 *
 * @brief   LC-trie wrapper for lookup table. Calls Stefan Nillson's LC-trie
 *          library routines.
 */

#ifndef SFRT_LCTRIE_H_
#define SFRT_LCTRIE_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfrt.h"

/*******************************************************************/
/* LC-trie data structure */
typedef struct {
    char dirty;         /* Whether or not this table needs to be rebuilt */
    entry_t *entries;   /* For insertion phase
                         * Only necessary for LC-trie and will
                         * most likely be moved later */
    uint32_t num_ent;
    uint32_t size;
    routtable_t lct;    /* The actual LC-trie data
                         * structure from Nilsson's code */
} lc_table_t;

/*******************************************************************/
/* LC trie functions, these are not intended to be called directly */
lc_table_t *   sfrt_lct_new(void);
void           sfrt_lct_free(void *);
inline tuple_t sfrt_lct_lookup(IP ip, void *table);
inline int     sfrt_lct_insert(IP ip, int len, uint32_t data_index,
                          int behavior, void *table);
int            sfrt_lct_compile(lc_table_t *table);
uint32_t      sfrt_lct_usage(void *table);

#endif /* SFRT_LCTRIE_H_ */

