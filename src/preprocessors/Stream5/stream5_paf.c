/* $Id: stream5_paf.c,v 1.2 2011/06/08 14:37:17 jjordan Exp $ */
/****************************************************************************
 *
 * Copyright (C) 2011-2011 Sourcefire, Inc.
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

//--------------------------------------------------------------------
// s5 stuff
//
// @file    stream5_paf.c
// @author  Russ Combs <rcombs@sourcefire.com>
//--------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sf_types.h"
#include "snort_bounds.h"
#include "snort_debug.h"
#include "sfPolicyUserData.h"
#include "stream5_common.h"
#include "stream5_paf.h"

//--------------------------------------------------------------------
// private state
//--------------------------------------------------------------------

typedef enum {
    FT_NOP,  // no flush
    FT_SFP,  // abort paf
    FT_PAF,  // flush to paf pt when len >= paf
    FT_MAX   // flush len when len >= mfp
} FlushType;

typedef struct {
    uint32_t mfp;

    uint32_t prep_calls;
    uint32_t prep_bytes;

    uint8_t map[MAXPORTS][2];
} PAF_Config;

// for cb registration
#define MAX_CB 32
static PAF_Callback s5_cb[MAX_CB];
static uint8_t s5_cb_idx;

// s5_len and s5_idx are used only during the
// lifetime of s5_paf_check()
static uint32_t s5_len;  // total bytes queued
static uint32_t s5_idx;  // offset from start of queued bytes

//--------------------------------------------------------------------

static uint32_t s5_paf_flush (
    PAF_Config* pc, PAF_State* ps, FlushType ft, uint32_t* flags)
{
    uint32_t at = 0;
    *flags &= ~(PKT_PDU_HEAD | PKT_PDU_TAIL);

    DEBUG_WRAP(DebugMessage(DEBUG_PAF,
       "%s: type=%d, fpt=%u, len=%u, tot=%u\n",
        __FUNCTION__, ft, ps->fpt, s5_len, ps->tot);)

    switch ( ft )
    {
    case FT_NOP:
        return 0;

    case FT_SFP:
        *flags = 0;
        return 0;

    case FT_PAF:
        at = ps->fpt;
        *flags |= PKT_PDU_TAIL;
        break;

    case FT_MAX:
        at = s5_len;
        ps->fpt -= s5_len;
        break;
    }

    if ( !at || !s5_len )
        return 0;

    if ( !ps->tot )
        *flags |= PKT_PDU_HEAD;

    ps->tot += at;

    return at;
}

//--------------------------------------------------------------------

static inline PAF_Status s5_paf_callback (
    PAF_Config* pc, PAF_State* ps, void* ssn,
    const uint8_t* data, uint32_t len,
    uint32_t flags, uint16_t port) 
{
    bool c2s = ( (flags & PKT_FROM_CLIENT) != 0 );
    int fn = pc->map[port][c2s?1:0];
    PAF_Callback cb = s5_cb[fn];

    assert(cb);

    if ( !cb )
        ps->paf = PAF_ABORT;
    else
        ps->paf = cb(ssn, &ps->user, data, len, flags, &ps->fpt);

    if ( ps->paf != PAF_SEARCH )
    {
        ps->fpt += s5_idx;

        if ( ps->fpt <= s5_len )
        {
            s5_idx = ps->fpt;
            return true;
        }
    }
    s5_idx = s5_len;
    return false;
}

//--------------------------------------------------------------------

static inline bool s5_paf_eval (
    PAF_Config* pc, PAF_State* ps, void* ssn, 
    uint16_t port, uint32_t flags, uint32_t fuzz,
    const uint8_t* data, uint32_t len, FlushType* ft)
{
    DEBUG_WRAP(DebugMessage(DEBUG_PAF,
        "%s: paf=%d, idx=%u, len=%u, fpt=%u\n",
        __FUNCTION__, ps->paf, s5_idx, s5_len, ps->fpt);)

    switch ( ps->paf )
    {
    case PAF_SEARCH:
        ps->tot = 0;

        if ( s5_len > s5_idx )
        {
            return s5_paf_callback(pc, ps, ssn, data, len, flags, port);
        }
        return false;

    case PAF_FLUSH:
        if ( s5_len >= ps->fpt )
        {
            *ft = FT_PAF;
            ps->paf = PAF_SEARCH;
            return true;
        }
        if ( s5_len >= pc->mfp + fuzz )
        {
            *ft = FT_MAX;
            return false;
        }
        return false;

    case PAF_SKIP:
        if ( s5_len > ps->fpt )
        {
            s5_idx = ps->fpt;
            return s5_paf_callback(pc, ps, ssn, data, len, flags, port);
        }
        return false;

    default:
        // PAF_ABORT || PAF_START
        break;
    }

    *ft = FT_SFP;
    return false;
}

//--------------------------------------------------------------------
// public stuff
//--------------------------------------------------------------------

void s5_paf_setup (PAF_State* ps)
{
    memset(ps, 0, sizeof(*ps));
    ps->paf = PAF_START;
}

void s5_paf_clear (PAF_State* ps)
{
    // either require pp to manage in other session state
    // or provide user free func?
    if ( ps->user )
    {
        free(ps->user);
        ps->user = NULL;
    }
    ps->paf = PAF_ABORT;
}

//--------------------------------------------------------------------

uint32_t s5_paf_check (
    void* pv, PAF_State* ps, void* ssn,
    const uint8_t* data, uint32_t len, uint32_t total,
    uint32_t seq, uint16_t port, uint32_t* flags, uint32_t fuzz)
{
    PAF_Config* pc = pv;

    DEBUG_WRAP(DebugMessage(DEBUG_PAF,
        "%s: len=%u, tot=%u, seq=%u, cur=%u\n",
        __FUNCTION__, len, total, seq, ps->seq);)

    if ( !s5_paf_initialized(ps) )
    {
        ps->seq = ps->pos = seq;
        ps->paf = PAF_SEARCH;
    }
    else if ( SEQ_LT(seq + len, ps->seq) )
    {
        return 0;
    }
    else if ( SEQ_LT(seq, ps->seq) )
    {
        uint32_t shift = ps->seq - seq;
        data += shift;
        len -= shift;
    }
    ps->seq += len;

    pc->prep_calls++;
    pc->prep_bytes += len;

    s5_len = total;
    s5_idx = total - len;

    do {
        FlushType ft = FT_NOP;
        uint32_t idx = s5_idx;
        uint32_t shift, fp;

        bool cont = s5_paf_eval(pc, ps, ssn, port, *flags, fuzz, data, len, &ft);

        if ( ft != FT_NOP )
        {
            fp = s5_paf_flush(pc, ps, ft, flags);

            ps->pos += fp;
            ps->seq = ps->pos;

            return fp;
        }
        shift = s5_idx - idx;
        data += shift;
        len -= shift;

        if ( !cont )
            break;

    } while ( 1 );

    if ( (ps->paf != PAF_FLUSH) && (s5_len > pc->mfp) )
    {
        *flags = 0;
        return s5_len;
    }
    return 0;
}

//--------------------------------------------------------------------
// FIXTHIS don't register if reassembly not enabled

bool s5_paf_register (
    tSfPolicyId pid, uint16_t port, bool c2s, PAF_Callback cb)
{
    Stream5Config* config = sfPolicyUserDataGet(s5_config, pid);
    PAF_Config* pc = config->tcp_config->paf_config;

    int i, dir = c2s ? 1 : 0;
    DEBUG_WRAP(DebugMessage(DEBUG_PAF,
        "%s: port=%u, dir=%d\n",  __FUNCTION__, port, c2s);)

    for ( i = 1; i <= s5_cb_idx; i++ )
    {
        if ( s5_cb[i] == cb )
            break;
    }
    if ( i == MAX_CB )
        return false;

    if ( i > s5_cb_idx )
    {
        s5_cb_idx = i;
        s5_cb[i] = cb;
    }
    if ( pc->map[port][dir] )
        return false;
    else
        pc->map[port][dir] = i;

    return true;
}

bool s5_paf_enabled (void* pv, uint16_t port, bool dir)
{
    PAF_Config* pc = pv;
    if ( !pc )
        return false;
    return ( pc->map[port][dir?1:0] != 0 );
}

void s5_paf_print (tSfPolicyId pid, void* pv)
{
#ifdef DEBUG_MSGS
    unsigned i;

    for ( i = 0; i < MAXPORTS; i++ )
    {
        if ( s5_paf_enabled(pv, (uint16_t)i, true) )
        {
            DebugMessage(DEBUG_PAF,
                "PAF policy=%u, port=%d, to server\n", pid, i);
        }

        if ( s5_paf_enabled(pv, (uint16_t)i, false) )
        {
            DebugMessage(DEBUG_PAF,
                "PAF policy=%u, port=%d, to client\n", pid, i);
        }
    }
#endif
}

//--------------------------------------------------------------------

void* s5_paf_new (void)
{
    PAF_Config* pc = SnortAlloc(sizeof(*pc));
    assert( pc );

    pc->mfp = ScPafMax();

    if ( !pc->mfp )
        // this ensures max < IP_MAXPACKET
        pc->mfp = (65535 - 255);

    DEBUG_WRAP(DebugMessage(DEBUG_PAF,
        "%s: mfp=%u\n",
        __FUNCTION__, pc->mfp);)

    return pc;
}

void s5_paf_delete (void* pv)
{
    PAF_Config* pc = (PAF_Config*)pv;

    DEBUG_WRAP(DebugMessage(DEBUG_PAF,
        "%s: prep=%u/%u\n",  __FUNCTION__,
        pc->prep_calls, pc->prep_bytes);)

    free(pc);
}

