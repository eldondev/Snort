/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* $Id$ */

/* 
 * 06/07/2007 - tw
 * Commented out 'content-list' code since it's considered broken and there
 * are no plans to fix it
 */

#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef DEBUG
#include <assert.h>
#endif

#include "sp_pattern_match.h"
#include "sp_replace.h"
#include "bounds.h"
#include "rules.h"
#include "plugbase.h"
#include "debug.h"
#include "mstring.h"
#include "util.h" 
#include "parser.h"  /* why does parser.h define Add functions.. */
#include "plugin_enum.h"
#include "checksum.h"
#include "inline.h"
#include "sfhashfcn.h"
#include "spp_httpinspect.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats contentPerfStats;
PreprocStats uricontentPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#define MAX_PATTERN_SIZE 2048

static void PayloadSearchInit(char *, OptTreeNode *, int);
//static void PayloadSearchListInit(char *, OptTreeNode *, int);
//static void ParseContentListFile(char *, OptTreeNode *, int);
static void PayloadSearchUri(char *, OptTreeNode *, int);
static void PayloadSearchHttpBody(char *, OptTreeNode *, int);
static void PayloadSearchHttpUri(char *, OptTreeNode *, int);
static void PayloadSearchHttpHeader(char *, OptTreeNode *, int);
static void PayloadSearchHttpMethod(char *, OptTreeNode *, int);
static void PayloadSearchHttpCookie(char *, OptTreeNode *, int);
static void PayloadSearchFastPattern(char *data, OptTreeNode *otn, int protocol);
//void ParsePattern(char *, OptTreeNode *, int);
//int CheckANDPatternMatch(void *option_data, Packet *p);
//int CheckORPatternMatch(void *option_data, Packet *p);
//int CheckUriPatternMatch(void *option_data, Packet *p);
static void PayloadSearchOffset(char *, OptTreeNode *, int);
static void PayloadSearchDepth(char *, OptTreeNode *, int);
static void PayloadSearchNocase(char *, OptTreeNode *, int);
static void PayloadSearchDistance(char *, OptTreeNode *, int);
static void PayloadSearchWithin(char *, OptTreeNode *, int);
static void PayloadSearchRawbytes(char *, OptTreeNode *, int);
static int uniSearchReal(const char *data, int dlen, PatternMatchData *pmd, int nocase);

//PatternMatchData * NewNode(OptTreeNode *, int);
void PayloadSearchCompile();

int list_file_line;     /* current line being processed in the list file */
int lastType = PLUGIN_PATTERN_MATCH;
const uint8_t *doe_ptr;

int detect_depth;       /* depth to the first char of the match */

extern HttpUri UriBufs[URI_COUNT]; /* the set of buffers that we are using to match against
                      set in decode.c */
extern uint8_t DecodeBuffer[DECODE_BLEN];

extern char *file_name;
extern int file_line;

#include "sfhashfcn.h"
#include "detection_options.h"

void PatternMatchFree(void *d)
{
    PatternMatchData *pmd = (PatternMatchData *)d;

    if (pmd == NULL)
        return;

    if (pmd->pattern_buf)
        free(pmd->pattern_buf);
    if (pmd->replace_buf)
        free(pmd->replace_buf);
    if(pmd->skip_stride)
       free(pmd->skip_stride);
    if(pmd->shift_stride)
       free(pmd->shift_stride);

    free(pmd);
}

uint32_t PatternMatchHash(void *d)
{
    uint32_t a,b,c,tmp;
    unsigned int i,j,k,l;
    PatternMatchData *pmd = (PatternMatchData *)d;

    a = pmd->exception_flag;
    b = pmd->offset;
    c = pmd->depth;

    mix(a,b,c);

    a += pmd->distance;
    b += pmd->within;
    c += pmd->rawbytes;
    
    mix(a,b,c);

    a += pmd->nocase;
    b += pmd->use_doe;
    c += pmd->uri_buffer;
    
    mix(a,b,c);

    a += pmd->pattern_size;
    b += pmd->replace_size;
    c += pmd->pattern_max_jump_size;
    
    mix(a,b,c);

    for (i=0,j=0;i<pmd->pattern_size;i+=4)
    {
        tmp = 0;
        k = pmd->pattern_size - i;
        if (k > 4)
            k=4;
       
        for (l=0;l<k;l++)
        {
            tmp |= *(pmd->pattern_buf + i + l) << l*8;
        }

        switch (j)
        {
            case 0:
                a += tmp;
                break;
            case 1:
                b += tmp;
                break;
            case 2:
                c += tmp;
                break;
        }
        j++;

        if (j == 3)
        {
            mix(a,b,c);
            j = 0;
        }
    }

    for (i=0;i<pmd->replace_size;i+=4)
    {
        tmp = 0;
        k = pmd->replace_size - i;
        if (k > 4)
            k=4;
       
        for (l=0;l<k;l++)
        {
            tmp |= *(pmd->replace_buf + i + l) << l*8;
        }

        switch (j)
        {
            case 0:
                a += tmp;
                break;
            case 1:
                b += tmp;
                break;
            case 2:
                c += tmp;
                break;
        }
        j++;

        if (j == 3)
        {
            mix(a,b,c);
            j = 0;
        }
    }

    if (j != 0)
    {
        mix(a,b,c);
    }

    if (pmd->uri_buffer)
    {
        a += RULE_OPTION_TYPE_CONTENT_URI;
    }
    else
    {
        a += RULE_OPTION_TYPE_CONTENT;
    }
    b+= pmd->flags;

    final(a,b,c); 

    return c;
}

int PatternMatchCompare(void *l, void *r)
{
    PatternMatchData *left = (PatternMatchData *)l;
    PatternMatchData *right = (PatternMatchData *)r;
    unsigned int i;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if (left->buffer_func != right->buffer_func)
        return DETECTION_OPTION_NOT_EQUAL;

    /* Sizes will be most different, check that first */
    if ((left->pattern_size != right->pattern_size) ||
        (left->replace_size != right->replace_size) ||
        (left->nocase != right->nocase))
        return DETECTION_OPTION_NOT_EQUAL;

    /* Next compare the patterns for uniqueness */
    if (left->pattern_size)
    {
        if (left->nocase)
        {
            /* If nocase is set, do case insensitive compare on pattern */
            for (i=0;i<left->pattern_size;i++)
            {
                if (toupper(left->pattern_buf[i]) != toupper(right->pattern_buf[i]))
                {
                    return DETECTION_OPTION_NOT_EQUAL;
                }
            }
        }
        else
        {
            /* If nocase is not set, do case sensitive compare on pattern */
            if (memcmp(left->pattern_buf, right->pattern_buf, left->pattern_size) != 0)
            {
                return DETECTION_OPTION_NOT_EQUAL;
            }
        }
    }

    /* Check the replace pattern if exists */
    if (left->replace_size)
    {
        if (memcmp(left->replace_buf, right->replace_buf, left->replace_size) != 0)
        {
            return DETECTION_OPTION_NOT_EQUAL;
        }
    }

    /* Now check the rest of the options */
    if ((left->exception_flag == right->exception_flag) &&
        (left->offset == right->offset) &&
        (left->depth == right->depth) &&
        (left->distance == right->distance) &&
        (left->within == right->within) &&
        (left->rawbytes == right->rawbytes) &&
        (left->use_doe == right->use_doe) &&
        (left->uri_buffer == right->uri_buffer) &&
        (left->search == right->search) &&
        (left->pattern_max_jump_size == right->pattern_max_jump_size) &&
        (left->flags == right->flags))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}

void FinalizeContentUniqueness(OptTreeNode *otn)
{
    OptFpList *opt_fp = otn->opt_func;
    option_type_t option_type;
    PatternMatchData *pmd;
    void *pmd_dup;

    while (opt_fp)
    {
        if ((opt_fp->OptTestFunc == CheckANDPatternMatch) ||
            (opt_fp->OptTestFunc == CheckUriPatternMatch))
        {
            pmd = (PatternMatchData *)opt_fp->context;
            if (opt_fp->OptTestFunc == CheckANDPatternMatch)
                option_type = RULE_OPTION_TYPE_CONTENT;
            else
                option_type = RULE_OPTION_TYPE_CONTENT_URI;

            if (add_detection_option(option_type, (void *)pmd, &pmd_dup) == DETECTION_OPTION_EQUAL)
            {
#if 0
                PatternMatchData *pmd_dup_ptr = (PatternMatchData *)pmd_dup;
                LogMessage("Duplicate %sContent:\n"
                    "%d %d %d %d %d %d %d %d %d %d\n"
                    "%d %d %d %d %d %d %d %d %d %d\n",
                    (opt_fp->OptTestFunc == CheckANDPatternMatch) ? "" : "Uri",
                    pmd->exception_flag,
                    pmd->offset,
                    pmd->depth,
                    pmd->distance,
                    pmd->within,
                    pmd->rawbytes,
                    pmd->nocase,
                    pmd->use_doe,
                    pmd->uri_buffer,
                    pmd->pattern_max_jump_size,
                    pmd_dup_ptr->exception_flag,
                    pmd_dup_ptr->offset,
                    pmd_dup_ptr->depth,
                    pmd_dup_ptr->distance,
                    pmd_dup_ptr->within,
                    pmd_dup_ptr->rawbytes,
                    pmd_dup_ptr->nocase,
                    pmd_dup_ptr->use_doe,
                    pmd_dup_ptr->uri_buffer,
                    pmd_dup_ptr->pattern_max_jump_size);
#endif
/*
                for (i=0;i<pmd->pattern_size;i++)
                {
                    LogMessage("0x%x 0x%x", pmd->pattern_buf[i], pmd_dup_ptr->pattern_buf[i]);
                }
                LogMessage("\n");
                for (i=0;i<pmd->replace_size;i++)
                {
                    LogMessage("0x%x 0x%x", pmd->replace_buf[i], pmd_dup_ptr->replace_buf[i]);
                }
                LogMessage("\n");
                LogMessage("\n");
*/
                if (pmd->buffer_func == CHECK_AND_PATTERN_MATCH)
                {
                    if (pmd == otn->ds_list[PLUGIN_PATTERN_MATCH])
                    {
                        otn->ds_list[PLUGIN_PATTERN_MATCH] = pmd_dup;
                    }
                }
                else if (pmd->buffer_func == CHECK_URI_PATTERN_MATCH)
                {
                    if (pmd == otn->ds_list[PLUGIN_PATTERN_MATCH_URI])
                    {
                        otn->ds_list[PLUGIN_PATTERN_MATCH_URI] = pmd_dup;
                    }
                }

                PatternMatchFree(pmd);

                opt_fp->context = pmd_dup;
            }
            else
            {
#if 0
                LogMessage("Unique %sContent\n",
                    (opt_fp->OptTestFunc == CheckANDPatternMatch) ? "" : "Uri");
#endif
            }
        }

        opt_fp = opt_fp->next;
    }

    return;
}

void PatternMatchDuplicatePmd(void *src, PatternMatchData *pmd_dup)
{
    /* Oh, C++ where r u?  can't we have a friggin' copy constructor? */
    PatternMatchData *pmd_src = (PatternMatchData *)src;
    if (!pmd_src || !pmd_dup)
        return;

    pmd_dup->exception_flag = pmd_src->exception_flag;
    pmd_dup->offset = pmd_src->offset;
    pmd_dup->depth = pmd_src->depth;
    pmd_dup->distance = pmd_src->distance;
    pmd_dup->within = pmd_src->within;
    pmd_dup->rawbytes = pmd_src->rawbytes;
    pmd_dup->nocase = pmd_src->nocase;
    pmd_dup->use_doe = pmd_src->use_doe;
    pmd_dup->uri_buffer = pmd_src->uri_buffer;
    pmd_dup->buffer_func = pmd_src->buffer_func;
    pmd_dup->pattern_size = pmd_src->pattern_size;
    pmd_dup->replace_size = pmd_src->replace_size;
    pmd_dup->replace_buf = pmd_src->replace_buf;
    pmd_dup->pattern_buf = pmd_src->pattern_buf;
    pmd_dup->search = pmd_src->search;
    pmd_dup->skip_stride = pmd_src->skip_stride;
    pmd_dup->shift_stride = pmd_src->shift_stride;
    pmd_dup->pattern_max_jump_size = pmd_src->pattern_max_jump_size;
    pmd_dup->flags = pmd_src->flags;

    pmd_dup->last_check.ts.tv_sec = pmd_src->last_check.ts.tv_sec;
    pmd_dup->last_check.ts.tv_usec = pmd_src->last_check.ts.tv_usec;
    pmd_dup->last_check.packet_number = pmd_src->last_check.packet_number;
    pmd_dup->last_check.rebuild_flag = pmd_src->last_check.rebuild_flag;

    pmd_dup->next = NULL;
    pmd_dup->fpl = NULL;

    Replace_ResetOffset(pmd_dup);
}

int PatternMatchAdjustRelativeOffsets(PatternMatchData *pmd, const uint8_t *orig_doe_ptr, const uint8_t *start_doe_ptr, const uint8_t *dp)
{
    int retval = 1; /* return 1 if still valid */

    if (orig_doe_ptr)
    {
        if (((pmd->distance != 0) && ((int)(start_doe_ptr - orig_doe_ptr) > pmd->distance)) ||
            ((pmd->offset != 0) && ((int)(start_doe_ptr - orig_doe_ptr) > pmd->offset)))
        {
            /* This was relative to a previously found pattern.
             * No space left to search, we're done */
            retval = 0;
        }

        if (((pmd->within != 0) && ((int)(start_doe_ptr - orig_doe_ptr + pmd->pattern_size) > pmd->within)) ||
            ((pmd->depth != 0) && ((int)(start_doe_ptr - orig_doe_ptr + pmd->pattern_size) > pmd->depth)))
        {
            /* This was within to a previously found pattern.
             * No space left to search, we're done */
            retval = 0;
        }
    }
    else
    {
        if (((pmd->distance != 0) && (start_doe_ptr - dp > pmd->distance)) ||
            ((pmd->offset != 0) && (start_doe_ptr - dp > pmd->offset)))
        {
            /* This was relative to a beginning of packet.
             * No space left to search, we're done */
            retval = 0;
        }

        if (((pmd->within != 0) && ((int)(start_doe_ptr - dp + pmd->pattern_size) > pmd->within)) ||
            ((pmd->depth != 0) && ((int)(start_doe_ptr - dp + pmd->pattern_size) > pmd->depth)))
        {
            /* This was within to a previously found pattern.
             * No space left to search, we're done */
            retval = 0;
        }
    }
    return retval;
}


void SetupPatternMatch(void)
{
    RegisterRuleOption("content", PayloadSearchInit, NULL, OPT_TYPE_DETECTION);
    //RegisterRuleOption("content-list", PayloadSearchListInit, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("offset", PayloadSearchOffset, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("depth", PayloadSearchDepth, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("nocase", PayloadSearchNocase, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("rawbytes", PayloadSearchRawbytes, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("uricontent", PayloadSearchUri, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("http_client_body", PayloadSearchHttpBody, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("http_uri", PayloadSearchHttpUri, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("http_header", PayloadSearchHttpHeader, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("http_method", PayloadSearchHttpMethod, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("http_cookie", PayloadSearchHttpCookie, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("fast_pattern", PayloadSearchFastPattern, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("distance", PayloadSearchDistance, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("within", PayloadSearchWithin, NULL, OPT_TYPE_DETECTION);
    RegisterRuleOption("replace", PayloadReplaceInit, NULL, OPT_TYPE_DETECTION);

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("content", &contentPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("uricontent", &uricontentPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "Plugin: PatternMatch Initialized!\n"););
}

static INLINE int computeDepth(int dlen, PatternMatchData * pmd) 
{
    /* do some tests to make sure we stay in bounds */
    if((pmd->depth + pmd->offset) > dlen)
    {
        /* we want to check only depth bytes anyway */
        int sub_depth = dlen - pmd->offset; 

        if((sub_depth > 0) && (sub_depth >= (int)pmd->pattern_size))
        {
            return  sub_depth;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                        "Pattern Match failed -- sub_depth: %d < "
                        "(int)pmd->pattern_size: %d!\n",
                        sub_depth, (int)pmd->pattern_size););

            return -1;
        }
    }
    else
    {      
        if(pmd->depth && (dlen - pmd->offset > pmd->depth))
        {
            return pmd->depth;
        }
        else
        {
            return dlen - pmd->offset;
        }
    }
}

/*
 * Figure out how deep the into the packet from the base_ptr we can go
 *
 * base_ptr = the offset into the payload relative to the last match plus the offset
 *            contained within the current pmd
 *
 * dlen = amount of data in the packet from the base_ptr to the end of the packet
 *
 * pmd = the patterm match data struct for this test
 */
static INLINE int computeWithin(int dlen, PatternMatchData *pmd)
{
    /* do we want to check more bytes than there are in the buffer? */
    if(pmd->within > dlen)
    {
        /* should we just return -1 here since the data might actually be within 
         * the stream but not the current packet's payload?
         */
        
        /* if the buffer size is greater than the size of the pattern to match */
        if(dlen >= (int)pmd->pattern_size)
        {
            /* return the size of the buffer */
            return dlen;
        }
        else
        {
            /* failed, pattern size is greater than number of bytes in the buffer */
            return -1;
        }
    }

    /* the within vaule is in range of the number of buffer bytes */
    return pmd->within;
}

#if 0
/* not in use - delete? */
static int uniSearchREG(char * data, int dlen, PatternMatchData * pmd)
{
    int depth = computeDepth(dlen, pmd);
    /* int distance_adjustment = 0;
     *  int depth_adjustment = 0;
     */
    int success = 0;

    if (depth < 0)
        return 0;

    /* XXX DESTROY ME */
    /*success =  mSearchREG(data + pmd->offset + distance_adjustment, 
            depth_adjustment!=0?depth_adjustment:depth, 
            pmd->pattern_buf, pmd->pattern_size, pmd->skip_stride, 
            pmd->shift_stride);*/

    return success;
}
#endif

/* 
 * case sensitive search
 *
 * data = ptr to buffer to search
 * dlen = distance to the back of the buffer being tested, validated 
 *        against offset + depth before function entry (not distance/within)
 * pmd = pointer to pattern match data struct
 */

static int uniSearch(const char *data, int dlen, PatternMatchData *pmd)
{
    return uniSearchReal(data, dlen, pmd, 0);
}

/* 
 * case insensitive search
 *
 * data = ptr to buffer to search
 * dlen = distance to the back of the buffer being tested, validated 
 *        against offset + depth before function entry (not distance/within)
 * pmd = pointer to pattern match data struct
 */
int uniSearchCI(const char *data, int dlen, PatternMatchData *pmd)
{
    return uniSearchReal(data, dlen, pmd, 1);
}


/* 
 * single search function. 
 *
 * data = ptr to buffer to search
 * dlen = distance to the back of the buffer being tested, validated 
 *        against offset + depth before function entry (not distance/within)
 * pmd = pointer to pattern match data struct
 * nocase = 0 means case sensitve, 1 means case insensitive
 *
 * return  1 for found
 * return  0 for not found
 * return -1 for error (search out of bounds)
 */       
static int uniSearchReal(const char *data, int dlen, PatternMatchData *pmd, int nocase)
{
    /* 
     * in theory computeDepth doesn't need to be called because the 
     * depth + offset adjustments have been made by the calling function
     */
    int depth = dlen;
    int old_depth = dlen;
    int success = 0;
    const char *start_ptr = data;
    const char *end_ptr = data + dlen;
    const char *base_ptr = start_ptr;
    
    DEBUG_WRAP(char *hexbuf;);


    if(pmd->use_doe != 1)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "NOT Using Doe Ptr\n"););
        doe_ptr = NULL; /* get rid of all our pattern match state */
    }

    /* check to see if we've got a stateful start point */
    if(doe_ptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "Using Doe Ptr\n"););

        base_ptr = (const char *)doe_ptr;
        depth = dlen - ((char *) doe_ptr - data);
    }
    else
    {
        base_ptr = start_ptr;
        depth = dlen;
    }

    /* if we're using a distance call */
    if(pmd->distance)
    {
        /* set the base pointer up for the distance */
        base_ptr += pmd->distance;
        depth -= pmd->distance;
    }
    else /* otherwise just use the offset (validated by calling function) */
    {
        base_ptr += pmd->offset;
        depth -= pmd->offset;
    }
    
    if(pmd->within != 0)
    {
        /* 
         * calculate the "real" depth based on the current base and available
         * number of bytes in the buffer
         *
         * this should account for the current base_ptr as it relates to 
         * the back of the buffer being tested
         */
        old_depth = depth;
        
        depth = computeWithin(depth, pmd);
        
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Changing Depth from %d to %d\n", old_depth, depth););
    }

    /* make sure we and in range */
    if(!inBounds((const uint8_t *)start_ptr, (const uint8_t *)end_ptr, (const uint8_t *)base_ptr))
    {
        
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "returning because base_ptr"
                                " is out of bounds start_ptr: %p end: %p base: %p\n",
                                start_ptr, end_ptr, base_ptr););
        return -1;
    }

    if(depth < 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "returning because depth is negative (%d)\n",
                                depth););
        return -1;        
    }

    if(depth > dlen)
    {
        /* if offsets are negative but somehow before the start of the
           packet, let's make sure that we get everything going
           straight */
        depth = dlen;
    }

    if((pmd->depth > 0) && (depth > pmd->depth))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "Setting new depth to %d from %d\n",
                                pmd->depth, depth););

        depth = pmd->depth;
    }
    
    /* make sure we end in range */
    if(!inBounds((const uint8_t *)start_ptr, (const uint8_t *)end_ptr, (const uint8_t *)(base_ptr + depth - 1)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "returning because base_ptr + depth - 1"
                                " is out of bounds start_ptr: %p end: %p base: %p\n",
                                start_ptr, end_ptr, base_ptr););
        return 0;
    }

#ifdef DEBUG
    assert(depth <= old_depth);

    DebugMessage(DEBUG_PATTERN_MATCH, "uniSearchReal:\n ");

    hexbuf = hex((u_char *)pmd->pattern_buf, pmd->pattern_size);
    DebugMessage(DEBUG_PATTERN_MATCH, "   p->data: %p\n   doe_ptr: %p\n   "
                 "base_ptr: %p\n   depth: %d\n   searching for: %s\n", 
                 data, doe_ptr, base_ptr, depth, hexbuf);
    free(hexbuf);
#endif /* DEBUG */
    
    if(nocase)
    {
        success = mSearchCI(base_ptr, depth, 
                            pmd->pattern_buf,
                            pmd->pattern_size,
                            pmd->skip_stride, 
                            pmd->shift_stride);
    }
    else
    {
        success = mSearch(base_ptr, depth,
                          pmd->pattern_buf,
                          pmd->pattern_size,
                          pmd->skip_stride,
                          pmd->shift_stride);
    }


#ifdef DEBUG
    if(success)
    {
        DebugMessage(DEBUG_PATTERN_MATCH, "matched, doe_ptr: %p (%d)\n", 
                     doe_ptr, ((char *)doe_ptr - data));
    }
#endif

    return success;
}


void make_precomp(PatternMatchData * idx)
{
    if(idx->skip_stride)
       free(idx->skip_stride);
    if(idx->shift_stride)
       free(idx->shift_stride);

    idx->skip_stride = make_skip(idx->pattern_buf, idx->pattern_size);

    idx->shift_stride = make_shift(idx->pattern_buf, idx->pattern_size);
}

#if 0
void PayloadSearchListInit(char *data, OptTreeNode * otn, int protocol)
{
    char *sptr;
    char *eptr;

    lastType = PLUGIN_PATTERN_MATCH_OR;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "In PayloadSearchListInit()\n"););

    /* get the path/file name from the data */
    while(isspace((int) *data))
        data++;

    /* grab everything between the starting " and the end one */
    sptr = index(data, '"');
    eptr = strrchr(data, '"');

    if(sptr != NULL && eptr != NULL)
    {
        /* increment past the first quote */
        sptr++;

        /* zero out the second one */
        *eptr = 0;
    }
    else
    {
        sptr = data;
    }

    /* read the content keywords from the list file */
    ParseContentListFile(sptr, otn, protocol);

    /* link the plugin function in to the current OTN */
    AddOptFuncToList(CheckORPatternMatch, otn);

    return;
}
#endif

static char *PayloadExtractParameter(char *data, int *result_len)
{
    char *quote_one = NULL, *quote_two = NULL;
    char *comma = NULL;

    quote_one = index(data, '"');
    if (quote_one)
    {
        quote_two = index(quote_one+1, '"');
        while ( quote_two && quote_two[-1] == '\\' )
            quote_two = index(quote_two+1, '"');
    }

    if (quote_one && quote_two)
    {
        comma = index(quote_two, ',');
    }
    else if (!quote_one)
    {
        comma = index(data, ',');
    }

    if (comma)
    {
        *result_len = comma - data;
        *comma = '\0';
    }
    else
    {
        *result_len = strlen(data);
    }

    return data;
}

void PayloadSearchInit(char *data, OptTreeNode * otn, int protocol)
{
    OptFpList *fpl;
    PatternMatchData *pmd;
    char *data_end;
    char *data_dup;
    char *opt_data;
    int opt_len = 0;
    char *next_opt;

    lastType = PLUGIN_PATTERN_MATCH;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "In PayloadSearchInit()\n"););

    /* whack a new node onto the list */
    pmd = NewNode(otn, PLUGIN_PATTERN_MATCH);

    if (!data)
    {
        FatalError("%s(%d) => No Content Pattern specified!\n",
            file_name, file_line);
    }

    data_dup = SnortStrdup(data);
    data_end = data_dup + strlen(data_dup);

    opt_data = PayloadExtractParameter(data_dup, &opt_len);

    /* set up the pattern buffer */
    ParsePattern(opt_data, otn, PLUGIN_PATTERN_MATCH);
    next_opt = opt_data + opt_len;

    /* link the plugin function in to the current OTN */
    fpl = AddOptFuncToList(CheckANDPatternMatch, otn);
    fpl->type = RULE_OPTION_TYPE_CONTENT;
    pmd->buffer_func = CHECK_AND_PATTERN_MATCH;

    fpl->context = pmd;
    pmd->fpl = fpl;

    // if content is followed by any comma separated options,
    // we have to parse them here.  content related options
    // separated by semicolons go straight to the callbacks.
    while (next_opt < data_end)
    {
        char **opts;        /* dbl ptr for mSplit call, holds rule tokens */
        int num_opts;       /* holds number of tokens found by mSplit */
        char* opt1;

        next_opt++;
        if (next_opt == data_end)
            break;

        opt_len = 0;
        opt_data = PayloadExtractParameter(next_opt, &opt_len);
        if (!opt_data)
            break;

        next_opt = opt_data + opt_len;

        opts = mSplit(opt_data, " \t", 2, &num_opts, 0);

        if (!opts)
            continue;
        opt1 = (num_opts == 2) ? opts[1] : NULL;

        if (!strcasecmp(opts[0], "offset"))
        {
            PayloadSearchOffset(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "depth"))
        {
            PayloadSearchDepth(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "nocase"))
        {
            PayloadSearchNocase(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "rawbytes"))
        {
            PayloadSearchRawbytes(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "http_uri"))
        {
            PayloadSearchHttpUri(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "http_client_body"))
        {
            PayloadSearchHttpBody(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "http_header"))
        {
            PayloadSearchHttpHeader(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "http_method"))
        {
            PayloadSearchHttpMethod(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "http_cookie"))
        {
            PayloadSearchHttpCookie(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "fast_pattern"))
        {
            PayloadSearchFastPattern(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "distance"))
        {
            PayloadSearchDistance(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "within"))
        {
            PayloadSearchWithin(opt1, otn, protocol);
        }
        else if (!strcasecmp(opts[0], "replace"))
        {
            PayloadReplaceInit(opt1, otn, protocol);
        }
        else
        {
            FatalError("%s(%d) => Invalid Content parameter specified!\n",
                file_name, file_line);
        }
        mSplitFree(&opts, num_opts);
    }

    free(data_dup);

    if(pmd->use_doe == 1)
        fpl->isRelative = 1;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "OTN function PatternMatch Added to rule!\n"););
}



void PayloadSearchUri(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData * pmd;
    OptFpList *fpl;

    if (!IsPreprocEnabled(PP_HTTPINSPECT))
    {
        FatalError("(%s)%d => Please enable the HTTP Inspect preprocessor "
            "before using the 'uricontent' modifier.\n", file_name, file_line);
    }

    lastType = PLUGIN_PATTERN_MATCH_URI;
    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "In PayloadSearchUri()\n"););

    /* whack a new node onto the list */
    pmd = NewNode(otn, PLUGIN_PATTERN_MATCH_URI);

    /* set up the pattern buffer */
    ParsePattern(data, otn, PLUGIN_PATTERN_MATCH_URI);

    pmd->uri_buffer |= HTTP_SEARCH_URI;

#ifdef PATTERN_FAST
    pmd->search = uniSearch;
    make_precomp(pmd);
#endif

    /* link the plugin function in to the current OTN */
    fpl = AddOptFuncToList(CheckUriPatternMatch, otn);

    fpl->type = RULE_OPTION_TYPE_CONTENT_URI;
    pmd->buffer_func = CHECK_URI_PATTERN_MATCH;

    fpl->context = pmd;
    pmd->fpl = fpl;

    if(pmd->use_doe == 1)
        fpl->isRelative = 1;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "OTN function PatternMatch Added to rule!\n"););
}


void PayloadSearchHttpBody(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx = NULL;
    PatternMatchData *uriidx = NULL, *previdx = NULL;

    if ( data )
    {
        FatalError("%s(%d) => 'http_client_body' does not take an argument\n",
            file_name, file_line);
    }
    if (!IsPreprocEnabled(PP_HTTPINSPECT))
    {
        FatalError("(%s)%d => Please enable the HTTP Inspect preprocessor "
            "before using the 'http_client_body' modifier.\n", file_name, file_line);
    }

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("(%s)%d => Please place \"content\" rules before"
           " http_client_body modifier.\n", file_name, file_line);
    }
    while(idx->next != NULL)
    {
        previdx = idx;
        idx = idx->next;
    }
    if( idx->replace_buf != NULL )
    {
        FatalError("(%s)%d => \"replace\" option is not supported in"
            " conjunction with 'http_client_body' modifier.\n", file_name, file_line);
    }

    if (lastType != PLUGIN_PATTERN_MATCH_URI)
    {
        /* Need to move this PatternMatchData structure to the
         * PLUGIN_PATTERN_MATCH_URI */
        
        /* Remove it from the tail of the old list */
        if (previdx)
        {
            previdx->next = idx->next;
        }
        else
        {
            otn->ds_list[lastType] = NULL;
        }

        if (idx)
        {
            idx->next = NULL;
        }

        uriidx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH_URI];

        if (uriidx)
        {
            /* There are some uri/post patterns in this rule already */
            while (uriidx->next != NULL)
            {
                uriidx = uriidx->next;
            }
            uriidx->next = idx;
        }
        else
        {
            /* This is the first uri/post patterns in this rule */
            otn->ds_list[PLUGIN_PATTERN_MATCH_URI] = idx;
        }
        lastType = PLUGIN_PATTERN_MATCH_URI;
        idx->fpl->OptTestFunc = CheckUriPatternMatch;
        idx->fpl->type = RULE_OPTION_TYPE_CONTENT_URI;
        idx->buffer_func = CHECK_URI_PATTERN_MATCH;
    }

    idx->uri_buffer |= HTTP_SEARCH_CLIENT_BODY;

    if (idx->rawbytes == 1)
    {
        FatalError("(%s)%d => Cannot use 'rawbytes' and 'http_client_body'"
            " as modifiers for the same \"content\".\n", file_name, file_line);
    }

    return;
}


void PayloadSearchHttpUri(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx = NULL;
    PatternMatchData *uriidx = NULL, *previdx = NULL;

    if ( data )
    {
        FatalError("%s(%d) => 'http_uri' does not take an argument\n",
            file_name, file_line);
    }
    if (!IsPreprocEnabled(PP_HTTPINSPECT))
    {
        FatalError("(%s)%d => Please enable the HTTP Inspect preprocessor "
            "before using the 'http_uri' modifier.\n", file_name, file_line);
    }

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("(%s)%d => Please place \"content\" rules before"
           " http_uri modifiers.\n", file_name, file_line);
    }
    while(idx->next != NULL)
    {
        previdx = idx;
        idx = idx->next;
    }
    if( idx->replace_buf != NULL )
    {
        FatalError("(%s)%d => \"replace\" option is not supported in"
            " conjunction with 'http_uri' modifiers.\n", file_name, file_line);
    }
 
    if (lastType != PLUGIN_PATTERN_MATCH_URI)
    {
        /* Need to move this PatternMatchData structure to the
         * PLUGIN_PATTERN_MATCH_URI */
        
        /* Remove it from the tail of the old list */
        if (previdx)
        {
            previdx->next = idx->next;
        }
        else
        {
            otn->ds_list[lastType] = NULL;
        }

        if (idx)
        {
            idx->next = NULL;
        }

        uriidx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH_URI];

        if (uriidx)
        {
            /* There are some uri/post patterns in this rule already */
            while (uriidx->next != NULL)
            {
                uriidx = uriidx->next;
            }
            uriidx->next = idx;
        }
        else
        {
            /* This is the first uri/post patterns in this rule */
            otn->ds_list[PLUGIN_PATTERN_MATCH_URI] = idx;
        }
        lastType = PLUGIN_PATTERN_MATCH_URI;
        idx->fpl->OptTestFunc = CheckUriPatternMatch;
        idx->fpl->type = RULE_OPTION_TYPE_CONTENT_URI;
        idx->buffer_func = CHECK_URI_PATTERN_MATCH;
    }

    idx->uri_buffer |= HTTP_SEARCH_URI;

    if (idx->rawbytes == 1)
    {
        FatalError("(%s)%d => Cannot use 'rawbytes' and 'http_uri'"
            " as modifiers for the same \"content\".\n", file_name, file_line);
    }

    return;
}

void PayloadSearchHttpHeader(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx = NULL;
    PatternMatchData *uriidx = NULL, *previdx = NULL;

    if ( data )
    {
        FatalError("%s(%d) => 'http_header' does not take an argument\n",
            file_name, file_line);
    }
    if (!IsPreprocEnabled(PP_HTTPINSPECT))
    {
        FatalError("(%s)%d => Please enable the HTTP Inspect preprocessor "
            "before using the 'http_header' modifier.\n", file_name, file_line);
    }

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("(%s)%d => Please place \"content\" rules before"
           " http_header modifiers.\n", file_name, file_line);
    }
    while(idx->next != NULL)
    {
        previdx = idx;
        idx = idx->next;
    }
    if( idx->replace_buf != NULL )
    {
        FatalError("(%s)%d => \"replace\" option is not supported in"
            " conjunction with 'http_header' modifiers.\n", file_name, file_line);
    }
  
    if (lastType != PLUGIN_PATTERN_MATCH_URI)
    {
        /* Need to move this PatternMatchData structure to the
         * PLUGIN_PATTERN_MATCH_URI */
        
        /* Remove it from the tail of the old list */
        if (previdx)
        {
            previdx->next = idx->next;
        }
        else
        {
            otn->ds_list[lastType] = NULL;
        }

        if (idx)
        {
            idx->next = NULL;
        }

        uriidx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH_URI];

        if (uriidx)
        {
            /* There are some uri/post patterns in this rule already */
            while (uriidx->next != NULL)
            {
                uriidx = uriidx->next;
            }
            uriidx->next = idx;
        }
        else
        {
            /* This is the first uri/post patterns in this rule */
            otn->ds_list[PLUGIN_PATTERN_MATCH_URI] = idx;
        }
        lastType = PLUGIN_PATTERN_MATCH_URI;
        idx->fpl->OptTestFunc = CheckUriPatternMatch;
        idx->fpl->type = RULE_OPTION_TYPE_CONTENT_URI;
        idx->buffer_func = CHECK_URI_PATTERN_MATCH;
    }

    idx->uri_buffer |= HTTP_SEARCH_HEADER;

    if (idx->rawbytes == 1)
    {
        FatalError("(%s)%d => Cannot use 'rawbytes' and 'http_header'"
            " as modifiers for the same \"content\".\n", file_name, file_line);
    }

    return;
}

void PayloadSearchHttpMethod(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx = NULL;
    PatternMatchData *uriidx = NULL, *previdx = NULL;

    if ( data )
    {
        FatalError("%s(%d) => 'http_method' does not take an argument\n",
            file_name, file_line);
    }
    if (!IsPreprocEnabled(PP_HTTPINSPECT))
    {
        FatalError("(%s)%d => Please enable the HTTP Inspect preprocessor "
            "before using the 'http_method' modifier.\n", file_name, file_line);
    }

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("(%s)%d => Please place \"content\" rules before"
           " http_method modifiers.\n", file_name, file_line);
    }
    while(idx->next != NULL)
    {
        previdx = idx;
        idx = idx->next;
    }
    if( idx->replace_buf != NULL )
    {
        FatalError("(%s)%d => \"replace\" option is not supported in"
            " conjunction with 'http_method' modifiers.\n", file_name, file_line);
    }
  
    if (lastType != PLUGIN_PATTERN_MATCH_URI)
    {
        /* Need to move this PatternMatchData structure to the
         * PLUGIN_PATTERN_MATCH_URI */
        
        /* Remove it from the tail of the old list */
        if (previdx)
        {
            previdx->next = idx->next;
        }
        else
        {
            otn->ds_list[lastType] = NULL;
        }

        if (idx)
        {
            idx->next = NULL;
        }

        uriidx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH_URI];

        if (uriidx)
        {
            /* There are some uri/post patterns in this rule already */
            while (uriidx->next != NULL)
            {
                uriidx = uriidx->next;
            }
            uriidx->next = idx;
        }
        else
        {
            /* This is the first uri/post patterns in this rule */
            otn->ds_list[PLUGIN_PATTERN_MATCH_URI] = idx;
        }
        lastType = PLUGIN_PATTERN_MATCH_URI;
        idx->fpl->OptTestFunc = CheckUriPatternMatch;
        idx->fpl->type = RULE_OPTION_TYPE_CONTENT_URI;
        idx->buffer_func = CHECK_URI_PATTERN_MATCH;
    }

    idx->uri_buffer |= HTTP_SEARCH_METHOD;

    if (idx->rawbytes == 1)
    {
        FatalError("(%s)%d => Cannot use 'rawbytes' and 'http_method'"
            " as modifiers for the same \"content\".\n", file_name, file_line);
    }

    return;
}

void PayloadSearchHttpCookie(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx = NULL;
    PatternMatchData *uriidx = NULL, *previdx = NULL;

    if ( data )
    {
        FatalError("%s(%d) => 'http_cookie' does not take an argument\n",
            file_name, file_line);
    }
    if (!IsPreprocEnabled(PP_HTTPINSPECT))
    {
        FatalError("(%s)%d => Please enable the HTTP Inspect preprocessor "
            "before using the 'http_cookie' modifier.\n", file_name, file_line);
    }

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("(%s)%d => Please place \"content\" rules before"
           " http_cookie modifiers.\n", file_name, file_line);
    }
    while(idx->next != NULL)
    {
        previdx = idx;
        idx = idx->next;
    }
    if( idx->replace_buf != NULL )
    {
        FatalError("(%s)%d => \"replace\" option is not supported in"
            " conjunction with 'http_cookie' modifiers.\n", file_name, file_line);
    }
 
    if (lastType != PLUGIN_PATTERN_MATCH_URI)
    {
        /* Need to move this PatternMatchData structure to the
         * PLUGIN_PATTERN_MATCH_URI */
        
        /* Remove it from the tail of the old list */
        if (previdx)
        {
            previdx->next = idx->next;
        }
        else
        {
            otn->ds_list[lastType] = NULL;
        }

        if (idx)
        {
            idx->next = NULL;
        }

        uriidx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH_URI];

        if (uriidx)
        {
            /* There are some uri/post patterns in this rule already */
            while (uriidx->next != NULL)
            {
                uriidx = uriidx->next;
            }
            uriidx->next = idx;
        }
        else
        {
            /* This is the first uri/post patterns in this rule */
            otn->ds_list[PLUGIN_PATTERN_MATCH_URI] = idx;
        }
        lastType = PLUGIN_PATTERN_MATCH_URI;
        idx->fpl->OptTestFunc = CheckUriPatternMatch;
        idx->fpl->type = RULE_OPTION_TYPE_CONTENT_URI;
        idx->buffer_func = CHECK_URI_PATTERN_MATCH;
    }

    idx->uri_buffer |= HTTP_SEARCH_COOKIE;

    if (idx->rawbytes == 1)
    {
        FatalError("(%s)%d => Cannot use 'rawbytes' and 'http_cookie'"
            " as modifiers for the same \"content\".\n", file_name, file_line);
    }

    if (idx->flags & CONTENT_FAST_PATTERN)
    {
        FatalError("Error %s(%d) => FastPattern cannot be set for \"content\" with "
            "http cookie buffer\n", file_name, file_line);
    }

    return;
}

static int32_t ParseInt (const char* data, const char* tag)
{
    int32_t value = 0;
    char* endptr = NULL;
    errno = 0;
    
    value = strtol(data, &endptr, 10);

    if ( *endptr )
    {
        FatalError("%s(%d) => Invalid '%s' format.\n", 
                file_name, file_line, tag);
    }
    if ( errno == ERANGE )
    {
        FatalError("%s(%d) => Range problem on '%s' value\n", 
                file_name, file_line, tag);
    }

    if ( value > 65535 || value < -65535 )
    {
        FatalError("%s(%d) => '%s' must in -65535:65535\n",
            tag, file_name, file_line);
    }
    return value;
}

void PayloadSearchOffset(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "In PayloadSearch()\n"););

    if ( !data )
    {
        FatalError("%s(%d) => Missing argument to 'offset' option\n",
            file_name, file_line);
    }
    idx = otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("%s(%d) => Please place \"content\" rules before "
                "depth, nocase or offset modifiers.\n", file_name, file_line);
    }

    while(idx->next != NULL)
        idx = idx->next;

    idx->offset = ParseInt(data, "offset");

    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Pattern offset = %d\n", 
                idx->offset););
}

void PayloadSearchDepth(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx;

    if ( !data )
    {
        FatalError("%s(%d) => Missing argument to 'depth' option\n",
            file_name, file_line);
    }
    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("%s(%d) => Please place \"content\" rules "
                "before depth, nocase or offset modifiers.\n", 
                file_name, file_line);
    }

    while(idx->next != NULL)
        idx = idx->next;

    idx->depth = ParseInt(data, "depth");

    /* check to make sure that this the depth allows this rule to fire */
    if(idx->depth != 0 && idx->depth < (int)idx->pattern_size)
    {
        FatalError("%s(%d) => The depth(%d) is less than the size of the content(%u)!\n",
                   file_name, file_line, idx->depth, idx->pattern_size);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern depth = %d\n", 
                idx->depth););
}

void PayloadSearchNocase(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx;
    int i;

    if ( data )
    {
        FatalError("%s(%d) => 'nocase' does not take an argument\n",
            file_name, file_line);
    }
    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("(%s)%d => Please place \"content\" rules before"
           " depth, nocase or offset modifiers.\n", file_name, file_line);
    }
    while(idx->next != NULL)
        idx = idx->next;

    i = idx->pattern_size;

    while(--i >= 0)
        idx->pattern_buf[i] = toupper((unsigned char) idx->pattern_buf[i]);

    idx->nocase = 1;

#ifdef PATTERN_FAST
    idx->search = setSearch;
#else
    idx->search = uniSearchCI;
    make_precomp(idx);
#endif


    return;
}

const char *format_uri_buffer_str(int uri_buffer, int search_buf, char *first_buf)
{
    if (uri_buffer & search_buf)
    {
        if (*first_buf == 1)
        {
            switch (search_buf)
            {
                case HTTP_SEARCH_URI:
                    return "http_uri";
                    break;
                case HTTP_SEARCH_CLIENT_BODY:
                    return "http_client_body";
                    break;
                case HTTP_SEARCH_HEADER:
                    return "http_header";
                    break;
                case HTTP_SEARCH_METHOD:
                    return "http_method";
                    break;
                case HTTP_SEARCH_COOKIE:
                    return "http_cookie";
                    break;
            }
            *first_buf = 0;
        }
        else
        {
            switch (search_buf)
            {
                case HTTP_SEARCH_URI:
                    return " | http_uri";
                    break;
                case HTTP_SEARCH_CLIENT_BODY:
                    return " | http_client_body";
                    break;
                case HTTP_SEARCH_HEADER:
                    return " | http_header";
                    break;
                case HTTP_SEARCH_METHOD:
                    return " | http_method";
                    break;
                case HTTP_SEARCH_COOKIE:
                    return " | http_cookie";
                    break;
            }
        }
    }
    return "";
}

void PayloadSearchRawbytes(char *data, OptTreeNode * otn, int protocol)
{
    char first_buf = 1;
    PatternMatchData *idx;

    if ( data )
    {
        FatalError("%s(%d) => 'rawbytes' does not take an argument\n",
            file_name, file_line);
    }
    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("Line %d => Please place \"content\" rules before"
                " rawbytes, depth, nocase or offset modifiers.\n", file_line);
    }
    while(idx->next != NULL)
        idx = idx->next;

    /* mark this as inspecting a raw pattern match rather than a
       decoded application buffer */
    idx->rawbytes = 1;    

    if (lastType == PLUGIN_PATTERN_MATCH_URI)
    {
        FatalError("(%s)%d => Cannot use 'rawbytes' and '%s%s%s%s%s' as modifiers for "
            "the same \"content\" nor use 'rawbytes' with \"uricontent\".\n",
            file_name, file_line,
            format_uri_buffer_str(idx->uri_buffer, HTTP_SEARCH_URI, &first_buf),
            format_uri_buffer_str(idx->uri_buffer, HTTP_SEARCH_CLIENT_BODY, &first_buf),
            format_uri_buffer_str(idx->uri_buffer, HTTP_SEARCH_HEADER, &first_buf),
            format_uri_buffer_str(idx->uri_buffer, HTTP_SEARCH_METHOD, &first_buf),
            format_uri_buffer_str(idx->uri_buffer, HTTP_SEARCH_COOKIE, &first_buf) );
    }

    return;
}

void PayloadSearchFastPattern(char *data, OptTreeNode *otn, int protocol)
{
    PatternMatchData *idx;
    PatternMatchData *last;
    int uri_buffers = 0;

    if ( data )
    {
        FatalError("%s(%d) => 'fast_pattern' does not take an argument\n",
            file_name, file_line);
    }
    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("Error %s(%d) => FastPattern without context, please place "
                "\"content\" keywords before fast_pattern modifiers\n", file_name,
                file_line);
    }

    while(idx->next != NULL)
        idx = idx->next;
    
    last = idx;

    idx = (PatternMatchData *) otn->ds_list[lastType];
    while(idx->next != NULL)
    {
        if (idx->flags & CONTENT_FAST_PATTERN)
        {
            if ((lastType == PLUGIN_PATTERN_MATCH) ||   /* regular content */
                ((idx->uri_buffer & ~HTTP_SEARCH_COOKIE) & uri_buffers)) /* or uri buffer is same */
            {
                FatalError("Error %s(%d) => FastPattern set for another \"content\" "
                    "within this rule\n", file_name, file_line);
            }
            uri_buffers |= idx->uri_buffer;
        }

        idx = idx->next;
    }

    if ((idx->uri_buffer & ~HTTP_SEARCH_COOKIE) & uri_buffers) /* uri buffer is same as earlier fast pattern */
    {
        FatalError("Error %s(%d) => FastPattern set for another \"content\" "
            "within this rule\n", file_name, file_line);
    }

    if ((lastType == PLUGIN_PATTERN_MATCH_URI) && (last->uri_buffer == HTTP_SEARCH_COOKIE))
    {
        FatalError("Error %s(%d) => FastPattern cannot be set for \"content\" with "
            "http cookie buffer\n", file_name, file_line);
    }

    if (idx->exception_flag)
    {
        FatalError("Error %s(%d) => FastPattern cannot be set for negated "
            "\"content\" searches\n", file_name, file_line);
    }

    idx->flags |= CONTENT_FAST_PATTERN;

    return;
}

void PayloadSearchDistance(char *data, OptTreeNode *otn, int protocol)
{
    PatternMatchData *idx;

    if ( !data )
    {
        FatalError("%s(%d) => Missing argument to 'distance' option\n",
            file_name, file_line);
    }
    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("Error %s(%d) => Distance without context, please place "
                "\"content\" keywords before distance modifiers\n", file_name,
                file_line);
    }

    while(idx->next != NULL)
        idx = idx->next;

    idx->distance = ParseInt(data, "distance");


    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern distance = %d\n", 
                idx->distance););


    /* Only do a relative search if this is a normal content match. */
    if((lastType == PLUGIN_PATTERN_MATCH) &&
       !SetUseDoePtr(otn))
    {
        FatalError("%s(%d) => Unable to initialize doe_ptr\n",
                   file_name, file_line);
    }

    if (idx->use_doe)
    {
        idx->fpl->isRelative = 1;
    }
}


void PayloadSearchWithin(char *data, OptTreeNode *otn, int protocol)
{
    PatternMatchData *idx;

    if ( !data )
    {
        FatalError("%s(%d) => Missing argument to 'within' option\n",
            file_name, file_line);
    }
    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("Error %s(%d) => Distance without context, please place "
                "\"content\" keywords before distance modifiers\n", file_name,
                file_line);
    }

    while(idx->next != NULL)
        idx = idx->next;

    idx->within = ParseInt(data, "within");

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern within = %d\n", 
                idx->within););

    /* Only do a relative search if this is a normal content match. */
    if((lastType == PLUGIN_PATTERN_MATCH) &&
       !SetUseDoePtr(otn))
    {
        FatalError("%s(%d) => Unable to initialize doe_ptr\n",
                   file_name, file_line);
    }

    if (idx->use_doe)
    {
        idx->fpl->isRelative = 1;
    }
}


PatternMatchData * NewNode(OptTreeNode * otn, int type)
{
    PatternMatchData *idx;

    idx = (PatternMatchData *) otn->ds_list[type];

    if(idx == NULL)
    {
        if((otn->ds_list[type] = 
                    (PatternMatchData *) calloc(sizeof(PatternMatchData), 
                                                sizeof(char))) == NULL)
        {
            FatalError("sp_pattern_match NewNode() calloc failed!\n");
        }
        
        return otn->ds_list[type];
    }
    else
    {
        idx = otn->ds_list[type];

        while(idx->next != NULL)
            idx = idx->next;

        if((idx->next = (PatternMatchData *) 
                    calloc(sizeof(PatternMatchData), sizeof(char))) == NULL)
        {
            FatalError("sp_pattern_match NewNode() calloc failed!\n");
        }

        return idx->next;
    }
}

/* This is an exported function that sets
 * PatternMatchData->use_doe so that when 
 *
 * distance, within, byte_jump, byte_test are used, they can make the
 * pattern matching functions "keep state" WRT the current packet.
 */
int SetUseDoePtr(OptTreeNode * otn)
{
    PatternMatchData *idx;

    idx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH];

    if(idx == NULL)
    {
        LogMessage("SetUseDoePtr: No pattern match data found\n");
        return 0;
    }
    else
    {
        /* Walk the linked list of content checks */
        while(idx->next != NULL)
        {
            idx = idx->next;
        }

        idx->use_doe = 1;
        return 1;
    }
}


/****************************************************************************
 *
 * Function: GetMaxJumpSize(char *, int)
 *
 * Purpose: Find the maximum number of characters we can jump ahead
 *          from the current offset when checking for this pattern again.
 *
 * Arguments: data => the pattern string
 *            data_len => length of pattern string
 *
 * Returns: int => number of bytes before pattern repeats within itself
 *
 ***************************************************************************/
static unsigned int GetMaxJumpSize(char *data, int data_len)
{
    int i, j;
    
    j = 0;
    for ( i = 1; i < data_len; i++ )
    {
        if ( data[j] != data[i] )
        {
            j = 0;
            continue;
        }
        if ( i == (data_len - 1) )
        {
            return (data_len - j - 1);
        }
        j++;
    }
    return data_len;
}


/****************************************************************************
 *
 * Function: ParsePattern(char *)
 *
 * Purpose: Process the application layer patterns and attach them to the
 *          appropriate rule.  My god this is ugly code.
 *
 * Arguments: rule => the pattern string
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParsePattern(char *rule, OptTreeNode * otn, int type)
{
    char tmp_buf[MAX_PATTERN_SIZE];

    /* got enough ptrs for you? */
    char *start_ptr;
    char *end_ptr;
    char *idx;
    char *dummy_idx;
    char *dummy_end;
    char *tmp;
    char hex_buf[3];
    u_int dummy_size = 0;
    int size;
    int hexmode = 0;
    int hexsize = 0;
    int pending = 0;
    int cnt = 0;
    int literal = 0;
    int exception_flag = 0;
    PatternMatchData *ds_idx;

    /* clear out the temp buffer */
    bzero(tmp_buf, MAX_PATTERN_SIZE);

    if(rule == NULL)
    {
        FatalError("%s(%d) => ParsePattern Got Null "
           "enclosed in quotation marks (\")!\n", 
           file_name, file_line);
    }

    while(isspace((int)*rule))
        rule++;

    if(*rule == '!')
    {
        exception_flag = 1;
        while(isspace((int)*++rule));
    }

    /* find the start of the data */
    start_ptr = index(rule, '"');

    if(start_ptr != rule)
    {
        FatalError("%s(%d) => Content data needs to be "
           "enclosed in quotation marks (\")!\n", 
           file_name, file_line);
    }

    /* move the start up from the beggining quotes */
    start_ptr++;

    /* find the end of the data */
    end_ptr = strrchr(start_ptr, '"');

    if(end_ptr == NULL)
    {
        FatalError("%s(%d) => Content data needs to be enclosed "
                   "in quotation marks (\")!\n", file_name, file_line);
    }

    /* Move the null termination up a bit more */
    *end_ptr = '\0';

    /* Is there anything other than whitespace after the trailing
     * double quote? */
    tmp = end_ptr + 1;
    while (*tmp != '\0' && isspace ((int)*tmp))
        tmp++;

    if (strlen (tmp) > 0)
    {
        FatalError("%s(%d) => Bad data (possibly due to missing semicolon) "
                   "after trailing double quote.",
                   file_name, file_line, end_ptr + 1);
    }

    /* how big is it?? */
    size = end_ptr - start_ptr;

    /* uh, this shouldn't happen */
    if(size <= 0)
    {
        FatalError("%s(%d) => Bad pattern length!\n", 
                   file_name, file_line);
    }
    /* set all the pointers to the appropriate places... */
    idx = start_ptr;

    /* set the indexes into the temp buffer */
    dummy_idx = tmp_buf;
    dummy_end = (dummy_idx + size);

    /* why is this buffer so small? */
    bzero(hex_buf, 3);
    memset(hex_buf, '0', 2);

    /* BEGIN BAD JUJU..... */
    while(idx < end_ptr)
    {
        if (dummy_size >= MAX_PATTERN_SIZE-1)
        {
            /* Have more data to parse and pattern is about to go beyond end of buffer */
            FatalError("ParsePattern() dummy "
                    "buffer overflow, make a smaller "
                    "pattern please! (Max size = %d)\n", MAX_PATTERN_SIZE-1);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "processing char: %c\n", *idx););
        switch(*idx)
        {
            case '|':
                DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Got bar... "););
                if(!literal)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "not in literal mode... "););
                    if(!hexmode)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Entering hexmode\n"););
                        hexmode = 1;
                    }
                    else
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Exiting hexmode\n"););

                        /*
                        **  Hexmode is not even.
                        */
                        if(!hexsize || hexsize % 2)
                        {
                            FatalError("%s(%d) => Content hexmode argument has invalid "
                                       "number of hex digits.  The argument '%s' must "
                                       "contain a full even byte string.\n",
                                       file_name, file_line, start_ptr);
                        }

                        hexmode = 0;
                        pending = 0;
                    }

                    if(hexmode)
                        hexsize = 0;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "literal set, Clearing\n"););
                    literal = 0;
                    tmp_buf[dummy_size] = start_ptr[cnt];
                    dummy_size++;
                }

                break;

            case '\\':
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Got literal char... "););

                if(!literal)
                {
                    /* Make sure the next char makes this a valid
                     * escape sequence.
                     */
                    if (idx [1] != '\0' && strchr ("\\\":;", idx [1]) == NULL)
                    {
                        FatalError("%s(%d) => bad escape sequence starting "
                                   "with \"%s\". ", file_name, file_line, idx);
                    }

                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Setting literal\n"););

                    literal = 1;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Clearing literal\n"););
                    tmp_buf[dummy_size] = start_ptr[cnt];
                    literal = 0;
                    dummy_size++;
                }

                break;
            case '"':
                if (!literal) {
                    FatalError("%s(%d) => Non-escaped "
                            " '\"' character!\n", file_name, file_line);
                }
                /* otherwise process the character as default */
            default:
                if(hexmode)
                {
                    if(isxdigit((int) *idx))
                    {
                        hexsize++;

                        if(!pending)
                        {
                            hex_buf[0] = *idx;
                            pending++;
                        }
                        else
                        {
                            hex_buf[1] = *idx;
                            pending--;

                            if(dummy_idx < dummy_end)
                            {                            
                                tmp_buf[dummy_size] = (u_char) 
                                    strtol(hex_buf, (char **) NULL, 16)&0xFF;

                                dummy_size++;
                                bzero(hex_buf, 3);
                                memset(hex_buf, '0', 2);
                            }
                            else
                            {
                                FatalError("ParsePattern() dummy "
                                        "buffer overflow, make a smaller "
                                        "pattern please! (Max size = %d)\n", MAX_PATTERN_SIZE-1);
                            }
                        }
                    }
                    else
                    {
                        if(*idx != ' ')
                        {
                            FatalError("%s(%d) => What is this "
                                    "\"%c\"(0x%X) doing in your binary "
                                    "buffer?  Valid hex values only please! "
                                    "(0x0 - 0xF) Position: %d\n",
                                    file_name, 
                                    file_line, (char) *idx, (char) *idx, cnt);
                        }
                    }
                }
                else
                {
                    if(*idx >= 0x1F && *idx <= 0x7e)
                    {
                        if(dummy_idx < dummy_end)
                        {
                            tmp_buf[dummy_size] = start_ptr[cnt];
                            dummy_size++;
                        }
                        else
                        {
                            FatalError("%s(%d)=> ParsePattern() "
                                    "dummy buffer overflow!\n", file_name, file_line);
                        }

                        if(literal)
                        {
                            literal = 0;
                        }
                    }
                    else
                    {
                        if(literal)
                        {
                            tmp_buf[dummy_size] = start_ptr[cnt];
                            dummy_size++;
                            DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Clearing literal\n"););
                            literal = 0;
                        }
                        else
                        {
                            FatalError("%s(%d)=> character value out "
                                    "of range, try a binary buffer\n", 
                                    file_name, file_line);
                        }
                    }
                }

                break;
        }

        dummy_idx++;
        idx++;
        cnt++;
    }
    /* ...END BAD JUJU */

    /* error prunning */

    if (literal) {
        FatalError("%s(%d)=> backslash escape is not "
           "completed\n", file_name, file_line);
    }
    if (hexmode) {
        FatalError("%s(%d)=> hexmode is not "
           "completed\n", file_name, file_line);
    }

    ds_idx = (PatternMatchData *) otn->ds_list[type];

    while(ds_idx->next != NULL)
        ds_idx = ds_idx->next;

    if((ds_idx->pattern_buf = (char *) calloc(dummy_size+1, sizeof(char))) 
       == NULL)
    {
        FatalError("ParsePattern() pattern_buf malloc failed!\n");
    }

    memcpy(ds_idx->pattern_buf, tmp_buf, dummy_size);

    ds_idx->pattern_size = dummy_size;
    ds_idx->search = uniSearch;
    
    make_precomp(ds_idx);
    ds_idx->exception_flag = exception_flag;

    ds_idx->pattern_max_jump_size = GetMaxJumpSize(ds_idx->pattern_buf, ds_idx->pattern_size);

    return;
}

#if 0
static int CheckORPatternMatch(Packet * p, struct _OptTreeNode * otn_idx, 
                   OptFpList * fp_list)
{
    int found = 0;
    int dsize;
    char *dp;
    

    PatternMatchData *idx;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "CheckPatternORMatch: "););
    
    idx = otn_idx->ds_list[PLUGIN_PATTERN_MATCH_OR];

    while(idx != NULL)
    {

        if((p->packet_flags & PKT_ALT_DECODE) && (idx->rawbytes == 0))
        {
            dsize = p->alt_dsize;
            dp = (char *) DecodeBuffer; /* decode.c */
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Using Alternative Decode buffer!\n"););
        }
        else
        {
            dsize = p->dsize;
            dp = (char *) p->data;
        }
        

        if(idx->offset > dsize)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                        "Initial offset larger than payload!\n"););

            goto sizetoosmall;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                        "testing pattern: %s\n", idx->pattern_buf););
            found = idx->search(dp, dsize, idx);

            if(!found)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                            "Pattern Match failed!\n"););
            }
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "Checking the results\n"););

        if(found)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern Match "
                    "successful: %s!\n", idx->pattern_buf););

            return fp_list->next->OptTestFunc(p, otn_idx, fp_list->next);

        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                        "Pattern match failed\n"););
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "Stepping to next content keyword\n"););

    sizetoosmall:

        idx = idx->next;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "No more keywords, exiting... \n"););

    return 0;
}
#endif

int CheckANDPatternMatch(void *option_data, Packet *p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    int found = 0;
    int dsize;
    char *dp;
    int origUseDoe;
    char *orig_doe;
    PatternMatchData *idx;
    PROFILE_VARS;

    PREPROC_PROFILE_START(contentPerfStats);

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "CheckPatternANDMatch: "););

    idx = (PatternMatchData *)option_data;
    origUseDoe = idx->use_doe;

    if((p->packet_flags & PKT_ALT_DECODE) && (idx->rawbytes == 0))
    {
        dsize = p->alt_dsize;
        dp = (char *) DecodeBuffer; /* decode.c */
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "Using Alternative Decode buffer!\n"););
    }
    else
    {
        dsize = p->dsize;
        dp = (char *) p->data;
    }

    /* this now takes care of all the special cases where we'd run
     * over the buffer */
    orig_doe = (char *)doe_ptr;
#ifndef NO_FOUND_ERROR
    found = idx->search(dp, dsize, idx);
    if ( found == -1 )
    {
        /* On error, mark as not found.  This is necessary to handle !content
           cases.  In that case, a search that is outside the given buffer will
           return 0, and !0 is 1, so a !content out of bounds will return true,
           which is not what we want.  */
        found = 0;
    }
    else
    {
        found = found ^ idx->exception_flag;
    }
#else
    /* Original code.  Does not account for searching outside the buffer. */
    found = (idx->search(dp, dsize, idx) ^ idx->exception_flag);
#endif

    if (found && idx->replace_buf)
    {
        //fix the packet buffer to have the new string
        detect_depth = (char *)doe_ptr - idx->pattern_size - dp;

        if (detect_depth < 0)
        {
            PREPROC_PROFILE_END(contentPerfStats);
            return rval;
        }
        Replace_StoreOffset(idx, detect_depth);
    }

    if (found)
    {
        rval = DETECTION_OPTION_MATCH;
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Pattern match found\n"););
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Pattern match failed\n"););
    }
#if 0
    while (found)
    {
        /* save where we last did the pattern match */
        tmp_doe = (char *)doe_ptr;

        /* save start doe as beginning of this pattern + non-repeating length*/
        start_doe = (char *)doe_ptr - idx->pattern_size + idx->pattern_max_jump_size;

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern Match successful!\n"););      
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Check next functions!\n"););
        /* PROFILING Don't count rest of options towards content */
        PREPROC_PROFILE_TMPEND(contentPerfStats);

        /* Try evaluating the rest of the rules chain */
        next_found= fp_list->next->OptTestFunc(p, otn_idx, fp_list->next);

        /* PROFILING Don't count rest of options towards content */
        PREPROC_PROFILE_TMPSTART(contentPerfStats);

        if(next_found != 0) 
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Next functions matched!\n"););

            /* We found a successful match, return that this rule has fired off */
            PREPROC_PROFILE_END(contentPerfStats);
            return next_found;
        }
        else if(tmp_doe != NULL)
        {
            int new_dsize = dsize-(start_doe-dp);

            /* if the next option isn't relative and it failed, we're done */
            if (fp_list->next->isRelative == 0)
            {
                PREPROC_PROFILE_END(contentPerfStats);
                return 0;
            }

            if(new_dsize <= 0 || new_dsize > dsize)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                        "The new dsize is less than <= 0 or > "
                                        "the the original dsize;returning "
                                        "false\n"););
                idx->use_doe = origUseDoe;
                PREPROC_PROFILE_END(contentPerfStats);
                return 0;
            }

            if (orig_doe)
            {
                /* relative to a previously found pattern */
                if (((idx->distance != 0) && (start_doe - orig_doe > idx->distance)) ||
                    ((idx->offset != 0) && (start_doe - orig_doe > idx->offset)) )
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                            "The next starting point to search "
                                            "from is beyond the original "
                                            "distance;returning false\n"););
                    idx->use_doe = origUseDoe;
                    PREPROC_PROFILE_END(contentPerfStats);
                    return 0;
                }

                if (((idx->within != 0) &&
                     (start_doe - orig_doe + idx->pattern_size > (unsigned int)idx->within)) ||
                    ((idx->depth != 0) &&
                     (start_doe - orig_doe + idx->pattern_size > (unsigned int)idx->depth)) )
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                            "The next starting point to search "
                                            "from is beyond the original "
                                            "within;returning false\n"););
                    idx->use_doe = origUseDoe;
                    PREPROC_PROFILE_END(contentPerfStats);
                    return 0;
                }
            }
            else
            {
                /* relative to beginning of data */
                if (((idx->distance != 0) && (start_doe - dp > idx->distance)) ||
                    ((idx->offset != 0) && (start_doe - dp > idx->offset)) )
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                            "The next starting point to search "
                                            "from is beyond the original "
                                            "distance;returning false\n"););
                    idx->use_doe = origUseDoe;
                    PREPROC_PROFILE_END(contentPerfStats);
                    return 0;
                }

                if (((idx->within != 0) &&
                     (start_doe - dp + idx->pattern_size > (unsigned int)idx->within)) ||
                    ((idx->depth != 0) &&
                     (start_doe - dp + idx->pattern_size > (unsigned int)idx->depth)) )
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                            "The next starting point to search "
                                            "from is beyond the original "
                                            "within;returning false\n"););
                    idx->use_doe = origUseDoe;
                    PREPROC_PROFILE_END(contentPerfStats);
                    return 0;
                }
            }

            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "At least ONE of the next functions does to match!\n"););      
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Start search again from a next point!\n"););

            /* Start the search again from the last set of contents, with a new depth and dsize */
            doe_ptr = (uint8_t *)start_doe;
            idx->use_doe = 1;
            found = (idx->search(start_doe, new_dsize,idx) ^ idx->exception_flag);
            
            /*
            **  If we haven't updated doe since we set it at the beginning
            **  of the loop, then that means we have already done the exact 
            **  same search previously, and have nothing else to gain from
            **  doing the same search again.
            */
            if(start_doe == (char *)doe_ptr)
            {
                idx->use_doe = origUseDoe;
                PREPROC_PROFILE_END(contentPerfStats);
                return 0;
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Returning 0 because tmp_doe is NULL\n"););
            
            idx->use_doe = origUseDoe;
            PREPROC_PROFILE_END(contentPerfStats);
            return 0;
        }
        
    }
#endif
    
    //idx->use_doe = origUseDoe;
    PREPROC_PROFILE_END(contentPerfStats);
    return rval;
}

/************************************************************************/
/************************************************************************/
/************************************************************************/

char *uri_buffer_name[] =
{
    "http_uri",
    "http_header",
    "http_client_body",
    "http_method",
    "http_cookie"
};

int PatternMatchUriBuffer(void *p)
{
    PatternMatchData *pmd = (PatternMatchData *)p;

    if (pmd->uri_buffer != 0)
    {
        /* return 1 if not just cookie */
        return pmd->uri_buffer != HTTP_SEARCH_COOKIE;
    }
    return 0; /* not set */
}

int CheckUriPatternMatch(void *option_data, Packet *p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    int found = 0;
    int i = 0;
    PatternMatchData *idx = (PatternMatchData *)option_data;
    PROFILE_VARS;

    if(p->uri_count <= 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_HTTP_DECODE,"CheckUriPatternMatch: no "
            "HTTP buffers set, retuning"););
        return rval;
    }

    PREPROC_PROFILE_START(uricontentPerfStats);
    for (i = 0; i<p->uri_count; i++)

    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "CheckUriPatternMatch: "););

        if (!UriBufs[i].uri || (UriBufs[i].length == 0))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_HTTP_DECODE,"Checking for %s pattern in "
                "buffer %d: HTTP buffer not set/zero length, returning",
                uri_buffer_name[i], i););
            continue;
        }

        if (!(idx->uri_buffer & (1 << i)))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_HTTP_DECODE,"Skipping %s pattern in "
                "buffer %d: buffer not part of inspection set",
                uri_buffer_name[i], i););
            continue;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_HTTP_DECODE,"Checking for %s pattern in "
                "buffer %d ",
                uri_buffer_name[i], i););

#ifdef DEBUG /* for variable declaration */
        {
            int j;
    
            DebugMessage(DEBUG_HTTP_DECODE,"Checking against HTTP data (%s): ", uri_buffer_name[idx->uri_buffer]);
            for(j=0; j<UriBufs[i].length; j++)
            {
                DebugMessage(DEBUG_HTTP_DECODE, "%c", UriBufs[i].uri[j]);
            }
            DebugMessage(DEBUG_HTTP_DECODE,"\n");
        }
#endif /* DEBUG */

        /* 
        * have to reset the doe_ptr for each new UriBuf 
        */
        doe_ptr = NULL;
    
        /* this now takes care of all the special cases where we'd run
         * over the buffer */
        found = (idx->search((const char *)UriBufs[i].uri, UriBufs[i].length, idx) ^ idx->exception_flag);
    
        if(found)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern Match successful!\n"););
            /* call the next function in the OTN */
            PREPROC_PROFILE_END(uricontentPerfStats);
            return DETECTION_OPTION_MATCH;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Pattern match failed\n"););
    }

    PREPROC_PROFILE_END(uricontentPerfStats);
    return rval;
}


#if 0
/****************************************************************************
 *
 * Function: ParseContentListFile(char *, OptTreeNode *, int protocol)
 *
 * Purpose:  Read the content_list file a line at a time, put the content of
 *           the line into buffer
 *
 * Arguments:otn => rule including the list
 *           file => list file filename
 *           protocol => protocol
 *
 * Returns: void function
 *
 ***************************************************************************/
static void ParseContentListFile(char *file, OptTreeNode * otn, int protocol)
{
    FILE *thefp;                /* file pointer for the content_list file */
    char buf[STD_BUF+1];        /* file read buffer */
    char rule_buf[STD_BUF+1];   /* content keyword buffer */
    int frazes_count;           /* frazes counter */


#ifdef DEBUG
    PatternMatchData *idx;
    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Opening content_list file: %s\n", file););
#endif /* DEBUG */
    /* open the list file */
    thefp = fopen(file, "r");
    if (thefp == NULL)
    {
        FatalError("Unable to open list file: %s\n", file);
    }

    /* clear the line and rule buffers */
    bzero((char *) buf, STD_BUF);
    bzero((char *) rule_buf, STD_BUF);
    frazes_count = 0;

    /* loop thru each list_file line and content to the rule */
    while((fgets(buf, STD_BUF-2, thefp)) != NULL)
    {
        /* inc the line counter */
        list_file_line++;

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Got line %d: %s", 
                list_file_line, buf););

        /* if it's not a comment or a <CR>, send it to the parser */
        if((buf[0] != '#') && (buf[0] != 0x0a) && (buf[0] != ';'))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "Adding content keyword: %s", buf););

            frazes_count++;
            strip(buf);

            NewNode(otn, PLUGIN_PATTERN_MATCH_OR);

            /* check and add content keyword */
            ParsePattern(buf, otn, PLUGIN_PATTERN_MATCH_OR);

            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                        "Content keyword %s\" added!\n", buf););
        }
    }
#ifdef DEBUG
    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "%d frazes read...\n", frazes_count););
    idx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH_OR];
    
    if(idx == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "No patterns loaded\n"););
    }
    else
    {
        while(idx != NULL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern = %s\n", 
                    idx->pattern_buf););
            idx = idx->next;
        }
    }
#endif /* DEBUG */
    
    fclose(thefp);

    return;
}
#endif

