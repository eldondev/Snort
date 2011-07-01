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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "bounds.h"
#include "checksum.h"
#include "debug.h"
#include "decode.h"
#include "inline.h"
#include "parser.h"
#include "sp_replace.h"
#include "snort.h"

//#define REPLACE_TEST
#define MAX_PATTERN_SIZE 2048
extern int lastType;

static PatternMatchData* Replace_Parse(char*, OptTreeNode*);
static void Replace_UpdateIP4Checksums(Packet*);
#ifdef SUP_IP6
static void Replace_UpdateIP6Checksums(Packet*);
#endif

void PayloadReplaceInit(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx;
    PatternMatchData *test_idx;

#ifndef REPLACE_TEST
    if(!ScInlineMode())
        return;
#endif
    if ( lastType ==  PLUGIN_PATTERN_MATCH_URI )
    {
        FatalError("%s(%d) => \"replace\" option is not supported "
                "with uricontent, nor in conjunction with http_uri, " 
                "http_header, http_method http_cookie or "
                "http_client_body modifiers.\n",
                file_name, file_line);
    }
    idx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH];

    if(idx == NULL)
    {
        FatalError("%s(%d) => Please place \"content\" rules "
                   "before depth, nocase, replace or offset modifiers.\n",
                   file_name, file_line);
    }

    test_idx = Replace_Parse(data, otn);

    if (test_idx && test_idx->pattern_size != test_idx->replace_size)
    {
        FatalError("%s(%d) => The length of the replacement "
                   "string must be the same length as the content string.\n",
                   file_name, file_line);
    }
}

static PatternMatchData * Replace_Parse(char *rule, OptTreeNode * otn)
{
    char tmp_buf[MAX_PATTERN_SIZE];

    /* got enough ptrs for you? */
    char *start_ptr;
    char *end_ptr;
    char *idx;
    const char *dummy_idx;
    const char *dummy_end;
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
    int ret;

    if ( !rule )
    {
        FatalError("%s(%d) => missing argument to 'replace' option\n",
            file_name, file_line);
    }
    /* clear out the temp buffer */
    bzero(tmp_buf, MAX_PATTERN_SIZE);

    while(isspace((int)*rule))
        rule++;

    if(*rule == '!')
    {
        exception_flag = 1;
    }

    /* find the start of the data */
    start_ptr = index(rule, '"');

    if(start_ptr == NULL)
    {
        FatalError("%s(%d) => Replace data needs to be "
                   "enclosed in quotation marks (\")!\n",
                   file_name, file_line);
    }

    /* move the start up from the beggining quotes */
    start_ptr++;

    /* find the end of the data */
    end_ptr = strrchr(start_ptr, '"');

    if(end_ptr == NULL)
    {
        FatalError("%s(%d) => Replace data needs to be enclosed "
                   "in quotation marks (\")!\n", file_name, file_line);
    }

    /* set the end to be NULL */
    *end_ptr = '\0';

    /* how big is it?? */
    size = end_ptr - start_ptr;

    /* uh, this shouldn't happen */
    if(size <= 0)
    {
        FatalError("%s(%d) => Replace data has bad pattern length!\n",
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
            FatalError("%s(%d) => Replace buffer overflow, make a "
                    "smaller pattern please! (Max size = %d)\n",
                    file_name, file_line, MAX_PATTERN_SIZE-1);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "processing char: %c\n", *idx););

        switch(*idx)
        {
            case '|':
            
                DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Got bar... "););
        
                if(!literal)
                {
            
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER,
                        "not in literal mode... "););
            
                    if(!hexmode)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                        "Entering hexmode\n"););

                        hexmode = 1;
                    }
                    else
                    {
                
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                        "Exiting hexmode\n"););
            
                        hexmode = 0;
                        pending = 0;
                    }

                    if(hexmode)
                        hexsize = 0;
                }
                else
                {

                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                        "literal set, Clearing\n"););

                    literal = 0;
                    tmp_buf[dummy_size] = start_ptr[cnt];
                    dummy_size++;
                }

                break;

            case '\\':
        
                DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Got literal char... "););

                if(!literal)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                        "Setting literal\n"););
            
                    literal = 1;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                        "Clearing literal\n"););
            
                    tmp_buf[dummy_size] = start_ptr[cnt];
                    literal = 0;
                    dummy_size++;
                }
                break;

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
                                FatalError("%s(%d) => Replace buffer overflow, make a "
                                           "smaller pattern please! (Max size = %d)\n",
                                           file_name, file_line, MAX_PATTERN_SIZE-1);
                            }
                        }
                    }
                    else
                    {
                        if(*idx != ' ')
                        {
                            FatalError("%s(%d) => Replace found \"%c\"(0x%X) in "
                                       "your binary buffer.  Valid hex values only "
                                       "please! (0x0 -0xF) Position: %d\n",
                                       file_name, file_line, (char) *idx, (char) *idx, cnt);
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
                            FatalError("%s(%d) => Replace buffer overflow!\n",
                                       file_name, file_line);
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
                
                            DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                            "Clearing literal\n"););
                
                            literal = 0;
                        }
                        else
                        {
                            FatalError("%s(%d) => Replace found character value out of "
                                       "range, only hex characters allowed in binary "
                                       "content buffers\n",
                                       file_name, file_line);
                        }
                    }
                }

                break;

        } /* end switch */

        dummy_idx++;
        idx++;
        cnt++;
    }
    /* ...END BAD JUJU */

    /* error pruning */

    if (literal) {
        FatalError("%s(%d) => Replace backslash escape is not completed\n",
            file_name, file_line);
    }
    if (hexmode) {
        FatalError("%s(%d) => Replace hexmode is not completed\n",
            file_name, file_line);
    }
    ds_idx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH];

    while(ds_idx->next != NULL)
        ds_idx = ds_idx->next;

    if((ds_idx->replace_buf = (char *) calloc(dummy_size+1,
                                                  sizeof(char))) == NULL)
    {
        FatalError("%s(%d) => Replace pattern_buf malloc failed!\n",
            file_name, file_line);
    }

    ret = SafeMemcpy(ds_idx->replace_buf, tmp_buf, dummy_size, 
                     ds_idx->replace_buf, (ds_idx->replace_buf+dummy_size));

    if (ret == SAFEMEM_ERROR)
    {
        FatalError("%s(%d) => Replace SafeMemcpy failed\n", file_name, file_line);
    }

    ds_idx->replace_size = dummy_size;

    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                "ds_idx (%p) replace_size(%d) replace_buf(%s)\n", ds_idx,
                ds_idx->replace_size, ds_idx->replace_buf););

    return ds_idx;
}

typedef struct {
    const char* data;
    int size;
    int depth;
} Replacement;

#define MAX_REPLACEMENTS 32
static Replacement rpl[MAX_REPLACEMENTS];
static int num_rpl = 0;

void Replace_ResetQueue(void)
{
    num_rpl = 0;
}

void Replace_QueueChange(PatternMatchData* pmd)
{
    Replacement* r;

    if ( num_rpl == MAX_REPLACEMENTS )
        return;

    r = rpl + num_rpl++;

    r->data = pmd->replace_buf;
    r->size = pmd->replace_size;
    r->depth = pmd->replace_depth;
}

static INLINE void Replace_ApplyChange(Packet *p, Replacement* r)
{
    int err = SafeMemcpy(
        (void *)(p->data + r->depth), r->data,
        r->size, p->data, (p->data + p->dsize) );

    if ( err == SAFEMEM_ERROR )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "Replace_Apply() => SafeMemcpy() failed\n"););
        return;
    }

#ifdef REPLACE_TEST
    printf("replaced: %s\n", r->data);
#endif
}

void Replace_ModifyPacket(Packet *p)
{
    int n;

    if ( num_rpl == 0 )
        return;

    for ( n = 0; n < num_rpl; n++ )
    {
        Replace_ApplyChange(p, rpl+n);
    }
    num_rpl = 0;

    if(IS_IP4(p)) 
    {
        Replace_UpdateIP4Checksums(p);
    }
#ifdef SUP_IP6
    else
    {
        Replace_UpdateIP6Checksums(p);
    }
#endif

#ifdef GIDS
    InlineReplace();
#endif
}

static void Replace_UpdateIP4Checksums(Packet* p)
{
    struct pseudoheader
    {
        uint32_t sip, dip;
        uint8_t zero;
        uint8_t protocol;
        uint16_t len;
    };

    struct pseudoheader ph;
    unsigned int ip_len;
    unsigned int hlen;

#ifdef SUP_IP6
    sfip_t *tmp;

    p->ip4h->ip_csum=0;
    hlen = GET_IPH_HLEN(p) << 2;
    ip_len=ntohs(p->ip4h->ip_len);
    ip_len -= hlen;
    p->ip4h->ip_csum = in_chksum_ip((u_short *)p->iph, hlen);

    tmp = GET_SRC_IP(p);
    ph.sip = tmp->ip32[0];
    tmp = GET_DST_IP(p);
    ph.dip = tmp->ip32[0];
#else
    /* calculate new checksum */
    ((IPHdr *)p->iph)->ip_csum=0;
    hlen = IP_HLEN(p->iph) << 2;
    ip_len=ntohs(p->iph->ip_len);
    ip_len -= hlen;
    ((IPHdr *)p->iph)->ip_csum = in_chksum_ip((u_short *)p->iph, hlen);
    ph.sip = (uint32_t)(p->iph->ip_src.s_addr);
    ph.dip = (uint32_t)(p->iph->ip_dst.s_addr);
#endif

    if (p->tcph)
    {
        ((TCPHdr *)p->tcph)->th_sum = 0;
        ph.zero = 0;
        ph.protocol = GET_IPH_PROTO(p);
        ph.len = htons((u_short)ip_len);
        ((TCPHdr *)p->tcph)->th_sum =
            in_chksum_tcp((u_short *)&ph, (u_short *)(p->tcph), ip_len);
    }
    else if (p->udph)
    {
        ((UDPHdr *)p->udph)->uh_chk = 0;
        ph.zero = 0;
        ph.protocol = GET_IPH_PROTO(p);
        ph.len = htons((u_short)ip_len);
        ((UDPHdr *)p->udph)->uh_chk =
            in_chksum_udp((u_short *)&ph, (u_short *)(p->udph), ip_len);
    }
    else if (p->icmph)
    {
        ((ICMPHdr *)p->icmph)->csum = 0;
        ph.zero = 0;
        ph.protocol = GET_IPH_PROTO(p);
        ph.len = htons((u_short)ip_len);
        ((ICMPHdr *)p->icmph)->csum =
            in_chksum_icmp((uint16_t *)(p->icmph), ip_len);
    }
}

#ifdef SUP_IP6
static void Replace_UpdateIP6Checksums(Packet* p)
{
    struct pseudoheader6
    {
        struct in6_addr sip, dip;
        uint8_t zero;
        uint8_t protocol;
        uint16_t len;
    };
    struct pseudoheader6 ph6;
    unsigned int ip_len;
    unsigned int hlen;
    sfip_t *tmp;

    hlen = GET_IPH_HLEN(p) << 2;
    ip_len=ntohs(p->ip6h->len);
    ip_len -= hlen;

    tmp = GET_SRC_IP(p);
    memcpy(&ph6.sip, tmp->ip8, sizeof(struct in6_addr));
    tmp = GET_DST_IP(p);
    memcpy(&ph6.dip, tmp->ip8, sizeof(struct in6_addr));

    ph6.zero = 0;
    ph6.protocol = GET_IPH_PROTO(p);
    ph6.len = htons((u_short)ip_len);

    if (p->tcph)
    {
        ph6.protocol = IPPROTO_TCP;
        ((TCPHdr *)p->tcph)->th_sum = 0;
        ((TCPHdr *)p->tcph)->th_sum =
            in_chksum_tcp6((u_short *)&ph6, (u_short *)(p->tcph), ip_len);
    }
    else if (p->udph)
    {
        ph6.protocol = IPPROTO_UDP;
        ((UDPHdr *)p->udph)->uh_chk = 0;
        ((UDPHdr *)p->udph)->uh_chk =
            in_chksum_udp6((u_short *)&ph6, (u_short *)(p->udph), ip_len);
    }
    else if (p->icmph)
    {
        ph6.protocol = IPPROTO_ICMP;
        ((ICMPHdr *)p->icmph)->csum = 0;
        ((ICMPHdr *)p->icmph)->csum =
            in_chksum_icmp6((uint16_t *)(p->icmph), ip_len);
    }
}
#endif

