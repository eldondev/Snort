/* $Id$ */

/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000,2001 Maciej Szarpak
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

/* Snort React Plugin by Maciej Szarpak, Warsaw University of Technology */

/* sp_react.c 
 * 
 * Purpose:
 *
 * React! Deny the access to some unsuitable web-sites (like porn sites) or
 * close the offending connections.
 *
 * Arguments:
 *   
 * This plugin can take two basic arguments:
 *    block => closes the connection and sends a suitable HTML page to the
 *             browser (if got tcp 80 port packet)
 *    warn  => sends a HTML/JavaScript warning to the browser
 *
 * The following additional arguments are valid for this option:
 *    msg   	      => puts the msg option comment into the HTML page
 *    proxy <port_nr> => sends the respond code to the proxy port_nr
 *
 * Effect:
 *
 * Closes the connections by sending TCP RST packets (similar to resp option).
 * If the connection uses http or proxy server ports a visible information
 * to a browser user is send (HTML code).
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_REACT

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libnet.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "plugin_enum.h"
#include "sfhashfcn.h"
#include "sp_react.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats reactPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#include "sfhashfcn.h"
#include "detection_options.h"

#define TCP_DATA_BUF    1024

#define REACT_BLOCK 0x01
#define REACT_WARN  0x02

typedef struct _ReactData
{
    int reaction_flag;  /* flexible reaction on alert */
    int proxy_port_nr;      /* proxy TCP port */
    u_int html_resp_size;       /* size of app html response */
    u_char *html_resp_buf;      /* html response to send */

} ReactData;

static void ReactInit(char *, OptTreeNode *, int);
static void ParseReact(char *, OptTreeNode *, ReactData *);
static int React(Packet *, RspFpList *);
static int SendTCP(u_long, u_long, u_short, u_short, int, int, u_char, const u_char *,
                    int);
static void ReactCleanup(int signal, void *data);

void ReactFree(void *d)
{
    ReactData *data = (ReactData *)d;
    if (data->html_resp_buf)
        free(data->html_resp_buf);
    free(data);
}

uint32_t ReactHash(void *d)
{
    uint32_t a,b,c,tmp;
    unsigned int i,j,k,l;
    ReactData *data = (ReactData *)d;

    a = data->reaction_flag;
    b = data->proxy_port_nr;
    c = data->html_resp_size;

    mix(a,b,c);

    for (i=0,j=0;i<data->html_resp_size;i+=4)
    {
        tmp = 0;
        k = data->html_resp_size - i;
        if (k > 4)
            k=4;
                                                               
        for (l=0;l<k;l++)
        {
            tmp |= *(data->html_resp_buf + i + l) << l*8;
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

    a += RULE_OPTION_TYPE_REACT;

    final(a,b,c);

    return c;
}

int ReactCompare(void *l, void *r)
{
    ReactData *left = (ReactData *)l;
    ReactData *right = (ReactData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if (left->html_resp_size != right->html_resp_size)
        return DETECTION_OPTION_NOT_EQUAL;

    if (memcmp(left->html_resp_buf, right->html_resp_buf, left->html_resp_size) != 0)
        return DETECTION_OPTION_NOT_EQUAL;

    if (( left->reaction_flag == right->reaction_flag) &&
        ( left->proxy_port_nr == right->proxy_port_nr))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* ENABLE_REACT */

#if defined(ENABLE_REACT) || defined(ENABLE_RESPONSE)
#include <libnet.h>
#include "util.h"

int nd = -1;             /* raw socket descriptor */
static int nd_users = 0; /* reference count */

void RawSocket_Open ()
{
    if ( ++nd_users == 1 ) /* need to open it only once */
    {   
        if((nd = libnet_open_raw_sock(IPPROTO_RAW)) < 0)
        {
            FatalError("cannot open raw socket for libnet, exiting...\n");
        }
    }   
}

void RawSocket_Close ()
{
    if ( nd_users > 0 && --nd_users == 0 ) 
    {   
        libnet_close_raw_sock(nd);
    }   
}
#endif

#ifdef ENABLE_REACT
/****************************************************************************
 * 
 * Function: SetupReact()
 *
 * Purpose: Flexible response plugin. Registers the configuration function 
 *	    and links it to a rule keyword.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupReact(void)
{

/* we need an empty plug otherwise. To avoid #ifdef in plugbase */

    RegisterRuleOption("react", ReactInit, NULL, OPT_TYPE_ACTION);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("react", &reactPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: React Initialized!\n"););
}


/****************************************************************************
 * 
 * Function: ReactInit(char *, OptTreeNode *, int protocol)
 *
 * Purpose: React rule configuration function.  Handles parsing the rule 
 *          information and attaching the associated structures to the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *	      protocol => current rule protocol
 *
 * Returns: void function
 *
 ****************************************************************************/
static void ReactInit(char *data, OptTreeNode *otn, int protocol)
{
    ReactData *idx;
    void *idx_dup;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"In ReactInit()\n"););

    if(protocol != IPPROTO_TCP)
    {
        FatalError("Line %s(%d): TCP Options on non-TCP rule\n", file_name, file_line);
    }

    /* If it hasn't been opened yet, there are no rules currently using this
     * rule option, so on a reload, setting this during parsing won't step
     * on runtime evaluation */
    RawSocket_Open();

    // depending on reloads and ordering of inits/cleans, 
    // opening module may not be same as closing module.
    AddFuncToCleanExitList(ReactCleanup, NULL);

    if((idx = (ReactData *) calloc(sizeof(ReactData), sizeof(char))) == NULL)
    {
        FatalError("sp_react ReactInit() calloc failed!\n");
    }

    /* parse the react keywords */
    ParseReact(data, otn, idx);

    if (add_detection_option(RULE_OPTION_TYPE_REACT, (void *)idx, &idx_dup) == DETECTION_OPTION_EQUAL)
    {
        free(idx);
        idx = idx_dup;
    }

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    AddRspFuncToList(React, otn, (void *)idx);
}



/****************************************************************************
 * 
 * Function: ParseReact(char *, OptTreeNode *)
 *
 * Purpose: React rule configuration function. Handles parsing the rule 
 *          information.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
static void ParseReact(char *data, OptTreeNode *otn, ReactData *rd)
{
    ReactData *idx;
    char *tok;      /* token buffer */
    u_int buf_size; 
    int ret;

    char tmp_buf1[] = "<HTML><HEAD><TITLE>Snort</TITLE></HEAD><BODY BGCOLOR=\"#FFFFFF\"><CENTER><BR><H1>Snort!</H1>Version ";
    char tmp_buf2[] = "<H1><BR><BR><FONT COLOR=\"#FF0000\">You are not authorized to open this site!</FONT><BR><BR></H1><H2>";
    char tmp_buf3[] = "<BR></H2><BR><A HREF=\"mailto:mszarpak@elka.pw.edu.pl\">Any questions?</A></CENTER></BODY></HTML>";    
    char tmp_buf4[]="<HTML><HEAD><SCRIPT LANGUAGE=\"JavaScript\"><!-- Hiding function pop() { alert(\"Snort, ver. ";
    char tmp_buf5[] = "\\n\\nThis page contents ...!\\n\\n";
    char tmp_buf6[] = "\"); } // --></SCRIPT></HEAD><BODY ONLOAD=\"pop()\"></BODY></HTML>";

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "In ParseReact()\n"););

    idx = rd;

    /* set the standard proxy port */
    idx->proxy_port_nr = 8080;

    /* parse the react option keywords */
    while(isspace((int)*data)) data++;

    tok = strtok(data, ",");
    while(tok)
    {
        if(!strcasecmp(tok, "block"))
            idx->reaction_flag = REACT_BLOCK;
        else if(!strcasecmp(tok, "warn"))
/*	    idx->reaction_flag = REACT_WARN*/;
        else if(!strcasecmp(tok, "msg"))
            if(otn->sigInfo.message == NULL)
                FatalError( "%s(%d) => msg option missed or react "
                            "keyword placed before msg!\n", file_name, file_line);
            else
                idx->html_resp_size = 1;
        else if(!strcasecmp(tok, "proxy"))
        {
            if(strlen(tok) > strlen("proxy"))
            {
                char *endp;

                tok = tok + 5;
                
                while(isspace((int)(*tok)))
                    tok++;

                idx->proxy_port_nr = strtoul(tok,&endp,10);
                if(endp ==  tok)
                {
                    FatalError("Can't parse the dang proxy option\n");
                }
            }
            else
            {
                FatalError("Can't parse the dang proxy option\n");
            }

            /* make sure it's in bounds */
            if((idx->proxy_port_nr < 0) || (idx->proxy_port_nr >= MAXPORTS))
            {
                FatalError("%s(%d): bad proxy port number: %d\n", file_name, file_line, idx->proxy_port_nr);
            }
        }
        else
        {
            FatalError("%s(%d): invalid react modifier: %s\n", file_name, file_line, tok);
        }
        tok = strtok(NULL, ","); 

        /* get rid of spaces */
        if(tok != NULL)
            while(isspace((int)*tok)) tok++;
    }

    /* test the basic modifier */
    if(idx->reaction_flag == 0)
        FatalError("%s(%d): missing react basic modifier\n", file_name, file_line);
    else
    {
        /* prepare the html response data */
        buf_size = 1;  /* allocate one extra byte for '\0' */
        if(idx->reaction_flag == REACT_BLOCK)
        {
            /* count the respond buf size (max TCP_DATA_BUF) */
            buf_size += strlen(tmp_buf1) + strlen(tmp_buf2) + strlen(tmp_buf3) + strlen(VERSION);

            if(buf_size > TCP_DATA_BUF)
            {
                FatalError("%s(%d): invalid html response buffer size: %d\n", file_name, file_line, buf_size);
            }
            else
            {
                /* msg included */
                if((idx->html_resp_size == 1) && (buf_size + 
                            strlen(otn->sigInfo.message) < TCP_DATA_BUF))
                {
                    buf_size += strlen(otn->sigInfo.message);
                }

                /* create html response buffer */
                idx->html_resp_buf = (u_char *)SnortAlloc(sizeof(char) * buf_size);

                if (idx->html_resp_size == 1)
                {
                    ret = SnortSnprintf((char *)idx->html_resp_buf, buf_size,
                                        "%s%s%s%s%s",
                                        tmp_buf1, VERSION, tmp_buf2, otn->sigInfo.message, tmp_buf3);
                }
                else
                {
                    ret = SnortSnprintf((char *)idx->html_resp_buf, buf_size,
                                        "%s%s%s%s",
                                        tmp_buf1, VERSION, tmp_buf2, tmp_buf3);
                }

                if (ret != SNORT_SNPRINTF_SUCCESS)
                {
                    FatalError("%s(%d): SnortSnprintf failed\n", file_name, file_line);
                }
            }
        }
        else if(idx->reaction_flag == REACT_WARN)
        {
            /* count the respond buf size (max TCP_DATA_BUF) */
            buf_size += strlen(tmp_buf4) + strlen(tmp_buf5) + strlen(tmp_buf6) + strlen(VERSION);

            if(buf_size > TCP_DATA_BUF)
            {
                FatalError("%s(%d): invalid html response buffer size: %d\n",
                           file_name, file_line, buf_size);
            }
            else
            {
                /* msg included */
                if((idx->html_resp_size == 1) && (buf_size + 
                                                  strlen(otn->sigInfo.message) < TCP_DATA_BUF))
                {
                    buf_size += strlen(otn->sigInfo.message);
                }

                /* create html response buffer */
                idx->html_resp_buf = (u_char *)SnortAlloc(sizeof(char) * buf_size);

                if (idx->html_resp_size == 1)
                {
                    ret = SnortSnprintf((char *)idx->html_resp_buf, buf_size,
                                        "%s%s%s%s%s",
                                        tmp_buf4, VERSION, tmp_buf5, otn->sigInfo.message, tmp_buf6);
                }
                else
                {
                    ret = SnortSnprintf((char *)idx->html_resp_buf, buf_size,
                                        "%s%s%s%s",
                                        tmp_buf4, VERSION, tmp_buf5, tmp_buf6);
                }

                if (ret != SNORT_SNPRINTF_SUCCESS)
                {
                    FatalError("%s(%d): SnortSnprintf failed\n", file_name, file_line);
                }
            }
        }

        /* set the html response buffer size */
        idx->html_resp_size = buf_size;
    }

    return;
}



/****************************************************************************
 *
 * Function: React(Packet *p, OptTreeNode *otn_tmp)
 *
 * Purpose: React to hostile connection attempts according to reaction_flag
 *
 * Arguments: p => pointer to the current packet
 *	      otn => pointer to the current rule option list node
 *
 * Returns: Always calls the next function (this one doesn't test the data,
 *          it just closes the connection...)
 *
 ***************************************************************************/
static int React(Packet *p,  RspFpList *fp_list)
{
    ReactData *idx;
    int i;
    PROFILE_VARS;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"In React()\n"););

    if(!p->tcph)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No TCP header ... leaving"););
        return 1;
    }

    PREPROC_PROFILE_START(reactPerfStats);

    idx = (ReactData *)fp_list->params;

    if(idx == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Nothing to do ... leaving"););
        PREPROC_PROFILE_END(reactPerfStats);
        return 1;
    }

    /* check the reaction flag */
    if(idx->reaction_flag == REACT_BLOCK)
    {
        /* send HTML page buffer to a rude browser user and close the connection */
        /* incoming */
        if((ntohs(p->tcph->th_sport)) == 80 || (ntohs(p->tcph->th_sport)) == idx->proxy_port_nr)
        {
            for(i = 0; i < 5; i++)
            {
                SendTCP(p->iph->ip_src.s_addr, p->iph->ip_dst.s_addr,
                        p->tcph->th_sport, p->tcph->th_dport,
                        p->tcph->th_seq, htonl(ntohl(p->tcph->th_ack) + i),
                        TH_FIN, idx->html_resp_buf, idx->html_resp_size);
            }
            for(i = 0; i < 5; i++)
            {
                SendTCP(p->iph->ip_dst.s_addr, p->iph->ip_src.s_addr,
                        p->tcph->th_dport, p->tcph->th_sport,
                        p->tcph->th_ack, htonl(ntohl(p->tcph->th_seq) + i),
                        TH_RST, idx->html_resp_buf, 0);
            }
        }
        /* outgoing */
        else if(ntohs(p->tcph->th_dport) == 80 || (ntohs(p->tcph->th_dport)) == idx->proxy_port_nr)
        {
            for(i = 0; i < 5; i++)
            {
                SendTCP(p->iph->ip_dst.s_addr, p->iph->ip_src.s_addr,
                        p->tcph->th_dport, p->tcph->th_sport,
                        p->tcph->th_ack, htonl(ntohl(p->tcph->th_seq) + i),
                        TH_FIN, idx->html_resp_buf, idx->html_resp_size);
                SendTCP(p->iph->ip_src.s_addr, p->iph->ip_dst.s_addr,
                        p->tcph->th_sport, p->tcph->th_dport,
                        p->tcph->th_seq, htonl(ntohl(p->tcph->th_ack) + i),
                        TH_RST, idx->html_resp_buf, 0);
            }
        }
        else
        /* reset the connection */
        {
            for(i = 0; i < 5; i++)
            {
                SendTCP(p->iph->ip_dst.s_addr, p->iph->ip_src.s_addr,
                        p->tcph->th_dport, p->tcph->th_sport,
                        p->tcph->th_ack, htonl(ntohl(p->tcph->th_seq) + i),
                        TH_RST, idx->html_resp_buf, 0);
                SendTCP(p->iph->ip_src.s_addr, p->iph->ip_dst.s_addr,
                        p->tcph->th_sport, p->tcph->th_dport,
                        p->tcph->th_seq, htonl(ntohl(p->tcph->th_ack) + i),
                        TH_RST, idx->html_resp_buf, 0);
            }
        }
    }
    else if(idx->reaction_flag == REACT_WARN)
    { 
        /* send HTML warning page buffer to a rude browser user */
        /* incoming */
        if((ntohs(p->tcph->th_sport)) == 80 || (ntohs(p->tcph->th_sport)) == idx->proxy_port_nr)
        {
            for(i = 0; i < 5; i++)
            {
                SendTCP(p->iph->ip_src.s_addr, p->iph->ip_dst.s_addr,
                        p->tcph->th_sport, p->tcph->th_dport,
                        p->tcph->th_seq, p->tcph->th_ack + i,
                        TH_URG, idx->html_resp_buf, idx->html_resp_size);
            }
        }
        /* outgoing */
        else if(ntohs(p->tcph->th_dport) == 80 || (ntohs(p->tcph->th_dport)) == idx->proxy_port_nr)
        {
            for(i = 0; i < 5; i++)
            {
                SendTCP(p->iph->ip_dst.s_addr, p->iph->ip_src.s_addr,
                        p->tcph->th_dport, p->tcph->th_sport,
                        p->tcph->th_ack, p->tcph->th_seq + i,
                        TH_URG, idx->html_resp_buf, idx->html_resp_size);
            }
        }
    }
    PREPROC_PROFILE_END(reactPerfStats);
    return 1;
}    




static int SendTCP(u_long saddr, u_long daddr, u_short sport, u_short dport, int seq,
                   int ack, u_char bits, const u_char *data_buf, int data_size)
{
    u_char *buf;
    int sz = data_size + IP_H + TCP_H;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"In SendTCP()\n"););

    if((buf = malloc(sz)) == NULL)
    {
        perror("SendTCPRST: malloc");
        return -1;
    }

    memset(buf, 0, sz);

    libnet_build_ip( TCP_H                             /* Length of packet data */
                   , 0xF4                              /* IP tos */
                   , (u_short) libnet_get_prand(PRu16) /* IP ID */
                   , 0                                 /* Fragmentation flags and offset */
                   , 64                                /* TTL */
                   , IPPROTO_TCP                       /* Protocol */
                   , saddr                             /* Source IP Address */
                   , daddr                             /* Destination IP Address */
                   , NULL                              /* Pointer to packet data (or NULL) */
                   , 0                                 /* Packet payload size */
                   , buf                               /* Pointer to packet header memory */
                   );

    
    libnet_build_tcp( ntohs(sport)  /* Source port */
                    , ntohs(dport)  /* Destination port */
                    , ntohl(seq)    /* Sequence Number */
                    , ntohl(ack)    /* Acknowledgement Number */
                    , bits          /* Control bits */
                    , 1024          /* Advertised Window Size */
                    , 0             /* Urgent Pointer */
                    , data_buf      /* Pointer to packet data (or NULL) */
                    , data_size     /* Packet payload size */
                    , buf + IP_H    /* Pointer to packet header memory */
                    );
    
    libnet_do_checksum(buf, IPPROTO_TCP, sz - IP_H);
    
    if(libnet_write_ip(nd, buf, sz) < sz)
    {
        libnet_error(LIBNET_ERR_CRITICAL, "SendTCP: libnet_write_ip\n");
        return -1;
    }

    libnet_destroy_packet(&buf);

    return 0;

}

static void ReactCleanup(int signal, void *data)
{
    RawSocket_Close();
}

#endif /* ENABLE_REACT */

