/* $Id$ */
/*
** Copyright (C) 2002-2004 Jeff Nathan <jeff@snort.org>
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 1999,2000,2001 Christian Lademann <cal@zls.de>
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

/* Snort sp_respond2 Detection Plugin
 *   by Jeff Nathan <jeff@snort.org>
 *   Version 1.0.2
 *
 * Purpose:
 *
 * Perform active response on packets matching conditions specified
 * in Snort rules.
 *
 *
 * Arguments:
 *
 * To enable link-layer response, specify the following in snort.conf
 *   config flexresp2_interface: <interface> 
 *
 * To configure the number of TCP response attempts, specify the following in 
 * snort.conf (the maximum is 20)
 *   config flexresp2_attempts: <attempts> 
 *
 * To configure the response cache memcap, specify the following in snort.conf
 *   config flexresp2_memcap: <memcap> 
 *
 * To configure the number of rows in the response cache , specify the 
 * following in snort.conf
 *   config flexresp2_rows: <rows> 
 *
 * Effect:
 *
 * Shutdown hostile network connections by falsifying TCP resets or ICMP
 * unreachable packets
 *
 *
 * Acknowledgements:
 *
 * Improvements inspired by Dug Song's tcpkill.  Thanks Dug.
 *
 *
 * Comments:
 *
 * sp_respond2 uses libdnet rather than libnet and supports link-layer 
 * injection so you can specify the network interface responses will be sent 
 * from (and bypass the kernel routing table).  This allows multi-homed 
 * systems to use Snort's flexible response system (sp_respond was broken in 
 * this regard).
 *
 * Resetting TCP connections with a passive NIDS is depends on speed,
 * and prediction.  sp_respond2 attempts to brute force active response by 
 * trying to predict changes in the sequence number and ack number of 
 * an active connection while trying to shut it down.  
 *
 * Finally,
 * sp_respond2 does NOT utilize TCP flags to determine whether or not
 * a packet should be considered valid.  This is primarily due to
 * inconsistencies in establishing TCP connections.  Reference:
 * http://www.securityfocus.com/archive/1/296122/2002-10-19/2002-10-25/2
 *
 *
 * Bugs:
 *
 * All software has bugs.  When you find a bug read the BUGS document 
 * in the doc directory of the Snort source distribution for instructions
 * on submitting a bug report.
 *
 * Enjoy,
 *
 * -Jeff
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_RESPONSE2

#include <dnet.h>

#include "decode.h"
#include "rules.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "log.h"
#include "mstring.h"
#include "plugin_enum.h"
#include "snort.h"
#include "checksum.h"
#include "bounds.h"
#include "sfxhash.h"
#include "sp_respond.h"

#define IPIDCOUNT 8192              /* number of randomly generated IP IDs */
#define CACHETIME 2                 /* dampening interval */ 
#define MODNAME   "sp_respond2"     /* plugin name */
#define DEFAULT_ROWS 1024
#define DEFAULT_MEMCAP (1024 * 1024)

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats respond2PerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#include "sfhashfcn.h"
#include "detection_options.h"

typedef struct _RespondData
{
    u_int response_flag;
} RespondData;

/* response cache data structure */
typedef struct _RESPKEY
{
    uint32_t sip;                      /* source IP */
    uint32_t dip;                      /* dest IP */
    uint16_t sport;                    /* source port/ICMP type */
    uint16_t dport;                    /* dest   port/ICMP code */
    uint8_t  proto;                    /* IP protocol */
    uint8_t  _pad[3];                  /* empty bits for word alignment */
} RESPKEY;

typedef struct _RESPOND2_CONFIG
{
    int rows;                           /* response cache size (in rows) */
    int memcap;                         /* response cache memcap */
    uint8_t respond_attempts;          /* respond attempts per trigger */
    ip_t *rawdev;                       /* dnet(3) raw IP handle */
    eth_t *ethdev;                      /* dnet(3) ethernet device handle */   
    rand_t *randh;                      /* dnet(3) rand handle */
} RESPOND2_CONFIG;


extern SnortConfig *snort_conf_for_parsing;

static void *ip_id_pool = NULL;         /* random IP ID buffer */
static uint32_t ip_id_iterator;        /* consumed IP IDs */

static void *tcp_pkt = NULL;            /* TCP packet memory placeholder */
static void *icmp_pkt = NULL;           /* ICMP packet memory placeholder */

static uint8_t link_offset;            /* offset from L2 to L3 header */
static uint8_t alignment;              /* force alignment ?? */

SFXHASH *respcache = NULL;              /* cache responses to prevent loops */
static RESPKEY response;

static RESPOND2_CONFIG *resp2_config = NULL;


/* API functions */
static void RespondInit(char *data, OptTreeNode *otn, int protocol);
static void RespondCleanup(int signal, void *data);
static int ParseResponse2(char *type);

/* CORE respond2 functions */
static int Respond(Packet *p, RspFpList *fp_list);
static INLINE void SendReset(const int mode, Packet *p, RESPOND2_CONFIG *conf);
static INLINE void SendUnreach(const int code, Packet *p, 
        RESPOND2_CONFIG *conf);
static INLINE int IsRSTCandidate(Packet *p);
static INLINE int IsUNRCandidate(Packet *p);
static INLINE int IsLinkCandidate(Packet *p);
static INLINE uint16_t RandID(RESPOND2_CONFIG *conf);
static INLINE uint8_t CalcOriginalTTL(Packet *p);

/* UTILITY functions */
static void PrecacheTCP(void);
static void PrecacheICMP(void);
static void GenRandIPID(RESPOND2_CONFIG *conf);
static void SetLinkInfo(void);
static void SetRespAttempts(RESPOND2_CONFIG *conf);
static void SetRespCacheRows(RESPOND2_CONFIG *conf);
static void SetRespCacheMemcap(RESPOND2_CONFIG *conf);

/* HASH functions */
static int respcache_init(SFXHASH **cache, RESPOND2_CONFIG *conf);
static INLINE int dampen_response(Packet *p);
static INLINE int respkey_make(RESPKEY *hashkey, Packet *p);


/* ######## API section ######## */
uint32_t RespondHash(void *d)
{
    uint32_t a,b,c;
    RespondData *data = (RespondData *)d;

    a = data->response_flag;
    b = RULE_OPTION_TYPE_RESPOND;
    c = 0;

    final(a,b,c);

    return c;
}

int RespondCompare(void *l, void *r)
{
    RespondData *left = (RespondData *)l;
    RespondData *right = (RespondData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if (left->response_flag == right->response_flag)
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}

/**
 * Initialize respond2 plugin
 *
 * @return void function
 */
void SetupRespond(void)
{
    RegisterRuleOption("resp", RespondInit, NULL, OPT_TYPE_ACTION);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("resp2", &respond2PerfStats, 3, &ruleOTNEvalPerfStats);
#endif
}


/**
 * Respond initialization function
 *
 * @param data argument passed to the resp keyword
 * @param otn pointer to an OptTreeNode structure
 * @param protocol Snort rule protocol (IP/TCP/UDP)
 *
 * @return void function
 */
static void RespondInit(char *data, OptTreeNode *otn, int protocol) 
{
    RespondData *rd = NULL;
    void *idx_dup;

    if (!(protocol & (IPPROTO_ICMP | IPPROTO_TCP | IPPROTO_UDP)))
        FatalError("%s: %s(%d): Can't respond to IP protocol rules.\n", 
                MODNAME, file_name, file_line);

    rd = (RespondData *)SnortAlloc(sizeof(RespondData));

    /* XXX XXX */
    if (resp2_config == NULL)
    {
        resp2_config = (RESPOND2_CONFIG *)SnortAlloc(sizeof(RESPOND2_CONFIG));
        SnortConfig *sc = snort_conf_for_parsing;

        if (sc == NULL)
        {
            FatalError("%s(%d) Snort config for parsing is NULL.\n",
                       __FILE__, __LINE__);
        }

        GenRandIPID(resp2_config);  /* generate random IP ID cache */
        SetLinkInfo();      /* setup link-layer pointer arithmetic info */
        SetRespAttempts(resp2_config);       /* configure # of TCP attempts */
        SetRespCacheRows(resp2_config);      /* configure # of rows in cache */
        SetRespCacheMemcap(resp2_config);    /* configure response cache memcap */

        if ((respcache_init(&respcache, resp2_config)) != 0)
            FatalError("%s: Unable to allocate hash table memory.\n", MODNAME);

        /* Open raw socket or network device before Snort drops privileges */
        if (link_offset)
        {
            if (resp2_config->ethdev == NULL)     /* open link-layer device */
            {
                if ((resp2_config->ethdev = eth_open(sc->respond2_ethdev)) == NULL)
                {
                    FatalError("%s: Unable to open link-layer device: %s.\n", 
                            MODNAME, sc->respond2_ethdev);
                }
            }

            DEBUG_WRAP(
                    DebugMessage(DEBUG_PLUGIN, "%s: using link-layer "
                            "injection on interface %s\n", MODNAME,
                            sc->respond2_ethdev);
                    DebugMessage(DEBUG_PLUGIN, "%s: link_offset = %d\n", 
                            MODNAME, link_offset);
        
                    );
        }
        else
        {
            if (resp2_config->rawdev == NULL)   /* open raw device if necessary */
            {
                if ((resp2_config->rawdev = ip_open()) == NULL)
                    FatalError("%s: Unable to open raw socket.\n", 
                            MODNAME);
            }
        }

        DEBUG_WRAP(
                DebugMessage(DEBUG_PLUGIN, "%s: respond_attempts = %d\n", 
                        MODNAME, resp2_config->respond_attempts);
                DebugMessage(DEBUG_PLUGIN, "Plugin: Respond is setup\n");
        );

        AddFuncToCleanExitList(RespondCleanup, NULL);
        AddFuncToRestartList(RespondCleanup, NULL);
    }

    rd->response_flag = ParseResponse2(data);
    
    if (add_detection_option(RULE_OPTION_TYPE_RESPOND, (void *)rd, &idx_dup) == DETECTION_OPTION_EQUAL)
    {
        free(rd);
        rd = idx_dup;
    }

    AddRspFuncToList(Respond, otn, (void *)rd);
    /* Restart and CleanExit function are identical */
}

void RespondFree (void* d)
{
    free(d);
}

/**
 * respond2 signal handler
 * re-initializes packet memory and close device handles
 * 
 * @param data pointer to a RESPOND2_CONFIG data structure
 *
 * @return void function
 */
static void RespondCleanup(int signal, void *data)
{
    if (resp2_config != NULL)
    {
        /* device and raw IP handles */
        if (resp2_config->rawdev != NULL)
            resp2_config->rawdev = ip_close(resp2_config->rawdev);

        if (resp2_config->ethdev != NULL)
            resp2_config->ethdev = eth_close(resp2_config->ethdev);

        if (resp2_config->randh != NULL)
            resp2_config->randh = rand_close(resp2_config->randh);

        free(resp2_config);
        resp2_config = NULL;
    }

    /* free packet memory */
    if (tcp_pkt != NULL)
    {
        tcp_pkt -= alignment;
        free(tcp_pkt);
        tcp_pkt = NULL;
    }

    if (icmp_pkt != NULL)
    {
        icmp_pkt -= alignment;
        free(icmp_pkt);
        icmp_pkt = NULL;
    }

    /* free IP ID pool and close random handle */
    if (ip_id_pool != NULL)
    {
        free(ip_id_pool);
        ip_id_pool = NULL;
        /* reset iterator */
        ip_id_iterator = 0;
    }

    /* destroy the response dampening hash table */
    if (respcache != NULL)
    {
        sfxhash_delete(respcache);
        respcache = NULL;
    }
}


/**
 * Determine how to handle hostile connection attempts
 *
 * @param type string of comma-separated response modifiers
 *
 * @return integer describing the type of response action on a matching packet
 */
static int ParseResponse2(char *type)
{
    char **toks;
    int response_flag = 0;
    int num_toks;
    static int make_tcp = 0;
    static int make_icmp = 0;
    int i;

    while (isspace((int) *type))
        type++;

    if (!type || !(*type))
        return 0;

    toks = mSplit(type, ",", 6, &num_toks, 0);

    if (num_toks < 1)
        FatalError("%s (%d): Bad arguments to respond2: %s.\n", file_name,
                file_line, type);

    i = 0;
    while (i < num_toks)
    {
        if (!strcasecmp(toks[i], "reset_source"))
        {
            response_flag |= RESP_RST_SND;
            if (!make_tcp)
                make_tcp = 1;
            i++;
        }
        else if (!strcasecmp(toks[i], "reset_dest"))
        {
            response_flag |= RESP_RST_RCV;
            if (!make_tcp)
                make_tcp = 1;
            i++;
        }
        else if (!strcasecmp(toks[i], "reset_both"))
        {
            response_flag |= (RESP_RST_RCV | RESP_RST_SND);
            if (!make_tcp)
                make_tcp = 1;
            i++;
        }
        else if (!strcasecmp(toks[i], "icmp_net"))
        {
            response_flag |= RESP_BAD_NET;
            if (!make_icmp)
                make_icmp = 1;
            i++;
        }
        else if (!strcasecmp(toks[i], "icmp_host"))
        {
            response_flag |= RESP_BAD_HOST;
            if (!make_icmp)
                make_icmp = 1;
            i++;
        }
        else if (!strcasecmp(toks[i], "icmp_port"))
        {
            response_flag |= RESP_BAD_PORT;
            if (!make_icmp)
                make_icmp = 1;
            i++;
        }
        else if (!strcasecmp(toks[i], "icmp_all"))
        {
            response_flag |= (RESP_BAD_NET | RESP_BAD_HOST | RESP_BAD_PORT);
            if (!make_icmp)
                make_icmp = 1;
            i++;
        }
        else
            FatalError("%s: %s(%d): invalid response modifier: %s\n", 
                    MODNAME, file_name, file_line, toks[i]);
    }

    if (make_tcp)
        PrecacheTCP();

    if (make_icmp)
        PrecacheICMP();

    mSplitFree(&toks, num_toks);

    return response_flag;
}


/* ######## CORE respond2 section ######## */

/**
 * Respond to hostile connection attempts
 *
 * @param p pointer to a Snort packet structure
 * @param fp_list pointer to a response list node
 *
 * @return void function
 */
static int Respond(Packet *p, RspFpList *fp_list)
{
    RespondData *rd;
    PROFILE_VARS;
    
    rd = (RespondData *)fp_list->params;

    if (p->iph == NULL)
        return 0;

    /* check the dampen cache before responding */
    if ((dampen_response(p)) == 1)
        return 0;

    PREPROC_PROFILE_START(respond2PerfStats);

    if (rd->response_flag)
    {
        /* if reset_both was used, receiver is reset first */
        if ((rd->response_flag & (RESP_RST_RCV | RESP_RST_SND)) && 
                IsRSTCandidate(p))
        {
            SendReset(RESP_RST_RCV, p, resp2_config);
            SendReset(RESP_RST_SND, p, resp2_config);
        }
        if ((rd->response_flag & RESP_RST_RCV) && IsRSTCandidate(p))
            SendReset(RESP_RST_RCV, p, resp2_config);

        if ((rd->response_flag & RESP_RST_SND) && IsRSTCandidate(p))
            SendReset(RESP_RST_SND, p, resp2_config);

        if (rd->response_flag & RESP_BAD_NET && IsUNRCandidate(p))
            SendUnreach(ICMP_UNREACH_NET, p, resp2_config);

        if (rd->response_flag & RESP_BAD_HOST && IsUNRCandidate(p))
            SendUnreach(ICMP_UNREACH_HOST, p, resp2_config);

        if (rd->response_flag & RESP_BAD_PORT && IsUNRCandidate(p))
            SendUnreach(ICMP_UNREACH_PORT, p, resp2_config);
    }
    PREPROC_PROFILE_END(respond2PerfStats);
    return 1;   /* injection functions do not return an error */
}


/**
 * TCP reset response function
 *
 * @param flag flag describing whom to respond to (sender/receiver)
 * @param p Pointer to a Snort packet structure
 * @param data pointer to a RESPOND2_CONFIG data structure
 *
 * @return void function
 */
static void SendReset(const int mode, Packet *p, RESPOND2_CONFIG *conf)
{
    size_t sz = IP_HDR_LEN + TCP_HDR_LEN;
    ssize_t n;
    int reversed;
    uint32_t i, ack, seq;
    uint16_t window, dsize;
    EtherHdr *eh;
    IPHdr *iph;
    TCPHdr *tcp;
#if defined(DEBUG)
    char *source, *dest;
#endif

    if(IS_IP6(p)) return;

    if (mode == RESP_RST_SND)
        reversed = 1;
    else
        reversed = 0;

    iph = (IPHdr *)(tcp_pkt + link_offset);
    tcp = (TCPHdr *)(tcp_pkt + IP_HDR_LEN + link_offset);

    if (link_offset)
    {
        if (!IsLinkCandidate(p))
        {
            ErrorMessage("%s: link-layer response only works on Ethernet!\n"
                    "Remove \"config flexresp2_interface\" from snort.conf.\n",
                    MODNAME);
            return;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s: setting up link-layer "
                    "header on TCP packet: %p.\n.", MODNAME, p););

            /* setup the Ethernet header */
            eh = (EtherHdr *)tcp_pkt;
            if (reversed)
            {
                memcpy(eh->ether_src, p->eh->ether_dst, 6);
                memcpy(eh->ether_dst, p->eh->ether_src, 6);
            }
            else
            {
                memcpy(eh->ether_src, p->eh->ether_src, 6);
                memcpy(eh->ether_dst, p->eh->ether_dst, 6);
            }
        }
    }

    /* save p->dsize */
    dsize = p->dsize;

    /* Reverse the source and destination IP addr for attack-response rules */
    if (reversed)
    {
#ifdef SUP_IP6
    memcpy(&iph->ip_src.s_addr, &(GET_DST_IP(p))->ip32[0], 4);
    memcpy(&iph->ip_dst.s_addr, &(GET_SRC_IP(p))->ip32[0], 4);
#else
    iph->ip_src.s_addr = GET_DST_IP(p);
    iph->ip_dst.s_addr = GET_SRC_IP(p);
#endif

        tcp->th_sport = p->tcph->th_dport;
        tcp->th_dport = p->tcph->th_sport;
        seq = ntohl(p->tcph->th_ack);
        ack = ntohl(p->tcph->th_seq) + p->dsize;
    }
    else
    {
#ifdef SUP_IP6
    memcpy(&iph->ip_src.s_addr, &(GET_SRC_IP(p))->ip32[0], 4);
    memcpy(&iph->ip_dst.s_addr, &(GET_DST_IP(p))->ip32[0], 4);
#else
    iph->ip_src.s_addr = GET_SRC_IP(p);
    iph->ip_dst.s_addr = GET_DST_IP(p);
#endif

        tcp->th_sport = p->tcph->th_sport;
        tcp->th_dport = p->tcph->th_dport;
        seq = ntohl(p->tcph->th_seq);
        ack = ntohl(p->tcph->th_ack) + p->dsize;
    }
    iph->ip_ttl = CalcOriginalTTL(p);
    tcp->th_win = 0;

    /* save the window size for all calculations */
    window = ntohs(p->tcph->th_win);

    for (i = 0; i < conf->respond_attempts; i++)
    {
        if (link_offset)
            iph->ip_id = RandID(resp2_config);

        /* As Dug Song pointed out, if you can't determine the rate of 
         * SEQ and ACK number consumption, do the next best thing and try to
         * "land" a reset within the acceptable window of sequence numbers.
         *
         * sp_respond2 uses data sent in the offending packet and the window
         * size of the offending packet to 'predict' an acceptable SEQ and 
         * ACK number.  
         *
         * A minimum of four responses are sent per trigger using the 
         * following algorithm:
         *
         * (the numbers represent iterations through a loop starting at 0)
         *
         * 0:
         *   SEQ = seq
         *   ACK = ack + data
         *
         * 1:
         *   SEQ += data
         *
         * 2:
         *   SEQ += (data * 2)
         *   ACK += (data * 2)
         *
         * 3:
         *   SEQ += (data * 2)
         *   ACK += (data * 2)
         *
         * 4:
         *   SEQ += (data * 4)
         *   ACK += (data * 4)
         *
         * n:
         *
         *   SEQ += (window / 2)
         *   ACK += (window / 2)
         *   
         *
         * I refer to the above as "sequence strafing", whereby sp_respond2 
         * iteratively brute forces sequence and ack numbers into an
         * acceptable window
         */
        switch (i)
        {
            case 0:
                break;
            case 1:
                seq += dsize;
                break;
            case 2:
                seq += (dsize << 1);
                ack += (dsize << 1);
                break;
            case 3:
                seq += (dsize << 1);
                ack += (dsize << 1);
                break;
            case 4:
                seq += (dsize << 2);
                ack += (dsize << 2);
                break;
            default:
                seq += (window >> 1);
                ack += (window >> 1);
                break;
        }

        tcp->th_seq = htonl(seq);
        tcp->th_ack = htonl(ack);

        iph->ip_len = htons(sz);
        ip_checksum(tcp_pkt + link_offset, sz);
    
#if defined(DEBUG)
        DEBUG_WRAP(
#ifndef SUP_IP6
                source = strdup(inet_ntoa(*(struct in_addr *)&iph->ip_src.s_addr));
                dest = strdup(inet_ntoa(*(struct in_addr *)&iph->ip_dst.s_addr));
#else
                source = "";
                dest = "";
#endif
                DebugMessage(DEBUG_PLUGIN, "%s: firing TCP response packet.\n",
                        MODNAME);
                DebugMessage(DEBUG_PLUGIN, "%s:%u -> %s:%d\n(seq: %#lX "
                        "ack: %#lX win: %hu)\n\n", source, 
                        ntohs(tcp->th_sport), dest, ntohs(tcp->th_dport), 
                        ntohl(tcp->th_seq), ntohl(tcp->th_ack), 
                        ntohs(tcp->th_win));

                PrintNetData(stdout, (u_char *)tcp_pkt, sz);
                //ClearDumpBuf();
                free(source);
                free(dest);
        );
#endif /* defined(DEBUG) */

        if (link_offset)
            n = eth_send(conf->ethdev, tcp_pkt, sz + link_offset);
        else
            n = ip_send(conf->rawdev, tcp_pkt, sz);

        if (n < sz)
            ErrorMessage("%s: failed to send TCP reset (%s).\n", MODNAME, 
                    ((link_offset == 0) ? "raw socket" : "link-layer"));
    }
    return;
}


/**
 * ICMP unreachable response function
 *
 * @param code ICMP unreachable type
 * @param p Pointer to a Snort packet structure
 * @param data pointer to a RESPOND2_CONFIG data structure
 *
 * @return void function
 */
static void SendUnreach(const int code, Packet *p, RESPOND2_CONFIG *conf)
{
    uint16_t payload_len;
    size_t sz;
    ssize_t n;
    EtherHdr *eh;
    IPHdr *iph;
    ICMPHdr *icmph;
#if defined(DEBUG)
    char *source, *dest, *icmp_rtype;
#endif

    if(IS_IP6(p)) return;

    /* only send ICMP port unreachable responses for TCP and UDP */
    if (GET_IPH_PROTO(p) == IPPROTO_ICMP && code == ICMP_UNREACH_PORT)
    {
        ErrorMessage("%s: ignoring icmp_port set on ICMP packet.\n", MODNAME);
        return;
    }

    iph = (IPHdr *)(icmp_pkt + link_offset);
    icmph = (ICMPHdr *)(icmp_pkt + IP_HDR_LEN + link_offset);

#ifdef SUP_IP6
    memcpy(&iph->ip_src.s_addr, &(GET_DST_IP(p))->ip32[0], 4);
    memcpy(&iph->ip_dst.s_addr, &(GET_SRC_IP(p))->ip32[0], 4);
#else
    iph->ip_src.s_addr = GET_DST_IP(p);
    iph->ip_dst.s_addr = GET_SRC_IP(p);
#endif
    iph->ip_ttl = CalcOriginalTTL(p);

    icmph->code = code;

    if (link_offset)
    {
        if (!IsLinkCandidate(p))
        {
            ErrorMessage("%s: link-layer response only works on Ethernet!\n"
                    "Remove \"config flexresp2_interface\" from snort.conf.\n", 
                    MODNAME);
            return;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s: setting up link-layer "
                    "header on ICMP packet: %p.\n.", MODNAME, p););

            /* setup the Ethernet header */
            eh = (EtherHdr *)icmp_pkt;
            memcpy(eh->ether_src, p->eh->ether_dst, 6);
            memcpy(eh->ether_dst, p->eh->ether_src, 6);

            /* With a raw socket, the kernel automatically sets the IP ID when
             * it's 0.  With link-layer injection, an IP ID must be specified.
             * A randomly generated IP ID is used here to evade fingerprinting.
             */
            iph->ip_id = RandID(resp2_config);
        }
    }

    if ((payload_len = ntohs(GET_IPH_LEN(p)) - (GET_IPH_HLEN(p) << 2)) > 8)
        payload_len = 8;

    memcpy((char *)icmph + ICMP_LEN_MIN, p->iph, (IP_HLEN(p->iph) << 2)
              + payload_len);

    sz = IP_HDR_LEN + ICMP_LEN_MIN + (IP_HLEN(p->iph) << 2) + payload_len;

    iph->ip_len = htons(sz);
    ip_checksum(icmp_pkt + link_offset, sz);
    sz += link_offset;

#ifdef DEBUG
    DEBUG_WRAP(
#ifdef SUP_IP6
            source = strdup(sfip_ntoa(iph->ip_src.s_addr));
            dest = strdup(sfip_ntoa(iph->ip_dst.s_addr));
#else
            source = strdup(inet_ntoa(*(struct in_addr *)&iph->ip_src.s_addr));
            dest = strdup(inet_ntoa(*(struct in_addr *)&iph->ip_dst.s_addr));
#endif
            switch (code)
            {
                case RESP_BAD_NET:
                    icmp_rtype = "ICMP network unreachable";
                    break;
                case RESP_BAD_HOST:
                    icmp_rtype = "ICMP host unreachable";
                    break;
                case RESP_BAD_PORT: /* FALLTHROUGH */
                default:
                    icmp_rtype = "ICMP port unreachable";
                    break;
            }
            DebugMessage(DEBUG_PLUGIN, "%s: firing ICMP response packet.\n", 
                    MODNAME);
            DebugMessage(DEBUG_PLUGIN, "%s -> %s (%s)\n\n", source, dest, 
                icmp_rtype);
            PrintNetData(stdout, (u_char *)icmp_pkt, (const int)sz);
            //ClearDumpBuf();
            free(source);
            free(dest);
    );
#endif /* DEBUG */

    if (link_offset)
        n = eth_send(conf->ethdev, icmp_pkt, sz);
    else
        n = ip_send(conf->rawdev, icmp_pkt, sz);

    if (n < sz)
        ErrorMessage("%s: failed to send ICMP unreachable (%s).\n", MODNAME,
                ((link_offset == 0) ? "raw socket" : "link-layer"));
    return;
}


/**
 * Determine whether or not a TCP RST response can be sent
 *
 * @param p pointer to a Snort packet structure
 *
 * @return 1 on success, 0 on failure
 */
static INLINE int IsRSTCandidate(Packet *p)
{
    if (p->tcph != NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s: got RST candidate\n",
                MODNAME););
        return 1;
    }
    return 0;
}


/**
 * Determine whether or not an ICMP Unreach response can be sent
 *
 * @param p pointer to a Snort packet structure
 *
 * @return 1 on success, 0 on failure
 */
static INLINE int IsUNRCandidate(Packet *p)
{
    if ((p->icmph == NULL) || (p->icmph->type == ICMP_ECHO) || 
        (p->icmph->type == ICMP_TIMESTAMP) || 
        (p->icmph->type == ICMP_INFO_REQUEST) || 
        (p->icmph->type == ICMP_ADDRESS))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s: got Unreach candidate\n",
                MODNAME););
        return 1;
    }
    return 0;
}


/**
 * Determine if frame is IP encapsulated Ethernet 
 *
 * @param p pointer to a Snort packet structure
 *
 * @return 1 on success, 0 on failure
 */
static INLINE int IsLinkCandidate(Packet *p)
{
    if (p->eh != NULL && ntohs(p->eh->ether_type) == ETHERNET_TYPE_IP)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s: got Link candidate\n", 
                MODNAME););
        return 1;
    }
    return 0;
}


/**
 * Generate a pool of random IP IDs at start-up.
 *
 * @param data pointer to a RESPOND2_CONFIG data structure
 *
 * @return random IP ID
 */
static INLINE uint16_t RandID(RESPOND2_CONFIG *conf)
{
    if (ip_id_iterator >= (IPIDCOUNT - 1))
    {
        rand_add(conf->randh, ip_id_pool, sizeof(uint16_t) * IPIDCOUNT); 
        ip_id_iterator = 0;
    }
    return *(uint16_t *)(ip_id_pool + ip_id_iterator++);
}


/**
 * Calculate original IP TTL
 *
 * @param p pointer to a Snort packet structure
 *
 * @return calculated original TTL
 */
static INLINE uint8_t CalcOriginalTTL(Packet *p)
{
    switch (p->iph->ip_ttl / 64)
    {
        case 3:
            return 255;
        case 2:
            return 192;
        case 1:
            return 128;
        default:
            return 64;
    }
}


/* ######## UTILITY section ######## */

/**
 * Pre-cache TCP RST packet memory to improve response speed
 *
 * @return void function
 */
static void PrecacheTCP(void)
{
    EtherHdr *eth;
    IPHdr *iph;
    TCPHdr *tcp;
    int sz;

    if (tcp_pkt == NULL)
    {
        /* allocates memory for the Ethernet header only when necessary  */
        sz = alignment + link_offset + IP_HDR_LEN + TCP_HDR_LEN;

        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s: allocating %d bytes in "
                                "PrecacheTCP().\n", MODNAME, sz););

        tcp_pkt = SnortAlloc(sz);

        /* force alignment */
        tcp_pkt += alignment;

        if (link_offset)
        {
            eth = (EtherHdr *)tcp_pkt; 
            eth->ether_type = htons(ETH_TYPE_IP);
        }

        /* points to the start of the IP header */
        iph = (IPHdr *)(tcp_pkt + link_offset);
        SET_IP_VER(iph, 4);
        SET_IP_HLEN(iph, (IP_HDR_LEN >> 2));
        iph->ip_proto = IPPROTO_TCP;

        /* points to the start of the TCP header */
        tcp = (TCPHdr *)(tcp_pkt + IP_HDR_LEN + link_offset);
        tcp->th_flags = TH_RST|TH_ACK;
        SET_TCP_OFFSET(tcp, (TCP_HDR_LEN >> 2));
    }
}


/**
 * Pre-cache ICMP unreachable packet memory to improve response speed
 *
 * @return void function
 */
static void PrecacheICMP(void)
{
    EtherHdr *eth;
    IPHdr *iph;
    ICMPHdr *icmp;
    int sz;

    if (icmp_pkt == NULL)
    {
        /* allocates memory for the Ethernet header only when necessary 
         * additional 68 bytes are allocated to accomodate an IP header with 
         * options -Jeff */
        sz = alignment + link_offset + IP_HDR_LEN + ICMP_LEN_MIN + 68;

        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s: allocating %d bytes in "
                                "PrecacheICMP().\n", MODNAME, sz););

        icmp_pkt = SnortAlloc(sz);

        /* force alignment */
        icmp_pkt += alignment;

        if (link_offset)
        {
            eth = (EtherHdr *)icmp_pkt; 
            eth->ether_type = htons(ETH_TYPE_IP);
        }

        /* points to the start of the IP header */
        iph = (IPHdr *)(icmp_pkt + link_offset);
        SET_IP_VER(iph, 4);
        SET_IP_HLEN(iph, (IP_HDR_LEN >> 2));
        iph->ip_proto = IPPROTO_ICMP;

        /* points to the start of the ICMP header */
        icmp = (ICMPHdr *)(icmp_pkt + IP_HDR_LEN + link_offset);
        icmp->type = ICMP_UNREACH;
    }
}


/**
 * Generate a pool of random IP IDs at start-up.
 *
 * @param data pointer to a RESPOND2_CONFIG data structure
 *
 * @return void function
 */
static void GenRandIPID(RESPOND2_CONFIG *conf)
{
    if ((conf->randh = rand_open()) == NULL)
        FatalError("%s: Unable to open random device handle.\n", MODNAME);

    ip_id_pool = SnortAlloc(sizeof(uint16_t) * IPIDCOUNT);
    rand_get(conf->randh, ip_id_pool, sizeof(uint16_t) * IPIDCOUNT);
}


/**
 * Set link-layer offset
 *
 * @return void function
 */
static void SetLinkInfo(void)
{
    SnortConfig *sc = snort_conf_for_parsing;

    if (sc == NULL)
    {
        FatalError("%s(%d) Snort config for parsing is NULL.\n",
                   __FILE__, __LINE__);
    }

    if (sc->respond2_link)
    {
        link_offset = ETH_HDR_LEN;
        alignment = 2;
    }
    else
    {
        link_offset = 0;
        alignment = 0;
    }
}


/**
 * Set number of responses per triggered event
 *
 * @param data pointer to a RESPOND2_CONFIG data structure
 *
 * @return void function
 */
static void SetRespAttempts(RESPOND2_CONFIG *conf)
{
    SnortConfig *sc = snort_conf_for_parsing;

    if (sc == NULL)
    {
        FatalError("%s(%d) Snort config for parsing is NULL.\n",
                   __FILE__, __LINE__);
    }

    if ((sc->respond2_attempts > 4) && (sc->respond2_attempts < 21))
        conf->respond_attempts = sc->respond2_attempts;
    else
        conf->respond_attempts = 4;
}


/**
 * Set number of rows in response cache hash table
 *
 * @param data pointer to a RESPOND2_CONFIG data structure
 *
 * @return void function
 */
static void SetRespCacheRows(RESPOND2_CONFIG *conf)
{
    SnortConfig *sc = snort_conf_for_parsing;

    if (sc == NULL)
    {
        FatalError("%s(%d) Snort config for parsing is NULL.\n",
                   __FILE__, __LINE__);
    }

    conf->rows = DEFAULT_ROWS;

    if (sc->respond2_rows)
        conf->rows = sc->respond2_rows;
}


/**
 * Set memcap of response cache hash table
 *
 * @param data pointer to a RESPOND2_CONFIG data structure
 *
 * @return void function
 */
static void SetRespCacheMemcap(RESPOND2_CONFIG *conf)
{
    SnortConfig *sc = snort_conf_for_parsing;

    if (sc == NULL)
    {
        FatalError("%s(%d) Snort config for parsing is NULL.\n",
                   __FILE__, __LINE__);
    }

    conf->memcap = DEFAULT_MEMCAP;

    if (sc->respond2_memcap)
        conf->memcap = sc->respond2_memcap;
}


/* ######## HASH section ######## */

/**
 * Initialize response cache at start-up.
 *
 * @param respcachep response cache pointer
 * @param data pointer to a RESPOND2_CONFIG data structure
 *
 * @return 0 on success, 1 on error
 */
static int respcache_init(SFXHASH **cache, RESPOND2_CONFIG *conf)
{

    if (conf->memcap <= (sizeof(time_t) + sizeof(response) + 
                sizeof(SFXHASH_NODE)))
    {
        /* without sufficient memory to store one node, return an error */
        return 1;
    }

    if (conf->rows < 1)
        return 1;

    *cache = sfxhash_new(conf->rows,
                             sizeof(response),          /* size of hash key */
                             sizeof(time_t),            /* size of data */
                             conf->memcap,
                             1,                         /* auto recover nodes */
                             NULL,
                             NULL,
                             1);                        /* recycle old nodes */

    if (*cache == NULL)
        return 1;

    return 0;
}


/**
 * normalize response packets for a hash lookup
 *
 * @param key pointer to hash key
 * @param p pointer to a Snort packet structure
 *
 * @return 0 on success, 1 on error
 */
static INLINE int respkey_make(RESPKEY *hashkey, Packet *p)
{
    hashkey->sip = p->iph->ip_src.s_addr;
    hashkey->dip = p->iph->ip_dst.s_addr;
    hashkey->proto = p->iph->ip_proto;
    switch (hashkey->proto)
    {
        case IPPROTO_ICMP:
            hashkey->sport = p->icmph->type;
            hashkey->dport = p->icmph->code;
            break;
        case IPPROTO_TCP:
            hashkey->sport = p->tcph->th_sport;
            hashkey->dport = p->tcph->th_dport;
            break;
        case IPPROTO_UDP:
            hashkey->sport = p->udph->uh_sport;
            hashkey->dport = p->udph->uh_dport;
            break;
    }
    return 0;
}


/**
 * dampen responses if they're occuring too quickly
 *
 * @param p pointer to a Snort packet structure
 *
 * @return 0 on success, 1 on error
 */
static INLINE int dampen_response(Packet *p)
{
    int ret;
    time_t pkt_time = p->pkth->ts.tv_sec;
    time_t *resp_time;
    RESPKEY tmpkey;

    memset((void *)&tmpkey, 0, sizeof(response));

    /* normalize the packet for a hash lookup */
    respkey_make(&tmpkey, p);

    /* sfxhash_add uses sfxhash_find internally, optimize with this in mind
     * by always trying to add.  If the key already exists, use its data.
     */
    ret = sfxhash_add(respcache, (void *)&tmpkey, (void *)&pkt_time);
    switch(ret)
    {
        case SFXHASH_OK:
            ret = 0;
            break;
        case SFXHASH_NOMEM:
            ret = 1;
            break;
        case SFXHASH_INTABLE:
            resp_time = (time_t *)respcache->cnode->data;
            if ((pkt_time - *resp_time) < CACHETIME)
            {
               /* dampen this response because sp_respond2 observed this 
                * response < CACHETIME seconds ago.
                */
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s: dampening "
                            "response\n", MODNAME););
                ret = 1;
            }
            else
            {
                /* sp_respond2 has sent this response > CACHETIME seconds 
                 * ago.  In this case, replace the hash data and proceed.
                 */

                ret = 0;
                if ((sfxhash_remove(respcache, (void *)&tmpkey)) != SFXHASH_OK)
                    ret = 1;
                else if ((sfxhash_add(respcache, (void *)&tmpkey, 
                                (void *)&pkt_time)) != SFXHASH_OK)
                    ret = 1;
            }
	    break;
    }

    return ret;
}
#endif /* ENABLE_RESPONSE2 */
