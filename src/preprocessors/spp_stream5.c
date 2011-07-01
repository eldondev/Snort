/* $Id$ */
/****************************************************************************
 *
 * Copyright (C) 2005-2009 Sourcefire, Inc.
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

/**
 * @file    spp_stream5.c
 * @author  Martin Roesch <roesch@sourcefire.com>
 *         Steven Sturges <ssturges@sourcefire.com>
 * @date    19 Apr 2005
 *
 * @brief   You can never have too many stream reassemblers...
 */

/*  I N C L U D E S  ************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#ifndef WIN32
#include <sys/time.h>       /* struct timeval */
#endif
#include <sys/types.h>      /* u_int*_t */

#include "snort.h"
#include "bounds.h"
#include "util.h"
#include "debug.h"
#include "plugbase.h"
#include "spp_stream5.h"
#include "stream_api.h"
#include "stream5_common.h"
#include "snort_stream5_session.h"
#include "snort_stream5_tcp.h"
#include "snort_stream5_udp.h"
#include "snort_stream5_icmp.h"
#include "checksum.h"
#include "mstring.h"
#include "parser/IpAddrSet.h"
#include "decode.h"
#include "detect.h"
#include "generators.h"
#include "event_queue.h"
#include "stream_ignore.h"
#include "stream_api.h"
#include "perf.h"

#include "ipv6_port.h"

#ifdef TARGET_BASED
#include "sftarget_protocol_reference.h"
#include "sftarget_hostentry.h"
#endif

#include "sfPolicy.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats s5PerfStats;
extern PreprocStats s5TcpPerfStats;
extern PreprocStats s5UdpPerfStats;
extern PreprocStats s5IcmpPerfStats;
#endif

extern OptTreeNode *otn_tmp;
extern SnortConfig *snort_conf_for_parsing;
extern SnortConfig *snort_conf;
extern Stream5SessionCache *tcp_lws_cache;
extern Stream5SessionCache *udp_lws_cache;

extern FlushConfig ignore_flush_policy[MAX_PORTS];
#ifdef TARGET_BASED
extern FlushConfig ignore_flush_policy_protocol[MAX_PROTOCOL_ORDINAL];
#endif


/*  M A C R O S  **************************************************/

/* default limits */
#define S5_DEFAULT_PRUNE_QUANTA  30       /* seconds to timeout a session */
#define S5_DEFAULT_MEMCAP        8388608  /* 8MB */
#define S5_DEFAULT_PRUNE_LOG_MAX 1048576  /* 1MB */
#define S5_RIDICULOUS_HI_MEMCAP  1024*1024*1024 /* 1GB */
#define S5_RIDICULOUS_LOW_MEMCAP 32768    /* 32k*/
#define S5_DEFAULT_MIN_TTL       1        /* default for min TTL */
#define S5_DEFAULT_TTL_LIMIT     5        /* default for TTL Limit */
#define S5_RIDICULOUS_MAX_SESSIONS 1024*1024 /* 1 million sessions */
#define S5_DEFAULT_MAX_TCP_SESSIONS 262144 /* 256k TCP sessions by default */
#define S5_DEFAULT_MAX_UDP_SESSIONS 131072 /* 128k UDP sessions by default */
#define S5_DEFAULT_MAX_ICMP_SESSIONS 65536 /* 64k ICMP sessions by default */
#define S5_MIN_PRUNE_LOG_MAX     1024      /* 1k packet data stored */
#define S5_MAX_PRUNE_LOG_MAX     S5_RIDICULOUS_HI_MEMCAP  /* 1GB packet data stored */


/*  G L O B A L S  **************************************************/
tSfPolicyUserContextId s5_config = NULL;
Stream5Config *s5_eval_config = NULL;
Stream5GlobalConfig *s5_global_eval_config = NULL;
Stream5TcpConfig *s5_tcp_eval_config = NULL;
Stream5UdpConfig *s5_udp_eval_config = NULL;
Stream5IcmpConfig *s5_icmp_eval_config = NULL;

uint32_t mem_in_use = 0;

uint32_t firstPacketTime = 0;
Stream5Stats s5stats;
MemPool s5FlowMempool;
static PoolCount total_sessions = 0;

/* Define this locally when Flow preprocessor has actually been removed */
const unsigned int giFlowbitSize = 64;


/*  P R O T O T Y P E S  ********************************************/
static void Stream5GlobalInit(char *);
static void Stream5ParseGlobalArgs(Stream5GlobalConfig *, char *);
static void Stream5PolicyInitTcp(char *);
static void Stream5PolicyInitUdp(char *);
static void Stream5PolicyInitIcmp(char *);
static void Stream5Restart(int, void *);
static void Stream5CleanExit(int, void *);
static void Stream5Reset(int, void *);
static void Stream5ResetStats(int, void *);
static void Stream5VerifyConfig(void);
static void Stream5PrintGlobalConfig(Stream5GlobalConfig *);
static void Stream5PrintStats(int);
static void Stream5Process(Packet *p, void *context);
static INLINE int IsEligible(Packet *p);
#ifdef TARGET_BASED
static void s5InitServiceFilterStatus(void);
#endif

#ifdef SNORT_RELOAD
tSfPolicyUserContextId s5_swap_config = NULL;
static void Stream5GlobalReload(char *);
static void Stream5TcpReload(char *);
static void Stream5UdpReload(char *);
static void Stream5IcmpReload(char *);
static int Stream5ReloadVerify(void);
static void * Stream5ReloadSwap(void);
static void Stream5ReloadSwapFree(void *);
#endif

/*  S T R E A M  A P I **********************************************/
static int Stream5MidStreamDropAlert(void)
{
    Stream5Config *config = sfPolicyUserDataGet(s5_config, getRuntimePolicy());

    if (config == NULL)
        return 1;

    return (config->global_config->flags &
            STREAM5_CONFIG_MIDSTREAM_DROP_NOALERT) ? 0 : 1;
}

static void Stream5UpdateDirection(
                    void * ssnptr,
                    char dir,
                    snort_ip_p ip,
                    uint16_t port);
static uint32_t Stream5GetPacketDirection(
                    Packet *p);
static void Stream5StopInspection(
                    void * ssnptr,
                    Packet *p,
                    char dir,
                    int32_t bytes,
                    int response);
static int Stream5IgnoreChannel(
                    snort_ip_p srcIP,
                    uint16_t srcPort,
                    snort_ip_p dstIP,
                    uint16_t dstPort,
                    char protocol,
                    char direction,
                    char flags);
static void Stream5ResumeInspection(
                    void *ssnptr,
                    char dir);
static void Stream5DropTraffic(
                    void *ssnptr,
                    char dir);
static void Stream5DropPacket(
                    Packet *p);
static void Stream5SetApplicationData(
                    void *ssnptr,
                    uint32_t protocol,
                    void *data,
                    StreamAppDataFree free_func);
static void *Stream5GetApplicationData(
                    void *ssnptr,
                    uint32_t protocol);
static uint32_t Stream5SetSessionFlags(
                    void *ssnptr,
                    uint32_t flags);
static uint32_t Stream5GetSessionFlags(void *ssnptr);
static int Stream5AlertFlushStream(Packet *p);
static int Stream5ResponseFlushStream(Packet *p);
static int Stream5AddSessionAlert(void *ssnptr, 
                                  Packet *p,
                                  uint32_t gid,
                                  uint32_t sid);
static int Stream5CheckSessionAlert(void *ssnptr,
                                    Packet *p,
                                    uint32_t gid,
                                    uint32_t sid);
static char Stream5SetReassembly(void *ssnptr,
                                    uint8_t flush_policy,
                                    char dir,
                                    char flags);
static char Stream5GetReassemblyDirection(void *ssnptr);
static char Stream5GetReassemblyFlushPolicy(void *ssnptr, char dir);
static char Stream5IsStreamSequenced(void *ssnptr, char dir);
static int Stream5MissingInReassembled(void *ssnptr, char dir);
static char Stream5PacketsMissing(void *ssnptr, char dir);

static int Stream5GetRebuiltPackets(
                            Packet *p,
                            PacketIterator callback,
                            void *userdata);
static StreamFlowData *Stream5GetFlowData(Packet *p);
#ifdef TARGET_BASED
static int16_t Stream5GetApplicationProtocolId(void *ssnptr);
static int16_t Stream5SetApplicationProtocolId(void *ssnptr, int16_t id);
static void s5SetServiceFilterStatus(
        int protocolId, 
        int status,
        tSfPolicyId policyId,
        int parsing
        );
static int s5GetServiceFilterStatus (
        int protocolId,
        tSfPolicyId policyId,
        int parsing
        );
#endif
static void s5SetPortFilterStatus(
        int protocol, 
        uint16_t port, 
        int status,
        tSfPolicyId policyId,
        int parsing
        );

static uint32_t Stream5GetFlushPoint(void *ssnptr, char dir);
static void Stream5SetFlushPoint(void *ssnptr, char dir, uint32_t flush_point);

StreamAPI s5api = {
    STREAM_API_VERSION5,
    Stream5MidStreamDropAlert,
    Stream5UpdateDirection,
    Stream5GetPacketDirection,
    Stream5StopInspection,
    Stream5IgnoreChannel,
    Stream5ResumeInspection,
    Stream5DropTraffic,
    Stream5DropPacket,
    Stream5SetApplicationData,
    Stream5GetApplicationData,
    Stream5SetSessionFlags,
    Stream5GetSessionFlags,
    Stream5AlertFlushStream,
    Stream5ResponseFlushStream,
    Stream5GetRebuiltPackets,
    Stream5AddSessionAlert,
    Stream5CheckSessionAlert,
    Stream5GetFlowData,
    Stream5SetReassembly,
    Stream5GetReassemblyDirection,
    Stream5GetReassemblyFlushPolicy,
    Stream5IsStreamSequenced,
    Stream5MissingInReassembled,
    Stream5PacketsMissing,
#ifdef TARGET_BASED
    Stream5GetApplicationProtocolId,
    Stream5SetApplicationProtocolId,
    s5SetServiceFilterStatus,
#endif
    s5SetPortFilterStatus,
    Stream5GetFlushPoint,
    Stream5SetFlushPoint
    /* More to follow */
};

void SetupStream5(void)
{
#ifndef SNORT_RELOAD
    RegisterPreprocessor("stream5_global", Stream5GlobalInit);
    RegisterPreprocessor("stream5_tcp", Stream5PolicyInitTcp);
    RegisterPreprocessor("stream5_udp", Stream5PolicyInitUdp);
    RegisterPreprocessor("stream5_icmp", Stream5PolicyInitIcmp);
#else
    RegisterPreprocessor("stream5_global", Stream5GlobalInit, Stream5GlobalReload,
                         Stream5ReloadSwap, Stream5ReloadSwapFree);
    RegisterPreprocessor("stream5_tcp", Stream5PolicyInitTcp,
                         Stream5TcpReload, NULL, NULL);
    RegisterPreprocessor("stream5_udp", Stream5PolicyInitUdp,
                         Stream5UdpReload, NULL, NULL);
    RegisterPreprocessor("stream5_icmp", Stream5PolicyInitIcmp,
                         Stream5IcmpReload, NULL, NULL);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Preprocessor stream5 is setup\n"););
}

void Stream5GlobalInit(char *args)
{
    tSfPolicyId policy_id = getParserPolicy();
    Stream5Config *pDefaultPolicyConfig = NULL;
    Stream5Config *pCurrentPolicyConfig = NULL;


    if (s5_config == NULL)
    {
        //create a context
        s5_config = sfPolicyConfigCreate();

#ifdef PERF_PROFILING
        RegisterPreprocessorProfile("s5", &s5PerfStats, 0, &totalPerfStats);
        RegisterPreprocessorProfile("s5tcp", &s5TcpPerfStats, 1, &s5PerfStats);
        RegisterPreprocessorProfile("s5udp", &s5UdpPerfStats, 1, &s5PerfStats);
        RegisterPreprocessorProfile("s5icmp", &s5IcmpPerfStats, 1, &s5PerfStats);
#endif

        AddFuncToPreprocCleanExitList(Stream5CleanExit, NULL, PRIORITY_FIRST, PP_STREAM5);
        AddFuncToPreprocRestartList(Stream5Restart, NULL, PRIORITY_FIRST, PP_STREAM5);
        AddFuncToPreprocResetList(Stream5Reset, NULL, PRIORITY_FIRST, PP_STREAM5);
        AddFuncToPreprocResetStatsList(Stream5ResetStats, NULL, PRIORITY_FIRST, PP_STREAM5);
        AddFuncToConfigCheckList(Stream5VerifyConfig);
        RegisterPreprocStats("stream5", Stream5PrintStats);

        stream_api = &s5api;
    }

    sfPolicyUserPolicySet (s5_config, policy_id);

    pDefaultPolicyConfig = (Stream5Config *)sfPolicyUserDataGet(s5_config, getDefaultPolicy());
    pCurrentPolicyConfig = (Stream5Config *)sfPolicyUserDataGetCurrent(s5_config);

    if ((policy_id != getDefaultPolicy()) && (pDefaultPolicyConfig == NULL))
    {
        ParseError("Stream5: Must configure default policy if other targeted "
                   "policies are configured.\n");
    }

    if (pCurrentPolicyConfig != NULL)
    {
        FatalError("%s(%d) ==> Cannot duplicate Stream5 global "
                   "configuration\n", file_name, file_line);
    }

    pCurrentPolicyConfig = (Stream5Config *)SnortAlloc(sizeof(Stream5Config));
    sfPolicyUserDataSetCurrent(s5_config, pCurrentPolicyConfig);

    pCurrentPolicyConfig->global_config =
        (Stream5GlobalConfig *)SnortAlloc(sizeof(Stream5GlobalConfig));

    pCurrentPolicyConfig->global_config->track_tcp_sessions = S5_TRACK_YES;
    pCurrentPolicyConfig->global_config->max_tcp_sessions = S5_DEFAULT_MAX_TCP_SESSIONS;
    pCurrentPolicyConfig->global_config->track_udp_sessions = S5_TRACK_YES;
    pCurrentPolicyConfig->global_config->max_udp_sessions = S5_DEFAULT_MAX_UDP_SESSIONS;
    pCurrentPolicyConfig->global_config->track_icmp_sessions = S5_TRACK_NO;
    pCurrentPolicyConfig->global_config->max_icmp_sessions = S5_DEFAULT_MAX_ICMP_SESSIONS;
    pCurrentPolicyConfig->global_config->memcap = S5_DEFAULT_MEMCAP;
    pCurrentPolicyConfig->global_config->prune_log_max = S5_DEFAULT_PRUNE_LOG_MAX;

    Stream5ParseGlobalArgs(pCurrentPolicyConfig->global_config, args);

    if ((pCurrentPolicyConfig->global_config->track_tcp_sessions == S5_TRACK_NO) &&
        (pCurrentPolicyConfig->global_config->track_udp_sessions == S5_TRACK_NO) &&
        (pCurrentPolicyConfig->global_config->track_icmp_sessions == S5_TRACK_NO))

    {
        FatalError("%s(%d) ==> Stream5 enabled, but not configured to track "
                   "TCP, UDP, or ICMP.\n", file_name, file_line);
    }

    if (policy_id != getDefaultPolicy())
    {
        pCurrentPolicyConfig->global_config->max_tcp_sessions =
            pDefaultPolicyConfig->global_config->max_tcp_sessions;
        pCurrentPolicyConfig->global_config->max_udp_sessions =
            pDefaultPolicyConfig->global_config->max_udp_sessions;
        pCurrentPolicyConfig->global_config->max_icmp_sessions =
            pDefaultPolicyConfig->global_config->max_icmp_sessions;
        pCurrentPolicyConfig->global_config->memcap =
            pDefaultPolicyConfig->global_config->memcap;
    }

    Stream5PrintGlobalConfig(pCurrentPolicyConfig->global_config);

    if (snort_conf_for_parsing == NULL)
    {
        FatalError("%s(%d) Snort config for parsing is NULL.\n",
                   __FILE__, __LINE__);
    }

    snort_conf_for_parsing->run_flags |= RUN_FLAG__STATEFUL;
}

static void Stream5ParseGlobalArgs(Stream5GlobalConfig *config, char *args)
{
    char **toks;
    int num_toks;
    int i;
    char **stoks;
    int s_toks;
    char *endPtr = NULL;
#define MAX_TCP 0x01
#define MAX_UDP 0x02
#define MAX_ICMP 0x04
    char max_set = 0;

    if (config == NULL)
        return;

    if ((args == NULL) || (strlen(args) == 0))
        return;

    toks = mSplit(args, ",", 0, &num_toks, 0);
    i = 0;

    for (i = 0; i < num_toks; i++)
    {
        stoks = mSplit(toks[i], " ", 4, &s_toks, 0);

        if (s_toks == 0)
        {
            FatalError("%s(%d) => Missing parameter in Stream5 Global config.\n",
                       file_name, file_line);
        }

        if(!strcasecmp(stoks[0], "memcap"))
        {
            if (stoks[1])
            {
                config->memcap = strtoul(stoks[1], &endPtr, 10);
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid memcap in config file.  Requires integer parameter.\n",
                           file_name, file_line);
            }

            if ((config->memcap > S5_RIDICULOUS_HI_MEMCAP) ||
                (config->memcap < S5_RIDICULOUS_LOW_MEMCAP))
            {
                FatalError("%s(%d) => 'memcap %s' invalid: value must be "
                           "between %d and %d bytes\n",
                           file_name, file_line,
                           stoks[1], S5_RIDICULOUS_LOW_MEMCAP,
                           S5_RIDICULOUS_HI_MEMCAP);
            }
        }
        else if(!strcasecmp(stoks[0], "max_tcp"))
        {
            if (stoks[1])
            {
                config->max_tcp_sessions = strtoul(stoks[1], &endPtr, 10);
                if (config->track_tcp_sessions == S5_TRACK_NO)
                {
                    if (config->max_tcp_sessions != 0)
                    {
                        FatalError("%s(%d) => max_tcp conflict: not "
                                   "tracking TCP sessions\n",
                                   file_name, file_line);
                    }
                }
                else
                {
                    if ((config->max_tcp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                        (config->max_tcp_sessions == 0))
                    {
                        FatalError("%s(%d) => 'max_tcp %d' invalid: value must be "
                                   "between 1 and %d sessions\n",
                                   file_name, file_line,
                                   config->max_tcp_sessions,
                                   S5_RIDICULOUS_MAX_SESSIONS);
                    }
                }
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid max_tcp in config file.  Requires integer parameter.\n",
                           file_name, file_line);
            }

            max_set |= MAX_TCP;
        }
        else if(!strcasecmp(stoks[0], "track_tcp"))
        {
            if (stoks[1])
            {
                if(!strcasecmp(stoks[1], "no"))
                    config->track_tcp_sessions = S5_TRACK_NO;
                else
                    config->track_tcp_sessions = S5_TRACK_YES;
            }
            else
            {
                FatalError("%s(%d) => 'track_tcp' missing option\n",
                           file_name, file_line);
            }

            if ((max_set & MAX_TCP) && 
                (config->track_tcp_sessions == S5_TRACK_NO))
            {
                FatalError("%s(%d) => max_tcp/track_tcp conflict: not "
                           "tracking TCP sessions\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "max_udp"))
        {
            if (stoks[1])
            {
                config->max_udp_sessions = strtoul(stoks[1], &endPtr, 10);
                if (config->track_udp_sessions == S5_TRACK_NO)
                {
                    if (config->max_udp_sessions != 0)
                    {
                        FatalError("%s(%d) => max_udp conflict: not "
                                   "tracking UDP sessions\n",
                                   file_name, file_line);
                    }
                }
                else
                {
                    if ((config->max_udp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                        (config->max_udp_sessions == 0))
                    {
                        FatalError("%s(%d) => 'max_udp %d' invalid: value must be "
                                   "between 1 and %d sessions\n",
                                   file_name, file_line,
                                   config->max_udp_sessions,
                                   S5_RIDICULOUS_MAX_SESSIONS);
                    }
                }
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid max_udp in config file.  Requires integer parameter.\n",
                           file_name, file_line);
            }
            max_set |= MAX_UDP;
        }
        else if(!strcasecmp(stoks[0], "track_udp"))
        {
            if (stoks[1])
            {
                if(!strcasecmp(stoks[1], "no"))
                    config->track_udp_sessions = S5_TRACK_NO;
                else
                    config->track_udp_sessions = S5_TRACK_YES;
            }
            else
            {
                FatalError("%s(%d) => 'track_udp' missing option\n",
                           file_name, file_line);
            }

            if ((max_set & MAX_UDP) && 
                (config->track_udp_sessions == S5_TRACK_NO))
            {
                FatalError("%s(%d) => max_udp/track_udp conflict: not "
                           "tracking UDP sessions\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "max_icmp"))
        {
            if (stoks[1])
            {
                config->max_icmp_sessions = strtoul(stoks[1], &endPtr, 10);

                if (config->track_icmp_sessions == S5_TRACK_NO)
                {
                    if (config->max_icmp_sessions != 0)
                    {
                        FatalError("%s(%d) => max_icmp conflict: not "
                                   "tracking ICMP sessions\n",
                                   file_name, file_line);
                    }
                }
                else
                {
                    if ((config->max_icmp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                        (config->max_icmp_sessions == 0))
                    {
                        FatalError("%s(%d) => 'max_icmp %d' invalid: value must be "
                                   "between 1 and %d sessions\n",
                                   file_name, file_line,
                                   config->max_icmp_sessions,
                                   S5_RIDICULOUS_MAX_SESSIONS);
                    }
                }
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid max_icmp in config file.  Requires integer parameter.\n",
                           file_name, file_line);
            }
            max_set |= MAX_ICMP;
        }
        else if(!strcasecmp(stoks[0], "track_icmp"))
        {
            if (stoks[1])
            {
                if(!strcasecmp(stoks[1], "no"))
                    config->track_icmp_sessions = S5_TRACK_NO;
                else
                    config->track_icmp_sessions = S5_TRACK_YES;
            }
            else
            {
                FatalError("%s(%d) => 'track_icmp' missing option\n",
                           file_name, file_line);
            }

            if ((max_set & MAX_ICMP) && 
                (config->track_icmp_sessions == S5_TRACK_NO))
            {
                FatalError("%s(%d) => max_icmp/track_icmp conflict: not "
                           "tracking ICMP sessions\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "flush_on_alert"))
        {
            config->flags |= STREAM5_CONFIG_FLUSH_ON_ALERT;
        }
        else if(!strcasecmp(stoks[0], "show_rebuilt_packets"))
        {
            config->flags |= STREAM5_CONFIG_SHOW_PACKETS;
        }
        else if(!strcasecmp(stoks[0], "prune_log_max"))
        {
            if (stoks[1])
            {
                config->prune_log_max = strtoul(stoks[1], &endPtr, 10);
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid prune_log_max in config file.  Requires integer parameter.\n",
                           file_name, file_line);
            }

            if (((config->prune_log_max > S5_MAX_PRUNE_LOG_MAX) ||
                 (config->prune_log_max < S5_MIN_PRUNE_LOG_MAX)) &&
                (config->prune_log_max != 0))
            {
                FatalError("%s(%d) => Invalid Prune Log Max."
                           "  Must be 0 (disabled) or between %d and %d\n",
                           file_name, file_line,
                           S5_MIN_PRUNE_LOG_MAX, S5_MAX_PRUNE_LOG_MAX);
            }
        }
#ifdef TBD
        else if(!strcasecmp(stoks[0], "no_midstream_drop_alerts"))
        {
            /*
             * XXX: Do we want to not alert on drops for sessions picked
             * up midstream ?  If we're inline, and get a session midstream,
             * its because it was picked up during startup.  In inline
             * mode, we should ALWAYS be requiring TCP 3WHS.
             */
            config->flags |= STREAM5_CONFIG_MIDSTREAM_DROP_NOALERT;
        }
#endif
        else
        {
            FatalError("%s(%d) => Unknown Stream5 global option (%s)\n",
                       file_name, file_line, toks[i]);
        }

        mSplitFree(&stoks, s_toks);
    }

    mSplitFree(&toks, num_toks);
}

static void Stream5PrintGlobalConfig(Stream5GlobalConfig *config)
{
    if (config == NULL)
        return;

    LogMessage("Stream5 global config:\n");
    LogMessage("    Track TCP sessions: %s\n",
        config->track_tcp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (config->track_tcp_sessions == S5_TRACK_YES)
        LogMessage("    Max TCP sessions: %lu\n",
            config->max_tcp_sessions);
    LogMessage("    Memcap (for reassembly packet storage): %d\n",
        config->memcap);
    LogMessage("    Track UDP sessions: %s\n",
        config->track_udp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (config->track_udp_sessions == S5_TRACK_YES)
        LogMessage("    Max UDP sessions: %lu\n",
            config->max_udp_sessions);
    LogMessage("    Track ICMP sessions: %s\n",
        config->track_icmp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (config->track_icmp_sessions == S5_TRACK_YES)
        LogMessage("    Max ICMP sessions: %lu\n",
            config->max_icmp_sessions);
    if (config->prune_log_max)
    {
        LogMessage("    Log info if session memory consumption exceeds %d\n",
            config->prune_log_max);
    }
}

static void Stream5PolicyInitTcp(char *args)
{
    tSfPolicyId policy_id = getParserPolicy();
    Stream5Config *config = NULL;

    if (s5_config == NULL)
        FatalError("Tried to config stream5 TCP policy without global config!\n");

    sfPolicyUserPolicySet (s5_config, policy_id);
    config = (Stream5Config *)sfPolicyUserDataGetCurrent(s5_config);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 TCP policy without global config!\n");
    }

    if (!config->global_config->track_tcp_sessions)
    {
#ifdef SNORT_RELOAD
        /* Return if we're reloading - the discrepancy will be handled in
         * the reload verify */
        if (s5_swap_config != NULL)
            return;
#endif

        FatalError("Stream5 TCP Configuration specified, but TCP tracking is turned off\n");
    }

    if (config->tcp_config == NULL)
    {
        config->tcp_config =
            (Stream5TcpConfig *)SnortAlloc(sizeof(Stream5TcpConfig));

        if (policy_id == 0)
            Stream5InitTcp(config->global_config);

        Stream5TcpInitFlushPoints();
        Stream5TcpRegisterRuleOptions();
    }

    /* Call the protocol specific initializer */
    Stream5TcpPolicyInit(config->tcp_config, args);
}

static void Stream5PolicyInitUdp(char *args)
{
    tSfPolicyId policy_id = getParserPolicy();
    Stream5Config *config;

    if (s5_config == NULL)
        FatalError("Tried to config stream5 UDP policy without global config!\n");

    sfPolicyUserPolicySet (s5_config, policy_id);
    config = (Stream5Config *)sfPolicyUserDataGetCurrent(s5_config);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 UDP policy without global config!\n");
    }

    if (!config->global_config->track_udp_sessions)
    {
#ifdef SNORT_RELOAD
        /* Return if we're reloading - the discrepancy will be handled in
         * the reload verify */
        if (s5_swap_config != NULL)
            return;
#endif

        FatalError("Stream5 UDP Configuration specified, but UDP tracking is turned off\n");
    }

    if (config->udp_config == NULL)
    {
        config->udp_config =
            (Stream5UdpConfig *)SnortAlloc(sizeof(Stream5UdpConfig));

        Stream5InitUdp(config->global_config);
    }

    /* Call the protocol specific initializer */
    Stream5UdpPolicyInit(config->udp_config, args);
}

static void Stream5PolicyInitIcmp(char *args)
{
    tSfPolicyId policy_id = getParserPolicy();
    Stream5Config *config;

    if (s5_config == NULL)
        FatalError("Tried to config stream5 ICMP policy without global config!\n");

    sfPolicyUserPolicySet (s5_config, policy_id);
    config = (Stream5Config *)sfPolicyUserDataGetCurrent(s5_config);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 ICMP policy without global config!\n");
    }

    if (!config->global_config->track_icmp_sessions)
    {
#ifdef SNORT_RELOAD
        /* Return if we're reloading - the discrepancy will be handled in
         * the reload verify */
        if (s5_swap_config != NULL)
            return;
#endif

        FatalError("Stream5 ICMP Configuration specified, but ICMP tracking is turned off\n");
    }

    if (config->icmp_config == NULL)
    {
        config->icmp_config =
            (Stream5IcmpConfig *)SnortAlloc(sizeof(Stream5IcmpConfig));

        Stream5InitIcmp(config->global_config);
    }

    /* Call the protocol specific initializer */
    Stream5IcmpPolicyInit(config->icmp_config, args);
}

static void Stream5Restart(int signal, void *foo)
{
    Stream5CleanExit(signal, foo);
    return;
}

static void Stream5Reset(int signal, void *foo)
{
    if (s5_config == NULL)
        return;

    Stream5ResetTcp();
    Stream5ResetUdp();
    Stream5ResetIcmp();

    mempool_clean(&s5FlowMempool);
}

static void Stream5ResetStats(int signal, void *foo)
{
    memset(&s5stats, 0, sizeof(s5stats));
}

static void Stream5CleanExit(int signal, void *foo)
{
    /* Clean up the hash tables for these */
    Stream5CleanTcp();
    Stream5CleanUdp();
    Stream5CleanIcmp();

    mempool_destroy(&s5FlowMempool);

    /* Free up the ignore data that was queued */
    CleanupIgnore();

    Stream5FreeConfigs(s5_config);
    s5_config = NULL;
}

static int Stream5VerifyConfigPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId, 
        void* pData
        )
{
    Stream5Config *pPolicyConfig = (Stream5Config *)pData;
    int tcpNotConfigured = 0;
    int udpNotConfigured = 0;
    int icmpNotConfigured = 0;
    int proto_flags = 0;
    tSfPolicyId tmp_policy_id = getParserPolicy();

    //do any housekeeping before freeing Stream5Config
    if (pPolicyConfig->global_config == NULL)
    {
        FatalError("%s(%d) Stream5 global config is NULL.\n",
                __FILE__, __LINE__);
    }

    if (pPolicyConfig->global_config->track_tcp_sessions)
    {
        tcpNotConfigured = Stream5VerifyTcpConfig(pPolicyConfig->tcp_config, policyId);
        if (tcpNotConfigured)
        {
            ErrorMessage("WARNING: Stream5 TCP misconfigured\n");
        }
        else
        {
            if (policyId == 0)
                total_sessions += pPolicyConfig->global_config->max_tcp_sessions;

            proto_flags |= PROTO_BIT__TCP;
        }
    }

    if (pPolicyConfig->global_config->track_udp_sessions)
    {
        udpNotConfigured = Stream5VerifyUdpConfig(pPolicyConfig->udp_config, policyId);
        if (udpNotConfigured)
        {
            ErrorMessage("WARNING: Stream5 UDP misconfigured\n");
        }
        else
        {
            if (policyId == 0)
                total_sessions += pPolicyConfig->global_config->max_udp_sessions;

            proto_flags |= PROTO_BIT__UDP;
        }
    }

    if (pPolicyConfig->global_config->track_icmp_sessions)
    {
        icmpNotConfigured = Stream5VerifyIcmpConfig(pPolicyConfig->icmp_config, policyId);
        if (icmpNotConfigured)
        {
            ErrorMessage("WARNING: Stream5 ICMP misconfigured\n");
        }
        else
        {
            if (policyId == 0)
                total_sessions += pPolicyConfig->global_config->max_icmp_sessions;

            proto_flags |= PROTO_BIT__ICMP;
        }
    }

    if ((policyId == 0) && (total_sessions == 0))
    {
        ErrorMessage("WARNING: Stream5 enabled, but not tracking any "
                "of TCP, UDP or ICMP.\n");
    }

    if (tcpNotConfigured || udpNotConfigured ||
            icmpNotConfigured || ((policyId == 0) && (total_sessions == 0)))
    {
        FatalError("Stream5 not properly configured... exiting\n");
    }

    setParserPolicy(policyId);
    AddFuncToPreprocList(Stream5Process, PRIORITY_TRANSPORT, PP_STREAM5, proto_flags);
    setParserPolicy(tmp_policy_id);

    return 0;
}

static void Stream5VerifyConfig(void)
{
    int obj_size = 0;

    if (s5_config == NULL)
        return;

    total_sessions = 0;

    sfPolicyUserDataIterate (s5_config, Stream5VerifyConfigPolicy);

    /* Initialize the memory pool for Flowbits Data */
    /* use giFlowbitSize - 1, since there is already 1 byte in the
     * StreamFlowData structure */
    obj_size = sizeof(StreamFlowData) + giFlowbitSize - 1;

    if (obj_size % sizeof(long) != 0)
    {
        /* Increase obj_size by sizeof(long) to force sizeof(long) byte
         * alignment for each object in the mempool.  Without this,
         * the mempool data buffer was not aligned. Overlaying the
         * StreamFlowData structure caused problems on some Solaris
         * platforms. */
        obj_size += ( sizeof(long) - (obj_size % sizeof(long)));
    }

    if (mempool_init(&s5FlowMempool, total_sessions, obj_size) != 0)
    {
        FatalError("%s(%d) Could not initialize flow bits memory pool.\n",
                   __FILE__, __LINE__);
    }

#ifdef TARGET_BASED
    s5InitServiceFilterStatus();
#endif
}

static void Stream5PrintStats(int exiting)
{
    LogMessage("Stream5 statistics:\n");
    LogMessage("            Total sessions: %lu\n",
            s5stats.total_tcp_sessions +
            s5stats.total_udp_sessions +
            s5stats.total_icmp_sessions);
    LogMessage("              TCP sessions: %lu\n", s5stats.total_tcp_sessions);
    LogMessage("              UDP sessions: %lu\n", s5stats.total_udp_sessions);
    LogMessage("             ICMP sessions: %lu\n", s5stats.total_icmp_sessions);

    LogMessage("                TCP Prunes: %lu\n", s5stats.tcp_prunes);
    LogMessage("                UDP Prunes: %lu\n", s5stats.udp_prunes);
    LogMessage("               ICMP Prunes: %lu\n", s5stats.icmp_prunes);
    LogMessage("TCP StreamTrackers Created: %lu\n",
            s5stats.tcp_streamtrackers_created);
    LogMessage("TCP StreamTrackers Deleted: %lu\n",
            s5stats.tcp_streamtrackers_released);
    LogMessage("              TCP Timeouts: %lu\n", s5stats.tcp_timeouts);
    LogMessage("              TCP Overlaps: %lu\n", s5stats.tcp_overlaps);
    LogMessage("       TCP Segments Queued: %lu\n", s5stats.tcp_streamsegs_created);
    LogMessage("     TCP Segments Released: %lu\n", s5stats.tcp_streamsegs_released);
    LogMessage("       TCP Rebuilt Packets: %lu\n", s5stats.tcp_rebuilt_packets);
    LogMessage("         TCP Segments Used: %lu\n", s5stats.tcp_rebuilt_seqs_used);
    LogMessage("              TCP Discards: %lu\n", s5stats.tcp_discards);
    LogMessage("      UDP Sessions Created: %lu\n",
            s5stats.udp_sessions_created);
    LogMessage("      UDP Sessions Deleted: %lu\n",
            s5stats.udp_sessions_released);
    LogMessage("              UDP Timeouts: %lu\n", s5stats.udp_timeouts);
    LogMessage("              UDP Discards: %lu\n", s5stats.udp_discards);
    LogMessage("                    Events: %lu\n", s5stats.events);
    LogMessage("           Internal Events: %lu\n", s5stats.internalEvents);
    LogMessage("           TCP Port Filter\n");
    LogMessage("                   Dropped: %lu\n", s5stats.tcp_port_filter.dropped);
    LogMessage("                 Inspected: %lu\n", s5stats.tcp_port_filter.inspected);
    LogMessage("                   Tracked: %lu\n", s5stats.tcp_port_filter.session_tracked);
    LogMessage("           UDP Port Filter\n");
    LogMessage("                   Dropped: %lu\n", s5stats.udp_port_filter.dropped);
    LogMessage("                 Inspected: %lu\n", s5stats.udp_port_filter.inspected);
    LogMessage("                   Tracked: %lu\n", s5stats.udp_port_filter.session_tracked);
}

/*
 * MAIN ENTRY POINT
 */
void Stream5Process(Packet *p, void *context)
{
    SessionKey key;
    Stream5LWSession *lwssn;
    PROFILE_VARS;

    if (!firstPacketTime)
        firstPacketTime = p->pkth->ts.tv_sec;

    if(!IsEligible(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, "Is not eligible!\n"););
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, "In Stream5!\n"););

    PREPROC_PROFILE_START(s5PerfStats);

    /* Call individual TCP/UDP/ICMP processing, per GET_IPH_PROTO(p) */
    switch(GET_IPH_PROTO(p))
    {
        case IPPROTO_TCP:
            {
                Stream5TcpPolicy *policy = NULL;

                lwssn = GetLWSession(tcp_lws_cache, p, &key);
                if (lwssn != NULL)
                    policy = (Stream5TcpPolicy *)lwssn->policy;

                if (Stream5SetRuntimeConfiguration(lwssn, IPPROTO_TCP) == -1)
                    return;

                if (s5_global_eval_config->track_tcp_sessions)
                    Stream5ProcessTcp(p, lwssn, policy, &key);
            }

            break;

        case IPPROTO_UDP:
            {
                Stream5UdpPolicy *policy = NULL;

                lwssn = GetLWSession(udp_lws_cache, p, &key);
                if (lwssn != NULL)
                    policy = (Stream5UdpPolicy *)lwssn->policy;

                if (Stream5SetRuntimeConfiguration(lwssn, IPPROTO_UDP) == -1)
                    return;

                if (s5_global_eval_config->track_udp_sessions)
                    Stream5ProcessUdp(p, lwssn, policy, &key);
            }

            break;

        case IPPROTO_ICMP:
            if (Stream5SetRuntimeConfiguration(NULL, IPPROTO_ICMP) == -1)
                return;

            if (s5_global_eval_config->track_icmp_sessions)
                Stream5ProcessIcmp(p);

            break;

        default:
            break;
    }

    PREPROC_PROFILE_END(s5PerfStats);
}

static INLINE int IsEligible(Packet *p)
{
    if ((p->frag_flag) || (p->csum_flags & CSE_IP))
        return 0;

    if (p->packet_flags & PKT_REBUILT_STREAM)
        return 0;

    if (!IPH_IS_VALID(p))
        return 0;

    switch(GET_IPH_PROTO(p))
    {
        case IPPROTO_TCP:
        {
             if(p->tcph == NULL)
                 return 0;

             if (p->csum_flags & CSE_TCP)
                 return 0;
        }
        break;
        case IPPROTO_UDP:
        {
             if(p->udph == NULL)
                 return 0;

             if (p->csum_flags & CSE_UDP)
                 return 0;
        }
        break;
        case IPPROTO_ICMP:
        {
             if(p->icmph == NULL)
                 return 0;

             if (p->csum_flags & CSE_ICMP)
                 return 0;
        }
        break;
        default:
            return 0;
    }

    return 1;
}

/*************************** API Implementations *******************/
static void Stream5SetApplicationData(
                    void *ssnptr,
                    uint32_t protocol,
                    void *data,
                    StreamAppDataFree free_func)
{
    Stream5LWSession *ssn;
    Stream5AppData *appData = NULL;
    if (ssnptr)
    {
        ssn = (Stream5LWSession*)ssnptr;
        appData = ssn->appDataList;
        while (appData)
        {
            if (appData->protocol == protocol)
            {
                /* If changing the pointer to the data, free old one */
                if ((appData->freeFunc) && (appData->dataPointer != data))
                {
                    appData->freeFunc(appData->dataPointer);
                }
                else
                {
                    /* Same pointer, same protocol.  Go away */
                    break;
                }

                appData->dataPointer = NULL;
                break;
            }

            appData = appData->next;
        }

        /* If there isn't one for this protocol, allocate */
        if (!appData)
        {
            appData = SnortAlloc(sizeof(Stream5AppData));

            /* And add it to the list */
            if (ssn->appDataList)
            {
                ssn->appDataList->prev = appData;
            }
            appData->next = ssn->appDataList;
            ssn->appDataList = appData;
        }

        /* This will reset free_func if it already exists */
        appData->protocol = protocol;
        appData->freeFunc = free_func;
        appData->dataPointer = data;
    }
}

static void *Stream5GetApplicationData(
                    void *ssnptr,
                    uint32_t protocol)
{
    Stream5LWSession *ssn;
    Stream5AppData *appData = NULL;
    void *data = NULL;
    if (ssnptr)
    {
        ssn = (Stream5LWSession*)ssnptr;
        appData = ssn->appDataList;
        while (appData)
        {
            if (appData->protocol == protocol)
            {
                data = appData->dataPointer;
                break;
            }
            appData = appData->next;
        }
    }
    return data;
}

static int Stream5AlertFlushStream(Packet *p)
{
    Stream5LWSession *ssn;

    if (!p || !p->ssnptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush NULL packet or session\n"););
        return 0;
    }

    ssn = p->ssnptr;
    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    if (!(s5_global_eval_config->flags & STREAM5_CONFIG_FLUSH_ON_ALERT))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush on alert from individual packet\n"););
        return 0;
    }

    if ((ssn->protocol != IPPROTO_TCP) ||
        (p->packet_flags & PKT_REBUILT_STREAM))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush on rebuilt packets\n"););
        return 0;
    }

    /* Flush the listener queue -- this is the same side that
     * the packet gets inserted into */
    Stream5FlushListener(p, ssn);

    return 0;
}

static int Stream5ResponseFlushStream(Packet *p)
{
    Stream5LWSession *ssn;

    if ((p == NULL) || (p->ssnptr == NULL))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush NULL packet or session\n"););
        return 0;
    }

    ssn = p->ssnptr;
    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    if ((ssn->protocol != IPPROTO_TCP) ||
        (p->packet_flags & PKT_REBUILT_STREAM))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush on rebuilt packets\n"););
        return 0;
    }

    /* Flush the talker queue -- this is the opposite side that
     * the packet gets inserted into */
    Stream5FlushTalker(p, ssn);

    return 0;
}

static uint32_t Stream5SetSessionFlags(
                    void *ssnptr,
                    uint32_t flags)
{
    Stream5LWSession *ssn;
    if (ssnptr)
    {
        ssn = (Stream5LWSession *)ssnptr;
        ssn->session_flags |= flags;
        return ssn->session_flags;
    }

    return 0;
}

static uint32_t Stream5GetSessionFlags(void *ssnptr)
{
    Stream5LWSession *ssn;
    if (ssnptr)
    {
        ssn = (Stream5LWSession *)ssnptr; 
        return ssn->session_flags;
    }

    return 0;
}

static int Stream5AddSessionAlert(void *ssnptr,
                                  Packet *p,
                                  uint32_t gid,
                                  uint32_t sid)
{
    Stream5LWSession *ssn;
    if (ssnptr)
    {
        ssn = (Stream5LWSession *)ssnptr;
        if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
            return 0;
        switch (GET_IPH_PROTO(p))
        {
            case IPPROTO_TCP:
                return Stream5AddSessionAlertTcp(ssn, p, gid, sid);
                break;
#if 0 /* Don't need to do this for UDP/ICMP because they don't
         do any reassembly. */
            case IPPROTO_UDP:
                return Stream5AddSessionAlertUdp(ssn, p, gid, sid);
                break;
            case IPPROTO_ICMP:
                return Stream5AddSessionAlertIcmp(ssn, p, gid, sid);
                break;
#endif
        }
    }

    return 0;
}

/* return non-zero if gid/sid have already been seen */
static int Stream5CheckSessionAlert(void *ssnptr,
                                    Packet *p,
                                    uint32_t gid,
                                    uint32_t sid)
{
    Stream5LWSession *ssn;

    if (ssnptr)
    {
        ssn = (Stream5LWSession *)ssnptr;
        if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
            return 0;
        switch (GET_IPH_PROTO(p))
        {
            case IPPROTO_TCP:
                return Stream5CheckSessionAlertTcp(ssn, p, gid, sid);
                break;
#if 0 /* Don't need to do this for UDP/ICMP because they don't
         do any reassembly. */
            case IPPROTO_UDP:
                return Stream5CheckSessionAlertUdp(ssn, p, gid, sid);
                break;
            case IPPROTO_ICMP:
                return Stream5CheckSessionAlertIcmp(ssn, p, gid, sid);
                break;
#endif
        }
    }
    return 0;
}

static int Stream5IgnoreChannel(
                    snort_ip_p      srcIP,
                    uint16_t srcPort,
                    snort_ip_p      dstIP,
                    uint16_t dstPort,
                    char protocol,
                    char direction,
                    char flags)
{
    return IgnoreChannel(srcIP, srcPort, dstIP, dstPort,
                         protocol, direction, flags, 300);
}

void Stream5DisableInspection(Stream5LWSession *lwssn, Packet *p)
{
    /*
     * Don't want to mess up PortScan by "dropping"
     * this packet.
     *
     * Also still want the perfmon to collect the stats.
     *
     * And don't want to do any detection with rules
     */
    DisableDetect(p);
    SetPreprocBit(p, PP_SFPORTSCAN);
    SetPreprocBit(p, PP_PERFMONITOR);
    otn_tmp = NULL;
}

static void Stream5StopInspection(
                    void * ssnptr,
                    Packet *p,
                    char dir,
                    int32_t bytes,
                    int response)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    switch (dir)
    {
        case SSN_DIR_BOTH:
            ssn->ignore_direction = dir;
            break;
        case SSN_DIR_CLIENT:
            ssn->ignore_direction = dir;
            break;
        case SSN_DIR_SERVER:
            ssn->ignore_direction = dir;
            break;
    }

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return;

    /* Flush any queued data on the client and/or server */
    if (ssn->protocol == IPPROTO_TCP)
    {
        if (ssn->ignore_direction & SSN_DIR_CLIENT)
        {
            Stream5FlushClient(p, ssn);
        }

        if (ssn->ignore_direction & SSN_DIR_SERVER)
        {
            Stream5FlushServer(p, ssn);
        }
    }

    /* TODO: Handle bytes/response parameters */

    Stream5DisableInspection(ssn, p);
}

static void Stream5ResumeInspection(
                    void *ssnptr,
                    char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    switch (dir)
    {
        case SSN_DIR_BOTH:
            ssn->ignore_direction &= ~dir;
            break;
        case SSN_DIR_CLIENT:
            ssn->ignore_direction &= ~dir;
            break;
        case SSN_DIR_SERVER:
            ssn->ignore_direction &= ~dir;
            break;
    }

}

static void Stream5UpdateDirection(
                    void * ssnptr,
                    char dir,
                    snort_ip_p ip,
                    uint16_t port)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return;

    switch (ssn->protocol)
    {
        case IPPROTO_TCP:
            TcpUpdateDirection(ssn, dir, ip, port);
            break;
        case IPPROTO_UDP:
            UdpUpdateDirection(ssn, dir, ip, port);
            break;
        case IPPROTO_ICMP:
            //IcmUpdateDirection(ssn, dir, ip, port);
            break;
    }
}

static uint32_t Stream5GetPacketDirection(Packet *p)
{
    Stream5LWSession *lwssn;
    
    if (!p || !(p->ssnptr))
        return 0;
    
    lwssn = (Stream5LWSession *)p->ssnptr;
    if (Stream5SetRuntimeConfiguration(lwssn, lwssn->protocol) == -1)
        return 0;

    GetLWPacketDirection(p, lwssn);

    return (p->packet_flags & (PKT_FROM_SERVER|PKT_FROM_CLIENT));
}

static void Stream5DropTraffic(
                    void *ssnptr,
                    char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    if (dir & SSN_DIR_CLIENT)
    {
        ssn->session_flags |= STREAM5_STATE_DROP_CLIENT;
        ssn->session_flags |= SSNFLAG_DROP_CLIENT;
    }

    if (dir & SSN_DIR_SERVER)
    {
        ssn->session_flags |= STREAM5_STATE_DROP_SERVER;
        ssn->session_flags |= SSNFLAG_DROP_SERVER;
    }

    /* XXX: Issue resets if TCP or ICMP Unreach if UDP? */
}

static void Stream5DropPacket(
                            Packet *p)
{
    Stream5TcpBlockPacket(p);
    Stream5DropTraffic(p->ssnptr, SSN_DIR_BOTH);
}

static int Stream5GetRebuiltPackets(
                            Packet *p,
                            PacketIterator callback,
                            void *userdata)
{
    Stream5LWSession *ssn = (Stream5LWSession*)p->ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 0;

    /* Only if this is a rebuilt packet */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
        return 0;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    return GetTcpRebuiltPackets(p, ssn, callback, userdata);
}

static StreamFlowData *Stream5GetFlowData(Packet *p)
{
#if 0
    FLOW *fp;
    FLOWDATA *flowdata;
    if (!p->flow)
        return NULL;

    fp = (FLOW *)p->flow;
    flowdata = &fp->data;

    return (StreamFlowData *)flowdata;
#endif
    Stream5LWSession *ssn = (Stream5LWSession*)p->ssnptr;

    if (!ssn)
        return NULL;

    return (StreamFlowData *)ssn->flowdata->data;
}

static char Stream5GetReassemblyDirection(void *ssnptr)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return SSN_DIR_NONE;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return SSN_DIR_NONE;

    return Stream5GetReassemblyDirectionTcp(ssn);
}

static uint32_t Stream5GetFlushPoint(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if ((ssn == NULL) || (ssn->protocol != IPPROTO_TCP))
        return 0;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    return Stream5GetFlushPointTcp(ssn, dir);
}

static void Stream5SetFlushPoint(void *ssnptr, char dir, uint32_t flush_point)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if ((ssn == NULL) || (ssn->protocol != IPPROTO_TCP))
        return;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return;

    Stream5SetFlushPointTcp(ssn, dir, flush_point);
}

static char Stream5SetReassembly(void *ssnptr,
                                   uint8_t flush_policy,
                                   char dir,
                                   char flags)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 0;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    return Stream5SetReassemblyTcp(ssn, flush_policy, dir, flags);
}

static char Stream5GetReassemblyFlushPolicy(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return STREAM_FLPOLICY_NONE;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return STREAM_FLPOLICY_NONE;

    return Stream5GetReassemblyFlushPolicyTcp(ssn, dir);
}

static char Stream5IsStreamSequenced(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 1;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 1;

    return Stream5IsStreamSequencedTcp(ssn, dir);
}

static int Stream5MissingInReassembled(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return SSN_MISSING_NONE;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return SSN_MISSING_NONE;

    return Stream5MissingInReassembledTcp(ssn, dir);
}

static char Stream5PacketsMissing(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 1;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 1;

    return Stream5PacketsMissingTcp(ssn, dir);
}

static void s5SetPortFilterStatus(
        int protocol, 
        uint16_t port, 
        int status,
        tSfPolicyId policyId,
        int parsing
        )
{
    switch (protocol)
    {
        case IPPROTO_TCP:
            s5TcpSetPortFilterStatus(port, status, policyId, parsing);
            break;
        case IPPROTO_UDP:
            s5UdpSetPortFilterStatus(port, status, policyId, parsing);
            break;
        case IPPROTO_ICMP:
            break;
        default:
            break;
    }
}

#ifdef TARGET_BASED
void Stream5SetIPProtocol(Stream5LWSession *lwssn)
{
    switch (lwssn->protocol)
    {
    case IPPROTO_TCP:
        lwssn->ipprotocol = FindProtocolReference("tcp");
        break;
    case IPPROTO_UDP:
        lwssn->ipprotocol = FindProtocolReference("udp");
        break;
    case IPPROTO_ICMP:
        lwssn->ipprotocol = FindProtocolReference("icmp");
        break;
    }
}

void Stream5SetApplicationProtocolIdFromHostEntry(Stream5LWSession *lwssn,
                                           HostAttributeEntry *host_entry,
                                           int direction)
{
    if (!lwssn || !host_entry)
        return;

    /* Cool, its already set! */
    if (lwssn->application_protocol != 0)
        return;

    if (lwssn->ipprotocol == 0)
    {
        Stream5SetIPProtocol(lwssn);
    }

    if (direction == SSN_DIR_SERVER)
    {
        lwssn->application_protocol = getApplicationProtocolId(host_entry,
                                        lwssn->ipprotocol,
                                        ntohs(lwssn->server_port),
                                        SFAT_SERVICE);
    }
    else
    {
        lwssn->application_protocol = getApplicationProtocolId(host_entry,
                                        lwssn->ipprotocol,
                                        ntohs(lwssn->client_port),
                                        SFAT_SERVICE);
    }
}

static void s5InitServiceFilterStatus(void)
{
    SFGHASH_NODE *hashNode;
    tSfPolicyId policyId = 0;
    SnortConfig *sc = snort_conf_for_parsing;

    if (sc == NULL)
    {
        FatalError("%s(%d) Snort config for parsing is NULL.\n",
                   __FILE__, __LINE__);
    }

    for (hashNode = sfghash_findfirst(sc->otn_map);
         hashNode;
         hashNode = sfghash_findnext(sc->otn_map))
    {
        OptTreeNode *otn = (OptTreeNode *)hashNode->data;

        for ( policyId = 0; 
              policyId < otn->proto_node_num; 
              policyId++)
        {
            RuleTreeNode *rtn = getRtnFromOtn(otn, policyId);

            if (rtn && (rtn->proto == IPPROTO_TCP))
            { 
                unsigned int svc_idx;

                for (svc_idx = 0; svc_idx < otn->sigInfo.num_services; svc_idx++)
                {
                    if (otn->sigInfo.services[svc_idx].service_ordinal)
                    {
                        s5SetServiceFilterStatus
                            (otn->sigInfo.services[svc_idx].service_ordinal,
                             PORT_MONITOR_SESSION, policyId, 1);
                    }
                }
            }
        }
    }
}

static void s5SetServiceFilterStatus(
        int protocolId, 
        int status,
        tSfPolicyId policyId,
        int parsing
        )
{
    Stream5Config *config;

#ifdef SNORT_RELOAD
    if (parsing && (s5_swap_config != NULL))
        config = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policyId);
    else
#endif
    config = (Stream5Config *)sfPolicyUserDataGet(s5_config, policyId);

    if (config == NULL)
        return;

    config->service_filter[protocolId] = status;
}

static int s5GetServiceFilterStatus (
        int protocolId,
        tSfPolicyId policyId,
        int parsing
        )
{
    Stream5Config *config;

#ifdef SNORT_RELOAD
    if (parsing && (s5_swap_config != NULL))
        config = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policyId);
    else
#endif
    config = (Stream5Config *)sfPolicyUserDataGet(s5_config, policyId);

    if (config == NULL)
        return PORT_MONITOR_NONE;

    return config->service_filter[protocolId];
}

static int16_t Stream5GetApplicationProtocolId(void *ssnptr)
{
    Stream5LWSession *lwssn = (Stream5LWSession *)ssnptr;
    /* Not caching the source and dest host_entry in the session so we can
     * swap the table out after processing this packet if we need
     * to.  */
    HostAttributeEntry *host_entry = NULL;
    int16_t protocol = 0;

    if (!lwssn)
        return protocol;

    if (lwssn->application_protocol != 0)
        return lwssn->application_protocol;

    if (!IsAdaptiveConfigured(getRuntimePolicy(), 0))
        return lwssn->application_protocol;

    if (Stream5SetRuntimeConfiguration(lwssn, lwssn->protocol) == -1)
        return lwssn->application_protocol;

    if (lwssn->ipprotocol == 0)
    {
        Stream5SetIPProtocol(lwssn);
    }

#ifdef SUP_IP6
    host_entry = SFAT_LookupHostEntryByIP(&lwssn->server_ip);
#else
    host_entry = SFAT_LookupHostEntryByIp4Addr(ntohl(lwssn->server_ip));
#endif
    if (host_entry)
    {
        Stream5SetApplicationProtocolIdFromHostEntry(lwssn,
                                           host_entry, SSN_DIR_SERVER);

        if (lwssn->application_protocol != 0)
        {
            return lwssn->application_protocol;
        }
    }

#ifdef SUP_IP6
    host_entry = SFAT_LookupHostEntryByIP(&lwssn->client_ip);
#else
    host_entry = SFAT_LookupHostEntryByIp4Addr(ntohl(lwssn->client_ip));
#endif
    if (host_entry)
    {
        Stream5SetApplicationProtocolIdFromHostEntry(lwssn,
                                           host_entry, SSN_DIR_CLIENT);
        if (lwssn->application_protocol != 0)
        {
            return lwssn->application_protocol;
        }
    }

    return lwssn->application_protocol;
}

static int16_t Stream5SetApplicationProtocolId(void *ssnptr, int16_t id)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;
    if (!ssn)
        return 0;

    if (!IsAdaptiveConfigured(getRuntimePolicy(), 0))
        return 0;

    ssn->application_protocol = id;

    return id;
}
#endif

int isPacketFilterDiscard(
        Packet *p,
        int ignore_any_rules
        )
{
    uint8_t  action = 0;
    tPortFilterStats   *pPortFilterStats = NULL;
    tSfPolicyId policy_id = getRuntimePolicy();
#ifdef TARGET_BASED
    int protocolId = GetProtocolReference(p);
#endif

#ifdef TARGET_BASED
    if ((protocolId > 0) && s5GetServiceFilterStatus(protocolId, policy_id, 0))
    {
        return PORT_MONITOR_PACKET_PROCESS;
    }
#endif

    switch(GET_IPH_PROTO(p))
    {
        case IPPROTO_TCP:
            if ((s5_global_eval_config != NULL) &&
                s5_global_eval_config->track_tcp_sessions)
            {
                action = s5TcpGetPortFilterStatus(p->sp, policy_id, 0) |
                    s5TcpGetPortFilterStatus(p->dp, policy_id, 0);
            }

            pPortFilterStats = &s5stats.tcp_port_filter;
            break;

        case IPPROTO_UDP:
            if ((s5_global_eval_config != NULL) &&
                s5_global_eval_config->track_udp_sessions)
            {
                action = s5UdpGetPortFilterStatus(p->sp, policy_id, 0) |
                    s5UdpGetPortFilterStatus(p->dp, policy_id, 0);
            }

            pPortFilterStats = &s5stats.udp_port_filter;
            break;
        default:
            return PORT_MONITOR_PACKET_PROCESS;
    }

    if (!(action & PORT_MONITOR_SESSION))
    {
        if (!(action & PORT_MONITOR_INSPECT) && ignore_any_rules)
        {
            /* Ignore this TCP packet entirely */
            DisableDetect(p);
            SetPreprocBit(p, PP_SFPORTSCAN);
            SetPreprocBit(p, PP_PERFMONITOR);
            //otn_tmp = NULL;
            pPortFilterStats->dropped++;
        }
        else
        {
            pPortFilterStats->inspected++;
        }

        return PORT_MONITOR_PACKET_DISCARD;
    }

    pPortFilterStats->session_tracked++;
    return PORT_MONITOR_PACKET_PROCESS;
}

#ifdef SNORT_RELOAD
static void Stream5GlobalReload(char *args)
{
    tSfPolicyId policy_id = getParserPolicy();
    Stream5Config *pDefaultPolicyConfig = NULL;
    Stream5Config *pCurrentPolicyConfig = NULL;

    if (s5_swap_config == NULL)
    {
        //create a context
        s5_swap_config = sfPolicyConfigCreate();
        AddFuncToPreprocReloadVerifyList(Stream5ReloadVerify);
    }

    sfPolicyUserPolicySet (s5_swap_config, policy_id);

    pDefaultPolicyConfig = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, getDefaultPolicy());
    pCurrentPolicyConfig = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policy_id);

    if ((policy_id != getDefaultPolicy()) && (pDefaultPolicyConfig == NULL))
    {
        ParseError("Stream5: Must configure default policy if other targeted "
                   "policies are configured.\n");
    }

    if (pCurrentPolicyConfig != NULL)
    {
        FatalError("%s(%d) ==> Cannot duplicate Stream5 global "
                   "configuration\n", file_name, file_line);
    }

    pCurrentPolicyConfig = (Stream5Config *)SnortAlloc(sizeof(Stream5Config));
    sfPolicyUserDataSetCurrent(s5_swap_config, pCurrentPolicyConfig);

    pCurrentPolicyConfig->global_config =
        (Stream5GlobalConfig *)SnortAlloc(sizeof(Stream5GlobalConfig));

    pCurrentPolicyConfig->global_config->track_tcp_sessions = S5_TRACK_YES;
    pCurrentPolicyConfig->global_config->max_tcp_sessions = S5_DEFAULT_MAX_TCP_SESSIONS;
    pCurrentPolicyConfig->global_config->track_udp_sessions = S5_TRACK_YES;
    pCurrentPolicyConfig->global_config->max_udp_sessions = S5_DEFAULT_MAX_UDP_SESSIONS;
    pCurrentPolicyConfig->global_config->track_icmp_sessions = S5_TRACK_NO;
    pCurrentPolicyConfig->global_config->max_icmp_sessions = S5_DEFAULT_MAX_ICMP_SESSIONS;
    pCurrentPolicyConfig->global_config->memcap = S5_DEFAULT_MEMCAP;
    pCurrentPolicyConfig->global_config->prune_log_max = S5_DEFAULT_PRUNE_LOG_MAX;

    Stream5ParseGlobalArgs(pCurrentPolicyConfig->global_config, args);

    if ((pCurrentPolicyConfig->global_config->track_tcp_sessions == S5_TRACK_NO) &&
        (pCurrentPolicyConfig->global_config->track_udp_sessions == S5_TRACK_NO) &&
        (pCurrentPolicyConfig->global_config->track_icmp_sessions == S5_TRACK_NO))
    {
        FatalError("%s(%d) ==> Stream5 enabled, but not configured to track "
                   "TCP, UDP, or ICMP.\n", file_name, file_line);
    }

    if (policy_id != getDefaultPolicy())
    {
        pCurrentPolicyConfig->global_config->max_tcp_sessions =
            pDefaultPolicyConfig->global_config->max_tcp_sessions;
        pCurrentPolicyConfig->global_config->max_udp_sessions =
            pDefaultPolicyConfig->global_config->max_udp_sessions;
        pCurrentPolicyConfig->global_config->max_icmp_sessions =
            pDefaultPolicyConfig->global_config->max_icmp_sessions;
        pCurrentPolicyConfig->global_config->memcap =
            pDefaultPolicyConfig->global_config->memcap;
    }

    Stream5PrintGlobalConfig(pCurrentPolicyConfig->global_config);

    if (snort_conf_for_parsing == NULL)
    {
        FatalError("%s(%d) Snort config for parsing is NULL.\n",
                   __FILE__, __LINE__);
    }

    snort_conf_for_parsing->run_flags |= RUN_FLAG__STATEFUL;
}

static void Stream5TcpReload(char *args)
{
    tSfPolicyId policy_id = getParserPolicy();
    Stream5Config *config;

    if (s5_swap_config == NULL)
        FatalError("Tried to config stream5 TCP policy without global config!\n");

    config = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policy_id);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 TCP policy without global config!\n");
    }

    if (!config->global_config->track_tcp_sessions)
    {
        FatalError("Stream5 TCP Configuration specified, but TCP tracking is turned off\n");
    }

    if (config->tcp_config == NULL)
    {
        config->tcp_config = (Stream5TcpConfig *)SnortAlloc(sizeof(Stream5TcpConfig));

        Stream5TcpInitFlushPoints();
        Stream5TcpRegisterRuleOptions();
    }

    /* Call the protocol specific initializer */
    Stream5TcpPolicyInit(config->tcp_config, args);
}

static void Stream5UdpReload(char *args)
{
    tSfPolicyId policy_id = getParserPolicy();
    Stream5Config *config;

    if (s5_swap_config == NULL)
        FatalError("Tried to config stream5 UDP policy without global config!\n");

    config = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policy_id);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 UDP policy without global config!\n");
    }

    if (!config->global_config->track_udp_sessions)
    {
        FatalError("Stream5 UDP Configuration specified, but UDP tracking is turned off\n");
    }

    if (config->udp_config == NULL)
        config->udp_config = (Stream5UdpConfig *)SnortAlloc(sizeof(Stream5UdpConfig));

    /* Call the protocol specific initializer */
    Stream5UdpPolicyInit(config->udp_config, args);
}

static void Stream5IcmpReload(char *args)
{
    tSfPolicyId policy_id = getParserPolicy();
    Stream5Config *config;

    if (s5_swap_config == NULL)
        FatalError("Tried to config stream5 ICMP policy without global config!\n");

    config = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policy_id);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 ICMP policy without global config!\n");
    }

    if (!config->global_config->track_icmp_sessions)
    {
        FatalError("Stream5 ICMP Configuration specified, but ICMP tracking is turned off\n");
    }

    if (config->icmp_config == NULL)
        config->icmp_config = (Stream5IcmpConfig *)SnortAlloc(sizeof(Stream5IcmpConfig));

    /* Call the protocol specific initializer */
    Stream5IcmpPolicyInit(config->icmp_config, args);
}

static int Stream5ReloadSwapPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId, 
        void* pData
        )
{
    Stream5Config *pPolicyConfig = (Stream5Config *)pData;

    //do any housekeeping before freeing Stream5Config
    if (pPolicyConfig->ref_count == 0)
    {
        sfPolicyUserDataClear (config, policyId);
        Stream5FreeConfig(pPolicyConfig);
    }

    return 0;
}

static void * Stream5ReloadSwap(void)
{
    tSfPolicyUserContextId old_config = s5_config;

    if (s5_swap_config == NULL)
        return NULL;

    s5_config = s5_swap_config;
    s5_swap_config = NULL;

    sfPolicyUserDataIterate (old_config, Stream5ReloadSwapPolicy);

    if (sfPolicyUserPolicyGetActive(old_config) == 0)
        return (void *)old_config;

    return NULL;
}

static void Stream5ReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    Stream5FreeConfigs((tSfPolicyUserContextId )data);
}

static int Stream5ReloadVerifyPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId, 
        void* pData
        )
{
    Stream5Config *cc = (Stream5Config *)pData;
    Stream5Config *sc = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policyId);
    int tcpNotConfigured = 0;
    int udpNotConfigured = 0;
    int icmpNotConfigured = 0;
    PoolCount total_sessions = 0;
    int proto_flags = 0;

    //do any housekeeping before freeing Stream5Config

    if ((sc != NULL) && (cc != NULL))
    {
        if (sc->global_config == NULL)
        {
            FatalError("%s(%d) Stream5 global config is NULL.\n",
                    __FILE__, __LINE__);
        }

        if ((sc->global_config->track_tcp_sessions != cc->global_config->track_tcp_sessions) ||
                (sc->global_config->track_udp_sessions != cc->global_config->track_udp_sessions) ||
                (sc->global_config->track_icmp_sessions != cc->global_config->track_icmp_sessions))
        {
            ErrorMessage("Stream5 Reload: Changing tracking of TCP, UDP or ICMP "
                    "sessions requires a restart.\n");
            Stream5FreeConfigs(s5_swap_config);
            s5_swap_config = NULL;
            return -1;
        }

        if (sc->global_config->memcap != cc->global_config->memcap)
        {
            ErrorMessage("Stream5 Reload: Changing \"memcap\" requires a restart.\n");
            Stream5FreeConfigs(s5_swap_config);
            s5_swap_config = NULL;
            return -1;
        }

        if (sc->global_config->max_tcp_sessions != cc->global_config->max_tcp_sessions)
        {
            ErrorMessage("Stream5 Reload: Changing \"max_tcp\" requires a restart.\n");
            Stream5FreeConfigs(s5_swap_config);
            s5_swap_config = NULL;
            return -1;
        }

        if (sc->global_config->max_udp_sessions != cc->global_config->max_udp_sessions)
        {
            ErrorMessage("Stream5 Reload: Changing \"max_udp\" requires a restart.\n");
            Stream5FreeConfigs(s5_swap_config);
            s5_swap_config = NULL;
            return -1;
        }

        if (cc->global_config->max_icmp_sessions != sc->global_config->max_icmp_sessions)
        {
            ErrorMessage("Stream5 Reload: Changing \"max_icmp\" requires a restart.\n");
            Stream5FreeConfigs(s5_swap_config);
            s5_swap_config = NULL;
            return -1;
        }
    }

    if (sc == NULL)
        return 0;

    if (sc->global_config->track_tcp_sessions)
    {
        tcpNotConfigured = Stream5VerifyTcpConfig(sc->tcp_config, policyId);
        if (tcpNotConfigured)
        {
            ErrorMessage("WARNING: Stream5 TCP misconfigured\n");
        }
        else
        {
            if (policyId == 0)
                total_sessions += sc->global_config->max_tcp_sessions;

            proto_flags |= PROTO_BIT__TCP;
        }
    }

    if (sc->global_config->track_udp_sessions)
    {
        udpNotConfigured = Stream5VerifyUdpConfig(sc->udp_config, policyId);
        if (udpNotConfigured)
        {
            ErrorMessage("WARNING: Stream5 UDP misconfigured\n");
        }
        else
        {
            if (policyId == 0)
                total_sessions += sc->global_config->max_udp_sessions;

            proto_flags |= PROTO_BIT__UDP;
        }
    }

    if (sc->global_config->track_icmp_sessions)
    {
        icmpNotConfigured = Stream5VerifyIcmpConfig(sc->icmp_config, policyId);
        if (icmpNotConfigured)
        {
            ErrorMessage("WARNING: Stream5 ICMP misconfigured\n");
        }
        else
        {
            if (policyId == 0)
                total_sessions += sc->global_config->max_icmp_sessions;

            proto_flags |= PROTO_BIT__ICMP;
        }
    }

    if ((policyId == 0) && (total_sessions == 0))
    {
        ErrorMessage("WARNING: Stream5 enabled, but not tracking any "
                "of TCP, UDP or ICMP.\n");
    }

    if (tcpNotConfigured || udpNotConfigured ||
            icmpNotConfigured || ((policyId == 0) && (total_sessions == 0)))
    {
        FatalError("Stream5 not properly configured... exiting\n");
    }

    setParserPolicy(policyId);
    AddFuncToPreprocList(Stream5Process, PRIORITY_TRANSPORT, PP_STREAM5, proto_flags);

#ifdef TARGET_BASED
    s5InitServiceFilterStatus();
#endif

    return 0;
}

static int Stream5ReloadVerify(void)
{

    if ((s5_swap_config == NULL) || (s5_config == NULL))
        return 0;

    if (sfPolicyUserDataIterate(s5_config, Stream5ReloadVerifyPolicy) != 0)
        return -1;

    return 0;
}
#endif

