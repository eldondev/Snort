/* $Id$ */
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

/*
 *
 * Program: Snort
 *
 * Purpose: Check out the README file for info on what you can do
 *          with Snort.
 *
 * Author: Martin Roesch (roesch@clark.net)
 *
 * Comments: Ideas and code stolen liberally from Mike Borella's IP Grab
 *           program. Check out his stuff at http://www.borella.net.  I
 *           also have ripped some util functions from TCPdump, plus Mike's
 *           prog is derived from it as well.  All hail TCPdump....
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <timersub.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>

#ifndef WIN32
#include <netdb.h>
#endif

#ifdef HAVE_GETOPT_LONG
//#define _GNU_SOURCE
/* A GPL copy of getopt & getopt_long src code is now in sfutil */
# undef HAVE_GETOPT_LONG
#endif
#include <getopt.h>

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifndef WIN32
# include <grp.h>
# include <pwd.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#endif  /* !WIN32 */

#if !defined(CATCH_SEGV) && !defined(WIN32)
# include <sys/resource.h>
#endif

#ifdef MIMICK_IPV6
# include <net/ethernet.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip6.h>
# include <pcap.h>
#endif

#include "decode.h"
#include "snort.h"
#include "rules.h"
#include "plugbase.h"
#include "debug.h"
#include "util.h"
#include "parser.h"
#include "tag.h"
#include "log.h"
#include "detect.h"
#include "mstring.h"
#include "fpcreate.h"
#include "fpdetect.h"
#include "sfthreshold.h"
#include "rate_filter.h"
#include "packet_time.h"
#include "detection-plugins/sp_flowbits.h"
#include "preprocessors/spp_perfmonitor.h"
#include "preprocessors/perf-base.h"
#include "preprocessors/perf.h"
#include "mempool.h"
#include "strlcpyu.h"
#include "sflsq.h"
#include "sp_replace.h"
#include "output-plugins/spo_log_tcpdump.h"
#include "event_queue.h"
#include "asn1.h"
#include "inline.h"
#include "mpse.h"
#include "generators.h"
#include "ppm.h"
#include "profiler.h"
#include "dynamic-plugins/sp_dynamic.h"
#include "dynamic-plugins/sf_dynamic_define.h"

#ifdef HAVE_LIBPRELUDE
# include "output-plugins/spo_alert_prelude.h"
#endif

#ifdef DYNAMIC_PLUGIN
# include "dynamic-plugins/sf_dynamic_engine.h"
# include "dynamic-plugins/sf_dynamic_detection.h"
# define PROFILE_PREPROCS_NOREDEF
# include "dynamic-plugins/sf_dynamic_preprocessor.h"
# include "dynamic-plugins/sp_preprocopt.h"
#endif

#ifdef TARGET_BASED
# include "target-based/sftarget_reader.h"
#endif

#ifdef EXIT_CHECK
# include "cpuclock.h"
#endif
#include "sfActionQueue.h"

/* Macros *********************************************************************/
#ifndef DLT_LANE8023
/*
 * Old OPEN BSD Log format is 17.
 * Define DLT_OLDPFLOG unless DLT_LANE8023 (Suse 6.3) is already
 * defined in bpf.h.
 */
# define DLT_OLDPFLOG 17
#endif

#ifdef MIMICK_IPV6
# define ETYPE_8021Q 0x8100
# define ETYPE_IP    0x0800
# define ETYPE_IPV6  0x86dd
#endif

#define ALERT_MODE_OPT__NONE       "none"
#define ALERT_MODE_OPT__PKT_CNT    "packet-count"
#define ALERT_MODE_OPT__FULL       "full"
#define ALERT_MODE_OPT__FAST       "fast"
#define ALERT_MODE_OPT__CONSOLE    "console"
#define ALERT_MODE_OPT__CMG        "cmg"
#define ALERT_MODE_OPT__JH         "jh"
#define ALERT_MODE_OPT__DJR        "djr"
#define ALERT_MODE_OPT__AJK        "ajk"
#define ALERT_MODE_OPT__UNIX_SOCK  "unsock"
#define ALERT_MODE_OPT__TEST       "test"

#define LOG_MODE_OPT__NONE    "none"
#define LOG_MODE_OPT__PCAP    "pcap"
#define LOG_MODE_OPT__ASCII   "ascii"

#ifdef MPLS
# define MPLS_PAYLOAD_OPT__IPV4      "ipv4"
# define MPLS_PAYLOAD_OPT__IPV6      "ipv6"
# define MPLS_PAYLOAD_OPT__ETHERNET  "ethernet"
#endif


/* Data types *****************************************************************/
#ifdef MIMICK_IPV6
typedef struct ether_header EHDR;

typedef struct s_VHDR
{
    u_short vlan;
    u_short proto;

} VHDR;

typedef struct iphdr    IPHDR;
typedef struct ip6_hdr  IPV6;
typedef struct ip6_frag IP6_FRAG;
#endif

enum
{
    SIGLOC_PARSE_RULES_FILE = 1,
    SIGLOC_PCAP_LOOP
};

typedef enum _GetOptArgType
{
    LONGOPT_ARG_NONE = 0,
    LONGOPT_ARG_REQUIRED,
    LONGOPT_ARG_OPTIONAL

} GetOptArgType;


/* Globals ********************************************************************/
PacketCount pc;  /* packet count information */
uint32_t *netmasks = NULL;   /* precalculated netmask array */
char **protocol_names = NULL;
char *snort_conf_file = NULL;   /* -c */
char *snort_conf_dir = NULL;

SnortConfig *snort_cmd_line_conf = NULL;
SnortConfig *snort_conf = NULL;

#if defined(SNORT_RELOAD) && !defined(WIN32)
SnortConfig *snort_conf_new = NULL;
SnortConfig *snort_conf_old = NULL;
#endif

tSfActionQueueId decoderActionQ = NULL;
MemPool decoderAlertMemPool;

static struct timeval starttime;
static struct timeval endtime;

VarNode *cmd_line_var_list = NULL;
SF_LIST *pcap_object_list = NULL;

static long int pcap_loop_count = 0;
static SF_QUEUE *pcap_queue = NULL;
static SF_QUEUE *pcap_save_queue = NULL;
static char current_read_file[STD_BUF];

#if defined(INLINE_FAILOPEN) && !defined(GIDS) && !defined(WIN32)
static pthread_t inline_failopen_thread_id;
static pid_t inline_failopen_thread_pid;
static volatile int inline_failopen_thread_running = 0;
static volatile int inline_failopen_pcap_initialized = 0;
static int inline_failopen_pass_pkt_cnt = 0;
static void * SnortPostInitThread(void *);
static void PcapIgnorePacket(char *, struct pcap_pkthdr *, const u_char *);
#endif

static int exit_signal = 0;
static int usr_signal = 0;
#ifdef TIMESTATS
static int alrm_signal = 0;
#endif

#ifndef SNORT_RELOAD
static volatile int hup_signal = 0;
#else
/* hup_signal is incremented in the signal handler for SIGHUP which is handled
 * in the main thread.  The reload thread compares the hup_signal count to
 * reload_hups which it increments after an equality test between hup_signal
 * and reload_hups fails (which means we got a new SIGHUP).  They need to be
 * the same type and size to do this comparision.  See ReloadConfigThread() */
typedef uint32_t snort_hup_t; 
static volatile snort_hup_t hup_signal = 0;
static snort_hup_t reload_hups = 0;
#endif

#ifdef TARGET_BASED
pthread_t attribute_reload_thread_id;
pid_t attribute_reload_thread_pid;
volatile int attribute_reload_thread_running = 0;
volatile int attribute_reload_thread_stop = 0;
int reload_attribute_table_flags = 0;
#endif

static int done_processing = 0;

volatile int snort_initializing = 1;
static volatile int snort_exiting = 0;

#if defined(SNORT_RELOAD) && !defined(WIN32)
static volatile int snort_reload = 0;
static volatile int snort_swapped = 0;
static volatile int snort_reload_thread_created = 0;
static pthread_t snort_reload_thread_id;
static pid_t snort_reload_thread_pid;
#endif

const struct timespec thread_sleep = { 0, 100 };

PreprocConfigFuncNode *preproc_config_funcs = NULL;
OutputConfigFuncNode *output_config_funcs = NULL;
RuleOptConfigFuncNode *rule_opt_config_funcs = NULL;
RuleOptOverrideInitFuncNode *rule_opt_override_init_funcs = NULL;
RuleOptParseCleanupNode *rule_opt_parse_cleanup_list = NULL;

PreprocSignalFuncNode *preproc_restart_funcs = NULL;
PreprocSignalFuncNode *preproc_clean_exit_funcs = NULL;
PreprocSignalFuncNode *preproc_shutdown_funcs = NULL;
PreprocSignalFuncNode *preproc_reset_funcs = NULL;
PreprocSignalFuncNode *preproc_reset_stats_funcs = NULL;
PreprocStatsFuncNode *preproc_stats_funcs = NULL;

PluginSignalFuncNode *plugin_shutdown_funcs = NULL;
PluginSignalFuncNode *plugin_clean_exit_funcs = NULL;
PluginSignalFuncNode *plugin_restart_funcs = NULL;

OutputFuncNode *AlertList = NULL;   /* Alert function list */
OutputFuncNode *LogList = NULL;     /* Log function list */

#ifdef DYNAMIC_PLUGIN
DynamicRuleNode *dynamic_rules = NULL;
#endif

int datalink;   /* the datalink value */
pcap_t *pcap_handle = NULL;
char *pcap_interface = NULL;
uint32_t pcap_snaplen = SNAPLEN;

#ifndef WIN32
SO_PUBLIC int g_drop_pkt;        /* inline drop pkt flag */ 
SO_PUBLIC int g_pcap_test;       /* pcap test mode */
#endif

grinder_t grinder;

static int exit_logged = 0;

static int snort_argc = 0;
static char **snort_argv = NULL;

/* command line options for getopt */
#ifndef WIN32
# ifdef GIDS
#  ifndef IPFW
static char *valid_options = "?a:A:bB:c:CdDefF:g:G:h:Hi:Ik:K:l:L:m:Mn:NoOpP:qQr:R:sS:t:Tu:UvVw:XxyzZ:";
#  else
static char *valid_options = "?a:A:bB:c:CdDefF:g:G:h:Hi:IJ:k:K:l:L:m:Mn:NoOpP:qr:R:sS:t:Tu:UvVw:XxyzZ:";
#  endif /* IPFW */
# else
#  ifdef MIMICK_IPV6
/* Unix does not support an argument to -s <wink marty!> OR -E, -W */
static char *valid_options = "?a:A:bB:c:CdDefF:g:G:h:Hi:Ik:K:l:L:m:Mn:NoOpP:qQr:R:sS:t:Tu:UvVw:XxyzZ:6";
#  else
/* Unix does not support an argument to -s <wink marty!> OR -E, -W */
static char *valid_options = "?a:A:bB:c:CdDefF:g:G:h:Hi:Ik:K:l:L:m:Mn:NoOpP:qQr:R:sS:t:Tu:UvVw:XxyzZ:";
#  endif
# endif /* GIDS */
#else
/* Win32 does not support:  -D, -g, -m, -t, -u */
/* Win32 no longer supports an argument to -s, either! */
static char *valid_options = "?A:bB:c:CdeEfF:G:h:Hi:Ik:K:l:L:Mn:NoOpP:qr:R:sS:TUvVw:WXxyzZ:";
#endif

static struct option long_options[] =
{
   {"logid", LONGOPT_ARG_REQUIRED, NULL, 'G'},
   {"perfmon-file", LONGOPT_ARG_REQUIRED, NULL, 'Z'},
   {"snaplen", LONGOPT_ARG_REQUIRED, NULL, 'P'},
   {"version", LONGOPT_ARG_NONE, NULL, 'V'},
   {"help", LONGOPT_ARG_NONE, NULL, '?'},
   {"conf-error-out", LONGOPT_ARG_NONE, NULL,'x'},

#ifdef DYNAMIC_PLUGIN
   {"dynamic-engine-lib", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_ENGINE_FILE},
   {"dynamic-engine-lib-dir", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_ENGINE_DIRECTORY},
   {"dynamic-detection-lib", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_LIBRARY_FILE},
   {"dynamic-detection-lib-dir", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_LIBRARY_DIRECTORY},
   {"dump-dynamic-rules", LONGOPT_ARG_OPTIONAL, NULL, DUMP_DYNAMIC_RULES},
   {"dynamic-preprocessor-lib", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_PREPROC_FILE},
   {"dynamic-preprocessor-lib-dir", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_PREPROC_DIRECTORY},
#endif

   {"alert-before-pass", LONGOPT_ARG_NONE, NULL, ALERT_BEFORE_PASS},
   {"treat-drop-as-alert", LONGOPT_ARG_NONE, NULL, TREAT_DROP_AS_ALERT},
   {"process-all-events", LONGOPT_ARG_NONE, NULL, PROCESS_ALL_EVENTS},
   {"restart", LONGOPT_ARG_NONE, NULL, ARG_RESTART},
   {"pid-path", LONGOPT_ARG_REQUIRED, NULL, PID_PATH},
   {"create-pidfile", LONGOPT_ARG_NONE, NULL, CREATE_PID_FILE},
   {"nolock-pidfile", LONGOPT_ARG_NONE, NULL, NOLOCK_PID_FILE},
   {"disable-inline-initialization", LONGOPT_ARG_NONE, NULL, DISABLE_INLINE_INIT}, 

#ifdef INLINE_FAILOPEN
   {"disable-inline-init-failopen", LONGOPT_ARG_NONE, NULL, DISABLE_INLINE_FAILOPEN},
#endif

   {"nostamps", LONGOPT_ARG_NONE, NULL, NO_LOGGING_TIMESTAMPS},

#ifdef TARGET_BASED
   {"disable-attribute-reload-thread", LONGOPT_ARG_NONE, NULL, DISABLE_ATTRIBUTE_RELOAD},
#endif

   {"pcap-single", LONGOPT_ARG_REQUIRED, NULL, PCAP_SINGLE},
   {"pcap-file", LONGOPT_ARG_REQUIRED, NULL, PCAP_FILE_LIST},
   {"pcap-list", LONGOPT_ARG_REQUIRED, NULL, PCAP_LIST},

#ifndef WIN32
   {"pcap-dir", LONGOPT_ARG_REQUIRED, NULL, PCAP_DIR},
   {"pcap-filter", LONGOPT_ARG_REQUIRED, NULL, PCAP_FILTER},
   {"pcap-no-filter", LONGOPT_ARG_NONE, NULL, PCAP_NO_FILTER},
#endif

   {"pcap-loop", LONGOPT_ARG_REQUIRED, NULL, PCAP_LOOP},
   {"pcap-reset", LONGOPT_ARG_NONE, NULL, PCAP_RESET},
   {"pcap-show", LONGOPT_ARG_NONE, NULL, PCAP_SHOW},

#ifdef EXIT_CHECK
   {"exit-check", LONGOPT_ARG_REQUIRED, NULL, ARG_EXIT_CHECK},
#endif

   {"search-method", LONGOPT_ARG_REQUIRED, NULL, DETECTION_SEARCH_METHOD},
   {"man", LONGOPT_ARG_REQUIRED, NULL, DETECTION_SEARCH_METHOD},

#ifdef MPLS
   {"enable-mpls-multicast", LONGOPT_ARG_NONE, NULL, ENABLE_MPLS_MULTICAST},
   {"enable-mpls-overlapping-ip", LONGOPT_ARG_NONE, NULL, ENABLE_OVERLAPPING_IP},
   {"max-mpls-labelchain-len", LONGOPT_ARG_REQUIRED, NULL, MAX_MPLS_LABELCHAIN_LEN},
   {"mpls-payload-type", LONGOPT_ARG_REQUIRED, NULL, MPLS_PAYLOAD_TYPE},
#endif

   {"require-rule-sid", LONGOPT_ARG_NONE, NULL, REQUIRE_RULE_SID},

   {0, 0, 0, 0}
};


/* Externs *******************************************************************/

/* Undefine the one from sf_dynamic_preprocessor.h */
#ifdef PERF_PROFILING
extern PreprocStats detectPerfStats, decodePerfStats,
       totalPerfStats, eventqPerfStats, rulePerfStats, mpsePerfStats;
extern PreprocStats ruleCheckBitPerfStats, ruleSetBitPerfStats, ruleFailedFlowbitsPerfStats;
extern PreprocStats ruleRTNEvalPerfStats, ruleOTNEvalPerfStats, ruleHeaderNoMatchPerfStats;
extern PreprocStats ruleAddEventQPerfStats, ruleNQEventQPerfStats;
extern PreprocStats preprocRuleOptionPerfStats;
#endif

/* for getopt */
extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

extern SFBASE sfBase;
extern ListHead *head_tmp;

extern SnortConfig *snort_conf_for_parsing;


/* Private function prototypes ************************************************/
static void InitNetmasks(void);
static void InitProtoNames(void);

static void SnortInit(int, char **);
static void InitPidChrootAndPrivs(void);
static void ParseCmdLine(int, char **);
static int ShowUsage(char *);
static void PrintVersion(void);
static void SetSnortConfDir(void);
static void InitGlobals(void);
static SnortConfig * MergeSnortConfs(SnortConfig *, SnortConfig *);
static void InitSignals(void);
#if defined(NOCOREFILE) && !defined(WIN32)
static void SetNoCores(void);
#endif
static void SnortCleanup(int);

#ifdef DYNAMIC_PLUGIN
static void ParseCmdLineDynamicLibInfo(SnortConfig *, int, char *);
static DynamicLibInfo * DupDynamicLibInfo(DynamicLibInfo *);
static void FreeDynamicLibInfo(DynamicLibInfo *);
static void FreeDynamicLibInfos(SnortConfig *);
#endif

static void FreeOutputConfigs(OutputConfig *);
static void FreePreprocConfigs(SnortConfig *);
static void FreeRuleStateList(RuleState *);
static void FreeClassifications(ClassType *);
static void FreeReferences(ReferenceSystemNode *);
static void FreePlugins(SnortConfig *);
static void FreePreprocessors(SnortConfig *);

static void SnortPostInit(void);
static int SetPktProcessor(void);
static void * InterfaceThread(void *);
static void InitPcap(int);
static void OpenPcap(void);
static char * ConfigFileSearch(void);
static void PcapReset(void);
static void SetBpfFilter(char *);
static void SnortProcess(void);

#ifdef DYNAMIC_PLUGIN
static void LoadDynamicPlugins(SnortConfig *);
#endif

static void SnortIdle(void);
#ifndef WIN32
static void SnortStartThreads(void);
#endif

#ifdef MIMICK_IPV6
static int conv_ip4_to_ip6(const struct pcap_pkthdr *phdr,const  u_char *pkt, 
                           struct pcap_pkthdr *phdrx, u_char *pktx, 
                           int  encap46 )
#endif

/* Signal handler declarations ************************************************/
static void SigExitHandler(int);
static void SigUsrHandler(int);
static void SigHupHandler(int);

#ifdef TIMESTATS
static void SigAlrmHandler(int);
#endif

#if defined(SNORT_RELOAD) && !defined(WIN32)
static SnortConfig * ReloadConfig(void);
static void * ReloadConfigThread(void *);
static int VerifyReload(SnortConfig *);
static int VerifyOutputs(SnortConfig *, SnortConfig *);
#ifdef DYNAMIC_PLUGIN
static int VerifyLibInfos(DynamicLibInfo *, DynamicLibInfo *);
#endif  /* DYNAMIC_PLUGIN */
#endif  /* SNORT_RELOAD */


/* INLINE FUNCTION ************************************************************/
static INLINE void CheckForReload(void)
{

#if defined(SNORT_RELOAD) && !defined(WIN32)
    /* Check for a new configuration */
    if (snort_reload)
    {
        snort_reload = 0;
        /* There was an error reloading.  A non-reloadable configuration
         * option changed */
        if (snort_conf_new == NULL)
        {
#ifdef RELOAD_ERROR_FATAL
            CleanExit(1);
#else
            Restart();
#endif
        }
        snort_conf_old = snort_conf;
        snort_conf = snort_conf_new;
        snort_conf_new = NULL;
        SwapPreprocConfigurations();

        /* Need to do this here because there is potentially outstanding
         * state data pointing to the previous configuration.  A race
         * condition is created if these are free'd in the reload thread
         * where a double free could occur. */

        FreeSwappedPreprocConfigurations();
        snort_swapped = 1;
    }
#endif

}

/*  F U N C T I O N   D E F I N I T I O N S  **********************************/

/*
 *
 * Function: main(int, char *)
 *
 * Purpose:  Handle program entry and exit, call main prog sections
 *           This can handle both regular (command-line) style
 *           startup, as well as Win32 Service style startup.
 *
 * Arguments: See command line args in README file
 *
 * Returns: 0 => normal exit, 1 => exit on error
 *
 */
int main(int argc, char *argv[]) 
{
#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
    /* Do some sanity checking, because some people seem to forget to
     * put spaces between their parameters
     */
    if ((argc > 1) &&
        ((_stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_INSTALL_CMDLINE_PARAM)) == 0) ||
         (_stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_UNINSTALL_CMDLINE_PARAM)) == 0) ||
         (_stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_SHOW_CMDLINE_PARAM)) == 0)))
    {
        FatalError("You must have a space after the '%s' command-line parameter\n",
                   SERVICE_CMDLINE_PARAM);
    }

    /* If the first parameter is "/SERVICE", then start Snort as a Win32 service */
    if((argc > 1) && (_stricmp(argv[1],SERVICE_CMDLINE_PARAM) == 0))
    {
        return SnortServiceMain(argc, argv);
    }
#endif /* WIN32 && ENABLE_WIN32_SERVICE */

    snort_argc = argc;
    snort_argv = argv;

    return SnortMain(argc, argv);
}

/*
 *
 * Function: SnortMain(int, char *)
 *
 * Purpose:  The real place that the program handles entry and exit.  Called
 *           called by main(), or by SnortServiceMain().
 *
 * Arguments: See command line args in README file
 *
 * Returns: 0 => normal exit, 1 => exit on error
 *
 */
int SnortMain(int argc, char *argv[])
{
    InitSignals();

#if defined(NOCOREFILE) && !defined(WIN32)
    SetNoCores();
#endif

#ifdef WIN32
    if (!init_winsock())
        FatalError("Could not Initialize Winsock!\n");
#endif

    SnortInit(argc, argv);

    if (ScDaemonMode())
    {
        /* Test pcap open if daemonizing so that we FatalError before 
         * daemonizing if pcap cannot be opened. */
        InitPcap(1);

        if (pcap_handle != NULL)
        {
            pcap_close(pcap_handle);
            pcap_handle = NULL;
        }

        GoDaemon();
    }

#ifndef WIN32
# ifndef HAVE_LINUXTHREADS
    /* All threads need to be created after daemonizing.  If created in
     * the parent thread, when it goes away, so will all of the threads.
     * The child does not "inherit" threads created in the parent */
    SnortStartThreads();
# else
    InitPcap(0);
    InitPidChrootAndPrivs();
# endif
#endif

#if defined(INLINE_FAILOPEN) && !defined(GIDS) && !defined(WIN32)
    if (ScAdapterInlineMode() && ScIdsMode() &&
        !ScReadMode() && !ScDisableInlineFailopen())
    {
        /* If in inline mode, start a thread to handle the rest of snort
         * initialization, then dispatch packets until that initialization
         * is complete. */
        LogMessage("Fail Open Thread starting..\n");

        if (pthread_create(&inline_failopen_thread_id, NULL, SnortPostInitThread, NULL))
        {
            ErrorMessage("Failed to start Fail Open Thread.  "
                         "Starting normally\n");

# ifndef HAVE_LINUXTHREADS
            InitPcap(0);
            SnortPostInit();
# endif
        }
        else
        {
            while (!inline_failopen_thread_running)
                nanosleep(&thread_sleep, NULL);

            LogMessage("Fail Open Thread started tid=%u (pid=%u)\n",
                    inline_failopen_thread_id, inline_failopen_thread_pid);

# ifdef DEBUG
            {
                FILE *tmp = fopen("/var/tmp/fo_threadid", "w");
                if ( tmp )
                {
                    fprintf(tmp, "Fail Open Thread PID: %u\n", inline_failopen_thread_pid);
                    fclose(tmp);
                }
            }
# endif

# ifndef HAVE_LINUXTHREADS
            InitPcap(0);
            InitPidChrootAndPrivs();
# endif
            inline_failopen_pcap_initialized = 1;

            /* Passing packets is in the main thread because some systems
             * may have to refer to packet passing thread via process
             * id (linuxthreads) */
            while (snort_initializing)
            {
                (void)pcap_dispatch(pcap_handle, 1,
                                    (pcap_handler)PcapIgnorePacket, NULL);
            }

            pthread_join(inline_failopen_thread_id, NULL);
            inline_failopen_thread_running = 0;

            LogMessage("Fail Open Thread terminated, passed %d packets.\n",
                       inline_failopen_pass_pkt_cnt);
        }
    }
    else
#endif  /* defined(INLINE_FAILOPEN) && !defined(GIDS) && !defined(WIN32) */
    {
#if !defined(HAVE_LINUXTHREADS) || defined(WIN32)
        InitPcap(0);
#endif
        SnortPostInit();
    }

    SnortProcess();
    
#ifndef WIN32
    closelog();
#endif

    return 0;
}

#ifndef WIN32
static void SnortStartThreads(void)
{
# ifdef SNORT_RELOAD
    if (ScIdsMode())
    {
        LogMessage("Reload thread starting...\n");
        if (pthread_create(&snort_reload_thread_id, NULL, ReloadConfigThread, NULL) != 0)
        {
            ErrorMessage("Could not create configuration reload thread.\n");
            CleanExit(1);
        }

        while (!snort_reload_thread_created)
            nanosleep(&thread_sleep, NULL);

        LogMessage("Reload thread started, thread %u (%u)\n",
                snort_reload_thread_id, snort_reload_thread_pid);
    }
# endif

# ifdef TARGET_BASED
    SFAT_StartReloadThread();
# endif
}
#endif  /* WIN32 */

static void InitPidChrootAndPrivs(void)
{
    /* create the PID file */
    /* TODO should be part of the GoDaemon process */
    if (!ScReadMode() && (ScDaemonMode() || *snort_conf->pidfile_suffix || ScCreatePidFile()))
    {
#ifdef WIN32
        CreatePidFile("WIN32");
#else            
# ifdef GIDS
        if (ScAdapterInlineMode())
        {
            if (pcap_interface != NULL)
            {
                CreatePidFile(pcap_interface);
            }
            else
            {
                CreatePidFile("inline");
            }
        }
        else
        {
            /* We need to create the PID over here too */    
            CreatePidFile(pcap_interface);
        }
# else
        CreatePidFile(pcap_interface);
# endif /* GIDS */
#endif /* WIN32 */
    }

#ifndef WIN32
    /* Drop the Chrooted Settings */
    if (snort_conf->chroot_dir)
        SetChroot(snort_conf->chroot_dir, &snort_conf->log_dir);

    /* Drop privileges if requested, when initialization is done */
    SetUidGid(ScUid(), ScGid());
#endif  /* WIN32 */
}

#ifdef DYNAMIC_PLUGIN
static void LoadDynamicPlugins(SnortConfig *sc)
{
    unsigned i;

    if (sc == NULL)
        return;

    snort_conf_for_parsing = sc;

    if (sc->dyn_engines != NULL)
    {
        /* Load the dynamic engines */
        for (i = 0; i < sc->dyn_engines->count; i++)
        {
            switch (sc->dyn_engines->lib_paths[i]->ptype)
            {
                case PATH_TYPE__FILE:
                    LoadDynamicEngineLib(sc->dyn_engines->lib_paths[i]->path, 0);
                    break;

                case PATH_TYPE__DIRECTORY:
                    LoadAllDynamicEngineLibs(sc->dyn_engines->lib_paths[i]->path);
                    break;
            }
        }
    }

    if (sc->dyn_rules != NULL)
    {
        /* Load the dynamic detection libs */
        for (i = 0; i < sc->dyn_rules->count; i++)
        {
            switch (sc->dyn_rules->lib_paths[i]->ptype)
            {
                case PATH_TYPE__FILE:
                    LoadDynamicDetectionLib(sc->dyn_rules->lib_paths[i]->path, 0);
                    break;

                case PATH_TYPE__DIRECTORY:
                    LoadAllDynamicDetectionLibs(sc->dyn_rules->lib_paths[i]->path);
                    break;
            }
        }
    }

    if (sc->dyn_preprocs != NULL)
    {
        /* Load the dynamic preprocessors */
        for (i = 0; i < sc->dyn_preprocs->count; i++)
        {
            switch (sc->dyn_preprocs->lib_paths[i]->ptype)
            {
                case PATH_TYPE__FILE:
                    LoadDynamicPreprocessor(sc->dyn_preprocs->lib_paths[i]->path, 0);
                    break;

                case PATH_TYPE__DIRECTORY:
                    LoadAllDynamicPreprocessors(sc->dyn_preprocs->lib_paths[i]->path);
                    break;
            }
        }
    }
    
    ValidateDynamicEngines();
    snort_conf_for_parsing = NULL;
}

static void DisplayDynamicPluginVersions(void)
{
    void *lib = NULL;
    DynamicPluginMeta *meta;

    RemoveDuplicateEngines();
    RemoveDuplicateDetectionPlugins();
    RemoveDuplicatePreprocessorPlugins();

    lib = GetNextEnginePluginVersion(NULL);
    while ( lib != NULL )
    {
        meta = GetDetectionPluginMetaData(lib);

        LogMessage("           Rules Engine: %s  Version %d.%d  <Build %d>\n",
                   meta->uniqueName, meta->major, meta->minor, meta->build);
        lib = GetNextEnginePluginVersion(lib);
    }
    
    lib = GetNextDetectionPluginVersion(NULL);
    while ( lib != NULL )
    {
        meta = GetEnginePluginMetaData(lib);

        LogMessage("           Rules Object: %s  Version %d.%d  <Build %d>\n",
                   meta->uniqueName, meta->major, meta->minor, meta->build);
        lib = GetNextDetectionPluginVersion(lib);
    }    
    
    lib = GetNextPreprocessorPluginVersion(NULL);
    while ( lib != NULL )
    {
        meta = GetPreprocessorPluginMetaData(lib);

        LogMessage("           Preprocessor Object: %s  Version %d.%d  <Build %d>\n",
                   meta->uniqueName, meta->major, meta->minor, meta->build);
        lib = GetNextPreprocessorPluginVersion(lib);
    }    
}
#endif

/*
 * This function will print versioning information regardless of whether or
 * not the quiet flag is set.  If the quiet flag has been set and we want
 * to honor it, check it before calling this function.
 */
static void PrintVersion(void)
{
    /* Unset quiet flag so LogMessage will print, then restore just
     * in case anything other than exiting after this occurs */
    int save_quiet_flag = snort_conf->logging_flags & LOGGING_FLAG__QUIET;

    snort_conf->logging_flags &= ~LOGGING_FLAG__QUIET;
    DisplayBanner();
    
#ifdef DYNAMIC_PLUGIN
    //  Get and print out library versions
    DisplayDynamicPluginVersions();
#endif

    snort_conf->logging_flags |= save_quiet_flag;
}

#ifdef EXIT_CHECK
static uint64_t exitTime = 0;

static void ExitCheckStart (void)
{
    if ( exitTime )
    {
        return;
    }
    LogMessage("Exit Check: signaling at %ldth callback\n", pc.total_from_pcap);
    get_clockticks(exitTime);
#ifndef WIN32
    kill(0, SIGINT);  // send to all processes in my process group
#else
    raise(SIGINT);
#endif
}

static void ExitCheckEnd (void)
{
    uint64_t now = 0;
    double usecs = 0.0;

    if ( !exitTime )
    {
        LogMessage(
            "Exit Check: callbacks = " STDu64 "(limit not reached)\n",
            pc.total_from_pcap
        );
        return;
    }
    get_clockticks(now);
    exitTime = now - exitTime;
    usecs = exitTime / get_ticks_per_usec();

    LogMessage("Exit Check: usecs = %f\n", usecs);
}
#endif

void PcapProcessPacket(char *user, struct pcap_pkthdr * pkthdr, const u_char * pkt)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(totalPerfStats);

#ifdef EXIT_CHECK
    if (snort_conf->exit_check && (pc.total_from_pcap >= snort_conf->exit_check))
        ExitCheckStart();
#endif

    /* First thing we do is process a Usr signal that we caught */
    if (SignalCheck())
    {
#ifndef SNORT_RELOAD
        /* Got SIGHUP */
        PREPROC_PROFILE_END(totalPerfStats);
        Restart();
#endif
    }

    pc.total_from_pcap++;

    if (ScIdsMode())
    {
#ifdef TARGET_BASED
        /* Load in a new attribute table if we need to... */
        AttributeTableReloadCheck();
#endif

        CheckForReload();

        /* Save off the time of each and every packet */ 
        packet_time_update(pkthdr->ts.tv_sec);

        /* reset the thresholding subsystem checks for this packet */
        sfthreshold_reset();

        PREPROC_PROFILE_START(eventqPerfStats);
        SnortEventqReset();
        Replace_ResetQueue();
        PREPROC_PROFILE_END(eventqPerfStats);
    }

#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
    if (ScTerminateService() || ScPauseService())
    {
        //ClearDumpBuf();  /* cleanup and return without processing */
        return;
    }
#endif  /* WIN32 && ENABLE_WIN32_SERVICE */

#ifndef SUP_IP6
    BsdPseudoPacket = NULL;
#endif

    ProcessPacket(user, pkthdr, pkt, NULL);
    
    /* Collect some "on the wire" stats about packet size, etc */
    UpdateWireStats(&sfBase, pkthdr->caplen);

    PREPROC_PROFILE_END(totalPerfStats);
    return;
}

#ifdef MIMICK_IPV6
/*
 * convert an ip4 packet to an ip6 packet
 * 
 * phdr-input packet, possibly ip4
 * pkt- input packet
 * phdrx- output ip6 packet hdr
 * pktx- output packet
 * encap46- encapsulation flag
 *      0: no encapsulation ip6 == ip4
 *      1: ip4 encapsulation ip4(ip6)
 *      2: ip6 encapsulation ip6(ip4)
 * 
 * returns:  0 - ok
 *          !0 - could not create an ipv6 packet
 *
 * notes: 
 *   ip4 addreses are imbeeded in ip6 addresses 
 */
static int conv_ip4_to_ip6(const struct pcap_pkthdr *phdr,const  u_char *pkt, 
                           struct pcap_pkthdr *phdrx, u_char *pktx, 
                           int  encap46 )
{
    EHDR   *ehdr=NULL;
    VHDR   *vhdr=NULL;
    IPHDR  *iphdr=NULL;
    IPHDR  *ipe=NULL;
    IPV6   *ipe6=NULL; 
    IPV6   *ipv6=NULL; 
    IPV6   *pip6=NULL;
    u_short pip6_size=0;
    u_short etype;
    u_short esize;
    u_char *pnext;
    int     ip4_encap=0;
    int     ip6_encap=0;
    int     isfrag=0; 
    struct ip6_frag * pip6_frag=NULL;
    
    memcpy(phdrx, phdr, sizeof(struct pcap_pkthdr));

    if( encap46 == 1 ) ip4_encap=1;
    else if( encap46 == 2 )ip6_encap=1;
    
    if(sizeof(EHDR) > phdr->caplen)
        return 1;
    
    /* ether packets */
    ehdr = (EHDR *)pkt;

    /* bail if we don't support this ether 'type'*/
    
    // 
    // ETHER LAYER
    // 
    memcpy(&pktx[0],pkt,sizeof(EHDR));

    //
    //  VLAN Layer
    //
    if(ntohs(ehdr->ether_type) == ETYPE_8021Q)
    {
#ifdef IPSTATS
        ether_8021q++;
#endif
        if((sizeof(EHDR) + sizeof(VHDR) + sizeof(IPHDR)) > phdr->caplen)
        {
            return 1;
        }

        vhdr = (VHDR *)(pkt + sizeof(EHDR));
        etype = ntohs(vhdr->proto); 

        if(  etype != ETYPE_IP && etype != ETYPE_IPV6 )
        {
            return 1;
        }
    
        /* build vhdr layer for packet */
        memcpy(&pktx[sizeof(EHDR)],vhdr,sizeof(VHDR));
        /* vhdr -> ether type */
        if( ip4_encap )
        {
          pktx[16]=0x08;
          pktx[17]=0x00;
        }
        else
        {
          pktx[16]=0x86;
          pktx[17]=0xdd;
        }
    
        esize = sizeof(EHDR) + sizeof(VHDR);
        pnext = pktx + esize;
        phdrx->caplen = esize;
        iphdr = (IPHDR *)(pkt + esize );
    }
    else if( ntohs(ehdr->ether_type) == ETYPE_IP || ntohs(ehdr->ether_type) == ETYPE_IPV6 )
    {
        if((sizeof(EHDR) + sizeof(IPHDR)) > phdr->caplen)
        {
            return 1;
        }
        if( ip4_encap )
        {
          pktx[12]=0x08;
          pktx[13]=0x00;
        }
        else
        {
          pktx[12]=0x86;
          pktx[13]=0xdd;
        }
        etype = ntohs(ehdr->ether_type);
        esize = sizeof(EHDR) ;
        pnext = pktx + esize;
        phdrx->caplen = esize;
        iphdr = (IPHDR *)(pkt + esize );
    }
    else 
    {
#ifdef IPSTATS
        other_ether_frame++;
#endif
        return 1;
    }
  
    //
    //  IP encapsulation setup
    //
    if( ip4_encap )
    {
      /* wrap it all with an outer ip4 header */
      static unsigned  ip_id=111;
      static unsigned  ip_s=1;
      static unsigned  ip_d=2;
      
      ipe=(IPHDR*)pnext;
      
      memset(ipe,0,sizeof(IPHDR));
      ipe->ihl=5;
      ipe->version=4;
      ipe->tos=0;
      ipe->id=ip_id++;
      ipe->ttl=64;
      ipe->protocol=IPPROTO_IPV6;
      ipe->tot_len=0;//must do after ipv6 is completed.
      ipe->check = 0;//TODO: when tot_size is known, needs to be accurate
      ipe->saddr=ip_s++; //these will be stripped, so session tracking is not needed
      ipe->daddr=ip_d++;

      pnext += sizeof(IPHDR);
   
    }
    else if( ip6_encap )
    {
      ipe6=(IPV6*)pnext;
    }

    // 
    // IPv6 LAYER
    // 
    if( etype == ETYPE_IPV6 )
    {
      ipv6 = (IPV6*)iphdr;
#ifdef IPSTATS
      if( iphdr->version == 6  )
      {
        ether_ip6++;
      }
      else
      {
        ether_unknown_ip6_ver++; 
      }
          
      if(ipv6->ip6_nxt == 1)
        {
          ip6_icmp_frame++;
        }
      else if(ipv6->ip6_nxt == 17)
        {
            ip6_udp_frame++;
        }
      else if(ipv6->ip6_nxt == 6)
        {
            ip6_tcp_frame++;
        }
      else if(ipv6->ip6_nxt == 4) // ip4 is next hdr
        {
            ether_ip6_ip4++;
        }
      else if(ipv6->ip6_nxt == 44) // fragment hdr
        {
           ether_ip6_frag++;
        }
        else
        {
          other_ip6_frame++;    
        }
#endif
      return 1; // already ipv6 
    }

    
    // 
    // IPv4 LAYER
    // 
    else if( etype == ETYPE_IP )
    {
      if( iphdr->version == 4 )
      {
#ifdef IPSTATS
        ether_ip++;
#endif
        if( (esize + sizeof(IPHDR)) > phdr->caplen)
        {
            return 1;
        }
          
        /* ignore ip4  frags for now */
        if( (ntohs(iphdr->frag_off) & IP_MF) ||
            (ntohs(iphdr->frag_off) & IP_OFFMASK) )
        {
            isfrag=1;
#ifdef IPSTATS
            ether_ip4_frag++;

            if( !dofrags )
            return 1; /* we don't convert frag traffic yet */
           
            /* save the ip4 frag, if were collecting frags */
            if (w_f )
            {
              pcap_dump((char *)w_f, phdr, pkt);
            }
#endif
        }
       
        /* setup ip6 info */        
        pip6 = (IPV6*)pnext;

        if( ip6_encap )//ip6(ip4)
        {
          // size = ip4+payload 
          pip6->ip6_nxt   = IPPROTO_IPIP;
          pip6_size       = phdr->caplen - esize; 
          pnext       += sizeof(IPV6);
          memcpy(pnext, (char*)iphdr, pip6_size);
          phdrx->caplen = esize + sizeof(IPV6) + pip6_size;
          phdrx->len    = phdrx->caplen;
        }
        else 
        {
          /* size = tcp/udp/icmp + ip6 ext headers */
          pip6_size    = phdr->caplen - (esize+(iphdr->ihl<<2)); 

          phdrx->caplen = esize + sizeof(IPV6) + pip6_size;

          phdrx->len    = phdrx->caplen;
          pnext += sizeof(IPV6);
          if( ip4_encap )
              phdrx->caplen += sizeof(IPHDR);
          phdrx->len    = phdrx->caplen;
          if( isfrag )
          {
        // XXX
        /// fragmentation not supported yet
            //return 1;
                  
            pip6->ip6_nxt = 44; // ipv6 frag header
            pip6_frag = (struct ip6_frag *)pnext;
            pnext += sizeof(struct ip6_frag);
           
            //pip6_frag->ip6f_offlg  = iphdr->frag_off;
            pip6_frag->ip6f_offlg  = 0;
            
            if(ntohs(iphdr->frag_off) & IP_OFFMASK)
                 pip6_frag->ip6f_offlg |= (ntohs(iphdr->frag_off) & IP_OFFMASK)<<3 ;
            if(  ntohs(iphdr->frag_off) & IP_MF)
                 pip6_frag->ip6f_offlg |= 1;//IP6F_MORE_FRAG;  /* more-fragments flag */

            pip6_frag->ip6f_offlg = htons(pip6_frag->ip6f_offlg);
           
            pip6_frag->ip6f_ident = htonl((unsigned int)iphdr->id);
            pip6_frag->ip6f_reserved = 0;
            pip6_frag->ip6f_nxt = iphdr->protocol; // ipv6 frag header

            memcpy(pnext, (char*)iphdr + (iphdr->ihl<<2), pip6_size);
            
            //do add the frag header into ip6  size field ? 
//            pip6_size = phdr->caplen - (esize+(iphdr->ihl<<2)) + 
            pip6_size = ntohs(iphdr->tot_len) - (iphdr->ihl<<2) +
                    sizeof(struct ip6_frag); 
           
            phdrx->caplen += sizeof(struct ip6_frag );
            phdrx->len     = phdrx->caplen;
            if( ip4_encap )
            {
              ipe->tot_len = ntohs( sizeof(IPHDR) +  sizeof(IPV6) + sizeof(struct ip6_frag) + pip6_size );
              ipe->check   = in_chksum_ip((u_short*)ipe,sizeof(IPHDR));
            }
          }
          else /* ip4 packet is not fragmented */
          {
            pip6->ip6_nxt  = iphdr->protocol;
            memcpy(pnext, (char*)iphdr + (iphdr->ihl<<2), pip6_size);
            if( ip4_encap )
            {
              ipe->tot_len = ntohs( sizeof(IPHDR) +  sizeof(IPV6) + pip6_size );
              ipe->check   = in_chksum_ip((u_short*)ipe,sizeof(IPHDR));
            }
          }
        }
        
        if(iphdr->protocol == 1)
        {
#ifdef IPSTATS
            icmp_frame++;
#endif
        }
        else if(iphdr->protocol == 17)
        {
#ifdef IPSTATS
            udp_frame++;
#endif
        }
        else if(iphdr->protocol == 6)
        {
#ifdef IPSTATS
         tcp_frame++;
#endif
        }
        else if(iphdr->protocol == 41)
        {
#ifdef IPSTATS
          ether_ip4_ip6++;
          if( w_46 )
          {
          pcap_dump((char *)w_46, phdr, pkt);
          }
#endif
          return 1;
        }
        else /* other ip protocol */
        {
#ifdef IPSTATS
          other_ip_frame++;    
#endif
          return 1;
        }
         
        
      }
      else /* not ver 4 */
      {
#ifdef IPSTATS
          ether_unknown_ip_ver++; 
#endif
          return 1;
      }
    }
    
    /* 
    * Finish  
    *
    * IPv6 or IPv4(IPv6) or IPv6(IPv4) encapsulation
    */
    pip6->ip6_flow=0;
    pip6->ip6_vfc= 6<<4;
    pip6->ip6_plen=htons(ntohs(iphdr->tot_len) - (iphdr->ihl << 2));
    pip6->ip6_hlim=iphdr->ttl;
       
    memset(&pip6->ip6_src,0,16);
    memcpy(&pip6->ip6_src.s6_addr[12],&iphdr->saddr,4);
        
    memset(&pip6->ip6_dst,0,16);
    memcpy(&pip6->ip6_dst.s6_addr[12],&iphdr->daddr,4);
        
#ifdef IPSTATS
    /* save it if were collecting frags */
    if( isfrag && w_f )
    {
       pcap_dump((char *)w_f, phdrx, pktx);
    }
#endif
    
    return 0;
}
#endif

static void PrintPacket(Packet *p)
{
    if (p->iph != NULL)
    {
        PrintIPPkt(stdout, GET_IPH_PROTO((p)), p);
    }
#ifndef NO_NON_ETHER_DECODER
    else if (p->ah != NULL)
    {
        PrintArpHeader(stdout, p);
    }
    else if (p->eplh != NULL)
    {
        PrintEapolPkt(stdout, p);
    }
    else if (p->wifih && ScOutputWifiMgmt())
    {
        PrintWifiPkt(stdout, p);
    }
#endif  // NO_NON_ETHER_DECODER
}

void ProcessPacket(char *user, const struct pcap_pkthdr * pkthdr, const u_char * pkt, void *ft)
{
    Packet p;
#if defined(MIMICK_IPV6) && defined(SUP_IP6)
    struct pcap_pkthdr pkthdrx;
    static u_char pktx[65536+256];
    EHDR   *ehdr=0;
    VHDR   *vhdr;
    int etype;

    if( !conv_ip4_to_ip6(pkthdr,pkt,&pkthdrx,pktx, 0 /* encap46 flag 0=6, 1=4(6), 2=6(4)*/) )
    {
        /* reset to point to new pkt */
        if( mimick_ip6 )
        {
            pkthdr = &pkthdrx;
            pkt = pktx;
        
        }      
        pc.ipv6_up++;
     }
     else 
     { 
        pc.ipv6_upfail++; 
# ifdef SUP_IP6
        //return;
# endif
     }
    
#endif  /* defined(MIMICK_IPV6) && defined(SUP_IP6) */

#if !defined(GIDS) && !defined(WIN32)
    g_drop_pkt = 0;
#endif

    setRuntimePolicy(getDefaultPolicy());

    /* call the packet decoder */
    (*grinder) (&p, pkthdr, pkt);

    if(!p.pkth || !p.pkt)
    {
        return;
    }

    /* Make sure this packet skips the rest of the preprocessors */
    /* Remove once the IPv6 frag code is moved into frag 3 */
    if(p.packet_flags & PKT_NO_DETECT)
    {
        DisableAllDetect(&p);
    }

    if (ft)
    {
        p.packet_flags |= PKT_REBUILT_FRAG;
        p.fragtracker = ft;
    }

    switch (snort_conf->run_mode)
    {
        case RUN_MODE__IDS:
            {
                int vlanId = (p.vh) ? VTH_VLAN(p.vh) : -1;
                snort_ip_p srcIp = (p.iph) ? GET_SRC_IP((&p)) : (snort_ip_p)0;
                snort_ip_p dstIp = (p.iph) ? GET_DST_IP((&p)) : (snort_ip_p)0;

                //set policy id for this packet
                setRuntimePolicy(sfGetApplicablePolicyId(
                            snort_conf->policy_config, vlanId, srcIp, dstIp));

                p.configPolicyId =
                    snort_conf->targeted_policies[getRuntimePolicy()]->configPolicyId;

                //actions are queued only for IDS case
                sfActionQueueExecAll(decoderActionQ);

                /* allow the user to throw away TTLs that won't apply to the
                   detection engine as a whole. */
                if (ScMinTTL() && IPH_IS_VALID((&p)) && (GET_IPH_TTL((&p)) < ScMinTTL()))
                {
                    DEBUG_WRAP(DebugMessage(
                                DEBUG_DECODE, "ScMinTTL reached in main detection loop\n"););

                    return;
                } 

                /* just throw away the packet if we are configured to ignore this port */
                if (p.packet_flags & PKT_IGNORE_PORT)
                    return;


                /* start calling the detection processes */
                Preprocess(&p);

                if (ScLogVerbose())
                    PrintPacket(&p);
            }
            break;

        case RUN_MODE__PACKET_LOG:
            CallLogPlugins(&p, NULL, NULL, NULL);
            break;

        case RUN_MODE__PACKET_DUMP:
            PrintPacket(&p);
            break;

        default:
            break;
    }

    //ClearDumpBuf();
}


/*
 * Function: ShowUsage(char *)
 *
 * Purpose:  Display the program options and exit
 *
 * Arguments: argv[0] => name of the program (argv[0])
 *
 * Returns: 0 => success
 */
static int ShowUsage(char *program_name)
{
    fprintf(stdout, "USAGE: %s [-options] <filter options>\n", program_name);
#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
    fprintf(stdout, "       %s %s %s [-options] <filter options>\n", program_name
                                                                   , SERVICE_CMDLINE_PARAM
                                                                   , SERVICE_INSTALL_CMDLINE_PARAM);
    fprintf(stdout, "       %s %s %s\n", program_name
                                       , SERVICE_CMDLINE_PARAM
                                       , SERVICE_UNINSTALL_CMDLINE_PARAM);
    fprintf(stdout, "       %s %s %s\n", program_name
                                       , SERVICE_CMDLINE_PARAM
                                       , SERVICE_SHOW_CMDLINE_PARAM);
#endif

#ifdef WIN32
# define FPUTS_WIN32(msg) fputs(msg,stdout)
# define FPUTS_UNIX(msg)  NULL
# define FPUTS_BOTH(msg)  fputs(msg,stdout)
#else
# define FPUTS_WIN32(msg) 
# define FPUTS_UNIX(msg)  fputs(msg,stdout)
# define FPUTS_BOTH(msg)  fputs(msg,stdout)
#endif

    FPUTS_BOTH ("Options:\n");
    FPUTS_BOTH ("        -A         Set alert mode: fast, full, console, test or none "
                                  " (alert file alerts only)\n");
    FPUTS_UNIX ("                   \"unsock\" enables UNIX socket logging (experimental).\n");
    FPUTS_BOTH ("        -b         Log packets in tcpdump format (much faster!)\n");
    FPUTS_BOTH ("        -B <mask>  Obfuscated IP addresses in alerts and packet dumps using CIDR mask\n");
    FPUTS_BOTH ("        -c <rules> Use Rules File <rules>\n");
    FPUTS_BOTH ("        -C         Print out payloads with character data only (no hex)\n");
    FPUTS_BOTH ("        -d         Dump the Application Layer\n");
    FPUTS_UNIX ("        -D         Run Snort in background (daemon) mode\n");
    FPUTS_BOTH ("        -e         Display the second layer header info\n");
    FPUTS_WIN32("        -E         Log alert messages to NT Eventlog. (Win32 only)\n");
    FPUTS_BOTH ("        -f         Turn off fflush() calls after binary log writes\n");
    FPUTS_BOTH ("        -F <bpf>   Read BPF filters from file <bpf>\n");
    FPUTS_UNIX ("        -g <gname> Run snort gid as <gname> group (or gid) after initialization\n");
    FPUTS_BOTH ("        -G <0xid>  Log Identifier (to uniquely id events for multiple snorts)\n");
    FPUTS_BOTH ("        -h <hn>    Home network = <hn>\n");
    FPUTS_BOTH ("        -H         Make hash tables deterministic.\n");
    FPUTS_BOTH ("        -i <if>    Listen on interface <if>\n");
    FPUTS_BOTH ("        -I         Add Interface name to alert output\n");
#if defined(GIDS) && defined(IPFW)
    FPUTS_BOTH ("        -J <port>  ipfw divert socket <port> to listen on vice libpcap (FreeBSD only)\n");
#endif
    FPUTS_BOTH ("        -k <mode>  Checksum mode (all,noip,notcp,noudp,noicmp,none)\n");
    FPUTS_BOTH ("        -K <mode>  Logging mode (pcap[default],ascii,none)\n");
    FPUTS_BOTH ("        -l <ld>    Log to directory <ld>\n");
    FPUTS_BOTH ("        -L <file>  Log to this tcpdump file\n");
    FPUTS_UNIX ("        -M         Log messages to syslog (not alerts)\n");
    FPUTS_UNIX ("        -m <umask> Set umask = <umask>\n");
    FPUTS_BOTH ("        -n <cnt>   Exit after receiving <cnt> packets\n");
    FPUTS_BOTH ("        -N         Turn off logging (alerts still work)\n");
    FPUTS_BOTH ("        -O         Obfuscate the logged IP addresses\n");
    FPUTS_BOTH ("        -p         Disable promiscuous mode sniffing\n");
    fprintf(stdout, "        -P <snap>  Set explicit snaplen of packet (default: %d)\n",
                                    SNAPLEN);
    FPUTS_BOTH ("        -q         Quiet. Don't show banner and status report\n");
#if !defined(IPFW) && !defined(WIN32)
    FPUTS_BOTH ("        -Q         Enable inline mode operation.\n");
#endif
    FPUTS_BOTH ("        -r <tf>    Read and process tcpdump file <tf>\n");
    FPUTS_BOTH ("        -R <id>    Include 'id' in snort_intf<id>.pid file name\n");
    FPUTS_BOTH ("        -s         Log alert messages to syslog\n");
    FPUTS_BOTH ("        -S <n=v>   Set rules file variable n equal to value v\n");
    FPUTS_UNIX ("        -t <dir>   Chroots process to <dir> after initialization\n");
    FPUTS_BOTH ("        -T         Test and report on the current Snort configuration\n");
    FPUTS_UNIX ("        -u <uname> Run snort uid as <uname> user (or uid) after initialization\n");
    FPUTS_BOTH ("        -U         Use UTC for timestamps\n");
    FPUTS_BOTH ("        -v         Be verbose\n");
    FPUTS_BOTH ("        -V         Show version number\n");
    FPUTS_WIN32("        -W         Lists available interfaces. (Win32 only)\n");
#if defined(NON_ETHER_DECODER) && defined(DLT_IEEE802_11)
    FPUTS_BOTH ("        -w         Dump 802.11 management and control frames\n");
#endif
    FPUTS_BOTH ("        -X         Dump the raw packet data starting at the link layer\n");
    FPUTS_BOTH ("        -x         Exit if Snort configuration problems occur\n");
    FPUTS_BOTH ("        -y         Include year in timestamp in the alert and log files\n");
    FPUTS_BOTH ("        -Z <file>  Set the performonitor preprocessor file path and name\n");
    FPUTS_BOTH ("        -?         Show this information\n");
    FPUTS_BOTH ("<Filter Options> are standard BPF options, as seen in TCPDump\n");

    FPUTS_BOTH ("Longname options and their corresponding single char version\n");
    FPUTS_BOTH ("   --logid <0xid>                  Same as -G\n");
    FPUTS_BOTH ("   --perfmon-file <file>           Same as -Z\n");
    FPUTS_BOTH ("   --pid-path <dir>                Specify the directory for the Snort PID file\n");
    FPUTS_BOTH ("   --snaplen <snap>                Same as -P\n");
    FPUTS_BOTH ("   --help                          Same as -?\n");
    FPUTS_BOTH ("   --version                       Same as -V\n");
    FPUTS_BOTH ("   --alert-before-pass             Process alert, drop, sdrop, or reject before pass, default is pass before alert, drop,...\n");
    FPUTS_BOTH ("   --treat-drop-as-alert           Converts drop, sdrop, and reject rules into alert rules during startup\n");
    FPUTS_BOTH ("   --process-all-events            Process all queued events (drop, alert,...), default stops after 1st action group\n");
#ifdef DYNAMIC_PLUGIN
    FPUTS_BOTH ("   --dynamic-engine-lib <file>     Load a dynamic detection engine\n");
    FPUTS_BOTH ("   --dynamic-engine-lib-dir <path> Load all dynamic engines from directory\n");
    FPUTS_BOTH ("   --dynamic-detection-lib <file>  Load a dynamic rules library\n");
    FPUTS_BOTH ("   --dynamic-detection-lib-dir <path> Load all dynamic rules libraries from directory\n");
    FPUTS_BOTH ("   --dump-dynamic-rules <path>     Creates stub rule files of all loaded rules libraries\n");
    FPUTS_BOTH ("   --dynamic-preprocessor-lib <file>  Load a dynamic preprocessor library\n");
    FPUTS_BOTH ("   --dynamic-preprocessor-lib-dir <path> Load all dynamic preprocessor libraries from directory\n");
#endif
    FPUTS_UNIX ("   --create-pidfile                Create PID file, even when not in Daemon mode\n");
    FPUTS_UNIX ("   --nolock-pidfile                Do not try to lock Snort PID file\n");
    FPUTS_UNIX ("   --disable-inline-initialization Do not perform the IPTables initialization in inline mode.\n");
#ifdef INLINE_FAILOPEN
    FPUTS_UNIX ("   --disable-inline-init-failopen  Do not fail open and pass packets while initializing with inline mode.\n");
#endif
#ifdef TARGET_BASED
    FPUTS_UNIX ("   --disable-attribute-reload-thread Do not create a thread to reload the attribute table\n");
#endif
    FPUTS_BOTH ("   --pcap-single <tf>              Same as -r.\n");
    FPUTS_BOTH ("   --pcap-file <file>              file that contains a list of pcaps to read - read mode is implied.\n");
    FPUTS_BOTH ("   --pcap-list \"<list>\"            a space separated list of pcaps to read - read mode is implied.\n");
    FPUTS_UNIX ("   --pcap-dir <dir>                a directory to recurse to look for pcaps - read mode is implied.\n");
    FPUTS_UNIX ("   --pcap-filter <filter>          filter to apply when getting pcaps from file or directory.\n");
    FPUTS_UNIX ("   --pcap-no-filter                reset to use no filter when getting pcaps from file or directory.\n");
    FPUTS_BOTH ("   --pcap-loop <count>             this option will read the pcaps specified on command line continuously.\n"
                "                                   for <count> times.  A value of 0 will read until Snort is terminated.\n");
    FPUTS_BOTH ("   --pcap-reset                    if reading multiple pcaps, reset snort to post-configuration state before reading next pcap.\n");
    FPUTS_BOTH ("   --pcap-show                     print a line saying what pcap is currently being read.\n");
    FPUTS_BOTH ("   --exit-check <count>            Signal termination after <count> callbacks from pcap_dispatch(), showing the time it\n"
                "                                   takes from signaling until pcap_close() is called.\n");
    FPUTS_BOTH ("   --conf-error-out                Same as -x\n");
#ifdef MPLS
    FPUTS_BOTH ("   --enable-mpls-multicast         Allow multicast MPLS\n");
    FPUTS_BOTH ("   --enable-mpls-overlapping-ip    Handle overlapping IPs within MPLS clouds\n");
    FPUTS_BOTH ("   --max-mpls-labelchain-len       Specify the max MPLS label chain\n");
    FPUTS_BOTH ("   --mpls-payload-type             Specify the protocol (ipv4, ipv6, ethernet) that is encapsulated by MPLS\n");
#endif
    FPUTS_BOTH ("   --require-rule-sid              Require that all snort rules have SID specified.\n");
#undef FPUTS_WIN32
#undef FPUTS_UNIX
#undef FPUTS_BOTH
    return 0;
}

#ifdef DYNAMIC_PLUGIN
static void ParseCmdLineDynamicLibInfo(SnortConfig *sc, int type, char *path)
{
    DynamicLibInfo *dli = NULL;
    DynamicLibPath *dlp = NULL;

    if ((sc == NULL) || (path == NULL))
        FatalError("%s(%d) NULL arguments.\n", __FILE__, __LINE__);

    switch (type)
    {
        case DYNAMIC_PREPROC_FILE:
        case DYNAMIC_PREPROC_DIRECTORY:
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Dynamic preprocessor specifier\n"););
            if (sc->dyn_preprocs == NULL)
            {
                sc->dyn_preprocs = (DynamicLibInfo *)SnortAlloc(sizeof(DynamicLibInfo));
                sc->dyn_preprocs->type = DYNAMIC_TYPE__PREPROCESSOR;
            }
            else if (sc->dyn_preprocs->count >= MAX_DYNAMIC_LIBS)
            {
                FatalError("Maximum number of loaded Dynamic Preprocessor Libs "
                           "(%d) exceeded.\n", MAX_DYNAMIC_LIBS);
            }

            dli = sc->dyn_preprocs;
            break;

        case DYNAMIC_LIBRARY_FILE:
        case DYNAMIC_LIBRARY_DIRECTORY:
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Dynamic detection specifier\n"););
            if (sc->dyn_rules == NULL)
            {
                sc->dyn_rules = (DynamicLibInfo *)SnortAlloc(sizeof(DynamicLibInfo));
                sc->dyn_rules->type = DYNAMIC_TYPE__DETECTION;
            }
            else if (sc->dyn_rules->count >= MAX_DYNAMIC_LIBS)
            {
                FatalError("Maximum number of loaded Dynamic Detection Libs "
                           "(%d) exceeded.\n", MAX_DYNAMIC_LIBS);
            }

            dli = sc->dyn_rules;
            break;

        case DYNAMIC_ENGINE_FILE:
        case DYNAMIC_ENGINE_DIRECTORY:
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Dynamic engine specifier\n"););
            if (sc->dyn_engines == NULL)
            {
                sc->dyn_engines = (DynamicLibInfo *)SnortAlloc(sizeof(DynamicLibInfo));
                sc->dyn_engines->type = DYNAMIC_TYPE__ENGINE;
            }
            else if (sc->dyn_engines->count >= MAX_DYNAMIC_LIBS)
            {
                FatalError("Maximum number of loaded Dynamic Engine Libs "
                           "(%d) exceeded.\n", MAX_DYNAMIC_LIBS);
            }

            dli = sc->dyn_engines;
            break;

        default:
            FatalError("%s(%d) Invalid dynamic type: %d\n", __FILE__, __LINE__, type);
            break;
    }

    dlp = (DynamicLibPath *)SnortAlloc(sizeof(DynamicLibPath));
    switch (type)
    {
        case DYNAMIC_PREPROC_FILE:
        case DYNAMIC_LIBRARY_FILE:
        case DYNAMIC_ENGINE_FILE:
            dlp->ptype = PATH_TYPE__FILE;
            break;

        case DYNAMIC_PREPROC_DIRECTORY:
        case DYNAMIC_LIBRARY_DIRECTORY:
        case DYNAMIC_ENGINE_DIRECTORY:
            dlp->ptype = PATH_TYPE__DIRECTORY;
            break;

        default:
            FatalError("%s(%d) Invalid dynamic type: %d\n", __FILE__, __LINE__, type);
            break;
    }

    dlp->path = SnortStrdup(path);
    dli->lib_paths[dli->count] = dlp;
    dli->count++;
}
#endif

/*
 * Function: ParseCmdLine(int, char **)
 *
 * Parses command line arguments
 *
 * Arguments:
 *  int
 *      count of arguments passed to the routine
 *  char **
 *      2-D character array, contains list of command line args
 *
 * Returns: None
 *
 */

static void ParseCmdLine(int argc, char **argv)
{
    int ch;
    int i;
    int option_index = -1;
    PcapReadObject *pro = NULL;
    char *pcap_filter = NULL;
    char *endptr;   /* for strtol calls */
    SnortConfig *sc;
    int output_logging = 0;
    int output_alerting = 0;
    int syslog_configured = 0;
#ifndef WIN32
    int daemon_configured = 0;
#endif
#ifdef WIN32
    char errorbuf[PCAP_ERRBUF_SIZE];
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Parsing command line...\n"););

    if (snort_cmd_line_conf != NULL)
    {
        FatalError("%s(%d) Trying to parse the command line again.\n",
                   __FILE__, __LINE__);
    }

    snort_cmd_line_conf = SnortConfNew();
    snort_conf = snort_cmd_line_conf;     /* Set the global for log messages */
    sc = snort_cmd_line_conf;

    /* Look for a -D and/or -M switch so we can start logging to syslog
     * with "snort" tag right away */
    for (i = 0; i < argc; i++)
    {
        if (strcmp("-M", argv[i]) == 0)
        {
            if (syslog_configured)
                continue;

            /* If daemon or logging to syslog use "snort" as identifier and
             * start logging there now */
            openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON); 

            sc->logging_flags |= LOGGING_FLAG__SYSLOG;
            syslog_configured = 1;
        }
#ifndef WIN32
        else if ((strcmp("-D", argv[i]) == 0) ||
                 (strcmp("--restart", argv[i]) == 0))
        {
            if (daemon_configured)
                continue;

            /* If daemon or logging to syslog use "snort" as identifier and
             * start logging there now */
            openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON); 

            if (strcmp("--restart", argv[i]) == 0)
                sc->run_flags |= RUN_FLAG__DAEMON_RESTART;

            ConfigDaemon(sc, optarg);
            daemon_configured = 1;
        }
#endif
        else if (strcmp("-q", argv[i]) == 0)
        {
            /* Turn on quiet mode if configured so any log messages that may
             * be printed while parsing the command line before the quiet option
             * is read won't be printed */
            ConfigQuiet(sc, NULL);
        }
    }

    /*
    **  Set this so we know whether to return 1 on invalid input.
    **  Snort uses '?' for help and getopt uses '?' for telling us there
    **  was an invalid option, so we can't use that to tell invalid input.
    **  Instead, we check optopt and it will tell us.
    */
    optopt = 0;

    /* loop through each command line var and process it */
    while ((ch = getopt_long(argc, argv, valid_options, long_options, &option_index)) != -1)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Processing cmd line switch: %c\n", ch););

        switch (ch)
        {
#ifdef DYNAMIC_PLUGIN
            case DYNAMIC_ENGINE_FILE:       /* Load dynamic engine specified */
            case DYNAMIC_ENGINE_DIRECTORY:  /* Load dynamic engine specified */
            case DYNAMIC_PREPROC_FILE:      /* Load dynamic preprocessor lib specified */
            case DYNAMIC_PREPROC_DIRECTORY:
            case DYNAMIC_LIBRARY_FILE:      /* Load dynamic detection lib specified */
            case DYNAMIC_LIBRARY_DIRECTORY:
                ParseCmdLineDynamicLibInfo(sc, ch, optarg);
                break;

            case DUMP_DYNAMIC_RULES:
                ConfigDumpDynamicRulesPath(sc, optarg);
                break;
#endif
            case ALERT_BEFORE_PASS:
                ConfigAlertBeforePass(sc, NULL);
                break;

            case PROCESS_ALL_EVENTS:
                ConfigProcessAllEvents(sc, NULL);
                break;

            case TREAT_DROP_AS_ALERT:
                ConfigTreatDropAsAlert(sc, NULL);
                break;

            case PID_PATH:
                ConfigPidPath(sc, optarg);
                break;

            case CREATE_PID_FILE:
                ConfigCreatePidFile(sc, NULL);
                break;

            case NOLOCK_PID_FILE:
                sc->run_flags |= RUN_FLAG__NO_LOCK_PID_FILE;
                break;

            case DISABLE_INLINE_INIT:
                sc->run_flags |= RUN_FLAG__DISABLE_INLINE_INIT;
                break;

#ifdef INLINE_FAILOPEN
            case DISABLE_INLINE_FAILOPEN:
                ConfigDisableInlineFailopen(sc, NULL);
                break;
#endif
            case NO_LOGGING_TIMESTAMPS:
                ConfigNoLoggingTimestamps(sc, NULL);
                break;

#ifdef EXIT_CHECK
            case ARG_EXIT_CHECK:
                {
                    char* endPtr;

                    sc->exit_check = strtoul(optarg, &endPtr, 0);
                    if ((errno == ERANGE) || (*endPtr != '\0'))
                        FatalError("--exit-check value must be non-negative integer\n");

                    LogMessage("Exit Check: limit = %ld callbacks\n", sc->exit_check);
                }

                break;
#endif

#ifdef TARGET_BASED
            case DISABLE_ATTRIBUTE_RELOAD:
                sc->run_flags |= RUN_FLAG__DISABLE_ATTRIBUTE_RELOAD_THREAD;
                break;
#endif
            case DETECTION_SEARCH_METHOD:
                if (sc->fast_pattern_config != NULL)
                    FatalError("Can only configure search method once.\n");

                sc->fast_pattern_config = FastPatternConfigNew();

                if (fpSetDetectSearchMethod(sc->fast_pattern_config, optarg) == -1)
                    FatalError("Invalid search method: %s.\n", optarg);

                break;

            case 'A':  /* alert mode */
                output_alerting = 1;

                if (strcasecmp(optarg, ALERT_MODE_OPT__NONE) == 0)
                {
                    sc->no_alert = 1;
                }
                else if (strcasecmp(optarg, ALERT_MODE_OPT__PKT_CNT) == 0)
                {
                    /* print packet count at start of alert */
                    sc->output_flags |= OUTPUT_FLAG__ALERT_PKT_CNT;
                }
                else if (strcasecmp(optarg, ALERT_MODE_OPT__FULL) == 0)
                {
                    ParseOutput(sc, NULL, "alert_full");
                }
                else if (strcasecmp(optarg, ALERT_MODE_OPT__FAST) == 0)
                {
                    ParseOutput(sc, NULL, "alert_fast");
                }
                else if (strcasecmp(optarg, ALERT_MODE_OPT__CONSOLE) == 0)
                {
                    ParseOutput(sc, NULL, "alert_fast: stdout");
                }
                else if ((strcasecmp(optarg, ALERT_MODE_OPT__CMG) == 0) ||
                         (strcasecmp(optarg, ALERT_MODE_OPT__JH) == 0) ||
                         (strcasecmp(optarg, ALERT_MODE_OPT__DJR) == 0))
                {
                    ParseOutput(sc, NULL, "alert_fast: stdout packet");
                    sc->no_log = 1;
                    /* turn on layer2 headers */
                    sc->output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK;
                    /* turn on data dump */
                    sc->output_flags |= OUTPUT_FLAG__APP_DATA;
                }
                else if (strcasecmp(optarg, ALERT_MODE_OPT__AJK) == 0)
                {
                    ParseOutput(sc, NULL, "unified2");
                }
                else if (strcasecmp(optarg, ALERT_MODE_OPT__UNIX_SOCK) == 0)
                {
                    ParseOutput(sc, NULL, "alert_unixsock");
                }
                else if (strcasecmp(optarg, ALERT_MODE_OPT__TEST) == 0)
                {
                    ParseOutput(sc, NULL, "alert_test");
                    sc->no_log = 1;
                }
                else
                {
                    FatalError("Unknown command line alert option: %s\n", optarg);
                }

                break;

#ifdef MIMICK_IPV6
            case '6':
                sc->run_flags |= RUN_FLAG__MIMICK_IP6;
                break;
#endif
            case 'b':  /* log packets in binary format for post-processing */
                ParseOutput(sc, NULL, "log_tcpdump");
                output_logging = 1;
                break;

            case 'B':  /* obfuscate with a substitution mask */
                ConfigObfuscationMask(sc, optarg);
                break;

            case 'c':  /* use configuration file x */
                sc->run_mode_flags |= RUN_MODE_FLAG__IDS;
                snort_conf_file = SnortStrdup(optarg);
                break;

            case 'C':  /* dump the application layer as text only */
                ConfigDumpCharsOnly(sc, NULL);
                break;

            case 'd':  /* dump the application layer data */
                ConfigDumpPayload(sc, NULL);
                break;

            case ARG_RESTART:  /* Restarting from daemon mode */
            case 'D':  /* daemon mode */
                /* These are parsed at the beginning so as to start logging
                 * to syslog right away */
                break;

            case 'e':  /* show second level header info */
                ConfigDecodeDataLink(sc, NULL);
                break;
#ifdef WIN32
            case 'E':  /* log alerts to Event Log */
                ParseOutput(sc, NULL, "alert_syslog");
                sc->logging_flags &= ~LOGGING_FLAG__SYSLOG_REMOTE;
                output_alerting = 1;
                break;
#endif
            case 'f':
                sc->output_flags |= OUTPUT_FLAG__LINE_BUFFER;
                break;

            case 'F':   /* read BPF filter in from a file */
                ConfigBpfFile(sc, optarg);
                break;

            case 'g':   /* setgid */
                ConfigSetGid(sc, optarg);
                break;

            case 'G':  /* snort loG identifier */
                sc->event_log_id = strtoul(optarg, &endptr, 0);
                if ((errno == ERANGE) || (*endptr != '\0') ||
                    (sc->event_log_id > UINT16_MAX))
                {
                    FatalError("Snort log identifier invalid: %s.  It must "
                               "be between 0 and %u.\n", optarg, UINT16_MAX);
                }

                /* Forms upper 2 bytes.  Lower two bytes are the event id */
                sc->event_log_id <<= 16;

                break;

            case 'h':  
                /* set home network to x, this will help determine what to set
                 * logging diectories to */
                ConfigReferenceNet(sc, optarg);
                break;

            case 'H':
                sc->run_flags |= RUN_FLAG__STATIC_HASH;
                break;

            case 'i':
                ConfigInterface(sc, optarg);
                break;

            case 'I':  /* add interface name to alert string */
                ConfigAlertWithInterfaceName(sc, NULL);
                break;

#if defined(GIDS) && defined(IPFW)
            case 'J':
                LogMessage("Reading from ipfw divert socket\n");

                sc->run_flags |= RUN_FLAG__INLINE;
                sc->run_flags |= RUN_FLAG__NO_PROMISCUOUS;

                sc->divert_port = strtoul(optarg, &endptr, 0);
                if ((errno == ERANGE) || (*endptr != '\0'))
                    FatalError("Divert port out of range: %s.\n", optarg);

                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Divert port set to: %d\n", sc->divert_port););

                LogMessage("IPFW Divert port set to: %d\n", sc->divert_port);

                if (sc->interface != NULL)
                {
                    free(sc->interface);
                    sc->interface = NULL;
                }

                break;
#endif
            case 'k':  /* set checksum mode */
                ConfigChecksumMode(sc, optarg);
                break;

            case 'K':  /* log mode */
                if (strcasecmp(optarg, LOG_MODE_OPT__NONE) == 0)
                {
                    sc->no_log = 1;
                }
                else if (strcasecmp(optarg, LOG_MODE_OPT__PCAP) == 0)
                {
                    ParseOutput(sc, NULL, "log_tcpdump");
                }
                else if (strcasecmp(optarg, LOG_MODE_OPT__ASCII) == 0)
                {
                    ParseOutput(sc, NULL, "log_ascii");
                }
                else
                {
                    FatalError("Unknown command line log option: %s\n", optarg);
                }

                output_logging = 1;
                break;

            case 'l':  /* use log dir <X> */
                ConfigLogDir(sc, optarg);
                break;

            case 'L':  /* set BinLogFile name */
                /* implies tcpdump format logging
                 * 256 is kind of arbitrary but should be more than enough */
                if (strlen(optarg) < 256)
                {
                    ParseOutput(sc, NULL, "log_tcpdump");
                    sc->pcap_log_file = SnortStrdup(optarg);
                }
                else
                {
                    FatalError("Pcap log file name \"%s\" has to be less "
                               "than or equal to 256 characters.\n", optarg);
                }             

                output_logging = 1;
                break;

            case 'M':
                /* This is parsed at the beginning so as to start logging
                 * to syslog right away */
                break;
                
            case 'm':  /* set the umask for the output files */
                ConfigUmask(sc, optarg);
                break;

            case 'n':  /* grab x packets and exit */
                ConfigPacketCount(sc, optarg);
                break;

            case 'N':  /* no logging mode */
                ConfigNoLog(sc, NULL);
                break;

            case 'O':  /* obfuscate the logged IP addresses for privacy */
                ConfigObfuscate(sc, NULL);
                break;

            case 'p':  /* disable explicit promiscuous mode */
                ConfigNoPromiscuous(sc, NULL);
                break;

            case 'P':  /* explicitly define snaplength of packets */
                ConfigPacketSnaplen(sc, optarg);
                break;

            case 'q':  /* no stdout output mode */
                /* This is parsed at the beginning so as to start logging
                 * in quiet mode right away */
                break;

#if !defined(IPFW) && !defined(WIN32)
            case 'Q':
                LogMessage("Enabling inline operation\n");
                sc->run_flags |= RUN_FLAG__INLINE;
                break;
#endif
            case 'r':  /* read packets from a TCPdump file instead of the net */
            case PCAP_SINGLE:
                if (pcap_object_list == NULL)
                {
                    pcap_object_list = sflist_new();
                    if (pcap_object_list == NULL)
                        FatalError("Could not allocate list to store pcap\n");
                }

                pro = (PcapReadObject *)SnortAlloc(sizeof(PcapReadObject));
                pro->type = PCAP_SINGLE;
                pro->arg = SnortStrdup(optarg);
                pro->filter = NULL;

                if (sflist_add_tail(pcap_object_list, (NODE_DATA)pro) == -1)
                    FatalError("Could not add pcap object to list: %s\n", optarg);

                sc->run_flags |= RUN_FLAG__READ;
                break;

            case 'R': /* augment pid file name suffix */
                if ((strlen(optarg) >= MAX_PIDFILE_SUFFIX) || (strlen(optarg) <= 0) ||
                    (strstr(optarg, "..") != NULL) || (strstr(optarg, "/") != NULL))
                {
                        FatalError("Invalid pidfile suffix: %s.  Suffix must "
                                   "less than %u characters and not have "
                                   "\"..\" or \"/\" in the name.\n", optarg,
                                   MAX_PIDFILE_SUFFIX);
                }

                SnortStrncpy(sc->pidfile_suffix, optarg, sizeof(sc->pidfile_suffix));
                break;

            case 's':  /* log alerts to syslog */
#ifndef WIN32
                ParseOutput(sc, NULL, "alert_syslog");
#else
                sc->logging_flags |= LOGGING_FLAG__SYSLOG_REMOTE;
#endif
                output_alerting = 1;
                break;

            case 'S':  /* set a rules file variable */
                {
                    char *equal_ptr = strchr(optarg, '=');
                    VarNode *node;

                    if (equal_ptr == NULL)
                    {
                        FatalError("Format for command line variable definitions "
                                   "is:\n -S var=value\n");
                    }

                    /* Save these and parse when snort conf is parsed so
                     * they can be added to the snort conf configuration */
                    node = (VarNode *)SnortAlloc(sizeof(VarNode));
                    node->name = SnortStrndup(optarg, equal_ptr - optarg);

                    /* Make sure it's not already in the list */
                    if (cmd_line_var_list != NULL)
                    {
                        VarNode *tmp = cmd_line_var_list;

                        while (tmp != NULL)
                        {
                            if (strcasecmp(tmp->name, node->name) == 0)
                            {
                                FreeVarList(cmd_line_var_list);
                                FatalError("Duplicate variable name: %s.\n",
                                           tmp->name);
                            }

                            tmp = tmp->next;
                        }
                    }

                    node->value = SnortStrdup(equal_ptr + 1);
                    node->line = SnortStrdup(optarg);
                    node->next = cmd_line_var_list;
                    cmd_line_var_list = node;

                    /* Put line in a parser parsable form - we know the
                     * equals is already there */
                    equal_ptr = strchr(node->line, '=');
                    *equal_ptr = ' ';
                }

                break;

            case 't':  /* chroot to the user specified directory */
                ConfigChrootDir(sc, optarg);
                break;

            case 'T':  /* test mode, verify that the rules load properly */
                sc->run_mode_flags |= RUN_MODE_FLAG__TEST;
                break;    

            case 'u':  /* setuid */
                ConfigSetUid(sc, optarg);
                break;

            case 'U':  /* use UTC */
                ConfigUtc(sc, NULL);
                break;

            case 'v':  /* be verbose */
                ConfigVerbose(sc, NULL);
                break;

            case 'V':  /* prog ver already gets printed out, so we just exit */
                sc->run_mode_flags |= RUN_MODE_FLAG__VERSION;
                sc->logging_flags |= LOGGING_FLAG__QUIET;
                break;

#ifdef WIN32
            case 'W':
                {
                    pcap_if_t *alldevs;
                    pcap_if_t *dev;
                    int j = 1;

                    if (pcap_findalldevs(&alldevs, errorbuf) == -1)
                        FatalError("Could not get device list: %s.", errorbuf);

                    PrintVersion();

                    printf("Interface  Device                               Description\n");
                    printf("--------------------------------------------------------------------------------\n");

                    for (dev = alldevs; dev != NULL; dev = dev->next, j++)
                        printf("%9d  %s\t%s\n", j, dev->name, dev->description);

                    pcap_freealldevs(alldevs);

                    exit(0);  /* XXX Should maybe use CleanExit here? */
                }

                break;
#endif  /* WIN32 */

#if !defined(NO_NON_ETHER_DECODER) && defined(DLT_IEEE802_11)
            case 'w':  /* show 802.11 all frames info */
                sc->output_flags |= OUTPUT_FLAG__SHOW_WIFI_MGMT;
                break;
#endif
            case 'X':  /* display verbose packet bytecode dumps */
                ConfigDumpPayloadVerbose(sc, NULL);
                break;
                
            case 'x':
                sc->run_flags |= RUN_FLAG__CONF_ERROR_OUT;
                break;
                
            case 'y':  /* Add year to timestamp in alert and log files */
                ConfigShowYear(sc, NULL);
                break;

            case 'Z':  /* Set preprocessor perfmon file path/filename */
                ConfigPerfFile(sc, optarg);
                break;

            case PCAP_FILE_LIST:
            case PCAP_LIST:
#ifndef WIN32
            case PCAP_DIR:
#endif
                if (pcap_object_list == NULL)
                {
                    pcap_object_list = sflist_new();
                    if (pcap_object_list == NULL)
                        FatalError("Could not allocate list to store pcaps\n");
                }

                pro = (PcapReadObject *)SnortAlloc(sizeof(PcapReadObject));
                pro->type = ch;
                pro->arg = SnortStrdup(optarg);
                if (pcap_filter != NULL)
                    pro->filter = SnortStrdup(pcap_filter);
                else
                    pro->filter = NULL;

                if (sflist_add_tail(pcap_object_list, (NODE_DATA)pro) == -1)
                    FatalError("Could not add pcap object to list: %s\n", optarg);

                sc->run_flags |= RUN_FLAG__READ;
                break;

            case PCAP_LOOP:
                {
                    long int loop_count = strtol(optarg, &endptr, 0);

                    if ((errno == ERANGE) || (*endptr != '\0') ||
                        (loop_count < 0) || (loop_count > 2147483647))
                    {
                        FatalError("Valid values for --pcap-loop are between 0 and 2147483647\n");
                    }

                    if (loop_count == 0)
                        pcap_loop_count = -1;
                    else
                        pcap_loop_count = loop_count;
                }

                break;

            case PCAP_RESET:
                sc->run_flags |= RUN_FLAG__PCAP_RESET;
                break;

#ifndef WIN32
            case PCAP_FILTER:
                if (pcap_filter != NULL)
                    free(pcap_filter);
                pcap_filter = SnortStrdup(optarg);

                break;

            case PCAP_NO_FILTER:
                if (pcap_filter != NULL)
                {
                    free(pcap_filter);
                    pcap_filter = NULL;
                }

                break;
#endif

            case PCAP_SHOW:
                sc->run_flags |= RUN_FLAG__PCAP_SHOW;
                break;
#ifdef MPLS
            case ENABLE_MPLS_MULTICAST:
                ConfigEnableMplsMulticast(sc, NULL);
                break;

            case ENABLE_OVERLAPPING_IP:
                ConfigEnableMplsOverlappingIp(sc, NULL);
                break;

            case MAX_MPLS_LABELCHAIN_LEN:
                ConfigMaxMplsLabelChain(sc, optarg);
                break;

            case MPLS_PAYLOAD_TYPE:
                ConfigMplsPayloadType(sc, optarg);
                break;
#endif
            case REQUIRE_RULE_SID:
                sc->run_flags |= RUN_FLAG__REQUIRE_RULE_SID;
                break;

            case '?':  /* show help and exit with 1 */
                PrintVersion();
                ShowUsage(argv[0]);
                /* XXX Should do a clean exit */
                exit(1);
                break;

            default:
                FatalError("Invalid option: %c.\n", ch);
                break;
        }
    }

    sc->bpf_filter = copy_argv(&argv[optind]);

    if ((sc->run_mode_flags & RUN_MODE_FLAG__TEST) &&
        (sc->run_flags & RUN_FLAG__DAEMON))
    {
        FatalError("Cannot use test mode and daemon mode together.\n"
                   "To verify configuration, run first in test "
                   "mode and then restart in daemon mode.\n");
    }

    if ((sc->run_mode_flags & RUN_MODE_FLAG__TEST) &&
        (snort_conf_file == NULL))
    {
        FatalError("Test mode must be run with a snort configuration "
                   "file.  Use the '-c' option on the command line to "
                   "specify a configuration file.\n");
    }

    if ((sc->interface != NULL) && (sc->run_flags & RUN_FLAG__READ))
    {
        FatalError("Cannot listen on interface and read pcaps at the "
                   "same time.\n");
    }

    if (pcap_filter != NULL)
        free(pcap_filter);

    if (pcap_loop_count && !(sc->run_flags & RUN_FLAG__READ))
    {
        FatalError("--pcap-loop can only be used in combination with pcaps "
                   "on the command line.\n");
    }

    /* Set the run mode based on what we've got from command line */

    /* Version overrides all */
    if (sc->run_mode_flags & RUN_MODE_FLAG__VERSION)
    {
        sc->run_mode = RUN_MODE__VERSION;
    }
#ifdef DYNAMIC_PLUGIN
    /* Next dumping so rule stubs */
    else if (sc->run_mode_flags & RUN_MODE_FLAG__RULE_DUMP)
    {
        sc->run_mode = RUN_MODE__RULE_DUMP;
    }
#endif
    /* Next if we want to test a snort conf */
    else if (sc->run_mode_flags & RUN_MODE_FLAG__TEST)
    {
        sc->run_mode = RUN_MODE__TEST;
    }
    /* Now if there is a snort conf.  If a snort conf wasn't given on the
     * command line, we'll look in a default place if the next ones
     * don't match */
    else if ((sc->run_mode_flags & RUN_MODE_FLAG__IDS) && (snort_conf_file != NULL))
    {
        sc->run_mode = RUN_MODE__IDS;
    }
    /* If logging but not alerting or log directory is set */
    else if ((output_logging && !output_alerting) || (sc->log_dir != NULL))
    {
        sc->no_alert = 1;
        sc->run_mode = RUN_MODE__PACKET_LOG;
    }
    /* If none of the above and not logging or alerting and verbose */
    else if ((!output_logging && !output_alerting) &&
             (sc->logging_flags & LOGGING_FLAG__VERBOSE))
    {
        sc->no_alert = 1;
        sc->no_log = 1;
        sc->run_mode = RUN_MODE__PACKET_DUMP;
    }

    if (!sc->run_mode)
        sc->run_mode = RUN_MODE__IDS;

    /* If no mode is set, try and find snort conf in some default location */
    if (((sc->run_mode == RUN_MODE__IDS) || (sc->run_mode == RUN_MODE__TEST)) &&
        (snort_conf_file == NULL))
    {
        snort_conf_file = ConfigFileSearch();
        if (snort_conf_file == NULL)
        {
            /* unable to determine a run mode */
            DisplayBanner();
            ShowUsage(argv[0]);
            
            ErrorMessage("\n");
            ErrorMessage("\n");
            ErrorMessage("Uh, you need to tell me to do something...");
            ErrorMessage("\n");
            ErrorMessage("\n");
            FatalError("");
        }
    }

    if ((sc->run_mode == RUN_MODE__PACKET_LOG) &&
        (sc->output_configs == NULL))
    {
        ParseOutput(sc, NULL, "log_tcpdump");
    }

    SetSnortConfDir();
}

/*
 * Function: SetPktProcessor()
 *
 * Purpose:  Set which packet processing function we're going to use based on
 *           what type of datalink layer we're using
 *
 * Arguments: int num => number of interface
 *
 * Returns: 0 => success
 */
static int SetPktProcessor(void)
{
#ifdef GIDS
    if (ScAdapterInlineMode())
    {

#ifndef IPFW
        LogMessage("Setting the Packet Processor to decode packets "
                   "from iptables\n");

        grinder = DecodeIptablesPkt;
#else
        LogMessage("Setting the Packet Processor to decode packets "
                   "from ipfw divert\n");

        grinder = DecodeIpfwPkt;
#endif /* IPFW */

        return 0;

    }
#endif /* GIDS */

    switch(datalink)
    {
        case DLT_EN10MB:        /* Ethernet */
            if (!ScReadMode())
            {
                LogMessage("Decoding Ethernet on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodeEthPkt;
            break;

#ifndef NO_NON_ETHER_DECODER
#ifdef DLT_IEEE802_11
        case DLT_IEEE802_11:
            if (!ScReadMode())
            {
                LogMessage("Decoding IEEE 802.11 on interface %s\n",
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodeIEEE80211Pkt;
            break;
#endif
#ifdef DLT_ENC
        case DLT_ENC:           /* Encapsulated data */
            if (!ScReadMode())
            {
                LogMessage("Decoding Encapsulated data on interface %s\n",
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodeEncPkt;
            break;

#else
        case 13:
#endif /* DLT_ENC */
        case DLT_IEEE802:                /* Token Ring */
            if (!ScReadMode())
            {
                LogMessage("Decoding Token Ring on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodeTRPkt;
            break;

        case DLT_FDDI:                /* FDDI */
            if (!ScReadMode())
            {
                LogMessage("Decoding FDDI on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodeFDDIPkt;
            break;

#ifdef DLT_CHDLC
        case DLT_CHDLC:              /* Cisco HDLC */
            if (!ScReadMode())
            {
                LogMessage("Decoding Cisco HDLC on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodeChdlcPkt;
            break;
#endif

        case DLT_SLIP:                /* Serial Line Internet Protocol */
            if (!ScReadMode())
            {
                LogMessage("Decoding Slip on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            if (ScOutputDataLink())
            {
                LogMessage("Second layer header parsing for this datalink "
                           "isn't implemented yet\n");

                snort_conf->output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
            }

            grinder = DecodeSlipPkt;
            break;
#endif  // NO_NON_ETHER_DECODER

        case DLT_PPP:                /* point-to-point protocol */
            if (!ScReadMode())
            {
                LogMessage("Decoding PPP on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            if (ScOutputDataLink())
            {
                /* do we need ppp header showup? it's only 4 bytes anyway ;-) */
                LogMessage("Second layer header parsing for this datalink "
                           "isn't implemented yet\n");

                snort_conf->output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
            }

            grinder = DecodePppPkt;
            break;

#ifndef NO_NON_ETHER_DECODER
#ifdef DLT_PPP_SERIAL
        case DLT_PPP_SERIAL:         /* PPP with full HDLC header*/
            if (!ScReadMode())
            {
                LogMessage("Decoding PPP on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            if (ScOutputDataLink())
            {
                /* do we need ppp header showup? it's only 4 bytes anyway ;-) */
                LogMessage("Second layer header parsing for this datalink "
                        "isn't implemented yet\n");

                snort_conf->output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
            }

            grinder = DecodePppSerialPkt;
            break;
#endif

#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            if (!ScReadMode())
            {
                LogMessage("Decoding 'ANY' on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodeLinuxSLLPkt;
            break;
#endif

#ifdef DLT_PFLOG
        case DLT_PFLOG:
            if (!ScReadMode())
            {
                LogMessage("Decoding OpenBSD PF log on interface %s\n",
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodePflog;
            break;
#endif

#ifdef DLT_OLDPFLOG
        case DLT_OLDPFLOG:
            if (!ScReadMode())
            {
                LogMessage("Decoding old OpenBSD PF log on interface %s\n",
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodeOldPflog;
            break;
#endif

#ifdef DLT_LOOP
        case DLT_LOOP:
#endif
#endif  // NON_ETHER_DECODER
        case DLT_NULL:
            /* loopback and stuff.. you wouldn't perform intrusion detection
             * on it, but it's ok for testing. */
            if (!ScReadMode())
            {
                LogMessage("Decoding LoopBack on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            if (ScOutputDataLink())
            {
                LogMessage("Data link layer header parsing for this network "
                           "type isn't implemented yet\n");

                snort_conf->output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
            }

            grinder = DecodeNullPkt;
            break;

#ifdef DLT_RAW /* Not supported in some arch or older pcap
                * versions */
        case DLT_RAW:
            if (!ScReadMode())
            {
                LogMessage("Decoding raw data on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            if (ScOutputDataLink())
            {
                LogMessage("There's no second layer header available for "
                           "this datalink\n");

                snort_conf->output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
            }

            grinder = DecodeRawPkt;
            break;
#endif
            /*
             * you need the I4L modified version of libpcap to get this stuff
             * working
             */
#ifdef DLT_I4L_RAWIP
        case DLT_I4L_RAWIP:
            if (!ScReadMode())
            {
                LogMessage("Decoding I4L-rawip on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodeI4LRawIPPkt;
            break;
#endif

#ifdef DLT_I4L_IP
        case DLT_I4L_IP:
            if (!ScReadMode())
            {
                LogMessage("Decoding I4L-ip on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodeEthPkt;
            break;
#endif

#ifdef DLT_I4L_CISCOHDLC
        case DLT_I4L_CISCOHDLC:
            if (!ScReadMode())
            {
                LogMessage("Decoding I4L-cisco-h on interface %s\n", 
                           PRINT_INTERFACE(pcap_interface));
            }

            grinder = DecodeI4LCiscoIPPkt;
            break;
#endif

        default:
            /* oops, don't know how to handle this one */
            FatalError("Cannot handle data link type %d\n", datalink);
            break;
    }

    return 0;
}

/*
 *  Handle idle time checks in snort packet processing loop 
 */
static void SnortIdle(void)
{
    /* Rollover of performance log */ 
    if (IsSetRotatePerfFileFlag())
    {
        sfRotatePerformanceStatisticsFile();
        ClearRotatePerfFileFlag();
    }
}

/*
 * Function: void *InterfaceThread(void *arg)
 *
 * Purpose: wrapper for pthread_create() to create a thread per interface
 */
void * InterfaceThread(void *arg)
{
    int pcap_ret;
    struct timezone tz;
    int pkts_to_read = (int)snort_conf->pkt_cnt;

    memset(&tz, 0, sizeof(tz));
    gettimeofday(&starttime, &tz);

    /* Read all packets on the device.  Continue until cnt packets read */
#ifdef USE_PCAP_LOOP
    pcap_ret = pcap_loop(pcap_handle, pkts_to_read, (pcap_handler)PcapProcessPacket, NULL);
#else

    while (1)
    {
        if (ScReadMode() && ScPcapShow())
        {
            fprintf(stdout, "Reading network traffic from \"%s\" with snaplen = %d\n",
                    strcmp(current_read_file, "-") == 0 ? "stdin" : current_read_file,
                    pcap_snapshot(pcap_handle));
        }

        pcap_ret = pcap_dispatch(pcap_handle, pkts_to_read,
                                 (pcap_handler)PcapProcessPacket, NULL);

        if (pcap_ret < 0)
            break;

        /* If reading from a file... 0 packets at EOF */
        if (ScReadMode() && (pcap_ret == 0))
        {
            char reopen_pcap = 0;

            if (sfqueue_count(pcap_queue) > 0)
            {
                reopen_pcap = 1;
            }
            else if (pcap_loop_count)
            {
                if (pcap_loop_count > 0)
                    pcap_loop_count--;

                if (pcap_loop_count != 0)
                {
                    SF_QUEUE *tmp;

                    /* switch pcap lists */
                    tmp = pcap_queue;
                    pcap_queue = pcap_save_queue;
                    pcap_save_queue = tmp;

                    reopen_pcap = 1;
                }
            }

            if (reopen_pcap)
            {
                if (ScPcapReset())
                    PcapReset();

                /* reinitialize pcap */
                pcap_close(pcap_handle);
                pcap_handle = NULL;
                OpenPcap();
                if (ScPcapReset())
                    SetPktProcessor();

                /* open a new tcpdump file - necessary because the snaplen and
                 * datalink could be different between pcaps */
                if (snort_conf->log_tcpdump)
                {
                    /* this sleep is to ensure we get a new log file since it has a
                     * time stamp with resolution to the second */
#ifdef WIN32
                    Sleep(1000);
#else
                    sleep(1);
#endif
                    LogTcpdumpReset();
                }

                continue;
            }

            break;
        }

        /* continue... pcap_ret packets that time around. */
        pkts_to_read -= pcap_ret;

        if ((pkts_to_read <= 0) && (snort_conf->pkt_cnt != -1))
        {
            break;
        }
        
        /* Check for any pending signals when no packets are read*/        
        if (pcap_ret == 0)
        {
            /* check for signals */
            if (SignalCheck())
            { 
#ifndef SNORT_RELOAD
                /* Got SIGHUP */
                Restart();
#endif
            }


            if (ScIdsMode())
            {
                CheckForReload();
            }
        }


        /* idle time processing..quick things to check or do ... */
        SnortIdle();
    }
#endif
    if (pcap_ret < 0)
    {
        if (ScDaemonMode())
        {
            syslog(LOG_PID | LOG_CONS | LOG_DAEMON,
                   "pcap_loop: %s", pcap_geterr(pcap_handle));
        }
        else
        {
            ErrorMessage("pcap_loop: %s\n", pcap_geterr(pcap_handle));
        }

        CleanExit(1);
    }
    
    done_processing = 1;

    CleanExit(0);

    return NULL;                /* avoid warnings */
}


/* Resets Snort to a post-configuration state */
static void PcapReset(void)
{
    PreprocSignalFuncNode *idxPreprocReset;
    PreprocSignalFuncNode *idxPreprocResetStats;

    /* reset preprocessors */
    idxPreprocReset = preproc_reset_funcs;
    while (idxPreprocReset != NULL)
    {
        idxPreprocReset->func(-1, idxPreprocReset->arg);
        idxPreprocReset = idxPreprocReset->next;
    }

    SnortEventqReset();
    Replace_ResetQueue();

    sfthreshold_reset_active();
    RateFilter_ResetActive();
#ifndef SUP_IP6
    BsdFragHashReset();
#endif
    TagCacheReset();

#ifdef PERF_PROFILING
    ShowPreprocProfiles();
    ShowRuleProfiles();
#endif

    DropStats(0);
    
    /* zero out packet count */
    memset(&pc, 0, sizeof(pc));

#ifdef TIMESTATS
    ResetTimeStats();
#endif

#ifdef PERF_PROFILING
    ResetRuleProfiling();
    ResetPreprocProfiling();
#endif

    /* reset preprocessor stats */
    idxPreprocResetStats = preproc_reset_stats_funcs;
    while (idxPreprocResetStats != NULL)
    {
        idxPreprocResetStats->func(-1, idxPreprocResetStats->arg);
        idxPreprocResetStats = idxPreprocResetStats->next;
    }
}

/****************************************************************************
 *
 * Function: EmptyPcapCmd(char *)
 *
 * Purpose:  Check for empty pcap command string
 *
 * Arguments: pcap_cmd => the string to be passed to pcap_compile()
 *
 * Returns: 0 => string is not empty
 *          1 => string is empty
 *
 ****************************************************************************/
static int EmptyPcapCmd(char *pcap_cmd)
{
    int i = 0;

    if (pcap_cmd == NULL)
        return 1;

    while ((pcap_cmd[i] != '\0') && isspace((int)pcap_cmd[i]))
        i++;

    if (pcap_cmd[i] == '\0')
        return 1;

    return 0;
}

/****************************************************************************
 *
 * Function: OpenPcap()
 *
 * Purpose:  Open the libpcap interface
 *
 * Arguments: none
 *
 * Returns: None
 *
 ****************************************************************************/
static void OpenPcap(void)
{
    char errorbuf[PCAP_ERRBUF_SIZE];      /* buffer to put error strings in */
    static char first_pcap = 1;           /* for backwards compatibility only show first pcap */
    int ret;

    if (pcap_handle != NULL)
        return;

    errorbuf[0] = '\0';

    if (pcap_interface == NULL)
    {
        if (snort_conf->interface == NULL)
        {
            /* if we're not reading packets from a file */
            if (!ScReadMode())
            {
#ifdef WIN32
                pcap_if_t *alldevs;

                if ((pcap_findalldevs(&alldevs, errorbuf) == -1) ||
                    (alldevs == NULL))
                {
                    FatalError("OpenPcap() interface lookup: %s\n",
                               errorbuf);
                }

                /* Pick first interface */
                pcap_interface = SnortStrdup(alldevs->name);
                pcap_freealldevs(alldevs);
#else
                char *interface;

                DEBUG_WRAP(DebugMessage(
                    DEBUG_INIT, "interface is NULL, looking up interface...."););

                /* look up the device and get the handle */
                interface = pcap_lookupdev(errorbuf);

                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "found interface %s\n",
                                        PRINT_INTERFACE(interface)););

                /* uh oh, we couldn't find the interface name */
                if (interface == NULL)
                {
                    FatalError("OpenPcap() interface lookup: %s\n",
                               errorbuf);
                }

                pcap_interface = SnortStrdup(interface);
#endif
            }
            else
            {
                /* interface is null and we are in readmode
                 * some routines would hate it to be NULL */
                pcap_interface = SnortStrdup("[reading from a file]"); 
            }
        }
        else
        {
            pcap_interface = SnortStrdup(snort_conf->interface);
        }
    }

    if (!ScReadMode() && first_pcap)
    {
        LogMessage("Initializing Network Interface %s\n", 
                   PRINT_INTERFACE(pcap_interface));
    }
    else if (first_pcap)
    {
        LogMessage("TCPDUMP file reading mode.\n");
    }

    if (!ScReadMode())
    {
        int promisc = !(snort_conf->run_flags & RUN_FLAG__NO_PROMISCUOUS);

        /* get the device file descriptor */
        pcap_handle = pcap_open_live(pcap_interface, pcap_snaplen, promisc,
                                     READ_TIMEOUT, errorbuf);
    }
    else
    {
        /* reading packets from a file */
        if (sfqueue_count(pcap_queue) > 0)
        {
            char *pcap = NULL;

            pcap = (char *)sfqueue_remove(pcap_queue);
            if (pcap == NULL)
            {
                FatalError("Could not get pcap from list\n");
            }

            ret = SnortStrncpy(current_read_file, pcap, sizeof(current_read_file));
            if (ret != SNORT_STRNCPY_SUCCESS)
                FatalError("Could not copy pcap name to current read file buffer.\n");

            ret = sfqueue_add(pcap_save_queue, (NODE_DATA)pcap);
            if (ret == -1)
                FatalError("Could not add pcap to saved list\n");
        }

        if (first_pcap)
        {
            LogMessage("Reading network traffic from \"%s\" file.\n", 
                       strcmp(current_read_file, "-") == 0 ? "stdin" : current_read_file);
        }

        /* open the file */
        pcap_handle = pcap_open_offline(current_read_file, errorbuf);

        /* the file didn't open correctly */
        if (pcap_handle == NULL)
        {
            FatalError("Unable to open file \"%s\" for readback: %s\n",
                       current_read_file, errorbuf);
        }

        /* set the snaplen for the file (so we don't get a lot of extra crap
         * in the end of packets */
        pcap_snaplen = pcap_snapshot(pcap_handle);

        if (first_pcap)
        {
            LogMessage("snaplen = %d\n", pcap_snaplen);
        }
    }

    /* something is wrong with the opened packet socket */
    if (pcap_handle == NULL)
    {
        if (strstr(errorbuf, "Permission denied"))
        {
            FatalError("You don't have permission to sniff.  Try "
                       "doing this as root.\n");
        }
        else
        {
            FatalError("OpenPcap() device %s open: %s\n",
                       PRINT_INTERFACE(pcap_interface), errorbuf);
        }
    }

    if (strlen(errorbuf) > 0)
    {
        LogMessage("Warning: OpenPcap() device %s success with warning: %s.\n",
                   PRINT_INTERFACE(pcap_interface), errorbuf);
    }

    SetBpfFilter(snort_conf->bpf_filter);

    /* get data link type */
    datalink = pcap_datalink(pcap_handle);

    if (datalink < 0)
    {
        FatalError("OpenPcap() datalink grab: %s\n", pcap_geterr(pcap_handle));
    }

    first_pcap = 0;
}

static void SetBpfFilter(char *bpf_filter)
{
    struct bpf_program bpf_prog;
    bpf_u_int32 defaultnet = 0xFFFFFF00;
    bpf_u_int32 localnet, netmask;
    char errorbuf[PCAP_ERRBUF_SIZE];

    errorbuf[0] = '\0';

    if ((pcap_handle == NULL) || (pcap_interface == NULL) ||
        (bpf_filter == NULL) || EmptyPcapCmd(bpf_filter))
    {
        return;
    }

    /* get local net and netmask */
    if (pcap_lookupnet(pcap_interface, &localnet, &netmask, errorbuf) < 0)
    {
        if (!ScReadMode())
        {
            ErrorMessage("OpenPcap() device %s network lookup: %s.\n",
                         PRINT_INTERFACE(pcap_interface), errorbuf);

        }

        /* set the default netmask to 255.255.255.0 (for stealthed
         * interfaces) */
        netmask = htonl(defaultnet);
    }

    /* compile BPF filter spec info fcode FSM */
    if (pcap_compile(pcap_handle, &bpf_prog, bpf_filter, 1, netmask) < 0)
    {
        FatalError("Bpf compilation failed: %s.  PCAP filter: %s.\n",
                   pcap_geterr(pcap_handle), snort_conf->bpf_filter);
    }

    /* set the pcap filter */
    if (pcap_setfilter(pcap_handle, &bpf_prog) < 0)
    {
        FatalError("Bpf set filter failed: %s\n", pcap_geterr(pcap_handle));
    }

    /* we can do this here now instead of later before every pcap_close() */
    pcap_freecode(&bpf_prog);
}


/* locate one of the possible default config files */
/* allocates memory to hold filename */
static char *ConfigFileSearch(void)
{
    struct stat st;
    int i;
    char *conf_files[]={"/etc/snort.conf", "./snort.conf", NULL};
    char *fname = NULL;
    char *rval = NULL;

    i = 0;

    /* search the default set of config files */
    while(conf_files[i])
    {
        fname = conf_files[i];

        if(stat(fname, &st) != -1)
        {
            rval = SnortStrdup(fname);
            break;
        }
        i++;
    }

    /* search for .snortrc in the HOMEDIR */
    if(!rval)
    {
        char *home_dir = NULL;

        if((home_dir = getenv("HOME")) != NULL)
        {
            char *snortrc = "/.snortrc";
            int path_len;

            path_len = strlen(home_dir) + strlen(snortrc) + 1;

            /* create the full path */
            fname = (char *)SnortAlloc(path_len);

            SnortSnprintf(fname, path_len, "%s%s", home_dir, snortrc);

            if(stat(fname, &st) != -1)
                rval = fname;
            else
                free(fname);
        }
    }

    return rval;
}

/* Signal Handlers ************************************************************/
static void SigExitHandler(int signal)
{
    if (exit_signal != 0)
        return;

    /* Don't want to have to wait to start processing packets before
     * getting out of dodge */
    if (snort_initializing)
        _exit(0);

    exit_signal = signal;
}

#ifdef TIMESTATS
static void SigAlrmHandler(int signal)
{
    /* Save off the alarm signal */
    alrm_signal = signal;
}
#endif

static void SigUsrHandler(int signal)
{
    if (usr_signal != 0)
        return;

    usr_signal = signal;
}

static void SigHupHandler(int signal)
{
#if defined(SNORT_RELOAD) && !defined(WIN32)
    hup_signal++;
#else
    hup_signal = 1;
#endif
}

/****************************************************************************
 *
 * Function: CleanExit()
 *
 * Purpose:  Clean up misc file handles and such and exit
 *
 * Arguments: exit value;
 *
 * Returns: void function
 *
 ****************************************************************************/
void CleanExit(int exit_val)
{
    /* Have to trick LogMessage to log correctly after snort_conf is freed */
    SnortConfig tmp;

    memset(&tmp, 0, sizeof(SnortConfig));
    if (snort_conf != NULL)
    {
        tmp.logging_flags |= (snort_conf->logging_flags & LOGGING_FLAG__QUIET);
        tmp.run_flags |= (snort_conf->run_flags & RUN_FLAG__DAEMON);
        tmp.logging_flags |= (snort_conf->logging_flags & LOGGING_FLAG__SYSLOG);
    }

    SnortCleanup(exit_val);
    snort_conf = &tmp;
    LogMessage("Snort exiting\n");
#ifndef WIN32
    closelog();
#endif
    exit(exit_val);
}

static void SnortCleanup(int exit_val)
{
    PreprocSignalFuncNode *idxPreproc = NULL;
    PluginSignalFuncNode *idxPlugin = NULL;

    /* This function can be called more than once.  For example,
     * once from the SIGINT signal handler, and once recursively
     * as a result of calling pcap_close() below.  We only need
     * to perform the cleanup once, however.  So the static
     * variable already_exiting will act as a flag to prevent
     * double-freeing any memory.  Not guaranteed to be
     * thread-safe, but it will prevent the simple cases.
     */
    static int already_exiting = 0;
    if( already_exiting != 0 )
    {
        return;
    }
    already_exiting = 1;
    snort_exiting = 1;
    snort_initializing = 0;  /* just in case we cut out early */

#ifdef PCAP_CLOSE
#ifdef GIDS
    if ((pcap_handle != NULL) && !ScAdapterInlineMode())
#else
    if (pcap_handle != NULL)
#endif
    {
        /* update stats before exit check */
        UpdatePcapPktStats(1);

#ifdef EXIT_CHECK
        if (snort_conf->exit_check)
            ExitCheckEnd();
#endif
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }
#endif

#if defined(SNORT_RELOAD) && !defined(WIN32)
    /* Setting snort_exiting will cause the thread to break out
     * of it's loop and exit */
    if (snort_reload_thread_created)
        pthread_join(snort_reload_thread_id, NULL);
#endif

#if defined(INLINE_FAILOPEN) && !defined(GIDS) && !defined(WIN32)
    if (inline_failopen_thread_running)
        pthread_kill(inline_failopen_thread_id, SIGKILL);
#endif

#if defined(TARGET_BASED) && !defined(WIN32)
    if (attribute_reload_thread_running)
    {
        /* Set the flag to stop the attribute reload thread and
         * send VTALRM signal to pull it out of the idle sleep.
         * Thread exits normally on next iteration through its
         * loop.
         * 
         * If its doing other processing, that continues post
         * interrupt and thread exits normally.
         */
        attribute_reload_thread_stop = 1;
        pthread_kill(attribute_reload_thread_id, SIGVTALRM);
        while (attribute_reload_thread_running)
            nanosleep(&thread_sleep, NULL);
        pthread_join(attribute_reload_thread_id, NULL);
    }
#endif

    if (ScIdsMode())
    {
        /* Do some post processing on any incomplete Preprocessor Data */
        idxPreproc = preproc_shutdown_funcs;
        while (idxPreproc)
        {
            idxPreproc->func(SIGQUIT, idxPreproc->arg);
            idxPreproc = idxPreproc->next;
        }

        /* Do some post processing on any incomplete Plugin Data */
        idxPlugin = plugin_shutdown_funcs;
        while(idxPlugin)
        {
            idxPlugin->func(SIGQUIT, idxPlugin->arg);
            idxPlugin = idxPlugin->next;
        }
    }

    if (!exit_val)
    {
        struct timeval difftime;
        struct timezone tz;

        bzero((char *) &tz, sizeof(tz));
        gettimeofday(&endtime, &tz);

        TIMERSUB(&endtime, &starttime, &difftime);

        if (done_processing)
        {
            LogMessage("Run time for packet processing was %lu.%lu seconds\n", 
                       (unsigned long)difftime.tv_sec,
                       (unsigned long)difftime.tv_usec);
        }
        else if (exit_signal)
        {
            LogMessage("Run time prior to being shutdown was %lu.%lu seconds\n", 
                       (unsigned long)difftime.tv_sec,
                       (unsigned long)difftime.tv_usec);
        }
    }

#ifdef TIMESTATS
    alarm(0);   /* cancel any existing alarm and disable alarm() function */
#endif

    if (ScIdsMode() || ScTestMode())
    {
        /* Exit preprocessors */
        idxPreproc = preproc_clean_exit_funcs;
        while(idxPreproc)
        {
            idxPreproc->func(SIGQUIT, idxPreproc->arg);
            idxPreproc = idxPreproc->next;
        }

        /* Do some post processing on any incomplete Plugin Data */
        idxPlugin = plugin_clean_exit_funcs;
        while(idxPlugin)
        {
            idxPlugin->func(SIGQUIT, idxPlugin->arg);
            idxPlugin = idxPlugin->next;
        }
    }

    if (decoderActionQ != NULL)
    {
        sfActionQueueDestroy (decoderActionQ);
        mempool_destroy (&decoderAlertMemPool);
        decoderActionQ = NULL;
        bzero(&decoderAlertMemPool, sizeof(decoderAlertMemPool));
    }

    /* Print Statistics */
    if (!ScTestMode() && !ScVersionMode()
#ifdef DYNAMIC_PLUGIN
        && !ScRuleDumpMode()
#endif
       )
    {
        if (ScIdsMode())
            fpShowEventStats(snort_conf);

#ifdef PERF_PROFILING
        if (ScIdsMode())
        {
            int save_quiet_flag = snort_conf->logging_flags & LOGGING_FLAG__QUIET;

            snort_conf->logging_flags &= ~LOGGING_FLAG__QUIET;

            ShowPreprocProfiles();
            ShowRuleProfiles();

            snort_conf->logging_flags |= save_quiet_flag;
        }
#endif

        DropStats(2);
    }

#if defined(GIDS) && !defined(IPFW)
    if (ScAdapterInlineMode())
    {
        if (ipqh)
        {
            ipq_destroy_handle(ipqh);
        }
    }
#endif /* defined(GIDS) && !defined(IPFW) (may need cleanup code here) */

#ifndef SUP_IP6
    BsdFragHashCleanup();
#endif

    CleanupProtoNames();

#ifdef TARGET_BASED
    SFAT_Cleanup();
#endif

#ifndef PCAP_CLOSE
    /* close pcap */
#ifdef GIDS
    if ((pcap_handle != NULL) && !ScAdapterInlineMode())
#else
    if (pcap_handle != NULL)
#endif
    {
#ifdef EXIT_CHECK
        if (snort_conf->exit_check)
            ExitCheckEnd();
#endif
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }
#endif

    /* clean up pcap queues */
    if (pcap_queue != NULL)
        sfqueue_free_all(pcap_queue, free);
    if (pcap_save_queue != NULL)
        sfqueue_free_all(pcap_save_queue, free);

    ClosePidFile();

    /* remove pid file */
    if (SnortStrnlen(snort_conf->pid_filename, sizeof(snort_conf->pid_filename)) > 0)
    {
        int ret;

        ret = unlink(snort_conf->pid_filename);
        if (ret != 0)
        {
            ErrorMessage("Could not remove pid file %s: %s\n",
                         snort_conf->pid_filename, strerror(errno));
        }
    }

    /* free allocated memory */
    if (snort_conf == snort_cmd_line_conf)
    {
        SnortConfFree(snort_cmd_line_conf);
        snort_cmd_line_conf = NULL;
        snort_conf = NULL;
    }
    else
    {
        SnortConfFree(snort_cmd_line_conf);
        snort_cmd_line_conf = NULL;
        SnortConfFree(snort_conf);
        snort_conf = NULL;
    }

    detection_filter_cleanup();
    sfthreshold_free();
    RateFilter_Cleanup();
    asn1_free_mem();
    FreeOutputConfigFuncs();
    FreePreprocConfigFuncs();

    FreeRuleOptConfigFuncs(rule_opt_config_funcs);
    rule_opt_config_funcs = NULL;

    FreeRuleOptOverrideInitFuncs(rule_opt_override_init_funcs);
    rule_opt_override_init_funcs = NULL;

    FreeRuleOptParseCleanupList(rule_opt_parse_cleanup_list);
    rule_opt_parse_cleanup_list = NULL;

    FreeOutputList(AlertList);
    AlertList = NULL;

    FreeOutputList(LogList);
    LogList = NULL;

    /* Global lists */
    FreePreprocStatsFuncs(preproc_stats_funcs);
    preproc_stats_funcs = NULL;

    FreePreprocSigFuncs(preproc_shutdown_funcs);
    preproc_shutdown_funcs = NULL;

    FreePreprocSigFuncs(preproc_clean_exit_funcs);
    preproc_clean_exit_funcs = NULL;

    FreePreprocSigFuncs(preproc_restart_funcs);
    preproc_restart_funcs = NULL;

    FreePreprocSigFuncs(preproc_reset_funcs);
    preproc_reset_funcs = NULL;

    FreePreprocSigFuncs(preproc_reset_stats_funcs);
    preproc_reset_stats_funcs = NULL;

    FreePluginSigFuncs(plugin_shutdown_funcs);
    plugin_shutdown_funcs = NULL;

    FreePluginSigFuncs(plugin_clean_exit_funcs);
    plugin_clean_exit_funcs = NULL;

    FreePluginSigFuncs(plugin_restart_funcs);
    plugin_restart_funcs = NULL;

    ParserCleanup();

    /* Stuff from plugbase */
#ifdef DYNAMIC_PLUGIN
    DynamicRuleListFree(dynamic_rules);
    dynamic_rules = NULL;

    CloseDynamicPreprocessorLibs();
    CloseDynamicDetectionLibs();
    CloseDynamicEngineLibs();
#endif

    CleanupTag();
    ClearDumpBuf();

#ifdef PERF_PROFILING
    CleanupPreprocStatsNodeList();
#endif

    if (pcap_interface != NULL)
    {
        free(pcap_interface);
        pcap_interface = NULL;
    }

    if (netmasks != NULL)
    {
        free(netmasks);
        netmasks = NULL;
    }

    if (protocol_names != NULL)
    {
        int i;

        for (i = 0; i < NUM_IP_PROTOS; i++)
        {
            if (protocol_names[i] != NULL)
                free(protocol_names[i]);
        }

        free(protocol_names);
        protocol_names = NULL;
    }

    SynToMulticastDstIpDestroy();

    if (snort_conf_file != NULL)
        free(snort_conf_file);

    if (snort_conf_dir != NULL)
        free(snort_conf_dir);
}

void Restart(void)
{
    int daemon_mode = ScDaemonMode();

#ifndef WIN32
    if ((!ScReadMode() && (getuid() != 0)) ||
        (snort_conf->chroot_dir != NULL))
    {
        LogMessage("Reload via Signal HUP does not work if you aren't root "
                   "or are chroot'ed.\n");
#if defined(SNORT_RELOAD) && !defined(WIN32)
        /* We are restarting because of a configuration verification problem */
        CleanExit(1);
#else
        return;
#endif
    }
#endif

    LogMessage("\n");
    LogMessage("***** Restarting Snort *****\n");
    LogMessage("\n");
    SnortCleanup(0);

    if (daemon_mode)
    {
        int i;

        for (i = 0; i < snort_argc; i++)
        {
            if (!strcmp(snort_argv[i], "--restart"))
            {
                break;
            }
            else if (!strncmp(snort_argv[i], "-D", 2))
            {
                /* Replace -D with --restart */
                /* a probable memory leak - but we're exec()ing anyway */
                snort_argv[i] = SnortStrdup("--restart");
                break;
            }
        }
    }

#ifdef PARANOID
    execv(snort_argv[0], snort_argv);
#else
    execvp(snort_argv[0], snort_argv);
#endif

    /* only get here if we failed to restart */
    LogMessage("Restarting %s failed: %s\n", snort_argv[0], strerror(errno));

#ifndef WIN32
    closelog();
#endif

    exit(-1);
}

static void InitPcap(int test_flag)
{
    if (ScVersionMode() || (ScTestMode() && (snort_conf->interface == NULL))
#ifdef DYNAMIC_PLUGIN
        || ScRuleDumpMode()
#endif
        )
    {
        return;
    }

    if ((snort_conf->interface == NULL) &&
        (pcap_interface == NULL) && !ScReadMode())
    {
#ifdef MUST_SPECIFY_DEVICE
        FatalError( "You must specify either: a network interface (-i), "
# ifdef DYNAMIC_PLUGIN
                    "dump dynamic rules to a file (--dump-dynamic-rules), "
# endif
                    "a capture file (-r), or the test flag (-T)\n");
#else
        char errorbuf[PCAP_ERRBUF_SIZE];

# ifdef GIDS
        if (!ScAdapterInlineMode())
        {
# endif /* GIDS */
#ifdef WIN32
            pcap_if_t *alldevs;

            if ((pcap_findalldevs(&alldevs, errorbuf) == -1) ||
                (alldevs == NULL))
            {
                FatalError("OpenPcap() interface lookup: %s\n",
                           errorbuf);
            }

            /* Pick first interface */
            pcap_interface = SnortStrdup(alldevs->name);
            pcap_freealldevs(alldevs);
#else
            char *interface = pcap_lookupdev(errorbuf);

            if (interface == NULL)
            {
                FatalError( "Failed to lookup for interface: %s. "
                            "Please specify one with -i switch\n", errorbuf);
            }
            else
            {
                LogMessage("***\n");
                LogMessage("*** interface device lookup found: %s\n", interface);
                LogMessage("***\n");
            }

            pcap_interface = SnortStrdup(interface);
#endif
# ifdef GIDS
        }
# endif /* GIDS */

#endif
    }

#ifndef WIN32
    g_pcap_test = test_flag;
#endif

    OpenPcap();

    /* If test mode, need to close pcap again. */
    if (test_flag || ScTestMode())
    {
#ifdef GIDS
        if ((pcap_handle != NULL) && !ScAdapterInlineMode())
#else
        if (pcap_handle != NULL)
#endif
        {
            pcap_close(pcap_handle);
            pcap_handle = NULL;
        }

        return;
    }
}

//PORTLISTS
void print_packet_count(void)
{
    LogMessage("[" STDu64 "]", pc.total_from_pcap);
}

/*
 *  Check for signal activity 
 */
int SignalCheck(void)
{
    switch (exit_signal)
    {
        case SIGTERM:
            if (!exit_logged)
            {
                ErrorMessage("*** Caught Term-Signal\n");
                exit_logged = 1;
            }
            CleanExit(0);
            break;

        case SIGINT:
            if (!exit_logged)
            {
                ErrorMessage("*** Caught Int-Signal\n");
                exit_logged = 1;
            }
            CleanExit(0);
            break;

        case SIGQUIT:
            if (!exit_logged)
            {
                ErrorMessage("*** Caught Quit-Signal\n");
                exit_logged = 1;
            }
            CleanExit(0);
            break;

        default:
            break;
    }

    exit_signal = 0;

    switch (usr_signal)
    {
        case SIGUSR1:
            ErrorMessage("*** Caught Usr-Signal\n");
            DropStats(0);
            break;

        case SIGNAL_SNORT_ROTATE_STATS:
            ErrorMessage("*** Caught Usr-Signal: 'Rotate Stats'\n");
            SetRotatePerfFileFlag();
            break;
    }

    usr_signal = 0;

#ifdef TIMESTATS
    switch (alrm_signal)
    {
        case SIGALRM:
            ErrorMessage("*** Caught Alrm-Signal\n");
            DropStatsPerTimeInterval();
            break;
    }

    alrm_signal = 0;
#endif

#ifndef SNORT_RELOAD
    if (hup_signal)
    {
        ErrorMessage("*** Caught Hup-Signal\n");
        hup_signal = 0;
        return 1;
    }
#endif

    return 0;
}

static void InitGlobals(void)
{
    memset(&pc, 0, sizeof(PacketCount));

    InitNetmasks();
    InitProtoNames();
}

/* XXX Alot of this initialization can be skipped if not running
 * in IDS mode */
SnortConfig * SnortConfNew(void)
{
    SnortConfig *sc = (SnortConfig *)SnortAlloc(sizeof(SnortConfig));

    sc->pkt_cnt = -1;
    sc->pkt_snaplen = -1;

    sc->user_id = -1;
    sc->group_id = -1;

    sc->checksum_flags = CHECKSUM_FLAG__ALL;
    sc->tagged_packet_limit = 256;
    sc->default_rule_state = RULE_STATE_ENABLED;
    sc->pcre_match_limit = 1500;
    sc->pcre_match_limit_recursion = 1500;
    sc->ipv6_max_frag_sessions = 10000;
    sc->ipv6_frag_timeout = 60;  /* This is the default timeout on BSD */

    memset(sc->pid_path, 0, sizeof(sc->pid_path));
    memset(sc->pid_filename, 0, sizeof(sc->pid_filename));
    memset(sc->pidfile_suffix, 0, sizeof(sc->pidfile_suffix));

#ifdef TIMESTATS
    sc->timestats_interval = 3600;  /* Default to 1 hour */
#endif

#ifdef TARGET_BASED
    /* Default max size of the attribute table */
    sc->max_attribute_hosts = DEFAULT_MAX_ATTRIBUTE_HOSTS;

    /* Default max number of services per rule */
    sc->max_metadata_services = DEFAULT_MAX_METADATA_SERVICES;
#endif

#ifdef MPLS
    sc->mpls_stack_depth = DEFAULT_LABELCHAIN_LENGTH;
#endif

#if defined(GIDS) && defined(IPFW)
    sc->divert_port = 8000;
#endif

    sc->targeted_policies = NULL;
    sc->num_policies_allocated = 0;

    return sc;
}

void SnortConfFree(SnortConfig *sc)
{
    tSfPolicyId i;

    if (sc == NULL)
        return;

    if (sc->dynamic_rules_path != NULL)
        free(sc->dynamic_rules_path);

    if (sc->log_dir != NULL)
        free(sc->log_dir);

    if (sc->orig_log_dir != NULL)
        free(sc->orig_log_dir);

    if (sc->interface != NULL)
        free(sc->interface);

    if (sc->bpf_file != NULL)
        free(sc->bpf_file);

    if (sc->pcap_log_file != NULL)
        free(sc->pcap_log_file);

    if (sc->chroot_dir != NULL)
        free(sc->chroot_dir);

    if (sc->alert_file != NULL)
        free(sc->alert_file);

    if (sc->perf_file != NULL)
        free(sc->perf_file);

    if (sc->bpf_filter != NULL)
        free(sc->bpf_filter);

#ifdef PERF_PROFILING
    if (sc->profile_rules.filename != NULL)
        free(sc->profile_rules.filename);

    if (sc->profile_preprocs.filename != NULL)
        free(sc->profile_preprocs.filename);
#endif

#ifdef ENABLE_RESPONSE2
    if (sc->respond2_ethdev != NULL)
        free(sc->respond2_ethdev);
#endif

#ifdef DYNAMIC_PLUGIN
    FreeDynamicLibInfos(sc);
#endif

    FreeOutputConfigs(sc->output_configs);
    FreeOutputConfigs(sc->rule_type_output_configs);
    FreePreprocConfigs(sc);

    if (sc->config_table != NULL)
        sfghash_delete(sc->config_table);

    if (sc->base_version != NULL)
        free(sc->base_version);

    for (i = 0; i < sc->num_policies_allocated; i++)
    {
        SnortPolicyFree(sc->targeted_policies[i]);
    }

    FreeRuleStateList(sc->rule_state_list);
    FreeClassifications(sc->classifications);
    FreeReferences(sc->references);

    FreeRuleLists(sc);
    SoRuleOtnLookupFree(sc->so_rule_otn_map);
    OtnLookupFree(sc->otn_map);
    VarTablesFree(sc);

#ifdef PORTLISTS
    PortTablesFree(sc->port_tables);
#endif

    FastPatternConfigFree(sc->fast_pattern_config);
    EventQueueConfigFree(sc->event_queue_config);
    SnortEventqFree(sc->event_queue);
    ThresholdConfigFree(sc->threshold_config);
    RateFilter_ConfigFree(sc->rate_filter_config);
    DetectionFilterConfigFree(sc->detection_filter_config);

    FreePlugins(sc);

    OtnxMatchDataFree(sc->omd);

    if (sc->ip_proto_only_lists != NULL)
    {
        unsigned int j;

        for (j = 0; j < NUM_IP_PROTOS; j++)
            sflist_free_all(sc->ip_proto_only_lists[j], NULL);

        free(sc->ip_proto_only_lists);
    }

#if defined(SNORT_RELOAD) && !defined(WIN32)
    FreePreprocReloadVerifyFuncList(sc->preproc_reload_verify_funcs);
#endif

#ifdef DYNAMIC_PLUGIN
    for (i = 0; i < sc->num_policies_allocated; i++)
    {
        SnortPolicy *p = sc->targeted_policies[i];

        if (p == NULL)
            continue;

        PreprocessorRuleOptionsFree(p->preproc_rule_options);
    }
#endif

    sfPolicyFini(sc->policy_config);

    fpDeleteFastPacketDetection(sc);

    for (i = 0; i < sc->num_policies_allocated; i++)
    {
        SnortPolicy *p = sc->targeted_policies[i];

        if (p != NULL)
            free(p);
    }

    free(sc->targeted_policies);

    free(sc);
}

/****************************************************************************
 *
 * Function: InitNetMasks()
 *
 * Purpose: Loads the netmask struct in network order.  Yes, I know I could
 *          just load the array when I define it, but this is what occurred
 *          to me when I wrote this at 3:00 AM.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
static void InitNetmasks(void)
{
    if (netmasks == NULL)
        netmasks = (uint32_t *)SnortAlloc(33 * sizeof(uint32_t));

    netmasks[0]  = 0x00000000;
    netmasks[1]  = 0x80000000;
    netmasks[2]  = 0xC0000000;
    netmasks[3]  = 0xE0000000;
    netmasks[4]  = 0xF0000000;
    netmasks[5]  = 0xF8000000;
    netmasks[6]  = 0xFC000000;
    netmasks[7]  = 0xFE000000;
    netmasks[8]  = 0xFF000000;
    netmasks[9]  = 0xFF800000;
    netmasks[10] = 0xFFC00000;
    netmasks[11] = 0xFFE00000;
    netmasks[12] = 0xFFF00000;
    netmasks[13] = 0xFFF80000;
    netmasks[14] = 0xFFFC0000;
    netmasks[15] = 0xFFFE0000;
    netmasks[16] = 0xFFFF0000;
    netmasks[17] = 0xFFFF8000;
    netmasks[18] = 0xFFFFC000;
    netmasks[19] = 0xFFFFE000;
    netmasks[20] = 0xFFFFF000;
    netmasks[21] = 0xFFFFF800;
    netmasks[22] = 0xFFFFFC00;
    netmasks[23] = 0xFFFFFE00;
    netmasks[24] = 0xFFFFFF00;
    netmasks[25] = 0xFFFFFF80;
    netmasks[26] = 0xFFFFFFC0;
    netmasks[27] = 0xFFFFFFE0;
    netmasks[28] = 0xFFFFFFF0;
    netmasks[29] = 0xFFFFFFF8;
    netmasks[30] = 0xFFFFFFFC;
    netmasks[31] = 0xFFFFFFFE;
    netmasks[32] = 0xFFFFFFFF;
}

/****************************************************************************
 *
 * Function: InitProtoNames()
 *
 * Purpose: Initializes the protocol names
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
static void InitProtoNames(void)
{
    int i;

    if (protocol_names == NULL)
        protocol_names = (char **)SnortAlloc(sizeof(char *) * NUM_IP_PROTOS);

    for (i = 0; i < NUM_IP_PROTOS; i++)
    {
        struct protoent *pt = getprotobynumber(i);

        if (pt != NULL)
        {
            size_t j;

            protocol_names[i] = SnortStrdup(pt->p_name);
            for (j = 0; j < strlen(protocol_names[i]); j++)
                protocol_names[i][j] = toupper(protocol_names[i][j]);
        }
        else
        {
            char protoname[10];

            SnortSnprintf(protoname, sizeof(protoname), "PROTO:%03d", i);
            protocol_names[i] = SnortStrdup(protoname);
        }
    }
}


static void SetSnortConfDir(void)
{
    /* extract the config directory from the config filename */
    if (snort_conf_file != NULL)
    {
#ifndef WIN32
        char *path_sep = strrchr(snort_conf_file, '/');
#else
        char *path_sep = strrchr(snort_conf_file, '\\');
#endif

        /* is there a directory seperator in the filename */
        if (path_sep != NULL)
        {
            path_sep++;  /* include path separator */
            snort_conf_dir = SnortStrndup(snort_conf_file, path_sep - snort_conf_file);
        }
        else
        {
            snort_conf_dir = SnortStrdup("./");
        }

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Config file = %s, config dir = "
                    "%s\n", snort_conf_file, snort_conf_dir););
    }
}

static void FreePlugins(SnortConfig *sc)
{
    if (sc == NULL)
        return;

    FreePreprocessors(sc);

    FreePluginSigFuncs(sc->plugin_post_config_funcs);
    sc->plugin_post_config_funcs = NULL;
}

static void FreePreprocessors(SnortConfig *sc)
{
    tSfPolicyId i;

    if (sc == NULL)
        return;

    FreePreprocCheckConfigFuncs(sc->preproc_config_check_funcs);
    sc->preproc_config_check_funcs = NULL;

    for (i = 0; i < sc->num_policies_allocated; i++)
    {
        SnortPolicy *p = sc->targeted_policies[i];

        if (p == NULL)
            continue;

        FreePreprocReassemblyPktFuncs(p->preproc_reassembly_pkt_funcs);
        p->preproc_reassembly_pkt_funcs = NULL;

        FreePreprocEvalFuncs(p->preproc_eval_funcs);
        p->preproc_eval_funcs = NULL;
    }

    FreePreprocPostConfigFuncs(sc->preproc_post_config_funcs);
    sc->preproc_post_config_funcs = NULL;
}

static SnortConfig * MergeSnortConfs(SnortConfig *cmd_line, SnortConfig *config_file)
{
    unsigned int i;

    /* Move everything from the command line config over to the
     * config_file config */

    if (cmd_line == NULL)
    {
        FatalError("%s(%d) Merging snort configs: snort conf is NULL.\n",
                   __FILE__, __LINE__);
    }

    ResolveOutputPlugins(cmd_line, config_file);

    if (config_file == NULL)
    {
        if (cmd_line->log_dir == NULL)
            cmd_line->log_dir = SnortStrdup(DEFAULT_LOG_DIR);
    }
    else if ((cmd_line->log_dir == NULL) && (config_file->log_dir == NULL))
    {
        config_file->log_dir = SnortStrdup(DEFAULT_LOG_DIR);
    }
    else if (cmd_line->log_dir != NULL)
    {
        if (config_file->log_dir != NULL)
            free(config_file->log_dir);

        config_file->log_dir = SnortStrdup(cmd_line->log_dir);
    }

    if (config_file == NULL)
        return cmd_line;

    /* Used because of a potential chroot */
    config_file->orig_log_dir = SnortStrdup(config_file->log_dir);

    config_file->run_mode = cmd_line->run_mode;
    config_file->run_mode_flags |= cmd_line->run_mode_flags;

    if ((cmd_line->run_mode == RUN_MODE__TEST) &&
        (config_file->run_flags & RUN_FLAG__DAEMON))
    {
        /* Just ignore deamon setting in conf file */
        config_file->run_flags &= ~RUN_FLAG__DAEMON;
    }

    config_file->run_flags |= cmd_line->run_flags;

    config_file->output_flags |= cmd_line->output_flags;

    config_file->logging_flags |= cmd_line->logging_flags;

    /* Merge checksum flags.  If command line modified them, use from the
     * command line, else just use from config_file. */
    for (i = 0; i < config_file->num_policies_allocated; i++)
    {
        if (config_file->targeted_policies[i] != NULL)
        {
            if (cmd_line->checksum_flags_modified)
                config_file->targeted_policies[i]->checksum_flags = cmd_line->checksum_flags;

            if (cmd_line->checksum_drop_flags_modified)
                config_file->targeted_policies[i]->checksum_drop_flags = cmd_line->checksum_drop_flags;
        }
    }

    config_file->event_log_id = cmd_line->event_log_id;

    if (cmd_line->dynamic_rules_path != NULL)
    {
        if(strcmp(cmd_line->dynamic_rules_path, "")  != 0)
        {
            if( config_file->dynamic_rules_path != NULL )
                free(config_file->dynamic_rules_path);
            config_file->dynamic_rules_path = SnortStrdup(cmd_line->dynamic_rules_path);
        }
    }


#ifdef DYNAMIC_PLUGIN
    if (cmd_line->dyn_engines != NULL)
    {
        FreeDynamicLibInfo(config_file->dyn_engines);
        config_file->dyn_engines = DupDynamicLibInfo(cmd_line->dyn_engines);
    }

    if (cmd_line->dyn_rules != NULL)
    {
        FreeDynamicLibInfo(config_file->dyn_rules);
        config_file->dyn_rules = DupDynamicLibInfo(cmd_line->dyn_rules);
    }

    if (cmd_line->dyn_preprocs != NULL)
    {
        FreeDynamicLibInfo(config_file->dyn_preprocs);
        config_file->dyn_preprocs = DupDynamicLibInfo(cmd_line->dyn_preprocs);
    }
#endif

    if (cmd_line->pid_path[0] != '\0')
        ConfigPidPath(config_file, cmd_line->pid_path);

    config_file->exit_check = cmd_line->exit_check;

    /* Command line only configures search method */
    if (cmd_line->fast_pattern_config != NULL)
        config_file->fast_pattern_config->search_method = cmd_line->fast_pattern_config->search_method;

#ifdef SUP_IP6
    if (cmd_line->obfuscation_net.family != 0)
        memcpy(&config_file->obfuscation_net, &cmd_line->obfuscation_net, sizeof(sfip_t));

    if (cmd_line->homenet.family != 0)
        memcpy(&config_file->homenet, &cmd_line->homenet, sizeof(sfip_t));
#else
    if (cmd_line->obfuscation_mask != 0)
    {
        config_file->obfuscation_mask = cmd_line->obfuscation_mask;
        config_file->obfuscation_net = cmd_line->obfuscation_net;
    }

    if (cmd_line->netmask != 0)
    {
        config_file->netmask = cmd_line->netmask;
        config_file->homenet = cmd_line->homenet;
    }
#endif

    if (cmd_line->interface != NULL)
    {
        if (config_file->interface != NULL)
            free(config_file->interface);
        config_file->interface = SnortStrdup(cmd_line->interface);
    }

    if (cmd_line->bpf_file != NULL)
    {
        if (config_file->bpf_file != NULL)
            free(config_file->bpf_file);
        config_file->bpf_file = SnortStrdup(cmd_line->bpf_file);
    }

    if (cmd_line->bpf_filter != NULL)
        config_file->bpf_filter = SnortStrdup(cmd_line->bpf_filter);

    if (cmd_line->pkt_snaplen != -1)
        config_file->pkt_snaplen = cmd_line->pkt_snaplen;

    if (cmd_line->pkt_cnt != -1)
        config_file->pkt_cnt = cmd_line->pkt_cnt;

    if (cmd_line->group_id != -1)
        config_file->group_id = cmd_line->group_id;

    if (cmd_line->user_id != -1)
        config_file->user_id = cmd_line->user_id;

#if defined(GIDS) && defined(IPFW)
    config_file->divert_port = cmd_line->divert_port;

    if (config_file->interface != NULL)
    {
        free(config_file->interface);
        config_file->interface = NULL;
    }
#endif

    /* Only configurable on command line */
    if (cmd_line->pcap_log_file != NULL)
        config_file->pcap_log_file = SnortStrdup(cmd_line->pcap_log_file);

    if (cmd_line->file_mask != 0)
        config_file->file_mask = cmd_line->file_mask;

    if (cmd_line->pidfile_suffix[0] != '\0')
    {
        SnortStrncpy(config_file->pidfile_suffix, cmd_line->pidfile_suffix,
                     sizeof(config_file->pidfile_suffix));
    }

    if (cmd_line->chroot_dir != NULL)
    {
        if (config_file->chroot_dir != NULL)
            free(config_file->chroot_dir);
        config_file->chroot_dir = SnortStrdup(cmd_line->chroot_dir);
    }

    if (cmd_line->perf_file != NULL)
    {
        if (config_file->perf_file != NULL)
            free(config_file->perf_file);
        config_file->perf_file = SnortStrdup(cmd_line->perf_file);
    }

#ifdef MPLS
    if (cmd_line->mpls_stack_depth != DEFAULT_LABELCHAIN_LENGTH)
        config_file->mpls_stack_depth = cmd_line->mpls_stack_depth;

    /* Set MPLS payload type here if it hasn't been defined */
    if ((cmd_line->mpls_payload_type == 0) &&
        (config_file->mpls_payload_type == 0))
    {
        config_file->mpls_payload_type = DEFAULT_MPLS_PAYLOADTYPE;
    }
    else if (cmd_line->mpls_payload_type != 0)
    {
        config_file->mpls_payload_type = cmd_line->mpls_payload_type;
    }
#endif

    if (cmd_line->run_flags & RUN_FLAG__PROCESS_ALL_EVENTS)
        config_file->event_queue_config->process_all_events = 1;

    return config_file;
}

#ifdef DYNAMIC_PLUGIN
static void FreeDynamicLibInfos(SnortConfig *sc)
{
    if (sc == NULL)
        return;

    if (sc->dyn_engines != NULL)
    {
        FreeDynamicLibInfo(sc->dyn_engines);
        sc->dyn_engines = NULL;
    }

    if (sc->dyn_rules != NULL)
    {
        FreeDynamicLibInfo(sc->dyn_rules);
        sc->dyn_rules = NULL;
    }

    if (sc->dyn_preprocs != NULL)
    {
        FreeDynamicLibInfo(sc->dyn_preprocs);
        sc->dyn_preprocs = NULL;
    }
}

static void FreeDynamicLibInfo(DynamicLibInfo *lib_info)
{
    unsigned i;

    if (lib_info == NULL)
        return;

    for (i = 0; i < lib_info->count; i++)
    {
        free(lib_info->lib_paths[i]->path);
        free(lib_info->lib_paths[i]);
    }

    free(lib_info);
}

static DynamicLibInfo * DupDynamicLibInfo(DynamicLibInfo *src)
{
    DynamicLibInfo *dst;
    unsigned i;

    if (src == NULL)
        return NULL;

    dst = (DynamicLibInfo *)SnortAlloc(sizeof(DynamicLibInfo));
    dst->type = src->type;
    dst->count = src->count;

    for (i = 0; i < src->count; i++)
    {
        DynamicLibPath *dylib_path = (DynamicLibPath *)SnortAlloc(sizeof(DynamicLibPath));

        dylib_path->ptype = src->lib_paths[i]->ptype;
        dylib_path->path = SnortStrdup(src->lib_paths[i]->path);

        dst->lib_paths[i] = dylib_path;
    }

    return dst;
}
#endif

void FreeVarList(VarNode *head)
{
    while (head != NULL)
    {
        VarNode *tmp = head;
        
        head = head->next;

        if (tmp->name != NULL)
            free(tmp->name);

        if (tmp->value != NULL)
            free(tmp->value);

        if (tmp->line != NULL)
            free(tmp->line);

        free(tmp);
    }
}

static void SnortInit(int argc, char **argv)
{
    InitGlobals();

    /* chew up the command line */
    ParseCmdLine(argc, argv);

    switch (snort_conf->run_mode)
    {
        case RUN_MODE__VERSION:
            break;

#ifdef DYNAMIC_PLUGIN
        case RUN_MODE__RULE_DUMP:
            LogMessage("Running in Rule Dump mode\n");
            break;
#endif
        case RUN_MODE__IDS:
            LogMessage("Running in IDS mode\n");
            break;

        case RUN_MODE__TEST:
            LogMessage("Running in Test mode\n");
            break;

        case RUN_MODE__PACKET_LOG:
            LogMessage("Running in packet logging mode\n");
            break;

        case RUN_MODE__PACKET_DUMP:
            LogMessage("Running in packet dump mode\n");
            break;

        default:
            break;
    }

    LogMessage("\n");
    LogMessage("        --== Initializing Snort ==--\n");

    /* If running with -Q and not combination of test mode and
     * disable inline init flag.  The disable inline init flag is used for
     * test mode so as not to open iptables stuff */
#ifdef GIDS
    if (ScAdapterInlineMode() && !(ScTestMode() && ScDisableInlineInit()))
    {
        InitInline();
    }
#endif /* GIDS */

    if (!ScVersionMode())
    {
        /* Every run mode except version will potentially need output
         * If output plugins should become dynamic, this needs to move */
        RegisterOutputPlugins();
#ifdef DEBUG
        DumpOutputPlugins();
#endif
    }

    /* if we're using the rules system, it gets initialized here */
    if (snort_conf_file != NULL)
    {
        SnortConfig *sc;

        /* initialize all the plugin modules */
        RegisterPreprocessors();
        RegisterRuleOptions();
        InitTag();

#ifdef DEBUG
        DumpPreprocessors();
        DumpRuleOptions();
#endif

#ifdef PERF_PROFILING
        /* Register the main high level perf stats */
        RegisterPreprocessorProfile("detect", &detectPerfStats, 0, &totalPerfStats);
        RegisterPreprocessorProfile("mpse", &mpsePerfStats, 1, &detectPerfStats);
        RegisterPreprocessorProfile("rule eval", &rulePerfStats, 1, &detectPerfStats);
        RegisterPreprocessorProfile("rtn eval", &ruleRTNEvalPerfStats, 2, &rulePerfStats);
        RegisterPreprocessorProfile("rule tree eval", &ruleOTNEvalPerfStats, 2, &rulePerfStats);
#ifdef DYNAMIC_PLUGIN
        RegisterPreprocessorProfile("preproc_rule_options", &preprocRuleOptionPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
        RegisterPreprocessorProfile("decode", &decodePerfStats, 0, &totalPerfStats);
        RegisterPreprocessorProfile("eventq", &eventqPerfStats, 0, &totalPerfStats);
        RegisterPreprocessorProfile("total", &totalPerfStats, 0, NULL);
#endif

        LogMessage("Parsing Rules file \"%s\"\n", snort_conf_file);
        sc = ParseSnortConf();

        /* Merge the command line and config file confs to take care of
         * command line overriding config file.
         * Set the global snort_conf that will be used during run time */
        snort_conf = MergeSnortConfs(snort_cmd_line_conf, sc);

        InitSynToMulticastDstIp();

#ifdef TARGET_BASED
        /* Parse attribute table stuff here since config max_attribute_hosts
         * is apart from attribute table configuration.
         * Only attribute table in default policy is processed. Attribute table in 
         * other policies indicates that attribute table in default table should 
         * be used. Filenames for attribute_table should be same across all policies.
         */ 
        if (ScIdsMode())
        {
            tSfPolicyId defaultPolicyId = sfGetDefaultPolicy(snort_conf->policy_config);
            TargetBasedConfig *tbc = &snort_conf->targeted_policies[defaultPolicyId]->target_based_config;

            if (tbc->args != NULL)
            {
                char *saved_file_name = file_name;
                int saved_file_line = file_line;

                file_name = tbc->file_name;
                file_line = tbc->file_line;

                SFAT_ParseAttributeTable(tbc->args);

                file_name = saved_file_name;
                file_line = saved_file_line;
            }
        }
#endif

        if (snort_conf->asn1_mem != 0)
            asn1_init_mem(snort_conf->asn1_mem);
        else
            asn1_init_mem(256);

        if (snort_conf->alert_file != NULL)
        {
            char *tmp = snort_conf->alert_file;
            snort_conf->alert_file = ProcessFileOption(snort_conf, snort_conf->alert_file);
            free(tmp);
        }

        if (snort_conf->pcap_file != NULL)
        {
            PcapReadObject *pro;

            if (pcap_object_list == NULL)
            {
                pcap_object_list = sflist_new();
                if (pcap_object_list == NULL)
                    FatalError("Could not allocate list to store pcap\n");
            }

            pro = (PcapReadObject *)SnortAlloc(sizeof(PcapReadObject));
            pro->type = PCAP_SINGLE;
            pro->arg = SnortStrdup(snort_conf->pcap_file);
            pro->filter = NULL;

            if (sflist_add_tail(pcap_object_list, (NODE_DATA)pro) == -1)
            {
                FatalError("Could not add pcap object to list: %s\n",
                           snort_conf->pcap_file);
            }
        }

#ifdef PERF_PROFILING
        /* Parse profiling here because of file option and potential
         * dependence on log directory */
        {
            char *opts = NULL;
            int in_table;

            in_table = sfghash_find2(snort_conf->config_table,
                                     CONFIG_OPT__PROFILE_PREPROCS, (void *)&opts);
            if (in_table)
                ConfigProfilePreprocs(snort_conf, opts);

            in_table = sfghash_find2(snort_conf->config_table,
                                     CONFIG_OPT__PROFILE_RULES, (void *)&opts);
            if (in_table)
                ConfigProfileRules(snort_conf, opts);
        }
#endif

        if (ScAlertBeforePass())
        {
#ifdef GIDS
            OrderRuleLists(snort_conf, "activation dynamic drop sdrop reject alert pass log");
#else
            OrderRuleLists(snort_conf, "activation dynamic drop alert pass log");
#endif
        }

        LogMessage("Tagged Packet Limit: %d\n", snort_conf->tagged_packet_limit);

#ifndef SUP_IP6
        BsdFragHashInit(ScIpv6MaxFragSessions());
#endif

        /* Handles Fatal Errors itself. */
        snort_conf->event_queue = SnortEventqNew(snort_conf->event_queue_config);
    }
    else if (ScPacketLogMode() || ScPacketDumpMode())
    {
        /* Make sure there is a log directory */
        /* This will return the cmd line conf and resolve the output
         * configuration */
        SnortConfig* sc = ParseSnortConf();
        snort_conf = MergeSnortConfs(snort_cmd_line_conf, sc);
#ifndef SUP_IP6
        BsdFragHashInit(ScIpv6MaxFragSessions());
#endif
    }

#if defined(GIDS) && !defined(IPFW)
    if (ScAdapterInlineMode() && !(ScTestMode() && ScDisableInlineInit()))
    {
        InitInlinePostConfig();
    }
#endif

    /* pcap_snaplen is already initialized to SNAPLEN */
    if (snort_conf->pkt_snaplen != -1)
        pcap_snaplen = (uint32_t)snort_conf->pkt_snaplen;

    /* Finish up the pcap list an put in the queues */
    if (pcap_object_list != NULL)
    {
        if (sflist_count(pcap_object_list) == 0)
        {
            sflist_free_all(pcap_object_list, NULL);
            FatalError("No pcaps specified.\n");
        }

        pcap_queue = sfqueue_new();
        pcap_save_queue = sfqueue_new();
        if ((pcap_queue == NULL) || (pcap_save_queue == NULL))
            FatalError("Could not allocate pcap queues.\n");

        if (GetPcaps(pcap_object_list, pcap_queue) == -1)
            FatalError("Error getting pcaps.\n");

        if (sfqueue_count(pcap_queue) == 0)
            FatalError("No pcaps found.\n");

        /* free pcap list used to get params */
        while (sflist_count(pcap_object_list) > 0)
        {
            PcapReadObject *pro = (PcapReadObject *)sflist_remove_head(pcap_object_list);
            if (pro == NULL)
                FatalError("Failed to remove pcap item from list.\n");

            if (pro->arg != NULL)
                free(pro->arg);

            if (pro->filter != NULL)
                free(pro->filter);

            free(pro);
        }

        sflist_free_all(pcap_object_list, NULL);
        pcap_object_list = NULL;
    }

    if ((snort_conf->bpf_filter == NULL) && (snort_conf->bpf_file != NULL))
    {
        LogMessage("Reading filter from bpf file: %s\n", snort_conf->bpf_file);
        snort_conf->bpf_filter = read_infile(snort_conf->bpf_file);
    }

    if (snort_conf->bpf_filter != NULL)
        LogMessage("Snort BPF option: %s\n", snort_conf->bpf_filter);

#ifdef DYNAMIC_PLUGIN
    LoadDynamicPlugins(snort_conf);
#endif

    /* Display snort version information here so that we can also show dynamic
     * plugin versions, if loaded.  */
    if (ScVersionMode())
    {
        PrintVersion();
        CleanExit(0);
    }

    /* Validate the log directory for logging packets - probably should
     * add test mode as well, but not expected behavior */
    if ((ScIdsMode() || ScPacketLogMode()) &&
        (!(ScNoLog() && ScNoAlert())))
    {
        if (ScPacketLogMode())
            CheckLogDir();

        LogMessage("Log directory = %s\n", snort_conf->log_dir);
    }

    if (ScOutputUseUtc())
        snort_conf->thiszone = 0;
    else
        snort_conf->thiszone = gmt2local(0);  /* ripped from tcpdump */

    ConfigureOutputPlugins(snort_conf);

    if (ScIdsMode() || ScTestMode())
    {
        /* Have to split up configuring preprocessors between internal and dynamic
         * because the dpd structure has a pointer to the stream api and stream5
         * needs to be configured first to set this */
        ConfigurePreprocessors(snort_conf, 0);
    }

#ifdef DYNAMIC_PLUGIN
    InitDynamicEngines(snort_conf->dynamic_rules_path);

    if (ScRuleDumpMode())
    {
        if( snort_conf->dynamic_rules_path == NULL )
        {
            FatalError("%s(%d) Please specify the directory path for dumping the dynamic rules \n",
                                       __FILE__, __LINE__);
        }

        DumpDetectionLibRules();
        CleanExit(0);
    }

    /* This will load each dynamic preprocessor module specified and set
     * the _dpd structure for each */
    InitDynamicPreprocessors();
#endif

    if (ScIdsMode() || ScTestMode())
    {
        /* Now configure the dynamic preprocessors since the dpd structure
         * should be filled in and have the correct values */
        ConfigurePreprocessors(snort_conf, 1);

        ParseRules(snort_conf);
        RuleOptParseCleanup();
    }

#ifdef DYNAMIC_PLUGIN
    InitDynamicDetectionPlugins(snort_conf);
#endif

    if (ScIdsMode() || ScTestMode())
    {
        detection_filter_print_config(snort_conf->detection_filter_config);
        RateFilter_PrintConfig(snort_conf->rate_filter_config);
        print_thresholding(snort_conf->threshold_config);
        PrintRuleOrder(snort_conf->rule_lists);

        /* Check rule state lists, enable/disabled
         * and err on 'special' GID without OTN.
         */
        /* 
         * Modified toi use sigInfo.shared in otn instead of the GENERATOR ID  - man 
         */ 
        SetRuleStates(snort_conf);

        /* Verify the preprocessors are configured properly */
        CheckPreprocessorsConfig(snort_conf);

        /* Need to do this after dynamic detection stuff is initialized, too */
        FlowBitsVerify();
    }

    if (snort_conf->file_mask != 0)
        umask(snort_conf->file_mask);
    else
        umask(077);    /* set default to be sane */

#ifdef TIMESTATS
    alarm(ScTimestatsInterval());
#endif
}

#if defined(INLINE_FAILOPEN) && !defined(GIDS) && !defined(WIN32)
static void * SnortPostInitThread(void *data)
{
    sigset_t mtmask;

    inline_failopen_thread_pid = getpid();
    inline_failopen_thread_running = 1;

    /* Don't handle any signals here */
    sigfillset(&mtmask);
    pthread_sigmask(SIG_BLOCK, &mtmask, NULL);

    while (!inline_failopen_pcap_initialized)
        nanosleep(&thread_sleep, NULL);

    SnortPostInit();

    pthread_exit((void *)NULL);
}

static void PcapIgnorePacket(char *user, struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
    /* Empty function -- do nothing with the packet we just read */
    inline_failopen_pass_pkt_cnt++;

#ifdef DEBUG
    {
        FILE *tmp = fopen("/var/tmp/fo_threadid", "a");
        if ( tmp )
        {
            fprintf(tmp, "Packet Count %d\n", inline_failopen_pass_pkt_cnt);
            fclose(tmp);
        }
    }
#endif
}
#endif /* defined(INLINE_FAILOPEN) && !defined(GIDS) && !defined(WIN32) */

static void SnortPostInit(void)
{
#ifndef HAVE_LINUXTHREADS
# if defined(INLINE_FAILOPEN) && !defined(GIDS) && !defined(WIN32)
    if (!inline_failopen_thread_running)
# endif
    {
        InitPidChrootAndPrivs();
    }
#elif !defined(WIN32)
    SnortStartThreads();
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Setting Packet Processor\n"););

    /* set the packet processor (ethernet, slip, t/r, etc ) */
    SetPktProcessor();

    decoderActionQ = sfActionQueueInit(snort_conf->event_queue_config->max_events*2);
    if (mempool_init(&decoderAlertMemPool,
                snort_conf->event_queue_config->max_events*2, sizeof(EventNode)) != 0)
    {
        FatalError("%s(%d) Could not initialize decoder action queue memory pool.\n",
                __FILE__, __LINE__);
    }

#ifdef HAVE_LIBPRELUDE
    AlertPreludeSetupAfterSetuid();
#endif

    PostConfigPreprocessors(snort_conf);
    PostConfigInitPlugins(snort_conf->plugin_post_config_funcs);

    fpCreateFastPacketDetection(snort_conf);

#ifdef PPM_MGR
    PPM_PRINT_CFG(&snort_conf->ppm_cfg);
#endif
#ifndef PORTLISTS
    mpsePrintSummary();
#endif

    LogMessage("\n");
    LogMessage("        --== Initialization Complete ==--\n");

    /* Tell 'em who wrote it, and what "it" is */
    if (!ScLogQuiet())
        PrintVersion();

    if (ScTestMode())
    {
        LogMessage("\n");
        LogMessage("Snort successfully loaded all rules and checked all rule chains!\n");
        CleanExit(0);
    }

    if (ScDaemonMode())
    {
        LogMessage("Snort initialization completed successfully (pid=%u)\n",getpid());
    }
    
    if( getenv("PCAP_FRAMES") )
    {
        LogMessage("Using PCAP_FRAMES = %s\n", getenv("PCAP_FRAMES") );
    }
    else
    {
        LogMessage("Not Using PCAP_FRAMES\n" );
    }

#ifdef TIMESTATS
    InitTimeStats();
#endif

    snort_initializing = 0;
}

static void SnortProcess(void)
{
#ifdef GIDS
    if (ScAdapterInlineMode())
    {
#ifndef IPFW
        IpqLoop();
#else
        IpfwLoop();
#endif
    }
    else
    {
#endif /* GIDS */

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Entering pcap loop\n"););

        InterfaceThread(NULL);
#ifdef GIDS
    }
#endif /* GIDS */
}

#if defined(NOCOREFILE) && !defined(WIN32)
static void SetNoCores(void)
{
    struct rlimit rlim;

    getrlimit(RLIMIT_CORE, &rlim);
    rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);
}
#endif

static void InitSignals(void)
{
#ifndef WIN32
# if defined(LINUX) || defined(FREEBSD) || defined(OPENBSD) || \
     defined(SOLARIS) || defined(BSD) || defined(MACOS)
    sigset_t set;

    sigemptyset(&set);
#  if defined(HAVE_LIBPRELUDE) || defined(INLINE_FAILOPEN) || \
      defined(TARGET_BASED) || defined(SNORT_RELOAD)
    pthread_sigmask(SIG_SETMASK, &set, NULL);
#  else
    sigprocmask(SIG_SETMASK, &set, NULL);
#  endif /* HAVE_LIBPRELUDE || INLINE_FAILOPEN */
# else
    sigsetmask(0);
# endif /* LINUX, BSD, SOLARIS */
#endif  /* !WIN32 */

    /* Make this prog behave nicely when signals come along.
     * Windows doesn't like all of these signals, and will
     * set errno for some.  Ignore/reset this error so it
     * doesn't interfere with later checks of errno value.  */
    signal(SIGTERM, SigExitHandler);
    signal(SIGINT, SigExitHandler);
    signal(SIGQUIT, SigExitHandler);
    signal(SIGUSR1, SigUsrHandler);
    signal(SIGNAL_SNORT_ROTATE_STATS, SigUsrHandler);

#ifdef TIMESTATS
    /* Establish a handler for SIGALRM signals and set an alarm to go off
     * in approximately one hour.  This is used to drop statistics at
     * an interval which the alarm will tell us to do. */
    signal(SIGALRM, SigAlrmHandler);
#endif

    signal(SIGHUP, SigHupHandler);

    errno = 0;
}

static void FreeOutputConfigs(OutputConfig *head)
{
    while (head != NULL)
    {
        OutputConfig *tmp = head;

        head = head->next;

        if (tmp->keyword != NULL)
            free(tmp->keyword);

        if (tmp->opts != NULL)
            free(tmp->opts);

        if (tmp->file_name != NULL)
            free(tmp->file_name);

        /* Don't free listhead as it's just a pointer to the user defined
         * rule's rule list node's list head */

        free(tmp);
    }
}

static void FreePreprocConfigs(SnortConfig *sc)
{
    tSfPolicyId i;

    if (sc == NULL)
        return;

    for (i = 0; i < sc->num_policies_allocated; i++)
    {
        SnortPolicy *p = sc->targeted_policies[i];
        PreprocConfig *head;

        if (p == NULL)
            continue;

        head = p->preproc_configs;

        while (head != NULL)
        {
            PreprocConfig *tmp = head;

            head = head->next;

            if (tmp->keyword != NULL)
                free(tmp->keyword);

            if (tmp->opts != NULL)
                free(tmp->opts);

            if (tmp->file_name != NULL)
                free(tmp->file_name);

            free(tmp);
        }
    }
}

static void FreeRuleStateList(RuleState *head)
{
    while (head != NULL)
    {
        RuleState *tmp = head;

        head = head->next;

        free(tmp);
    }
}

static void FreeClassifications(ClassType *head)
{
    while (head != NULL)
    {
        ClassType *tmp = head;

        head = head->next;

        if (tmp->name != NULL)
            free(tmp->name);

        if (tmp->type != NULL)
            free(tmp->type);

        free(tmp);
    }
}

static void FreeReferences(ReferenceSystemNode *head)
{
    while (head != NULL)
    {
        ReferenceSystemNode *tmp = head;

        head = head->next;

        if (tmp->name != NULL)
            free(tmp->name);

        if (tmp->url != NULL)
            free(tmp->url);

        free(tmp);
    }
}

#if defined(SNORT_RELOAD) && !defined(WIN32)
static void * ReloadConfigThread(void *data)
{
    sigset_t mtmask;

    /* Don't handle any signals here */
    sigfillset(&mtmask);
    pthread_sigmask(SIG_BLOCK, &mtmask, NULL);

    snort_reload_thread_pid = getpid();
    snort_reload_thread_created = 1;

    while (snort_initializing)
        nanosleep(&thread_sleep, NULL);

    while (!snort_exiting)
    {
        if (hup_signal != reload_hups)
        {
            reload_hups++;

            LogMessage("\n");
            LogMessage("        --== Reloading Snort ==--\n");
            LogMessage("\n");

            snort_conf_new = ReloadConfig();
            snort_reload = 1;

            while (!snort_swapped && !snort_exiting)
                nanosleep(&thread_sleep, NULL);

            snort_swapped = 0;

            SnortConfFree(snort_conf_old);
            snort_conf_old = NULL;

            if (snort_exiting)
            {
                /* If main thread is exiting, it won't swap in the new
                 * configuration, so free it here, really just to quiet
                 * valgrind.  Note the main thread will wait until this
                 * thread has exited */
                SnortConfFree(snort_conf_new);
                snort_conf_new = NULL;

                /* This will load the new preprocessor configurations and
                 * free the old ones, so any preprocessor cleanup that
                 * requires a configuration will be using the new one
                 * unless it relies on old configurations that are still
                 * attached to existing sessions. */
                SwapPreprocConfigurations();
                FreeSwappedPreprocConfigurations();

                /* Get out of the loop and exit */
                break;
            }

            LogMessage("\n");
            LogMessage("        --== Reload Complete ==--\n");
            LogMessage("\n");
        }

        sleep(1);
    }

    pthread_exit((void *)0);
}

static SnortConfig * ReloadConfig(void)
{
    SnortConfig *sc = ParseSnortConf();

    sc = MergeSnortConfs(snort_cmd_line_conf, sc);

#ifdef PERF_PROFILING
    /* Parse profiling here because of file option and potential
     * dependence on log directory */
    {
        char *opts = NULL;
        int in_table;

        in_table = sfghash_find2(sc->config_table,
                                 CONFIG_OPT__PROFILE_PREPROCS, (void *)&opts);
        if (in_table)
            ConfigProfilePreprocs(sc, opts);

        in_table = sfghash_find2(sc->config_table,
                                 CONFIG_OPT__PROFILE_RULES, (void *)&opts);
        if (in_table)
            ConfigProfileRules(sc, opts);
    }
#endif

    if (VerifyReload(sc) == -1)
    {
        SnortConfFree(sc);
        return NULL;
    }

    if (sc->output_flags & OUTPUT_FLAG__USE_UTC)
        snort_conf->thiszone = 0;
    else
        snort_conf->thiszone = gmt2local(0);

    /* Preprocessors will have a reload callback */
    ConfigurePreprocessors(sc, 1);

    ParseRules(sc);
    RuleOptParseCleanup();

#ifdef DYNAMIC_PLUGIN
    ReloadDynamicRules(sc);
#endif

    /* Handles Fatal Errors itself. */
    sc->event_queue = SnortEventqNew(sc->event_queue_config);

    detection_filter_print_config(sc->detection_filter_config);
    RateFilter_PrintConfig(sc->rate_filter_config);
    print_thresholding(sc->threshold_config);
    PrintRuleOrder(sc->rule_lists);

    SetRuleStates(sc);

    if (VerifyReloadedPreprocessors(sc) == -1)
    {
        SnortConfFree(sc);
        return NULL;
    }

    CheckPreprocessorsConfig(sc);
    PostConfigPreprocessors(sc);

    /* Need to do this after dynamic detection stuff is initialized, too */
    FlowBitsVerify();

#if 0
/* Don't allow reloading for now.  If the filter is deleted, there is no
 * pcap api function to delete the filter, but only set it to empty */
    if ((sc->bpf_filter == NULL) && (sc->bpf_file != NULL))
    {
        LogMessage("Reading filter from bpf file: %s\n", sc->bpf_file);
        sc->bpf_filter = read_infile(sc->bpf_file);
    }

    if ((sc->bpf_filter != NULL) && (snort_conf->bpf_filter != NULL))
    {
        if (strcasecmp(snort_conf->bpf_filter, sc->bpf_filter) != 0)
        {
            LogMessage("Snort BPF option: %s\n", sc->bpf_filter);
            SetBpfFilter(sc->bpf_filter);
        }
    }
    else if (sc->bpf_filter != NULL)
    {
        LogMessage("Snort BPF option: %s\n", sc->bpf_filter);
        SetBpfFilter(sc->bpf_filter);
    }
    else if (snort_conf->bpf_filter != NULL)
    {
        LogMessage("Resetting Snort BPF filter\n");
        SetBpfFilter("");
    }
#endif

    if ((sc->file_mask != 0) && (sc->file_mask != snort_conf->file_mask))
        umask(sc->file_mask);

    /* Transfer any user defined rule type outputs to the new rule list */
    {
        RuleListNode *cur = snort_conf->rule_lists;

        for (; cur != NULL; cur = cur->next)
        {
            RuleListNode *new = sc->rule_lists;

            for (; new != NULL; new = new->next)
            {
                if (strcasecmp(cur->name, new->name) == 0)
                {
                    OutputFuncNode *alert_list = cur->RuleList->AlertList;
                    OutputFuncNode *log_list = cur->RuleList->LogList;

                    head_tmp = new->RuleList;

                    for (; alert_list != NULL; alert_list = alert_list->next)
                    {
                        AddFuncToOutputList(alert_list->func,
                                            OUTPUT_TYPE__ALERT, alert_list->arg);
                    }

                    for (; log_list != NULL; log_list = log_list->next)
                    {
                        AddFuncToOutputList(log_list->func,
                                            OUTPUT_TYPE__LOG, log_list->arg);
                    }

                    head_tmp = NULL;
                    break;
                }
            }
        }
    }

    /* XXX XXX Can't do any output plugins */
    //PostConfigInitPlugins(sc->plugin_post_config_funcs);

    fpCreateFastPacketDetection(sc);

#ifdef PPM_MGR
    PPM_PRINT_CFG(&sc->ppm_cfg);
#endif

#ifndef PORTLISTS
    mpsePrintSummary();
#endif

    return sc;
}

static int VerifyReload(SnortConfig *sc)
{
    if (sc == NULL)
        return -1;

#ifdef TARGET_BASED
    {
        SnortPolicy *p1 = sc->targeted_policies[getDefaultPolicy()];
        SnortPolicy *p2 = snort_conf->targeted_policies[getDefaultPolicy()];

        if ((p1->target_based_config.args != NULL) &&
            (p2->target_based_config.args != NULL))
        {
            if (strcasecmp(p1->target_based_config.args,
                           p2->target_based_config.args) != 0)
            {
                ErrorMessage("Snort Reload: Changing the attribute table "
                             "configuration requires a restart.\n");
                return -1;
            }
        }
        else if (p1->target_based_config.args !=
                 p2->target_based_config.args)
        {
            /* Covers one being NULL and not the other */
            ErrorMessage("Snort Reload: Changing the attribute table "
                         "configuration requires a restart.\n");
            return -1;
        }
    }
#endif

    if ((snort_conf->alert_file != NULL) && (sc->alert_file != NULL))
    {
        if (strcasecmp(snort_conf->alert_file, sc->alert_file) != 0)
        {
            ErrorMessage("Snort Reload: Changing the alert file "
                         "configuration requires a restart.\n");
            return -1;
        }
    }
    else if (snort_conf->alert_file != sc->alert_file)
    {
        ErrorMessage("Snort Reload: Changing the alert file "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->asn1_mem != sc->asn1_mem)
    {
        ErrorMessage("Snort Reload: Changing the asn1 memory configuration "
                     "requires a restart.\n");
        return -1;
    }

    if ((sc->bpf_filter == NULL) && (sc->bpf_file != NULL))
        sc->bpf_filter = read_infile(sc->bpf_file);

    if ((sc->bpf_filter != NULL) && (snort_conf->bpf_filter != NULL))
    {
        if (strcasecmp(snort_conf->bpf_filter, sc->bpf_filter) != 0)
        {
            ErrorMessage("Snort Reload: Changing the bpf filter configuration "
                         "requires a restart.\n");
            return -1;
        }
    }
    else if (sc->bpf_filter != snort_conf->bpf_filter)
    {
        ErrorMessage("Snort Reload: Changing the bpf filter configuration "
                     "requires a restart.\n");
        return -1;
    }

    if ((snort_conf->chroot_dir != NULL) &&
        (sc->chroot_dir != NULL))
    {
        if (strcasecmp(snort_conf->chroot_dir, sc->chroot_dir) != 0)
        {
            ErrorMessage("Snort Reload: Changing the chroot directory "
                         "configuration requires a restart.\n");
            return -1;
        }
    }
    else if (snort_conf->chroot_dir != sc->chroot_dir)
    {
        ErrorMessage("Snort Reload: Changing the chroot directory "
                     "configuration requires a restart.\n");
        return -1;
    }

    if ((snort_conf->run_flags & RUN_FLAG__DAEMON) !=
        (sc->run_flags & RUN_FLAG__DAEMON))
    {
        ErrorMessage("Snort Reload: Changing to or from daemon mode "
                     "requires a restart.\n");
        return -1;
    }

#ifdef ENABLE_RESPONSE2
    if ((snort_conf->respond2_link != sc->respond2_link) ||
        (snort_conf->respond2_rows != sc->respond2_rows) ||
        (snort_conf->respond2_memcap != sc->respond2_memcap) ||
        (snort_conf->respond2_attempts != sc->respond2_attempts))
    {
        ErrorMessage("Snort Reload: Changing the respond2 link, rows, memcap "
                     "or attempts requires a restart.\n");
        return -1;
    }
#endif

    if ((snort_conf->interface != NULL) && (sc->interface != NULL))
    {
        if (strcasecmp(snort_conf->interface, sc->interface) != 0)
        {
            ErrorMessage("Snort Reload: Changing the interface "
                         "configuration requires a restart.\n");
            return -1;
        }
    }
    else if (snort_conf->interface != sc->interface)
    {
        ErrorMessage("Snort Reload: Changing the interface "
                     "configuration requires a restart.\n");
        return -1;
    }

    /* Orig log dir because a chroot might have changed it */
    if ((snort_conf->orig_log_dir != NULL) &&
        (sc->orig_log_dir != NULL))
    {
        if (strcasecmp(snort_conf->orig_log_dir, sc->orig_log_dir) != 0)
        {
            ErrorMessage("Snort Reload: Changing the log directory "
                         "configuration requires a restart.\n");
            return -1;
        }
    }
    else if (snort_conf->orig_log_dir != sc->orig_log_dir)
    {
        ErrorMessage("Snort Reload: Changing the log directory "
                     "configuration requires a restart.\n");
        return -1;
    }

#ifdef TARGET_BASED
    if (snort_conf->max_attribute_hosts != sc->max_attribute_hosts)
    {
        ErrorMessage("Snort Reload: Changing the max attribute hosts "
                     "configuration requires a restart.\n");
        return -1;
    }
#endif

    if (snort_conf->no_log != sc->no_log)
    {
        ErrorMessage("Snort Reload: Changing from log to no log or vice "
                     "versa requires a restart.\n");
        return -1;
    }

    if ((snort_conf->run_flags & RUN_FLAG__NO_PROMISCUOUS) !=
        (sc->run_flags & RUN_FLAG__NO_PROMISCUOUS))
    {
        ErrorMessage("Snort Reload: Changing to or from promiscuous mode "
                     "requires a restart.\n");
        return -1;
    }

    if (snort_conf->pkt_cnt != sc->pkt_cnt)
    {
        ErrorMessage("Snort Reload: Changing the packet count "
                     "configuration requires a restart.\n");
        return -1;
    }

#ifdef PPM_MGR
    /* XXX XXX Not really sure we need to disallow this */
    if (snort_conf->ppm_cfg.rule_log != sc->ppm_cfg.rule_log)
    {
        ErrorMessage("Snort Reload: Changing the ppm rule_log "
                     "configuration requires a restart.\n");
        return -1;
    }
#endif

#ifdef PERF_PROFILING
    if ((snort_conf->profile_rules.num != sc->profile_rules.num) ||
        (snort_conf->profile_rules.sort != sc->profile_rules.sort) ||
        (snort_conf->profile_rules.append != sc->profile_rules.append))
    {
        ErrorMessage("Snort Reload: Changing rule profiling number, sort "
                     "or append configuration requires a restart.\n");
        return -1;
    }

    if ((snort_conf->profile_rules.filename != NULL) &&
        (sc->profile_rules.filename != NULL))
    {
        if (strcasecmp(snort_conf->profile_rules.filename,
                       sc->profile_rules.filename) != 0)
        {
            ErrorMessage("Snort Reload: Changing the rule profiling filename "
                         "configuration requires a restart.\n");
            return -1;
        }
    }
    else if (snort_conf->profile_rules.filename !=
             sc->profile_rules.filename)
    {
        ErrorMessage("Snort Reload: Changing the rule profiling filename "
                     "configuration requires a restart.\n");
        return -1;
    }

    if ((snort_conf->profile_preprocs.num !=  sc->profile_preprocs.num) ||
        (snort_conf->profile_preprocs.sort != sc->profile_preprocs.sort) ||
        (snort_conf->profile_preprocs.append != sc->profile_preprocs.append))
    {
        ErrorMessage("Snort Reload: Changing preprocessor profiling number, "
                     "sort or append configuration requires a restart.\n");
        return -1;
    }

    if ((snort_conf->profile_preprocs.filename != NULL) &&
        (sc->profile_preprocs.filename != NULL))
    {
        if (strcasecmp(snort_conf->profile_preprocs.filename,
                       sc->profile_preprocs.filename) != 0)
        {
            ErrorMessage("Snort Reload: Changing the preprocessor profiling "
                         "filename configuration requires a restart.\n");
            return -1;
        }
    }
    else if (snort_conf->profile_preprocs.filename !=
             sc->profile_preprocs.filename)
    {
        ErrorMessage("Snort Reload: Changing the preprocessor profiling "
                     "filename configuration requires a restart.\n");
        return -1;
    }
#endif

    /* config read_bin_file */
    if ((snort_conf->pcap_file != NULL) &&
        (sc->pcap_file != NULL))
    {
        if (strcasecmp(snort_conf->pcap_file, sc->pcap_file) != 0)
        {
            ErrorMessage("Snort Reload: Changing the pcap file "
                         "configuration requires a restart.\n");
            return -1;
        }
    }
    else if (snort_conf->pcap_file != sc->pcap_file)
    {
        ErrorMessage("Snort Reload: Changing the pcap file "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->group_id != sc->group_id)
    {
        ErrorMessage("Snort Reload: Changing the group id "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->user_id != sc->user_id)
    {
        ErrorMessage("Snort Reload: Changing the user id "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->pkt_snaplen != sc->pkt_snaplen)
    {
        ErrorMessage("Snort Reload: Changing the packet snaplen "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->threshold_config->memcap !=
        sc->threshold_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the threshold memcap "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->rate_filter_config->memcap !=
        sc->rate_filter_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the rate filter memcap "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->detection_filter_config->memcap !=
        sc->detection_filter_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the detection filter memcap "
                     "configuration requires a restart.\n");
        return -1;
    }

#ifdef DYNAMIC_PLUGIN
    if (VerifyLibInfos(snort_conf->dyn_engines, sc->dyn_engines) == -1)
    {
        ErrorMessage("Snort Reload: Any change to the dynamic engine "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (VerifyLibInfos(snort_conf->dyn_rules, sc->dyn_rules) == -1)
    {
        ErrorMessage("Snort Reload: Any change to the dynamic detection "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (VerifyLibInfos(snort_conf->dyn_preprocs, sc->dyn_preprocs) == -1)
    {
        ErrorMessage("Snort Reload: Any change to the dynamic preprocessor "
                     "configuration requires a restart.\n");
        return -1;
    }
#endif

    if (VerifyOutputs(snort_conf, sc) == -1)
        return -1;

    return 0;
}

static int VerifyOutputs(SnortConfig *old_config, SnortConfig *new_config)
{
    OutputConfig *old_output_config, *new_output_config;
    int old_outputs = 0, new_outputs = 0;

    /* Get from output_configs to see if output has changed */
    for (old_output_config = old_config->output_configs;
         old_output_config != NULL;
         old_output_config = old_output_config->next)
    {
        old_outputs++;
    }

    for (new_output_config = new_config->output_configs;
         new_output_config != NULL;
         new_output_config = new_output_config->next)
    {
        new_outputs++;
    }

    if (new_outputs != old_outputs)
    {
        ErrorMessage("Snort Reload: Any change to any output "
                     "configurations requires a restart.\n");
        return -1;
    }

    for (old_output_config = old_config->output_configs;
         old_output_config != NULL;
         old_output_config = old_output_config->next)
    {

        for (new_output_config = new_config->output_configs;
             new_output_config != NULL;
             new_output_config = new_output_config->next)
        {
            if ((strcasecmp(old_output_config->keyword,
                            new_output_config->keyword) == 0) &&
                (strcasecmp(old_output_config->opts,
                            new_output_config->opts) == 0))
            {
                new_outputs++;
                break;
            }
        }

        old_outputs++;
    }

    if (new_outputs != old_outputs)
    {
        ErrorMessage("Snort Reload: Any change to any output "
                     "configurations requires a restart.\n");
        return -1;
    }

    /* Check user defined rule type outputs */
    for (old_output_config = old_config->rule_type_output_configs;
         old_output_config != NULL;
         old_output_config = old_output_config->next)
    {
        old_outputs++;
    }

    for (new_output_config = new_config->rule_type_output_configs;
         new_output_config != NULL;
         new_output_config = new_output_config->next)
    {
        new_outputs++;
    }

    if (new_outputs != old_outputs)
    {
        ErrorMessage("Snort Reload: Any change to any output "
                     "configurations requires a restart.\n");
        return -1;
    }

    /* Do user defined rule type outputs as well */
    for (old_output_config = old_config->rule_type_output_configs;
         old_output_config != NULL;
         old_output_config = old_output_config->next)
    {
        for (new_output_config = new_config->rule_type_output_configs;
             new_output_config != NULL;
             new_output_config = new_output_config->next)
        {
            if (strcasecmp(old_output_config->keyword,
                           new_output_config->keyword) == 0)
            {
                if (strcasecmp(old_output_config->opts,
                               new_output_config->opts) == 0)
                {
                    new_outputs++;
                    break;
                }
            }
        }

        old_outputs++;
    }

    if (new_outputs != old_outputs)
    {
        ErrorMessage("Snort Reload: Any change to any output "
                     "configurations requires a restart.\n");
        return -1;
    }

    return 0;
}

#ifdef DYNAMIC_PLUGIN
static int VerifyLibInfos(DynamicLibInfo *old_info, DynamicLibInfo *new_info)
{
    if ((old_info != NULL) && (new_info != NULL))
    {
        unsigned i;

        if (old_info->type != new_info->type)
        {
            FatalError("%s(%d) Incompatible library types.\n",
                       __FILE__, __LINE__);
        }

        if (old_info->count != new_info->count)
            return -1;

        for (i = 0; i < old_info->count; i++)
        {
            unsigned j;
            DynamicLibPath *old_path = old_info->lib_paths[i];

            for (j = 0; j < new_info->count; j++)
            {
                DynamicLibPath *new_path = new_info->lib_paths[j];

                if ((strcmp(old_path->path, new_path->path) == 0) &&
                    (old_path->ptype == new_path->ptype))
                {
                    if (old_path->last_mod_time != new_path->last_mod_time)
                        return -1;

                    break;
                }
            }

            if (j == new_info->count)
                return -1;
        }
    }
    else if (old_info != new_info)
    {
        return -1;
    }

    return 0;
}
#endif  /* DYNAMIC_PLUGIN */
#endif  /* SNORT_RELOAD */

