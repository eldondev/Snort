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
#ifndef __PLUGBASE_H__
#define __PLUGBASE_H__

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "bitop_funcs.h"
#include "rules.h"
#include "sf_types.h"
#include "debug.h"

#ifndef WIN32
# include <sys/ioctl.h>
#endif  /* !WIN32 */

#ifdef ENABLE_SSL
# ifdef Free
/* Free macro in radix.h if defined, will conflict with OpenSSL definition */
#  undef Free
# endif
#endif

#ifndef WIN32
# include <net/route.h>
#endif /* !WIN32 */

#ifdef ENABLE_SSL
# undef Free
#endif

#if defined(SOLARIS) || defined(FREEBSD) || defined(OPENBSD)
# include <sys/param.h>
#endif

#if defined(FREEBSD) || defined(OPENBSD) || defined(NETBSD) || defined(OSF1)
# include <sys/mbuf.h>
#endif

#ifndef IFNAMSIZ /* IFNAMSIZ is defined in all platforms I checked.. */
# include <net/if.h>
#endif

#include "preprocids.h"


/* Macros *********************************************************************/
#define SMALLBUFFER 32

#define DETECTION_KEYWORD 0
#define RESPONSE_KEYWORD  1

#define ENCODING_HEX     0
#define ENCODING_BASE64  1
#define ENCODING_ASCII   2

#define DETAIL_FAST  0
#define DETAIL_FULL  1


/**************************** Detection Plugin API ****************************/
typedef enum _RuleOptType
{
	OPT_TYPE_ACTION = 0,
	OPT_TYPE_LOGGING,
	OPT_TYPE_DETECTION,
	OPT_TYPE_MAX

} RuleOptType;

typedef void (*RuleOptConfigFunc)(char *, OptTreeNode *, int);
typedef void (*RuleOptOverrideFunc)(char *, char *, char *, OptTreeNode *, int);
typedef void (*RuleOptOverrideInitFunc)(char *, char *, RuleOptOverrideFunc);
typedef int (*RuleOptEvalFunc)(void *, Packet *);
typedef int (*ResponseFunc)(Packet *, RspFpList *);
typedef void (*PluginSignalFunc)(int, void *);
typedef void (*RuleOptParseCleanupFunc)(void);

typedef struct _RuleOptConfigFuncNode
{
    char *keyword;
    RuleOptType type;
    RuleOptConfigFunc func;
    struct _RuleOptConfigFuncNode *next;

} RuleOptConfigFuncNode;

typedef struct _RuleOptOverrideInitFuncNode
{
    char *keyword;
    RuleOptType type;
    RuleOptOverrideInitFunc func;
    struct _RuleOptOverrideInitFuncNode *next;

} RuleOptOverrideInitFuncNode;

typedef struct _RuleOptParseCleanupNode
{
    RuleOptParseCleanupFunc func;
    struct _RuleOptParseCleanupNode *next;

} RuleOptParseCleanupNode;

void RegisterRuleOptions(void);
void RegisterRuleOption(char *, RuleOptConfigFunc, RuleOptOverrideInitFunc, RuleOptType);
void RegisterOverrideKeyword(char *, char *, RuleOptOverrideFunc);
void DumpRuleOptions(void);
OptFpList * AddOptFuncToList(RuleOptEvalFunc, OptTreeNode *);
void AddRspFuncToList(ResponseFunc, OptTreeNode *, void *);
void FreeRuleOptConfigFuncs(RuleOptConfigFuncNode *);
void FreeRuleOptOverrideInitFuncs(RuleOptOverrideInitFuncNode *);
void AddFuncToRuleOptParseCleanupList(RuleOptParseCleanupFunc);
void RuleOptParseCleanup(void);
void FreeRuleOptParseCleanupList(RuleOptParseCleanupNode *);


/***************************** Preprocessor API *******************************/
typedef void (*PreprocConfigFunc)(char *);
typedef void (*PreprocStatsFunc)(int);
typedef void (*PreprocEvalFunc)(Packet *, void *);
typedef void (*PreprocCheckConfigFunc)(void);
typedef void (*PreprocSignalFunc)(int, void *);
typedef void * (*PreprocReassemblyPktFunc)(void);
typedef void (*PreprocPostConfigFunc)(void *);

#ifdef SNORT_RELOAD
typedef void (*PreprocReloadFunc)(char *);
typedef int (*PreprocReloadVerifyFunc)(void);
typedef void * (*PreprocReloadSwapFunc)(void);
typedef void (*PreprocReloadSwapFreeFunc)(void *);
#endif

typedef struct _PreprocConfigFuncNode
{
    char *keyword;
    PreprocConfigFunc config_func;

#ifdef SNORT_RELOAD
    /* Tells whether we call the config func or reload func */
    int initialized;
    void *swap_free_data;
    PreprocReloadFunc reload_func;
    PreprocReloadVerifyFunc reload_verify_func;
    PreprocReloadSwapFunc reload_swap_func;
    PreprocReloadSwapFreeFunc reload_swap_free_func;
#endif

    struct _PreprocConfigFuncNode *next;

} PreprocConfigFuncNode;

typedef struct _PreprocStatsFuncNode
{
    char *keyword;
    PreprocStatsFunc func;
    struct _PreprocStatsFuncNode *next;

} PreprocStatsFuncNode;

typedef struct _PreprocEvalFuncNode
{
    void *context;
    uint16_t priority;
    uint32_t preproc_id;
    uint32_t preproc_bit;
    uint32_t proto_mask;
    PreprocEvalFunc func;
    struct _PreprocEvalFuncNode *next;

} PreprocEvalFuncNode;

typedef struct _PreprocCheckConfigFuncNode
{
    PreprocCheckConfigFunc func;
    struct _PreprocCheckConfigFuncNode *next;

} PreprocCheckConfigFuncNode;

typedef struct _PreprocSignalFuncNode
{
    void *arg;
    uint16_t priority;
    uint32_t preproc_id;
    PreprocSignalFunc func;
    struct _PreprocSignalFuncNode *next;

} PreprocSignalFuncNode;

typedef struct _PreprocReassemblyPktFuncNode
{
    unsigned int preproc_id;
    PreprocReassemblyPktFunc func;
    struct _PreprocReassemblyPktFuncNode *next;

} PreprocReassemblyPktFuncNode;

typedef struct _PreprocPostConfigFuncNode
{
    void *data;
    PreprocPostConfigFunc func;
    struct _PreprocPostConfigFuncNode *next;

} PreprocPostConfigFuncNode;

#ifdef SNORT_RELOAD
typedef struct _PreprocReloadVerifyFuncNode
{
    PreprocReloadVerifyFunc func;
    struct _PreprocReloadVerifyFuncNode *next;

} PreprocReloadVerifyFuncNode;
#endif


struct _SnortConfig;

void RegisterPreprocessors(void);
#ifndef SNORT_RELOAD
void RegisterPreprocessor(char *, PreprocConfigFunc);
#else
void RegisterPreprocessor(char *, PreprocConfigFunc, PreprocReloadFunc,
                          PreprocReloadSwapFunc, PreprocReloadSwapFreeFunc);
#endif
PreprocConfigFuncNode * GetPreprocConfig(char *);
PreprocConfigFunc GetPreprocConfigFunc(char *);
void RegisterPreprocStats(char *, PreprocStatsFunc);
void DumpPreprocessors(void);
void AddFuncToConfigCheckList(PreprocCheckConfigFunc);
void AddFuncToPreprocPostConfigList(PreprocPostConfigFunc, void *);
void CheckPreprocessorsConfig(struct _SnortConfig *);
PreprocEvalFuncNode * AddFuncToPreprocList(PreprocEvalFunc, uint16_t, uint32_t, uint32_t);
void AddFuncToPreprocRestartList(PreprocSignalFunc, void *, uint16_t, uint32_t);
void AddFuncToPreprocCleanExitList(PreprocSignalFunc, void *, uint16_t, uint32_t);
void AddFuncToPreprocShutdownList(PreprocSignalFunc, void *, uint16_t, uint32_t);
void AddFuncToPreprocResetList(PreprocSignalFunc, void *, uint16_t, uint32_t);
void AddFuncToPreprocResetStatsList(PreprocSignalFunc, void *, uint16_t, uint32_t);
void AddFuncToPreprocReassemblyPktList(PreprocReassemblyPktFunc, uint32_t);
int IsPreprocEnabled(uint32_t);
void FreePreprocConfigFuncs(void);
void FreePreprocCheckConfigFuncs(PreprocCheckConfigFuncNode *);
void FreePreprocStatsFuncs(PreprocStatsFuncNode *);
void FreePreprocEvalFuncs(PreprocEvalFuncNode *);
void FreePreprocReassemblyPktFuncs(PreprocReassemblyPktFuncNode *);
void FreePreprocSigFuncs(PreprocSignalFuncNode *);
void FreePreprocPostConfigFuncs(PreprocPostConfigFuncNode *);
void PostConfigPreprocessors(struct _SnortConfig *);

#ifdef SNORT_RELOAD
void AddFuncToPreprocReloadVerifyList(PreprocReloadVerifyFunc);
void FreePreprocReloadVerifyFuncs(PreprocReloadVerifyFuncNode *);
int VerifyReloadedPreprocessors(struct _SnortConfig *);
void SwapPreprocConfigurations(void);
void FreeSwappedPreprocConfigurations(void);
void FreePreprocReloadVerifyFuncList(PreprocReloadVerifyFuncNode *);
#endif

static INLINE void DisablePreprocessors(Packet *p) 
{
    p->preprocessor_bits = PP_ALL_OFF;
}

static INLINE void EnablePreprocessors(Packet *p) 
{
    p->preprocessor_bits = PP_ALL_ON;
}

static INLINE int IsPreprocBitSet(Packet *p, unsigned int preproc_bit)
{
    return (p->preprocessor_bits & preproc_bit);
}

static INLINE int SetPreprocBit(Packet *p, unsigned int preproc_id)
{
    p->preprocessor_bits |= (1 << preproc_id);
    return 0;
}

static INLINE int IsPreprocReassemblyPktBitSet(Packet *p, unsigned int preproc_id)
{
    return (p->preproc_reassembly_pkt_bits & (1 << preproc_id)) != 0;
}

static INLINE int SetPreprocReassemblyPktBit(Packet *p, unsigned int preproc_id)
{
    p->preproc_reassembly_pkt_bits |= (1 << preproc_id);
    p->packet_flags |= PKT_PREPROC_RPKT;
    return 0;
}

/************************** Miscellaneous Functions  **************************/

typedef struct _PluginSignalFuncNode
{
    void *arg;
    PluginSignalFunc func;
    struct _PluginSignalFuncNode *next;

} PluginSignalFuncNode;

/* Used for both rule options and output.  Preprocessors have their own */
void AddFuncToRestartList(PluginSignalFunc, void *);
void AddFuncToCleanExitList(PluginSignalFunc, void *);
void AddFuncToShutdownList(PluginSignalFunc, void *);
void AddFuncToPostConfigList(PluginSignalFunc, void *);
void AddFuncToSignalList(PluginSignalFunc, void *, PluginSignalFuncNode **);
void PostConfigInitPlugins(PluginSignalFuncNode *);
void FreePluginSigFuncs(PluginSignalFuncNode *);

#endif /* __PLUGBASE_H__ */
