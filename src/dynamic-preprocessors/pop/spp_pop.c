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

/**************************************************************************
 *
 * spp_pop.c
 *
 * Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>
 *
 * Description:
 *
 * This file initializes POP as a Snort preprocessor.
 *
 * This file registers the POP initialization function,
 * adds the POP function into the preprocessor list.
 *
 * In general, this file is a wrapper to POP functionality,
 * by interfacing with the Snort preprocessor functions.  The rest
 * of POP should be separate from the preprocessor hooks.
 *
 **************************************************************************/

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "spp_pop.h"
#include "sf_preproc_info.h"
#include "snort_pop.h"
#include "pop_config.h"
#include "pop_log.h"

#include "preprocids.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "snort_debug.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats popPerfStats;
PreprocStats popDetectPerfStats;
int popDetectCalled = 0;
#endif

#include "sf_types.h"
#include "mempool.h"
#include "snort_bounds.h"

const int MAJOR_VERSION = 1;
const int MINOR_VERSION = 0;
const int BUILD_VERSION = 1;
#ifdef SUP_IP6
const char *PREPROC_NAME = "SF_POP (IPV6)";
#else
const char *PREPROC_NAME = "SF_POP";
#endif

#define SetupPOP DYNAMIC_PREPROC_SETUP

MemPool *pop_mempool = NULL;

tSfPolicyUserContextId pop_config = NULL;
POPConfig *pop_eval_config = NULL;

extern POP pop_no_session;
extern int16_t pop_proto_id;

static void POPInit(char *);
static void POPDetect(void *, void *context);
static void POPCleanExitFunction(int, void *);
static void POPResetFunction(int, void *);
static void POPResetStatsFunction(int, void *);
static void _addPortsToStream5Filter(POPConfig *, tSfPolicyId);
#ifdef TARGET_BASED
static void _addServicesToStream5Filter(tSfPolicyId);
#endif
static void POPCheckConfig(void);

#ifdef SNORT_RELOAD
tSfPolicyUserContextId pop_swap_config = NULL;
static void POPReload(char *);
static int POPReloadVerify(void);
static void * POPReloadSwap(void);
static void POPReloadSwapFree(void *);
#endif


/*
 * Function: SetupPOP()
 *
 * Purpose: Registers the preprocessor keyword and initialization
 *          function into the preprocessor list.  This is the function that
 *          gets called from InitPreprocessors() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupPOP(void)
{
    /* link the preprocessor keyword to the init function in the preproc list */
#ifndef SNORT_RELOAD
    _dpd.registerPreproc("pop", POPInit);
#else
    _dpd.registerPreproc("pop", POPInit, POPReload,
                         POPReloadSwap, POPReloadSwapFree);
#endif
}


/*
 * Function: POPInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void POPInit(char *args)
{
    POPToken *tmp;
    tSfPolicyId policy_id = _dpd.getParserPolicy();
    POPConfig * pPolicyConfig = NULL;

    if (pop_config == NULL)
    {
        //create a context
        pop_config = sfPolicyConfigCreate();
        if (pop_config == NULL)
        {
            DynamicPreprocessorFatalMessage("Not enough memory to create POP "
                                            "configuration.\n");
        }

        /* Initialize the searches not dependent on configuration.
         * headers, reponsed, data, mime boundary regular expression */
        POP_SearchInit();

        /* zero out static POP global used for stateless POP or if there
         * is no session pointer */
        memset(&pop_no_session, 0, sizeof(POP));

        /* Put the preprocessor function into the function list */
        /* _dpd.addPreproc(POPDetect, PRIORITY_APPLICATION, PP_POP, PROTO_BIT__TCP);*/
        _dpd.addPreprocExit(POPCleanExitFunction, NULL, PRIORITY_LAST, PP_POP);
        _dpd.addPreprocReset(POPResetFunction, NULL, PRIORITY_LAST, PP_POP);
        _dpd.addPreprocResetStats(POPResetStatsFunction, NULL, PRIORITY_LAST, PP_POP);
        _dpd.addPreprocConfCheck(POPCheckConfig);

#ifdef TARGET_BASED
        pop_proto_id = _dpd.findProtocolReference(POP_PROTO_REF_STR);
        if (pop_proto_id == SFTARGET_UNKNOWN_PROTOCOL)
            pop_proto_id = _dpd.addProtocolReference(POP_PROTO_REF_STR);

        DEBUG_WRAP(DebugMessage(DEBUG_POP,"POP: Target-based: Proto id for %s: %u.\n",
                                POP_PROTO_REF_STR, pop_proto_id););
#endif

#ifdef PERF_PROFILING
        _dpd.addPreprocProfileFunc("pop", (void*)&popPerfStats, 0, _dpd.totalPerfStats);
#endif
    }

    sfPolicyUserPolicySet (pop_config, policy_id);
    pPolicyConfig = (POPConfig *)sfPolicyUserDataGetCurrent(pop_config);
    if (pPolicyConfig != NULL)
    {
        DynamicPreprocessorFatalMessage("Can only configure POP preprocessor once.\n");
    }

    pPolicyConfig = (POPConfig *)calloc(1, sizeof(POPConfig));
    if (pPolicyConfig == NULL)
    {
        DynamicPreprocessorFatalMessage("Not enough memory to create POP "
                                        "configuration.\n");
    }

    sfPolicyUserDataSetCurrent(pop_config, pPolicyConfig);

    POP_InitCmds(pPolicyConfig);
    POP_ParseArgs(pPolicyConfig, args);

    POP_CheckConfig(pPolicyConfig, pop_config);
    POP_PrintConfig(pPolicyConfig);

    if(pPolicyConfig->disabled)
        return;

    _dpd.addPreproc(POPDetect, PRIORITY_APPLICATION, PP_POP, PROTO_BIT__TCP);

    if (_dpd.streamAPI == NULL)
    {
        DynamicPreprocessorFatalMessage("Streaming & reassembly must be enabled "
                "for POP preprocessor\n");
    }

    /* Command search - do this here because it's based on configuration */
    pPolicyConfig->cmd_search_mpse = _dpd.searchAPI->search_instance_new();
    if (pPolicyConfig->cmd_search_mpse == NULL)
    {
        DynamicPreprocessorFatalMessage("Could not allocate POP "
                                        "command search.\n");
    }

    for (tmp = pPolicyConfig->cmds; tmp->name != NULL; tmp++)
    {
        pPolicyConfig->cmd_search[tmp->search_id].name = tmp->name;
        pPolicyConfig->cmd_search[tmp->search_id].name_len = tmp->name_len;

        _dpd.searchAPI->search_instance_add(pPolicyConfig->cmd_search_mpse, tmp->name,
                                            tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_instance_prep(pPolicyConfig->cmd_search_mpse);

    _addPortsToStream5Filter(pPolicyConfig, policy_id);

#ifdef TARGET_BASED
    _addServicesToStream5Filter(policy_id);
#endif
}

/*
 * Function: POPDetect(void *, void *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct
 *
 * Returns: void function
 *
 */
static void POPDetect(void *pkt, void *context)
{
    SFSnortPacket *p = (SFSnortPacket *)pkt;
    tSfPolicyId policy_id = _dpd.getRuntimePolicy();
    PROFILE_VARS;

    if ((p->payload_size == 0) || !IsTCP(p) || (p->payload == NULL))
        return;

    PREPROC_PROFILE_START(popPerfStats);

    DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP Start (((((((((((((((((((((((((((((((((((((((\n"););

    sfPolicyUserPolicySet (pop_config, policy_id);

    SnortPOP(p);

    DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP End )))))))))))))))))))))))))))))))))))))))))\n\n"););

    PREPROC_PROFILE_END(popPerfStats);
#ifdef PERF_PROFILING
    if (PROFILING_PREPROCS && popDetectCalled)
    {
        popPerfStats.ticks -= popDetectPerfStats.ticks;
        /* And Reset ticks to 0 */
        popDetectPerfStats.ticks = 0;
        popDetectCalled = 0;
    }
#endif

}


/*
 * Function: POPCleanExitFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is exiting, if there's
 *          any cleanup that needs to be performed (e.g. closing files)
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this
 *                    function when it was registered, may be
 *                    needed to properly exit
 *
 * Returns: void function
 */
static void POPCleanExitFunction(int signal, void *data)
{
    POP_Free();
    if (mempool_destroy(pop_mempool) == 0)
    {
        free(pop_mempool);
        pop_mempool = NULL;
    }

}


static void POPResetFunction(int signal, void *data)
{
    return;
}

static void POPResetStatsFunction(int signal, void *data)
{
    return;
}

static void _addPortsToStream5Filter(POPConfig *config, tSfPolicyId policy_id)
{
    unsigned int portNum;

    if (config == NULL)
        return;

    for (portNum = 0; portNum < MAXPORTS; portNum++)
    {
        if(config->ports[(portNum/8)] & (1<<(portNum%8)))
        {
            //Add port the port
            _dpd.streamAPI->set_port_filter_status(IPPROTO_TCP, (uint16_t)portNum,
                                                   PORT_MONITOR_SESSION, policy_id, 1);
        }
    }
}

#ifdef TARGET_BASED
static void _addServicesToStream5Filter(tSfPolicyId policy_id)
{
    _dpd.streamAPI->set_service_filter_status(pop_proto_id, PORT_MONITOR_SESSION, policy_id, 1);
}
#endif

static int POPEnableDecoding(tSfPolicyUserContextId config,
            tSfPolicyId policyId, void *pData)
{
    POPConfig *context = (POPConfig *)pData;

    if (pData == NULL)
        return 0;

    if(context->disabled)
        return 0;

    if(!POP_IsDecodingEnabled(context))
        return 1;

    return 0;
}

static int POPCheckPolicyConfig(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
        )
{
    POPConfig *context = (POPConfig *)pData;

    _dpd.setParserPolicy(policyId);

    /* In a multiple-policy setting, the POP preproc can be turned on in a
       "disabled" state. In this case, we don't require Stream5. */
    if (context->disabled)
        return 0;

    if (!_dpd.isPreprocEnabled(PP_STREAM5))
    {
        DynamicPreprocessorFatalMessage("Streaming & reassembly must be enabled "
                                        "for POP preprocessor\n");
    }

    return 0;
}

static void POPCheckConfig(void)
{

    POPConfig *defaultConfig =
            (POPConfig *)sfPolicyUserDataGetDefault(pop_config);

    sfPolicyUserDataIterate (pop_config, POPCheckPolicyConfig);

    if (sfPolicyUserDataIterate(pop_config, POPEnableDecoding) != 0)
    {
        int encode_depth;
        int max_sessions;

        if (defaultConfig == NULL)
        {
            /*error message */
            DynamicPreprocessorFatalMessage("POP: Must configure a default "
                    "configuration if you want to pop decoding.\n");
        }

        encode_depth = defaultConfig->max_depth;

        if (encode_depth & 7)
        {
            encode_depth += (8 - (encode_depth & 7));
        }

        max_sessions = defaultConfig->memcap / (2 * encode_depth );

        pop_mempool = (MemPool *)calloc(1, sizeof(MemPool));

        if (mempool_init(pop_mempool, max_sessions,
                    (2 * encode_depth )) != 0)
        {
            DynamicPreprocessorFatalMessage("POP:  Could not allocate POP mempool.\n");
        }
    }


}

#ifdef SNORT_RELOAD
static void POPReload(char *args)
{
    POPToken *tmp;
    tSfPolicyId policy_id = _dpd.getParserPolicy();
    POPConfig *pPolicyConfig = NULL;

    if (pop_swap_config == NULL)
    {
        //create a context
        pop_swap_config = sfPolicyConfigCreate();
        if (pop_swap_config == NULL)
        {
            DynamicPreprocessorFatalMessage("Not enough memory to create POP "
                                            "configuration.\n");
        }

        _dpd.addPreprocReloadVerify(POPReloadVerify);
    }

    sfPolicyUserPolicySet (pop_swap_config, policy_id);
    pPolicyConfig = (POPConfig *)sfPolicyUserDataGetCurrent(pop_swap_config);

    if (pPolicyConfig != NULL)
        DynamicPreprocessorFatalMessage("Can only configure POP preprocessor once.\n");

    pPolicyConfig = (POPConfig *)calloc(1, sizeof(POPConfig));
    if (pPolicyConfig == NULL)
    {
        DynamicPreprocessorFatalMessage("Not enough memory to create POP "
                                        "configuration.\n");
    }

    sfPolicyUserDataSetCurrent(pop_swap_config, pPolicyConfig);

    POP_InitCmds(pPolicyConfig);
    POP_ParseArgs(pPolicyConfig, args);

    POP_CheckConfig(pPolicyConfig, pop_swap_config);
    POP_PrintConfig(pPolicyConfig);

    if( pPolicyConfig->disabled )
        return;

    if (_dpd.streamAPI == NULL)
    {
        DynamicPreprocessorFatalMessage("Streaming & reassembly must be enabled "
                                        "for POP preprocessor\n");
    }

    /* Command search - do this here because it's based on configuration */
    pPolicyConfig->cmd_search_mpse = _dpd.searchAPI->search_instance_new();
    if (pPolicyConfig->cmd_search_mpse == NULL)
    {
        DynamicPreprocessorFatalMessage("Could not allocate POP "
                                        "command search.\n");
    }

    for (tmp = pPolicyConfig->cmds; tmp->name != NULL; tmp++)
    {
        pPolicyConfig->cmd_search[tmp->search_id].name = tmp->name;
        pPolicyConfig->cmd_search[tmp->search_id].name_len = tmp->name_len;

        _dpd.searchAPI->search_instance_add(pPolicyConfig->cmd_search_mpse, tmp->name,
                                            tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_instance_prep(pPolicyConfig->cmd_search_mpse);

    _dpd.addPreproc(POPDetect, PRIORITY_APPLICATION, PP_POP, PROTO_BIT__TCP);

    _addPortsToStream5Filter(pPolicyConfig, policy_id);

#ifdef TARGET_BASED
    _addServicesToStream5Filter(policy_id);
#endif
}

static int POPReloadVerify(void)
{
    POPConfig *config = NULL;
    POPConfig *configNext = NULL;

    if (pop_swap_config == NULL)
        return 0;

    if (pop_config != NULL)
    {
        config = (POPConfig *)sfPolicyUserDataGet(pop_config, _dpd.getDefaultPolicy());
    }

    configNext = (POPConfig *)sfPolicyUserDataGet(pop_swap_config, _dpd.getDefaultPolicy());

    if (config == NULL)
    {
        return 0;
    }

    if (pop_mempool != NULL)
    {
        if (configNext == NULL)
        {
            _dpd.errMsg("POP reload: Changing the POP configuration requires a restart.\n");
            POP_FreeConfigs(pop_swap_config);
            pop_swap_config = NULL;
            return -1;
        }
        if (configNext->memcap != config->memcap)
        {
            _dpd.errMsg("POP reload: Changing the memcap requires a restart.\n");
            POP_FreeConfigs(pop_swap_config);
            pop_swap_config = NULL;
            return -1;
        }
        if(configNext->b64_depth != config->b64_depth)
        {
            _dpd.errMsg("POP reload: Changing the b64_decode_depth requires a restart.\n");
            POP_FreeConfigs(pop_swap_config);
            pop_swap_config = NULL;
            return -1;
        }
        if(configNext->qp_depth != config->qp_depth)
        {   
            _dpd.errMsg("POP reload: Changing the qp_decode_depth requires a restart.\n");
            POP_FreeConfigs(pop_swap_config);
            pop_swap_config = NULL;
            return -1; 
        }
        if(configNext->bitenc_depth != config->bitenc_depth)
        {   
            _dpd.errMsg("POP reload: Changing the bitenc_decode_depth requires a restart.\n");
            POP_FreeConfigs(pop_swap_config);
            pop_swap_config = NULL;
            return -1; 
        }
        if(configNext->uu_depth != config->uu_depth)
        {   
            _dpd.errMsg("POP reload: Changing the uu_decode_depth requires a restart.\n");
            POP_FreeConfigs(pop_swap_config);
            pop_swap_config = NULL;
            return -1; 
        }

    }
    else if(configNext != NULL)
    {
        if (sfPolicyUserDataIterate(pop_swap_config, POPEnableDecoding) != 0)
        {
            int encode_depth;
            int max_sessions;


            encode_depth = configNext->max_depth;

            if (encode_depth & 7)
            {
                encode_depth += (8 - (encode_depth & 7));
            }

            max_sessions = configNext->memcap / ( 2 * encode_depth);

            pop_mempool = (MemPool *)calloc(1, sizeof(MemPool));

            if (mempool_init(pop_mempool, max_sessions,
                            (2 * encode_depth)) != 0)
            {
                DynamicPreprocessorFatalMessage("POP:  Could not allocate POP mempool.\n");
            }
        }

    }


    if ( configNext->disabled )
        return 0;


    if (!_dpd.isPreprocEnabled(PP_STREAM5))
    {
        DynamicPreprocessorFatalMessage("Streaming & reassembly must be enabled "
                                        "for POP preprocessor\n");
    }

    return 0;
}

static int POPReloadSwapPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
        )
{
    POPConfig *pPolicyConfig = (POPConfig *)pData;

    if (pPolicyConfig->ref_count == 0)
    {
        sfPolicyUserDataClear (config, policyId);
        POP_FreeConfig(pPolicyConfig);
    }

    return 0;
}

static void * POPReloadSwap(void)
{
    tSfPolicyUserContextId old_config = pop_config;

    if (pop_swap_config == NULL)
        return NULL;

    pop_config = pop_swap_config;
    pop_swap_config = NULL;

    sfPolicyUserDataIterate (old_config, POPReloadSwapPolicy);

    if (sfPolicyUserPolicyGetActive(old_config) == 0)
        POP_FreeConfigs(old_config);

    return NULL;
}

static void POPReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    POP_FreeConfigs((tSfPolicyUserContextId)data);
}
#endif
