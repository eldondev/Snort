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
 * spp_imap.c
 *
 * Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>
 *
 * Description:
 *
 * This file initializes IMAP as a Snort preprocessor.
 *
 * This file registers the IMAP initialization function,
 * adds the IMAP function into the preprocessor list.
 *
 * In general, this file is a wrapper to IMAP functionality,
 * by interfacing with the Snort preprocessor functions.  The rest
 * of IMAP should be separate from the preprocessor hooks.
 *
 **************************************************************************/

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "spp_imap.h"
#include "sf_preproc_info.h"
#include "snort_imap.h"
#include "imap_config.h"
#include "imap_log.h"

#include "preprocids.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "snort_debug.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats imapPerfStats;
PreprocStats imapDetectPerfStats;
int imapDetectCalled = 0;
#endif

#include "sf_types.h"
#include "mempool.h"
#include "snort_bounds.h"

const int MAJOR_VERSION = 1;
const int MINOR_VERSION = 0;
const int BUILD_VERSION = 1;
#ifdef SUP_IP6
const char *PREPROC_NAME = "SF_IMAP (IPV6)";
#else
const char *PREPROC_NAME = "SF_IMAP";
#endif

#define SetupIMAP DYNAMIC_PREPROC_SETUP

MemPool *imap_mempool = NULL;

tSfPolicyUserContextId imap_config = NULL;
IMAPConfig *imap_eval_config = NULL;

extern IMAP imap_no_session;
extern int16_t imap_proto_id;

static void IMAPInit(char *);
static void IMAPDetect(void *, void *context);
static void IMAPCleanExitFunction(int, void *);
static void IMAPResetFunction(int, void *);
static void IMAPResetStatsFunction(int, void *);
static void _addPortsToStream5Filter(IMAPConfig *, tSfPolicyId);
#ifdef TARGET_BASED
static void _addServicesToStream5Filter(tSfPolicyId);
#endif
static void IMAPCheckConfig(void);

#ifdef SNORT_RELOAD
tSfPolicyUserContextId imap_swap_config = NULL;
static void IMAPReload(char *);
static int IMAPReloadVerify(void);
static void * IMAPReloadSwap(void);
static void IMAPReloadSwapFree(void *);
#endif


/*
 * Function: SetupIMAP()
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
void SetupIMAP(void)
{
    /* link the preprocessor keyword to the init function in the preproc list */
#ifndef SNORT_RELOAD
    _dpd.registerPreproc("imap", IMAPInit);
#else
    _dpd.registerPreproc("imap", IMAPInit, IMAPReload,
                         IMAPReloadSwap, IMAPReloadSwapFree);
#endif
}


/*
 * Function: IMAPInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void IMAPInit(char *args)
{
    IMAPToken *tmp;
    tSfPolicyId policy_id = _dpd.getParserPolicy();
    IMAPConfig * pPolicyConfig = NULL;

    if (imap_config == NULL)
    {
        //create a context
        imap_config = sfPolicyConfigCreate();
        if (imap_config == NULL)
        {
            DynamicPreprocessorFatalMessage("Not enough memory to create IMAP "
                                            "configuration.\n");
        }

        /* Initialize the searches not dependent on configuration.
         * headers, reponsed, data, mime boundary regular expression */
        IMAP_SearchInit();

        /* zero out static IMAP global used for stateless IMAP or if there
         * is no session pointer */
        memset(&imap_no_session, 0, sizeof(IMAP));

        /* Put the preprocessor function into the function list */
        /* _dpd.addPreproc(IMAPDetect, PRIORITY_APPLICATION, PP_IMAP, PROTO_BIT__TCP);*/
        _dpd.addPreprocExit(IMAPCleanExitFunction, NULL, PRIORITY_LAST, PP_IMAP);
        _dpd.addPreprocReset(IMAPResetFunction, NULL, PRIORITY_LAST, PP_IMAP);
        _dpd.addPreprocResetStats(IMAPResetStatsFunction, NULL, PRIORITY_LAST, PP_IMAP);
        _dpd.addPreprocConfCheck(IMAPCheckConfig);

#ifdef TARGET_BASED
        imap_proto_id = _dpd.findProtocolReference(IMAP_PROTO_REF_STR);
        if (imap_proto_id == SFTARGET_UNKNOWN_PROTOCOL)
            imap_proto_id = _dpd.addProtocolReference(IMAP_PROTO_REF_STR);

        DEBUG_WRAP(DebugMessage(DEBUG_IMAP,"IMAP: Target-based: Proto id for %s: %u.\n",
                                IMAP_PROTO_REF_STR, imap_proto_id););
#endif

#ifdef PERF_PROFILING
        _dpd.addPreprocProfileFunc("imap", (void*)&imapPerfStats, 0, _dpd.totalPerfStats);
#endif
    }

    sfPolicyUserPolicySet (imap_config, policy_id);
    pPolicyConfig = (IMAPConfig *)sfPolicyUserDataGetCurrent(imap_config);
    if (pPolicyConfig != NULL)
    {
        DynamicPreprocessorFatalMessage("Can only configure IMAP preprocessor once.\n");
    }

    pPolicyConfig = (IMAPConfig *)calloc(1, sizeof(IMAPConfig));
    if (pPolicyConfig == NULL)
    {
        DynamicPreprocessorFatalMessage("Not enough memory to create IMAP "
                                        "configuration.\n");
    }

    sfPolicyUserDataSetCurrent(imap_config, pPolicyConfig);

    IMAP_InitCmds(pPolicyConfig);
    IMAP_ParseArgs(pPolicyConfig, args);

    IMAP_CheckConfig(pPolicyConfig, imap_config);
    IMAP_PrintConfig(pPolicyConfig);

    if(pPolicyConfig->disabled)
        return;

    _dpd.addPreproc(IMAPDetect, PRIORITY_APPLICATION, PP_IMAP, PROTO_BIT__TCP);

    if (_dpd.streamAPI == NULL)
    {
        DynamicPreprocessorFatalMessage("Streaming & reassembly must be enabled "
                "for IMAP preprocessor\n");
    }

    /* Command search - do this here because it's based on configuration */
    pPolicyConfig->cmd_search_mpse = _dpd.searchAPI->search_instance_new();
    if (pPolicyConfig->cmd_search_mpse == NULL)
    {
        DynamicPreprocessorFatalMessage("Could not allocate IMAP "
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
 * Function: IMAPDetect(void *, void *)
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
static void IMAPDetect(void *pkt, void *context)
{
    SFSnortPacket *p = (SFSnortPacket *)pkt;
    tSfPolicyId policy_id = _dpd.getRuntimePolicy();
    PROFILE_VARS;

    if ((p->payload_size == 0) || !IsTCP(p) || (p->payload == NULL))
        return;

    PREPROC_PROFILE_START(imapPerfStats);

    DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP Start (((((((((((((((((((((((((((((((((((((((\n"););

    sfPolicyUserPolicySet (imap_config, policy_id);

    SnortIMAP(p);

    DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP End )))))))))))))))))))))))))))))))))))))))))\n\n"););

    PREPROC_PROFILE_END(imapPerfStats);
#ifdef PERF_PROFILING
    if (PROFILING_PREPROCS && imapDetectCalled)
    {
        imapPerfStats.ticks -= imapDetectPerfStats.ticks;
        /* And Reset ticks to 0 */
        imapDetectPerfStats.ticks = 0;
        imapDetectCalled = 0;
    }
#endif

}


/*
 * Function: IMAPCleanExitFunction(int, void *)
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
static void IMAPCleanExitFunction(int signal, void *data)
{
    IMAP_Free();
    if (mempool_destroy(imap_mempool) == 0)
    {
        free(imap_mempool);
        imap_mempool = NULL;
    }

}


static void IMAPResetFunction(int signal, void *data)
{
    return;
}

static void IMAPResetStatsFunction(int signal, void *data)
{
    return;
}

static void _addPortsToStream5Filter(IMAPConfig *config, tSfPolicyId policy_id)
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
    _dpd.streamAPI->set_service_filter_status(imap_proto_id, PORT_MONITOR_SESSION, policy_id, 1);
}
#endif

static int IMAPEnableDecoding(tSfPolicyUserContextId config,
            tSfPolicyId policyId, void *pData)
{
    IMAPConfig *context = (IMAPConfig *)pData;

    if (pData == NULL)
        return 0;

    if(context->disabled)
        return 0;

    if(!IMAP_IsDecodingEnabled(context))
        return 1;

    return 0;
}

static int IMAPCheckPolicyConfig(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
        )
{
    IMAPConfig *context = (IMAPConfig *)pData;

    _dpd.setParserPolicy(policyId);

    /* In a multiple-policy setting, the IMAP preproc can be turned on in a
       "disabled" state. In this case, we don't require Stream5. */
    if (context->disabled)
        return 0;

    if (!_dpd.isPreprocEnabled(PP_STREAM5))
    {
        DynamicPreprocessorFatalMessage("Streaming & reassembly must be enabled "
                                        "for IMAP preprocessor\n");
    }

    return 0;
}

static void IMAPCheckConfig(void)
{

    IMAPConfig *defaultConfig =
            (IMAPConfig *)sfPolicyUserDataGetDefault(imap_config);

    sfPolicyUserDataIterate (imap_config, IMAPCheckPolicyConfig);

    if (sfPolicyUserDataIterate(imap_config, IMAPEnableDecoding) != 0)
    {
        int encode_depth;
        int max_sessions;

        if (defaultConfig == NULL)
        {
            /*error message */
            DynamicPreprocessorFatalMessage("IMAP: Must configure a default "
                    "configuration if you want to imap decoding.\n");
        }

        encode_depth = defaultConfig->max_depth;

        if (encode_depth & 7)
        {
            encode_depth += (8 - (encode_depth & 7));
        }

        max_sessions = defaultConfig->memcap / (2 * encode_depth );

        imap_mempool = (MemPool *)calloc(1, sizeof(MemPool));

        if (mempool_init(imap_mempool, max_sessions,
                    (2 * encode_depth )) != 0)
        {
            DynamicPreprocessorFatalMessage("IMAP:  Could not allocate IMAP mempool.\n");
        }
    }


}

#ifdef SNORT_RELOAD
static void IMAPReload(char *args)
{
    IMAPToken *tmp;
    tSfPolicyId policy_id = _dpd.getParserPolicy();
    IMAPConfig *pPolicyConfig = NULL;

    if (imap_swap_config == NULL)
    {
        //create a context
        imap_swap_config = sfPolicyConfigCreate();
        if (imap_swap_config == NULL)
        {
            DynamicPreprocessorFatalMessage("Not enough memory to create IMAP "
                                            "configuration.\n");
        }

        _dpd.addPreprocReloadVerify(IMAPReloadVerify);
    }

    sfPolicyUserPolicySet (imap_swap_config, policy_id);
    pPolicyConfig = (IMAPConfig *)sfPolicyUserDataGetCurrent(imap_swap_config);

    if (pPolicyConfig != NULL)
        DynamicPreprocessorFatalMessage("Can only configure IMAP preprocessor once.\n");

    pPolicyConfig = (IMAPConfig *)calloc(1, sizeof(IMAPConfig));
    if (pPolicyConfig == NULL)
    {
        DynamicPreprocessorFatalMessage("Not enough memory to create IMAP "
                                        "configuration.\n");
    }

    sfPolicyUserDataSetCurrent(imap_swap_config, pPolicyConfig);

    IMAP_InitCmds(pPolicyConfig);
    IMAP_ParseArgs(pPolicyConfig, args);

    IMAP_CheckConfig(pPolicyConfig, imap_swap_config);
    IMAP_PrintConfig(pPolicyConfig);

    if( pPolicyConfig->disabled )
        return;

    if (_dpd.streamAPI == NULL)
    {
        DynamicPreprocessorFatalMessage("Streaming & reassembly must be enabled "
                                        "for IMAP preprocessor\n");
    }

    /* Command search - do this here because it's based on configuration */
    pPolicyConfig->cmd_search_mpse = _dpd.searchAPI->search_instance_new();
    if (pPolicyConfig->cmd_search_mpse == NULL)
    {
        DynamicPreprocessorFatalMessage("Could not allocate IMAP "
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

    _dpd.addPreproc(IMAPDetect, PRIORITY_APPLICATION, PP_IMAP, PROTO_BIT__TCP);

    _addPortsToStream5Filter(pPolicyConfig, policy_id);

#ifdef TARGET_BASED
    _addServicesToStream5Filter(policy_id);
#endif
}

static int IMAPReloadVerify(void)
{
    IMAPConfig *config = NULL;
    IMAPConfig *configNext = NULL;

    if (imap_swap_config == NULL)
        return 0;

    if (imap_config != NULL)
    {
        config = (IMAPConfig *)sfPolicyUserDataGet(imap_config, _dpd.getDefaultPolicy());
    }

    configNext = (IMAPConfig *)sfPolicyUserDataGet(imap_swap_config, _dpd.getDefaultPolicy());

    if (config == NULL)
    {
        return 0;
    }

    if (imap_mempool != NULL)
    {
        if (configNext == NULL)
        {
            _dpd.errMsg("IMAP reload: Changing the IMAP configuration requires a restart.\n");
            IMAP_FreeConfigs(imap_swap_config);
            imap_swap_config = NULL;
            return -1;
        }
        if (configNext->memcap != config->memcap)
        {
            _dpd.errMsg("IMAP reload: Changing the memcap requires a restart.\n");
            IMAP_FreeConfigs(imap_swap_config);
            imap_swap_config = NULL;
            return -1;
        }
        if(configNext->b64_depth != config->b64_depth)
        {
            _dpd.errMsg("IMAP reload: Changing the b64_decode_depth requires a restart.\n");
            IMAP_FreeConfigs(imap_swap_config);
            imap_swap_config = NULL;
            return -1;
        }
        if(configNext->qp_depth != config->qp_depth)
        {   
            _dpd.errMsg("IMAP reload: Changing the qp_decode_depth requires a restart.\n");
            IMAP_FreeConfigs(imap_swap_config);
            imap_swap_config = NULL;
            return -1; 
        }
        if(configNext->bitenc_depth != config->bitenc_depth)
        {   
            _dpd.errMsg("IMAP reload: Changing the bitenc_decode_depth requires a restart.\n");
            IMAP_FreeConfigs(imap_swap_config);
            imap_swap_config = NULL;
            return -1; 
        }
        if(configNext->uu_depth != config->uu_depth)
        {   
            _dpd.errMsg("IMAP reload: Changing the uu_decode_depth requires a restart.\n");
            IMAP_FreeConfigs(imap_swap_config);
            imap_swap_config = NULL;
            return -1; 
        }

    }
    else if(configNext != NULL)
    {
        if (sfPolicyUserDataIterate(imap_swap_config, IMAPEnableDecoding) != 0)
        {
            int encode_depth;
            int max_sessions;


            encode_depth = configNext->max_depth;

            if (encode_depth & 7)
            {
                encode_depth += (8 - (encode_depth & 7));
            }

            max_sessions = configNext->memcap / ( 2 * encode_depth);

            imap_mempool = (MemPool *)calloc(1, sizeof(MemPool));

            if (mempool_init(imap_mempool, max_sessions,
                            (2 * encode_depth)) != 0)
            {
                DynamicPreprocessorFatalMessage("IMAP:  Could not allocate IMAP mempool.\n");
            }
        }

    }


    if ( configNext->disabled )
        return 0;


    if (!_dpd.isPreprocEnabled(PP_STREAM5))
    {
        DynamicPreprocessorFatalMessage("Streaming & reassembly must be enabled "
                                        "for IMAP preprocessor\n");
    }

    return 0;
}

static int IMAPReloadSwapPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
        )
{
    IMAPConfig *pPolicyConfig = (IMAPConfig *)pData;

    if (pPolicyConfig->ref_count == 0)
    {
        sfPolicyUserDataClear (config, policyId);
        IMAP_FreeConfig(pPolicyConfig);
    }

    return 0;
}

static void * IMAPReloadSwap(void)
{
    tSfPolicyUserContextId old_config = imap_config;

    if (imap_swap_config == NULL)
        return NULL;

    imap_config = imap_swap_config;
    imap_swap_config = NULL;

    sfPolicyUserDataIterate (old_config, IMAPReloadSwapPolicy);

    if (sfPolicyUserPolicyGetActive(old_config) == 0)
        IMAP_FreeConfigs(old_config);

    return NULL;
}

static void IMAPReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    IMAP_FreeConfigs((tSfPolicyUserContextId)data);
}
#endif
