/*
 * spp_dcerpc.c
 *
 * Copyright (C) 2004-2009 Sourcefire, Inc.
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
 * Description:
 *
 * This file initializes DCERPC as a Snort preprocessor.
 *
 * This file registers the DCERPC initialization function,
 * adds the DCERPC function into the preprocessor list, reads
 * the user configuration in the snort.conf file, and prints out
 * the configuration that is read.
 *
 * In general, this file is a wrapper to DCERPC preproc functionality,
 * by interfacing with the Snort preprocessor functions.  The rest
 * of DCERPC should be separate from the preprocessor hooks.
 *
 * The DCERPC preprocessor parses DCERPC requests from remote machines by
 * layering SMB and DCERPC data structures over the data stream and extracting
 * various pieces of information.
 *
 * Arguments:
 *   
 * This plugin takes port list(s) representing the TCP ports that the
 * user is interested in having decoded.  It is of the format
 *
 * ports nbt { port1 [port2 ...] }
 * ports raw { port1 [port2 ...] }
 *
 * where nbt & raw are used to specify the ports for SMB over NetBios/TCP
 * and raw SMB, respectively.
 *
 * Effect:
 *
 * None
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_STRINGS_H	 
#include <strings.h>	 
#endif

#include "debug.h"

#include "preprocids.h"
#include "sf_snort_packet.h"

#include "profiler.h"

#include "snort_dcerpc.h"

#ifdef PERF_PROFILING
PreprocStats dcerpcPerfStats;
PreprocStats dcerpcDetectPerfStats;
#endif

#include "sf_types.h"

/*
 * The length of the error string buffer.
 */
#define ERRSTRLEN 1000

/*
 * The definition of the configuration separators in the snort.conf
 * configure line.
 */
#define CONF_SEPARATORS " \t\n\r"

tSfPolicyUserContextId dcerpc_config = NULL;
DceRpcConfig *dcerpc_eval_config = NULL;
 
void DCERPCInit(char *);
void ProcessDCERPCPacket(void *, void *);
static void DCERPCCleanExitFunction(int, void *);
static void DCERPCReset(int, void *);
static void DCERPCResetStats(int, void *);
static void _addPortsToStream5Filter(DceRpcConfig *, tSfPolicyId);
#ifdef TARGET_BASED
static void _addServicesToStream5Filter(tSfPolicyId);
extern DCERPC_ProtoIds _dce_proto_ids;
#endif
static void DCERPCCheckConfig(void);

#ifdef SNORT_RELOAD
static tSfPolicyUserContextId dcerpc_swap_config = NULL;
static void DCERPCReload(char *);
static int DCERPCVerifyReload(void);
static void * DCERPCReloadSwap(void);
static void DCERPCReloadSwapFree(void *);
#endif


/*
 * Function: SetupDCERPC()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupDCERPC(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
#ifndef SNORT_RELOAD
    _dpd.registerPreproc("dcerpc", DCERPCInit);
#else
    _dpd.registerPreproc("dcerpc", DCERPCInit, DCERPCReload,
                         DCERPCReloadSwap, DCERPCReloadSwapFree);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,"Preprocessor: DCERPC in setup...\n"););
}


/*
 * Function: DCERPCInit(char *)
 *
 * Purpose: Processes the args sent to the preprocessor, sets up the
 *          port list, links the processing function into the preproc
 *          function list
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void DCERPCInit(char *args)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy();
    char ErrorString[ERRSTRLEN];
    int  iErrStrLen = ERRSTRLEN - 1;
    char *token = strtok(args, CONF_SEPARATORS);
    DceRpcConfig *pPolicyConfig = NULL;

    ErrorString[ERRSTRLEN - 1] = '\0';

    if (dcerpc_config == NULL)
    {
        //create a context
        dcerpc_config = sfPolicyConfigCreate();
        if (dcerpc_config == NULL)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Could not allocate memory "
                                            "for dcerpc preprocessor configuration.\n");
        }

        if (_dpd.streamAPI == NULL)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => dcerpc: Stream5 must be enabled.\n",
                                            *_dpd.config_file, *_dpd.config_line);
        }

#ifdef PERF_PROFILING
        _dpd.addPreprocProfileFunc("dcerpc", &dcerpcPerfStats, 0, _dpd.totalPerfStats);
#endif

#ifdef TARGET_BASED
        _dce_proto_ids.dcerpc = _dpd.findProtocolReference(DCE_PROTO_REF_STR__DCERPC);
        if (_dce_proto_ids.dcerpc == SFTARGET_UNKNOWN_PROTOCOL)
            _dce_proto_ids.dcerpc = _dpd.addProtocolReference(DCE_PROTO_REF_STR__DCERPC);

        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,"DCE/RPC: Target-based: Proto id for %s: %u.\n",
                                DCE_PROTO_REF_STR__DCERPC, _dce_proto_ids.dcerpc););

        /* smb and netbios-ssn refer to the same thing */
        _dce_proto_ids.nbss = _dpd.findProtocolReference(DCE_PROTO_REF_STR__NBSS);
        if (_dce_proto_ids.nbss == SFTARGET_UNKNOWN_PROTOCOL)
            _dce_proto_ids.nbss = _dpd.addProtocolReference(DCE_PROTO_REF_STR__NBSS);

        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,"DCE/RPC: Target-based: Proto id for %s: %u.\n",
                                DCE_PROTO_REF_STR__NBSS, _dce_proto_ids.nbss););
#endif

        /* Init reassembly packet */
        DCERPC_InitPacket();

        _dpd.addPreprocExit(DCERPCCleanExitFunction, NULL, PRIORITY_LAST, PP_DCERPC);
        _dpd.addPreprocReset(DCERPCReset, NULL, PRIORITY_LAST, PP_DCERPC);
        _dpd.addPreprocResetStats(DCERPCResetStats, NULL, PRIORITY_LAST, PP_DCERPC);
        _dpd.addPreprocConfCheck(DCERPCCheckConfig);
    }

    if ((policy_id != _dpd.getDefaultPolicy()) 
            && (sfPolicyUserDataGetDefault(dcerpc_config) == NULL))
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Must configure dcerpc in "
                "default policy if using in other policies.\n",
                *_dpd.config_file, *_dpd.config_line);
    }

    sfPolicyUserPolicySet (dcerpc_config, policy_id);
    pPolicyConfig = (DceRpcConfig *)sfPolicyUserDataGetCurrent(dcerpc_config);
    if (pPolicyConfig != NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Can only configure dcerpc "
                "preprocessor once.\n", *_dpd.config_file, *_dpd.config_line);
    }

    if (_dpd.isPreprocEnabled(PP_DCE2))
    {
        DynamicPreprocessorFatalMessage("%s(%d) => dcerpc: Only one DCE/RPC preprocessor can be configured.\n",
                 *_dpd.config_file, *_dpd.config_line);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,"Preprocessor: DCERPC Initialized\n"););

    pPolicyConfig = (DceRpcConfig *)calloc(1, sizeof(DceRpcConfig));
    if (pPolicyConfig == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Could not allocate memory "
                                        "for dcerpc preprocessor configuration.\n");
    }
 
    sfPolicyUserDataSetCurrent(dcerpc_config, pPolicyConfig);

    /* Parse configuration */
    if (DCERPCProcessConf(pPolicyConfig, token, ErrorString, iErrStrLen))
        DynamicPreprocessorFatalMessage("%s(%d) => %s\n", *_dpd.config_file, *_dpd.config_line, ErrorString);

    /* Set the preprocessor function into the function list */
    _dpd.addPreproc(ProcessDCERPCPacket, PRIORITY_APPLICATION, PP_DCERPC, PROTO_BIT__TCP);
    _dpd.addPreprocReassemblyPkt(DCERPC_GetReassemblyPkt, PP_DCERPC);

    _addPortsToStream5Filter(pPolicyConfig, policy_id);

#ifdef TARGET_BASED
    _addServicesToStream5Filter(policy_id);
#endif
}

#if 0
static void DCERPC_DisableDetect(SFSnortPacket *p)
{
    _dpd.disableAllDetect(p);

    _dpd.setPreprocBit(p, PP_SFPORTSCAN);
    _dpd.setPreprocBit(p, PP_PERFMONITOR);
    _dpd.setPreprocBit(p, PP_STREAM5);
}
#endif

static void DCERPC_DisablePreprocessors(SFSnortPacket *p)
{
    _dpd.disablePreprocessors(p);

    _dpd.setPreprocBit(p, PP_SFPORTSCAN);
    _dpd.setPreprocBit(p, PP_PERFMONITOR);
    _dpd.setPreprocBit(p, PP_STREAM5);
}


/*
 * Function: ProcessDCERPCPacket(void *)
 *
 * Purpose: Inspects the packet's payload for fragment records and 
 *          converts them into one infragmented record.
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
void ProcessDCERPCPacket(void *pkt, void *context)
{
	SFSnortPacket *p = (SFSnortPacket *)pkt;
    uint32_t      session_flags = 0;
    PROFILE_VARS;

    /* no data to inspect */
    if (p->payload_size == 0)
        return;

    /* check to make sure we're talking TCP and that the TWH has already
       completed before processing anything */
    if(!IsTCP(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,"It isn't TCP session traffic\n"););
        return;
    }

    if (p->stream_session_ptr == NULL)
        return;

    session_flags = _dpd.streamAPI->get_session_flags(p->stream_session_ptr);

    if (session_flags & SSNFLAG_MIDSTREAM)
        return;

    if (!(session_flags & SSNFLAG_ESTABLISHED))
        return;

    PREPROC_PROFILE_START(dcerpcPerfStats);

    if (DCERPCDecode(p))
        DCERPC_DisablePreprocessors(p);

    PREPROC_PROFILE_END(dcerpcPerfStats);
}

/* 
 * Function: DCERPCCleanExitFunction(int, void *)
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
static void DCERPCCleanExitFunction(int signal, void *data)
{
    DCERPC_Exit();

    if (dcerpc_config != NULL)
    {
        DceRpcFreeConfig(dcerpc_config);
        dcerpc_config = NULL;
    }
}

static void DCERPCReset(int signal, void *data)
{
    return;
}

static void DCERPCResetStats(int signal, void *data)
{
    return;
}

static void _addPortsToStream5Filter(DceRpcConfig *config, tSfPolicyId policy_id)
{
    unsigned int portNum;

    if (config == NULL)
        return;

    //smb ports
    for (portNum = 0; portNum < MAXPORTS; portNum++)
    {
        if(config->SMBPorts[(portNum/8)] & (1<<(portNum%8)))
        {
            //Add port the port. Only TCP port is used
            _dpd.streamAPI->set_port_filter_status
                (IPPROTO_TCP, (uint16_t)portNum, PORT_MONITOR_SESSION, policy_id, 1);
        }
    }

    //dcerpc ports
    for (portNum = 0; portNum < MAXPORTS; portNum++)
    {
        if(config->DCERPCPorts[(portNum/8)] & (1<<(portNum%8)))
        {
            //Add port the port. Only TCP port is used
            _dpd.streamAPI->set_port_filter_status
                (IPPROTO_TCP, (uint16_t)portNum, PORT_MONITOR_SESSION, policy_id, 1);
        }
    }
}
#ifdef TARGET_BASED
static void _addServicesToStream5Filter(tSfPolicyId policy_id)
{
    _dpd.streamAPI->set_service_filter_status
        (_dce_proto_ids.dcerpc, PORT_MONITOR_SESSION, policy_id, 1);

    _dpd.streamAPI->set_service_filter_status
        (_dce_proto_ids.nbss, PORT_MONITOR_SESSION, policy_id, 1);
}
#endif

static int DCERPCCheckPolicyConfig(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
        )
{
    _dpd.setParserPolicy(policyId);
    if (!_dpd.isPreprocEnabled(PP_STREAM5))
        DynamicPreprocessorFatalMessage("dcerpc: Stream5 must be enabled.\n");

    return 0;
}

static void DCERPCCheckConfig(void)
{
    sfPolicyUserDataIterate (dcerpc_config, DCERPCCheckPolicyConfig);
}

#ifdef SNORT_RELOAD
static void DCERPCReload(char *args)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy();
    char ErrorString[ERRSTRLEN];
    int  iErrStrLen = ERRSTRLEN - 1;
    char *token = strtok(args, CONF_SEPARATORS);
    DceRpcConfig * pPolicyConfig = NULL;

    ErrorString[ERRSTRLEN - 1] = '\0';

    if (dcerpc_swap_config == NULL)
    {
        //create a context
        dcerpc_swap_config = sfPolicyConfigCreate();
        if (dcerpc_swap_config == NULL)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Could not allocate memory "
                                            "for dcerpc preprocessor configuration.\n");
        }

        if (_dpd.streamAPI == NULL)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => dcerpc: Stream5 must be enabled.\n",
                                            *_dpd.config_file, *_dpd.config_line);
        }

        _dpd.addPreprocReloadVerify(DCERPCVerifyReload);
    }

    if ((policy_id != _dpd.getDefaultPolicy()) 
            && (sfPolicyUserDataGetDefault(dcerpc_swap_config) == NULL))
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Must configure dcerpc in "
                "default policy if using in other policies.\n",
                *_dpd.config_file, *_dpd.config_line);
    }

    sfPolicyUserPolicySet (dcerpc_swap_config, policy_id);
    pPolicyConfig = (DceRpcConfig *)sfPolicyUserDataGetCurrent(dcerpc_swap_config);
    if (pPolicyConfig != NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Can only configure dcerpc "
                "preprocessor once.\n", *_dpd.config_file, *_dpd.config_line);
    }

    if (_dpd.isPreprocEnabled(PP_DCE2))
    {
        DynamicPreprocessorFatalMessage("%s(%d) => dcerpc: Only one DCE/RPC preprocessor can be configured.\n",
                 *_dpd.config_file, *_dpd.config_line);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,"Preprocessor: DCERPC Initialized\n"););

    pPolicyConfig = (DceRpcConfig *)calloc(1, sizeof(DceRpcConfig));
    if (pPolicyConfig == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Could not allocate memory "
                                        "for dcerpc preprocessor configuration.\n");
    }
 
    sfPolicyUserDataSetCurrent(dcerpc_swap_config, pPolicyConfig);

    /* Parse configuration */
    if (DCERPCProcessConf(pPolicyConfig, token, ErrorString, iErrStrLen))
        DynamicPreprocessorFatalMessage("%s(%d) => %s\n", *_dpd.config_file, *_dpd.config_line, ErrorString);

	_dpd.addPreproc(ProcessDCERPCPacket, PRIORITY_APPLICATION, PP_DCERPC, PROTO_BIT__TCP);

#ifdef TARGET_BASED
    _addServicesToStream5Filter(policy_id);
#endif

    _addPortsToStream5Filter(pPolicyConfig, policy_id);
}

static int DCERPCVerifyReload(void)
{
    DceRpcConfig *config = NULL;
    DceRpcConfig *configNext = NULL;

    if (dcerpc_config != NULL)
    {
        config = (DceRpcConfig *)sfPolicyUserDataGet(dcerpc_config, _dpd.getDefaultPolicy());
    }

    if (dcerpc_swap_config != NULL)
    {
        configNext = (DceRpcConfig *)sfPolicyUserDataGet(dcerpc_swap_config, _dpd.getDefaultPolicy());
    }

    if ((configNext == NULL) || (config == NULL))
    {
        return 0;
    }

    if (!_dpd.isPreprocEnabled(PP_STREAM5))
        DynamicPreprocessorFatalMessage("dcerpc: Stream5 must be enabled.\n");

    if (configNext->memcap != config->memcap)
    {
        _dpd.errMsg("DCERPC reload: Changing the memcap requires a restart.\n");
        DceRpcFreeConfig(dcerpc_swap_config);
        dcerpc_swap_config = NULL;
        return -1;
    }

    return 0;
}

static int DceRPCReloadSwapPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId, 
        void* pData
        )
{
    DceRpcConfig *pPolicyConfig = (DceRpcConfig *)pData;

    //do any housekeeping before freeing DceRpcConfig
    if (pPolicyConfig->ref_count == 0)
    {
        sfPolicyUserDataClear (config, policyId);
        free(pPolicyConfig);
    }
    return 0;
}

static void * DCERPCReloadSwap(void)
{
    tSfPolicyUserContextId old_config = dcerpc_config;

    if (dcerpc_swap_config == NULL)
        return NULL;

    dcerpc_config = dcerpc_swap_config;
    dcerpc_swap_config = NULL;

    sfPolicyUserDataIterate (old_config, DceRPCReloadSwapPolicy);

    if (sfPolicyUserPolicyGetActive(old_config) != 0)
        return (void *)old_config;

    return NULL;
}

static void DCERPCReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    DceRpcFreeConfig((tSfPolicyUserContextId)data);
}
#endif
