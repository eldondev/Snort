/* $Id */

/*
 ** Copyright (C) 2011-2011 Sourcefire, Inc.
 **
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
 * SIP preprocessor
 *
 * This is the main entry point for this preprocessor
 *
 * Author: Hui Cao
 * Date: 03-15-2011
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif  /* HAVE_CONFIG_H */

#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "sf_snort_plugin_api.h"
#include "snort_debug.h"

#include "preprocids.h"
#include "spp_sip.h"
#include "sip_config.h"
#include "sip_roptions.h"
#include "sip_parser.h"
#include "sip_dialog.h"

#include  <assert.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#ifndef WIN32
#include <strings.h>
#include <sys/time.h>
#endif
#include <stdlib.h>
#include <ctype.h>

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats sipPerfStats;
#endif

#include "sf_types.h"

const int MAJOR_VERSION = 1;
const int MINOR_VERSION = 1;
const int BUILD_VERSION = 1;

#ifdef SUP_IP6
const char *PREPROC_NAME = "SF_SIP (IPV6)";
#else
const char *PREPROC_NAME = "SF_SIP";
#endif

#define SetupSIP DYNAMIC_PREPROC_SETUP

#ifdef TARGET_BASED
int16_t sip_app_id = SFTARGET_UNKNOWN_PROTOCOL;
#endif

/*
 * Session state flags for SIPData::state_flags
 */

#define SIP_FLG_MISSED_PACKETS        (0x10000)
#define SIP_FLG_REASSEMBLY_SET        (0x20000)
/*
 * Function prototype(s)
 */
SIPData * SIPGetNewSession(SFSnortPacket *, tSfPolicyId);
static void SIPInit( char* );
static void SIPCheckConfig(void);
static void FreeSIPData( void* );
static inline int SIP_Process(SFSnortPacket *, SIPData*);
static void SIPmain( void*, void* );
static inline int CheckSIPPort( uint16_t );
static void SIPFreeConfig(tSfPolicyUserContextId);
static void _addPortsToStream5Filter(SIPConfig *, tSfPolicyId);
static void SIP_PrintStats(int);
#ifdef TARGET_BASED
static void _addServicesToStream5Filter(tSfPolicyId);
#endif

static void SIPCleanExit(int, void *);

/********************************************************************
 * Global variables
 ********************************************************************/
uint32_t numSessions = 0;
SIP_Stats sip_stats;
SIPConfig *sip_eval_config;
tSfPolicyUserContextId sip_config;

#ifdef SNORT_RELOAD
static tSfPolicyUserContextId sip_swap_config = NULL;
static void SIPReload(char *);
static int SIPReloadVerify(void);
static void * SIPReloadSwap(void);
static void SIPReloadSwapFree(void *);
#endif


/* Called at preprocessor setup time. Links preprocessor keyword
 * to corresponding preprocessor initialization function.
 *
 * PARAMETERS:	None.
 *
 * RETURNS:	Nothing.
 *
 */
void SetupSIP(void)
{
    /* Link preprocessor keyword to initialization function
     * in the preprocessor list. */
#ifndef SNORT_RELOAD
    _dpd.registerPreproc( "sip", SIPInit );
#else
    _dpd.registerPreproc("sip", SIPInit, SIPReload,
            SIPReloadSwap, SIPReloadSwapFree);
#endif
}

/* Initializes the SIP preprocessor module and registers
 * it in the preprocessor list.
 * 
 * PARAMETERS:  
 *
 * argp:        Pointer to argument string to process for config
 *                      data.
 *
 * RETURNS:     Nothing. 
 */
static void SIPInit(char *argp)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy();
    SIPConfig *pDefaultPolicyConfig = NULL;
    SIPConfig *pPolicyConfig = NULL;


    if (sip_config == NULL)
    {
        //create a context
        sip_config = sfPolicyConfigCreate();
        if (sip_config == NULL)
        {
            DynamicPreprocessorFatalMessage("Failed to allocate memory "
                    "for SIP config.\n");
        }

        if (_dpd.streamAPI == NULL)
        {
            DynamicPreprocessorFatalMessage("SetupSIP(): The Stream preprocessor must be enabled.\n");
        }

        _dpd.addPreprocConfCheck(SIPCheckConfig);
        _dpd.registerPreprocStats(SIP_NAME, SIP_PrintStats);
        _dpd.addPreprocExit(SIPCleanExit, NULL, PRIORITY_LAST, PP_SIP);

#ifdef PERF_PROFILING
        _dpd.addPreprocProfileFunc("sip", (void *)&sipPerfStats, 0, _dpd.totalPerfStats);
#endif

#ifdef TARGET_BASED
        sip_app_id = _dpd.findProtocolReference("sip");
        if (sip_app_id == SFTARGET_UNKNOWN_PROTOCOL)
            sip_app_id = _dpd.addProtocolReference("sip");

#endif
    }

    sfPolicyUserPolicySet (sip_config, policy_id);
    pDefaultPolicyConfig = (SIPConfig *)sfPolicyUserDataGetDefault(sip_config);
    pPolicyConfig = (SIPConfig *)sfPolicyUserDataGetCurrent(sip_config);
    if ((pPolicyConfig != NULL) && (pDefaultPolicyConfig == NULL))
    {
        DynamicPreprocessorFatalMessage("SIP preprocessor can only be "
                "configured once.\n");
    }

    pPolicyConfig = (SIPConfig *)calloc(1, sizeof(SIPConfig));
    if (!pPolicyConfig)
    {
        DynamicPreprocessorFatalMessage("Could not allocate memory for "
                "SIP preprocessor configuration.\n");
    }

    sfPolicyUserDataSetCurrent(sip_config, pPolicyConfig);

    SIP_RegRuleOptions();

    ParseSIPArgs(pPolicyConfig, (u_char *)argp);

    if (policy_id != 0)
        pPolicyConfig->maxNumSessions = pDefaultPolicyConfig->maxNumSessions;
    if ( pPolicyConfig->disabled )
        return;

    _dpd.addPreproc( SIPmain, PRIORITY_APPLICATION, PP_SIP, PROTO_BIT__UDP|PROTO_BIT__TCP );

    _addPortsToStream5Filter(pPolicyConfig, policy_id);

#ifdef TARGET_BASED
    _addServicesToStream5Filter(policy_id);
#endif
}
/*********************************************************************
 * Overload PCRE options: this is to support the "H"
 *
 * For SIP messages, uri Buffers will point to SIP instead of HTTP
 *
 * Arguments:
 *  SFSnortPacket * - pointer to packet structure
 *
 * Returns:
 *  None
 *
 *********************************************************************/
static inline void SIP_overloadURI(SFSnortPacket *p, SIPMsg *sipMsg)
{
    _dpd.uriBuffers[HTTP_BUFFER_HEADER]->uriBuffer = (uint8_t *) sipMsg->header;
    _dpd.uriBuffers[HTTP_BUFFER_HEADER]->uriLength = sipMsg->headerLen;
    _dpd.uriBuffers[HTTP_BUFFER_CLIENT_BODY]->uriBuffer = (uint8_t *) sipMsg->body_data;
    _dpd.uriBuffers[HTTP_BUFFER_CLIENT_BODY]->uriLength = sipMsg->bodyLen;
    p->num_uris = HTTP_BUFFER_CLIENT_BODY + 1;

}
/*********************************************************************
 * Main entry point for SIP processing.
 *
 * Arguments:
 *  SFSnortPacket * - pointer to packet structure
 *
 * Returns:
 *  int - 	SIP_SUCCESS
 *		    SIP_FAILURE
 *
 *********************************************************************/
static inline int SIP_Process(SFSnortPacket *p, SIPData* sessp)
{
    int status;
    char* sip_buff = (char*) p->payload;
    char* end;
    SIP_Roptions *pRopts;
    SIPMsg sipMsg;

    memset(&sipMsg, 0, sizeof(sipMsg));

    end =  sip_buff + p->payload_size;

    status = sip_parse(&sipMsg, sip_buff, end);

    if (SIP_SUCCESS == status)
    {
        SIP_overloadURI(p, &sipMsg);
        /*Update the dialog state*/
        SIP_updateDialog(&sipMsg, &(sessp->dialogs));
    }
    /*Update the session data*/
    pRopts = &(sessp->ropts);
    pRopts->methodFlag = sipMsg.methodFlag;
    pRopts->header_data = sipMsg.header;
    pRopts->header_len = sipMsg.headerLen;
    pRopts->body_len = sipMsg.bodyLen;
    pRopts->body_data = sipMsg.body_data;
    pRopts->status_code = sipMsg.status_code;

    DEBUG_WRAP(DebugMessage(DEBUG_SIP, "SIP message header length: %d\n",
            sipMsg.headerLen));
    DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Parsed method: %.*s, Flag: 0x%x\n",
            sipMsg.methodLen, sipMsg.method, sipMsg.methodFlag));
    DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Parsed status code:  %d\n",
            sipMsg.status_code));
    DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Parsed header address: %p.\n",
            sipMsg.header));
    DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Parsed body address: %p.\n",
            sipMsg.body_data));

    sip_freeMsg(&sipMsg);

    return status;

}
/* Main runtime entry point for SIP preprocessor.
 * Analyzes SIP packets for anomalies/exploits.
 * 
 * PARAMETERS:
 *
 * packetp:    Pointer to current packet to process. 
 * contextp:    Pointer to context block, not used.
 *
 * RETURNS:     Nothing.
 */
static void SIPmain( void* ipacketp, void* contextp )
{
    SIPData* sessp = NULL;
    uint8_t source = 0;
    uint8_t dest = 0;

    SFSnortPacket* packetp;
#ifdef TARGET_BASED
    int16_t app_id = SFTARGET_UNKNOWN_PROTOCOL;
#endif
    tSfPolicyId policy_id = _dpd.getRuntimePolicy();
    PROFILE_VARS;

    DEBUG_WRAP(DebugMessage(DEBUG_SIP, "%s\n", SIP_DEBUG__START_MSG));

    packetp = (SFSnortPacket*) ipacketp;
    sfPolicyUserPolicySet (sip_config, policy_id);

    /* Make sure this preprocessor should run. */
    if (( !packetp ) ||	( !packetp->payload ) ||( !packetp->payload_size ))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_SIP, "No payload - not inspecting.\n"));
        DEBUG_WRAP(DebugMessage(DEBUG_SIP, "%s\n", SIP_DEBUG__END_MSG));
        return;
    }
    /* check if we're waiting on stream reassembly */
    else if 	( packetp->flags & FLAG_STREAM_INSERT)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Stream inserted - not inspecting.\n"));
        DEBUG_WRAP(DebugMessage(DEBUG_SIP, "%s\n", SIP_DEBUG__END_MSG));
        return;
    }
    else if (!IsTCP(packetp) && !IsUDP(packetp))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Not UDP or TCP - not inspecting.\n"));
        DEBUG_WRAP(DebugMessage(DEBUG_SIP, "%s\n", SIP_DEBUG__END_MSG));
        return;
    }

    PREPROC_PROFILE_START(sipPerfStats);

    sip_eval_config = sfPolicyUserDataGetCurrent(sip_config);

    /* Attempt to get a previously allocated SIP block. */
    sessp = _dpd.streamAPI->get_application_data(packetp->stream_session_ptr, PP_SIP);
    if (sessp != NULL)
    {
        sip_eval_config = sfPolicyUserDataGet(sessp->config, sessp->policy_id);

    }

    if (sessp == NULL)
    {
        /* If not doing autodetection, check the ports to make sure this is
         * running on an SIP port, otherwise no need to examine the traffic.
         */
#ifdef TARGET_BASED
        app_id = _dpd.streamAPI->get_application_protocol_id(packetp->stream_session_ptr);
        if (app_id == SFTARGET_UNKNOWN_PROTOCOL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Unknown protocol - not inspecting.\n"));
            DEBUG_WRAP(DebugMessage(DEBUG_SIP, "%s\n", SIP_DEBUG__END_MSG));
            PREPROC_PROFILE_END(sipPerfStats);
            return;
        }

        else if (app_id && (app_id != sip_app_id))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Not SIP - not inspecting.\n"));
            DEBUG_WRAP(DebugMessage(DEBUG_SIP, "%s\n", SIP_DEBUG__END_MSG));
            PREPROC_PROFILE_END(sipPerfStats);
            return;
        }

        else if (!app_id)
        {
#endif
            source = (uint8_t)CheckSIPPort( packetp->src_port );
            dest = (uint8_t)CheckSIPPort( packetp->dst_port );

            if ( !source && !dest )
            {
                /* Not one of the ports we care about. */
                DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Not SIP ports - not inspecting.\n"));
                DEBUG_WRAP(DebugMessage(DEBUG_SIP, "%s\n", SIP_DEBUG__END_MSG));
                PREPROC_PROFILE_END(sipPerfStats);
                return;
            }
#ifdef TARGET_BASED
        }
#endif
        /* Check the stream session. If it does not currently
         * have our SIP data-block attached, create one.
         */
        sessp = SIPGetNewSession(packetp, policy_id);

        if ( !sessp )
        {
            /* Could not get/create the session data for this packet. */
            DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Create session error - not inspecting.\n"));
            DEBUG_WRAP(DebugMessage(DEBUG_SIP, "%s\n", SIP_DEBUG__END_MSG));
            PREPROC_PROFILE_END(sipPerfStats);
            return;
        }

    }

    /* Don't process if we've missed packets */
    if (sessp->state_flags & SIP_FLG_MISSED_PACKETS)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Missed packets - not inspecting.\n"));
        DEBUG_WRAP(DebugMessage(DEBUG_SIP, "%s\n", SIP_DEBUG__END_MSG));
        PREPROC_PROFILE_END(sipPerfStats);
        return;
    }

    /* If we picked up mid-stream or missed any packets (midstream pick up
     * means we've already missed packets) set missed packets flag and make
     * sure we don't do any more reassembly on this session */
    if (IsTCP(packetp))
    {
        if ((_dpd.streamAPI->get_session_flags(packetp->stream_session_ptr) & SSNFLAG_MIDSTREAM)
                || _dpd.streamAPI->missed_packets(packetp->stream_session_ptr, SSN_DIR_BOTH))
        {
            _dpd.streamAPI->set_reassembly(packetp->stream_session_ptr,
                    STREAM_FLPOLICY_IGNORE, SSN_DIR_BOTH,
                    STREAM_FLPOLICY_SET_ABSOLUTE);

            sessp->state_flags |= SIP_FLG_MISSED_PACKETS;
            DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Missed packets - not inspecting.\n"));
            DEBUG_WRAP(DebugMessage(DEBUG_SIP, "%s\n", SIP_DEBUG__END_MSG));
            PREPROC_PROFILE_END(sipPerfStats);
            return;
        }
    }

    /* We're interested in this session. Turn on stream reassembly. */
    if ( !(sessp->state_flags & SIP_FLG_REASSEMBLY_SET ))
    {
        _dpd.streamAPI->set_reassembly(packetp->stream_session_ptr,
                STREAM_FLPOLICY_FOOTPRINT, SSN_DIR_BOTH, STREAM_FLPOLICY_SET_ABSOLUTE);
        sessp->state_flags |= SIP_FLG_REASSEMBLY_SET;
    }
    /*
     * Start process PAYLOAD
     */
    SIP_Process(packetp,sessp);

    DEBUG_WRAP(DebugMessage(DEBUG_SIP, "%s\n", SIP_DEBUG__END_MSG));
    PREPROC_PROFILE_END(sipPerfStats);

}

/**********************************************************************
 *  Retrieves the SIP data block registered with the stream
 * session associated w/ the current packet. If none exists,
 * allocates it and registers it with the stream API.
 *
 * Arguments:
 *
 * packetp:	Pointer to the packet from which/in which to
 * 		retrieve/store the SIP data block.
 *
 * RETURNS:	Pointer to an SIP data block, upon success.
 *		NULL, upon failure.
 **********************************************************************/
SIPData * SIPGetNewSession(SFSnortPacket *packetp, tSfPolicyId policy_id)
{
    SIPData* datap = NULL;
    static int MaxSessionsAlerted = 0;
    /* Sanity check(s) */
    assert( packetp );
    if ( !packetp->stream_session_ptr )
    {
        return NULL;
    }
    if(numSessions > ((SIPConfig *)sfPolicyUserDataGetCurrent(sip_config))->maxNumSessions)
    {
        if (!MaxSessionsAlerted)
            ALERT(SIP_EVENT_MAX_SESSIONS,SIP_EVENT_MAX_SESSIONS_STR);
        MaxSessionsAlerted = 1;
        return NULL;
    }
    else
    {
        MaxSessionsAlerted = 0;
    }
    datap = (SIPData *)calloc(1, sizeof(SIPData));

    if ( !datap )
        return NULL;

    /*Register the new SIP data block in the stream session. */
    _dpd.streamAPI->set_application_data(
            packetp->stream_session_ptr,
            PP_SIP, datap, FreeSIPData );

    datap->policy_id = policy_id;
    datap->config = sip_config;
    ((SIPConfig *)sfPolicyUserDataGetCurrent(sip_config))->ref_count++;
    numSessions++;
    sip_stats.sessions++;
    DEBUG_WRAP(DebugMessage(DEBUG_SIP, "Number of sessions created: %u\n", numSessions));

    return datap;
}


/***********************************************************************
 * Registered as a callback with our SIP data blocks when
 * they are added to the underlying stream session. Called
 * by the stream preprocessor when a session is about to be
 * destroyed.
 *
 * PARAMETERS:
 *
 * idatap:	Pointer to the moribund data.
 *
 * RETURNS:	Nothing.
 ***********************************************************************/
static void FreeSIPData( void* idatap )
{
    SIPData *ssn = (SIPData *)idatap;
    SIPConfig *config = NULL;

    if (ssn == NULL)
        return;
    if (numSessions > 0)
        numSessions--;

    /*Free all the dialog data*/
    sip_freeDialogs(ssn->dialogs);

    /*Clean the configuration data*/
    if (ssn->config != NULL)
    {
        config = (SIPConfig *)sfPolicyUserDataGet(ssn->config, ssn->policy_id);
    }

    if (config == NULL)
    {
        free(ssn);
        return;
    }

    config->ref_count--;
    if ((config->ref_count == 0) &&	(ssn->config != sip_config))
    {
        sfPolicyUserDataClear (ssn->config, ssn->policy_id);
        free(config);

        if (sfPolicyUserPolicyGetActive(ssn->config) == 0)
        {
            /* No more outstanding configs - free the config array */
            SIPFreeConfig(ssn->config);
        }

    }

    free(ssn);
}
/* **********************************************************************
 * Validates given port as an SIP server port.
 *
 * PARAMETERS:
 *
 * port:	Port to validate.
 *
 * RETURNS:	SIP_TRUE, if the port is indeed an SIP server port.
 *		    SIP_FALSE, otherwise.
 ***********************************************************************/
static inline int CheckSIPPort( uint16_t port )
{
    if ( sip_eval_config->ports[ PORT_INDEX(port) ] & CONV_PORT( port ) )
    {
        return SIP_TRUE;
    }

    return SIP_FALSE;
}

static void _addPortsToStream5Filter(SIPConfig *config, tSfPolicyId policy_id)
{
    int portNum;

    assert(config);
    assert(_dpd.streamAPI);

    for (portNum = 0; portNum < MAXPORTS; portNum++)
    {
        if(config->ports[(portNum/8)] & (1<<(portNum%8)))
        {
            //Add port the port
            _dpd.streamAPI->set_port_filter_status(IPPROTO_UDP, (uint16_t)portNum, PORT_MONITOR_SESSION, policy_id, 1);
            _dpd.streamAPI->set_port_filter_status(IPPROTO_TCP, (uint16_t)portNum, PORT_MONITOR_SESSION, policy_id, 1);
        }
    }

}
#ifdef TARGET_BASED

static void _addServicesToStream5Filter(tSfPolicyId policy_id)
{
    _dpd.streamAPI->set_service_filter_status(sip_app_id, PORT_MONITOR_SESSION, policy_id, 1);
}
#endif
static int SIPCheckPolicyConfig(tSfPolicyUserContextId config, tSfPolicyId policyId, void* pData)
{
    _dpd.setParserPolicy(policyId);

    if (!_dpd.isPreprocEnabled(PP_STREAM5))
    {
        DynamicPreprocessorFatalMessage("SIPCheckPolicyConfig(): The Stream preprocessor must be enabled.\n");
    }
    return 0;
}
void SIPCheckConfig(void)
{
    sfPolicyUserDataIterate (sip_config, SIPCheckPolicyConfig);
}


static void SIPCleanExit(int signal, void *data)
{
    if (sip_config != NULL)
    {
        SIPFreeConfig(sip_config);
        sip_config = NULL;
    }
}
static int SIPFreeConfigPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
)
{
    SIPConfig *pPolicyConfig = (SIPConfig *)pData;

    //do any housekeeping before freeing SIPConfig

    sfPolicyUserDataClear (config, policyId);

    SIP_FreeConfig(pPolicyConfig);
    return 0;
}

void SIPFreeConfig(tSfPolicyUserContextId config)
{
    if (config == NULL)
        return;

    sfPolicyUserDataIterate (config, SIPFreeConfigPolicy);
    sfPolicyConfigDelete(config);
}
/******************************************************************
 * Print statistics being kept by the preprocessor.
 *
 * Arguments:
 *  int - whether Snort is exiting or not
 *
 * Returns: None
 *
 ******************************************************************/
static void SIP_PrintStats(int exiting)
{
    int i;
    _dpd.logMsg("SIP Preprocessor Statistics\n");
    _dpd.logMsg("  Total sessions: "STDu64"\n", sip_stats.sessions);
    if (sip_stats.sessions > 0)
    {
        if (sip_stats.events > 0)
            _dpd.logMsg("  Preprocessor events: "STDu64"\n", sip_stats.events);
        if (sip_stats.dialogs > 0)
            _dpd.logMsg("  Total  dialogs: "STDu64"\n", sip_stats.dialogs);

        _dpd.logMsg("  Requests: "STDu64"\n", sip_stats.requests[0]);
        i = 0;
        while (NULL != StandardMethods[i].name)
        {
            _dpd.logMsg("%16s:   "STDu64"\n",
                    StandardMethods[i].name, sip_stats.requests[StandardMethods[i].methodFlag]);
            i++;
        }

        _dpd.logMsg("  Responses: "STDu64"\n", sip_stats.responses[TOTAL_RESPONSES]);
        for (i = 1; i <NUM_OF_RESPONSE_TYPES; i++ )
        {
            _dpd.logMsg("             %dxx:   "STDu64"\n", i, sip_stats.responses[i]);
        }

        _dpd.logMsg(" Ignore sessions:   "STDu64"\n", sip_stats.ignoreSessions);
        _dpd.logMsg(" Ignore channels:   "STDu64"\n", sip_stats.ignoreChannels);
    }
}
#ifdef SNORT_RELOAD
static void SIPReload(char *args)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy();
    SIPConfig * pPolicyConfig = NULL;

    if (sip_swap_config == NULL)
    {
        //create a context
        sip_swap_config = sfPolicyConfigCreate();
        if (sip_swap_config == NULL)
        {
            DynamicPreprocessorFatalMessage("Failed to allocate memory "
                    "for SIP config.\n");
        }

        if (_dpd.streamAPI == NULL)
        {
            DynamicPreprocessorFatalMessage("SetupSIP(): The Stream preprocessor must be enabled.\n");
        }
    }

    sfPolicyUserPolicySet (sip_swap_config, policy_id);
    pPolicyConfig = (SIPConfig *)sfPolicyUserDataGetCurrent(sip_swap_config);
    if (pPolicyConfig != NULL)
    {
        DynamicPreprocessorFatalMessage("SIP preprocessor can only be "
                "configured once.\n");
    }

    pPolicyConfig = (SIPConfig *)calloc(1, sizeof(SIPConfig));
    if (!pPolicyConfig)
    {
        DynamicPreprocessorFatalMessage("Could not allocate memory for "
                "SIP preprocessor configuration.\n");
    }
    sfPolicyUserDataSetCurrent(sip_swap_config, pPolicyConfig);

    SIP_RegRuleOptions();

    ParseSIPArgs(pPolicyConfig, (u_char *)args);

    _dpd.addPreproc( SIPmain, PRIORITY_APPLICATION, PP_SIP, PROTO_BIT__UDP|PROTO_BIT__TCP );
    _dpd.addPreprocReloadVerify(SIPReloadVerify);

    _addPortsToStream5Filter(pPolicyConfig, policy_id);

#ifdef TARGET_BASED
    _addServicesToStream5Filter(policy_id);
#endif
}

static int SIPReloadVerify(void)
{
    if (!_dpd.isPreprocEnabled(PP_STREAM5))
    {
        DynamicPreprocessorFatalMessage("SetupSIP(): The Stream preprocessor must be enabled.\n");
    }

    return 0;
}
static int SshFreeUnusedConfigPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
)
{
    SIPConfig *pPolicyConfig = (SIPConfig *)pData;

    //do any housekeeping before freeing SIPConfig
    if (pPolicyConfig->ref_count == 0)
    {
        sfPolicyUserDataClear (config, policyId);
        SIP_FreeConfig(pPolicyConfig);
    }
    return 0;
}

static void * SIPReloadSwap(void)
{
    tSfPolicyUserContextId old_config = sip_config;

    if (sip_swap_config == NULL)
        return NULL;

    sip_config = sip_swap_config;
    sip_swap_config = NULL;

    sfPolicyUserDataIterate (old_config, SshFreeUnusedConfigPolicy);

    if (sfPolicyUserPolicyGetActive(old_config) == 0)
    {
        /* No more outstanding configs - free the config array */
        return (void *)old_config;
    }

    return NULL;
}

static void SIPReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    SIPFreeConfig((tSfPolicyUserContextId)data);
}
#endif
