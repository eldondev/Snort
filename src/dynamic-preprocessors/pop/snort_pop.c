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
 * snort_pop.c
 *
 * Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>
 *
 * Description:
 *
 * This file handles POP protocol checking and normalization.
 *
 * Entry point functions:
 *
 *     SnortPOP()
 *     POP_Init()
 *     POP_Free()
 *
 **************************************************************************/


/* Includes ***************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#include "sf_types.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcre.h>

#include "snort_pop.h"
#include "pop_config.h"
#include "pop_util.h"
#include "pop_log.h"

#include "sf_snort_packet.h"
#include "stream_api.h"
#include "snort_debug.h"
#include "profiler.h"
#include "snort_bounds.h"
#include "sf_dynamic_preprocessor.h"
#include "ssl.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"

#ifdef DEBUG_MSGS
#include "sf_types.h"
#endif

/**************************************************************************/


/* Externs ****************************************************************/

#ifdef PERF_PROFILING
extern PreprocStats popDetectPerfStats;
extern int popDetectCalled;
#endif

extern tSfPolicyUserContextId pop_config;
extern POPConfig *pop_eval_config;
extern MemPool *pop_mempool;

#ifdef DEBUG_MSGS
extern char pop_print_buffer[];
#endif

/**************************************************************************/


/* Globals ****************************************************************/

const POPToken pop_known_cmds[] =
{
    {"APOP",          4, CMD_APOP},
    {"AUTH",          4, CMD_AUTH},
    {"CAPA",          4, CMD_CAPA},
    {"DELE",          4, CMD_DELE},
    {"LIST",          4, CMD_LIST},
    {"NOOP",          4, CMD_NOOP},
    {"PASS",          4, CMD_PASS},
    {"QUIT",          4, CMD_QUIT},
    {"RETR",          4, CMD_RETR},
    {"RSET",          4, CMD_RSET},
    {"STAT",          4, CMD_STAT},
    {"STLS",          4, CMD_STLS},
    {"TOP",           3, CMD_TOP},
    {"UIDL",          4, CMD_UIDL},
    {"USER",          4, CMD_USER},
    {NULL,            0, 0}
};

const POPToken pop_resps[] =
{
	{"+OK",   3,  RESP_OK},   /* SUCCESS */
	{"-ERR",  4,  RESP_ERR},  /* FAILURE */
	{NULL,   0,  0}
};

const POPToken pop_hdrs[] =
{
    {"Content-type:", 13, HDR_CONTENT_TYPE},
    {"Content-Transfer-Encoding:", 26, HDR_CONT_TRANS_ENC},
    {NULL,             0, 0}
};

const POPToken pop_data_end[] =
{
	{"\r\n.\r\n",  5,  DATA_END_1},
	{"\n.\r\n",    4,  DATA_END_2},
	{"\r\n.\n",    4,  DATA_END_3},
	{"\n.\n",      3,  DATA_END_4},
	{NULL,         0,  0}
};

POP *pop_ssn = NULL;
POP pop_no_session;
POPPcre mime_boundary_pcre;
char pop_normalizing;
POPSearchInfo pop_search_info;

#ifdef DEBUG_MSGS
uint64_t pop_session_counter = 0;
#endif

#ifdef TARGET_BASED
int16_t pop_proto_id;
#endif

void *pop_resp_search_mpse = NULL;
POPSearch pop_resp_search[RESP_LAST];

void *pop_hdr_search_mpse = NULL;
POPSearch pop_hdr_search[HDR_LAST];

void *pop_data_search_mpse = NULL;
POPSearch pop_data_end_search[DATA_END_LAST];

POPSearch *pop_current_search = NULL;


/**************************************************************************/


/* Private functions ******************************************************/

static int POP_Setup(SFSnortPacket *p, POP *ssn);
static void POP_ResetState(void);
static void POP_SessionFree(void *);
static void POP_NoSessionFree(void);
static int POP_GetPacketDirection(SFSnortPacket *, int);
static void POP_ProcessClientPacket(SFSnortPacket *);
static void POP_ProcessServerPacket(SFSnortPacket *);
static void POP_DisableDetect(SFSnortPacket *);
static const uint8_t * POP_HandleCommand(SFSnortPacket *, const uint8_t *, const uint8_t *);
static const uint8_t * POP_HandleData(SFSnortPacket *, const uint8_t *, const uint8_t *);
static const uint8_t * POP_HandleHeader(SFSnortPacket *, const uint8_t *, const uint8_t *);
static const uint8_t * POP_HandleDataBody(SFSnortPacket *, const uint8_t *, const uint8_t *);
static int POP_SearchStrFound(void *, void *, int, void *, void *);

static int POP_BoundaryStrFound(void *, void *, int , void *, void *);
static int POP_GetBoundary(const char *, int);

static int POP_Inspect(SFSnortPacket *);

/**************************************************************************/

static void SetPopBuffers(POP *ssn)
{
    if ((ssn != NULL) && (ssn->decode_state == NULL)
            && (!POP_IsDecodingEnabled(pop_eval_config)))
    {
        MemBucket *bkt = mempool_alloc(pop_mempool);

        if (bkt != NULL)
        {
            ssn->decode_state = (Email_DecodeState *)calloc(1, sizeof(Email_DecodeState));
            if( ssn->decode_state != NULL )
            {
                ssn->decode_bkt = bkt;
                SetEmailDecodeState(ssn->decode_state, bkt->data, pop_eval_config->max_depth, 
                        pop_eval_config->b64_depth, pop_eval_config->qp_depth, 
                        pop_eval_config->uu_depth, pop_eval_config->bitenc_depth);
            }
            else
            {
                /*free mempool if calloc fails*/
                mempool_free(pop_mempool, bkt);
            }
        }
        else
        {
            POP_GenerateAlert(POP_MEMCAP_EXCEEDED, "%s", POP_MEMCAP_EXCEEDED_STR);
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "No memory available for decoding. Memcap exceeded \n"););
        }
    }
}

void POP_InitCmds(POPConfig *config)
{
    const POPToken *tmp;

    if (config == NULL)
        return;

    /* add one to CMD_LAST for NULL entry */
    config->cmds = (POPToken *)calloc(CMD_LAST + 1, sizeof(POPToken));
    if (config->cmds == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => failed to allocate memory for pop "
                                        "command structure\n",
                                        *(_dpd.config_file), *(_dpd.config_line));
    }

    for (tmp = &pop_known_cmds[0]; tmp->name != NULL; tmp++)
    {
        config->cmds[tmp->search_id].name_len = tmp->name_len;
        config->cmds[tmp->search_id].search_id = tmp->search_id;
        config->cmds[tmp->search_id].name = strdup(tmp->name);

        if (config->cmds[tmp->search_id].name == NULL)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => failed to allocate memory for pop "
                                            "command structure\n",
                                            *(_dpd.config_file), *(_dpd.config_line));
        }
    }

    /* initialize memory for command searches */
    config->cmd_search = (POPSearch *)calloc(CMD_LAST, sizeof(POPSearch));
    if (config->cmd_search == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => failed to allocate memory for pop "
                                        "command structure\n",
                                        *(_dpd.config_file), *(_dpd.config_line));
    }

    config->num_cmds = CMD_LAST;
}


/*
 * Initialize POP searches
 *
 * @param  none
 *
 * @return none
 */
void POP_SearchInit(void)
{
    const char *error;
    int erroffset;
    const POPToken *tmp;

    /* Response search */
    pop_resp_search_mpse = _dpd.searchAPI->search_instance_new();
    if (pop_resp_search_mpse == NULL)
    {
        DynamicPreprocessorFatalMessage("Could not allocate POP "
                                        "response search.\n");
    }

    for (tmp = &pop_resps[0]; tmp->name != NULL; tmp++)
    {
        pop_resp_search[tmp->search_id].name = tmp->name;
        pop_resp_search[tmp->search_id].name_len = tmp->name_len;

        _dpd.searchAPI->search_instance_add(pop_resp_search_mpse, tmp->name,
                                            tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_instance_prep(pop_resp_search_mpse);

    /* Header search */
    pop_hdr_search_mpse = _dpd.searchAPI->search_instance_new();
    if (pop_hdr_search_mpse == NULL)
    {
        DynamicPreprocessorFatalMessage("Could not allocate POP "
                                        "header search.\n");
    }

    for (tmp = &pop_hdrs[0]; tmp->name != NULL; tmp++)
    {
        pop_hdr_search[tmp->search_id].name = tmp->name;
        pop_hdr_search[tmp->search_id].name_len = tmp->name_len;

        _dpd.searchAPI->search_instance_add(pop_hdr_search_mpse, tmp->name,
                                            tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_instance_prep(pop_hdr_search_mpse);

    /* Data end search */
    pop_data_search_mpse = _dpd.searchAPI->search_instance_new();
    if (pop_data_search_mpse == NULL)
    {
        DynamicPreprocessorFatalMessage("Could not allocate POP "
                                        "data search.\n");
    }

    for (tmp = &pop_data_end[0]; tmp->name != NULL; tmp++)
    {
        pop_data_end_search[tmp->search_id].name = tmp->name;
        pop_data_end_search[tmp->search_id].name_len = tmp->name_len;

        _dpd.searchAPI->search_instance_add(pop_data_search_mpse, tmp->name,
                                            tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_instance_prep(pop_data_search_mpse);


    /* create regex for finding boundary string - since it can be cut across multiple
     * lines, a straight search won't do. Shouldn't be too slow since it will most
     * likely only be acting on a small portion of data */
    //"^content-type:\\s*multipart.*boundary\\s*=\\s*\"?([^\\s]+)\"?"
    //"^\\s*multipart.*boundary\\s*=\\s*\"?([^\\s]+)\"?"
    //mime_boundary_pcre.re = pcre_compile("^.*boundary\\s*=\\s*\"?([^\\s\"]+)\"?",
    //mime_boundary_pcre.re = pcre_compile("boundary(?:\n|\r\n)?=(?:\n|\r\n)?\"?([^\\s\"]+)\"?",
    mime_boundary_pcre.re = pcre_compile("boundary\\s*=\\s*\"?([^\\s\"]+)\"?",
                                          PCRE_CASELESS | PCRE_DOTALL,
                                          &error, &erroffset, NULL);
    if (mime_boundary_pcre.re == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to compile pcre regex for getting boundary "
                                        "in a multipart POP message: %s\n", error);
    }

    mime_boundary_pcre.pe = pcre_study(mime_boundary_pcre.re, 0, &error);

    if (error != NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to study pcre regex for getting boundary "
                                        "in a multipart POP message: %s\n", error);
    }
}

/*
 * Initialize run-time boundary search
 */
static int POP_BoundarySearchInit(void)
{
    if (pop_ssn->mime_boundary.boundary_search != NULL)
        _dpd.searchAPI->search_instance_free(pop_ssn->mime_boundary.boundary_search);

    pop_ssn->mime_boundary.boundary_search = _dpd.searchAPI->search_instance_new();

    if (pop_ssn->mime_boundary.boundary_search == NULL)
        return -1;

    _dpd.searchAPI->search_instance_add(pop_ssn->mime_boundary.boundary_search,
                                        pop_ssn->mime_boundary.boundary,
                                        pop_ssn->mime_boundary.boundary_len, BOUNDARY);

    _dpd.searchAPI->search_instance_prep(pop_ssn->mime_boundary.boundary_search);

    return 0;
}



/*
 * Reset POP session state
 *
 * @param  none
 *
 * @return none
 */
static void POP_ResetState(void)
{
    if (pop_ssn->mime_boundary.boundary_search != NULL)
    {
        _dpd.searchAPI->search_instance_free(pop_ssn->mime_boundary.boundary_search);
        pop_ssn->mime_boundary.boundary_search = NULL;
    }

    pop_ssn->state = STATE_UNKNOWN;
    pop_ssn->data_state = STATE_DATA_INIT;
    pop_ssn->state_flags = 0;
    ClearEmailDecodeState(pop_ssn->decode_state);
    memset(&pop_ssn->mime_boundary, 0, sizeof(POPMimeBoundary));
}


/*
 * Given a server configuration and a port number, we decide if the port is
 *  in the POP server port list.
 *
 *  @param  port       the port number to compare with the configuration
 *
 *  @return integer
 *  @retval  0 means that the port is not a server port
 *  @retval !0 means that the port is a server port
 */
int POP_IsServer(uint16_t port)
{
    if (pop_eval_config->ports[port / 8] & (1 << (port % 8)))
        return 1;

    return 0;
}

static POP * POP_GetNewSession(SFSnortPacket *p, tSfPolicyId policy_id)
{
    POP *ssn;
    POPConfig *pPolicyConfig = NULL;

    pPolicyConfig = (POPConfig *)sfPolicyUserDataGetCurrent(pop_config);

    DEBUG_WRAP(DebugMessage(DEBUG_POP, "Creating new session data structure\n"););

    ssn = (POP *)calloc(1, sizeof(POP));
    if (ssn == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate POP session data\n");
    }

    pop_ssn = ssn;
    SetPopBuffers(ssn);

    _dpd.streamAPI->set_application_data(p->stream_session_ptr, PP_POP,
                                         ssn, &POP_SessionFree);

    if (p->flags & SSNFLAG_MIDSTREAM)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_POP, "Got midstream packet - "
                                "setting state to unknown\n"););
        ssn->state = STATE_UNKNOWN;
    }

#ifdef DEBUG_MSGS
    pop_session_counter++;
    ssn->session_number = pop_session_counter;
#endif

    if (p->stream_session_ptr != NULL)
    {
        /* check to see if we're doing client reassembly in stream */
        if (_dpd.streamAPI->get_reassembly_direction(p->stream_session_ptr) & SSN_DIR_CLIENT)
            ssn->reassembling = 1;

        if(!ssn->reassembling)
        {
            _dpd.streamAPI->set_reassembly(p->stream_session_ptr,
                    STREAM_FLPOLICY_FOOTPRINT, SSN_DIR_CLIENT, STREAM_FLPOLICY_SET_ABSOLUTE);
            ssn->reassembling = 1;
        }
    }

    ssn->policy_id = policy_id;
    ssn->config = pop_config;
    pPolicyConfig->ref_count++;

    return ssn;
}


/*
 * Do first-packet setup
 *
 * @param   p   standard Packet structure
 *
 * @return  none
 */
static int POP_Setup(SFSnortPacket *p, POP *ssn)
{
    int flags = 0;
    int pkt_dir;

    if (p->stream_session_ptr != NULL)
    {
        /* set flags to session flags */
        flags = _dpd.streamAPI->get_session_flags(p->stream_session_ptr);
    }

    /* Figure out direction of packet */
    pkt_dir = POP_GetPacketDirection(p, flags);

    DEBUG_WRAP(DebugMessage(DEBUG_POP, "Session number: "STDu64"\n", ssn->session_number););

    /* Check to see if there is a reassembly gap.  If so, we won't know
     * what state we're in when we get the _next_ reassembled packet */
    if ((pkt_dir != POP_PKT_FROM_SERVER) &&
        (p->flags & FLAG_REBUILT_STREAM))
    {
        int missing_in_rebuilt =
            _dpd.streamAPI->missing_in_reassembled(p->stream_session_ptr, SSN_DIR_CLIENT);

        if (ssn->session_flags & POP_FLAG_NEXT_STATE_UNKNOWN)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "Found gap in previous reassembly buffer - "
                                    "set state to unknown\n"););
            ssn->state = STATE_UNKNOWN;
            ssn->session_flags &= ~POP_FLAG_NEXT_STATE_UNKNOWN;
        }

        if (missing_in_rebuilt == SSN_MISSING_BOTH)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "Found missing packets before and after "
                                    "in reassembly buffer - set state to unknown and "
                                    "next state to unknown\n"););
            ssn->state = STATE_UNKNOWN;
            ssn->session_flags |= POP_FLAG_NEXT_STATE_UNKNOWN;
        }
        else if (missing_in_rebuilt == SSN_MISSING_BEFORE)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "Found missing packets before "
                                    "in reassembly buffer - set state to unknown\n"););
            ssn->state = STATE_UNKNOWN;
        }
        else if (missing_in_rebuilt == SSN_MISSING_AFTER)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "Found missing packets after "
                                    "in reassembly buffer - set next state to unknown\n"););
            ssn->session_flags |= POP_FLAG_NEXT_STATE_UNKNOWN;
        }
    }

    return pkt_dir;
}

/*
 * Determine packet direction
 *
 * @param   p   standard Packet structure
 *
 * @return  none
 */
static int POP_GetPacketDirection(SFSnortPacket *p, int flags)
{
    int pkt_direction = POP_PKT_FROM_UNKNOWN;

    if (flags & SSNFLAG_MIDSTREAM)
    {
        if (POP_IsServer(p->src_port) &&
            !POP_IsServer(p->dst_port))
        {
            pkt_direction = POP_PKT_FROM_SERVER;
        }
        else if (!POP_IsServer(p->src_port) &&
                 POP_IsServer(p->dst_port))
        {
            pkt_direction = POP_PKT_FROM_CLIENT;
        }
    }
    else
    {
        if (p->flags & FLAG_FROM_SERVER)
        {
            pkt_direction = POP_PKT_FROM_SERVER;
        }
        else if (p->flags & FLAG_FROM_CLIENT)
        {
            pkt_direction = POP_PKT_FROM_CLIENT;
        }

        /* if direction is still unknown ... */
        if (pkt_direction == POP_PKT_FROM_UNKNOWN)
        {
            if (POP_IsServer(p->src_port) &&
                !POP_IsServer(p->dst_port))
            {
                pkt_direction = POP_PKT_FROM_SERVER;
            }
            else if (!POP_IsServer(p->src_port) &&
                     POP_IsServer(p->dst_port))
            {
                pkt_direction = POP_PKT_FROM_CLIENT;
            }
        }
    }

    return pkt_direction;
}


/*
 * Free POP-specific related to this session
 *
 * @param   v   pointer to POP session structure
 *
 *
 * @return  none
 */
static void POP_SessionFree(void *session_data)
{
    POP *pop = (POP *)session_data;
#ifdef SNORT_RELOAD
    POPConfig *pPolicyConfig = NULL;
#endif

    if (pop == NULL)
        return;

#ifdef SNORT_RELOAD
    pPolicyConfig = (POPConfig *)sfPolicyUserDataGet(pop->config, pop->policy_id);

    if (pPolicyConfig != NULL)
    {
        pPolicyConfig->ref_count--;
        if ((pPolicyConfig->ref_count == 0) &&
            (pop->config != pop_config))
        {
            sfPolicyUserDataClear (pop->config, pop->policy_id);
            POP_FreeConfig(pPolicyConfig);

            /* No more outstanding policies for this config */
            if (sfPolicyUserPolicyGetActive(pop->config) == 0)
                POP_FreeConfigs(pop->config);
        }
    }
#endif

    if (pop->mime_boundary.boundary_search != NULL)
    {
        _dpd.searchAPI->search_instance_free(pop->mime_boundary.boundary_search);
        pop->mime_boundary.boundary_search = NULL;
    }

    if(pop->decode_state != NULL)
    {
        mempool_free(pop_mempool, pop->decode_bkt);
        free(pop->decode_state);
    }

    free(pop);
}


static void POP_NoSessionFree(void)
{
    if (pop_no_session.mime_boundary.boundary_search != NULL)
    {
        _dpd.searchAPI->search_instance_free(pop_no_session.mime_boundary.boundary_search);
        pop_no_session.mime_boundary.boundary_search = NULL;
    }
}

static int POP_FreeConfigsPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
        )
{
    POPConfig *pPolicyConfig = (POPConfig *)pData;

    //do any housekeeping before freeing POPConfig
    sfPolicyUserDataClear (config, policyId);
    POP_FreeConfig(pPolicyConfig);

    return 0;
}

void POP_FreeConfigs(tSfPolicyUserContextId config)
{
    if (config == NULL)
        return;

    sfPolicyUserDataIterate (config, POP_FreeConfigsPolicy);
    sfPolicyConfigDelete(config);
}

void POP_FreeConfig(POPConfig *config)
{
    if (config == NULL)
        return;

    if (config->cmds != NULL)
    {
        POPToken *tmp = config->cmds;

        for (; tmp->name != NULL; tmp++)
            free(tmp->name);

        free(config->cmds);
    }

    if (config->cmd_search_mpse != NULL)
        _dpd.searchAPI->search_instance_free(config->cmd_search_mpse);

    if (config->cmd_search != NULL)
        free(config->cmd_search);

    free(config);
}


/*
 * Free anything that needs it before shutting down preprocessor
 *
 * @param   none
 *
 * @return  none
 */
void POP_Free(void)
{
    POP_NoSessionFree();

    POP_FreeConfigs(pop_config);
    pop_config = NULL;

    if (pop_resp_search_mpse != NULL)
        _dpd.searchAPI->search_instance_free(pop_resp_search_mpse);

    if (pop_hdr_search_mpse != NULL)
        _dpd.searchAPI->search_instance_free(pop_hdr_search_mpse);

    if (pop_data_search_mpse != NULL)
        _dpd.searchAPI->search_instance_free(pop_data_search_mpse);

    if (mime_boundary_pcre.re )
        pcre_free(mime_boundary_pcre.re);

    if (mime_boundary_pcre.pe )
        pcre_free(mime_boundary_pcre.pe);
}


/*
 * Callback function for string search
 *
 * @param   id      id in array of search strings from pop_config.cmds
 * @param   index   index in array of search strings from pop_config.cmds
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
static int POP_SearchStrFound(void *id, void *unused, int index, void *data, void *unused2)
{
    int search_id = (int)(uintptr_t)id;

    pop_search_info.id = search_id;
    pop_search_info.index = index;
    pop_search_info.length = pop_current_search[search_id].name_len;

    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}


/*
 * Callback function for boundary search
 *
 * @param   id      id in array of search strings
 * @param   index   index in array of search strings
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
static int POP_BoundaryStrFound(void *id, void *unused, int index, void *data, void *unused2)
{
    int boundary_id = (int)(uintptr_t)id;

    pop_search_info.id = boundary_id;
    pop_search_info.index = index;
    pop_search_info.length = pop_ssn->mime_boundary.boundary_len;

    return 1;
}

static int POP_GetBoundary(const char *data, int data_len)
{
    int result;
    int ovector[9];
    int ovecsize = 9;
    const char *boundary;
    int boundary_len;
    int ret;
    char *mime_boundary;
    int  *mime_boundary_len;


    mime_boundary = &pop_ssn->mime_boundary.boundary[0];
    mime_boundary_len = &pop_ssn->mime_boundary.boundary_len;

    /* result will be the number of matches (including submatches) */
    result = pcre_exec(mime_boundary_pcre.re, mime_boundary_pcre.pe,
                       data, data_len, 0, 0, ovector, ovecsize);
    if (result < 0)
        return -1;

    result = pcre_get_substring(data, ovector, result, 1, &boundary);
    if (result < 0)
        return -1;

    boundary_len = strlen(boundary);
    if (boundary_len > MAX_BOUNDARY_LEN)
    {
        /* XXX should we alert? breaking the law of RFC */
        boundary_len = MAX_BOUNDARY_LEN;
    }

    mime_boundary[0] = '-';
    mime_boundary[1] = '-';
    ret = SafeMemcpy(mime_boundary + 2, boundary, boundary_len,
                     mime_boundary + 2, mime_boundary + 2 + MAX_BOUNDARY_LEN);

    pcre_free_substring(boundary);

    if (ret != SAFEMEM_SUCCESS)
    {
        return -1;
    }

    *mime_boundary_len = 2 + boundary_len;
    mime_boundary[*mime_boundary_len] = '\0';

    return 0;
}


/*
 * Handle COMMAND state
 *
 * @param   p       standard Packet structure
 * @param   ptr     pointer into p->payload buffer to start looking at data
 * @param   end     points to end of p->payload buffer
 *
 * @return          pointer into p->payload where we stopped looking at data
 *                  will be end of line or end of packet
 */
static const uint8_t * POP_HandleCommand(SFSnortPacket *p, const uint8_t *ptr, const uint8_t *end)
{
    const uint8_t *eol;   /* end of line */
    const uint8_t *eolm;  /* end of line marker */
    int cmd_line_len;
    int cmd_found;

    /* get end of line and end of line marker */
    POP_GetEOL(ptr, end, &eol, &eolm);

    /* calculate length of command line */
    cmd_line_len = eol - ptr;

    /* TODO If the end of line marker coincides with the end of payload we can't be
     * sure that we got a command and not a substring which we could tell through
     * inspection of the next packet. Maybe a command pending state where the first
     * char in the next packet is checked for a space and end of line marker */

    /* do not confine since there could be space chars before command */
    pop_current_search = &pop_eval_config->cmd_search[0];
    cmd_found = _dpd.searchAPI->search_instance_find
        (pop_eval_config->cmd_search_mpse, (const char *)ptr,
         eolm - ptr, 0, POP_SearchStrFound);

    /* see if we actually found a command and not a substring */
    if (cmd_found > 0)
    {
        const uint8_t *tmp = ptr;
        const uint8_t *cmd_start = ptr + pop_search_info.index;
        const uint8_t *cmd_end = cmd_start + pop_search_info.length;

        /* move past spaces up until start of command */
        while ((tmp < cmd_start) && isspace((int)*tmp))
            tmp++;

        /* if not all spaces before command, we found a
         * substring */
        if (tmp != cmd_start)
            cmd_found = 0;

        /* if we're before the end of line marker and the next
         * character is not whitespace, we found a substring */
        if ((cmd_end < eolm) && !isspace((int)*cmd_end))
            cmd_found = 0;

        /* there is a chance that end of command coincides with the end of payload
         * in which case, it could be a substring, but for now, we will treat it as found */
    }

    /* if command not found, alert and move on */
    if (!cmd_found)
    {
        POP_GenerateAlert(POP_UNKNOWN_CMD, "%s", POP_UNKNOWN_CMD_STR);
        DEBUG_WRAP(DebugMessage(DEBUG_POP, "No known command found\n"););

        return eol;
    }

    /* At this point we have definitely found a legitimate command */

    DEBUG_WRAP(DebugMessage(DEBUG_POP, "%s\n", pop_eval_config->cmds[pop_search_info.id].name););

/*    switch (pop_search_info.id)
    {
        case CMD_USER:
        case CMD_PASS:
        case CMD_RSET:
        case CMD_QUIT:
        case CMD_RETR:
            break;

        default:
            break;
    }*/

    return eol;
}


static const uint8_t * POP_HandleData(SFSnortPacket *p, const uint8_t *ptr, const uint8_t *end)
{
    const uint8_t *data_end_marker = NULL;
    const uint8_t *data_end = NULL;
    int data_end_found;

    /* if we've just entered the data state, check for a dot + end of line
     * if found, no data */
    if ((pop_ssn->data_state == STATE_DATA_INIT) ||
        (pop_ssn->data_state == STATE_DATA_UNKNOWN))
    {
        if ((ptr < end) && (*ptr == '.'))
        {
            const uint8_t *eol = NULL;
            const uint8_t *eolm = NULL;

            POP_GetEOL(ptr, end, &eol, &eolm);

            /* this means we got a real end of line and not just end of payload
             * and that the dot is only char on line */
            if ((eolm != end) && (eolm == (ptr + 1)))
            {
                /* if we're normalizing and not ignoring data copy data end marker
                 * and dot to alt buffer */

                POP_ResetState();

                return eol;
            }
        }

        if (pop_ssn->data_state == STATE_DATA_INIT)
            pop_ssn->data_state = STATE_DATA_HEADER;

        /* XXX A line starting with a '.' that isn't followed by a '.' is
         * deleted (RFC 821 - 4.5.2.  TRANSPARENCY).  If data starts with
         * '. text', i.e a dot followed by white space then text, some
         * servers consider it data header and some data body.
         * Postfix and Qmail will consider the start of data:
         * . text\r\n
         * .  text\r\n
         * to be part of the header and the effect will be that of a
         * folded line with the '.' deleted.  Exchange will put the same
         * in the body which seems more reasonable. */
    }

    /* get end of data body
     * TODO check last bytes of previous packet to see if we had a partial
     * end of data */
    pop_current_search = &pop_data_end_search[0];
    data_end_found = _dpd.searchAPI->search_instance_find
        (pop_data_search_mpse, (const char *)ptr, end - ptr,
         0, POP_SearchStrFound);

    if (data_end_found > 0)
    {
        data_end_marker = ptr + pop_search_info.index;
        data_end = data_end_marker + pop_search_info.length;
    }
    else
    {
        data_end_marker = data_end = end;
    }

    _dpd.setFileDataPtr((uint8_t*)ptr, data_end - ptr);

    if ((pop_ssn->data_state == STATE_DATA_HEADER) ||
        (pop_ssn->data_state == STATE_DATA_UNKNOWN))
    {
#ifdef DEBUG_MSGS
        if (pop_ssn->data_state == STATE_DATA_HEADER)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "DATA HEADER STATE ~~~~~~~~~~~~~~~~~~~~~~\n"););
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "DATA UNKNOWN STATE ~~~~~~~~~~~~~~~~~~~~~\n"););
        }
#endif

        ptr = POP_HandleHeader(p, ptr, data_end_marker);
        if (ptr == NULL)
            return NULL;

    }

    /* now we shouldn't have to worry about copying any data to the alt buffer
     * only mime headers if we find them and only if we're ignoring data */

    while ((ptr != NULL) && (ptr < data_end_marker))
    {
        /* multiple MIME attachments in one single packet.
         * Pipeline the MIME decoded data.*/
        if ( pop_ssn->state_flags & POP_FLAG_MULTIPLE_EMAIL_ATTACH)
        {
            _dpd.setFileDataPtr(pop_ssn->decode_state->decodePtr, pop_ssn->decode_state->decoded_bytes);
            _dpd.detect(p);
            pop_ssn->state_flags &= ~POP_FLAG_MULTIPLE_EMAIL_ATTACH;
            ResetEmailDecodeState(pop_ssn->decode_state);
            p->flags |=FLAG_ALLOW_MULTIPLE_DETECT;
            /* Reset the log count when a packet goes through detection multiple times */
            p->log_func_count = 0;
            _dpd.DetectReset((uint8_t *)p->payload, p->payload_size);
        }
        switch (pop_ssn->data_state)
        {
            case STATE_MIME_HEADER:
                DEBUG_WRAP(DebugMessage(DEBUG_POP, "MIME HEADER STATE ~~~~~~~~~~~~~~~~~~~~~~\n"););
                ptr = POP_HandleHeader(p, ptr, data_end_marker);
                break;
            case STATE_DATA_BODY:
                DEBUG_WRAP(DebugMessage(DEBUG_POP, "DATA BODY STATE ~~~~~~~~~~~~~~~~~~~~~~~~\n"););
                ptr = POP_HandleDataBody(p, ptr, data_end_marker);
                break;
        }
    }

    /* We have either reached the end of MIME header or end of MIME encoded data*/

    if(pop_ssn->decode_state != NULL)
    {
        _dpd.setFileDataPtr(pop_ssn->decode_state->decodePtr, pop_ssn->decode_state->decoded_bytes);
        ResetDecodedBytes(pop_ssn->decode_state);
    }

    /* if we got the data end reset state, otherwise we're probably still in the data
     * to expect more data in next packet */
    if (data_end_marker != end)
    {
        POP_ResetState();
    }

    return data_end;
}


/*
 * Handle Headers - Data or Mime
 *
 * @param   packet  standard Packet structure
 *
 * @param   i       index into p->payload buffer to start looking at data
 *
 * @return  i       index into p->payload where we stopped looking at data
 */
static const uint8_t * POP_HandleHeader(SFSnortPacket *p, const uint8_t *ptr,
                                          const uint8_t *data_end_marker)
{
    const uint8_t *eol;
    const uint8_t *eolm;
    const uint8_t *colon;
    const uint8_t *content_type_ptr = NULL;
    const uint8_t *cont_trans_enc = NULL;
    int header_found;
    int ret;
    const uint8_t *start_hdr;

    start_hdr = ptr;

    /* if we got a content-type in a previous packet and are
     * folding, the boundary still needs to be checked for */
    if (pop_ssn->state_flags & POP_FLAG_IN_CONTENT_TYPE)
        content_type_ptr = ptr;

    if (pop_ssn->state_flags & POP_FLAG_IN_CONT_TRANS_ENC)
        cont_trans_enc = ptr;

    while (ptr < data_end_marker)
    {
        POP_GetEOL(ptr, data_end_marker, &eol, &eolm);

        /* got a line with only end of line marker should signify end of header */
        if (eolm == ptr)
        {
            /* reset global header state values */
            pop_ssn->state_flags &=
                ~(POP_FLAG_FOLDING | POP_FLAG_IN_CONTENT_TYPE | POP_FLAG_DATA_HEADER_CONT
                        | POP_FLAG_IN_CONT_TRANS_ENC );

            pop_ssn->data_state = STATE_DATA_BODY;

            /* if no headers, treat as data */
            if (ptr == start_hdr)
                return eolm;
            else
                return eol;
        }

        /* if we're not folding, see if we should interpret line as a data line
         * instead of a header line */
        if (!(pop_ssn->state_flags & (POP_FLAG_FOLDING | POP_FLAG_DATA_HEADER_CONT)))
        {
            char got_non_printable_in_header_name = 0;

            /* if we're not folding and the first char is a space or
             * colon, it's not a header */
            if (isspace((int)*ptr) || *ptr == ':')
            {
                pop_ssn->data_state = STATE_DATA_BODY;
                return ptr;
            }

            /* look for header field colon - if we're not folding then we need
             * to find a header which will be all printables (except colon)
             * followed by a colon */
            colon = ptr;
            while ((colon < eolm) && (*colon != ':'))
            {
                if (((int)*colon < 33) || ((int)*colon > 126))
                    got_non_printable_in_header_name = 1;

                colon++;
            }

            /* If the end on line marker and end of line are the same, assume
             * header was truncated, so stay in data header state */
            if ((eolm != eol) &&
                ((colon == eolm) || got_non_printable_in_header_name))
            {
                /* no colon or got spaces in header name (won't be interpreted as a header)
                 * assume we're in the body */
                pop_ssn->state_flags &=
                    ~(POP_FLAG_FOLDING | POP_FLAG_IN_CONTENT_TYPE | POP_FLAG_DATA_HEADER_CONT 
                            |POP_FLAG_IN_CONT_TRANS_ENC);

                pop_ssn->data_state = STATE_DATA_BODY;

                return ptr;
            }

            if(tolower((int)*ptr) == 'c')
            {
                pop_current_search = &pop_hdr_search[0];
                header_found = _dpd.searchAPI->search_instance_find
                    (pop_hdr_search_mpse, (const char *)ptr,
                     eolm - ptr, 1, POP_SearchStrFound);

                /* Headers must start at beginning of line */
                if ((header_found > 0) && (pop_search_info.index == 0))
                {
                    switch (pop_search_info.id)
                    {
                        case HDR_CONTENT_TYPE:
                            /* for now we're just looking for the boundary in the data
                             * header section */
                            if (pop_ssn->data_state != STATE_MIME_HEADER)
                            {
                                content_type_ptr = ptr + pop_search_info.length;
                                pop_ssn->state_flags |= POP_FLAG_IN_CONTENT_TYPE;
                            }

                            break;
                        case HDR_CONT_TRANS_ENC:
                            cont_trans_enc = ptr + pop_search_info.length;
                            pop_ssn->state_flags |= POP_FLAG_IN_CONT_TRANS_ENC;
                            break;

                        default:
                            break;
                    }
                }
            }
            else if(tolower((int)*ptr) == 'e')
            {
                if((eolm - ptr) >= 9)
                {
                    if(strncasecmp((const char *)ptr, "Encoding:", 9) == 0)
                    {
                        cont_trans_enc = ptr + 9;
                        pop_ssn->state_flags |= POP_FLAG_IN_CONT_TRANS_ENC;
                    }
                }
            }
        }
        else
        {
            pop_ssn->state_flags &= ~POP_FLAG_DATA_HEADER_CONT;
        }


        /* check for folding 
         * if char on next line is a space and not \n or \r\n, we are folding */
        if ((eol < data_end_marker) && isspace((int)eol[0]) && (eol[0] != '\n'))
        {
            if ((eol < (data_end_marker - 1)) && (eol[0] != '\r') && (eol[1] != '\n'))
            {
                pop_ssn->state_flags |= POP_FLAG_FOLDING;
            }
            else
            {
                pop_ssn->state_flags &= ~POP_FLAG_FOLDING;
            }
        }
        else if (eol != eolm)
        {
            pop_ssn->state_flags &= ~POP_FLAG_FOLDING;
        }

        /* check if we're in a content-type header and not folding. if so we have the whole
         * header line/lines for content-type - see if we got a multipart with boundary
         * we don't check each folded line, but wait until we have the complete header
         * because boundary=BOUNDARY can be split across mulitple folded lines before
         * or after the '=' */
        if ((pop_ssn->state_flags &
             (POP_FLAG_IN_CONTENT_TYPE | POP_FLAG_FOLDING)) == POP_FLAG_IN_CONTENT_TYPE)
        {
            /* we got the full content-type header - look for boundary string */
            ret = POP_GetBoundary((const char *)content_type_ptr, eolm - content_type_ptr);
            if (ret != -1)
            {
                ret = POP_BoundarySearchInit();
                if (ret != -1)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_POP, "Got mime boundary: %s\n",
                                                         pop_ssn->mime_boundary.boundary););

                    pop_ssn->state_flags |= POP_FLAG_GOT_BOUNDARY;
                }
            }

            pop_ssn->state_flags &= ~POP_FLAG_IN_CONTENT_TYPE;
            content_type_ptr = NULL;
        }
        else if ((pop_ssn->state_flags &
                (POP_FLAG_IN_CONT_TRANS_ENC | POP_FLAG_FOLDING)) == POP_FLAG_IN_CONT_TRANS_ENC)
        {
            /* Check for Content-Transfer-Encoding : */
            if( (!POP_IsDecodingEnabled(pop_eval_config)) && (pop_ssn->decode_state != NULL))
            {
                POP_DecodeType((const char *)cont_trans_enc, eolm - cont_trans_enc );
                pop_ssn->state_flags |= POP_FLAG_EMAIL_ATTACH;
                /* check to see if there are other attachments in this packet */
                if( pop_ssn->decode_state->decoded_bytes )
                    pop_ssn->state_flags |= POP_FLAG_MULTIPLE_EMAIL_ATTACH;
            }
            pop_ssn->state_flags &= ~POP_FLAG_IN_CONT_TRANS_ENC;

            cont_trans_enc = NULL;
        }

        /* if state was unknown, at this point assume we know */
        if (pop_ssn->data_state == STATE_DATA_UNKNOWN)
            pop_ssn->data_state = STATE_DATA_HEADER;

        ptr = eol;

        if (ptr == data_end_marker)
            pop_ssn->state_flags |= POP_FLAG_DATA_HEADER_CONT;
    }

    return ptr;
}


/*
 * Handle DATA_BODY state
 *
 * @param   packet  standard Packet structure
 *
 * @param   i       index into p->payload buffer to start looking at data
 *
 * @return  i       index into p->payload where we stopped looking at data
 */
static const uint8_t * POP_HandleDataBody(SFSnortPacket *p, const uint8_t *ptr,
                                            const uint8_t *data_end_marker)
{
    int boundary_found = 0;
    const uint8_t *boundary_ptr = NULL;
    const uint8_t *attach_start = NULL;
    const uint8_t *attach_end = NULL;

    if ( pop_ssn->state_flags & POP_FLAG_EMAIL_ATTACH )
        attach_start = ptr;
    /* look for boundary */
    if (pop_ssn->state_flags & POP_FLAG_GOT_BOUNDARY)
    {
        boundary_found = _dpd.searchAPI->search_instance_find
            (pop_ssn->mime_boundary.boundary_search, (const char *)ptr,
             data_end_marker - ptr, 0, POP_BoundaryStrFound);

        if (boundary_found > 0)
        {
            boundary_ptr = ptr + pop_search_info.index;

            /* should start at beginning of line */
            if ((boundary_ptr == ptr) || (*(boundary_ptr - 1) == '\n'))
            {
                const uint8_t *eol;
                const uint8_t *eolm;
                const uint8_t *tmp;

                if (pop_ssn->state_flags & POP_FLAG_EMAIL_ATTACH )
                {
                    attach_end = boundary_ptr-1;
                    pop_ssn->state_flags &= ~POP_FLAG_EMAIL_ATTACH;
                    if(attach_start < attach_end)
                    {
                        if(EmailDecode( attach_start, attach_end, pop_ssn->decode_state) != DECODE_SUCCESS )
                        {
                            POP_DecodeAlert();
                        }
                    }
                }


                /* Check for end boundary */
                tmp = boundary_ptr + pop_search_info.length;
                if (((tmp + 1) < data_end_marker) && (tmp[0] == '-') && (tmp[1] == '-'))
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_POP, "Mime boundary end found: %s--\n",
                                            (char *)pop_ssn->mime_boundary.boundary););

                    /* no more MIME */
                    pop_ssn->state_flags &= ~POP_FLAG_GOT_BOUNDARY;

                    /* free boundary search */
                    _dpd.searchAPI->search_instance_free(pop_ssn->mime_boundary.boundary_search);
                    pop_ssn->mime_boundary.boundary_search = NULL;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_POP, "Mime boundary found: %s\n",
                                            (char *)pop_ssn->mime_boundary.boundary););

                    pop_ssn->data_state = STATE_MIME_HEADER;
                }

                /* get end of line - there could be spaces after boundary before eol */
                POP_GetEOL(boundary_ptr + pop_search_info.length, data_end_marker, &eol, &eolm);

                return eol;
            }
        }
    }

    if ( pop_ssn->state_flags & POP_FLAG_EMAIL_ATTACH )
    {
        attach_end = data_end_marker;
        if(attach_start < attach_end)
        {
            if(EmailDecode( attach_start, attach_end, pop_ssn->decode_state) != DECODE_SUCCESS )
            {
                POP_DecodeAlert();
            }
        }
    }

    return data_end_marker;
}


/*
 * Process client packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  none
 */
static void POP_ProcessClientPacket(SFSnortPacket *p)
{
    const uint8_t *ptr = p->payload;
    const uint8_t *end = p->payload + p->payload_size;

    ptr = POP_HandleCommand(p, ptr, end);


}



/*
 * Process server packet
 *
 * @param   packet  standard Packet structure
 *
 */
static void POP_ProcessServerPacket(SFSnortPacket *p)
{
    int resp_found;
    const uint8_t *ptr;
    const uint8_t *end;
    const uint8_t *eolm;
    const uint8_t *eol;
    int resp_line_len;
    const char *tmp = NULL;

    ptr = p->payload;
    end = p->payload + p->payload_size;

    while (ptr < end)
    {
        if(pop_ssn->state == STATE_DATA)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "DATA STATE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"););
            ptr = POP_HandleData(p, ptr, end);
            continue;
        }
        POP_GetEOL(ptr, end, &eol, &eolm);

        resp_line_len = eol - ptr;

        /* Check for response code */
        pop_current_search = &pop_resp_search[0];
        resp_found = _dpd.searchAPI->search_instance_find
            (pop_resp_search_mpse, (const char *)ptr,
             resp_line_len, 1, POP_SearchStrFound);

        if (resp_found > 0)
        {
            const uint8_t *cmd_start = ptr + pop_search_info.index;
            switch (pop_search_info.id)
            {
                case RESP_OK:
                    tmp = _dpd.SnortStrcasestr((const char *)cmd_start, (eol - cmd_start), "octets");
                    if(tmp != NULL)
                        pop_ssn->state = STATE_DATA;
                    else
                        pop_ssn->state = STATE_UNKNOWN;
                    break;

                default:
                    break;
            }

        }
        else
        {
            if(*ptr == '+' )
            {
                POP_GenerateAlert(POP_UNKNOWN_RESP, "%s", POP_UNKNOWN_RESP_STR);
                DEBUG_WRAP(DebugMessage(DEBUG_POP, "Server response not found\n"););
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_POP, "Server response description\n"););
            }

        }

        ptr = eol;

    }

    return;
}

/* For Target based
 * If a protocol for the session is already identified and not one POP is
 * interested in, POP should leave it alone and return without processing.
 * If a protocol for the session is already identified and is one that POP is
 * interested in, decode it.
 * If the protocol for the session is not already identified and the preprocessor
 * is configured to detect on one of the packet ports, detect.
 * Returns 0 if we should not inspect
 *         1 if we should continue to inspect
 */
static int POP_Inspect(SFSnortPacket *p)
{
#ifdef TARGET_BASED
    /* POP could be configured to be stateless.  If stream isn't configured, assume app id
     * will never be set and just base inspection on configuration */
    if (p->stream_session_ptr == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP: Target-based: No stream session.\n"););

        if ((POP_IsServer(p->src_port) && (p->flags & FLAG_FROM_SERVER)) ||
            (POP_IsServer(p->dst_port) && (p->flags & FLAG_FROM_CLIENT)))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP: Target-based: Configured for this "
                                    "traffic, so let's inspect.\n"););
            return 1;
        }
    }
    else
    {
        int16_t app_id = _dpd.streamAPI->get_application_protocol_id(p->stream_session_ptr);

        if (app_id != 0)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP: Target-based: App id: %u.\n", app_id););

            if (app_id == pop_proto_id)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP: Target-based: App id is "
                                        "set to \"%s\".\n", POP_PROTO_REF_STR););
                return 1;
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP: Target-based: Unknown protocol for "
                                    "this session.  See if we're configured.\n"););

            if ((POP_IsServer(p->src_port) && (p->flags & FLAG_FROM_SERVER)) ||
                (POP_IsServer(p->dst_port) && (p->flags & FLAG_FROM_CLIENT)))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP: Target-based: POP port is configured."););
                return 1;
            }
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_POP,"POP: Target-based: Not inspecting ...\n"););

#else
    /* Make sure it's traffic we're interested in */
    if ((POP_IsServer(p->src_port) && (p->flags & FLAG_FROM_SERVER)) ||
        (POP_IsServer(p->dst_port) && (p->flags & FLAG_FROM_CLIENT)))
        return 1;

#endif  /* TARGET_BASED */

    return 0;
}

/*
 * Entry point to snort preprocessor for each packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  none
 */
void SnortPOP(SFSnortPacket *p)
{
    int detected = 0;
    int pkt_dir;
    tSfPolicyId policy_id = _dpd.getRuntimePolicy();

    PROFILE_VARS;


    pop_ssn = (POP *)_dpd.streamAPI->get_application_data(p->stream_session_ptr, PP_POP);
    if (pop_ssn != NULL)
        pop_eval_config = (POPConfig *)sfPolicyUserDataGet(pop_ssn->config, pop_ssn->policy_id);
    else
        pop_eval_config = (POPConfig *)sfPolicyUserDataGetCurrent(pop_config);

    if (pop_eval_config == NULL)
        return;

    if (pop_ssn == NULL)
    {
        if (!POP_Inspect(p))
            return;

        pop_ssn = POP_GetNewSession(p, policy_id);
        if (pop_ssn == NULL)
            return;
    }

    pkt_dir = POP_Setup(p, pop_ssn);

    if (pkt_dir == POP_PKT_FROM_CLIENT)
    {
        POP_ProcessClientPacket(p);
        DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP client packet\n"););
    }
    else
    {
#ifdef DEBUG_MSGS
        if (pkt_dir == POP_PKT_FROM_SERVER)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP server packet\n"););
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP packet NOT from client or server! "
                        "Processing as a server packet\n"););
        }
#endif

        if (p->flags & FLAG_STREAM_INSERT)
        {
            /* Packet will be rebuilt, so wait for it */
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "Client packet will be reassembled\n"));
            return;
        }
        else if (pop_ssn->reassembling && !(p->flags & FLAG_REBUILT_STREAM))
        {
            /* If this isn't a reassembled packet and didn't get
             * inserted into reassembly buffer, there could be a
             * problem.  If we miss syn or syn-ack that had window
             * scaling this packet might not have gotten inserted
             * into reassembly buffer because it fell outside of
             * window, because we aren't scaling it */
            pop_ssn->session_flags |= POP_FLAG_GOT_NON_REBUILT;
            pop_ssn->state = STATE_UNKNOWN;
        }
        else if (pop_ssn->reassembling && (pop_ssn->session_flags & POP_FLAG_GOT_NON_REBUILT))
        {
            /* This is a rebuilt packet.  If we got previous packets
             * that were not rebuilt, state is going to be messed up
             * so set state to unknown. It's likely this was the
             * beginning of the conversation so reset state */
            DEBUG_WRAP(DebugMessage(DEBUG_POP, "Got non-rebuilt packets before "
                "this rebuilt packet\n"););

            pop_ssn->state = STATE_UNKNOWN;
            pop_ssn->session_flags &= ~POP_FLAG_GOT_NON_REBUILT;
        }
        /* Process as a server packet */
        POP_ProcessServerPacket(p);
    }


    PREPROC_PROFILE_START(popDetectPerfStats);
    
    detected = _dpd.detect(p);

#ifdef PERF_PROFILING
    popDetectCalled = 1;
#endif

    PREPROC_PROFILE_END(popDetectPerfStats);

    /* Turn off detection since we've already done it. */
    POP_DisableDetect(p);

    if (detected)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP vulnerability detected\n"););
    }
}

static void POP_DisableDetect(SFSnortPacket *p)
{
    _dpd.disableAllDetect(p);

    _dpd.setPreprocBit(p, PP_SFPORTSCAN);
    _dpd.setPreprocBit(p, PP_PERFMONITOR);
    _dpd.setPreprocBit(p, PP_STREAM5);
    _dpd.setPreprocBit(p, PP_SDF);
}


