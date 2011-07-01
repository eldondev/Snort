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
 * snort_imap.c
 *
 * Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>
 *
 * Description:
 *
 * This file handles IMAP protocol checking and normalization.
 *
 * Entry point functions:
 *
 *     SnortIMAP()
 *     IMAP_Init()
 *     IMAP_Free()
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

#include "snort_imap.h"
#include "imap_config.h"
#include "imap_util.h"
#include "imap_log.h"

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
extern PreprocStats imapDetectPerfStats;
extern int imapDetectCalled;
#endif

extern tSfPolicyUserContextId imap_config;
extern IMAPConfig *imap_eval_config;
extern MemPool *imap_mempool;

#ifdef DEBUG_MSGS
extern char imap_print_buffer[];
#endif

/**************************************************************************/


/* Globals ****************************************************************/

const IMAPToken imap_known_cmds[] =
{
    {"APPEND",          6, CMD_APPEND},
    {"AUTHENTICATE",    12, CMD_AUTHENTICATE},
    {"CAPABILITY",      10, CMD_CAPABILITY},
    {"CHECK",           5, CMD_CHECK},
    {"CLOSE",           5, CMD_CLOSE},
    {"COMPARATOR",      10, CMD_COMPARATOR},
    {"COMPRESS",        8, CMD_COMPRESS},
    {"CONVERSIONS",     11, CMD_CONVERSIONS},
    {"COPY",            4, CMD_COPY},
    {"CREATE",          6, CMD_CREATE},
    {"DELETE",          6, CMD_DELETE},
    {"DELETEACL",       9, CMD_DELETEACL},
    {"DONE",            4, CMD_DONE},
    {"EXAMINE",         7, CMD_EXAMINE},
    {"EXPUNGE",         7, CMD_EXPUNGE},
    {"FETCH",           5, CMD_FETCH},
    {"GETACL",          6, CMD_GETACL},
    {"GETMETADATA",     11, CMD_GETMETADATA},
    {"GETQUOTA",        8, CMD_GETQUOTA},
    {"GETQUOTAROOT",    12, CMD_GETQUOTAROOT},
    {"IDLE",            4, CMD_IDLE},
    {"LIST",            4, CMD_LIST},
    {"LISTRIGHTS",      10, CMD_LISTRIGHTS},
    {"LOGIN",           5, CMD_LOGIN},
    {"LOGOUT",          6, CMD_LOGOUT},
    {"LSUB",            4, CMD_LSUB},
    {"MYRIGHTS",        8, CMD_MYRIGHTS},
    {"NOOP",            4, CMD_NOOP},
    {"NOTIFY",          6, CMD_NOTIFY},
    {"RENAME",          6, CMD_RENAME},
    {"SEARCH",          6, CMD_SEARCH},
    {"SELECT",          6, CMD_SELECT},
    {"SETACL",          6, CMD_SETACL},
    {"SETMETADATA",     11, CMD_SETMETADATA},
    {"SETQUOTA",        8, CMD_SETQUOTA},
    {"SORT",            4, CMD_SORT},
    {"STARTTLS",        8, CMD_STARTTLS},
    {"STATUS",          6, CMD_STATUS},
    {"STORE",           5, CMD_STORE},
    {"SUBSCRIBE",       9, CMD_SUBSCRIBE},
    {"THREAD",          6, CMD_THREAD},
    {"UID",             3, CMD_UID},
    {"UNSELECT",        8, CMD_UNSELECT},
    {"UNSUBSCRIBE",     11, CMD_UNSUBSCRIBE},
    {"X",               1, CMD_X},
    {NULL,              0, 0}
};

const IMAPToken imap_resps[] =
{
    {"CAPABILITY",      10, RESP_CAPABILITY},
    {"LIST",            4, RESP_LIST},
    {"LSUB",            4, RESP_LSUB},
    {"STATUS",          6, RESP_STATUS},
    {"SEARCH",          6, RESP_SEARCH},
    {"FLAGS",           5, RESP_FLAGS},
    {"EXISTS",          6, RESP_EXISTS},
    {"RECENT",          6, RESP_RECENT},
    {"EXPUNGE",         7, RESP_EXPUNGE},
    {"FETCH",           5, RESP_FETCH},
	{"BAD",             3, RESP_BAD},  
	{"BYE",             3, RESP_BYE},
	{"NO",              2, RESP_NO},
	{"OK",              2, RESP_OK},
	{"PREAUTH",         7, RESP_PREAUTH},
	{"ENVELOPE",        8, RESP_ENVELOPE},
	{"UID",             3, RESP_UID},
	{NULL,              0, 0}
};

const IMAPToken imap_hdrs[] =
{
    {"Content-type:", 13, HDR_CONTENT_TYPE},
    {"Content-Transfer-Encoding:", 26, HDR_CONT_TRANS_ENC},
    {NULL,             0, 0}
};

const IMAPToken imap_data_end[] =
{
	{"\r\n.\r\n",  5,  DATA_END_1},
	{"\n.\r\n",    4,  DATA_END_2},
	{"\r\n.\n",    4,  DATA_END_3},
	{"\n.\n",      3,  DATA_END_4},
	{NULL,         0,  0}
};

IMAP *imap_ssn = NULL;
IMAP imap_no_session;
IMAPPcre mime_boundary_pcre;
char imap_normalizing;
IMAPSearchInfo imap_search_info;

#ifdef DEBUG_MSGS
uint64_t imap_session_counter = 0;
#endif

#ifdef TARGET_BASED
int16_t imap_proto_id;
#endif

void *imap_resp_search_mpse = NULL;
IMAPSearch imap_resp_search[RESP_LAST];

void *imap_hdr_search_mpse = NULL;
IMAPSearch imap_hdr_search[HDR_LAST];

void *imap_data_search_mpse = NULL;
IMAPSearch imap_data_end_search[DATA_END_LAST];

IMAPSearch *imap_current_search = NULL;


/**************************************************************************/


/* Private functions ******************************************************/

static int IMAP_Setup(SFSnortPacket *p, IMAP *ssn);
static void IMAP_ResetState(void);
static void IMAP_SessionFree(void *);
static void IMAP_NoSessionFree(void);
static int IMAP_GetPacketDirection(SFSnortPacket *, int);
static void IMAP_ProcessClientPacket(SFSnortPacket *);
static void IMAP_ProcessServerPacket(SFSnortPacket *);
static void IMAP_DisableDetect(SFSnortPacket *);
static const uint8_t * IMAP_HandleCommand(SFSnortPacket *, const uint8_t *, const uint8_t *);
static const uint8_t * IMAP_HandleData(SFSnortPacket *, const uint8_t *, const uint8_t *);
static const uint8_t * IMAP_HandleHeader(SFSnortPacket *, const uint8_t *, const uint8_t *);
static const uint8_t * IMAP_HandleDataBody(SFSnortPacket *, const uint8_t *, const uint8_t *);
static int IMAP_SearchStrFound(void *, void *, int, void *, void *);

static int IMAP_BoundaryStrFound(void *, void *, int , void *, void *);
static int IMAP_GetBoundary(const char *, int);

static int IMAP_Inspect(SFSnortPacket *);

/**************************************************************************/

static void SetImapBuffers(IMAP *ssn)
{
    if ((ssn != NULL) && (ssn->decode_state == NULL)
            && (!IMAP_IsDecodingEnabled(imap_eval_config)))
    {
        MemBucket *bkt = mempool_alloc(imap_mempool);

        if (bkt != NULL)
        {
            ssn->decode_state = (Email_DecodeState *)calloc(1, sizeof(Email_DecodeState));
            if( ssn->decode_state != NULL )
            {
                ssn->decode_bkt = bkt;
                SetEmailDecodeState(ssn->decode_state, bkt->data, imap_eval_config->max_depth, 
                        imap_eval_config->b64_depth, imap_eval_config->qp_depth, 
                        imap_eval_config->uu_depth, imap_eval_config->bitenc_depth);
            }
            else
            {
                /*free mempool if calloc fails*/
                mempool_free(imap_mempool, bkt);
            }
        }
        else
        {
            IMAP_GenerateAlert(IMAP_MEMCAP_EXCEEDED, "%s", IMAP_MEMCAP_EXCEEDED_STR);
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "No memory available for decoding. Memcap exceeded \n"););
        }
    }
}

void IMAP_InitCmds(IMAPConfig *config)
{
    const IMAPToken *tmp;

    if (config == NULL)
        return;

    /* add one to CMD_LAST for NULL entry */
    config->cmds = (IMAPToken *)calloc(CMD_LAST + 1, sizeof(IMAPToken));
    if (config->cmds == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => failed to allocate memory for imap "
                                        "command structure\n",
                                        *(_dpd.config_file), *(_dpd.config_line));
    }

    for (tmp = &imap_known_cmds[0]; tmp->name != NULL; tmp++)
    {
        config->cmds[tmp->search_id].name_len = tmp->name_len;
        config->cmds[tmp->search_id].search_id = tmp->search_id;
        config->cmds[tmp->search_id].name = strdup(tmp->name);

        if (config->cmds[tmp->search_id].name == NULL)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => failed to allocate memory for imap "
                                            "command structure\n",
                                            *(_dpd.config_file), *(_dpd.config_line));
        }
    }

    /* initialize memory for command searches */
    config->cmd_search = (IMAPSearch *)calloc(CMD_LAST, sizeof(IMAPSearch));
    if (config->cmd_search == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => failed to allocate memory for imap "
                                        "command structure\n",
                                        *(_dpd.config_file), *(_dpd.config_line));
    }

    config->num_cmds = CMD_LAST;
}


/*
 * Initialize IMAP searches
 *
 * @param  none
 *
 * @return none
 */
void IMAP_SearchInit(void)
{
    const char *error;
    int erroffset;
    const IMAPToken *tmp;

    /* Response search */
    imap_resp_search_mpse = _dpd.searchAPI->search_instance_new();
    if (imap_resp_search_mpse == NULL)
    {
        DynamicPreprocessorFatalMessage("Could not allocate IMAP "
                                        "response search.\n");
    }

    for (tmp = &imap_resps[0]; tmp->name != NULL; tmp++)
    {
        imap_resp_search[tmp->search_id].name = tmp->name;
        imap_resp_search[tmp->search_id].name_len = tmp->name_len;

        _dpd.searchAPI->search_instance_add(imap_resp_search_mpse, tmp->name,
                                            tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_instance_prep(imap_resp_search_mpse);

    /* Header search */
    imap_hdr_search_mpse = _dpd.searchAPI->search_instance_new();
    if (imap_hdr_search_mpse == NULL)
    {
        DynamicPreprocessorFatalMessage("Could not allocate IMAP "
                                        "header search.\n");
    }

    for (tmp = &imap_hdrs[0]; tmp->name != NULL; tmp++)
    {
        imap_hdr_search[tmp->search_id].name = tmp->name;
        imap_hdr_search[tmp->search_id].name_len = tmp->name_len;

        _dpd.searchAPI->search_instance_add(imap_hdr_search_mpse, tmp->name,
                                            tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_instance_prep(imap_hdr_search_mpse);

    /* Data end search */
    imap_data_search_mpse = _dpd.searchAPI->search_instance_new();
    if (imap_data_search_mpse == NULL)
    {
        DynamicPreprocessorFatalMessage("Could not allocate IMAP "
                                        "data search.\n");
    }

    for (tmp = &imap_data_end[0]; tmp->name != NULL; tmp++)
    {
        imap_data_end_search[tmp->search_id].name = tmp->name;
        imap_data_end_search[tmp->search_id].name_len = tmp->name_len;

        _dpd.searchAPI->search_instance_add(imap_data_search_mpse, tmp->name,
                                            tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_instance_prep(imap_data_search_mpse);


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
                                        "in a multipart IMAP message: %s\n", error);
    }

    mime_boundary_pcre.pe = pcre_study(mime_boundary_pcre.re, 0, &error);

    if (error != NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to study pcre regex for getting boundary "
                                        "in a multipart IMAP message: %s\n", error);
    }
}

/*
 * Initialize run-time boundary search
 */
static int IMAP_BoundarySearchInit(void)
{
    if (imap_ssn->mime_boundary.boundary_search != NULL)
        _dpd.searchAPI->search_instance_free(imap_ssn->mime_boundary.boundary_search);

    imap_ssn->mime_boundary.boundary_search = _dpd.searchAPI->search_instance_new();

    if (imap_ssn->mime_boundary.boundary_search == NULL)
        return -1;

    _dpd.searchAPI->search_instance_add(imap_ssn->mime_boundary.boundary_search,
                                        imap_ssn->mime_boundary.boundary,
                                        imap_ssn->mime_boundary.boundary_len, BOUNDARY);

    _dpd.searchAPI->search_instance_prep(imap_ssn->mime_boundary.boundary_search);

    return 0;
}



/*
 * Reset IMAP session state
 *
 * @param  none
 *
 * @return none
 */
static void IMAP_ResetState(void)
{
    if (imap_ssn->mime_boundary.boundary_search != NULL)
    {
        _dpd.searchAPI->search_instance_free(imap_ssn->mime_boundary.boundary_search);
        imap_ssn->mime_boundary.boundary_search = NULL;
    }

    imap_ssn->state = STATE_UNKNOWN;
    imap_ssn->data_state = STATE_DATA_INIT;
    imap_ssn->state_flags = 0;
    imap_ssn->body_read = imap_ssn->body_len = 0;
    ClearEmailDecodeState(imap_ssn->decode_state);
    memset(&imap_ssn->mime_boundary, 0, sizeof(IMAPMimeBoundary));
}


/*
 * Given a server configuration and a port number, we decide if the port is
 *  in the IMAP server port list.
 *
 *  @param  port       the port number to compare with the configuration
 *
 *  @return integer
 *  @retval  0 means that the port is not a server port
 *  @retval !0 means that the port is a server port
 */
int IMAP_IsServer(uint16_t port)
{
    if (imap_eval_config->ports[port / 8] & (1 << (port % 8)))
        return 1;

    return 0;
}

static IMAP * IMAP_GetNewSession(SFSnortPacket *p, tSfPolicyId policy_id)
{
    IMAP *ssn;
    IMAPConfig *pPolicyConfig = NULL;

    pPolicyConfig = (IMAPConfig *)sfPolicyUserDataGetCurrent(imap_config);

    DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Creating new session data structure\n"););

    ssn = (IMAP *)calloc(1, sizeof(IMAP));
    if (ssn == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate IMAP session data\n");
    }

    imap_ssn = ssn;
    SetImapBuffers(ssn);

    _dpd.streamAPI->set_application_data(p->stream_session_ptr, PP_IMAP,
                                         ssn, &IMAP_SessionFree);

    if (p->flags & SSNFLAG_MIDSTREAM)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Got midstream packet - "
                                "setting state to unknown\n"););
        ssn->state = STATE_UNKNOWN;
    }

#ifdef DEBUG_MSGS
    imap_session_counter++;
    ssn->session_number = imap_session_counter;
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

    ssn->body_read = ssn->body_len = 0;

    ssn->policy_id = policy_id;
    ssn->config = imap_config;
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
static int IMAP_Setup(SFSnortPacket *p, IMAP *ssn)
{
    int flags = 0;
    int pkt_dir;

    if (p->stream_session_ptr != NULL)
    {
        /* set flags to session flags */
        flags = _dpd.streamAPI->get_session_flags(p->stream_session_ptr);
    }

    /* Figure out direction of packet */
    pkt_dir = IMAP_GetPacketDirection(p, flags);

    DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Session number: "STDu64"\n", ssn->session_number););

    /* Check to see if there is a reassembly gap.  If so, we won't know
     * what state we're in when we get the _next_ reassembled packet */
    if ((pkt_dir != IMAP_PKT_FROM_SERVER) &&
        (p->flags & FLAG_REBUILT_STREAM))
    {
        int missing_in_rebuilt =
            _dpd.streamAPI->missing_in_reassembled(p->stream_session_ptr, SSN_DIR_CLIENT);

        if (ssn->session_flags & IMAP_FLAG_NEXT_STATE_UNKNOWN)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Found gap in previous reassembly buffer - "
                                    "set state to unknown\n"););
            ssn->state = STATE_UNKNOWN;
            ssn->session_flags &= ~IMAP_FLAG_NEXT_STATE_UNKNOWN;
        }

        if (missing_in_rebuilt == SSN_MISSING_BOTH)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Found missing packets before and after "
                                    "in reassembly buffer - set state to unknown and "
                                    "next state to unknown\n"););
            ssn->state = STATE_UNKNOWN;
            ssn->session_flags |= IMAP_FLAG_NEXT_STATE_UNKNOWN;
        }
        else if (missing_in_rebuilt == SSN_MISSING_BEFORE)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Found missing packets before "
                                    "in reassembly buffer - set state to unknown\n"););
            ssn->state = STATE_UNKNOWN;
        }
        else if (missing_in_rebuilt == SSN_MISSING_AFTER)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Found missing packets after "
                                    "in reassembly buffer - set next state to unknown\n"););
            ssn->session_flags |= IMAP_FLAG_NEXT_STATE_UNKNOWN;
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
static int IMAP_GetPacketDirection(SFSnortPacket *p, int flags)
{
    int pkt_direction = IMAP_PKT_FROM_UNKNOWN;

    if (flags & SSNFLAG_MIDSTREAM)
    {
        if (IMAP_IsServer(p->src_port) &&
            !IMAP_IsServer(p->dst_port))
        {
            pkt_direction = IMAP_PKT_FROM_SERVER;
        }
        else if (!IMAP_IsServer(p->src_port) &&
                 IMAP_IsServer(p->dst_port))
        {
            pkt_direction = IMAP_PKT_FROM_CLIENT;
        }
    }
    else
    {
        if (p->flags & FLAG_FROM_SERVER)
        {
            pkt_direction = IMAP_PKT_FROM_SERVER;
        }
        else if (p->flags & FLAG_FROM_CLIENT)
        {
            pkt_direction = IMAP_PKT_FROM_CLIENT;
        }

        /* if direction is still unknown ... */
        if (pkt_direction == IMAP_PKT_FROM_UNKNOWN)
        {
            if (IMAP_IsServer(p->src_port) &&
                !IMAP_IsServer(p->dst_port))
            {
                pkt_direction = IMAP_PKT_FROM_SERVER;
            }
            else if (!IMAP_IsServer(p->src_port) &&
                     IMAP_IsServer(p->dst_port))
            {
                pkt_direction = IMAP_PKT_FROM_CLIENT;
            }
        }
    }

    return pkt_direction;
}


/*
 * Free IMAP-specific related to this session
 *
 * @param   v   pointer to IMAP session structure
 *
 *
 * @return  none
 */
static void IMAP_SessionFree(void *session_data)
{
    IMAP *imap = (IMAP *)session_data;
#ifdef SNORT_RELOAD
    IMAPConfig *pPolicyConfig = NULL;
#endif

    if (imap == NULL)
        return;

#ifdef SNORT_RELOAD
    pPolicyConfig = (IMAPConfig *)sfPolicyUserDataGet(imap->config, imap->policy_id);

    if (pPolicyConfig != NULL)
    {
        pPolicyConfig->ref_count--;
        if ((pPolicyConfig->ref_count == 0) &&
            (imap->config != imap_config))
        {
            sfPolicyUserDataClear (imap->config, imap->policy_id);
            IMAP_FreeConfig(pPolicyConfig);

            /* No more outstanding policies for this config */
            if (sfPolicyUserPolicyGetActive(imap->config) == 0)
                IMAP_FreeConfigs(imap->config);
        }
    }
#endif

    if (imap->mime_boundary.boundary_search != NULL)
    {
        _dpd.searchAPI->search_instance_free(imap->mime_boundary.boundary_search);
        imap->mime_boundary.boundary_search = NULL;
    }

    if(imap->decode_state != NULL)
    {
        mempool_free(imap_mempool, imap->decode_bkt);
        free(imap->decode_state);
    }

    free(imap);
}


static void IMAP_NoSessionFree(void)
{
    if (imap_no_session.mime_boundary.boundary_search != NULL)
    {
        _dpd.searchAPI->search_instance_free(imap_no_session.mime_boundary.boundary_search);
        imap_no_session.mime_boundary.boundary_search = NULL;
    }
}

static int IMAP_FreeConfigsPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
        )
{
    IMAPConfig *pPolicyConfig = (IMAPConfig *)pData;

    //do any housekeeping before freeing IMAPConfig
    sfPolicyUserDataClear (config, policyId);
    IMAP_FreeConfig(pPolicyConfig);

    return 0;
}

void IMAP_FreeConfigs(tSfPolicyUserContextId config)
{
    if (config == NULL)
        return;

    sfPolicyUserDataIterate (config, IMAP_FreeConfigsPolicy);
    sfPolicyConfigDelete(config);
}

void IMAP_FreeConfig(IMAPConfig *config)
{
    if (config == NULL)
        return;

    if (config->cmds != NULL)
    {
        IMAPToken *tmp = config->cmds;

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
void IMAP_Free(void)
{
    IMAP_NoSessionFree();

    IMAP_FreeConfigs(imap_config);
    imap_config = NULL;

    if (imap_resp_search_mpse != NULL)
        _dpd.searchAPI->search_instance_free(imap_resp_search_mpse);

    if (imap_hdr_search_mpse != NULL)
        _dpd.searchAPI->search_instance_free(imap_hdr_search_mpse);

    if (imap_data_search_mpse != NULL)
        _dpd.searchAPI->search_instance_free(imap_data_search_mpse);

    if (mime_boundary_pcre.re )
        pcre_free(mime_boundary_pcre.re);

    if (mime_boundary_pcre.pe )
        pcre_free(mime_boundary_pcre.pe);
}


/*
 * Callback function for string search
 *
 * @param   id      id in array of search strings from imap_config.cmds
 * @param   index   index in array of search strings from imap_config.cmds
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
static int IMAP_SearchStrFound(void *id, void *unused, int index, void *data, void *unused2)
{
    int search_id = (int)(uintptr_t)id;

    imap_search_info.id = search_id;
    imap_search_info.index = index;
    imap_search_info.length = imap_current_search[search_id].name_len;

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
static int IMAP_BoundaryStrFound(void *id, void *unused, int index, void *data, void *unused2)
{
    int boundary_id = (int)(uintptr_t)id;

    imap_search_info.id = boundary_id;
    imap_search_info.index = index;
    imap_search_info.length = imap_ssn->mime_boundary.boundary_len;

    return 1;
}

static int IMAP_GetBoundary(const char *data, int data_len)
{
    int result;
    int ovector[9];
    int ovecsize = 9;
    const char *boundary;
    int boundary_len;
    int ret;
    char *mime_boundary;
    int  *mime_boundary_len;


    mime_boundary = &imap_ssn->mime_boundary.boundary[0];
    mime_boundary_len = &imap_ssn->mime_boundary.boundary_len;

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
static const uint8_t * IMAP_HandleCommand(SFSnortPacket *p, const uint8_t *ptr, const uint8_t *end)
{
    const uint8_t *eol;   /* end of line */
    const uint8_t *eolm;  /* end of line marker */
    int cmd_line_len;
    int cmd_found;

    /* get end of line and end of line marker */
    IMAP_GetEOL(ptr, end, &eol, &eolm);

    /* calculate length of command line */
    cmd_line_len = eol - ptr;

    /* TODO If the end of line marker coincides with the end of payload we can't be
     * sure that we got a command and not a substring which we could tell through
     * inspection of the next packet. Maybe a command pending state where the first
     * char in the next packet is checked for a space and end of line marker */

    /* do not confine since there could be space chars before command */
    imap_current_search = &imap_eval_config->cmd_search[0];
    cmd_found = _dpd.searchAPI->search_instance_find
        (imap_eval_config->cmd_search_mpse, (const char *)ptr,
         eolm - ptr, 0, IMAP_SearchStrFound);

    /* if command not found, alert and move on */
    if (!cmd_found)
    {
        IMAP_GenerateAlert(IMAP_UNKNOWN_CMD, "%s", IMAP_UNKNOWN_CMD_STR);
        DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "No known command found\n"););

        return eol;
    }

    /* At this point we have definitely found a legitimate command */

    DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "%s\n", imap_eval_config->cmds[imap_search_info.id].name););

    return eol;
}


static const uint8_t * IMAP_HandleData(SFSnortPacket *p, const uint8_t *ptr, const uint8_t *end)
{
    const uint8_t *data_end_marker = NULL;
    const uint8_t *data_end = NULL;
    int data_end_found;

    /* if we've just entered the data state, check for a dot + end of line
     * if found, no data */
    if ((imap_ssn->data_state == STATE_DATA_INIT) ||
        (imap_ssn->data_state == STATE_DATA_UNKNOWN))
    {
        if ((ptr < end) && (*ptr == '.'))
        {
            const uint8_t *eol = NULL;
            const uint8_t *eolm = NULL;

            IMAP_GetEOL(ptr, end, &eol, &eolm);

            /* this means we got a real end of line and not just end of payload
             * and that the dot is only char on line */
            if ((eolm != end) && (eolm == (ptr + 1)))
            {
                /* if we're normalizing and not ignoring data copy data end marker
                 * and dot to alt buffer */

                IMAP_ResetState();

                return eol;
            }
        }

        if (imap_ssn->data_state == STATE_DATA_INIT)
            imap_ssn->data_state = STATE_DATA_HEADER;

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
    imap_current_search = &imap_data_end_search[0];
    data_end_found = _dpd.searchAPI->search_instance_find
        (imap_data_search_mpse, (const char *)ptr, end - ptr,
         0, IMAP_SearchStrFound);

    if (data_end_found > 0)
    {
        data_end_marker = ptr + imap_search_info.index;
        data_end = data_end_marker + imap_search_info.length;
    }
    else
    {
        data_end_marker = data_end = end;
    }

    _dpd.setFileDataPtr((uint8_t*)ptr, data_end - ptr);

    if ((imap_ssn->data_state == STATE_DATA_HEADER) ||
        (imap_ssn->data_state == STATE_DATA_UNKNOWN))
    {
#ifdef DEBUG_MSGS
        if (imap_ssn->data_state == STATE_DATA_HEADER)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "DATA HEADER STATE ~~~~~~~~~~~~~~~~~~~~~~\n"););
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "DATA UNKNOWN STATE ~~~~~~~~~~~~~~~~~~~~~\n"););
        }
#endif

        ptr = IMAP_HandleHeader(p, ptr, data_end_marker);
        if (ptr == NULL)
            return NULL;

    }

    /* now we shouldn't have to worry about copying any data to the alt buffer
     * only mime headers if we find them and only if we're ignoring data */

    while ((ptr != NULL) && (ptr < data_end_marker))
    {
        /* multiple MIME attachments in one single packet.
         * Pipeline the MIME decoded data.*/
        if ( imap_ssn->state_flags & IMAP_FLAG_MULTIPLE_EMAIL_ATTACH)
        {
            _dpd.setFileDataPtr(imap_ssn->decode_state->decodePtr, imap_ssn->decode_state->decoded_bytes);
            _dpd.detect(p);
            imap_ssn->state_flags &= ~IMAP_FLAG_MULTIPLE_EMAIL_ATTACH;
            ResetEmailDecodeState(imap_ssn->decode_state);
            p->flags |=FLAG_ALLOW_MULTIPLE_DETECT;
            /* Reset the log count when a packet goes through detection multiple times */
            p->log_func_count = 0;
            _dpd.DetectReset((uint8_t *)p->payload, p->payload_size);
        }
        switch (imap_ssn->data_state)
        {
            case STATE_MIME_HEADER:
                DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "MIME HEADER STATE ~~~~~~~~~~~~~~~~~~~~~~\n"););
                ptr = IMAP_HandleHeader(p, ptr, data_end_marker);
                break;
            case STATE_DATA_BODY:
                DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "DATA BODY STATE ~~~~~~~~~~~~~~~~~~~~~~~~\n"););
                ptr = IMAP_HandleDataBody(p, ptr, data_end_marker);
                break;
        }
    }

    /* We have either reached the end of MIME header or end of MIME encoded data*/

    if(imap_ssn->decode_state != NULL)
    {
        _dpd.setFileDataPtr(imap_ssn->decode_state->decodePtr, imap_ssn->decode_state->decoded_bytes);
        ResetDecodedBytes(imap_ssn->decode_state);
    }

    /* if we got the data end reset state, otherwise we're probably still in the data
     * to expect more data in next packet */
    if (data_end_marker != end)
    {
        IMAP_ResetState();
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
static const uint8_t * IMAP_HandleHeader(SFSnortPacket *p, const uint8_t *ptr,
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
    if (imap_ssn->state_flags & IMAP_FLAG_IN_CONTENT_TYPE)
        content_type_ptr = ptr;

    if (imap_ssn->state_flags & IMAP_FLAG_IN_CONT_TRANS_ENC)
        cont_trans_enc = ptr;

    while (ptr < data_end_marker)
    {
        IMAP_GetEOL(ptr, data_end_marker, &eol, &eolm);

        /* got a line with only end of line marker should signify end of header */
        if (eolm == ptr)
        {
            /* reset global header state values */
            imap_ssn->state_flags &=
                ~(IMAP_FLAG_FOLDING | IMAP_FLAG_IN_CONTENT_TYPE | IMAP_FLAG_DATA_HEADER_CONT
                        | IMAP_FLAG_IN_CONT_TRANS_ENC );

            imap_ssn->data_state = STATE_DATA_BODY;

            /* if no headers, treat as data */
            if (ptr == start_hdr)
                return eolm;
            else
                return eol;
        }

        /* if we're not folding, see if we should interpret line as a data line
         * instead of a header line */
        if (!(imap_ssn->state_flags & (IMAP_FLAG_FOLDING | IMAP_FLAG_DATA_HEADER_CONT)))
        {
            char got_non_printable_in_header_name = 0;

            /* if we're not folding and the first char is a space or
             * colon, it's not a header */
            if (isspace((int)*ptr) || *ptr == ':')
            {
                imap_ssn->data_state = STATE_DATA_BODY;
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
                imap_ssn->state_flags &=
                    ~(IMAP_FLAG_FOLDING | IMAP_FLAG_IN_CONTENT_TYPE | IMAP_FLAG_DATA_HEADER_CONT 
                            |IMAP_FLAG_IN_CONT_TRANS_ENC);

                imap_ssn->data_state = STATE_DATA_BODY;

                return ptr;
            }

            if(tolower((int)*ptr) == 'c')
            {
                imap_current_search = &imap_hdr_search[0];
                header_found = _dpd.searchAPI->search_instance_find
                    (imap_hdr_search_mpse, (const char *)ptr,
                     eolm - ptr, 1, IMAP_SearchStrFound);

                /* Headers must start at beginning of line */
                if ((header_found > 0) && (imap_search_info.index == 0))
                {
                    switch (imap_search_info.id)
                    {
                        case HDR_CONTENT_TYPE:
                            /* for now we're just looking for the boundary in the data
                             * header section */
                            if (imap_ssn->data_state != STATE_MIME_HEADER)
                            {
                                content_type_ptr = ptr + imap_search_info.length;
                                imap_ssn->state_flags |= IMAP_FLAG_IN_CONTENT_TYPE;
                            }

                            break;
                        case HDR_CONT_TRANS_ENC:
                            cont_trans_enc = ptr + imap_search_info.length;
                            imap_ssn->state_flags |= IMAP_FLAG_IN_CONT_TRANS_ENC;
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
                        imap_ssn->state_flags |= IMAP_FLAG_IN_CONT_TRANS_ENC;
                    }
                }
            }
        }
        else
        {
            imap_ssn->state_flags &= ~IMAP_FLAG_DATA_HEADER_CONT;
        }


        /* check for folding 
         * if char on next line is a space and not \n or \r\n, we are folding */
        if ((eol < data_end_marker) && isspace((int)eol[0]) && (eol[0] != '\n'))
        {
            if ((eol < (data_end_marker - 1)) && (eol[0] != '\r') && (eol[1] != '\n'))
            {
                imap_ssn->state_flags |= IMAP_FLAG_FOLDING;
            }
            else
            {
                imap_ssn->state_flags &= ~IMAP_FLAG_FOLDING;
            }
        }
        else if (eol != eolm)
        {
            imap_ssn->state_flags &= ~IMAP_FLAG_FOLDING;
        }

        /* check if we're in a content-type header and not folding. if so we have the whole
         * header line/lines for content-type - see if we got a multipart with boundary
         * we don't check each folded line, but wait until we have the complete header
         * because boundary=BOUNDARY can be split across mulitple folded lines before
         * or after the '=' */
        if ((imap_ssn->state_flags &
             (IMAP_FLAG_IN_CONTENT_TYPE | IMAP_FLAG_FOLDING)) == IMAP_FLAG_IN_CONTENT_TYPE)
        {
            /* we got the full content-type header - look for boundary string */
            ret = IMAP_GetBoundary((const char *)content_type_ptr, eolm - content_type_ptr);
            if (ret != -1)
            {
                ret = IMAP_BoundarySearchInit();
                if (ret != -1)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Got mime boundary: %s\n",
                                                         imap_ssn->mime_boundary.boundary););

                    imap_ssn->state_flags |= IMAP_FLAG_GOT_BOUNDARY;
                }
            }

            imap_ssn->state_flags &= ~IMAP_FLAG_IN_CONTENT_TYPE;
            content_type_ptr = NULL;
        }
        else if ((imap_ssn->state_flags &
                (IMAP_FLAG_IN_CONT_TRANS_ENC | IMAP_FLAG_FOLDING)) == IMAP_FLAG_IN_CONT_TRANS_ENC)
        {
            /* Check for Encoding Type */
            if( (!IMAP_IsDecodingEnabled(imap_eval_config)) && (imap_ssn->decode_state != NULL))
            {
                IMAP_DecodeType((const char *)cont_trans_enc, eolm - cont_trans_enc );
                imap_ssn->state_flags |= IMAP_FLAG_EMAIL_ATTACH;
                /* check to see if there are other attachments in this packet */
                if( imap_ssn->decode_state->decoded_bytes )
                    imap_ssn->state_flags |= IMAP_FLAG_MULTIPLE_EMAIL_ATTACH;
            }
            imap_ssn->state_flags &= ~IMAP_FLAG_IN_CONT_TRANS_ENC;

            cont_trans_enc = NULL;
        }

        /* if state was unknown, at this point assume we know */
        if (imap_ssn->data_state == STATE_DATA_UNKNOWN)
            imap_ssn->data_state = STATE_DATA_HEADER;

        ptr = eol;

        if (ptr == data_end_marker)
            imap_ssn->state_flags |= IMAP_FLAG_DATA_HEADER_CONT;
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
static const uint8_t * IMAP_HandleDataBody(SFSnortPacket *p, const uint8_t *ptr,
                                            const uint8_t *data_end_marker)
{
    int boundary_found = 0;
    const uint8_t *boundary_ptr = NULL;
    const uint8_t *attach_start = NULL;
    const uint8_t *attach_end = NULL;

    if ( imap_ssn->state_flags & IMAP_FLAG_EMAIL_ATTACH )
        attach_start = ptr;
    /* look for boundary */
    if (imap_ssn->state_flags & IMAP_FLAG_GOT_BOUNDARY)
    {
        boundary_found = _dpd.searchAPI->search_instance_find
            (imap_ssn->mime_boundary.boundary_search, (const char *)ptr,
             data_end_marker - ptr, 0, IMAP_BoundaryStrFound);

        if (boundary_found > 0)
        {
            boundary_ptr = ptr + imap_search_info.index;

            /* should start at beginning of line */
            if ((boundary_ptr == ptr) || (*(boundary_ptr - 1) == '\n'))
            {
                const uint8_t *eol;
                const uint8_t *eolm;
                const uint8_t *tmp;

                if (imap_ssn->state_flags & IMAP_FLAG_EMAIL_ATTACH )
                {
                    attach_end = boundary_ptr-1;
                    imap_ssn->state_flags &= ~IMAP_FLAG_EMAIL_ATTACH;
                    if(attach_start < attach_end)
                    {
                        if(EmailDecode( attach_start, attach_end, imap_ssn->decode_state) != DECODE_SUCCESS )
                        {
                            IMAP_DecodeAlert();
                        }
                    }
                }


                /* Check for end boundary */
                tmp = boundary_ptr + imap_search_info.length;
                if (((tmp + 1) < data_end_marker) && (tmp[0] == '-') && (tmp[1] == '-'))
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Mime boundary end found: %s--\n",
                                            (char *)imap_ssn->mime_boundary.boundary););

                    /* no more MIME */
                    imap_ssn->state_flags &= ~IMAP_FLAG_GOT_BOUNDARY;

                    /* free boundary search */
                    _dpd.searchAPI->search_instance_free(imap_ssn->mime_boundary.boundary_search);
                    imap_ssn->mime_boundary.boundary_search = NULL;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Mime boundary found: %s\n",
                                            (char *)imap_ssn->mime_boundary.boundary););

                    imap_ssn->data_state = STATE_MIME_HEADER;
                }

                /* get end of line - there could be spaces after boundary before eol */
                IMAP_GetEOL(boundary_ptr + imap_search_info.length, data_end_marker, &eol, &eolm);

                return eol;
            }
        }
    }

    if ( imap_ssn->state_flags & IMAP_FLAG_EMAIL_ATTACH )
    {
        attach_end = data_end_marker;
        if(attach_start < attach_end)
        {
            if(EmailDecode( attach_start, attach_end, imap_ssn->decode_state) != DECODE_SUCCESS )
            {
                IMAP_DecodeAlert();
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
static void IMAP_ProcessClientPacket(SFSnortPacket *p)
{
    const uint8_t *ptr = p->payload;
    const uint8_t *end = p->payload + p->payload_size;

    ptr = IMAP_HandleCommand(p, ptr, end);


}



/*
 * Process server packet
 *
 * @param   packet  standard Packet structure
 *
 */
static void IMAP_ProcessServerPacket(SFSnortPacket *p)
{
    int resp_found;
    const uint8_t *ptr;
    const uint8_t *end;
    const uint8_t *data_end;
    const uint8_t *eolm;
    const uint8_t *eol;
    int resp_line_len;
    const char *tmp = NULL;
    uint8_t *body_start, *body_end;
    char *eptr;
    uint32_t len = 0;

    body_start = body_end = NULL;

    ptr = p->payload;
    end = p->payload + p->payload_size;

    while (ptr < end)
    {
        if(imap_ssn->state == STATE_DATA)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "DATA STATE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"););
            if( imap_ssn->body_len > imap_ssn->body_read)
            {

                len = imap_ssn->body_len - imap_ssn->body_read ;
                if( (end - ptr) < len )
                {
                    data_end = end;
                    len = data_end - ptr;
                }
                else
                    data_end = ptr + len;

                ptr = IMAP_HandleData(p, ptr, data_end);

                if( ptr < data_end)
                    len = len - (data_end - ptr);

                imap_ssn->body_read += len;

                continue;
            }
            else
            {
                imap_ssn->body_len = imap_ssn->body_read = 0;
                imap_ssn->state = STATE_UNKNOWN;

            }
        }
        IMAP_GetEOL(ptr, end, &eol, &eolm);

        resp_line_len = eol - ptr;

        /* Check for response code */
        imap_current_search = &imap_resp_search[0];
        resp_found = _dpd.searchAPI->search_instance_find
            (imap_resp_search_mpse, (const char *)ptr,
             resp_line_len, 0, IMAP_SearchStrFound);

        if (resp_found > 0)
        {
            const uint8_t *cmd_start = ptr + imap_search_info.index;
            switch (imap_search_info.id)
            {
                case RESP_FETCH:
                    imap_ssn->body_len = imap_ssn->body_read = 0;
                    imap_ssn->state = STATE_DATA;
                    tmp = _dpd.SnortStrcasestr((const char *)cmd_start, (eol - cmd_start), "BODY");
                    if(tmp != NULL)
                        imap_ssn->state = STATE_DATA;
                    else
                    {
                        tmp = _dpd.SnortStrcasestr((const char *)cmd_start, (eol - cmd_start), "RFC822");
                        if(tmp != NULL)
                            imap_ssn->state = STATE_DATA;
                        else
                            imap_ssn->state = STATE_UNKNOWN;
                    }
                    break;
                default:
                    break;
            }

            if(imap_ssn->state == STATE_DATA)
            {
                body_start = (uint8_t *)memchr((char *)ptr, '{', (eol - ptr));
                if( body_start == NULL )
                {
                    imap_ssn->state = STATE_UNKNOWN;
                }
                else
                {
                    if( (body_start + 1) < (uint8_t *)eol )
                    {
                        len = (uint32_t)_dpd.SnortStrtoul((const char *)(body_start + 1), &eptr, 10);
                        if (*eptr != '}')
                        {
                            imap_ssn->state = STATE_UNKNOWN;
                        }
                        else
                            imap_ssn->body_len = len;

                        len = 0;
                    }
                    else
                        imap_ssn->state = STATE_UNKNOWN;

                }
            }

        }
        else
        {
            if ( (*ptr != '*') && (*ptr !='+') && (*ptr != '\r') && (*ptr != '\n') )
            {
                IMAP_GenerateAlert(IMAP_UNKNOWN_RESP, "%s", IMAP_UNKNOWN_RESP_STR);
                DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Server response not found\n"););
            }

        }


        ptr = eol;

    }

    return;
}

/* For Target based
 * If a protocol for the session is already identified and not one IMAP is
 * interested in, IMAP should leave it alone and return without processing.
 * If a protocol for the session is already identified and is one that IMAP is
 * interested in, decode it.
 * If the protocol for the session is not already identified and the preprocessor
 * is configured to detect on one of the packet ports, detect.
 * Returns 0 if we should not inspect
 *         1 if we should continue to inspect
 */
static int IMAP_Inspect(SFSnortPacket *p)
{
#ifdef TARGET_BASED
    /* IMAP could be configured to be stateless.  If stream isn't configured, assume app id
     * will never be set and just base inspection on configuration */
    if (p->stream_session_ptr == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP: Target-based: No stream session.\n"););

        if ((IMAP_IsServer(p->src_port) && (p->flags & FLAG_FROM_SERVER)) ||
            (IMAP_IsServer(p->dst_port) && (p->flags & FLAG_FROM_CLIENT)))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP: Target-based: Configured for this "
                                    "traffic, so let's inspect.\n"););
            return 1;
        }
    }
    else
    {
        int16_t app_id = _dpd.streamAPI->get_application_protocol_id(p->stream_session_ptr);

        if (app_id != 0)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP: Target-based: App id: %u.\n", app_id););

            if (app_id == imap_proto_id)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP: Target-based: App id is "
                                        "set to \"%s\".\n", IMAP_PROTO_REF_STR););
                return 1;
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP: Target-based: Unknown protocol for "
                                    "this session.  See if we're configured.\n"););

            if ((IMAP_IsServer(p->src_port) && (p->flags & FLAG_FROM_SERVER)) ||
                (IMAP_IsServer(p->dst_port) && (p->flags & FLAG_FROM_CLIENT)))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP: Target-based: IMAP port is configured."););
                return 1;
            }
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_IMAP,"IMAP: Target-based: Not inspecting ...\n"););

#else
    /* Make sure it's traffic we're interested in */
    if ((IMAP_IsServer(p->src_port) && (p->flags & FLAG_FROM_SERVER)) ||
        (IMAP_IsServer(p->dst_port) && (p->flags & FLAG_FROM_CLIENT)))
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
void SnortIMAP(SFSnortPacket *p)
{
    int detected = 0;
    int pkt_dir;
    tSfPolicyId policy_id = _dpd.getRuntimePolicy();

    PROFILE_VARS;


    imap_ssn = (IMAP *)_dpd.streamAPI->get_application_data(p->stream_session_ptr, PP_IMAP);
    if (imap_ssn != NULL)
        imap_eval_config = (IMAPConfig *)sfPolicyUserDataGet(imap_ssn->config, imap_ssn->policy_id);
    else
        imap_eval_config = (IMAPConfig *)sfPolicyUserDataGetCurrent(imap_config);

    if (imap_eval_config == NULL)
        return;

    if (imap_ssn == NULL)
    {
        if (!IMAP_Inspect(p))
            return;

        imap_ssn = IMAP_GetNewSession(p, policy_id);
        if (imap_ssn == NULL)
            return;
    }

    pkt_dir = IMAP_Setup(p, imap_ssn);

    if (pkt_dir == IMAP_PKT_FROM_CLIENT)
    {
        IMAP_ProcessClientPacket(p);
        DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP client packet\n"););
    }
    else
    {
#ifdef DEBUG_MSGS
        if (pkt_dir == IMAP_PKT_FROM_SERVER)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP server packet\n"););
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP packet NOT from client or server! "
                        "Processing as a server packet\n"););
        }
#endif

        if (p->flags & FLAG_STREAM_INSERT)
        {
            /* Packet will be rebuilt, so wait for it */
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Client packet will be reassembled\n"));
            return;
        }
        else if (imap_ssn->reassembling && !(p->flags & FLAG_REBUILT_STREAM))
        {
            /* If this isn't a reassembled packet and didn't get
             * inserted into reassembly buffer, there could be a
             * problem.  If we miss syn or syn-ack that had window
             * scaling this packet might not have gotten inserted
             * into reassembly buffer because it fell outside of
             * window, because we aren't scaling it */
            imap_ssn->session_flags |= IMAP_FLAG_GOT_NON_REBUILT;
            imap_ssn->state = STATE_UNKNOWN;
        }
        else if (imap_ssn->reassembling && (imap_ssn->session_flags & IMAP_FLAG_GOT_NON_REBUILT))
        {
            /* This is a rebuilt packet.  If we got previous packets
             * that were not rebuilt, state is going to be messed up
             * so set state to unknown. It's likely this was the
             * beginning of the conversation so reset state */
            DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "Got non-rebuilt packets before "
                "this rebuilt packet\n"););

            imap_ssn->state = STATE_UNKNOWN;
            imap_ssn->session_flags &= ~IMAP_FLAG_GOT_NON_REBUILT;
        }
        /* Process as a server packet */
        IMAP_ProcessServerPacket(p);
    }


    PREPROC_PROFILE_START(imapDetectPerfStats);
    
    detected = _dpd.detect(p);

#ifdef PERF_PROFILING
    imapDetectCalled = 1;
#endif

    PREPROC_PROFILE_END(imapDetectPerfStats);

    /* Turn off detection since we've already done it. */
    IMAP_DisableDetect(p);

    if (detected)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_IMAP, "IMAP vulnerability detected\n"););
    }
}

static void IMAP_DisableDetect(SFSnortPacket *p)
{
    _dpd.disableAllDetect(p);

    _dpd.setPreprocBit(p, PP_SFPORTSCAN);
    _dpd.setPreprocBit(p, PP_PERFMONITOR);
    _dpd.setPreprocBit(p, PP_STREAM5);
    _dpd.setPreprocBit(p, PP_SDF);
}


