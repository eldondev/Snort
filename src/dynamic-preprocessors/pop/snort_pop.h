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
 * **************************************************************************/

/**************************************************************************
 *
 * snort_pop.h
 *
 * Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>
 *
 * Description:
 *
 * This file defines everything specific to the POP preprocessor.
 *
 **************************************************************************/

#ifndef __POP_H__
#define __POP_H__


/* Includes ***************************************************************/

#include <pcre.h>

#include "sf_snort_packet.h"
#include "pop_config.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"
#include "mempool.h"
#include "sf_email_attach_decode.h"

#ifdef DEBUG
#include "sf_types.h"
#endif

/**************************************************************************/


/* Defines ****************************************************************/

/* Direction packet is coming from, if we can figure it out */
#define POP_PKT_FROM_UNKNOWN  0
#define POP_PKT_FROM_CLIENT   1
#define POP_PKT_FROM_SERVER   2

#define SEARCH_CMD       0
#define SEARCH_RESP      1
#define SEARCH_HDR       2
#define SEARCH_DATA_END  3
#define NUM_SEARCHES  4

#define BOUNDARY     0

#define MAX_BOUNDARY_LEN  70  /* Max length of boundary string, defined in RFC 2046 */

#define STATE_DATA             0    /* Data state */
#define STATE_UNKNOWN          1

#define STATE_DATA_INIT    0
#define STATE_DATA_HEADER  1    /* Data header section of data state */
#define STATE_DATA_BODY    2    /* Data body section of data state */
#define STATE_MIME_HEADER  3    /* MIME header section within data section */
#define STATE_DATA_UNKNOWN 4

/* state flags */
#define POP_FLAG_FOLDING                    0x00000001
#define POP_FLAG_IN_CONTENT_TYPE            0x00000002
#define POP_FLAG_GOT_BOUNDARY               0x00000004
#define POP_FLAG_DATA_HEADER_CONT           0x00000008
#define POP_FLAG_IN_CONT_TRANS_ENC          0x00000010
#define POP_FLAG_EMAIL_ATTACH               0x00000020
#define POP_FLAG_MULTIPLE_EMAIL_ATTACH      0x00000040

/* session flags */
#define POP_FLAG_NEXT_STATE_UNKNOWN         0x00000004
#define POP_FLAG_GOT_NON_REBUILT            0x00000008

#define POP_SSL_ERROR_FLAGS  (SSL_BOGUS_HS_DIR_FLAG | \
                               SSL_BAD_VER_FLAG | \
                               SSL_BAD_TYPE_FLAG | \
                               SSL_UNKNOWN_FLAG)

/* Maximum length of header chars before colon, based on Exim 4.32 exploit */
#define MAX_HEADER_NAME_LEN 64

#define POP_PROTO_REF_STR  "pop"

/**************************************************************************/


/* Data structures ********************************************************/

typedef enum _POPCmdEnum
{
    CMD_APOP = 0,
    CMD_AUTH,
    CMD_CAPA,
    CMD_DELE,
    CMD_LIST,
    CMD_NOOP,
    CMD_PASS,
    CMD_QUIT,
    CMD_RETR,
    CMD_RSET,
    CMD_STAT,
    CMD_STLS,
    CMD_TOP,
    CMD_UIDL,
    CMD_USER,
    CMD_LAST

} POPCmdEnum;

typedef enum _POPRespEnum
{
    RESP_OK = 0,
    RESP_ERR,
    RESP_LAST

} POPRespEnum;

typedef enum _POPHdrEnum
{
    HDR_CONTENT_TYPE = 0,
    HDR_CONT_TRANS_ENC,
    HDR_LAST

} POPHdrEnum;

typedef enum _POPDataEndEnum
{
    DATA_END_1 = 0,
    DATA_END_2,
    DATA_END_3,
    DATA_END_4,
    DATA_END_LAST

} POPDataEndEnum;

typedef struct _POPSearchInfo
{
    int id;
    int index;
    int length;

} POPSearchInfo;

typedef struct _POPMimeBoundary
{
    char   boundary[2 + MAX_BOUNDARY_LEN + 1];  /* '--' + MIME boundary string + '\0' */
    int    boundary_len;
    void  *boundary_search;

} POPMimeBoundary;

typedef struct _POPPcre
{
    pcre       *re;
    pcre_extra *pe;

} POPPcre;

typedef struct _POP
{
    int state;
    int data_state;
    int state_flags;
    int session_flags;
    int alert_mask;
    int reassembling;
#ifdef DEBUG_MSGS
    uint64_t session_number;
#endif

    MemBucket *decode_bkt;
    POPMimeBoundary  mime_boundary;
    Email_DecodeState *decode_state;

    tSfPolicyId policy_id;
    tSfPolicyUserContextId config;

} POP;


/**************************************************************************/


/* Function prototypes ****************************************************/

void POP_InitCmds(POPConfig *config);
void POP_SearchInit(void);
void POP_Free(void);
void SnortPOP(SFSnortPacket *);
int  POP_IsServer(uint16_t);
void POP_FreeConfig(POPConfig *);
void POP_FreeConfigs(tSfPolicyUserContextId);

/**************************************************************************/

#endif  /* __POP_H__ */

