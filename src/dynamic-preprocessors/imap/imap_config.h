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

/***************************************************************************
 *
 * imap_config.h
 *
 * Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>
 *
 ***************************************************************************/

#ifndef __IMAP_CONFIG_H__
#define __IMAP_CONFIG_H__

#include "sfPolicyUserData.h"
#define CONF_SEPARATORS                  " \t\n\r"
#define CONF_PORTS                       "ports"
#define CONF_IMAP_MEMCAP                  "memcap"
#define CONF_B64_DECODE                  "b64_decode_depth"
#define CONF_QP_DECODE                   "qp_decode_depth"
#define CONF_BITENC_DECODE               "bitenc_decode_depth"
#define CONF_UU_DECODE                   "uu_decode_depth"
#define CONF_DISABLED                    "disabled"
#define CONF_START_LIST "{"
#define CONF_END_LIST   "}"

/*These are temporary values*/

#define DEFAULT_IMAP_MEMCAP            838860
#define DEFAULT_DEPTH                 1464
#define MAX_IMAP_MEMCAP                104857600
#define MIN_IMAP_MEMCAP                3276
#define MAX_DEPTH                     65535 
#define MIN_DEPTH                     -1 
#define IMAP_DEFAULT_SERVER_PORT       143  /* IMAP normally runs on port 143 */

#define ERRSTRLEN   512

typedef struct _IMAPSearch
{
    char *name;
    int   name_len;

} IMAPSearch;

typedef struct _IMAPToken
{
    char *name;
    int   name_len;
    int   search_id;

} IMAPToken;

typedef struct _IMAPCmdConfig
{
    char alert;          /*  1 if alert when seen                          */
    char normalize;      /*  1 if we should normalize this command         */
    int  max_line_len;   /*  Max length of this particular command         */

} IMAPCmdConfig;

typedef struct _IMAPConfig
{
    char  ports[8192];
    uint32_t   memcap;
    int max_depth;
    int b64_depth;
    int qp_depth;
    int bitenc_depth;
    int uu_depth;
    IMAPToken *cmds;
    IMAPCmdConfig *cmd_config;
    IMAPSearch *cmd_search;
    void *cmd_search_mpse;
    int num_cmds;
    int disabled;

    int ref_count;

} IMAPConfig;

/* Function prototypes  */
void IMAP_ParseArgs(IMAPConfig *, char *);
void IMAP_PrintConfig(IMAPConfig *config);

void IMAP_CheckConfig(IMAPConfig *, tSfPolicyUserContextId);
int IMAP_IsDecodingEnabled(IMAPConfig *);

#endif

