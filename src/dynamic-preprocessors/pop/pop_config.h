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
 * pop_config.h
 *
 * Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>
 *
 ***************************************************************************/

#ifndef __POP_CONFIG_H__
#define __POP_CONFIG_H__

#include "sfPolicyUserData.h"
#define CONF_SEPARATORS                  " \t\n\r"
#define CONF_PORTS                       "ports"
#define CONF_POP_MEMCAP                  "memcap"
#define CONF_B64_DECODE                  "b64_decode_depth"
#define CONF_QP_DECODE                   "qp_decode_depth"
#define CONF_BITENC_DECODE               "bitenc_decode_depth"
#define CONF_UU_DECODE                   "uu_decode_depth"
#define CONF_DISABLED                    "disabled"
#define CONF_START_LIST "{"
#define CONF_END_LIST   "}"

/*These are temporary values*/

#define DEFAULT_POP_MEMCAP            838860
#define DEFAULT_DEPTH                 1464
#define MAX_POP_MEMCAP                104857600
#define MIN_POP_MEMCAP                3276
#define MAX_DEPTH                     65535 
#define MIN_DEPTH                     -1 
#define POP_DEFAULT_SERVER_PORT       110  /* POP normally runs on port 110 */

#define ERRSTRLEN   512

typedef struct _POPSearch
{
    char *name;
    int   name_len;

} POPSearch;

typedef struct _POPToken
{
    char *name;
    int   name_len;
    int   search_id;

} POPToken;

typedef struct _POPCmdConfig
{
    char alert;          /*  1 if alert when seen                          */
    char normalize;      /*  1 if we should normalize this command         */
    int  max_line_len;   /*  Max length of this particular command         */

} POPCmdConfig;

typedef struct _POPConfig
{
    char  ports[8192];
    uint32_t   memcap;
    int max_depth;
    int b64_depth;
    int qp_depth;
    int bitenc_depth;
    int uu_depth;
    POPToken *cmds;
    POPCmdConfig *cmd_config;
    POPSearch *cmd_search;
    void *cmd_search_mpse;
    int num_cmds;
    int disabled;

    int ref_count;

} POPConfig;

/* Function prototypes  */
void POP_ParseArgs(POPConfig *, char *);
void POP_PrintConfig(POPConfig *config);

void POP_CheckConfig(POPConfig *, tSfPolicyUserContextId);
int POP_IsDecodingEnabled(POPConfig *);

#endif

