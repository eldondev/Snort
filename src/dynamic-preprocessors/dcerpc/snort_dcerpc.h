/*
 * snort_dcerpc.h
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
 * 
 * Description:
 *
 * Declares external routines that handle decoding SMB commands
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */
#ifndef _SNORT_SMB_H_
#define _SNORT_SMB_H_

#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "dcerpc_util.h"
#include "debug.h"
#include "bounds.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"

#ifdef TARGET_BASED
typedef struct _DCERPC_ProtoIds
{
    int16_t dcerpc;
    int16_t nbss;

} DCERPC_ProtoIds;

#define DCE_PROTO_REF_STR__DCERPC   "dcerpc"
#define DCE_PROTO_REF_STR__SMB      "smb"
#define DCE_PROTO_REF_STR__NBSS     "netbios-ssn"    /* This seems to be the name for SMB */
#endif  /* TARGET_BASED */

#ifdef WIN32
#pragma pack(push,snort_smb_hdrs,1)
#endif

/* Default maximum frag size, in bytes */
#define DEFAULT_MAX_FRAG_SIZE   3000
#define MAX_MAX_FRAG_SIZE       5840

/* Default maximum memory use, in KB */
#define DEFAULT_MEMCAP          100000

#define SMB_FRAGMENTATION       0x0001  /* SMB fragmentation     */
#define RPC_FRAGMENTATION       0x0002  /* DCE/RPC fragmentation */
#define SUSPEND_FRAGMENTATION   0x0004  /* Memcap reached, don't try to do more */

#define DCERPC_MIN_SEG_ALLOC_SIZE 100

#define STATE_START             0
#define STATE_GOT_TREE_CONNECT  1
#define STATE_GOT_NTCREATE      2   /* Or got SMB Open */
#define STATE_IS_DCERPC         3   /* Valid DCE/RPC session */

#define MAX_PORT_INDEX 65536 / 8

/* Convert port value into an index for the dns_config.ports array */
#define PORT_INDEX(port) port / 8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1 << (port % 8)

typedef struct _DceRpcConfig
{
    char SMBPorts[MAX_PORT_INDEX];
    char DCERPCPorts[MAX_PORT_INDEX];
    uint16_t max_frag_size;
    uint32_t memcap;
    uint8_t debug_print;
    uint8_t alert_memcap;
    uint8_t autodetect;
    uint8_t disable_smb_fragmentation;
    uint8_t disable_dcerpc_fragmentation;
    int reassemble_increment;

    int ref_count;

} DceRpcConfig;

typedef enum _DCERPC_TransType
{
    DCERPC_TRANS_TYPE__NONE = 0,
    DCERPC_TRANS_TYPE__SMB,
    DCERPC_TRANS_TYPE__DCERPC

} DCERPC_TransType;

typedef struct _DCERPC
{
    uint8_t    state;
    uint8_t    smb_state;
    uint8_t    fragmentation;
    DCERPC_Buffer dce_frag_buf;
    DCERPC_Buffer smb_seg_buf;
    DCERPC_Buffer tcp_seg_buf;

    int num_inc_reass;
    char autodetected;

    DCERPC_TransType trans;
    int no_inspect;

    tSfPolicyId policy_id;
    tSfPolicyUserContextId config;

} DCERPC;

#ifdef WIN32
#pragma pack(pop,snort_smb_hdrs,1)
#endif
    
int  DCERPCProcessConf(DceRpcConfig *, char *pcToken, char *ErrorString, int ErrStrLen);
int  DCERPCDecode(void *p);
void DCERPC_InitPacket(void);
SFSnortPacket * DCERPC_SetPseudoPacket(SFSnortPacket *p, const uint8_t *data, uint16_t data_len);
void * DCERPC_GetReassemblyPkt(void);
void DCERPC_Exit(void);
void DCERPC_EarlyFragReassemble(DCERPC *, const uint8_t *, uint16_t, uint16_t);
void DCERPC_BufferReassemble(DCERPC_Buffer *);

void DCERPC_BufferFreeData(DCERPC_Buffer *);
int DCERPC_BufferAddData(DCERPC *, DCERPC_Buffer *, const uint8_t *, uint16_t);
int DCERPC_BufferAlloc(DCERPC_Buffer *, uint16_t);
int DCERPC_IsMemcapExceeded(uint16_t);
void DceRpcFreeConfig(tSfPolicyUserContextId);

static INLINE int DCERPC_BufferIsEmpty(DCERPC_Buffer *);
static INLINE void DCERPC_BufferEmpty(DCERPC_Buffer *);

static INLINE int DCERPC_BufferIsEmpty(DCERPC_Buffer *sbuf)
{
    if ((sbuf == NULL) ||
        (sbuf->data == NULL) ||
        (sbuf->len == 0) ||
        (sbuf->size == 0))
    {
        return 1;
    }

    return 0;
}

static INLINE void DCERPC_BufferEmpty(DCERPC_Buffer *sbuf)
{
    if (sbuf == NULL)
        return;

    sbuf->len = 0;
}


#define GENERATOR_SMB 125
extern DynamicPreprocessorData _dpd;

#endif /* _SNORT_SMB_H_ */

