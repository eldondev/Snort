/*
 * smb_andx_decode.c
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
 * This performs the decoding of SMB AndX commands.
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif
#include <string.h>

#include "debug.h"
#include "bounds.h"

#include "snort_dcerpc.h"
#include "smb_structs.h"
#include "smb_andx_structs.h"
#include "smb_andx_decode.h"
#include "dcerpc_util.h"
#include "dcerpc.h"

#define FIELD_ACCT_NAME 0
#define FIELD_PRIM_DOMAIN 1
#define SESS_AUTH_FIELD(i) ((i == FIELD_ACCT_NAME) ? "AccountName" : ((i == FIELD_PRIM_DOMAIN) ? "PrimaryDomain"  : "Unknown"))

#define FIELD_NATIVE_OS 0
#define FIELD_NATIVE_LANMAN 1
#define SESS_NATIVE_FIELD(i) ((i == FIELD_NATIVE_OS) ? "NativeOS" : ((i == FIELD_NATIVE_LANMAN) ? "NativeLanMan" : "Unknown"))

/* Externs */
extern DCERPC         *_dcerpc;
extern SFSnortPacket  *_dcerpc_pkt;
extern uint8_t *dce_reassembly_buf;
extern uint16_t dce_reassembly_buf_size;
extern SFSnortPacket *real_dce_mock_pkt;
extern DceRpcConfig *dcerpc_eval_config;

static int GetSMBStringLength(uint8_t *data, uint16_t data_size, int unicode);

#ifdef DEBUG_DCERPC_PRINT
static void PrintSMBString(char *pre, uint8_t *str, uint16_t str_len, int unicode);
#endif

/* smb_data is guaranteed to be at least an SMB_WRITEX_REQ length away from writeX
 * if it's farther it's because there was padding */
void ReassembleSMBWriteX(uint8_t *smb_hdr, uint16_t smb_hdr_len)
{
    SMB_WRITEX_REQ *write_andx;
    int pkt_len;
    int status;
    uint16_t data_len = 0;
    DCERPC_Buffer *buf = &_dcerpc->smb_seg_buf;

    pkt_len = sizeof(NBT_HDR) + smb_hdr_len + buf->len;

    /* Make sure we have room to fit into reassembly buffer */
    if (pkt_len > dce_reassembly_buf_size)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Reassembled SMB packet greater "
                                "than %d bytes, skipping.", dce_reassembly_buf_size););

        /* just shorten it - don't want to lose all of
         * this information */
        buf->len = dce_reassembly_buf_size - (pkt_len - buf->len);
    }

    /* Copy headers into buffer */
    /* SMB Header */
    status = SafeMemcpy(dce_reassembly_buf, _dcerpc_pkt->payload, sizeof(NBT_HDR) + smb_hdr_len,
                        dce_reassembly_buf, dce_reassembly_buf + dce_reassembly_buf_size);

    if (status != SAFEMEM_SUCCESS)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "SMB header too big: %u, "
                                "skipping SMB reassembly.", dce_reassembly_buf_size););

        DCERPC_BufferFreeData(buf);
        return;
    }

    write_andx = (SMB_WRITEX_REQ *)((uint8_t *)dce_reassembly_buf + sizeof(NBT_HDR) + sizeof(SMB_HDR));
    write_andx->remaining = smb_htons(buf->len);
    write_andx->dataLength = smb_htons(buf->len);
    write_andx->dataOffset = smb_htons(smb_hdr_len);
    write_andx->andXCommand = 0xFF;
    write_andx->andXOffset = 0x0000;

    data_len = sizeof(NBT_HDR) + smb_hdr_len;
    
    status = SafeMemcpy(dce_reassembly_buf + data_len, buf->data, buf->len,
                        dce_reassembly_buf + data_len, dce_reassembly_buf + dce_reassembly_buf_size);

    if (status != SAFEMEM_SUCCESS)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "SMB fragments too big: %u, "
                                "skipping SMB reassembly.", dce_reassembly_buf_size););

        DCERPC_BufferFreeData(buf);
        return;
    }

    data_len += buf->len;

    /* create pseudo packet */
    real_dce_mock_pkt = DCERPC_SetPseudoPacket(_dcerpc_pkt, dce_reassembly_buf, data_len);
    if (real_dce_mock_pkt == NULL)
    {
        DCERPC_BufferFreeData(buf);
        return;
    }

    if (dcerpc_eval_config->debug_print)
    {
        PrintBuffer("SMB desegmented",
                    (uint8_t *)dce_reassembly_buf, data_len);
    }
}

/* IPC$ has to occur at the end of this path - path_len should include null termination */
static int IsIPC(uint8_t *path, int path_len, uint32_t isUnicode)
{
    const uint8_t ipc[] = {'I', 'P', 'C', '$', '\0'};
    const uint16_t ipc_len = 5;
    const uint8_t unicode_ipc[] = {'I', '\0', 'P', '\0', 'C', '\0', '$', '\0', '\0', '\0'};
    const uint16_t unicode_ipc_len = 10;

    if (isUnicode)
    {
        if (path_len < unicode_ipc_len)
            return 0;

        /* go to end of path then back up the length of the 
         * unicode_ipc string */
        path = (path + path_len) - unicode_ipc_len;

        if (memcmp(path, unicode_ipc, unicode_ipc_len) == 0)
            return 1;
    }
    else
    {
        if (path_len < ipc_len)
            return 0;

        /* go to end of path and back up the length of the
         * ipc string */
        path = (path + path_len) - ipc_len;

        if (memcmp(path, ipc, ipc_len) == 0)
            return 1;
    }
        
    return 0;
}

/* returns -1 if not null terminated 
 * returns -2 for other error
 * otherwise returns length of null terminated string
 * including null terminating bytes
 */
static int GetSMBStringLength(uint8_t *data, uint16_t data_size, int unicode)
{
    uint16_t size_left;

    if (data == NULL)
        return -2;

    size_left = data_size;

    if (unicode)
    {
        while (size_left >= sizeof(uni_char_t))
        {
            size_left -= sizeof(uni_char_t);

            if (*((uni_char_t *)data) == 0x0000)
            {
                return (int)(data_size - size_left);
            }

            data += sizeof(uni_char_t);
        }
    }
    else
    {
        while (size_left >= sizeof(char))
        {
            size_left -= sizeof(char);

            if (*((char *)data) == 0x00)
            {
                return (int)(data_size - size_left);
            }

            data += sizeof(char);
        }
    }

    return -1;
}

#ifdef DEBUG_DCERPC_PRINT
static void PrintSMBString(char *pre, uint8_t *str, uint16_t str_len, int unicode)
{
    if (pre == NULL || str == NULL || str_len == 0)
        return;

    printf("%s", pre);

    if (unicode)
    {
        int i = 0;

        while (i < str_len)
        {
            printf("%c", str[i]);
            i += sizeof(uni_char_t);
        }
    }
    else
    {
        printf("%.*s", str_len, str);
    }

    printf("\n");
}
#endif

int SkipBytes(uint8_t *data, uint16_t size)
{
    uint16_t i = 0;

    while ( i < size && *data != 0 )
    {
        data++;
        i++;
    }

    return i;
}

int SkipBytesWide(uint8_t *data, uint16_t size)
{
    uint16_t i = 0;

    /* Check against size-1 in case someone is screwing with us and giving
         us an odd number of bytes for 2-byte Unicode.  */
    while ( i < (size - 1) && *data != 0 )
    {
        data += 2;
        i += 2;
    }

    return i;
}


int ProcessSMBTreeConnXReq(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size)
{
    SMB_TREE_CONNECTX_REQ *treeConnX;
    uint16_t byteCount;
    uint8_t *tree_data;
    uint16_t tree_data_len;
    uint8_t *passwd_ptr;
    uint16_t passwd_len;
    uint8_t *path_ptr;
    int path_len;
    uint8_t *service_ptr;
    int service_len;
    int is_ipc;

    if ( size <= sizeof(SMB_TREE_CONNECTX_REQ) )
    {
        return 0;
    }

    treeConnX = (SMB_TREE_CONNECTX_REQ *)data;
    
    size -= sizeof(SMB_TREE_CONNECTX_REQ);
    tree_data = data + sizeof(SMB_TREE_CONNECTX_REQ);

    byteCount = smb_ntohs(treeConnX->byteCount);
    tree_data_len = byteCount;
    passwd_len = smb_ntohs(treeConnX->passwdLen);

    /* Sanity check */
    if ( byteCount > size || passwd_len >= byteCount)
        return 0;

    passwd_ptr = tree_data;
    tree_data += passwd_len;
    tree_data_len -= passwd_len;

    /* Get path */
    path_len = GetSMBStringLength(tree_data, tree_data_len, HAS_UNICODE_STRINGS(smbHdr));
    if (path_len == -1 || path_len == tree_data_len)
        return 0;

    path_ptr = tree_data;

    is_ipc = IsIPC(tree_data, path_len, HAS_UNICODE_STRINGS(smbHdr));

    if (is_ipc && _dcerpc->smb_state == STATE_START)
    {
        _dcerpc->smb_state = STATE_GOT_TREE_CONNECT;
    }

    tree_data += path_len;
    tree_data_len -= path_len;

    /* Service field is ALWAYS ascii */
    service_len = GetSMBStringLength(tree_data, tree_data_len, 0);
    if (service_len == -1)
        return 0;

    service_ptr = tree_data;

    /* there shouldn't be any more data */
    if (tree_data + service_len != tree_data + tree_data_len)
        return 0;

#ifdef DEBUG_DCERPC_PRINT
    /* Password data 
     * it seems like the password length has to be an odd number
     * This passwd will always be ASCII -- equiv of
     * CaseInsensitivePasswd field from SessSetupAndX message */
    if (passwd_len > 0)
        printf("Password: %02.*X\n", passwd_len, passwd_ptr);

    if (path_len > 0)
        PrintSMBString("Path: ", path_ptr, path_len, HAS_UNICODE_STRINGS(smbHdr));

    /* Service field is ALWAYS ascii */
    if (service_len > 0)
        PrintSMBString("Service: ", service_ptr, service_len, 0);
#endif

    /* put tree_data at end of this request for comparing
     * against andXOffset */
    tree_data += tree_data_len;

    /* Handle next andX command in this packet */
    if (treeConnX->andXCommand != SMB_NONE)
    {
        uint16_t andXOffset = smb_ntohs(treeConnX->andXOffset);
        uint8_t *next_command;
        uint16_t data_left_len;

        if ( andXOffset >= total_size )
            return 0;

        next_command = (uint8_t *)smbHdr + andXOffset;
     
        /* Make sure we don't backtrack or look at the same data again */
        if (next_command < tree_data)
            return 0;

        /* Skip header, get size of remaining data */
        data_left_len = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(treeConnX->andXCommand, smbHdr, next_command,
                                     data_left_len, total_size);        
    }

    return 0;
}


int ProcessSMBNTCreateX(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size)
{
    SMB_NTCREATEX_REQ *ntCreateX;
    uint16_t byteCount;
    uint8_t *nt_create_data;
    uint16_t nt_create_data_len;
    uint8_t *file_name_ptr;
    int file_name_len;

    if ( size <= sizeof(SMB_NTCREATEX_REQ) )
    {
        return 0;
    }

    ntCreateX = (SMB_NTCREATEX_REQ *)data;

    size -= sizeof(SMB_NTCREATEX_REQ);

    byteCount = smb_ntohs(ntCreateX->byteCount);

    if (byteCount > size)
        return 0;

    nt_create_data = data + sizeof(SMB_NTCREATEX_REQ);
    nt_create_data_len = byteCount;

    /* Appears to be a pad in there to word-align if unicode */
    if (HAS_UNICODE_STRINGS(smbHdr))
    {
        nt_create_data++;
        nt_create_data_len--;
    }

    /* note that the file name length in the header does not seem
     * to be used by the server */
    file_name_len = GetSMBStringLength(nt_create_data, nt_create_data_len,
                                       HAS_UNICODE_STRINGS(smbHdr));

    if (file_name_len == -1)
        return 0;

    file_name_ptr = nt_create_data;

    /* there shouldn't be any more data */
    if (nt_create_data + file_name_len != nt_create_data + nt_create_data_len)
        return 0;

    if ( _dcerpc->smb_state == STATE_GOT_TREE_CONNECT )
        _dcerpc->smb_state = STATE_GOT_NTCREATE;

#ifdef DEBUG_DCERPC_PRINT
    PrintSMBString("Create/Open: ", file_name_ptr, file_name_len, HAS_UNICODE_STRINGS(smbHdr));
#endif

    /* put nt_create_data at end of this request for comparing
     * against andXOffset */
    nt_create_data += nt_create_data_len;

    /* Handle next andX command in this packet */
    if (ntCreateX->andXCommand != SMB_NONE)
    {
        uint16_t andXOffset = smb_ntohs(ntCreateX->andXOffset);
        uint8_t *next_command;
        uint16_t data_left_len;

        if ( andXOffset >= total_size )
            return 0;
       
        next_command = (uint8_t *)smbHdr + andXOffset;

        /* Make sure we don't backtrack or look at the same data again */
        if (next_command < nt_create_data)
            return 0;

        /* Skip header, get size of remaining data */
        data_left_len = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(ntCreateX->andXCommand, smbHdr, next_command,
                                     data_left_len, total_size);
    }

    return 0;
}

int ProcessSMBWriteX(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size)
{
    SMB_WRITEX_REQ *writeX;
    uint8_t *writeX_data;
    uint16_t writeX_data_len;
    uint16_t writeX_byte_count;
    uint16_t data_offset;
    uint16_t padding;

    /* Only process WriteAndX packet if it is part of a DCE/RPC session */
    if ( _dcerpc->smb_state != STATE_GOT_NTCREATE )
    {
        return 0;
    }

    if ( size <= sizeof(SMB_WRITEX_REQ) )
    {
        return 0;
    }

    writeX = (SMB_WRITEX_REQ *)data;
    data_offset = smb_ntohs(writeX->dataOffset);

    if ( data_offset >= total_size )
    {
        return 0;
    }

    writeX_data = (uint8_t *)smbHdr + data_offset;
    writeX_data_len = smb_ntohs(writeX->dataLength);
    writeX_byte_count = smb_ntohs(writeX->byteCount);

    /* byte count is always greater than or equal to data length and
     * accounts for extra padding at end of header and before actual data */
    if (writeX_data_len > writeX_byte_count)
        return 0; 

    padding = writeX_byte_count - writeX_data_len;

    /* data_offset put us somewhere before the end of the header and padding */
    if (writeX_data < (uint8_t *)writeX + sizeof(SMB_WRITEX_REQ) + padding)
        return 0;

    /* data_offset + data_len will put us past end of packet */
    if (writeX_data + writeX_data_len > (uint8_t *)smbHdr + total_size)
        return 0;

#ifdef DEBUG_DCERPC_PRINT
    if (writeX_data_len > 0)
        printf("WriteAndX data: %02.*X\n", writeX_data_len, writeX_data);
#endif

    if (writeX_data_len > 0)
    {
        uint16_t smb_hdr_len = writeX_data - (uint8_t *)smbHdr;
        DCERPC_Buffer *sbuf = &_dcerpc->smb_seg_buf;
        int status = ProcessDCERPCMessage((uint8_t *)smbHdr, smb_hdr_len, writeX_data, writeX_data_len);

        if (status == -1)
            return -1;

        if ((status == DCERPC_FULL_FRAGMENT) && !DCERPC_BufferIsEmpty(sbuf))
        {
            ReassembleSMBWriteX((uint8_t *)smbHdr, smb_hdr_len);
            DCERPC_BufferFreeData(sbuf);
        }
        else if ((status == DCERPC_SEGMENTED) && dcerpc_eval_config->reassemble_increment)
        {
            _dcerpc->num_inc_reass++;
            if (dcerpc_eval_config->reassemble_increment == _dcerpc->num_inc_reass)
            {
                _dcerpc->num_inc_reass = 0;
                ReassembleSMBWriteX((uint8_t *)smbHdr, smb_hdr_len);
            }
        }
    }

    /* put dce_data at end of this request for comparing
     * against andXOffset */
    writeX_data += writeX_data_len;

    /* Handle next andX command in this packet */
    if (writeX->andXCommand != SMB_NONE)
    {
        uint16_t andXOffset = smb_ntohs(writeX->andXOffset);
        uint8_t *next_command;
        uint16_t data_left_len;

        if ( andXOffset >= total_size )
            return 0;

        next_command = (uint8_t *)smbHdr + andXOffset;

        /* Make sure we don't backtrack or look at the same data again */
        if (next_command < writeX_data)
            return 0;

        /* Skip WriteX header, get size of remaining data */
        data_left_len = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(writeX->andXCommand, smbHdr, next_command,
                                     data_left_len, total_size);
    }

    return 0;
}

int ProcessSMBTransaction(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size)
{
    SMB_TRANS_REQ  *trans;
    uint8_t  *dcerpc_data;
    uint16_t dcerpc_data_len;
    uint16_t data_offset;

    /* Only process Trans packet if we think it is part of a DCE/RPC session 
       NTCREATE state is when we get the bind packet
       IS_DCERPC is when we get a request packet 
     */
    if ( _dcerpc->smb_state != STATE_GOT_NTCREATE )
    {
        return 0;
    }

    /* We got a Tree Connect followed by a NTCreate, followed by Trans.  
       Assume DCE/RPC */
    _dcerpc->state = STATE_IS_DCERPC;

    if ( size <= sizeof(SMB_TRANS_REQ) )
    {
        return 0;
    }

    trans = (SMB_TRANS_REQ *)data;
    data_offset = smb_ntohs(trans->dataOffset);
    dcerpc_data = (uint8_t *)smbHdr + data_offset;

    if ( data_offset >= total_size )
        return 0;

    /* offset didn't put us after header
     * TODO Account for transaction name length - seems like
     * for unicode strings there is an extra byte of padding
     * after byteCount before name starts */
    if (dcerpc_data < (uint8_t *)trans + sizeof(SMB_TRANS_REQ))
        return 0;

    dcerpc_data_len = smb_ntohs(trans->totalDataCount);

    /* make sure data length doesn't put us past end of packet */
    if (dcerpc_data + dcerpc_data_len > (uint8_t *)smbHdr + total_size)
        return 0;

    if (dcerpc_data_len > 0)
        ProcessDCERPCMessage((uint8_t *)smbHdr,
		                     (uint16_t)(dcerpc_data - (uint8_t *)smbHdr),
		                     dcerpc_data, dcerpc_data_len);

#ifdef DEBUG_DCERPC_PRINT
    printf("Trans data: %02.*X\n", dcerpc_data_len, dcerpc_data);
#endif

    return 0;
}

int ProcessSMBReadX(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size)
{
    SMB_READX_REQ *readX;

    if ( size < sizeof(SMB_READX_REQ) )
    {
        return 0;
    }

    readX = (SMB_READX_REQ *)data;
    data += sizeof(SMB_READX_REQ);

    /* Handle next andX command in this packet */
    if (readX->andXCommand != SMB_NONE)
    {
        uint16_t andXOffset = smb_ntohs(readX->andXOffset);
        uint8_t *next_command;
        uint16_t data_left_len;

        if ( andXOffset >= total_size )
            return 0;
       
        next_command = (uint8_t *)smbHdr + andXOffset;

        /* Make sure we don't backtrack or look at the same data again */
        if (next_command < data)
            return 0;

        /* Skip ReadX header, get size of remaining data */
        data_left_len = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(readX->andXCommand, smbHdr, next_command,
                                     data_left_len, total_size);        
    }

    return 0;
}


#ifdef UNUSED_SMB_COMMAND

int ProcessSMBSetupXReq(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size)
{
    int extraIndex = 0;
    SMB_SESS_SETUPX_REQ_HDR *sess_setupx_req_hdr;

    /* Ptr to first null terminated data element */
    unsigned char wordCount;
    /* Skip the common header portion, wordCount byte + parameter bytes * 2 */
    unsigned char *smb_data;
    short byteCount = 0, extraBytes = 0;
    int skipBytes = 1;

    int passwdLen = 0;
    char unicodePasswd = 0;

    if ( size <= sizeof(SMB_SESS_SETUPX_REQ_HDR) )
    {
        return 0;
    }

    sess_setupx_req_hdr = (SMB_SESS_SETUPX_REQ_HDR *)data;
    wordCount = sess_setupx_req_hdr->wordCount;

    switch (wordCount)
    {
    case 10:
        {
            /* Old session setup andx */
            SMB_SESS_SETUPX_REQ_AUTH_OLD *sess_setupx_auth = 
                (SMB_SESS_SETUPX_REQ_AUTH_OLD *)
                (data + sizeof(SMB_SESS_SETUPX_REQ_HDR));
            passwdLen = smb_ntohs(sess_setupx_auth->passwdLen);
            byteCount = extraBytes = smb_ntohs(sess_setupx_auth->byteCount);
            smb_data = data + sizeof(SMB_SESS_SETUPX_REQ_HDR) +
                sizeof(SMB_SESS_SETUPX_REQ_AUTH_OLD);
        }
        break;
    case 12:
        {
            /* Extended Security session setup andx */
            SMB_SESS_SETUPX_REQ_AUTH_NTLM12 *sess_setupx_auth =
                (SMB_SESS_SETUPX_REQ_AUTH_NTLM12 *)
                (data + sizeof(SMB_SESS_SETUPX_REQ_HDR));
            passwdLen = 0; /* Its a blob */
            byteCount = extraBytes = smb_ntohs(sess_setupx_auth->byteCount);
            skipBytes = smb_ntohs(sess_setupx_auth->secBlobLength);
            smb_data = data + sizeof(SMB_SESS_SETUPX_REQ_HDR) +
                sizeof(SMB_SESS_SETUPX_REQ_AUTH_NTLM12);
        }
        break;
    case 13:
        {
            /* Non-Extended Security session setup andx */
            SMB_SESS_SETUPX_REQ_AUTH_NTLM12_NOEXT *sess_setupx_auth =
                (SMB_SESS_SETUPX_REQ_AUTH_NTLM12_NOEXT *)
                (data + sizeof(SMB_SESS_SETUPX_REQ_HDR));
            if (sess_setupx_auth->passwdLen)
            {
                passwdLen = smb_ntohs(sess_setupx_auth->passwdLen);
                unicodePasswd = 1;
            }
            else if (sess_setupx_auth->iPasswdLen)
            {
                passwdLen = smb_ntohs(sess_setupx_auth->iPasswdLen);
            }
            byteCount = extraBytes = smb_ntohs(sess_setupx_auth->byteCount);
            smb_data = data + sizeof(SMB_SESS_SETUPX_REQ_HDR) +
                sizeof(SMB_SESS_SETUPX_REQ_AUTH_NTLM12_NOEXT);
        }
        break;
    default:
        return -1;
        break;
    }

    size -= sizeof(SMB_SESS_SETUPX_REQ_HDR);

    /* Password data */
    if (passwdLen)
    {
        int i=0;
        if ( unicodePasswd )
        {
#ifdef DEBUG_DCERPC_PRINT
            /* UNICODE Password */
            wprintf(L"Case Sensitive Password: %.*s\n", passwdLen, smb_data);
#endif
            /* Skip past the password -- no terminating NULL */
            smb_data += passwdLen;
            extraBytes -= passwdLen;

            /* Jump past the pad that re-aligns the next fields */
            if (HAS_UNICODE_STRINGS(smbHdr))
            {
                smb_data += 1;
                extraBytes -= 1;
            }
        }
        else
        {
#ifdef DEBUG_DCERPC_PRINT           
            /* ASCII Password */
            printf("Case Insensitive Password: %.*s\n", passwdLen, smb_data);
#endif
            /* Skip past the password -- no terminating NULL */
            smb_data += passwdLen;
            extraBytes -= passwdLen;

            /* Jump past the pad that re-aligns the next fields -- pad
             * is present when ascii password is an even # of bytes. */
            if (HAS_UNICODE_STRINGS(smbHdr) &&
                (passwdLen %2 == 0))
            {
                smb_data += 1;
                extraBytes -= 1;
            }       
        }

        for (i=0;i<2;i++)
        {
            skipBytes = 1;
            if (HAS_UNICODE_STRINGS(smbHdr))
            {
                if (*smb_data != '\0')
                {
#ifdef DEBUG_DCERPC_PRINT
                    printf("%s: ", SESS_AUTH_FIELD(extraIndex));
                    wprintf(L"%s\n", smb_data);
#endif
                    skipBytes = SkipBytesWide(smb_data, size) + 2;
                }
            }
            else
            {
                if (*smb_data != '\0')
                {
#ifdef DEBUG_DCERPC_PRINT
                    printf("%s: %s\n", SESS_AUTH_FIELD(extraIndex), smb_data);
#endif
                    skipBytes = SkipBytes(smb_data, size) + 1;
                }
            }
            extraIndex++;
            smb_data += skipBytes;
            extraBytes -= skipBytes;
        }
    }
    else
    {
#ifdef DEBUG_DCERPC_PRINT
        /* The security blob... */
        int i;
        printf("Security blob... ");
        for (i=0;i<skipBytes;i++)
        {
            if ( isascii((int)smb_data[i]) && isprint((int)smb_data[i]) )
                printf("%c ", smb_data[i]);
            else
                printf("%.2x ", smb_data[i]);
        }
        printf("\n");
#endif
        smb_data += skipBytes;
        extraBytes -= skipBytes;

        /* Jump past the NULL Pad (ie fields following are word aligned) */
        if (skipBytes%2 == 0)
        {
            smb_data += 1;
            extraBytes -= 1;
        }

    }

    extraIndex = 0;

    /* Some extra data */
    while (extraBytes > 0)
    {
        skipBytes = 1;
        if (HAS_UNICODE_STRINGS(smbHdr))
        {
            if (*smb_data != '\0')
            {
#ifdef DEBUG_DCERPC_PRINT                
                printf("%s: ", SESS_NATIVE_FIELD(extraIndex));
                wprintf(L"%s\n", smb_data);
#endif
                skipBytes = wcslen(smb_data) + 1;
            }
            skipBytes *= 2;
        }
        else
        {
            if (*smb_data != '\0')
            {
#ifdef DEBUG_DCERPC_PRINT
                printf("%s: %s\n", SESS_NATIVE_FIELD(extraIndex), smb_data);
#endif
                skipBytes = strlen(smb_data) + 1;
            }
        }
        extraIndex++;
        smb_data += skipBytes;
        extraBytes -= skipBytes;
    }

    /* Handle next andX command in this packet */
    if (sess_setupx_req_hdr->andXCommand != SMB_NONE)
    {
        uint16_t data_size;
        uint16_t andXOffset = smb_ntohs(sess_setupx_req_hdr->andXOffset);

        if ( andXOffset >= total_size )
            return 0;
       
        /* Make sure we don't backtrack or look at the same data again */
        if ( andXOffset <= (data - (uint8_t *)smbHdr) )
            return 0;

        /* Skip header, get size of remaining data */
        data_size = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(sess_setupx_req_hdr->andXCommand, smbHdr,
            (uint8_t *)smbHdr + smb_ntohs(sess_setupx_req_hdr->andXOffset), data_size, total_size);        
    }

    return 0;
}


int ProcessSMBLogoffXReq(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size)
{
    SMB_LOGOFFX_REQ *logoffX;
    int              byteCount;

    if (byteCount > 0)
    {
        return -1;
    }

    if ( size < sizeof(SMB_LOGOFFX_REQ) )
    {
        return 0;
    }

    logoffX = (SMB_LOGOFFX_REQ *)data;
    byteCount = smb_ntohs(logoffX->byteCount);

    /* Handle next andX command in this packet */
    if (logoffX->andXCommand != SMB_NONE)
    {
        uint16_t data_size;
        uint16_t andXOffset = smb_ntohs(logoffX->andXOffset);

        if ( andXOffset >= total_size )
            return 0;
       
        /* Make sure we don't backtrack or look at the same data again */
        if ( andXOffset <= (data - (uint8_t *)smbHdr) )
            return 0;

        /* Skip header, get size of remaining data */
        data_size = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(logoffX->andXCommand, smbHdr,
            (uint8_t *)smbHdr + smb_ntohs(logoffX->andXOffset), data_size, total_size);        
    }

    return 0;
}




int ProcessSMBLockingX(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size)
{
    SMB_LOCKINGX_REQ *lockingX;
    unsigned char *smb_data;
    uint16_t numUnlocks;
    uint16_t numLocks;
    int lockRangeSize;

    if ( size < sizeof(SMB_LOCKINGX_REQ) )
    {
        return 0;
    }

    lockingX = (SMB_LOCKINGX_REQ *)data;
    smb_data = data + sizeof(SMB_LOCKINGX_REQ);
    numUnlocks = smb_ntohs(lockingX->numUnlocks);
    numLocks = smb_ntohs(lockingX->numLocks);

    if (lockingX->lockType & LOCKINGX_LARGE_FILES)
    {
        lockRangeSize = sizeof(SMB_LARGEFILE_LOCKINGX_RANGE);
#ifdef DEBUG_DCERPC_PRINT
        if (numUnlocks > 0)
        {
            int i;
            printf("Unlocking PIDs: ");
            for (i=0;i<numUnlocks;i++)
            {
                SMB_LARGEFILE_LOCKINGX_RANGE *lock =
                    (SMB_LARGEFILE_LOCKINGX_RANGE *)(smb_data + 
                    lockRangeSize * i);
                printf("%d ", lock->pid);
            }
            printf("\n");
        }

        if (numLocks > 0)
        {
            int i;
            printf("Locking PIDs: ");
            for (i=0;i<numLocks;i++)
            {
                SMB_LARGEFILE_LOCKINGX_RANGE *lock =
                    (SMB_LARGEFILE_LOCKINGX_RANGE *)(smb_data + 
                    lockRangeSize * numUnlocks+ 
                    lockRangeSize * i);
                printf("%d ", lock->pid);
            }
            printf("\n");
        }
#endif
    }
    else
    {
        lockRangeSize = sizeof(SMB_LOCKINGX_RANGE);
#ifdef DEBUG_DCERPC_PRINT
        if (numUnlocks > 0)
        {
            printf("Unlocking PIDs: ");
            for (i=0;i<numUnlocks;i++)
            {
                SMB_LOCKINGX_RANGE *lock =
                    (SMB_LOCKINGX_RANGE *)(smb_data + 
                    lockRangeSize * i);
                printf("%d ", lock->pid);
            }
            printf("\n");
        }

        if (numLocks > 0)
        {
            printf("Locking PIDs: ");
            for (i=0;i<numLocks;i++)
            {
                SMB_LOCKINGX_RANGE *lock =
                    (SMB_LOCKINGX_RANGE *)(smb_data + 
                    lockRangeSize * numUnlocks+ 
                    lockRangeSize * i);
                printf("%d ", lock->pid);
            }
            printf("\n");
        }
#endif
    }
    
    /* Handle next andX command in this packet */
    if (lockingX->andXCommand != SMB_NONE)
    {
        uint16_t data_size;
        uint16_t andXOffset = smb_ntohs(lockingX->andXOffset);

        if ( andXOffset >= total_size )
            return 0;
       
        /* Make sure we don't backtrack or look at the same data again */
        if ( andXOffset <= (data - (uint8_t *)smbHdr) )
            return 0;

        /* Skip header, get size of remaining data */
        data_size = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(lockingX->andXCommand, smbHdr,
            (uint8_t *)smbHdr + smb_ntohs(lockingX->andXOffset), data_size, total_size);        
    }

    return 0;
}



#endif /*  UNUSED_SMB_COMMAND */

