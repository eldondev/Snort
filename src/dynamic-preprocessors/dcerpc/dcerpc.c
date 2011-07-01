/*
 * dcerpc.c
 *
 * Copyright (C) 2006-2009 Sourcefire, Inc.
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
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif

#include "debug.h"
#include "sf_snort_packet.h"
#include "bounds.h"

#include "smb_structs.h"
#include "snort_dcerpc.h"
#include "dcerpc_util.h"
#include "dcerpc.h"

#define SEG_BUF_SIZE  100000

typedef enum _DCERPC_FragType
{
    DCERPC_FRAG_TYPE__FULL,
    DCERPC_FRAG_TYPE__FRAG,
    DCERPC_FRAG_TYPE__LAST,
    DCERPC_FRAG_TYPE__ERROR

} DCERPC_FragType;

extern DCERPC         *_dcerpc;
extern SFSnortPacket  *_dcerpc_pkt;
extern uint8_t *dce_reassembly_buf;
extern uint16_t dce_reassembly_buf_size;
extern SFSnortPacket *real_dce_mock_pkt;
extern DceRpcConfig *dcerpc_eval_config;

/* Check to see if we have a full DCE/RPC fragment
 * Guarantees:
 *  There is enough data to slap header on and grab fields from
 *  Is most likely a DCE/RPC packet
 *  DCE/RPC fragment length is greater than the size of request header
 *  DCE/RPC fragment length is less than or equal to size of data remaining
 */
int IsCompleteDCERPCMessage(const uint8_t *data, uint16_t size)
{
    const DCERPC_HDR *dcerpc;
    uint16_t       frag_length;

    if (size < sizeof(DCERPC_REQ))
        return 0;

    /* Check to see if this is a valid DCE/RPC packet */
    dcerpc = (const DCERPC_HDR *) data;

    /*  Check for version and packet type - mark as DCERPC session */
    if ((dcerpc->version != 5) || 
        ((dcerpc->packet_type != DCERPC_REQUEST) && (dcerpc->packet_type != DCERPC_BIND)))
    {
        return 0;
    }

    frag_length = dcerpc_ntohs(dcerpc->byte_order, dcerpc->frag_length);

    if (frag_length < sizeof(DCERPC_REQ))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Error: DCERPC frag length <= size of request header.\n"););
        return 0;
    }

    /* Wait until we have the whole DCE/RPC message */
    if ( frag_length > size )
        return 0;
    
    return 1;
}

/* Return 1 if successfully parsed at least one message */
int ProcessDCERPCMessage(const uint8_t *smb_hdr, uint16_t smb_hdr_len, const uint8_t *data, uint16_t size)
{
    uint16_t current_size = size;
    const uint8_t *current_data = data;
    uint16_t opnum = 0;
    DCERPC_Buffer *sbuf;

    if (_dcerpc->trans == DCERPC_TRANS_TYPE__DCERPC)
        sbuf = &_dcerpc->tcp_seg_buf;
    else
        sbuf = &_dcerpc->smb_seg_buf;

    if (!DCERPC_BufferIsEmpty(sbuf))
    {
        if (DCERPC_BufferAddData(_dcerpc, sbuf, current_data, current_size) == -1)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to add data to seg buf\n"););
            _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;
            DCERPC_BufferFreeData(sbuf);
            return -1;
        }

        if (!IsCompleteDCERPCMessage(sbuf->data, sbuf->len))
            return DCERPC_SEGMENTED;

        current_data = sbuf->data;
        current_size = sbuf->len;
    }
    else if (!IsCompleteDCERPCMessage(current_data, current_size))
    {
        if (DCERPC_BufferAddData(_dcerpc, sbuf, current_data, current_size) == -1)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to add data to seg buf\n"););
            _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;
            DCERPC_BufferFreeData(sbuf);
            return -1;
        }

        return DCERPC_SEGMENTED;
    }
    
    /* Check fragmentation - got at least one full fragment */
    while (current_size > 0)
    {
        const DCERPC_HDR *dcerpc = (DCERPC_HDR *) current_data;
        uint16_t frag_length = dcerpc_ntohs(dcerpc->byte_order, dcerpc->frag_length);
        DCERPC_FragType frag_type = DCERPC_FRAG_TYPE__FULL;

        if (dcerpc->packet_type != DCERPC_REQUEST)
            return DCERPC_FULL_FRAGMENT;

        if (current_size >= sizeof(DCERPC_REQ))
        {
            DCERPC_REQ *dce_req = (DCERPC_REQ *)current_data;
            opnum = dce_req->opnum;
        }

        if (frag_length > sizeof(DCERPC_REQ))
        {
            frag_type = DCERPC_Fragmentation(current_data, (uint16_t)current_size, frag_length);
            if (frag_type == DCERPC_FRAG_TYPE__LAST)
            {
                ReassembleDCERPCRequest(smb_hdr, smb_hdr_len, current_data);

                if (!DCERPC_BufferIsEmpty(sbuf))
                    DCERPC_BufferEmpty(sbuf);

                if (!DCERPC_BufferIsEmpty(&_dcerpc->dce_frag_buf))
                    DCERPC_BufferEmpty(&_dcerpc->dce_frag_buf);

                return DCERPC_FRAG_REASSEMBLED;
            }
            else if (frag_type == DCERPC_FRAG_TYPE__ERROR)
            {
                return -1;
            }
        }

        if (frag_type == DCERPC_FRAG_TYPE__FULL)
            return DCERPC_FULL_FRAGMENT;

        current_size -= frag_length;
        current_data += frag_length;

        /* see if we have another full fragment in this packet */
        if (!IsCompleteDCERPCMessage(current_data, current_size))
            break;
    }

    if (!DCERPC_BufferIsEmpty(sbuf))
    {
        if (current_size != 0)
        {
            int status = SafeMemmove(sbuf->data, current_data, current_size,
                                     sbuf->data, sbuf->data + sbuf->size);

            if (status != SAFEMEM_SUCCESS)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to move data in seg buf\n"););
                _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;
                DCERPC_BufferFreeData(sbuf);
                return -1;
            }

            sbuf->len = current_size;
        }
        else
        {
            DCERPC_BufferEmpty(sbuf);
        }
    }
    else if (current_size != 0)
    {
        if (DCERPC_BufferAddData(_dcerpc, sbuf, current_data, current_size) == -1)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to add data to seg buf\n"););
            _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;
            DCERPC_BufferFreeData(sbuf);
            return -1;
        }
    }

    if (dcerpc_eval_config->reassemble_increment)
        DCERPC_EarlyFragReassemble(_dcerpc, smb_hdr, smb_hdr_len, opnum);

    return DCERPC_FRAGMENT;
}


/*
    Return  0 if not fragmented OR if fragmented and not last fragment
    Return  1 if fragmented and last fragment
 */


int DCERPC_Fragmentation(const uint8_t *data, uint16_t data_size, uint16_t frag_length)
{
    DCERPC_HDR     *dcerpc_hdr;
    DCERPC_Buffer *buf = &_dcerpc->dce_frag_buf;

    if (data_size <= sizeof(DCERPC_REQ))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Error: Not a DCERPC request.\n"););
        return DCERPC_FRAG_TYPE__ERROR;
    }

    dcerpc_hdr = (DCERPC_HDR *) data;

    if ((dcerpc_hdr->flags & DCERPC_FIRST_FRAG) &&
        (dcerpc_hdr->flags & DCERPC_LAST_FRAG))
    {
        if (!DCERPC_BufferIsEmpty(buf))
            DCERPC_BufferFreeData(buf);

        return DCERPC_FRAG_TYPE__FULL;
    }

    if (frag_length <= sizeof(DCERPC_REQ))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Invalid frag length in DCERPC request.\n"););
        return DCERPC_FRAG_TYPE__ERROR;
    }

    frag_length -= sizeof(DCERPC_REQ);
    data += sizeof(DCERPC_REQ);
    data_size -= sizeof(DCERPC_REQ);

    if (frag_length > dcerpc_eval_config->max_frag_size)
        frag_length = dcerpc_eval_config->max_frag_size;

    if (DCERPC_BufferAddData(_dcerpc, buf, data, frag_length) == -1)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to add data to frag buf\n"););
        _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;
        DCERPC_BufferFreeData(buf);
        return DCERPC_FRAG_TYPE__ERROR;
    }

    if (dcerpc_eval_config->debug_print)
        PrintBuffer("DCE/RPC current frag reassembly buffer", buf->data, buf->len);

    if (dcerpc_hdr->flags & DCERPC_LAST_FRAG)
        return DCERPC_FRAG_TYPE__LAST;

    return DCERPC_FRAG_TYPE__FRAG;
}

void ReassembleDCERPCRequest(const uint8_t *smb_hdr, uint16_t smb_hdr_len, const uint8_t *data)
{
    int pkt_len;
    DCERPC_REQ fake_req;
    unsigned int dcerpc_req_len = sizeof(DCERPC_REQ);
    int status;
    uint16_t data_len = 0;
    DCERPC_Buffer *buf = &_dcerpc->dce_frag_buf;

    /* Make sure we have room to fit into buffer */
    if (smb_hdr != NULL)
        pkt_len = sizeof(NBT_HDR) + smb_hdr_len + dcerpc_req_len + buf->len;
    else
        pkt_len = dcerpc_req_len + buf->len;

    if (pkt_len > dce_reassembly_buf_size)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Reassembled DCE/RPC packet "
                                "greater than %d bytes, skipping.\n", dce_reassembly_buf_size));

        /* just shorten it - don't want to lose all of
         * this information */
        buf->len = dce_reassembly_buf_size - (pkt_len - buf->len);
    }

    /* Mock up header */
    status = SafeMemcpy(&fake_req, data, dcerpc_req_len,
                        &fake_req, (uint8_t *)&fake_req + dcerpc_req_len);
    
    if (status != SAFEMEM_SUCCESS)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to copy DCERPC header, "
                                "skipping DCERPC reassembly.\n"));

        DCERPC_BufferFreeData(buf);
        return;
    }

    fake_req.dcerpc_hdr.frag_length =
        dcerpc_htons(fake_req.dcerpc_hdr.byte_order, dcerpc_req_len + buf->len);
    fake_req.dcerpc_hdr.flags |= (DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG);
    fake_req.alloc_hint = dcerpc_htonl(fake_req.dcerpc_hdr.byte_order, buf->len);

    if (smb_hdr != NULL)
    {
        status = SafeMemcpy(dce_reassembly_buf, _dcerpc_pkt->payload, sizeof(NBT_HDR),
                            dce_reassembly_buf, dce_reassembly_buf + dce_reassembly_buf_size);

        if (status != SAFEMEM_SUCCESS)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to copy DCERPC header, "
                                    "skipping DCERPC reassembly.\n"););

            DCERPC_BufferFreeData(buf);
            return;
        }

        data_len += sizeof(NBT_HDR);

        status = SafeMemcpy(dce_reassembly_buf + data_len,
                            smb_hdr, smb_hdr_len,
                            dce_reassembly_buf, dce_reassembly_buf + dce_reassembly_buf_size);

        if (status != SAFEMEM_SUCCESS)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to copy DCERPC header, "
                                    "skipping DCERPC reassembly.\n"););

            DCERPC_BufferFreeData(buf);
            return;
        }

        data_len += smb_hdr_len;
    }

    status = SafeMemcpy(dce_reassembly_buf + data_len,
                        &fake_req, dcerpc_req_len,
                        dce_reassembly_buf, dce_reassembly_buf + dce_reassembly_buf_size);

    if (status != SAFEMEM_SUCCESS)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to copy DCERPC header, "
                                "skipping DCERPC reassembly.\n"););

        DCERPC_BufferFreeData(buf);
        return;
    }

    data_len += dcerpc_req_len;

    /* Copy data into buffer */
    status = SafeMemcpy(dce_reassembly_buf + data_len, buf->data, buf->len,
                        dce_reassembly_buf, dce_reassembly_buf + dce_reassembly_buf_size);

    if (status != SAFEMEM_SUCCESS)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to copy DCERPC data, "
                                "skipping DCERPC reassembly.\n"););

        DCERPC_BufferFreeData(buf);
        return;
    }

    data_len += buf->len;

    if (dcerpc_eval_config->debug_print)
    {
        PrintBuffer("DCE/RPC reassembled request",
                    (uint8_t *)dce_reassembly_buf, data_len);
    }

    /* create pseudo packet */
    real_dce_mock_pkt = DCERPC_SetPseudoPacket(_dcerpc_pkt, dce_reassembly_buf, data_len);
    if (real_dce_mock_pkt == NULL)
    {
        DCERPC_BufferFreeData(buf);
        return;
    }
}


