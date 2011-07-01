/*
 ** Copyright (C) 1998-2011 Sourcefire, Inc.
 **
 ** Writen by Bhagyashree Bantwal <bbantwal@sourcefire.com>
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

#ifndef _SF_EMAIL_ATTACH_DECODE_H_
#define _SF_EMAIL_ATTACH_DECODE_H_

#include "sf_types.h"
#include "util_unfold.h"
#include "sf_base64decode.h"
#include "snort_bounds.h"

#define MAX_BUF 65535
#define DECODE_SUCCESS  0
#define DECODE_FAIL    -1

typedef enum {

    DECODE_NONE = 0,
    DECODE_B64,
    DECODE_QP,
    DECODE_UU,
    DECODE_BITENC,
    DECODE_ALL

} DecodeType;

typedef struct s_Base64_DecodeState
{
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int encode_depth;
    int decode_depth;
} Base64_DecodeState;

typedef struct s_QP_DecodeState
{
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int encode_depth;
    int decode_depth;
} QP_DecodeState;

typedef struct s_UU_DecodeState
{
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int encode_depth;
    int decode_depth;
    uint8_t begin_found;
    uint8_t end_found;
} UU_DecodeState;

typedef struct s_BitEnc_DecodeState
{
    uint32_t bytes_read;
    int depth;
} BitEnc_DecodeState;

typedef struct s_Email_DecodeState
{
    DecodeType decode_type;
    uint8_t decode_present;
    uint32_t prev_encoded_bytes;
    unsigned char *prev_encoded_buf;
    uint32_t decoded_bytes;
    uint8_t *encodeBuf;
    uint8_t *decodeBuf;
    uint8_t *decodePtr;
    Base64_DecodeState b64_state;
    QP_DecodeState qp_state;
    UU_DecodeState uu_state;
    BitEnc_DecodeState bitenc_state;

} Email_DecodeState;


int EmailDecode(const uint8_t *, const uint8_t *, Email_DecodeState *);

static inline void SetEmailDecodeState(Email_DecodeState *ds, void *data, int max_depth, 
        int b64_depth, int qp_depth, int uu_depth, int bitenc_depth)
{
    if ( max_depth & 7 )
    {
        max_depth += (8 - (max_depth & 7));
    }

    ds->decode_type = DECODE_NONE;
    ds->decode_present = 0;
    ds->prev_encoded_bytes = 0;
    ds->prev_encoded_buf = NULL;
    ds->decoded_bytes = 0;

    ds->encodeBuf = (uint8_t *)data;
    ds->decodeBuf = (uint8_t *)data + max_depth;
    ds->decodePtr = ds->decodeBuf;

    ds->b64_state.encode_depth = ds->b64_state.decode_depth = b64_depth;
    ds->b64_state.encode_bytes_read = ds->b64_state.decode_bytes_read = 0;

    ds->qp_state.encode_depth = ds->qp_state.decode_depth = qp_depth;
    ds->qp_state.encode_bytes_read = ds->qp_state.decode_bytes_read = 0;

    ds->uu_state.encode_depth = ds->uu_state.decode_depth = uu_depth;
    ds->uu_state.encode_bytes_read = ds->uu_state.decode_bytes_read = 0;
    ds->uu_state.begin_found = 0;
    ds->uu_state.end_found = 0;

    ds->bitenc_state.depth = bitenc_depth;
    ds->bitenc_state.bytes_read = 0;

}

static inline void ClearPrevEncodeBuf(Email_DecodeState *ds)
{
    ds->prev_encoded_bytes = 0;
    ds->prev_encoded_buf = NULL;
}

static inline void ResetDecodedBytes(Email_DecodeState *ds)
{
    ds->decodePtr = NULL;
    ds->decoded_bytes = 0;
    ds->decode_present = 0;
}


static inline void ResetEmailDecodeState(Email_DecodeState *ds)
{
    if ( ds == NULL )
        return;

    ds->uu_state.begin_found = ds->uu_state.end_found = 0;
    ResetDecodedBytes(ds);
    ClearPrevEncodeBuf(ds);

}

static inline void ClearEmailDecodeState(Email_DecodeState *ds)
{
    if(ds == NULL)
        return;

    ds->decode_type = DECODE_NONE;
    ResetEmailDecodeState(ds);
}


#endif 
