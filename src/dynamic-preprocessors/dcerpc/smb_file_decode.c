/*
 * smb_file_decode.c
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

#ifdef UNUSED_SMB_COMMAND

#include "sf_snort_packet.h"

#include "smb_structs.h"
#include "smb_file_structs.h"

#include "smb_file_decode.h"

int ProcessSMBEcho(SMB_HDR *smbHdr, uint8_t *data, uint16_t size)
{
    //unsigned char *smb_data = data + sizeof(SMB_ECHO_REQ);

#ifdef DEBUG_DCERPC_PRINT
    SMB_ECHO_REQ *echoReq = (SMB_ECHO_REQ *)data;
    printf("Echo %d bytes, %d times: ", extraBytes, smb_ntohs(echoReq->echoCount));

#if 0
    {
        int i;
        for (i=0;i<extraBytes; i++)
            printf("%x", smb_data[i]);
    }
#endif

    printf("\n");
#endif

    return 0;
}

int ProcessSMBClose(SMB_HDR *smbHdr, uint8_t *data, uint16_t size)
{
    SMB_CLOSE_REQ *closeReq = (SMB_CLOSE_REQ *)data;

    if ((closeReq->wordCount != 3) ||
        (closeReq->byteCount != 0))
    {
        return -1;
    }

#ifdef DEBUG_DCERPC_PRINT
    printf("Closing file FID: %x, WriteTime %s", smb_ntohs(closeReq->fid), 
        ctime(&timeVal));
    if (smbHdr->command == SMB_COM_CLOSE_AND_TREE_DISC)
    {
        printf("and disconnecting from tree");
    }
    printf ("\n");
#endif

    return 0;
}

int ProcessSMBSeek(SMB_HDR *smbHdr, uint8_t *data, uint16_t size)
{
    SMB_SEEK_REQ *seekReq = (SMB_SEEK_REQ *)data;

    if ((seekReq->wordCount != 4) ||
        (seekReq->byteCount != 0))
    {
        return -1;
    }
#ifdef DEBUG_DCERPC_PRINT
    printf("Seeking file FID: %x, Mode: %d Offset %d\n", smb_ntohs(seekReq->fid), 
        smb_ntohs(seekReq->mode), smb_ntohl(seekReq->offset));
#endif
    return 0;
}


int ProcessSMBFlush(SMB_HDR *smbHdr, uint8_t *data, uint16_t size)
{
    SMB_FLUSH_REQ *flushReq = (SMB_FLUSH_REQ *)data;

    if ((flushReq->wordCount != 1) ||
        (flushReq->byteCount != 0))
    {
        return -1;
    }
#ifdef DEBUG_DCERPC_PRINT
    printf("Flushing file FID: %x\n", smb_ntohs(flushReq->fid));
#endif
    return 0;
}

int ProcessSMBNoParams(SMB_HDR *smbHdr, uint8_t *data, uint16_t size)
{
    SMB_TREE_DISCONNECT_REQ *disconnect = (SMB_TREE_DISCONNECT_REQ *)data;

    if ((disconnect->wordCount != 0) ||
        (disconnect->byteCount != 0))
    {
        return -1;
    }

    return 0;
}

#endif  /*  UNUSED_SMB_COMMAND */
