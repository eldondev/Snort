/*
 * smb_andx_decode.h
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
 * Declares routines that handle decoding SMB AndX commands
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */
#ifndef _SMB_ANDX_DECODE_H_
#define _SMB_ANDX_DECODE_H_

typedef unsigned short uni_char_t;

int ProcessSMBSetupXReq(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size);
int ProcessSMBTreeConnXReq(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size);
int ProcessSMBNTCreateX(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size);
int ProcessSMBLogoffXReq(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size);
int ProcessSMBReadX(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size);
int ProcessSMBWriteX(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size);
int ProcessSMBLockingX(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size);
int ProcessSMBTransaction(SMB_HDR *smbHdr, uint8_t *data, uint16_t size, uint16_t total_size);
void ReassembleSMBWriteX(uint8_t *, uint16_t);

#endif /* _SMB_ANDX_DECODE_H_ */
