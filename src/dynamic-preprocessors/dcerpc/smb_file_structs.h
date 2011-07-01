/*
 * smb_file_structs.h
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
 * Defines data structures representing SMB commands
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */
#ifndef _SMB_FILE_STRUCTS_H_
#define _SMB_FILE_STRUCTS_H_

#ifdef WIN32
#pragma pack(push,smb_hdrs,1)
#endif

typedef struct echo_req_hdr
{
    uint8_t wordCount;        /* Count of parameter words */
    uint8_t echoCount;

    uint16_t byteCount;       /* Should be 0 */
} SMB_ECHO_REQ;

typedef struct close_hdr
{
    uint8_t wordCount;
    uint16_t fid;
    SMB_UTIME lastWriteTime;
    uint16_t byteCount;
} SMB_CLOSE_REQ;

typedef struct seek_hdr
{
    uint8_t wordCount;
    uint16_t fid;
    uint16_t mode;
    uint32_t offset;
    uint16_t byteCount;
} SMB_SEEK_REQ;

typedef struct flush_hdr
{
    uint8_t wordCount;
    uint16_t fid;
    uint16_t byteCount;
} SMB_FLUSH_REQ;

typedef struct tree_disconnect_hdr
{
    uint8_t wordCount;
    uint16_t byteCount;
} SMB_TREE_DISCONNECT_REQ;



#ifdef WIN32
#pragma pack(pop,smb_hdrs)
#endif

#endif /* _SMB_FILE_STRUCTS_H_ */
