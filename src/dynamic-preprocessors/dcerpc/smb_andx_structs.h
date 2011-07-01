/*
 * smb_andx_structs.h
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
#ifndef _SMB_ANDX_STRUCTS_H_
#define _SMB_ANDX_STRUCTS_H_

#include "smb_structs.h"

#ifdef WIN32
#pragma pack(push,smb_hdrs,1)
#else
#pragma pack(1)
#endif

typedef struct sess_setupx_req_hdr
{ 
    uint8_t wordCount;        /* Count of parameter words */
    uint8_t andXCommand;
    uint8_t andXReserved;
    uint16_t andXOffset;

    uint16_t maxBufSize;
    uint16_t maxMPXCount;
    uint16_t vcNumber;
    uint32_t sessionKey;
} SMB_SESS_SETUPX_REQ_HDR;

typedef struct sess_setupx_req_auth_old
{
    uint16_t passwdLen;
    uint32_t reserved2;
    uint16_t byteCount;
} SMB_SESS_SETUPX_REQ_AUTH_OLD;

typedef struct sess_setupx_req_auth_ntlm12
{
    uint16_t secBlobLength;
    uint32_t reserved2;
    uint32_t capabilities;
    uint16_t byteCount;
} SMB_SESS_SETUPX_REQ_AUTH_NTLM12;

typedef struct sess_setupx_req_auth_ntlm12_noext
{
    uint16_t iPasswdLen;
    uint16_t passwdLen;
    uint32_t reserved2;
    uint32_t capabilities;
    uint16_t byteCount;
} SMB_SESS_SETUPX_REQ_AUTH_NTLM12_NOEXT;

typedef struct tree_connx_req_hdr
{
    uint8_t wordCount;        /* Count of parameter words */
    uint8_t andXCommand;
    uint8_t andXReserved;
    uint16_t andXOffset;

    uint16_t flags;
    uint16_t passwdLen;
    uint16_t byteCount;
} SMB_TREE_CONNECTX_REQ;

typedef struct logoffx_req_hdr
{
    uint8_t wordCount;        /* Count of parameter words */
    uint8_t andXCommand;
    uint8_t andXReserved;
    uint16_t andXOffset;

    uint16_t byteCount;       /* Should be 0 */
} SMB_LOGOFFX_REQ;

typedef struct ntcreatex_req_hdr
{
    uint8_t wordCount;        /* Count of parameter words */
    uint8_t andXCommand;
    uint8_t andXReserved;
    uint16_t andXOffset;

    uint8_t reserved2;
    uint16_t nameLength;
    uint32_t flags;

    uint32_t rootDirFid;
    SMB_ACCESS_MASK desiredAccess;
    SMB_LARGE_INTEGER allocationSize;

    uint32_t extFileAttributes;
    uint32_t shareAccess;
    uint32_t createDisposition;
    uint32_t createOptions;
    uint32_t impersonationLevel;

    uint8_t securityFlags;
    uint16_t byteCount;

} SMB_NTCREATEX_REQ;

typedef struct readx_hdr
{
    uint8_t wordCount;
    uint8_t andXCommand;
    uint8_t andXReserved;
    uint16_t andXOffset;

    uint16_t fid;
    uint32_t offset;

    uint16_t maxCount;
    uint16_t minCount;
    uint32_t maxCountHigh;

    uint16_t remaining;
    uint32_t highOffset;
    uint16_t byteCount;

} SMB_READX_REQ;

typedef struct lockingx_hdr
{
    uint8_t wordCount;
    uint8_t andXCommand;
    uint8_t andXReserved;
    uint16_t andXOffset;

    uint16_t fid;
    uint8_t lockType;
    uint8_t oplockLevel;
    uint32_t timeout;

    uint16_t numUnlocks;
    uint16_t numLocks;

    uint16_t byteCount;

} SMB_LOCKINGX_REQ;

#define LOCKINGX_SHARED_LOCK 0x01
#define LOCKINGX_OPLOCK_RELEASE 0x02
#define LOCKINGX_CHANGE_LOCKTYPE 0x04
#define LOCKINGX_CANCEL_LOCK 0x08
#define LOCKINGX_LARGE_FILES 0x10

typedef struct lockingx_range
{
    uint16_t pid;
    uint32_t offset;
    uint32_t length;
} SMB_LOCKINGX_RANGE;

typedef struct largefile_lockingx_range
{
    uint16_t pid;
    uint16_t pad;

    uint32_t offsetHigh;
    uint32_t offsetLow;
    uint32_t lengthHigh;
    uint32_t lengthLow;
} SMB_LARGEFILE_LOCKINGX_RANGE;

typedef struct writex_hdr
{
    uint8_t wordCount;
    uint8_t andXCommand;
    uint8_t andXReserved;
    uint16_t andXOffset;

    uint16_t fid;
    uint32_t offset;
    uint32_t reserved;

    uint16_t writeMode;

    uint16_t remaining;
    uint16_t dataLengthHigh;
    uint16_t dataLength;
    uint16_t dataOffset;
    uint32_t highOffset;
    uint16_t byteCount;

} SMB_WRITEX_REQ;

typedef struct trans_hdr
{
    uint8_t  wordCount;
    uint16_t totalParamCount;
    uint16_t totalDataCount;
    uint16_t maxParamCount;
    uint16_t maxDataCount;
    uint8_t  maxSetupCount;
    uint8_t  transReserved;

    uint16_t flags;
    uint32_t timeout;
    uint16_t reserved;

    uint16_t parameterCount;
    uint16_t parameterOffset;
    uint16_t dataCount;
    uint16_t dataOffset;
    uint8_t  setupCount;
    uint8_t  reserved2;
    uint16_t function;
    uint16_t fid;
    uint16_t byteCount;

} SMB_TRANS_REQ;

#ifdef WIN32
#pragma pack(pop,smb_hdrs)
#else
#pragma pack()
#endif

#endif /* _SMB_ANDX_STRUCTS_H_ */
