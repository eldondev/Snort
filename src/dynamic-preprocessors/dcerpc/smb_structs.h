
/*
 * smb_structs.h
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
#ifndef _SMB_STRUCTS_H_
#define _SMB_STRUCTS_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#pragma pack(push,smb_hdrs,1)
#else
#pragma pack(1)
#endif


/* NBT SMB info */
#define SMB_NTTRANSCREATE 0x01
#define SMB_TRANS2OPEN 0x00
#define SMB_SESSION 0x00
#define SMB_SESSIONREQ 0x81
#define SMB_NONE 0xff

#define SMB_COM_CREATE_DIRECTORY 0x00
#define SMB_COM_DELETE_DIRECTORY 0x01
#define SMB_COM_OPEN 0x02
#define SMB_COM_CREATE 0x03
#define SMB_COM_CLOSE 0x04
#define SMB_COM_FLUSH 0x05
#define SMB_COM_DELETE 0x06
#define SMB_COM_RENAME 0x07
#define SMB_COM_QUERY_INFORMATION 0x08
#define SMB_COM_SET_INFORMATION 0x09
#define SMB_COM_READ 0x0A
#define SMB_COM_WRITE 0x0B
#define SMB_COM_LOCK_BYTE_RANGE 0x0C
#define SMB_COM_UNLOCK_BYTE_RANGE 0x0D
#define SMB_COM_CREATE_TEMPORARY 0x0E
#define SMB_COM_CREATE_NEW 0x0F
#define SMB_COM_CHECK_DIRECTORY 0x10
#define SMB_COM_PROCESS_EXIT 0x11
#define SMB_COM_SEEK 0x12
#define SMB_COM_LOCK_AND_READ 0x13
#define SMB_COM_WRITE_AND_UNLOCK 0x14
#define SMB_COM_READ_RAW 0x1A
#define SMB_COM_READ_MPX 0x1B
#define SMB_COM_READ_MPX_SECONDARY 0x1C
#define SMB_COM_WRITE_RAW 0x1D
#define SMB_COM_WRITE_MPX 0x1E
#define SMB_COM_WRITE_MPX_SECONDARY 0x1F
#define SMB_COM_WRITE_COMPLETE 0x20
#define SMB_COM_QUERY_SERVER 0x21
#define SMB_COM_SET_INFORMATION2 0x22
#define SMB_COM_QUERY_INFORMATION2 0x23
#define SMB_COM_LOCKING_ANDX 0x24
#define SMB_COM_TRANSACTION 0x25
#define SMB_COM_TRANSACTION_SECONDARY 0x26
#define SMB_COM_IOCTL 0x27
#define SMB_COM_IOCTL_SECONDARY 0x28
#define SMB_COM_COPY 0x29
#define SMB_COM_MOVE 0x2A
#define SMB_COM_ECHO 0x2B
#define SMB_COM_WRITE_AND_CLOSE 0x2C
#define SMB_COM_OPEN_ANDX 0x2D
#define SMB_COM_READ_ANDX 0x2E
#define SMB_COM_WRITE_ANDX 0x2F
#define SMB_COM_NEW_FILE_SIZE 0x30
#define SMB_COM_CLOSE_AND_TREE_DISC 0x31
#define SMB_COM_TRANSACTION2 0x32
#define SMB_COM_TRANSACTION2_SECONDARY 0x33
#define SMB_COM_FIND_CLOSE2 0x34
#define SMB_COM_FIND_NOTIFY_CLOSE 0x35
/* Used by Xenix/Unix 0x60 - 0x6E */
#define SMB_COM_TREE_CONNECT 0x70
#define SMB_COM_TREE_DISCONNECT 0x71
#define SMB_COM_NEGOTIATE 0x72
#define SMB_COM_SESSION_SETUP_ANDX 0x73
#define SMB_COM_LOGOFF_ANDX 0x74
#define SMB_COM_TREE_CONNECT_ANDX 0x75
#define SMB_COM_QUERY_INFORMATION_DISK 0x80
#define SMB_COM_SEARCH 0x81
#define SMB_COM_FIND 0x82
#define SMB_COM_FIND_UNIQUE 0x83
#define SMB_COM_FIND_CLOSE 0x84
#define SMB_COM_NT_TRANSACT 0xA0
#define SMB_COM_NT_TRANSACT_SECONDARY 0xA1
#define SMB_COM_NT_CREATE_ANDX 0xA2
#define SMB_COM_NT_CANCEL 0xA4
#define SMB_COM_NT_RENAME 0xA5
#define SMB_COM_OPEN_PRINT_FILE 0xC0
#define SMB_COM_WRITE_PRINT_FILE 0xC1
#define SMB_COM_CLOSE_PRINT_FILE 0xC2
#define SMB_COM_GET_PRINT_QUEUE 0xC3
#define SMB_COM_READ_BULK 0xD8
#define SMB_COM_WRITE_BULK 0xD9
#define SMB_COM_WRITE_BULK_DATA 0xDA

typedef struct nbt_hdr
{
    uint8_t type;
    uint8_t flags;
    uint16_t length;
} NBT_HDR;

typedef struct {
    uint32_t LowPart;
    int32_t HighPart;
} SMB_LARGE_INTEGER; // 64 bits of data

typedef uint32_t SMB_UTIME;
typedef uint32_t SMB_ACCESS_MASK;

typedef struct smb_hdr
{
    uint8_t protocol[4];      /* Should always be 0xff,SMB */
    uint8_t command;          /* Command code */

    union
    {
        /* 32 Bits */
        struct {
            uint8_t errClass; /* Error class */
            uint8_t reserved; /* Should be 0 */
            uint16_t err;     /* Error code */
        } dosErr;
        uint32_t ntErrCode;    /* 32-bit Error code */
    } status;

    uint8_t flags;            /* Flags */
    uint16_t flags2;          /* 8 bits weren't enough */

    union
    {
        uint16_t pad[6];      /* Make this 12 bytes long */
        struct
        {
            uint16_t pidHigh; /* Upper 16 bits of PID */
            uint32_t unused;
            uint32_t unusedToo;
        } extra;
    } extended;

    uint16_t tid;             /* Tree ID */
    uint16_t pid;             /* Process ID */
    uint16_t uid;             /* User ID */
    uint16_t mid;             /* Multiplex ID */
} SMB_HDR;

typedef struct smb_neg_prot_hdr
{
    /* The SMB data portion starts at smb_hdr + 32 */
    uint8_t wordCount;        /* Should be 0 */
    uint16_t byteCount;       /* Number of data bytes */

    /* dialect array */
    /* format is (0x02, NULL-term string) */
} SMB_NEG_PROT_HDR;

typedef struct transaction2_hdr
{
    uint8_t wordCount;
    uint16_t totalParameterCount;
    uint16_t totalDataCount;
    uint16_t maxParameterCount;
    uint16_t maxDataCount;
    uint8_t maxSetupCount;
    uint8_t reserved;
    uint16_t flags;

    uint32_t timeout;
    uint16_t reserved2;

    uint16_t parameterCount;
    uint16_t parameterOffset;
    uint16_t dataCount;
    uint16_t dataOffset;

    uint8_t setupCount;
    uint8_t reserved3;

} SMB_TRANSACTION2_REQ;

typedef struct transaction2_secondary_hdr
{
    uint8_t wordCount;
    uint16_t totalParameterCount;
    uint16_t totalDataCount;

    uint16_t parameterCount;
    uint16_t parameterOffset;
    uint16_t parameterDisplacement;
    uint16_t dataCount;
    uint16_t dataOffset;
    uint16_t dataDisplacement;

    uint16_t fid;

    uint16_t byteCount;

} SMB_TRANSACTION2_SECONDARY_REQ;

typedef struct nttransact_hdr
{
    uint8_t wordCount;
    uint8_t maxSetupCount;
    uint16_t reserved;
    uint32_t totalParameterCount;
    uint32_t totalDataCount;
    uint32_t maxParameterCount;
    uint32_t maxDataCount;

    uint32_t parameterCount;
    uint32_t parameterOffset;
    uint32_t dataCount;
    uint32_t dataOffset;

    uint8_t setupCount;
    uint16_t function;
    uint8_t buffer; /* Pad */

} SMB_NTTRANSACT_REQ;

typedef struct nttransact_secondary_hdr
{
    uint8_t wordCount;
    uint8_t reserved[3];
    uint32_t totalParameterCount;
    uint32_t totalDataCount;

    uint32_t parameterCount;
    uint32_t parameterOffset;
    uint32_t parameterDisplacement;
    uint32_t dataCount;
    uint32_t dataOffset;
    uint32_t dataDisplacement;

    uint8_t reserved1;

    uint16_t byteCount;

} SMB_NTTRANSACT_SECONDARY_REQ;

typedef struct nttransact_create_hdr
{
    uint32_t flags;
    uint32_t rootDirFid;
    SMB_ACCESS_MASK desiredAccess;
    SMB_LARGE_INTEGER allocationSize;

    uint32_t extFileAttributes;
    uint32_t shareAccess;
    uint32_t createDisposition;
    uint32_t createOptions;

    uint32_t securityDescriptorLength;
    uint32_t eaLength;
    uint32_t nameLength;
    uint32_t impersonationLevel;

    uint8_t securityFlags;

} SMB_NTTRANSACT_CREATE_REQ;

#ifdef WIN32
#pragma pack(pop,smb_hdrs)
#else
#pragma pack()
#endif

/* from snort_smb.c */
int ProcessNextSMBCommand(uint8_t command, SMB_HDR *smbHdr,
            uint8_t *data, uint16_t data_size, uint16_t size);

/*
 * Grumble, grumble...
 *
 * Since IBM/Micrsoft decided to put SMBs out on the wire in
 * little endian order, the htonX & ntohX ops convert on the
 * wrong architectures -- ie, we need no conversion on little
 * endian.  So, use these for SMB...
 */

#ifdef WORDS_BIGENDIAN
#define smb_htons(A)  ((((uint16_t)(A) & 0xff00) >> 8) | (((uint16_t)(A) & 0x00ff) << 8))
#define smb_htonl(A)  ((((uint32_t)(A) & 0xff000000) >> 24) | (((uint32_t)(A) & 0x00ff0000) >> 8)  | (((uint32_t)(A) & 0x0000ff00) << 8)  | (((uint32_t)(A) & 0x000000ff) << 24))
#define smb_ntohs     smb_htons
#define smb_ntohl     smb_htonl
#define IS_LITTLE_ENDIAN 0
#else
#define smb_htons(A)  (A)
#define smb_htonl(A)  (A)
#define smb_ntohs(A)  (A)
#define smb_ntohl(A)  (A)
#define IS_LITTLE_ENDIAN 1
#endif

#define HAS_UNICODE_STRINGS(smbHdr) (smb_ntohs(smbHdr->flags2) & 0x8000)

#endif /* _SMB_STRUCTS_H_ */

