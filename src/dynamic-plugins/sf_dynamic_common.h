/*
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
 * Copyright (C) 2005-2009 Sourcefire, Inc.
 *
 */
#ifndef _SF_DYNAMIC_COMMON_H_
#define _SF_DYNAMIC_COMMON_H_

#ifndef WIN32
#include <sys/types.h>
#else
#include <stdint.h>
#endif

typedef void (*LogMsgFunc)(const char *, ...);
typedef void (*DebugMsgFunc)(int, char *, ...);
#ifdef HAVE_WCHAR_H
typedef void (*DebugWideMsgFunc)(int, wchar_t *, ...);
#endif

#define STD_BUF 1024

#define MAX_URIINFOS 5

#define HTTP_BUFFER_URI 0
#define HTTP_BUFFER_HEADER 1
#define HTTP_BUFFER_CLIENT_BODY 2
#define HTTP_BUFFER_METHOD 3
#define HTTP_BUFFER_COOKIE 4

typedef struct _UriInfo
{
    uint8_t *uriBuffer;
    uint16_t uriLength;
    uint32_t uriDecodeFlags;

} UriInfo;

#endif /* _SF_DYNAMIC_COMMON_H_ */
