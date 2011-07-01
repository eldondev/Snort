/****************************************************************************
 *
 * Copyright (C) 2003-2009 Sourcefire, Inc.
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
 ****************************************************************************/
 
#ifndef __HI_INCLUDE_H__
#define __HI_INCLUDE_H__

#include "sf_types.h"
#include "debug.h"
#include "ipv6_port.h"

#define HI_UNKNOWN_METHOD 1
#define HI_POST_METHOD 2
#define HI_GET_METHOD 4

typedef struct _hi_stats {
    uint64_t unicode;
    uint64_t double_unicode;
    uint64_t non_ascii;        /* Non ASCII-representable character in URL */
    uint64_t base36;
    uint64_t dir_trav;         /* '../' */
    uint64_t slashes;          /* '//' */
    uint64_t self_ref;         /* './' */
    uint64_t post;             /* Number of POST methods encountered */
    uint64_t get;              /* Number of GETs */
    uint64_t post_params;      /* Number of successfully extract post parameters */
    uint64_t headers;          /* Number of successfully extracted headers */
#ifdef DEBUG
    uint64_t header_len;
#endif
    uint64_t cookies;          /* Number of successfully extracted cookies */
#ifdef DEBUG
    uint64_t cookie_len;
#endif
    uint64_t total;
} HIStats;

extern HIStats hi_stats;

#ifndef INLINE

#ifdef WIN32
#define INLINE __inline
#else
#define INLINE inline
#endif

#endif /* endif for INLINE */
#endif
