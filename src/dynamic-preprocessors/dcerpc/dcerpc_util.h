/*
 * dcerpc_util.h
 *
 * Copyright (C) 2006-2009 Sourcefire, Inc.
 * Andrew Mullican
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
 * Declares routines for utility functions.
 *
 *
 */
#ifndef _DCERPC_UTIL_H_
#define _DCERPC_UTIL_H_

#include "debug.h"
#include "snort_dcerpc.h"

/* Needs to match what is in generators.h */
#define  GENERATOR_DCERPC    130


/* Events for DCERPC */
typedef enum _dcerpc_event_e 
{
    DCERPC_EVENT_MEMORY_OVERFLOW       = 1

} dcerpc_event_e;

typedef struct _DCERPC_Buffer
{
    uint8_t *data;
    uint16_t len;
    uint16_t size;

} DCERPC_Buffer;


#define     DCERPC_EVENT_MEMORY_OVERFLOW_STR  "(dcerpc) Maximum memory usage reached"


void DCERPC_GenerateAlert(dcerpc_event_e event, char *msg);
void PrintBuffer(const char * title, const uint8_t *buf, uint16_t buf_len);

#endif  /*  _DCERPC_UTIL_H_  */
