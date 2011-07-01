/****************************************************************************
 * 
 * Copyright (C) 2011-2011 Sourcefire, Inc.
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

/*************************************************************************
 *
 * pop_util.h
 *
 * Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>
 *
 *************************************************************************/

#ifndef __POP_UTIL_H__
#define __POP_UTIL_H__

#include "sf_snort_packet.h"

void POP_GetEOL(const uint8_t *, const uint8_t *, const uint8_t **, const uint8_t **);
void POP_DecodeType(const char *start, int length);

#ifdef DEBUG_MSGS
const char * POP_PrintBuffer(SFSnortPacket *);
#endif

#endif  /*  __POP_UTIL_H__  */

