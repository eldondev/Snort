/*
 * dcerpc_util.c
 *
 * Copyright (C) 2006-2009 Sourcefire, Inc.
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
 * Contains utility functions.
 *
 */

#include <stdio.h>
#include <ctype.h>

#include "snort_dcerpc.h"
#include "dcerpc_util.h"
#include "bounds.h"


void DCERPC_GenerateAlert(dcerpc_event_e event, char *msg)
{
    _dpd.alertAdd(GENERATOR_DCERPC, event, 1, 0, 3, msg, 0);
}

/* Print out given buffer in hex and ascii, for debugging */
void PrintBuffer(const char * title, const uint8_t *buf, uint16_t buf_len)
{
    uint16_t i, j = 0;

    printf("%s\n", title);

    for ( i = 0; i < buf_len; i+=16 )
    {
        printf("%.4x  ", i);
        for ( j = 0; j < (buf_len-i) && j < 16; j++ )
        {
            printf("%.2x ", *(buf+i+j));
            if ( (j+1)%8 == 0 )
                printf(" ");
        }
        if ( j != 16 )
            printf(" ");
        for ( ; j < 16; j++ )
            printf("   ");
        printf(" ");
        for ( j = 0; j < (buf_len-i) && j < 16; j++ )
        {
            if ( isascii((int)*(buf+i+j)) && isprint((int)*(buf+i+j)) )
                printf("%c", *(buf+i+j));
            else
                printf(".");
            if ( (j+1)%8 == 0 )
                printf(" ");
            if ( (j+1)%16 == 0 )
                printf("\n");
        }
    }
    if ( j != 16 )
        printf("\n");
}

