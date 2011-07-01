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
 
/**
**  @file       hi_server.c
**  
**  @author     Daniel Roelker <droelker@sourcefire.com>
**  
**  @brief      Handles inspection of HTTP server responses.
**  
**  HttpInspect handles server responses in a stateless manner because we
**  are really only interested in the first response packet that contains
**  the HTTP response code, headers, and the payload.
**  
**  The first big thing is to incorporate the HTTP protocol flow
**  analyzer.
**  
**  NOTES:
**      - Initial development.  DJR
*/
#include <stdio.h>

#include "hi_ui_config.h"
#include "hi_si.h"
#include "hi_return_codes.h"
#include "hi_server.h"

/**
**  NAME
**    IsHttpServerData::
*/
/**
**  Inspect an HTTP server response packet to determine the state.
**  
**  We inspect this packet and determine whether we are in the beginning
**  of a response header or if we are looking at payload.  We limit the
**  amount of inspection done on responses by only inspecting the HTTP header
**  and some payload.  If the whole packet is a payload, then we just ignore
**  it, since we inspected the previous header and payload.
**  
**  We limit the amount of the payload by adjusting the Server structure
**  members, header and header size.
**  
**  @param Server      the server structure
**  @param data        pointer to the beginning of payload
**  @param dsize       the size of the payload
**  @param flow_depth  the amount of header and payload to inspect
**  
**  @return integer
**  
**  @retval HI_INVALID_ARG invalid argument
**  @retval HI_SUCCESS     function success
*/
static int IsHttpServerData(HI_SERVER *Server, const u_char *data, int dsize,
                            int flow_depth)
{
    /* 
    ** HTTP:Server-Side-Session-Performance-Optimization
    ** This drops Server->Client packets which are not part of the 
    ** HTTP Response header. It can miss part of the response header 
    ** if the header is sent as multiple packets.
    */
    if(!data)
    {
        return HI_INVALID_ARG;
    }

    /*
    **  Let's set up the data pointers.
    */
    Server->header      = data;
    Server->header_size = dsize;

    /*
    **  This indicates that we want to inspect the complete response, so
    **  we don't waste any time otherwise.
    */
    if(flow_depth < 1)
    {
        return HI_SUCCESS;
    }

    if(dsize > 4 )
    {
        if( (data[0]!='H') || (data[1]!='T') || 
            (data[2]!='T') || (data[3]!='P') )
        {
            Server->header_size = 0;
            Server->header      = NULL;

            return HI_SUCCESS;
        }

        /*
        **  OK its an HTTP response header.
        **
        **  Now, limit the amount we inspect,
        **  we could just examine this whole packet, 
        **  since it's usually full of HTTP Response info.
        **  For protocol analysis purposes we probably ought to 
        **  let the whole thing get processed, or have a 
        **  different pattern match length and protocol inspection 
        **  length.
        */

        if(dsize > flow_depth)
        {
            Server->header_size = flow_depth;  
        }
    }

    return HI_SUCCESS;
}

static int ServerInspection(HI_SESSION *Session, const unsigned char *data,
                            int dsize)
{
    HI_SERVER *Server;
    int       iRet;

    Server = &(Session->server);

    /*
    **  There's really only one thing that we do right now for server
    **  responses, that's HTTP flow.
    */
    iRet = IsHttpServerData(Server, data, dsize, Session->server_conf->server_flow_depth);
    if (iRet)
    {
        return iRet;
    }

    return HI_SUCCESS;
}

int hi_server_inspection(void *S, const unsigned char *data, int dsize)
{
    HI_SESSION *Session;

    int iRet;

    if(!S || !data || dsize < 1)
    {
        return HI_INVALID_ARG;
    }

    Session = (HI_SESSION *)S;

    /*
    **  Let's inspect the server response.
    */
    iRet = ServerInspection(Session, data, dsize);
    if (iRet)
    {
        return iRet;
    }

    return HI_SUCCESS;
}
