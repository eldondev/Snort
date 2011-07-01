/*
** $Id$
**
** perf-flow.c
**
**
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Marc Norton <mnorton@sourcefire.com>
** Dan Roelker <droelker@sourcefire.com>
**
** NOTES
**   4.10.02 - Initial Checkin.  Norton
**   5.5.02  - Changed output format and added output structure for
**             easy stat printing. Roelker
**   5.29.02 - Added ICMP traffic stats and overall protocol flow 
**             stats. Roelker
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
**  DESCRIPTION
**    The following subroutines track eand analyze the traffic flow
**  statistics.
**
**   PacketLen vs Packet Count
**   TCP-Port vs Packet Count
**   UDP-Port vs Packet Count
**   TCP High<->High Port Count 
**   UDP High<->High Port Count
**
**
*/

#include <time.h>
#ifndef WIN32
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "snort.h"
#include "util.h"
#include "sf_types.h" 

extern SFPERF *perfmon_config;

static int DisplayFlowStats(SFFLOW_STATS *sfFlowStats);

/*
*  Allocate Memory, initialize arrays, etc...
*/
int InitFlowStats(SFFLOW *sfFlow)
{
    static char first = 1;

    if (first)
    {
        sfFlow->pktLenCnt = (uint64_t*)SnortAlloc(sizeof(uint64_t) * (SF_MAX_PKT_LEN + 1));
        sfFlow->portTcpSrc = (uint64_t*)SnortAlloc(sizeof(uint64_t) * SF_MAX_PORT);
        sfFlow->portTcpDst = (uint64_t*)SnortAlloc(sizeof(uint64_t) * SF_MAX_PORT);
        sfFlow->portUdpSrc = (uint64_t*)SnortAlloc(sizeof(uint64_t) * SF_MAX_PORT);
        sfFlow->portUdpDst = (uint64_t*)SnortAlloc(sizeof(uint64_t) * SF_MAX_PORT);
        sfFlow->typeIcmp = (uint64_t *)SnortAlloc(sizeof(uint64_t) * 256);

        first = 0;
    }
    else
    {
        memset(sfFlow->pktLenCnt, 0, sizeof(uint64_t) * (SF_MAX_PKT_LEN + 1));
        memset(sfFlow->portTcpSrc, 0, sizeof(uint64_t) * SF_MAX_PORT);
        memset(sfFlow->portTcpDst, 0, sizeof(uint64_t) * SF_MAX_PORT);
        memset(sfFlow->portUdpSrc, 0, sizeof(uint64_t) * SF_MAX_PORT);
        memset(sfFlow->portUdpDst, 0, sizeof(uint64_t) * SF_MAX_PORT);
        memset(sfFlow->typeIcmp, 0, sizeof(uint64_t) * 256);
    }

    sfFlow->pktTotal = 0;
    sfFlow->byteTotal = 0;

    sfFlow->portTcpHigh=0;
    sfFlow->portTcpTotal=0;

    sfFlow->portUdpHigh=0;
    sfFlow->portUdpTotal=0;

    sfFlow->typeIcmpTotal = 0;
    
    return 0;
}

int UpdateTCPFlowStats(SFFLOW *sfFlow, int sport, int dport, int len )
{
    /*
    ** Track how much data on each port, and hihg<-> high port data
    */
    /*
    if( sport < sfFlow->maxPortToTrack )
    {
        sfFlow->portTcpSrc  [ sport ]+= len;
    }
   
    if( dport < sfFlow->maxPortToTrack )
    {
        sfFlow->portTcpDst  [ dport ]+= len;
    }
    
    if( sport > 1023 && dport > 1023 )
    {
        sfFlow->portTcpHigh += len;
    }
    */
    if( sport <  1024 && dport > 1023 ) //sfFlow->maxPortToTrack )
    {
        sfFlow->portTcpSrc  [ sport ]+= len;
    }
    else if( dport < 1024 && sport > 1023 ) //sfFlow->maxPortToTrack )
    {
        sfFlow->portTcpDst  [ dport ]+= len;
    }
    else if( sport < 1023 && dport < 1023 )
    {
        sfFlow->portTcpSrc  [ sport ]+= len;
        sfFlow->portTcpDst  [ dport ]+= len;
    }
    else if( sport > 1023 && dport > 1023 )
    {
        sfFlow->portTcpSrc  [ sport ]+= len;
        sfFlow->portTcpDst  [ dport ]+= len;
        
        sfFlow->portTcpHigh += len;
    }


    sfFlow->portTcpTotal += len;

    return 0;
}

int UpdateTCPFlowStatsEx(SFFLOW *sfFlow, int sport, int dport, int len )
{
    if(!(perfmon_config->perf_flags & SFPERF_FLOW))
       return 1;

    if (sfFlow == NULL)
        return 1;

    return UpdateTCPFlowStats( sfFlow, sport, dport, len );
}

int UpdateUDPFlowStats(SFFLOW *sfFlow, int sport, int dport, int len )
{
    /*
     * Track how much data on each port, and hihg<-> high port data
     */
    if( sport <  1024 && dport > 1023 ) //sfFlow->maxPortToTrack )
    {
        sfFlow->portUdpSrc  [ sport ]+= len;
    }
    else if( dport < 1024 && sport > 1023 ) //sfFlow->maxPortToTrack )
    {
        sfFlow->portUdpDst  [ dport ]+= len;
    }
    else if( sport < 1023 && dport < 1023 )
    {
        sfFlow->portUdpSrc  [ sport ]+= len;
        sfFlow->portUdpDst  [ dport ]+= len;
    }
    else if( sport > 1023 && dport > 1023 )
    {
        sfFlow->portUdpSrc  [ sport ]+= len;
        sfFlow->portUdpDst  [ dport ]+= len;
        
        sfFlow->portUdpHigh += len;
    }

    sfFlow->portUdpTotal += len;

    return 0;
}

int UpdateUDPFlowStatsEx(SFFLOW *sfFlow, int sport, int dport, int len )
{
    if(!(perfmon_config->perf_flags & SFPERF_FLOW))
       return 1;

    if (sfFlow == NULL)
        return 1;

    return UpdateUDPFlowStats( sfFlow, sport, dport, len );
}

int UpdateICMPFlowStats(SFFLOW *sfFlow, int type, int len)
{
    if(type < 256)
    {
        sfFlow->typeIcmp[type] += len;
    }

    sfFlow->typeIcmpTotal += len;

    return 0;
}

int UpdateICMPFlowStatsEx(SFFLOW *sfFlow, int type, int len)
{
    if(!(perfmon_config->perf_flags & SFPERF_FLOW))
        return 1;

    if (sfFlow == NULL)
        return 1;

    return UpdateICMPFlowStats(sfFlow, type, len);
}

/*
*   Add in stats for this packet
*
*   Packet lengths
*/
int UpdateFlowStats(SFFLOW *sfFlow, const unsigned char *pucPacket, int len,
        int iRebuiltPkt)
{
    /*
    * Track how many packets of each length
    */
    if( (!iRebuiltPkt)&&(len <= SF_MAX_PKT_LEN) )
    {
        sfFlow->pktLenCnt[ len ]++;
        sfFlow->pktTotal++;
        sfFlow->byteTotal += len;
    }

    return 0;
}

/*
*   Analyze/Calc Stats and Display them.
*/
int ProcessFlowStats(SFFLOW *sfFlow)
{
    static SFFLOW_STATS sfFlowStats;
    int i;
    double rate, srate, drate, totperc;
    uint64_t tot;

    memset(&sfFlowStats, 0x00, sizeof(sfFlowStats));

    /*
    **  Calculate the percentage of TCP, UDP and ICMP
    **  and other traffic that consisted in the stream.
    */
    sfFlowStats.trafficTCP = 100.0 * (double)(sfFlow->portTcpTotal) /
                 (double)(sfFlow->byteTotal);
    sfFlowStats.trafficUDP = 100.0 * (double)(sfFlow->portUdpTotal) /
                 (double)(sfFlow->byteTotal);
    sfFlowStats.trafficICMP = 100.0 * (double)(sfFlow->typeIcmpTotal) /
                 (double)(sfFlow->byteTotal);
    sfFlowStats.trafficOTHER = 100.0 *
                   (double)((double)sfFlow->byteTotal -
                   ((double)sfFlow->portTcpTotal +
                   (double)sfFlow->portUdpTotal +
                   (double)sfFlow->typeIcmpTotal)) /
                   (double)sfFlow->byteTotal;
    
    /*
    **  Calculate Packet percent of total pkt length
    **  distribution.
    */
    for(i=1;i<SF_MAX_PKT_LEN;i++)
    {
        if( !sfFlow->pktLenCnt[i]  ) continue;
     
        rate =  100.0 * (double)(sfFlow->pktLenCnt[i]) / 
                (double)(sfFlow->pktTotal);

        if( rate > .10 )
        {
            sfFlowStats.pktLenPercent[i] = rate;
        }
        else
        {
            sfFlowStats.pktLenPercent[i] = 0;
        }  
      
        sfFlow->pktLenCnt[i]=0;
    }

    /*
    **  Calculate TCP port distribution by src, dst and
    **  total percentage.
    */
    for (i = 0; i < perfmon_config->flow_max_port_to_track; i++)
    {
        tot = sfFlow->portTcpSrc[i]+sfFlow->portTcpDst[i];
        if(!tot)
        {
            sfFlowStats.portflowTCP.totperc[i] = 0;
            continue;
        }

        totperc = 100.0 * tot / sfFlow->portTcpTotal;
        
        if(totperc > .1)
        {
            srate =  100.0 * (double)(sfFlow->portTcpSrc[i]) / tot ;
            drate =  100.0 * (double)(sfFlow->portTcpDst[i]) / tot ;
        
            sfFlowStats.portflowTCP.totperc[i]    = totperc;
            sfFlowStats.portflowTCP.sport_rate[i] = srate;
            sfFlowStats.portflowTCP.dport_rate[i] = drate;
        }
        else
        {
            sfFlowStats.portflowTCP.totperc[i] = 0;
        }
        
        sfFlow->portTcpSrc[i] = sfFlow->portTcpDst[i] = 0;
    }

    sfFlowStats.portflowHighTCP = 100.0 * sfFlow->portTcpHigh /
                                  sfFlow->portTcpTotal;

    /*
    **  Reset counters for next go round.
    */
    sfFlow->portTcpHigh=0;
    sfFlow->portTcpTotal=0;
    
    /*
    **  Calculate UDP port processing based on src, dst and
    **  total distributions.
    */
    for (i = 0; i < perfmon_config->flow_max_port_to_track; i++)
    {
        tot = sfFlow->portUdpSrc[i]+sfFlow->portUdpDst[i];
        if(!tot)
        {
            sfFlowStats.portflowUDP.totperc[i] = 0;
            continue;
        }

        totperc= 100.0 * tot / sfFlow->portUdpTotal;
        
        if(totperc > .1)
        {
            srate =  100.0 * (double)(sfFlow->portUdpSrc[i]) / tot ;
            drate =  100.0 * (double)(sfFlow->portUdpDst[i]) / tot ;

            sfFlowStats.portflowUDP.totperc[i]    = totperc;
            sfFlowStats.portflowUDP.sport_rate[i] = srate;
            sfFlowStats.portflowUDP.dport_rate[i] = drate;
        }
        else
        {
            sfFlowStats.portflowUDP.totperc[i] = 0;
        }
        
        sfFlow->portUdpSrc[i] = sfFlow->portUdpDst[i] = 0;
    }

    sfFlowStats.portflowHighUDP = 100.0 * sfFlow->portUdpHigh /
                                  sfFlow->portUdpTotal;

    /*
    **  Reset counters for next go round
    */
    sfFlow->portUdpHigh=0;
    sfFlow->portUdpTotal=0;

    /*
    **  Calculate ICMP statistics
    */
    for(i=0;i<256;i++)
    {
        tot = sfFlow->typeIcmp[i];
        if(!tot)
        {
            sfFlowStats.flowICMP.totperc[i] = 0;
            continue;
        }

        totperc= 100.0 * tot / sfFlow->typeIcmpTotal;
        
        if(totperc > .1)
        {
            sfFlowStats.flowICMP.totperc[i]  = totperc;
        }
        else
        {
            sfFlowStats.flowICMP.totperc[i] = 0;
        }

        sfFlow->typeIcmp[i] = 0;
    }

    sfFlow->typeIcmpTotal = 0;

    sfFlow->byteTotal = 0;
   
    sfFlow->pktTotal  = 0; 
 
    DisplayFlowStats(&sfFlowStats);

    return 0;
}
                                                
static int DisplayFlowStats(SFFLOW_STATS *sfFlowStats)
{
    int i;
  
    LogMessage("\n");
    LogMessage("\n");
    LogMessage("Protocol Byte Flows - %%Total Flow\n");
    LogMessage(    "--------------------------------------\n");
    LogMessage("TCP:   %.2f%%\n", sfFlowStats->trafficTCP);
    LogMessage("UDP:   %.2f%%\n", sfFlowStats->trafficUDP);
    LogMessage("ICMP:  %.2f%%\n", sfFlowStats->trafficICMP);
    LogMessage("OTHER: %.2f%%\n", sfFlowStats->trafficOTHER);

    LogMessage("\n");
    LogMessage("\n");
    LogMessage("PacketLen - %%TotalPackets\n");
    LogMessage(    "-------------------------\n"); 
    for(i=1;i<SF_MAX_PKT_LEN;i++)
    {
        if( sfFlowStats->pktLenPercent[i] < .1 ) continue;
     
        LogMessage("Bytes[%d] %.2f%%\n", i, sfFlowStats->pktLenPercent[i]);
    }

    LogMessage("\n");
    LogMessage("\n");
    LogMessage("TCP Port Flows\n");
    LogMessage(    "--------------\n"); 
    for(i=0;i<SF_MAX_PORT;i++)
    {
        if(sfFlowStats->portflowTCP.totperc[i] && 
           sfFlowStats->portflowTCP.dport_rate[i]  )
        {
            LogMessage("Port[%d] %.2f%% of Total, Src: %6.2f%% Dst: %6.2f%%\n",
                        i, sfFlowStats->portflowTCP.totperc[i],
                        sfFlowStats->portflowTCP.sport_rate[i],
                        sfFlowStats->portflowTCP.dport_rate[i]);
        }
    }

    if(sfFlowStats->portflowHighTCP > .1)
    {
        LogMessage("Ports[High<->High]: %.2f%%\n", 
                sfFlowStats->portflowHighTCP);
    }

    LogMessage("\n");
    LogMessage("\n");
    LogMessage("UDP Port Flows\n");
    LogMessage(    "--------------\n"); 
    for(i=0;i<SF_MAX_PORT;i++)
    {
        if(sfFlowStats->portflowUDP.totperc[i] && 
           sfFlowStats->portflowUDP.dport_rate[i]  )
        {
            LogMessage("Port[%d] %.2f%% of Total, Src: %6.2f%% Dst: %6.2f%%\n",
                        i, sfFlowStats->portflowUDP.totperc[i],
                        sfFlowStats->portflowUDP.sport_rate[i],
                        sfFlowStats->portflowUDP.dport_rate[i]);
        }
    }

    if(sfFlowStats->portflowHighUDP > .1)
    {
        LogMessage("Ports[High<->High]: %.2f%%\n", 
                sfFlowStats->portflowHighUDP);
    }

    LogMessage("\n");
    LogMessage("\n");
    LogMessage("ICMP Type Flows\n");
    LogMessage(    "---------------\n");
    for(i=0;i<256;i++)
    {
        if(sfFlowStats->flowICMP.totperc[i])
        {
            LogMessage("Type[%d] %.2f%% of Total\n",
                        i, sfFlowStats->flowICMP.totperc[i]);
        }
    }

         
    return 0;
}

