/*
** Copyright (C) 2007-2009 Sourcefire, Inc.
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
*/

/* spo_unified2.c
 * Adam Keeton
 * 
 * 09/26/06
 * This file is litterally spo_unified.c converted to write unified2
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>
#include <time.h>

#include "spo_unified2.h"
#include "decode.h"
#include "rules.h"
#include "util.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "parser.h"
#include "debug.h"
#include "mstring.h"
#include "event.h"
#include "generators.h"
#include "debug.h"
#include "bounds.h"

#include "snort.h"
#include "pcap_pkthdr32.h"

/* For the traversal of reassembled packets */
#include "stream_api.h"

#ifdef GIDS
#include "inline.h"
#endif

/* ------------------ Data structures --------------------------*/
typedef struct _Unified2Config
{
    char *base_filename;
    char filepath[STD_BUF];
    uint32_t timestamp;
    FILE *stream;
    unsigned int limit;
    unsigned int current;
    int nostamp;
#ifdef MPLS
    int mpls_event_types;
#endif
    int vlan_event_types;
} Unified2Config;

typedef struct _Unified2LogStreamCallbackData
{
    Unified2Packet *logheader;
    Unified2Config *config;
    Event *event;
    int once;
} Unified2LogStreamCallbackData;

/* ----------------External variables -------------------- */
/* From fpdetect.c, for logging reassembled packets */
extern uint16_t event_id;
extern OptTreeNode *otn_tmp;

#ifdef GIDS
#ifndef IPFW
extern ipq_packet_msg_t *g_m;
#endif
#endif

/* -------------------- Global Variables ----------------------*/
#ifdef GIDS
EtherHdr g_ethernet;
#endif

/* Used for buffering header and payload of unified records so only one
 * write is necessary.  Unified2Event6 is used as Unified2Event size
 * since it is the largest */
static uint8_t write_pkt_buffer[sizeof(Unified2RecordHeader) +
                                sizeof(Unified2Event6) + IP_MAXPACKET];
#define write_pkt_end (write_pkt_buffer + sizeof(write_pkt_buffer))

static uint8_t write_pkt_buffer_v2[sizeof(Unified2RecordHeader) +
                                     sizeof(Unified2Event6_v2) + IP_MAXPACKET];
#define write_pkt_end_v2 (write_pkt_buffer_v2 + sizeof(write_pkt_buffer_v2))

/* This is the buffer to use for I/O.  Try to make big enough so the system
 * doesn't potentially flush in the middle of a record.  Every write is
 * force flushed to disk immediately after the entire record is written so
 * spoolers get an entire record */
#define UNIFIED2_SETVBUF
#ifndef WIN32
/* use the size of the buffer we copy record data into */
static char io_buffer[sizeof(write_pkt_buffer_v2)];
#else
# ifdef _MSC_VER
#  if _MSC_VER <= 1200
/* use maximum size defined by VC++ 6.0 */
static char io_buffer[32768];
#  else
static char io_buffer[sizeof(write_pkt_buffer_v2)];
#  endif  /* _MSC_VER <= 1200 */
# else
/* no _MSC_VER, don't set I/O buffer */
#  undef UNIFIED2_SETVBUF
# endif  /* _MSC_VER */
#endif  /* WIN32 */

/* -------------------- Local Functions -----------------------*/
static Unified2Config * Unified2ParseArgs(char *, char *);
static void Unified2CleanExit(int, void *);
static void Unified2Restart(int, void *);

/* Unified2 Output functions */
static void Unified2Init(char *);
static void Unified2PostConfig(int, void *);
static void Unified2InitFile(Unified2Config *);
static INLINE void Unified2RotateFile(Unified2Config *);
static void Unified2LogAlert(Packet *, char *, void *, Event *);
static void _AlertIP4(Packet *, char *, Unified2Config *, Event *);
static void _AlertIP6(Packet *, char *, Unified2Config *, Event *);
static void Unified2LogPacketAlert(Packet *, char *, void *, Event *);
static void _Unified2LogPacketAlert(Packet *, char *, Unified2Config *, Event *);
static void _Unified2LogStreamAlert(Packet *, char *, Unified2Config *, Event *);
static int Unified2LogStreamCallback(struct pcap_pkthdr *, uint8_t *, void *);
static void Unified2Write(uint8_t *, uint32_t, Unified2Config *);

static void _AlertIP4_v2(Packet *, char *, Unified2Config *, Event *);
static void _AlertIP6_v2(Packet *, char *, Unified2Config *, Event *);

/* Unified2 Alert functions (deprecated) */
static void Unified2AlertInit(char *);

/* Unified2 Packet Log functions (deprecated) */
static void Unified2LogInit(char *);

#define U2_PACKET_FLAG 1

#define U2_FLAG_BLOCKED 0x20

/*
 * Function: SetupUnified2()
 *
 * Purpose: Registers the output plugin keyword and initialization 
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void Unified2Setup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("log_unified2", OUTPUT_TYPE_FLAG__LOG, Unified2LogInit);
    RegisterOutputPlugin("alert_unified2", OUTPUT_TYPE_FLAG__ALERT, Unified2AlertInit);
    RegisterOutputPlugin("unified2", OUTPUT_TYPE_FLAG__LOG | OUTPUT_TYPE_FLAG__ALERT, Unified2Init);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output plugin: Unified2 "
                            "logging/alerting is setup...\n"););
}

/*
 * Function: Unified2Init(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void Unified2Init(char *args)
{
    Unified2Config *config;

    /* parse the argument list from the rules file */
    config = Unified2ParseArgs(args, "snort-unified");

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(Unified2LogAlert, OUTPUT_TYPE__ALERT, config);
    AddFuncToOutputList(Unified2LogPacketAlert, OUTPUT_TYPE__LOG, config);

    AddFuncToCleanExitList(Unified2CleanExit, config);
    AddFuncToRestartList(Unified2Restart, config);
    AddFuncToPostConfigList(Unified2PostConfig, config);
}

static void Unified2PostConfig(int unused, void *data)
{
    Unified2Config *config = (Unified2Config *)data;
    int status;

    if (config == NULL || config->base_filename == NULL)
    {
        FatalError("%s(%d) Could not initialize unified2 file: Unified2 "
                   "configuration data or file name is NULL.\n",
                   __FILE__, __LINE__);
    }

#ifndef WIN32
    if (config->base_filename[0] == '/')
    {
        status = SnortSnprintf(config->filepath, sizeof(config->filepath),
                               "%s", config->base_filename);
    }
    else
#endif
    {
        status = SnortSnprintf(config->filepath, sizeof(config->filepath),
                               "%s/%s", snort_conf->log_dir, config->base_filename);
    }

    if (status != SNORT_SNPRINTF_SUCCESS)
    {
        FatalError("%s(%d) Failed to copy unified2 file name\n",
                   __FILE__, __LINE__);
    }

    Unified2InitFile(config);
}

/*
 * Function: Unified2InitFile()
 *
 * Purpose: Initialize the unified2 ouput file 
 *
 * Arguments: config => pointer to the plugin's reference data struct 
 *
 * Returns: void function
 */
static void Unified2InitFile(Unified2Config *config)
{
    char filepath[STD_BUF];
    char *fname_ptr;

    if (config == NULL)
    {
        FatalError("%s(%d) Could not initialize unified2 file: Unified2 "
                   "configuration data is NULL.\n", __FILE__, __LINE__);
    }

    config->timestamp = (uint32_t)time(NULL);

    if (!config->nostamp)
    {
        if (SnortSnprintf(filepath, sizeof(filepath), "%s.%u",
                          config->filepath, config->timestamp) != SNORT_SNPRINTF_SUCCESS)
        {
            FatalError("%s(%d) Failed to copy unified2 file path.\n",
                       __FILE__, __LINE__);
        }

        fname_ptr = filepath;
    }
    else
    {
        fname_ptr = config->filepath;
    }

    if ((config->stream = fopen(fname_ptr, "wb")) == NULL)
    {
        FatalError("%s(%d) Could not open %s: %s\n",
                   __FILE__, __LINE__, fname_ptr, strerror(errno));
    }

#ifdef UNIFIED2_SETVBUF
    /* Set buffer to size of record buffer so the system doesn't flush
     * part of a record if it's greater than BUFSIZ */
    if (setvbuf(config->stream, io_buffer, _IOFBF, sizeof(io_buffer)) != 0)
    {
        ErrorMessage("%s(%d) Could not set I/O buffer: %s. "
                     "Using system default.\n",
                     __FILE__, __LINE__, strerror(errno));
    }
#endif

    /* If test mode, close and delete the file */
    if (ScTestMode())
    {
        fclose(config->stream);
        config->stream = NULL;
        if (unlink(fname_ptr) == -1)
        {
            ErrorMessage("%s(%d) Running in test mode so we want to remove "
                         "test unified2 file. Could not unlink file \"%s\": %s\n",
                         __FILE__, __LINE__, fname_ptr, strerror(errno));
        }
    }
}

static INLINE void Unified2RotateFile(Unified2Config *config)
{
    fclose(config->stream);
    config->current = 0;
    Unified2InitFile(config);
}

static void _AlertIP4(Packet *p, char *msg, Unified2Config *config, Event *event)
{
    Unified2RecordHeader hdr;
    Unified2Event alertdata;
    uint32_t write_len = sizeof(Unified2RecordHeader) + sizeof(Unified2Event);

    memset(&alertdata, 0, sizeof(alertdata));
    
    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_generator);
    alertdata.signature_id = htonl(event->sig_id);
    alertdata.signature_revision = htonl(event->sig_rev);
    alertdata.classification_id = htonl(event->classification);
    alertdata.priority_id = htonl(event->priority);

    if (p != NULL)
    {
        if (p->packet_flags & PKT_INLINE_DROP)
        {
            alertdata.packet_action = U2_FLAG_BLOCKED;
        }

        if(IPH_IS_VALID(p))
        {
            alertdata.ip_source = p->iph->ip_src.s_addr;
            alertdata.ip_destination = p->iph->ip_dst.s_addr;
            alertdata.protocol = GET_IPH_PROTO(p);

            if ((alertdata.protocol == IPPROTO_ICMP) && p->icmph)
            {
                alertdata.sport_itype = htons(p->icmph->type);
                alertdata.dport_icode = htons(p->icmph->code);
            }
            else if (alertdata.protocol != 255)
            {
                alertdata.sport_itype = htons(p->sp);
                alertdata.dport_icode = htons(p->dp);
            }
        }
    }
    
    if ((config->current + write_len) > config->limit)
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Unified2Event));
    hdr.type = htonl(UNIFIED2_IDS_EVENT);

    if (SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Unified2RecordHeader), 
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2RecordHeader. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }
    
    if (SafeMemcpy(write_pkt_buffer + sizeof(Unified2RecordHeader),
                   &alertdata, sizeof(Unified2Event), 
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2Event. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    Unified2Write(write_pkt_buffer, write_len, config);
}

static void _AlertIP4_v2(Packet *p, char *msg, Unified2Config *config, Event *event)
{
    Unified2RecordHeader hdr;
    Unified2Event_v2 alertdata;
    uint32_t write_len = sizeof(Unified2RecordHeader) + sizeof(Unified2Event_v2);

    memset(&alertdata, 0, sizeof(alertdata));
    
    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_generator);
    alertdata.signature_id = htonl(event->sig_id);
    alertdata.signature_revision = htonl(event->sig_rev);
    alertdata.classification_id = htonl(event->classification);
    alertdata.priority_id = htonl(event->priority);

    if(p)
    {
        if (p->packet_flags & PKT_INLINE_DROP)
        {
            alertdata.packet_action = U2_FLAG_BLOCKED;
        }

        if(IPH_IS_VALID(p))
        {
            alertdata.ip_source = p->iph->ip_src.s_addr;
            alertdata.ip_destination = p->iph->ip_dst.s_addr;
            alertdata.protocol = GET_IPH_PROTO(p);

            if ((alertdata.protocol == IPPROTO_ICMP) && p->icmph)
            {
                alertdata.sport_itype = htons(p->icmph->type);
                alertdata.dport_icode = htons(p->icmph->code);
            }
            else if (alertdata.protocol != 255)
            {
                alertdata.sport_itype = htons(p->sp);
                alertdata.dport_icode = htons(p->dp);
            }

#ifdef MPLS
            if((p->mpls) && (config->mpls_event_types))
            {
                alertdata.mpls_label = htonl(p->mplsHdr.label);
            }
#endif
            if(config->vlan_event_types)
            {
                if(p->vh)
                {
                    alertdata.vlanId = htons(VTH_VLAN(p->vh));
                }

                alertdata.configPolicyId = htons(p->configPolicyId);
            }

        }
    }
    
    if ((config->current + write_len) > config->limit)
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Unified2Event_v2));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_V2);

    if (SafeMemcpy(write_pkt_buffer_v2, &hdr, sizeof(Unified2RecordHeader), 
                   write_pkt_buffer_v2, write_pkt_end_v2) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2RecordHeader. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }
    
    if (SafeMemcpy(write_pkt_buffer_v2 + sizeof(Unified2RecordHeader),
                   &alertdata, sizeof(Unified2Event_v2), 
                   write_pkt_buffer_v2, write_pkt_end_v2) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2Event. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    Unified2Write(write_pkt_buffer_v2, write_len, config);
}

static void _AlertIP6(Packet *p, char *msg, Unified2Config *config, Event *event) 
{
#ifdef SUP_IP6
    Unified2RecordHeader hdr;
    Unified2Event6 alertdata;
    uint32_t write_len = sizeof(Unified2RecordHeader) + sizeof(Unified2Event6);

    memset(&alertdata, 0, sizeof(alertdata));
    
    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_generator);
    alertdata.signature_id = htonl(event->sig_id);
    alertdata.signature_revision = htonl(event->sig_rev);
    alertdata.classification_id = htonl(event->classification);
    alertdata.priority_id = htonl(event->priority);

    if(p)
    {
        if (p->packet_flags & PKT_INLINE_DROP)
        {
            alertdata.packet_action = U2_FLAG_BLOCKED;
        }

        if(IPH_IS_VALID(p))
        {
            snort_ip_p ip;

            ip = GET_SRC_IP(p);
            alertdata.ip_source = *(struct in6_addr*)ip->ip32;

            ip = GET_DST_IP(p);
            alertdata.ip_destination = *(struct in6_addr*)ip->ip32;

            alertdata.protocol = GET_IPH_PROTO(p);

            if ((alertdata.protocol == IPPROTO_ICMP) && p->icmph)
            {
                alertdata.sport_itype = htons(p->icmph->type);
                alertdata.dport_icode = htons(p->icmph->code);
            }
            else if (alertdata.protocol != 255)
            {
                alertdata.sport_itype = htons(p->sp);
                alertdata.dport_icode = htons(p->dp);
            }
        }
    }
    
    if ((config->current + write_len) > config->limit)
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Unified2Event6));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_IPV6);

    if (SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Unified2RecordHeader), 
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2RecordHeader. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }
    
    if (SafeMemcpy(write_pkt_buffer + sizeof(Unified2RecordHeader),
                   &alertdata, sizeof(Unified2Event6), 
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2Event6. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    Unified2Write(write_pkt_buffer, write_len, config);
#endif
}

static void _AlertIP6_v2(Packet *p, char *msg, Unified2Config *config, Event *event)
{
#ifdef SUP_IP6
    Unified2RecordHeader hdr;
    Unified2Event6_v2 alertdata;
    uint32_t write_len = sizeof(Unified2RecordHeader) + sizeof(Unified2Event6_v2);

    memset(&alertdata, 0, sizeof(alertdata));

    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_generator);
    alertdata.signature_id = htonl(event->sig_id);
    alertdata.signature_revision = htonl(event->sig_rev);
    alertdata.classification_id = htonl(event->classification);
    alertdata.priority_id = htonl(event->priority);

    if(p)
    {
        if (p->packet_flags & PKT_INLINE_DROP)
        {
            alertdata.packet_action = U2_FLAG_BLOCKED;
        }

        if(IPH_IS_VALID(p))
        {
            snort_ip_p ip;

            ip = GET_SRC_IP(p);
            alertdata.ip_source = *(struct in6_addr*)ip->ip32;

            ip = GET_DST_IP(p);
            alertdata.ip_destination = *(struct in6_addr*)ip->ip32;

            alertdata.protocol = GET_IPH_PROTO(p);

            if ((alertdata.protocol == IPPROTO_ICMP) && p->icmph)
            {
                alertdata.sport_itype = htons(p->icmph->type);
                alertdata.dport_icode = htons(p->icmph->code);
            }
            else if (alertdata.protocol != 255)
            {
                alertdata.sport_itype = htons(p->sp);
                alertdata.dport_icode = htons(p->dp);
            }

#ifdef MPLS
            if((p->mpls) && (config->mpls_event_types))
            {
                alertdata.mpls_label = htonl(p->mplsHdr.label);
            }
#endif
            if(config->vlan_event_types)
            {
                if(p->vh)
                {
                    alertdata.vlanId = htons(VTH_VLAN(p->vh));
                }

                alertdata.configPolicyId = htons(p->configPolicyId);
            }
        }
    }
    
    if ((config->current + write_len) > config->limit)
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Unified2Event6_v2));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_IPV6_V2);

    if (SafeMemcpy(write_pkt_buffer_v2, &hdr, sizeof(Unified2RecordHeader), 
                   write_pkt_buffer_v2, write_pkt_end_v2) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2RecordHeader. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }
    
    if (SafeMemcpy(write_pkt_buffer_v2 + sizeof(Unified2RecordHeader),
                   &alertdata, sizeof(Unified2Event6_v2), 
                   write_pkt_buffer_v2, write_pkt_end_v2) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2Event6_v2. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    Unified2Write(write_pkt_buffer_v2, write_len, config);
#endif
}
static void Unified2LogAlert(Packet *p, char *msg, void *arg, Event *event)
{
    Unified2Config *config = (Unified2Config *)arg;

    if (config == NULL)
        return;

    if(!event) return;
    if(IS_IP4(p))
    {
#ifdef MPLS
        if((config->vlan_event_types) || (config->mpls_event_types))
#else
        if(config->vlan_event_types)
#endif
        {
            _AlertIP4_v2(p, msg, config, event); 
        }
        else 
            _AlertIP4(p, msg, config, event);
    } 
    else 
    {
#ifdef MPLS
        if((config->vlan_event_types) || (config->mpls_event_types))
#else
        if(config->vlan_event_types)
#endif
        {
            _AlertIP6_v2(p, msg, config, event); 
        }
        else 
            _AlertIP6(p, msg, config, event);
    }

    return;
}

static void Unified2LogPacketAlert(Packet *p, char *msg, void *arg, Event *event)
{
    Unified2Config *config = (Unified2Config *)arg;

    if (config == NULL)
        return;

    if(p) 
    {
        if ((p->packet_flags & PKT_REBUILT_STREAM) && stream_api)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_LOG, 
                        "[*] Reassembled packet, dumping stream packets\n"););
            _Unified2LogStreamAlert(p, msg, config, event);
        }
        else 
        {
            DEBUG_WRAP(DebugMessage(DEBUG_LOG, "[*] Logging unified 2 packets...\n"););
            _Unified2LogPacketAlert(p, msg, config, event);
        }
   }
}

static void _Unified2LogPacketAlert(Packet *p, char *msg, 
                                    Unified2Config *config, Event *event)
{ 
    Unified2RecordHeader hdr;
    Unified2Packet logheader;
    uint32_t pkt_length = 0; 
    uint32_t write_len = sizeof(Unified2RecordHeader) + sizeof(Unified2Packet) - 4;

    logheader.sensor_id = 0;
    logheader.linktype = htonl(datalink);

    if (event != NULL)
    {
        logheader.event_id = htonl(event->event_reference);
        logheader.event_second = htonl(event->ref_time.tv_sec);

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "------------\n"));
    }
    else
    {
        logheader.event_id = 0;
        logheader.event_second = 0;
    }

    if(p && p->pkt && p->pkth)
    {
        logheader.packet_second = htonl((uint32_t)p->pkth->ts.tv_sec);
        logheader.packet_microsecond = htonl((uint32_t)p->pkth->ts.tv_usec);
        logheader.packet_length = htonl(p->pkth->caplen);

        pkt_length = p->pkth->caplen;
        write_len += pkt_length;
    }
    else
    {
        logheader.packet_second = 0;
        logheader.packet_microsecond = 0;
        logheader.packet_length = 0;
    }

    if ((config->current + write_len) > config->limit)
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Unified2Packet) - 4 + pkt_length);
    hdr.type = htonl(UNIFIED2_PACKET);

    if (SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Unified2RecordHeader), 
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2RecordHeader. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    if (SafeMemcpy(write_pkt_buffer + sizeof(Unified2RecordHeader),
                   &logheader, sizeof(Unified2Packet) - 4,
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2Packet. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    if (pkt_length != 0)
    {
        if (SafeMemcpy(write_pkt_buffer + sizeof(Unified2RecordHeader) +
                       sizeof(Unified2Packet) - 4,
                       p->pkt, pkt_length,
                       write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
        {
            ErrorMessage("%s(%d) Failed to copy packet data. "
                         "Not writing unified2 event.\n", __FILE__, __LINE__);
            return;
        }
    }

    Unified2Write(write_pkt_buffer, write_len, config);
}

/**
 * Callback for the Stream reassembler to log packets
 *
 */
static int Unified2LogStreamCallback(struct pcap_pkthdr *pkth,
                                     uint8_t *packet_data, void *userdata)
{
    Unified2LogStreamCallbackData *unifiedData = (Unified2LogStreamCallbackData *)userdata;
    Unified2RecordHeader hdr;
    uint32_t write_len = sizeof(Unified2RecordHeader) + sizeof(Unified2Packet) - 4;

    if (!userdata || !pkth || !packet_data)
        return -1;

    write_len += pkth->caplen;
    if ((unifiedData->config->current + write_len) > unifiedData->config->limit)
        Unified2RotateFile(unifiedData->config);

    hdr.type = htonl(UNIFIED2_PACKET);
    hdr.length = htonl(sizeof(Unified2Packet) - 4 + pkth->caplen);

    /* Event data will already be set */

    unifiedData->logheader->packet_second = htonl((uint32_t)pkth->ts.tv_sec);
    unifiedData->logheader->packet_microsecond = htonl((uint32_t)pkth->ts.tv_usec);
    unifiedData->logheader->packet_length = htonl(pkth->caplen);

    if (SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Unified2RecordHeader),
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2RecordHeader. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return -1;
    }

    if (SafeMemcpy(write_pkt_buffer + sizeof(Unified2RecordHeader),
                   unifiedData->logheader, sizeof(Unified2Packet) - 4,
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2Packet. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return -1;
    }

    if (SafeMemcpy(write_pkt_buffer + sizeof(Unified2RecordHeader) +
                   sizeof(Unified2Packet) - 4,
                   packet_data, pkth->caplen,
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy packet data. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return -1;
    }

    Unified2Write(write_pkt_buffer, write_len, unifiedData->config);

#if 0 
    /* DO NOT DO THIS FOR UNIFIED2.
     * The event referenced below in the unifiedData is a pointer
     * to the actual event and this changes its gid & sid to 2:1.
     * That is baaaaad.
     */
    /* after the first logged packet modify the event headers */
    if(!unifiedData->once++)
    {
        unifiedData->event->sig_generator = GENERATOR_TAG;
        unifiedData->event->sig_id = TAG_LOG_PKT;
        unifiedData->event->sig_rev = 1;
        unifiedData->event->classification = 0;
        unifiedData->event->priority = unifiedData->event->priority;
        /* Note that event_id is now incorrect. 
         * See OldUnified2LogPacketAlert() for details. */
    }
#endif

    return 0;
}


/**
 * Log a set of packets stored in the stream reassembler
 *
 */
static void _Unified2LogStreamAlert(Packet *p, char *msg, Unified2Config *config, Event *event)
{
    Unified2LogStreamCallbackData unifiedData;
    Unified2Packet logheader;
    int once = 0;

    logheader.sensor_id = 0;
    logheader.linktype = htonl(datalink);

    /* setup the event header */
    if (event != NULL)
    {
        logheader.event_id = htonl(event->event_reference);
        logheader.event_second = htonl(event->ref_time.tv_sec);
    }
    else
    {
        logheader.event_id = 0;
        logheader.event_second = 0;
    }

    /* queue up the stream for logging */
    unifiedData.logheader = &logheader;
    unifiedData.config = config;
    unifiedData.event = event;
    unifiedData.once = once;

    stream_api->traverse_reassembled(p, Unified2LogStreamCallback, &unifiedData);
}

/*
 * Function: Unified2ParseArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
static Unified2Config * Unified2ParseArgs(char *args, char *default_filename)
{
    Unified2Config *config = (Unified2Config *)SnortAlloc(sizeof(Unified2Config));

    /* This is so the if 'nostamps' option is used on the command line,
     * it will be honored by unified2, and only one variable is used. */
    config->nostamp = ScNoOutputTimestamp();

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Args: %s\n", args););

    if(args != NULL)
    {
        char **toks;
        int num_toks;
        int i = 0;
        toks = mSplit((char *)args, ",", 31, &num_toks, '\\');
        for(i = 0; i < num_toks; ++i)
        {
            char **stoks;
            int num_stoks;
            char *index = toks[i];
            while(isspace((int)*index))
                ++index;
          
            stoks = mSplit(index, " \t", 2, &num_stoks, 0);
            
            if(strcasecmp("filename", stoks[0]) == 0)
            {
                if(num_stoks > 1 && config->base_filename == NULL)
                    config->base_filename = SnortStrdup(stoks[1]);
                else
                    FatalError("Argument Error in %s(%i): %s\n",
                            file_name, file_line, index);
            }
            else if(strcasecmp("limit", stoks[0]) == 0)
            {
                char *end;

                if ((num_stoks > 1) && (config->limit == 0))
                {
                    config->limit = strtoul(stoks[1], &end, 10);
                    if ((stoks[1] == end) || (errno == ERANGE))
                    {
                        FatalError("Argument Error in %s(%i): %s\n",
                                   file_name, file_line, index);
                    }
                }
                else
                {
                    FatalError("Argument Error in %s(%i): %s\n",
                               file_name, file_line, index);
                }
            }
            else if(strcasecmp("nostamp", stoks[0]) == 0)
            {
                config->nostamp = 1;
            }
#ifdef MPLS
            else if(strcasecmp("mpls_event_types", stoks[0]) == 0)
            {
                config->mpls_event_types = 1;
            }
#endif
            else if(strcasecmp("vlan_event_types", stoks[0]) == 0)
            {
                config->vlan_event_types = 1;
            }
            else
            {
                FatalError("Argument Error in %s(%i): %s\n",
                        file_name, file_line, index);
            }

            mSplitFree(&stoks, num_stoks);
        }
        mSplitFree(&toks, num_toks);
    }

    if (config->base_filename == NULL)
        config->base_filename = SnortStrdup(default_filename);

    if (config->limit == 0)
    {
        config->limit = 128;
    }
    else if (config->limit > 512)
    {
        LogMessage("spo_unified2 %s(%d)=> Lowering limit of %iMB to 512MB\n", 
            file_name, file_line, config->limit);
        config->limit = 512;
    }

    /* convert the limit to "MB" */
    config->limit <<= 20;

    return config;
}

/*
 * Function: Unified2CleanExitFunc()
 *
 * Purpose: Cleanup at exit time
 *
 * Arguments: signal => signal that caused this event
 *            arg => data ptr to reference this plugin's data
 *
 * Returns: void function
 */
static void Unified2CleanExit(int signal, void *arg)
{
    /* cast the arg pointer to the proper type */
    Unified2Config *config = (Unified2Config *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "SpoUnified2: CleanExit\n"););

    /* free up initialized memory */
    if (config != NULL)
    {
        if (config->stream != NULL)
            fclose(config->stream);

        if (config->base_filename != NULL)
            free(config->base_filename);

        free(config);
    }
}

/*
 * Function: Restart()
 *
 * Purpose: For restarts (SIGHUP usually) clean up structs that need it
 *
 * Arguments: signal => signal that caused this event
 *            arg => data ptr to reference this plugin's data
 *
 * Returns: void function
 */
static void Unified2Restart(int signal, void *arg)
{
    Unified2Config *config = (Unified2Config *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "SpoUnified2: Restart\n"););

    /* free up initialized memory */
    if (config != NULL)
    {
        if (config->stream != NULL)
            fclose(config->stream);

        if (config->base_filename != NULL)
            free(config->base_filename);

        free(config);
    }
}

/* Unified2 Alert functions (deprecated) */
static void Unified2AlertInit(char *args)
{
    Unified2Config *config;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: Unified2 Alert Initialized\n"););

    /* parse the argument list from the rules file */
    config = Unified2ParseArgs(args, "snort-unified.alert");

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(Unified2LogAlert, OUTPUT_TYPE__ALERT, config);
    AddFuncToCleanExitList(Unified2CleanExit, config);
    AddFuncToRestartList(Unified2Restart, config);
    AddFuncToPostConfigList(Unified2PostConfig, config);
}

/* Unified2 Packet Log functions (deprecated) */
static void Unified2LogInit(char *args)
{
    Unified2Config *config;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: Unified2 Log Initialized\n"););

    /* parse the argument list from the rules file */
    config = Unified2ParseArgs(args, "snort-unified.log");

    //LogMessage("Unified2LogFilename = %s\n", Unified2Info->filename);

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(Unified2LogPacketAlert, OUTPUT_TYPE__LOG, config);
    AddFuncToCleanExitList(Unified2CleanExit, config);
    AddFuncToRestartList(Unified2Restart, config);
    AddFuncToPostConfigList(Unified2PostConfig, config);
}

/******************************************************************************
 * Function: Unified2Write()
 *
 * Main function for writing to the unified2 file.
 *
 * For low level I/O errors, the current unified2 file is closed and a new
 * one created and a write to the new unified2 file is done.  It was found
 * that when writing to an NFS mounted share that is using a soft mount option,
 * writes sometimes fail and leave the unified2 file corrupted.  If the write
 * to the newly created unified2 file fails, Snort will fatal error.
 *
 * In the case of interrupt errors, the write is retried, but only for a 
 * finite number of times.
 *
 * All other errors are treated as non-recoverable and Snort will fatal error.
 *
 * Upon successful completion of write, the length of the data written is
 * added to the current amount of total data written thus far to the
 * unified2 file.
 *
 * Arguments
 *  uint8_t *
 *      The buffer containing the data to write
 *  uint32_t
 *      The length of the data to write
 *  Unified2Config *
 *      A pointer to the unified2 configuration data
 *
 * Returns: None
 *
 ******************************************************************************/
static void Unified2Write(uint8_t *buf, uint32_t buf_len, Unified2Config *config)
{
    size_t fwcount = 0;
    int ffstatus = 0;

    /* Nothing to write or nothing to write to */
    if ((buf == NULL) || (config == NULL) || (config->stream == NULL))
        return;

    /* Don't use fsync().  It is a total performance killer */
    if (((fwcount = fwrite(buf, (size_t)buf_len, 1, config->stream)) != 1) ||
        ((ffstatus = fflush(config->stream)) != 0))
    {
        /* errno is saved just to avoid other intervening calls
         * (e.g. ErrorMessage) potentially reseting it to something else. */
        int error = errno;
        int max_retries = 3;

        /* On iterations other than the first, the only non-zero error will be
         * EINTR or interrupt.  Only iterate a maximum of max_retries times so 
         * there is no chance of infinite looping if for some reason the write
         * is constantly interrupted */
        while ((error != 0) && (max_retries != 0))
        {
            if (config->nostamp)
            {
                ErrorMessage("%s(%d) Failed to write to unified2 file (%s): %s\n",
                             __FILE__, __LINE__, config->filepath, strerror(error));
            }
            else
            {
                ErrorMessage("%s(%d) Failed to write to unified2 file (%s.%u): %s\n",
                             __FILE__, __LINE__, config->filepath,
                             config->timestamp, strerror(error));
            }

            while ((error == EINTR) && (max_retries != 0))
            {
                max_retries--;

                /* Supposedly an interrupt can only occur before anything
                 * has been written.  Try again */
                ErrorMessage("%s(%d) Got interrupt. Retry write to unified2 "
                             "file.\n", __FILE__, __LINE__);

                if (fwcount != 1)
                {
                    /* fwrite() failed.  Redo fwrite and fflush */
                    if (((fwcount = fwrite(buf, (size_t)buf_len, 1, config->stream)) == 1) &&
                        ((ffstatus = fflush(config->stream)) == 0))
                    {
                        ErrorMessage("%s(%d) Write to unified2 file succeeded!\n",
                                     __FILE__, __LINE__);
                        error = 0;
                        break;
                    }
                }
                else if ((ffstatus = fflush(config->stream)) == 0)
                {
                    ErrorMessage("%s(%d) Write to unified2 file succeeded!\n",
                                 __FILE__, __LINE__);
                    error = 0;
                    break;
                }

                error = errno;

                ErrorMessage("%s(%d) Retrying write to unified2 file failed.\n",
                             __FILE__, __LINE__);
            }

            /* If we've reached the maximum number of interrupt retries,
             * just bail out of the main while loop */
            if (max_retries == 0)
                continue;

            switch (error)
            {
                case 0:
                    break;

                case EIO:
                    ErrorMessage("%s(%d) Unified2 file is possibly corrupt. "
                                 "Closing this unified2 file and creating "
                                 "a new one.\n", __FILE__, __LINE__);

                    Unified2RotateFile(config);

                    if (config->nostamp)
                    {
                        ErrorMessage("%s(%d) New unified2 file: %s\n",
                                     __FILE__, __LINE__, config->filepath);
                    }
                    else
                    {
                        ErrorMessage("%s(%d) New unified2 file: %s.%u\n",
                                     __FILE__, __LINE__,
                                     config->filepath, config->timestamp);
                    }

                    if (((fwcount = fwrite(buf, (size_t)buf_len, 1, config->stream)) == 1) &&
                        ((ffstatus = fflush(config->stream)) == 0))
                    {
                        ErrorMessage("%s(%d) Write to unified2 file succeeded!\n",
                                     __FILE__, __LINE__);
                        error = 0;
                        break;
                    }

                    error = errno;

                    /* Loop again if interrupt */
                    if (error == EINTR)
                        break;

                    /* Write out error message again, then fall through and fatal */
                    if (config->nostamp)
                    {
                        ErrorMessage("%s(%d) Failed to write to unified2 file (%s): %s\n",
                                     __FILE__, __LINE__, config->filepath, strerror(error));
                    }
                    else
                    {
                        ErrorMessage("%s(%d) Failed to write to unified2 file (%s.%u): %s\n",
                                     __FILE__, __LINE__, config->filepath,
                                     config->timestamp, strerror(error));
                    }

                    /* Fall through */

                case EAGAIN:  /* We're not in non-blocking mode */
                case EBADF:
                case EFAULT:
                case EFBIG:
                case EINVAL:
                case ENOSPC:
                case EPIPE:
                default:
                    FatalError("%s(%d) Cannot write to device.\n", __FILE__, __LINE__);
            }
        }

        if ((max_retries == 0) && (error != 0))
        {
            FatalError("%s(%d) Maximum number of interrupts exceeded. "
                       "Cannot write to device.\n", __FILE__, __LINE__);
        }
    }

    config->current += buf_len;
}

