/*
 * snort_dcerpc.c
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
 * Description:
 *
 * This performs the DCERPC decoding.
 *
 * Arguments:
 *   
 * Effect:
 *
 * None
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "debug.h"
#include "snort_dcerpc.h"
#include "smb_structs.h"
#include "smb_andx_decode.h"
#include "smb_file_decode.h"
#include "dcerpc.h"
#include "dcerpc_util.h"
#include "bounds.h"
#include "sf_snort_packet.h"
#include "sf_types.h"

#include "profiler.h"
#ifdef PERF_PROFILING
extern PreprocStats dcerpcPerfStats;
extern PreprocStats dcerpcDetectPerfStats;
extern PreprocStats dcerpcIgnorePerfStats;
#endif

uint32_t _total_memory = 0;

#ifdef TARGET_BASED
DCERPC_ProtoIds _dce_proto_ids;
#endif

/* Session structure */
DCERPC    *_dcerpc;
/* Save packet so we don't have to pass it around */
SFSnortPacket *_dcerpc_pkt;

uint8_t *dce_reassembly_buf = NULL;
const uint16_t dce_reassembly_buf_size = IP_MAXPKT - (IP_HDR_LEN + TCP_HDR_LEN);

/* this is used to store one of the below */
SFSnortPacket *real_dce_mock_pkt = NULL;

SFSnortPacket *dce_mock_pkt = NULL;
const uint16_t dce_mock_pkt_payload_len = IP_MAXPKT - (IP_HDR_LEN + TCP_HDR_LEN);
#ifdef SUP_IP6
SFSnortPacket *dce_mock_pkt_6 = NULL;
const uint16_t dce_mock_pkt_6_payload_len = IP_MAXPKT - (IP6_HDR_LEN + TCP_HDR_LEN);
#endif

extern tSfPolicyUserContextId dcerpc_config;
extern DceRpcConfig *dcerpc_eval_config;

static DCERPC_TransType DCERPC_AutoDetect(SFSnortPacket *, const uint8_t *, uint16_t);
static void DCERPC_DataFree(DCERPC *);
static int ProcessRawDCERPC(SFSnortPacket *, const uint8_t *, uint16_t);
static int ProcessRawSMB(SFSnortPacket *, const uint8_t *, uint16_t);
static DCERPC_TransType DCERPC_GetTransport(SFSnortPacket *, char *);

void DCERPC_BufferReassemble(DCERPC_Buffer *sbuf)
{
    uint16_t len;
    int status;

    if (DCERPC_BufferIsEmpty(sbuf))
        return;

    len = sbuf->len;

    /* Copy data into buffer */
    if (len > dce_reassembly_buf_size)
        len = dce_reassembly_buf_size;

    status = SafeMemcpy(dce_reassembly_buf, sbuf->data, len,
                        dce_reassembly_buf, dce_reassembly_buf + dce_reassembly_buf_size);

    if (status != SAFEMEM_SUCCESS)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Failed to copy DCERPC data, "
                                "skipping DCERPC reassembly.\n"););
        return;
    }

    if (dcerpc_eval_config->debug_print)
    {
        PrintBuffer("DCE/RPC reassembled fragment",
                    (uint8_t *)dce_reassembly_buf, (uint16_t)len);
    }

    /* create pseudo packet */
    real_dce_mock_pkt = DCERPC_SetPseudoPacket(_dcerpc_pkt, dce_reassembly_buf, len);
}

void DCERPC_EarlyFragReassemble(DCERPC *dce_ssn_data, const uint8_t *smb_hdr,
                                uint16_t smb_hdr_len, uint16_t opnum)
{
    dce_ssn_data->num_inc_reass++;
    if (dcerpc_eval_config->reassemble_increment == dce_ssn_data->num_inc_reass)
    {
        dce_ssn_data->num_inc_reass = 0;

        if (!DCERPC_BufferIsEmpty(&dce_ssn_data->dce_frag_buf))
        {
            DCERPC_REQ fake_req;

            memset(&fake_req, 0, sizeof(DCERPC_REQ));

            fake_req.dcerpc_hdr.version = 5;
            fake_req.dcerpc_hdr.flags = 0x03;
            fake_req.dcerpc_hdr.byte_order = 0x10;
            fake_req.opnum = opnum;

            /* Create a reassembly packet but don't free buffers */
            ReassembleDCERPCRequest(smb_hdr, smb_hdr_len, (uint8_t *)&fake_req);
        }
    }
}

void * DCERPC_GetReassemblyPkt(void)
{
    if (real_dce_mock_pkt != NULL)
        return (void *)real_dce_mock_pkt;

    return NULL;
}
 
SFSnortPacket * DCERPC_SetPseudoPacket(SFSnortPacket *p, const uint8_t *data, uint16_t data_len)
{
    SFSnortPacket *ret_pkt = dce_mock_pkt;
    uint16_t payload_len = dce_mock_pkt_payload_len;
    uint16_t ip_len;
    int result;
    int vlanHeaderLen = 0;

#ifdef SUP_IP6
    if (p->family == AF_INET)
    {
        IP_COPY_VALUE(ret_pkt->inner_ip4h.ip_src, (&p->ip4h->ip_src));
        IP_COPY_VALUE(ret_pkt->inner_ip4h.ip_dst, (&p->ip4h->ip_dst));

        //((IPV4Header *)ret_pkt->ip4h)->source.s_addr = p->ip4h->ip_src.ip32[0];
        //((IPV4Header *)ret_pkt->ip4h)->destination.s_addr = p->ip4h->ip_dst.ip32[0];
    }
    else
    {
        ret_pkt = dce_mock_pkt_6;

        IP_COPY_VALUE(ret_pkt->inner_ip6h.ip_src, (&p->ip6h->ip_src));
        IP_COPY_VALUE(ret_pkt->inner_ip6h.ip_dst, (&p->ip6h->ip_dst));

        payload_len = dce_mock_pkt_6_payload_len;
    }

    ret_pkt->family = p->family;

#else
    ((IPV4Header *)ret_pkt->ip4_header)->source.s_addr = p->ip4_header->source.s_addr;
    ((IPV4Header *)ret_pkt->ip4_header)->destination.s_addr = p->ip4_header->destination.s_addr;
#endif

    ((TCPHeader *)ret_pkt->tcp_header)->source_port = p->tcp_header->source_port;
    ((TCPHeader *)ret_pkt->tcp_header)->destination_port = p->tcp_header->destination_port;
    ret_pkt->src_port = p->src_port;
    ret_pkt->dst_port = p->dst_port;
    ret_pkt->proto_bits = p->proto_bits;

    if (p->ether_header != NULL)
    {
        result = SafeMemcpy((void *)((EtherHeader *)ret_pkt->ether_header)->ether_source,
                            (void *)p->ether_header->ether_source,
                            (size_t)6,
                            (void *)ret_pkt->ether_header->ether_source,
                            (void *)((uint8_t *)ret_pkt->ether_header->ether_source + 6));

        if (result != SAFEMEM_SUCCESS)
            return NULL;

        result = SafeMemcpy((void *)((EtherHeader *)ret_pkt->ether_header)->ether_destination,
                            (void *)p->ether_header->ether_destination,
                            (size_t)6,
                            (void *)ret_pkt->ether_header->ether_destination,
                            (void *)((uint8_t *)ret_pkt->ether_header->ether_destination + 6));

        if (result != SAFEMEM_SUCCESS)
            return NULL;

        ((EtherHeader *)ret_pkt->ether_header)->ethernet_type = ((EtherHeader *)p->ether_header)->ethernet_type;

        if (((EtherHeader *)p->ether_header)->ethernet_type == htons(ETHERNET_TYPE_8021Q))
        {
            result = SafeMemcpy((void *)ret_pkt->vlan_tag_header,
                    (void *)p->vlan_tag_header,
                    (size_t)VLAN_HDR_LEN,
                    (void *)ret_pkt->vlan_tag_header,
                    (void *)((uint8_t *)ret_pkt->vlan_tag_header + VLAN_HDR_LEN));

            if (result != SAFEMEM_SUCCESS)
                return NULL;

            vlanHeaderLen = VLAN_HDR_LEN;
        }
    }

    if (data_len > payload_len)
        data_len = payload_len;

    result = SafeMemcpy((void *)ret_pkt->payload, (void *)data, (size_t)data_len,
                        (void *)ret_pkt->payload,
                        (void *)((uint8_t *)ret_pkt->payload + payload_len));

    if (result != SAFEMEM_SUCCESS)
        return NULL;

    ret_pkt->payload_size = data_len;

    ((struct pcap_pkthdr *)ret_pkt->pcap_header)->caplen =
        ret_pkt->payload_size + IP_HDR_LEN + TCP_HDR_LEN + ETHER_HDR_LEN + vlanHeaderLen;
    ((struct pcap_pkthdr *)ret_pkt->pcap_header)->len = ret_pkt->pcap_header->caplen;
    ((struct pcap_pkthdr *)ret_pkt->pcap_header)->ts.tv_sec = p->pcap_header->ts.tv_sec;
    ((struct pcap_pkthdr *)ret_pkt->pcap_header)->ts.tv_usec = p->pcap_header->ts.tv_usec;

    ip_len = (uint16_t)(ret_pkt->payload_size + IP_HDR_LEN + TCP_HDR_LEN);
#ifdef SUP_IP6
    if (p->family == AF_INET)
    {
        ret_pkt->ip4h->ip_len = ((IPV4Header *)ret_pkt->ip4_header)->data_length = htons(ip_len);
    }
    else
    {
        ip_len = (uint16_t)(ret_pkt->payload_size + IP6_HDR_LEN + TCP_HDR_LEN);
        ret_pkt->ip6h->len = htons(ip_len);
    }
#else
    ((IPV4Header *)ret_pkt->ip4_header)->data_length = htons(ip_len);
#endif

    ret_pkt->flags = FLAG_STREAM_EST;
    ret_pkt->flags |= FLAG_FROM_CLIENT;
    ret_pkt->flags |= FLAG_DCE_RPKT;
    ret_pkt->stream_session_ptr = p->stream_session_ptr;

    /* Set bit in wire packet to indicate a reassembled packet needs to
     * be detected upon */
    _dpd.setPreprocReassemblyPktBit(_dcerpc_pkt, PP_DCERPC);

    return ret_pkt;
}

void DCERPC_InitPacket(void)
{
    /* Alloc for global reassembly buffers */
    dce_reassembly_buf = (uint8_t *)calloc(1, dce_reassembly_buf_size);
    if (dce_reassembly_buf == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate memory for "
                                        "reassembly packet\n");
    }

    /* Alloc for mock packets */
    dce_mock_pkt = (SFSnortPacket *)calloc(1, sizeof(SFSnortPacket));
    if (dce_mock_pkt == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate memory for "
                                        "mock packet\n");
    }

    dce_mock_pkt->pcap_header = calloc(1, sizeof(struct pcap_pkthdr) +
                                             ETHER_HDR_LEN +
                                             SUN_SPARC_TWIDDLE + IP_MAXPKT + VLAN_HDR_LEN);
    if (dce_mock_pkt->pcap_header == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate memory "
                                        "for mock pcap header\n");
    }

    dce_mock_pkt->pkt_data =
        ((uint8_t *)dce_mock_pkt->pcap_header) + sizeof(struct pcap_pkthdr);
    dce_mock_pkt->vlan_tag_header = 
        (void *)((uint8_t *)dce_mock_pkt->pkt_data + SUN_SPARC_TWIDDLE);
    dce_mock_pkt->ether_header = 
        (void *)((uint8_t *)dce_mock_pkt->vlan_tag_header + VLAN_HDR_LEN);
    dce_mock_pkt->ip4_header =
        (IPV4Header *)((uint8_t *)dce_mock_pkt->ether_header + ETHER_HDR_LEN);
    dce_mock_pkt->tcp_header =
        (TCPHeader *)((uint8_t *)dce_mock_pkt->ip4_header + IP_HDR_LEN);

    dce_mock_pkt->payload = (uint8_t *)dce_mock_pkt->tcp_header + TCP_HDR_LEN;

    ((EtherHeader *)dce_mock_pkt->ether_header)->ethernet_type = htons(0x0800);
    SET_IP4_VER((IPV4Header *)dce_mock_pkt->ip4_header, 0x4);
    SET_IP4_HLEN((IPV4Header *)dce_mock_pkt->ip4_header, 0x5);
    ((IPV4Header *)dce_mock_pkt->ip4_header)->proto = IPPROTO_TCP;
    ((IPV4Header *)dce_mock_pkt->ip4_header)->time_to_live = 0xF0;
    ((IPV4Header *)dce_mock_pkt->ip4_header)->type_service = 0x10;

    SET_TCP_HDR_OFFSET((TCPHeader *)dce_mock_pkt->tcp_header, 0x5);
    ((TCPHeader *)dce_mock_pkt->tcp_header)->flags = TCPHEADER_PUSH | TCPHEADER_ACK;

#ifdef SUP_IP6    
    _dpd.ip6Build((void *)dce_mock_pkt, dce_mock_pkt->ip4_header, AF_INET);

    /* Same thing as above, but for the IPv6-enabled packet */
    dce_mock_pkt_6 = (SFSnortPacket *)calloc(1, sizeof(SFSnortPacket));
    if (dce_mock_pkt_6 == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate memory for "
                                        "mock IPv6 packet\n");
    }

    dce_mock_pkt_6->pcap_header = calloc(1, sizeof(struct pcap_pkthdr) +
                                               ETHER_HDR_LEN +
                                               SUN_SPARC_TWIDDLE + IP_MAXPKT + VLAN_HDR_LEN);
    if (dce_mock_pkt_6 == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate memory for "
                                        "mock IPv6 pcap header\n");
    }

    dce_mock_pkt_6->pkt_data =
        ((uint8_t *)dce_mock_pkt_6->pcap_header) + sizeof(struct pcap_pkthdr);

    dce_mock_pkt_6->vlan_tag_header = 
        (void *)((uint8_t *)dce_mock_pkt_6->pkt_data + SUN_SPARC_TWIDDLE);
    dce_mock_pkt_6->ether_header = 
        (void *)((uint8_t *)dce_mock_pkt_6->vlan_tag_header + VLAN_HDR_LEN);
    dce_mock_pkt_6->ip4_header =
        (IPV4Header *)((uint8_t *)dce_mock_pkt_6->ether_header + ETHER_HDR_LEN);
    dce_mock_pkt_6->tcp_header =
        (TCPHeader *)((uint8_t *)dce_mock_pkt_6->ip4_header + IP6_HEADER_LEN);

    dce_mock_pkt_6->payload = (uint8_t *)dce_mock_pkt_6->tcp_header + TCP_HDR_LEN;

    ((EtherHeader *)dce_mock_pkt_6->ether_header)->ethernet_type = htons(0x0800);
    SET_IP4_VER((IPV4Header *)dce_mock_pkt_6->ip4_header, 0x4);
    SET_IP4_HLEN((IPV4Header *)dce_mock_pkt_6->ip4_header, 0x5);
    ((IPV4Header *)dce_mock_pkt_6->ip4_header)->type_service = 0x10;
    dce_mock_pkt_6->inner_ip6h.next = ((IPV4Header *)dce_mock_pkt_6->ip4_header)->proto = IPPROTO_TCP;
    dce_mock_pkt_6->inner_ip6h.hop_lmt = ((IPV4Header *)dce_mock_pkt_6->ip4_header)->time_to_live = 0xF0;
    dce_mock_pkt_6->inner_ip6h.len = IP6_HEADER_LEN >> 2;
 
    _dpd.ip6SetCallbacks((void *)dce_mock_pkt_6, AF_INET6, SET_CALLBACK_IP);
    dce_mock_pkt_6->ip6h = &dce_mock_pkt_6->inner_ip6h;
    dce_mock_pkt_6->ip4h = &dce_mock_pkt_6->inner_ip4h;

    SET_TCP_HDR_OFFSET((TCPHeader *)dce_mock_pkt_6->tcp_header, 0x5);
    ((TCPHeader *)dce_mock_pkt_6->tcp_header)->flags = TCPHEADER_PUSH | TCPHEADER_ACK;
#endif
}


static int ProcessRawSMB(SFSnortPacket *p, const uint8_t *data, uint16_t size)
{
    /* Must remember to convert stuff to host order before using it... */
    SMB_HDR *smbHdr;
    uint16_t nbt_data_size;
    uint8_t *smb_command;
    uint16_t smb_data_size;

    while (size > 0)
    {
        NBT_HDR *nbt_hdr;

        /* Check for size enough for NBT_HDR and SMB_HDR */
        if ( size <= (sizeof(NBT_HDR) + sizeof(SMB_HDR)) )
        {
            /* Not enough data */
            return 0;
        }

        nbt_hdr = (NBT_HDR *)data;
        nbt_data_size = ntohs(nbt_hdr->length);
        if (nbt_data_size > (size - sizeof(NBT_HDR)))
            nbt_data_size = size - sizeof(NBT_HDR);

        smbHdr = (SMB_HDR *)(data + sizeof(NBT_HDR));
        smb_command = (uint8_t *)smbHdr + sizeof(SMB_HDR);
        smb_data_size = nbt_data_size - sizeof(SMB_HDR);

        if (memcmp(smbHdr->protocol, "\xffSMB", 4) != 0)
        {
            /* Not an SMB request, nothing really to do here... */
            return 0;
        }

        ProcessNextSMBCommand(smbHdr->command, smbHdr, smb_command, smb_data_size, nbt_data_size);

        size -= (sizeof(NBT_HDR) + nbt_data_size);
        data += (sizeof(NBT_HDR) + nbt_data_size);
    }

    return 1;
}

static int ProcessRawDCERPC(SFSnortPacket *p, const uint8_t *data, uint16_t size)
{
    DCERPC_Buffer *sbuf = &_dcerpc->tcp_seg_buf;
    int status = ProcessDCERPCMessage(NULL, 0, data, size);

    if (status == -1)
        return -1;

    if ((status == DCERPC_FULL_FRAGMENT) && !DCERPC_BufferIsEmpty(sbuf))
    {
        DCERPC_BufferReassemble(sbuf);
        DCERPC_BufferEmpty(sbuf);
    }
    else if ((status == DCERPC_SEGMENTED) && dcerpc_eval_config->reassemble_increment)
    {
        _dcerpc->num_inc_reass++;
        if (dcerpc_eval_config->reassemble_increment == _dcerpc->num_inc_reass)
        {
            _dcerpc->num_inc_reass = 0;
            DCERPC_BufferReassemble(sbuf);
        }
    }

    return 1;
}

/*
 * Free SMB-specific related to this session
 *
 * @param   v   pointer to SMB session structure
 *
 * @return  none
 */
void DCERPC_SessionFree(void * v)
{
    DCERPC *x = (DCERPC *) v;
    DceRpcConfig *pPolicyConfig = NULL;

    if (x == NULL)
        return;

    pPolicyConfig = (DceRpcConfig *)sfPolicyUserDataGet(x->config, x->policy_id);

    if (pPolicyConfig != NULL)
    {
        pPolicyConfig->ref_count--;
        if ((pPolicyConfig->ref_count == 0) &&
            (x->config != dcerpc_config))
        {
            sfPolicyUserDataClear (x->config, x->policy_id);
            free(pPolicyConfig);

            /* No more outstanding configs - free the config array */
            if (sfPolicyUserPolicyGetActive(x->config) == 0)
                DceRpcFreeConfig(x->config);
        }
    }

    DCERPC_DataFree(x);
    free(x);
}

static void DCERPC_DataFree(DCERPC *dssn)
{
    DCERPC_BufferFreeData(&dssn->smb_seg_buf);
    DCERPC_BufferFreeData(&dssn->tcp_seg_buf);
    DCERPC_BufferFreeData(&dssn->dce_frag_buf);
}

static DCERPC_TransType DCERPC_AutoDetect(SFSnortPacket *p, const uint8_t *data, uint16_t size)
{
    NBT_HDR *nbtHdr;
    SMB_HDR *smbHdr;
    DCERPC_HDR *dcerpc;

    if ( !dcerpc_eval_config->autodetect )
    {
        return DCERPC_TRANS_TYPE__NONE;
    }

    if ( size > (sizeof(NBT_HDR) + sizeof(SMB_HDR)) )
    {
        /* See if this looks like SMB */
        smbHdr = (SMB_HDR *) (data + sizeof(NBT_HDR));

        if (memcmp(smbHdr->protocol, "\xffSMB", 4) == 0)
        {
            /* Do an extra check on NetBIOS header, which should be valid for both
               NetBIOS and raw SMB */
            nbtHdr = (NBT_HDR *)data;

            if (nbtHdr->type == SMB_SESSION )
            {
                return DCERPC_TRANS_TYPE__SMB;
            }
        }
    }

    /* Might be DCE/RPC */
    /*  Make sure it's a reasonable size */
    if (size > sizeof(DCERPC_REQ))
    {
        dcerpc = (DCERPC_HDR *) data;

        /*  Minimal DCE/RPC check - check for version and request */
        if ((dcerpc->version == 5) &&
            ((dcerpc->packet_type == DCERPC_REQUEST) || (dcerpc->packet_type == DCERPC_BIND)))
        {
            return DCERPC_TRANS_TYPE__DCERPC;
        }
    }

    return DCERPC_TRANS_TYPE__NONE;
}

/* For Target based *************************************************************
 *
 * (1) If a protocol for the session is already identified and not ones DCE/RPC is
 * interested in, DCE/RPC should leave it alone and return without processing.
 * (2) If a protocol for the session is already identified and is one that DCE/RPC is
 * interested in, decode it.
 * (3) If the protocol for the session is not already identified and the preprocessor
 * is configured to detect on one of the packet ports or can autodetect it,
 * decode the packet.
 *
 * Returns a transport type - none type if app id already set to something other
 * than DCE/RPC or SMB or if not configured or autodetect fails.
 */
static DCERPC_TransType DCERPC_GetTransport(SFSnortPacket *p, char *autodetected)
{
#ifdef TARGET_BASED
    int16_t app_id = _dpd.streamAPI->get_application_protocol_id(p->stream_session_ptr);

    *autodetected = 0;

    if (app_id != 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "DCE/RPC: Target-based: App id: %u.\n", app_id););

        if (app_id == _dce_proto_ids.dcerpc)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "DCE/RPC: Target-based: App id is "
                                    "set to \"%s\".\n", DCE_PROTO_REF_STR__DCERPC););

            return DCERPC_TRANS_TYPE__DCERPC;
        }
        else if (app_id == _dce_proto_ids.nbss)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "DCE/RPC: Target-based: App id is "
                                    "set to \"%s or %s\".\n",
                                    DCE_PROTO_REF_STR__SMB, DCE_PROTO_REF_STR__NBSS););

            return DCERPC_TRANS_TYPE__SMB;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "DCE/RPC: Target-based: App id is "
                                    "set to something not DCE/RPC or SMB.\n"););

            return DCERPC_TRANS_TYPE__NONE;
        }
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "DCE/RPC: Target-based: Unknown protocol for "
                                "this session.  See if we're configured or can autodetect.\n"););

        if (((p->flags & FLAG_FROM_CLIENT) &&
             (dcerpc_eval_config->SMBPorts[PORT_INDEX(p->dst_port)] & CONV_PORT(p->dst_port))) ||
            ((p->flags & FLAG_FROM_SERVER) &&
             (dcerpc_eval_config->SMBPorts[PORT_INDEX(p->src_port)] & CONV_PORT(p->src_port))))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "DCE/RPC: Target-based: SMB port is configured. "
                                    "Set protocol to NBSS/SMB for session.\n"););

            return DCERPC_TRANS_TYPE__SMB;
        }
        else if (((p->flags & FLAG_FROM_CLIENT) &&
                  (dcerpc_eval_config->DCERPCPorts[PORT_INDEX(p->dst_port)] & CONV_PORT(p->dst_port))) ||
                 ((p->flags & FLAG_FROM_SERVER) &&
                  (dcerpc_eval_config->DCERPCPorts[PORT_INDEX(p->src_port)] & CONV_PORT(p->src_port))))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "DCE/RPC: Target-based: DCE/RPC port is configured. "
                                    "Set protocol to DCE/RPC for session.\n"););

            return DCERPC_TRANS_TYPE__DCERPC;
        }
        else if (dcerpc_eval_config->autodetect)
        {
            DCERPC_TransType trans = DCERPC_AutoDetect(p, p->payload, p->payload_size);

            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "DCE/RPC: Target-based: Autodetecting ... \n"););

            switch (trans)
            {
                case DCERPC_TRANS_TYPE__DCERPC:
                    DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,
                                            "DCE/RPC: Target-based: Autodetected DCE/RPC. Set "
                                            "protocol to DCE/RPC for session.\n"););

                    break;

                case DCERPC_TRANS_TYPE__SMB:
                    DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,
                                            "DCE/RPC: Target-based: Autodetected SMB. Set "
                                            "protocol to SMB for session.\n"););

                    break;

                case DCERPC_TRANS_TYPE__NONE:
                default:
                    DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,
                                            "DCE/RPC: Target-based: Unable to autodetect.\n"););

                    return DCERPC_TRANS_TYPE__NONE;
            }

            *autodetected = 1;

            return trans;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "DCE/RPC: Target-based: No configured ports "
                                    "and autodetect not enabled.  Return unhappy and weepy.\n"););
        }
    }
#else
    *autodetected = 0;

    /* check the port list */
    if (((p->flags & FLAG_FROM_CLIENT) &&
         (dcerpc_eval_config->SMBPorts[PORT_INDEX(p->dst_port)] & CONV_PORT(p->dst_port))) ||
        ((p->flags & FLAG_FROM_SERVER) &&
         (dcerpc_eval_config->SMBPorts[PORT_INDEX(p->src_port)] & CONV_PORT(p->src_port))))
    {
        return DCERPC_TRANS_TYPE__SMB;
    }
    else if (((p->flags & FLAG_FROM_CLIENT) &&
              (dcerpc_eval_config->DCERPCPorts[PORT_INDEX(p->dst_port)] & CONV_PORT(p->dst_port))) ||
             ((p->flags & FLAG_FROM_SERVER) &&
              (dcerpc_eval_config->DCERPCPorts[PORT_INDEX(p->src_port)] & CONV_PORT(p->src_port))))
    {
        return DCERPC_TRANS_TYPE__DCERPC;
    }
    else if (dcerpc_eval_config->autodetect)
    {
        DCERPC_TransType trans = DCERPC_AutoDetect(p, p->payload, p->payload_size);
        *autodetected = 1;

        return trans;
    }
#endif  /* TARGET_BASED */

    return DCERPC_TRANS_TYPE__NONE;
}

int DCERPCDecode(void *pkt)
{
    SFSnortPacket *p = (SFSnortPacket *) pkt;
    DCERPC *x = NULL;
    DCERPC_TransType trans = DCERPC_TRANS_TYPE__NONE;
    tSfPolicyId policy_id = _dpd.getRuntimePolicy();
    DceRpcConfig *pPolicyConfig = NULL;

    real_dce_mock_pkt = NULL;

    sfPolicyUserPolicySet (dcerpc_config, policy_id);
    pPolicyConfig = (DceRpcConfig *)sfPolicyUserDataGetCurrent(dcerpc_config);
    dcerpc_eval_config = pPolicyConfig;

    x = (DCERPC *)_dpd.streamAPI->get_application_data(p->stream_session_ptr, PP_DCERPC);
    if (x != NULL)
        dcerpc_eval_config = (DceRpcConfig *)sfPolicyUserDataGet(x->config, x->policy_id);

    if (dcerpc_eval_config == NULL)
        return 0;

    if (x == NULL)
    {
        char autodetected = 0;

        trans = DCERPC_GetTransport(p, &autodetected);
        if (trans == DCERPC_TRANS_TYPE__NONE)
            return 0;

        x = (DCERPC *)calloc(1, sizeof(DCERPC));
        if ( x == NULL )
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate for SMB session data\n", 
                                            _dpd.config_file, _dpd.config_line);
        }
        else
        {
            x->policy_id = policy_id;
            x->config = dcerpc_config;
            pPolicyConfig->ref_count++;

            _dpd.streamAPI->set_application_data(p->stream_session_ptr, PP_DCERPC,
                                                 (void *)x, &DCERPC_SessionFree);        
        }

        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Created new session\n"););

        x->trans = trans;
        if (autodetected)
            x->autodetected = 1;

        if (_dpd.streamAPI->get_reassembly_direction(p->stream_session_ptr) != SSN_DIR_SERVER)
        {
            _dpd.streamAPI->set_reassembly(p->stream_session_ptr, STREAM_FLPOLICY_FOOTPRINT,
                                           SSN_DIR_SERVER, STREAM_FLPOLICY_SET_ABSOLUTE);
        }

        if (p->flags & FLAG_FROM_SERVER)
        {
            _dpd.streamAPI->response_flush_stream(p);
            return 0;
        }

        if (p->flags & FLAG_STREAM_INSERT)
            return 0;
    }
    else if (x->no_inspect)
    {
        return 0;
    }
    else if (p->flags & FLAG_FROM_SERVER)
    {
        _dpd.streamAPI->response_flush_stream(p);
        return 0;
    }
    else if ((p->flags & FLAG_FROM_CLIENT) && !(p->flags & FLAG_REBUILT_STREAM))
    {
        /* Should be doing reassembly at this point */
        return 0;
    }

    _dcerpc = x;
    _dcerpc_pkt = p;

    switch (_dcerpc->trans)
    {
        case DCERPC_TRANS_TYPE__SMB:
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Decoding SMB packet\n"););
            ProcessRawSMB(p, p->payload, p->payload_size);
            break;
        case DCERPC_TRANS_TYPE__DCERPC:
            DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Decoding DCE/RPC packet\n"););
            ProcessRawDCERPC(p, p->payload, p->payload_size);
            break;
        default:
            /* Shouldn't get here.  Just adding action for default case */
            return 0;
    }

    if (_dcerpc->fragmentation & SUSPEND_FRAGMENTATION)
    {
        DCERPC_DataFree(_dcerpc);
        _dcerpc->no_inspect = 1;
    }

    /* If it's an autodetected session, still let other preprocessors
     * look at it */
    if (_dcerpc->autodetected)
        return 0;

    return 1;
}

void DCERPC_Exit(void)
{
    if (dce_reassembly_buf != NULL)
        free((void *)dce_reassembly_buf);

    if (dce_mock_pkt != NULL)
    {
        if (dce_mock_pkt->pcap_header != NULL)
            free((void *)dce_mock_pkt->pcap_header);

        free((void *)dce_mock_pkt);
    }
#ifdef SUP_IP6
    if (dce_mock_pkt_6 != NULL)
    {
        if (dce_mock_pkt_6->pcap_header != NULL)
            free((void *)dce_mock_pkt_6->pcap_header);

        free((void *)dce_mock_pkt_6);
    }
#endif

#ifdef PERF_PROFILING
#ifdef DEBUG_DCERPC_PRINT
    printf("SMB Debug\n");
    printf("  Number of packets seen:      %u\n", dcerpcPerfStats.checks);
    printf("  Number of packets ignored: %d\n", dcerpcIgnorePerfStats.checks);
#endif
#endif
}


int ProcessNextSMBCommand(uint8_t command, SMB_HDR *smbHdr,
                          uint8_t *data, uint16_t size, uint16_t total_size)
{
    switch (command)
    {
        case SMB_COM_TREE_CONNECT_ANDX:
            return ProcessSMBTreeConnXReq(smbHdr, data, size, total_size);
        case SMB_COM_NT_CREATE_ANDX:
            return ProcessSMBNTCreateX(smbHdr, data, size, total_size);
        case SMB_COM_WRITE_ANDX: 
            return ProcessSMBWriteX(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION:
            return ProcessSMBTransaction(smbHdr, data, size, total_size);
        case SMB_COM_READ_ANDX:
            return ProcessSMBReadX(smbHdr, data, size, total_size);

#ifdef UNUSED_SMB_COMMAND

        case SMB_COM_SESSION_SETUP_ANDX:
            return ProcessSMBSetupXReq(smbHdr, data, size, total_size);
        case SMB_COM_LOGOFF_ANDX:
            return ProcessSMBLogoffXReq(smbHdr, data, size, total_size);
        case SMB_COM_READ_ANDX:
            return ProcessSMBReadX(smbHdr, data, size, total_size);
        case SMB_COM_LOCKING_ANDX:
            return ProcessSMBLockingX(smbHdr, data, size, total_size);

        case SMB_COM_NEGOTIATE:
            return ProcessSMBNegProtReq(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION2:
            return ProcessSMBTransaction2(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION2_SECONDARY:
            return ProcessSMBTransaction2Secondary(smbHdr, data, size, total_size);
        case SMB_COM_NT_TRANSACT:
            return ProcessSMBNTTransact(smbHdr, data, size, total_size);
        case SMB_COM_NT_TRANSACT_SECONDARY:
            return ProcessSMBNTTransactSecondary(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION_SECONDARY:
            break;
        
        case SMB_COM_ECHO:
            return ProcessSMBEcho(smbHdr, data, size, total_size);
        case SMB_COM_SEEK:
            return ProcessSMBSeek(smbHdr, data, size, total_size);
        case SMB_COM_FLUSH:
            return ProcessSMBFlush(smbHdr, data, size, total_size);
        case SMB_COM_CLOSE:
        case SMB_COM_CLOSE_AND_TREE_DISC:
            return ProcessSMBClose(smbHdr, data, size, total_size);
        case SMB_COM_TREE_DISCONNECT:
        case SMB_COM_NT_CANCEL:
            return ProcessSMBNoParams(smbHdr, data, size, total_size);
#endif
        default:
#ifdef DEBUG_DCERPC_PRINT
            printf("====> Unprocessed command 0x%02x <==== \n", command);
#endif
            break;
    }

    return 0;
}

int DCERPC_BufferAddData(DCERPC *dce_ssn, DCERPC_Buffer *sbuf, const uint8_t *data, uint16_t data_size)
{
    int status;

    if ((sbuf == NULL) || (data == NULL))
        return -1;

    if (data_size == 0)
        return 0;

    if ((sbuf == &dce_ssn->smb_seg_buf) && dcerpc_eval_config->disable_smb_fragmentation)
        return 0;
    else if (dcerpc_eval_config->disable_dcerpc_fragmentation)
        return 0;

    if (sbuf->data == NULL)
    {
        uint16_t alloc_size = data_size;

        if (dce_ssn->fragmentation & SUSPEND_FRAGMENTATION)
            return -1;

        /* Add a minimum size so we don't have to realloc as often */
        if (alloc_size < DCERPC_MIN_SEG_ALLOC_SIZE)
            alloc_size = DCERPC_MIN_SEG_ALLOC_SIZE;

        if (DCERPC_IsMemcapExceeded(alloc_size))
            return -1;

        sbuf->data = (uint8_t *)calloc(alloc_size, 1);
        if (sbuf->data == NULL)
            DynamicPreprocessorFatalMessage("Failed to allocate space for TCP seg buf\n");

        _total_memory += alloc_size;
        sbuf->size = alloc_size;
    }
    else
    {
        uint16_t buf_size_left = sbuf->size - sbuf->len;

        if (data_size > buf_size_left)
        {
            uint16_t alloc_size = data_size - buf_size_left;
            uint8_t *tmp_data;

            if (dce_ssn->fragmentation & SUSPEND_FRAGMENTATION)
                return -1;

            if (alloc_size < DCERPC_MIN_SEG_ALLOC_SIZE)
                alloc_size = DCERPC_MIN_SEG_ALLOC_SIZE;

            if ((USHRT_MAX - sbuf->size) < alloc_size)
                alloc_size = USHRT_MAX - sbuf->size;

            if (alloc_size == 0)
                return -1;

            if (DCERPC_IsMemcapExceeded(alloc_size))
                return -1;

            tmp_data = (uint8_t *)realloc(sbuf->data, sbuf->size + alloc_size);
            if (tmp_data == NULL)
                DynamicPreprocessorFatalMessage("Failed to allocate space for TCP seg buf\n");

            sbuf->data = tmp_data;

            _total_memory += alloc_size;
            sbuf->size += alloc_size;

            /* This would be because of potential overflow */
            if (sbuf->len + data_size > sbuf->size)
                data_size = sbuf->size - sbuf->len;
        }
    }

    status = SafeMemcpy(sbuf->data + sbuf->len, data, data_size,
                        sbuf->data + sbuf->len, sbuf->data + sbuf->size);

    if (status != SAFEMEM_SUCCESS)
        return -1;

    sbuf->len += data_size;

    return 0;
}

void DCERPC_BufferFreeData(DCERPC_Buffer *sbuf)
{
    if (sbuf == NULL)
        return;

    if (sbuf->data != NULL)
    {
        if (_total_memory > sbuf->size)
            _total_memory -= sbuf->size;
        else
            _total_memory = 0;

        free(sbuf->data);

        sbuf->data = NULL;
        sbuf->len = 0;
        sbuf->size = 0;
    }
}

int DCERPC_IsMemcapExceeded(uint16_t alloc_size)
{
    if ((alloc_size + _total_memory) > ((DceRpcConfig *)sfPolicyUserDataGetDefault(dcerpc_config))->memcap)
    {
        if (dcerpc_eval_config->alert_memcap)
        {
            DCERPC_GenerateAlert(DCERPC_EVENT_MEMORY_OVERFLOW, 
                                 DCERPC_EVENT_MEMORY_OVERFLOW_STR);
        }

        return 1;
    }

    return 0;
}

static int DceFreeConfigPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId, 
        void* pData
        )
{
    DceRpcConfig *pPolicyConfig = (DceRpcConfig *)pData;

    //do any housekeeping before freeing DceRpcConfig

    sfPolicyUserDataClear (config, policyId);
    free(pPolicyConfig);
    return 0;
}

void DceRpcFreeConfig(tSfPolicyUserContextId config)
{
    if (config == NULL)
        return;

    sfPolicyUserDataIterate (config, DceFreeConfigPolicy);
    sfPolicyConfigDelete(config);
}

