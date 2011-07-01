/*
 * smtp_util.c
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
 * Copyright (C) 2005-2011 Sourcefire, Inc.
 *
 * Author: Andy  Mullican
 *
 * Description:
 *
 * This file contains SMTP helper functions.
 *
 * Entry point functions:
 *
 *    safe_strchr()
 *    safe_strstr()
 *    copy_to_space()
 *    safe_sscanf()
 *
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include "snort_debug.h"
#include "snort_bounds.h"

#include "snort_smtp.h"
#include "smtp_util.h"
#include "sf_dynamic_preprocessor.h"
#include "sf_snort_packet.h"
#include "Unified2_common.h"

extern SMTP *smtp_ssn;
extern char smtp_normalizing;

void SMTP_GetEOL(const uint8_t *ptr, const uint8_t *end,
                 const uint8_t **eol, const uint8_t **eolm)
{
    const uint8_t *tmp_eol;
    const uint8_t *tmp_eolm;

    /* XXX maybe should fatal error here since none of these
     * pointers should be NULL */
    if (ptr == NULL || end == NULL || eol == NULL || eolm == NULL)
        return;

    tmp_eol = (uint8_t *)memchr(ptr, '\n', end - ptr);
    if (tmp_eol == NULL)
    {
        tmp_eol = end;
        tmp_eolm = end;
    }
    else
    {
        /* end of line marker (eolm) should point to marker and
         * end of line (eol) should point to end of marker */
        if ((tmp_eol > ptr) && (*(tmp_eol - 1) == '\r'))
        {
            tmp_eolm = tmp_eol - 1;
        }
        else
        {
            tmp_eolm = tmp_eol;
        }

        /* move past newline */
        tmp_eol++;
    }

    *eol = tmp_eol;
    *eolm = tmp_eolm;
}

int SMTP_CopyToAltBuffer(SFSnortPacket *p, const uint8_t *start, int length)
{
    uint8_t *alt_buf;
    int alt_size;
    uint16_t *alt_len;
    int ret;

    /* if we make a call to this it means we want to use the alt buffer
     * regardless of whether we copy any data into it or not - barring a failure */
    smtp_normalizing = 1;

    /* if start and end the same, nothing to copy */
    if (length == 0)
        return 0;

    alt_buf = _dpd.altBuffer->data;
    alt_size = sizeof(_dpd.altBuffer->data);
    alt_len = &_dpd.altBuffer->len;

    ret = SafeMemcpy(alt_buf + *alt_len, start, length, alt_buf, alt_buf + alt_size);

    if (ret != SAFEMEM_SUCCESS)
    {
        _dpd.DetectFlag_Disable(SF_FLAG_ALT_DECODE);
        smtp_normalizing = 0;
        return -1;
    }
    *alt_len += length;

    _dpd.SetAltDecode(*alt_len);

    return 0;
}
/* Accumulate EOL seperated headers, one or more at a time */
int SMTP_CopyEmailHdrs(const uint8_t *start, int length)
{
    int log_avail = 0;
    uint8_t *log_buf;
    uint32_t *hdrs_logged;
    int ret = 0;

    if ((smtp_ssn->log_state == NULL) || (length <= 0))
        return -1;

    
    log_avail = (smtp_ssn->log_state->log_depth - smtp_ssn->log_state->hdrs_logged);
    hdrs_logged = &(smtp_ssn->log_state->hdrs_logged);
    log_buf = (uint8_t *)smtp_ssn->log_state->emailHdrs;

    if(log_avail <= 0)
    {
        return -1;
    }

    if(length > log_avail )
    {
        length = log_avail;
    }

    /* appended by the EOL \r\n */

    ret = SafeMemcpy(log_buf + *hdrs_logged, start, length, log_buf, log_buf+(smtp_ssn->log_state->log_depth));

    if (ret != SAFEMEM_SUCCESS)
    {
        return -1;
    }

    *hdrs_logged += length;
    smtp_ssn->log_flags |= SMTP_FLAG_EMAIL_HDRS_PRESENT;

    return 0;
}

/* Accumulate email addresses from RCPT TO and/or MAIL FROM commands. Email addresses are separated by comma */
int SMTP_CopyEmailID(const uint8_t *start, int length, int command_type)
{
    uint8_t *alt_buf;
    int alt_size;
    uint16_t *alt_len;
    int ret;
    const uint8_t *tmp_eol;

    if (length <= 0)
        return -1;

    tmp_eol = (uint8_t *)memchr(start, ':', length);
    if(tmp_eol == NULL)
        return -1;

    if((tmp_eol+1) < (start+length))
    {
        length = length - ( (tmp_eol+1) - start );
        start = tmp_eol+1;
    }
    else
        return -1;


   
    switch (command_type)
    {
        case CMD_MAIL:
            alt_buf = smtp_ssn->senders.data;
            alt_size = sizeof(smtp_ssn->senders.data);
            alt_len = &(smtp_ssn->senders.len);
            break;

        case CMD_RCPT:
            alt_buf = smtp_ssn->recipients.data;
            alt_size = sizeof(smtp_ssn->recipients.data);
            alt_len = &(smtp_ssn->recipients.len);
            break;

        default:
            return -1;
    }

    if ( *alt_len > 0 && ((*alt_len + 1) < alt_size))
    {
        alt_buf[*alt_len] = ',';
        *alt_len = *alt_len + 1;
    }

    ret = SafeMemcpy(alt_buf + *alt_len, start, length, alt_buf, alt_buf + alt_size);

    if (ret != SAFEMEM_SUCCESS)
    {
        if(*alt_len != 0)
                *alt_len = *alt_len - 1;
        return -1;
    }

    *alt_len += length;

    return 0;
}


void SMTP_DecodeType(const char *start, int length)
{               
    const char *tmp = NULL;
    
    if(smtp_ssn->decode_state->b64_state.encode_depth > -1)
    {       
        tmp = _dpd.SnortStrcasestr(start, length, "base64");
        if( tmp != NULL )
        {   
            smtp_ssn->decode_state->decode_type = DECODE_B64;
            return;
        }
    }   
                    
    if(smtp_ssn->decode_state->qp_state.encode_depth > -1)
    {   
        tmp = _dpd.SnortStrcasestr(start, length, "quoted-printable");
        if( tmp != NULL )
        {   
            smtp_ssn->decode_state->decode_type = DECODE_QP;
            return;
        }
    }

    if(smtp_ssn->decode_state->uu_state.encode_depth > -1)
    {
        tmp = _dpd.SnortStrcasestr(start, length, "uuencode");
        if( tmp != NULL )
        {
            smtp_ssn->decode_state->decode_type = DECODE_UU;
            return;
        }
    }

    if(smtp_ssn->decode_state->bitenc_state.depth > -1)
    {
        smtp_ssn->decode_state->decode_type = DECODE_BITENC;
        return;
    }

    return;
}



/* Extract the filename from the header */
static inline int SMTP_ExtractFileName(const char **start, int length) 
{           
    const char *tmp = NULL;
    const char *end = *start+length;

    if(length<=0)
        return -1;
                        

    if (!(smtp_ssn->state_flags & SMTP_FLAG_IN_CONT_DISP_CONT))
    {
        tmp = _dpd.SnortStrcasestr(*start, length, "filename");
                        
        if( tmp == NULL )
            return -1;

        tmp = tmp + 8; 
        while( (tmp < end) && ((isspace(*tmp)) || (*tmp == '=') ))
        {
            tmp++;
        }
    }
    else
        tmp = *start;

    if(tmp < end)
    {
        if(*tmp == '"' || (smtp_ssn->state_flags & SMTP_FLAG_IN_CONT_DISP_CONT))
        {
            if(*tmp == '"')
            {
                if(smtp_ssn->state_flags & SMTP_FLAG_IN_CONT_DISP_CONT)
                {
                    smtp_ssn->state_flags &= ~SMTP_FLAG_IN_CONT_DISP_CONT;
                    return (tmp - *start);
                }
                    tmp++;

            }
            *start = tmp;
            tmp = _dpd.SnortStrnPbrk(*start ,(end - tmp),"\"");
            if(tmp == NULL )
            {
                if ((end - tmp) > 0 )
                {
                    tmp = end;
                    smtp_ssn->state_flags |= SMTP_FLAG_IN_CONT_DISP_CONT;
                }
                else
                    return -1;
            }
            else
                smtp_ssn->state_flags &= ~SMTP_FLAG_IN_CONT_DISP_CONT;
            end = tmp;
        }
        else
        {
            *start = tmp;
        }
        return (end - *start);
    }
    else
    {
        return -1;
    }
                                
    return 0;
}  


/* accumulate MIME attachment filenames. The filenames are appended by commas */
int SMTP_CopyFileName(const uint8_t *start, int length)
{
    uint8_t *alt_buf;
    int alt_size;
    uint16_t *alt_len;
    int ret=0;
    int cont =0;


    if(length == 0)
        return -1;

    if(smtp_ssn->state_flags & SMTP_FLAG_IN_CONT_DISP_CONT)
        cont = 1;

    ret = SMTP_ExtractFileName((const char **)(&start), length );

    if (ret == -1)
        return ret;

    length = ret;

    alt_buf = smtp_ssn->filenames.data;
    alt_size = sizeof(smtp_ssn->filenames.data);
    alt_len = &(smtp_ssn->filenames.len);

    if ( *alt_len > 0 && ((*alt_len + 1) < alt_size))
    {
        if(!cont)
        {
            alt_buf[*alt_len] = ',';
            *alt_len = *alt_len + 1;
        }
    }

    ret = SafeMemcpy(alt_buf + *alt_len, start, length, alt_buf, alt_buf + alt_size);

    if (ret != SAFEMEM_SUCCESS)
    {
        if(*alt_len != 0)
            *alt_len = *alt_len - 1;
        return -1;
    }

    *alt_len += length;
    smtp_ssn->log_flags |= SMTP_FLAG_FILENAME_PRESENT;

    return 0;
}

/* Callback to return the MIME attachment filenames accumulated */
static int SMTP_GetFilename(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    *buf = smtp_ssn->filenames.data;
    *len = smtp_ssn->filenames.len;
    *type = EVENT_INFO_SMTP_FILENAME;
    return 1;
}

/* Callback to return the email addresses accumulated from the MAIL FROM command */
static int SMTP_GetMailFrom(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{

    *buf = smtp_ssn->senders.data;
    *len = smtp_ssn->senders.len;
    *type = EVENT_INFO_SMTP_MAILFROM;
    return 1;
}

/* Callback to return the email addresses accumulated from the RCP TO command */
static int SMTP_GetRcptTo(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{

    *buf = smtp_ssn->recipients.data;
    *len = smtp_ssn->recipients.len;
    *type = EVENT_INFO_SMTP_RCPTTO;
    return 1;
}

/* Calback to return the email headers */
static int SMTP_GetEmailHdrs(void *data, uint8_t **buf, uint32_t *len, uint32_t *type)
{
    *buf = smtp_ssn->log_state->emailHdrs;
    *len = smtp_ssn->log_state->hdrs_logged;
    *type = EVENT_INFO_SMTP_EMAIL_HDRS;
    return 1;
}

void SMTP_LogFuncs(SFSnortPacket *p)
{
    if(smtp_ssn->log_flags == 0)
        return;

    if(smtp_ssn->log_flags & SMTP_FLAG_FILENAME_PRESENT)
    {
        SetLogFuncs(p, &SMTP_GetFilename);
    }

    if(smtp_ssn->log_flags & SMTP_FLAG_MAIL_FROM_PRESENT)
    {
        SetLogFuncs(p, &SMTP_GetMailFrom);
    }

    if(smtp_ssn->log_flags & SMTP_FLAG_RCPT_TO_PRESENT)
    {
        SetLogFuncs(p, &SMTP_GetRcptTo);
    }

    if(smtp_ssn->log_flags & SMTP_FLAG_EMAIL_HDRS_PRESENT)
    {
        SetLogFuncs(p, &SMTP_GetEmailHdrs);
    }

}

#ifdef DEBUG_MSGS
char smtp_print_buffer[65537];

const char * SMTP_PrintBuffer(SFSnortPacket *p)
{
    const uint8_t *ptr = NULL;
    int len = 0;
    int iorig, inew;

    if (smtp_normalizing)
    {
        ptr = _dpd.altBuffer->data;
        len = _dpd.altBuffer->len;
    }
    else
    {
        ptr = p->payload;
        len = p->payload_size;
    }

    for (iorig = 0, inew = 0; iorig < len; iorig++, inew++)
    {
        if ((isascii((int)ptr[iorig]) && isprint((int)ptr[iorig])) || (ptr[iorig] == '\n'))
        {
            smtp_print_buffer[inew] = ptr[iorig];
        }
        else if (ptr[iorig] == '\r' &&
                 ((iorig + 1) < len) && (ptr[iorig + 1] == '\n'))
        {
            iorig++;
            smtp_print_buffer[inew] = '\n';
        }
        else if (isspace((int)ptr[iorig]))
        {
            smtp_print_buffer[inew] = ' ';
        }
        else
        {
            smtp_print_buffer[inew] = '.';
        }
    }

    smtp_print_buffer[inew] = '\0';

    return &smtp_print_buffer[0];
}
#endif

