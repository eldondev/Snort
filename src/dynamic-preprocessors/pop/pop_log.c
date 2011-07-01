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

/**************************************************************************
 *
 * pop_log.c
 *
 * Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>
 *
 * Description:
 *
 * This file handles POP alerts.
 *
 * Entry point functions:
 *
 *    POP_GenerateAlert()
 *
 *
 **************************************************************************/

#include <stdarg.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_debug.h"
#include "pop_config.h"
#include "pop_log.h"
#include "snort_pop.h"
#include "sf_dynamic_preprocessor.h"

extern POPConfig *pop_eval_config;
extern POP *pop_ssn;

char pop_event[POP_EVENT_MAX][EVENT_STR_LEN];


void POP_GenerateAlert(int event, char *format, ...)
{
    va_list ap;

    /* Only log a specific alert once per session */
    if (pop_ssn->alert_mask & (1 << event))
    {
#ifdef DEBUG_MSGS
        DEBUG_WRAP(DebugMessage(DEBUG_POP, "Already alerted on: %s - "
                                "ignoring event.\n", pop_event[event]););
#endif
        return;
    }

    /* set bit for this alert so we don't alert on again
     * in this session */
    pop_ssn->alert_mask |= (1 << event);

    va_start(ap, format);

    pop_event[event][0] = '\0';
    vsnprintf(&pop_event[event][0], EVENT_STR_LEN - 1, format, ap);
    pop_event[event][EVENT_STR_LEN - 1] = '\0';

    _dpd.alertAdd(GENERATOR_SPP_POP, event, 1, 0, 3, &pop_event[event][0], 0);

    DEBUG_WRAP(DebugMessage(DEBUG_POP, "POP Alert generated: %s\n", pop_event[event]););

    va_end(ap);
}

void POP_DecodeAlert(void)
{
    switch( pop_ssn->decode_state->decode_type )
    {
        case DECODE_B64:
            POP_GenerateAlert(POP_B64_DECODING_FAILED, "%s", POP_B64_DECODING_FAILED_STR);
            break;
        case DECODE_QP:
            POP_GenerateAlert(POP_QP_DECODING_FAILED, "%s", POP_QP_DECODING_FAILED_STR);
            break;
        case DECODE_UU:
            POP_GenerateAlert(POP_UU_DECODING_FAILED, "%s", POP_UU_DECODING_FAILED_STR);
            break;
        case DECODE_BITENC:
            POP_GenerateAlert(POP_BITENC_DECODING_FAILED, "%s", POP_BITENC_DECODING_FAILED_STR);
            break;

        default:
            break;
    }
}

