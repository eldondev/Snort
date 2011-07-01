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

/***************************************************************************
 * imap_config.c
 *
 * Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>
 *
 * Description:
 *
 * Handle configuration of the IMAP preprocessor
 *
 * Entry point functions:
 *
 *    IMAP_ParseArgs()
 *
 ***************************************************************************/

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_imap.h"
#include "imap_config.h"
#include "snort_bounds.h"
#include "sf_dynamic_preprocessor.h"
#include "sfPolicy.h"


/*  Global variable to hold configuration */
extern IMAPConfig **imap_config;

extern const IMAPToken imap_known_cmds[];

/* Private functions */
static int  ProcessPorts(IMAPConfig *, char *, int);
static int  ProcessImapMemcap(IMAPConfig *, char *, int);
static int  ProcessDecodeDepth(IMAPConfig *, char *, int, char *, DecodeType);

/*
 * Function: IMAP_ParseArgs(char *)
 *
 * Purpose: Process the preprocessor arguments from the rules file and
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
void IMAP_ParseArgs(IMAPConfig *config, char *args)
{
    int ret = 0;
    char *arg;
    char errStr[ERRSTRLEN];
    int errStrLen = ERRSTRLEN;

    if ((config == NULL) || (args == NULL))
        return;

    config->ports[IMAP_DEFAULT_SERVER_PORT / 8]     |= 1 << (IMAP_DEFAULT_SERVER_PORT % 8);
    config->memcap = DEFAULT_IMAP_MEMCAP;
    config->b64_depth = DEFAULT_DEPTH;
    config->qp_depth = DEFAULT_DEPTH;
    config->uu_depth = DEFAULT_DEPTH;
    config->bitenc_depth = DEFAULT_DEPTH;
    config->max_depth = MIN_DEPTH;

    config->cmd_config = (IMAPCmdConfig *)calloc(CMD_LAST, sizeof(IMAPCmdConfig));
    if (config->cmd_config == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate memory for IMAP "
                                        "command structure\n",
                                        *(_dpd.config_file), *(_dpd.config_line));
    }

    *errStr = '\0';

    arg = strtok(args, CONF_SEPARATORS);

    while ( arg != NULL )
    {
        if ( !strcasecmp(CONF_PORTS, arg) )
        {
            ret = ProcessPorts(config, errStr, errStrLen);
        }
        else if ( !strcasecmp(CONF_IMAP_MEMCAP, arg) )
        {
            ret = ProcessImapMemcap(config, errStr, errStrLen);
        }
        else if ( !strcasecmp(CONF_B64_DECODE, arg) )
        {
            ret = ProcessDecodeDepth(config, errStr, errStrLen, CONF_B64_DECODE, DECODE_B64);
        }
        else if ( !strcasecmp(CONF_QP_DECODE, arg) )
        {
            ret = ProcessDecodeDepth(config, errStr, errStrLen, CONF_QP_DECODE, DECODE_QP);
        }
        else if ( !strcasecmp(CONF_UU_DECODE, arg) )
        {
            ret = ProcessDecodeDepth(config, errStr, errStrLen, CONF_UU_DECODE, DECODE_UU);
        }
        else if ( !strcasecmp(CONF_BITENC_DECODE, arg) )
        {
            ret = ProcessDecodeDepth(config, errStr, errStrLen, CONF_BITENC_DECODE, DECODE_BITENC);
        }
        else if ( !strcasecmp(CONF_DISABLED, arg) )
        {
            config->disabled = 1;
        }
        else
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Unknown IMAP configuration option %s\n",
                                            *(_dpd.config_file), *(_dpd.config_line), arg);
        }

        if (ret == -1)
        {
            /*
            **  Fatal Error, log error and exit.
            */
            if (*errStr)
            {
                DynamicPreprocessorFatalMessage("%s(%d) => %s\n",
                                                *(_dpd.config_file), *(_dpd.config_line), errStr);
            }
            else
            {
                DynamicPreprocessorFatalMessage("%s(%d) => Undefined Error.\n",
                                                *(_dpd.config_file), *(_dpd.config_line));
            }
        }

        /*  Get next token */
        arg = strtok(NULL, CONF_SEPARATORS);
    }

}

int IMAP_IsDecodingEnabled(IMAPConfig *pPolicyConfig)
{
    if( (pPolicyConfig->b64_depth > -1) || (pPolicyConfig->qp_depth > -1)
     || (pPolicyConfig->uu_depth > -1) || (pPolicyConfig->bitenc_depth > -1) )
    {
        return 0;
    }
    else
        return -1;

}

void IMAP_CheckConfig(IMAPConfig *pPolicyConfig, tSfPolicyUserContextId context)
{
    int max = -1;
    IMAPConfig *defaultConfig =
                (IMAPConfig *)sfPolicyUserDataGetDefault(context);

    if (pPolicyConfig == defaultConfig)
    {
        if (!pPolicyConfig->memcap)
            pPolicyConfig->memcap = DEFAULT_IMAP_MEMCAP;

        if(!pPolicyConfig->b64_depth || !pPolicyConfig->qp_depth
                || !pPolicyConfig->uu_depth || !pPolicyConfig->bitenc_depth)
        {
            pPolicyConfig->max_depth = MAX_DEPTH;
            return;
        }
        else
        {
            if(max < pPolicyConfig->b64_depth)
                max = pPolicyConfig->b64_depth;

            if(max < pPolicyConfig->qp_depth)
                max = pPolicyConfig->qp_depth;

            if(max < pPolicyConfig->bitenc_depth)
                max = pPolicyConfig->bitenc_depth;

            if(max < pPolicyConfig->uu_depth)
                max = pPolicyConfig->uu_depth;

            pPolicyConfig->max_depth = max;
        }

    }
    else if (defaultConfig == NULL)
    {
        if (pPolicyConfig->memcap)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: memcap must be "
                   "configured in the default config.\n",
                    *(_dpd.config_file), *(_dpd.config_line));
        }

        if (pPolicyConfig->b64_depth > -1)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: b64_decode_depth must be "
                   "configured in the default config.\n",
                   *(_dpd.config_file), *(_dpd.config_line));
        }

        if (pPolicyConfig->qp_depth > -1)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: qp_decode_depth must be "
                   "configured in the default config.\n",
                   *(_dpd.config_file), *(_dpd.config_line));
        }

        if (pPolicyConfig->uu_depth > -1)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: uu_decode_depth must be "
                   "configured in the default config.\n",
                   *(_dpd.config_file), *(_dpd.config_line));
        }

        if (pPolicyConfig->bitenc_depth > -1)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: bitenc_decode_depth must be "
                   "configured in the default config.\n",
                   *(_dpd.config_file), *(_dpd.config_line));
        }

    }    
    else 
    {    
        pPolicyConfig->memcap = defaultConfig->memcap;
        pPolicyConfig->max_depth = defaultConfig->max_depth;
        if(pPolicyConfig->disabled)
        {
            pPolicyConfig->b64_depth = defaultConfig->b64_depth;
            pPolicyConfig->qp_depth = defaultConfig->qp_depth;
            pPolicyConfig->uu_depth = defaultConfig->uu_depth;
            pPolicyConfig->bitenc_depth = defaultConfig->bitenc_depth;
            return;
        }
        if(!pPolicyConfig->b64_depth && defaultConfig->b64_depth)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: Cannot enable unlimited Base64 decoding"
                    " in non-default config without turning on unlimited Base64 decoding in the default "
                    " config.\n",
                    *(_dpd.config_file), *(_dpd.config_line));
        }
        else if(defaultConfig->b64_depth && (pPolicyConfig->b64_depth > defaultConfig->b64_depth))
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: b64_decode_depth value %d in non-default config"
                   " cannot exceed default config's value %d.\n",
                    *(_dpd.config_file), *(_dpd.config_line), pPolicyConfig->b64_depth, defaultConfig->b64_depth);
        }

        if(!pPolicyConfig->qp_depth && defaultConfig->qp_depth)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: Cannot enable unlimited Quoted-Printable decoding"
                    " in non-default config without turning on unlimited Quoted-Printable decoding in the default "
                    " config.\n",
                    *(_dpd.config_file), *(_dpd.config_line));
        }
        else if(defaultConfig->qp_depth && (pPolicyConfig->qp_depth > defaultConfig->qp_depth))
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: qp_decode_depth value %d in non-default config"
                   " cannot exceed default config's value %d.\n",
                    *(_dpd.config_file), *(_dpd.config_line), pPolicyConfig->qp_depth, defaultConfig->qp_depth);
        }

        if(!pPolicyConfig->uu_depth && defaultConfig->uu_depth )
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: Cannot enable unlimited Unix-to-Unix decoding"
                    " in non-default config without turning on unlimited Unix-to-Unix decoding in the default "
                    " config.\n",
                    *(_dpd.config_file), *(_dpd.config_line));
        }
        else if(defaultConfig->uu_depth && (pPolicyConfig->uu_depth > defaultConfig->uu_depth))
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: uu_decode_depth value %d in the non-default config"
                   " cannot exceed default config's value %d.\n",
                    *(_dpd.config_file), *(_dpd.config_line),pPolicyConfig->uu_depth, defaultConfig->uu_depth);
        }

        if(!pPolicyConfig->bitenc_depth && defaultConfig->bitenc_depth)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: Cannot enable unlimited 7bit/8bit/binary extraction"
                    " in non-default config without turning on unlimited 7bit/8bit/binary extraction in the default "
                    " config.\n",
                    *(_dpd.config_file), *(_dpd.config_line));
        }
        else if(defaultConfig->bitenc_depth && (pPolicyConfig->bitenc_depth > defaultConfig->bitenc_depth))
        {
            DynamicPreprocessorFatalMessage("%s(%d) => IMAP: bitenc_decode_depth value %d in non-default config"
                   " cannot exceed default config's value %d.\n",
                    *(_dpd.config_file), *(_dpd.config_line), pPolicyConfig->bitenc_depth, defaultConfig->bitenc_depth);
        }

    }    
}

void IMAP_PrintConfig(IMAPConfig *config)
{
    int i;
    int j = 0;
    char buf[8192];

    if (config == NULL)
        return;

    memset(&buf[0], 0, sizeof(buf));

    _dpd.logMsg("IMAP Config:\n");

    if(config->disabled)
        _dpd.logMsg("    IMAP: INACTIVE\n");

    snprintf(buf, sizeof(buf) - 1, "    Ports: ");

    for (i = 0; i < 65536; i++)
    {
        if (config->ports[i / 8] & (1 << (i % 8)))
        {
            j++;
            _dpd.printfappend(buf, sizeof(buf) - 1, "%d ", i);
            if(!(j%10))
                _dpd.printfappend(buf, sizeof(buf) - 1, "\n    ");
        }
    }

    _dpd.logMsg("%s\n", buf);


    _dpd.logMsg("    IMAP Memcap: %u\n",
            config->memcap);

    if(config->b64_depth > -1)
    {
        _dpd.logMsg("    Base64 Decoding: %s\n", "Enabled");
        switch(config->b64_depth)
        {
            case 0:
                _dpd.logMsg("    Base64 Decoding Depth: %s\n", "Unlimited");
                break;
            default:
                _dpd.logMsg("    Base64 Decoding Depth: %d\n", config->b64_depth);
                break;
        }
    }
    else
    _dpd.logMsg("    Base64 Decoding: %s\n", "Disabled");

    if(config->qp_depth > -1)
    {
        _dpd.logMsg("    Quoted-Printable Decoding: %s\n","Enabled");
        switch(config->qp_depth)
        {
            case 0:
                _dpd.logMsg("    Quoted-Printable Decoding Depth: %s\n", "Unlimited");
                break;
            default:
                _dpd.logMsg("    Quoted-Printable Decoding Depth: %d\n", config->qp_depth);
                break;
        }   
    }
    else
        _dpd.logMsg("    Quoted-Printable Decoding: %s\n", "Disabled");

    if(config->uu_depth > -1)
    {
        _dpd.logMsg("    Unix-to-Unix Decoding: %s\n","Enabled");
        switch(config->uu_depth)
        {
            case 0:
                _dpd.logMsg("    Unix-to-Unix Decoding Depth: %s\n", "Unlimited");
                break;
            default:
                _dpd.logMsg("    Unix-to-Unix Decoding Depth: %d\n", config->uu_depth);
                break;
        }   
    }
    else
        _dpd.logMsg("    Unix-to-Unix Decoding: %s\n", "Disabled");

    if(config->bitenc_depth > -1)
    {
        _dpd.logMsg("    7bit/8bit/binary Extraction: %s\n","Enabled");
        switch(config->bitenc_depth)
        {
            case 0:
                _dpd.logMsg("    7bit/8bit/binary Extraction Depth: %s\n", "Unlimited");
                break;
            default:
                _dpd.logMsg("    7bit/8bit/binary Extraction Depth: %d\n", config->bitenc_depth);
                break;
        }   
    }
    else
        _dpd.logMsg("    7bit/8bit/binary Extraction: %s\n", "Disabled");

}

/*
**  NAME
**    ProcessPorts::
*/
/**
**  Process the port list.
**
**  This configuration is a list of valid ports and is ended by a
**  delimiter.
**
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessPorts(IMAPConfig *config, char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    char *pcEnd;
    int  iPort;
    int  iEndPorts = 0;

    if (config == NULL)
    {
        snprintf(ErrorString, ErrStrLen, "IMAP config is NULL.\n");
        return -1;
    }

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(!pcToken)
    {
        snprintf(ErrorString, ErrStrLen, "Invalid port list format.");
        return -1;
    }

    if(strcmp(CONF_START_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start a port list with the '%s' token.", CONF_START_LIST);

        return -1;
    }

    /* Since ports are specified, clear default ports */
    config->ports[IMAP_DEFAULT_SERVER_PORT / 8] &= ~(1 << (IMAP_DEFAULT_SERVER_PORT % 8));

    while ((pcToken = strtok(NULL, CONF_SEPARATORS)) != NULL)
    {
        if(!strcmp(CONF_END_LIST, pcToken))
        {
            iEndPorts = 1;
            break;
        }

        iPort = strtol(pcToken, &pcEnd, 10);

        /*
        **  Validity check for port
        */
        if(*pcEnd)
        {
            snprintf(ErrorString, ErrStrLen,
                     "Invalid port number.");

            return -1;
        }

        if(iPort < 0 || iPort > MAXPORTS-1)
        {
            snprintf(ErrorString, ErrStrLen,
                     "Invalid port number.  Must be between 0 and 65535.");

            return -1;
        }

        config->ports[iPort / 8] |= (1 << (iPort % 8));
    }

    if(!iEndPorts)
    {
        snprintf(ErrorString, ErrStrLen,
                 "Must end '%s' configuration with '%s'.",
                 CONF_PORTS, CONF_END_LIST);

        return -1;
    }

    return 0;
}

static int ProcessImapMemcap(IMAPConfig *config, char *ErrorString, int ErrStrLen)
{
    char *endptr;
    char *value;
    uint32_t imap_memcap = 0;
    if (config == NULL)
    {
        snprintf(ErrorString, ErrStrLen, "IMAP config is NULL.\n");
        return -1;
    }

    value = strtok(NULL, CONF_SEPARATORS);
    if ( value == NULL )
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid format for IMAP config option 'memcap'.");
        return -1;
    }
    imap_memcap = strtoul(value, &endptr, 10);

    if((value[0] == '-') || (*endptr != '\0'))
    {
        snprintf(ErrorString, ErrStrLen,
            "Invalid format for IMAP config option 'memcap'.");
        return -1;
    }

    if (imap_memcap < MIN_IMAP_MEMCAP || imap_memcap > MAX_IMAP_MEMCAP)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid value for memcap."
                "It should range between %d and %d.", 
                MIN_IMAP_MEMCAP, MAX_IMAP_MEMCAP);
        return -1;
    }

    config->memcap = imap_memcap;
    return 0;
}


static int ProcessDecodeDepth(IMAPConfig *config, char *ErrorString, int ErrStrLen, char *decode_type, DecodeType type)
{
    char *endptr;
    char *value;
    int decode_depth = 0;
    if (config == NULL)
    {
        snprintf(ErrorString, ErrStrLen, "IMAP config is NULL.\n");
        return -1;
    }

    value = strtok(NULL, CONF_SEPARATORS);
    if ( value == NULL )
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid format for IMAP config option '%s'.", decode_type);
        return -1;
    }
    decode_depth = strtol(value, &endptr, 10);

    if(*endptr)
    {
        snprintf(ErrorString, ErrStrLen,
            "Invalid format for IMAP config option '%s'.", decode_type);
        return -1;
    }
    if(decode_depth < MIN_DEPTH || decode_depth > MAX_DEPTH)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid value for IMAP config option '%s'."
                "It should range between %d and %d.",
                decode_type, MIN_DEPTH, MAX_DEPTH);
        return -1;
    }

    switch(type)
    {
        case DECODE_B64:
            config->b64_depth = decode_depth;
            break;
        case DECODE_QP:
            config->qp_depth = decode_depth;
            break;
        case DECODE_UU:
            config->uu_depth = decode_depth;
            break;
        case DECODE_BITENC:
            config->bitenc_depth = decode_depth;
            break;
        default:
            return -1;
    }

    return 0;
}
