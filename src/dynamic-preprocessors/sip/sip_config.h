/****************************************************************************
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
 ****************************************************************************
 * Provides convenience functions for parsing and querying configuration.
 *
 * 2/17/2011 - Initial implementation ... Hui Cao <hcao@sourcefire.com>
 *
 ****************************************************************************/

#ifndef _SIP_CONFIG_H_
#define _SIP_CONFIG_H_

#include "sfPolicyUserData.h"
#include "snort_bounds.h"
#include "sip_debug.h"

#define SIP_NAME  "sip"


typedef enum _SIP_method
{
	SIP_METHOD_NULL        = 0, //0x0000,
	SIP_METHOD_INVITE      = 1, //0x0001,
	SIP_METHOD_CANCEL      = 2, //0x0002,
	SIP_METHOD_ACK         = 3, //0x0004,
	SIP_METHOD_BYE         = 4, //0x0008,
	SIP_METHOD_REGISTER    = 5, //0x0010,
	SIP_METHOD_OPTIONS     = 6, //0x0020,
	SIP_METHOD_REFER       = 7, //0x0040,
	SIP_METHOD_SUBSCRIBE   = 8, //0x0080,
	SIP_METHOD_UPDATE      = 9, //0x0100,
	SIP_METHOD_JOIN        = 10,//0x0200,
	SIP_METHOD_INFO        = 11,//0x0400,
	SIP_METHOD_MESSAGE     = 12,//0x0800,
	SIP_METHOD_NOTIFY      = 13,//0x1000,
	SIP_METHOD_PRACK       = 14,//0x2000,
	SIP_METHOD_USER_DEFINE = 15,//0x4000,
	SIP_METHOD_USER_DEFINE_MAX = 32//0x80000000,

} SIPMethodsFlag;

#define SIP_METHOD_DEFAULT     0x003f
#define SIP_METHOD_ALL     0xffffffff
/*
 * Header fields and processing functions
 */
typedef struct _SIPMethod
{
	char *name;
	SIPMethodsFlag methodFlag;

}SIPMethod;

extern SIPMethod StandardMethods[];


typedef struct _sipMethodlistNode
{
	char *methodName;
	int methodLen;
	SIPMethodsFlag methodFlag;
	struct _sipMethodlistNode* nextm;
} SIPMethodNode;

typedef SIPMethodNode *  SIPMethodlist;

/*
 * One of these structures is kept for each configured
 * server port.
 */
typedef struct _sipPortlistNode
{
	uint16_t server_port;
	struct _sipPortlistNode* nextp;
} SIPPortNode;

/*
 * SIP preprocessor configuration.
 *
 * disabled:  Whether or not to disable SIP PP.
 * maxNumSessions: Maximum amount of run-time memory
 * ports: Which ports to check for SIP messages
 * methods: Which methods to check
 * maxUriLen: Maximum requst_URI size
 * maxCallIdLen: Maximum call_ID size.
 * maxRequestNameLen: Maximum length of request name in the CSeqID.
 * maxFromLen: Maximum From field size
 * maxToLen: Maximum To field size
 * maxViaLen: Maximum Via field size
 * maxContactLen: Maximum Contact field size
 * maxContentLen: Maximum Content length
 * ignoreChannel: Whether to ignore media channels found by SIP PP
 */
typedef struct _sipConfig
{
	uint8_t  disabled;
	uint32_t maxNumSessions;
	uint8_t  ports[MAXPORTS/8];
	uint32_t methodsConfig;
	SIPMethodlist methods;
	uint16_t maxUriLen;
	uint16_t maxCallIdLen;
	uint16_t maxRequestNameLen;
	uint16_t maxFromLen;
	uint16_t maxToLen;
	uint16_t maxViaLen;
	uint16_t maxContactLen;
	uint16_t maxContentLen;
	uint8_t  ignoreChannel;
	int ref_count;

} SIPConfig;

/********************************************************************
 * Public function prototypes
 ********************************************************************/
void  SIP_FreeConfig(SIPConfig *);
void  ParseSIPArgs(SIPConfig *, u_char*);
SIPMethodNode*  SIP_AddUserDefinedMethod(char *, uint32_t *, SIPMethodlist*);

#endif
