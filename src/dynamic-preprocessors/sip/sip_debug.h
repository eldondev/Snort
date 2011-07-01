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
 * Provides macros and functions for debugging the preprocessor.
 * If Snort is not configured to do debugging, macros are empty.
 *
 * 8/17/2008 - Initial implementation ... Todd Wease <twease@sourcefire.com>
 *
 ****************************************************************************/

#ifndef _SIP_DEBUG_H_
#define _SIP_DEBUG_H_

#include <stdio.h>
#include "sfPolicyUserData.h"

/********************************************************************
 * Macros
 ********************************************************************/
#define DEBUG_SIP            0x00000010  /* 16 */


#define SIP_DEBUG__START_MSG  "SIP Start ********************************************"
#define SIP_DEBUG__END_MSG    "SIP End **********************************************"


#endif  /* _SIP_DEBUG_H_ */

