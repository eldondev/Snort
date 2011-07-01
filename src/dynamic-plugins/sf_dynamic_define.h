/*
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
 * Copyright (C) 2007-2009 Sourcefire, Inc.
 *
 * Author: Russ Combs
 *
 * #defines required by the dynamic engine.  These were factored out of
 * sf_snort_plugin_api.h because they are required by fpcreate.c.  They
 * could have been placed in sf_dynamic_engine.h but that would have
 * caused all the sf_engine/examples/ *.c to depend on that file.
 */
#ifndef _SF_DYNAMIC_DEFINE_H_
#define _SF_DYNAMIC_DEFINE_H_

/* the OPTION_TYPE_* and FLOW_*  values
 * are used as args to the hasFunc()
 * which replaces the prior has*Func()s.
 */
typedef enum {
     OPTION_TYPE_PREPROCESSOR,
     OPTION_TYPE_CONTENT,
     OPTION_TYPE_PCRE,
     OPTION_TYPE_FLOWBIT,
     OPTION_TYPE_FLOWFLAGS,
     OPTION_TYPE_ASN1,
     OPTION_TYPE_CURSOR,
     OPTION_TYPE_HDR_CHECK,
     OPTION_TYPE_BYTE_TEST,
     OPTION_TYPE_BYTE_JUMP,
     OPTION_TYPE_BYTE_EXTRACT,
     OPTION_TYPE_SET_CURSOR,
     OPTION_TYPE_LOOP,
     OPTION_TYPE_MAX
} DynamicOptionType;

#define FLOW_ESTABLISHED         0x0010
#define FLOW_FR_SERVER           0x0040
#define FLOW_TO_CLIENT           0x0040 /* Just for convenience */
#define FLOW_TO_SERVER           0x0080
#define FLOW_FR_CLIENT           0x0080 /* Just for convenience */
#define FLOW_IGNORE_REASSEMBLED  0x1000
#define FLOW_ONLY_REASSEMBLED    0x2000
#define FLOW_ONLY_REASSMBLED     FLOW_ONLY_REASSEMBLED

#define SNORT_PCRE_OVERRIDE_MATCH_LIMIT 0x8000000

#if defined _WIN32 || defined __CYGWIN__
#  if defined SF_SNORT_ENGINE_DLL || defined SF_SNORT_DETECTION_DLL || defined SF_SNORT_PREPROC_DLL
#    ifdef __GNUC__
#      define SO_PUBLIC __attribute__((dllexport))
#    else
#      define SO_PUBLIC __declspec(dllexport)
#    endif
#  else
#    ifdef __GNUC__
#      define SO_PUBLIC __attribute__((dllimport))
#    else
#      define SO_PUBLIC __declspec(dllimport)
#    endif
#  endif
#  define DLL_LOCAL
#else
#  ifdef HAVE_VISIBILITY
#    define SO_PUBLIC  __attribute__ ((visibility("default")))
#    define SO_PRIVATE __attribute__ ((visibility("hidden")))
#  else
#    define SO_PUBLIC
#    define SO_PRIVATE
#  endif
#endif

#endif /* _SF_DYNAMIC_DEFINE_H_ */

