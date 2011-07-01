/*
 * sf_snort_detection_engine.h
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
 * Author: Ryan Jordan
 *
 * Date: 4/2011
 *
 * Common definitions for the Dyanmic Rule Engine
 */

#ifndef SF_SNORT_DETECTION_ENGINE__H
#define SF_SNORT_DETECTION_ENGINE__H

int BoyerContentSetup(Rule *rule, ContentInfo *content);
int PCRESetup(Rule *rule, PCREInfo *pcreInfo);
int ValidateHeaderCheck(Rule *rule, HdrOptCheck *optData);
void ContentSetup(void);
int ByteExtractInitialize(Rule *rule, ByteExtract *extractData);
int LoopInfoInitialize(Rule *rule, LoopInfo *loopInfo);
int ByteDataInitialize(Rule *rule, ByteData *byte);
int CursorInfoInitialize(Rule *rule, CursorInfo *cursor);



#endif /* SF_SNORT_DETECTION_ENGINE__H */
