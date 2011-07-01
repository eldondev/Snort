 /*
 * sf_snort_detection_engine.c
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
 * Copyright (C) 2005-2009 Sourcefire, Inc.
 *
 * Author: Steve Sturges
 *         Andy  Mullican
 *
 * Date: 5/2005
 *
 * Dyanmic Rule Engine
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <stdarg.h>
#include "debug.h"
#include "sf_snort_packet.h"
#include "sf_snort_plugin_api.h"
#include "sf_dynamic_meta.h"
#include "sf_dynamic_engine.h"
#include "sfghash.h"
#include "bmh.h"

#define MAJOR_VERSION   1
#define MINOR_VERSION   11
#define BUILD_VERSION   17  
#define DETECT_NAME     "SF_SNORT_DETECTION_ENGINE"

#ifdef WIN32
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#else
#include <sys/param.h>
#include <limits.h>
#endif

DynamicEngineData _ded;
static void FreeOneRule(void *);

#define STD_BUF 1024

NORETURN void DynamicEngineFatalMessage(const char *format, ...)
{
    char buf[STD_BUF];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    buf[STD_BUF - 1] = '\0';

    _ded.fatalMsg("%s", buf);

    exit(1);
}

extern int BoyerContentSetup(Rule *rule, ContentInfo *content);
extern int PCRESetup(Rule *rule, PCREInfo *pcreInfo);
extern int ValidateHeaderCheck(Rule *rule, HdrOptCheck *optData);
extern void ContentSetup(void);
extern int ByteExtractInitialize(Rule *rule, ByteExtract *extractData);
extern int LoopInfoInitialize(Rule *rule, LoopInfo *loopInfo);

ENGINE_LINKAGE int InitializeEngine(DynamicEngineData *ded)
{
    int i;
    if (ded->version < ENGINE_DATA_VERSION)
    {
        return -1;
    }

    _ded.version = ded->version;
    _ded.altBuffer = ded->altBuffer;
    for (i=0;i<MAX_URIINFOS;i++)
    {
        _ded.uriBuffers[i] = ded->uriBuffers[i];
    }
    _ded.ruleRegister = ded->ruleRegister;
    _ded.flowbitRegister = ded->flowbitRegister;
    _ded.flowbitCheck = ded->flowbitCheck;
    _ded.asn1Detect = ded->asn1Detect;
    _ded.dataDumpDirectory = ded->dataDumpDirectory;
    _ded.logMsg = ded->logMsg;
    _ded.errMsg = ded->errMsg;
    _ded.fatalMsg = ded->fatalMsg;
    _ded.preprocRuleOptInit = ded->preprocRuleOptInit;
    _ded.setRuleData = ded->setRuleData;
    _ded.getRuleData = ded->getRuleData;

    _ded.debugMsg = ded->debugMsg;
#ifdef HAVE_WCHAR_H
    _ded.debugWideMsg = ded->debugWideMsg;
#endif
    _ded.debugMsgFile = ded->debugMsgFile;
    _ded.debugMsgLine = ded->debugMsgLine;

    _ded.pcreStudy = ded->pcreStudy;
    _ded.pcreCompile = ded->pcreCompile;
    _ded.pcreExec = ded->pcreExec;

    return 0;
}

ENGINE_LINKAGE int LibVersion(DynamicPluginMeta *dpm)
{

    dpm->type  = TYPE_ENGINE;
    dpm->major = MAJOR_VERSION;
    dpm->minor = MINOR_VERSION;
    dpm->build = BUILD_VERSION;
    strncpy(dpm->uniqueName, DETECT_NAME, MAX_NAME_LEN);
    return 0;
}

/*
 * Function: CheckCompatibility
 * eng = current engine version (as configured above in LibVersion())
 * req = required engine version (as obtained from the detection library)
 * Return values: 0 -- no compatibility issue detected; >0 -- incompatible.
 */
ENGINE_LINKAGE int CheckCompatibility(DynamicPluginMeta* eng, DynamicPluginMeta* req)
{
    if ( !eng || !req ) return 1;
    if ( eng->type != req->type ) return 2;
    if ( strcmp(eng->uniqueName, req->uniqueName) ) return 3;
    if ( eng->major < req->major ) return 4;
    if ( eng->major > req->major ) return 0;
    if ( eng->minor < req->minor ) return 5;
    return 0;
}

/* Variables to check type of InitializeEngine and LibVersion */
ENGINE_LINKAGE InitEngineLibFunc initEngineFunc = &InitializeEngine;
ENGINE_LINKAGE LibVersionFunc libVersionFunc = &LibVersion;


/* Evaluates the rule -- indirect interface, this will be
 * called from the SpecialPurpose detection plugin as
 * CheckRule (void *, void *);
 */
static int CheckRule(void *p, void *r)
{
    Rule *rule = (Rule *)r;
    if (!rule->initialized)
    {
        _ded.errMsg("Dynamic Rule [%d:%d] was not initialized properly.\n",
            rule->info.genID, rule->info.sigID);
        return RULE_NOMATCH;
    }

    ContentSetup();

    /* If there is an eval func, use it, this is a 'hand-coded' rule */
    if (rule->evalFunc)
        return rule->evalFunc((SFSnortPacket *)p);
    else
        return ruleMatch(p, rule);
}

static int HasOption (void *r, DynamicOptionType optionType, int flowFlag)
{
    Rule *rule = (Rule *)r;
    RuleOption *option;
    int i;

    if ((!rule) || (!rule->initialized))
    {
        return 0;
    }

    for (i=0,option = rule->options[i];option != NULL; option = rule->options[++i])
    {
        if (option->optionType == optionType)
        {
            if (!flowFlag) return 1;

            if (
                (optionType == OPTION_TYPE_FLOWFLAGS) &&
                (option->option_u.flowFlags->flags & flowFlag)
            ) return 1;
        }
    }

    return 0;
}

static int GetFPContent(void *r, int buf, FPContentInfo** contents, int maxNumContents)
{
    Rule *rule = (Rule *)r;
    int i, j = 0;
    RuleOption *option;
    int numContents = 0;

    for (i=0,option = rule->options[i];option != NULL; option = rule->options[++i])
    {
        if (option->optionType == OPTION_TYPE_CONTENT)
        {
            if ((option->option_u.content->flags & CONTENT_FAST_PATTERN) &&
                (((option->option_u.content->flags & (CONTENT_BUF_URI | CONTENT_BUF_POST | CONTENT_BUF_HEADER | CONTENT_BUF_METHOD)) && (buf == FASTPATTERN_URI)) ||
                 (!(option->option_u.content->flags & (CONTENT_BUF_URI | CONTENT_BUF_POST | CONTENT_BUF_HEADER | CONTENT_BUF_METHOD)) && (buf == FASTPATTERN_NORMAL)) ))
            {
                FPContentInfo *content = (FPContentInfo *)calloc(1, sizeof(FPContentInfo));
                if (content == NULL)
                {
                    DynamicEngineFatalMessage("Failed to allocate memory\n");
                }

                content->content = (char *)option->option_u.content->patternByteForm;
                content->length = option->option_u.content->patternByteFormLength;
                content->noCaseFlag = (char)(option->option_u.content->flags & CONTENT_NOCASE);

                contents[j++] = content;
                numContents++;
            }
        }
        if (numContents >= maxNumContents)
            break;
    }
    
    return numContents;
}

static int DecodeContentPattern(Rule *rule, ContentInfo *content)
{
    int pat_len;
    const u_int8_t *pat_begin = content->pattern;
    const u_int8_t *pat_idx;
    const u_int8_t *pat_end;
    char tmp_buf[2048];
    char *raw_idx;
    char *raw_end;
    int tmp_len = 0;
    int hex_encoding = 0;
    int hex_len = 0;
    int pending = 0;
    int char_count = 0;
    int escaped = 0;

    char hex_encoded[3];


    /* First, setup the raw data by parsing content */
    /* XXX: Basically, duplicate the code from ParsePattern()
     * in sp_pattern_match.c */
    pat_len = strlen((const char *)content->pattern);
    pat_end = pat_begin + pat_len;

    /* set the indexes into the temp buffer */
    raw_idx = tmp_buf;
    raw_end = (raw_idx + pat_len);

    /* why is this buffer so small? */
    memset(hex_encoded, 0, 3);
    memset(hex_encoded, '0', 2);

    pat_idx = pat_begin;

    /* Uggh, loop through each char */
    while(pat_idx < pat_end)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "processing char: %c\n", *pat_idx););
        switch(*pat_idx)
        {
            case '|':
                DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Got bar... "););
                if(!escaped)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "not in literal mode... "););
                    if(!hex_encoding)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Entering hexmode\n"););
                        hex_encoding = 1;
                    }
                    else
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Exiting hexmode\n"););

                        /*
                        **  Hexmode is not even.
                        */
                        if(!hex_len || hex_len % 2)
                        {
                            DynamicEngineFatalMessage("Content hexmode argument has invalid "
                                                      "number of hex digits for dynamic rule [%d:%d].\n", 
                                                      rule->info.genID, rule->info.sigID);
                        }

                        hex_encoding = 0;
                        pending = 0;
                    }

                    if(hex_encoding)
                        hex_len = 0;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "literal set, Clearing\n"););
                    escaped = 0;
                    tmp_buf[tmp_len] = pat_begin[char_count];
                    tmp_len++;
                }

                break;

            case '\\':
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Got literal char... "););

                if(!escaped)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Setting literal\n"););

                    escaped = 1;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Clearing literal\n"););
                    tmp_buf[tmp_len] = pat_begin[char_count];
                    escaped = 0;
                    tmp_len++;
                }

                break;
            case '"':
                if (!escaped)
                {
                    DynamicEngineFatalMessage("Non-escaped '\"' character in dynamic rule [%d:%d]!\n",
                                              rule->info.genID, rule->info.sigID);
                }
                /* otherwise process the character as default */
            default:
                if(hex_encoding)
                {
                    if(isxdigit((int) *pat_idx))
                    {
                        hex_len++;

                        if(!pending)
                        {
                            hex_encoded[0] = *pat_idx;
                            pending++;
                        }
                        else
                        {
                            hex_encoded[1] = *pat_idx;
                            pending--;

                            if(raw_idx < raw_end)
                            {                            
                                tmp_buf[tmp_len] = (u_char) 
                                    strtol(hex_encoded, (char **) NULL, 16)&0xFF;

                                tmp_len++;
                                memset(hex_encoded, 0, 3);
                                memset(hex_encoded, '0', 2);
                            }
                            else
                            {
                                DynamicEngineFatalMessage("ParsePattern() buffer overflow, "
                                                          "make a smaller pattern please for dynamic "
                                                          "rule [%d:%d]! (Max size = 2048)\n",
                                                          rule->info.genID, rule->info.sigID);
                            }
                        }
                    }
                    else
                    {
                        if(*pat_idx != ' ')
                        {
                            DynamicEngineFatalMessage("What is this \"%c\"(0x%X) doing in your "
                                                      "binary buffer for dynamic rule [%d:%d]? "
                                                      "Valid hex values only please! "
                                                      "(0x0 - 0xF) Position: %d\n",
                                                      (char) *pat_idx, (char) *pat_idx, 
                                                      rule->info.genID, rule->info.sigID, char_count);
                        }
                    }
                }
                else
                {
                    if(*pat_idx >= 0x1F && *pat_idx <= 0x7e)
                    {
                        if(raw_idx < raw_end)
                        {
                            tmp_buf[tmp_len] = pat_begin[char_count];
                            tmp_len++;
                        }
                        else
                        {
                            DynamicEngineFatalMessage("ParsePattern() buffer overflow in "
                                                      "dynamic rule [%d:%d]!\n",
                                                      rule->info.genID, rule->info.sigID);
                        }

                        if(escaped)
                        {
                            escaped = 0;
                        }
                    }
                    else
                    {
                        if(escaped)
                        {
                            tmp_buf[tmp_len] = pat_begin[char_count];
                            tmp_len++;
                            DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Clearing literal\n"););
                            escaped = 0;
                        }
                        else
                        {
                            DynamicEngineFatalMessage("character value out of range, try a "
                                                      "binary buffer for dynamic rule [%d:%d]\n", 
                                                      rule->info.genID, rule->info.sigID);
                        }
                    }
                }

                break;
        }

        raw_idx++;
        pat_idx++;
        char_count++;
    }
    
    /* Now, tmp_buf contains the decoded ascii & raw binary from the patter */
    content->patternByteForm = (u_int8_t *)calloc(tmp_len, sizeof(u_int8_t));
    if (content->patternByteForm == NULL)
    {
        DynamicEngineFatalMessage("Failed to allocate memory\n");
    }

    memcpy(content->patternByteForm, tmp_buf, tmp_len);
    content->patternByteFormLength = tmp_len;

    return 0;
}

static unsigned int getNonRepeatingLength(char *data, int data_len)
{
    int i, j;
    
    j = 0;
    for ( i = 1; i < data_len; i++ )
    {
        if ( data[j] != data[i] )
        {
            j = 0;
            continue;
        }
        if ( i == (data_len - 1) )
        {
            return (data_len - j - 1);
        }
        j++;
    }
    return data_len;
}

int RegisterOneRule(Rule *rule, int registerRule)
{
    int i;
    int fpContentFlags = 0;
    int result;
    RuleOption *option;
    unsigned long longestContent = 0;
    int longestContentIndex = -1;


    for (i=0;rule->options[i] != NULL; i++)
    {
        option = rule->options[i];
        switch (option->optionType)
        {
            case OPTION_TYPE_CONTENT:
                {
                    ContentInfo *content = option->option_u.content;

                    if (!content->patternByteForm)
                        DecodeContentPattern(rule, content);
                    if (!content->boyer_ptr)
                        BoyerContentSetup(rule, content);

                    content->incrementLength =
                        getNonRepeatingLength((char *)content->patternByteForm, content->patternByteFormLength);

                    if (!(content->flags & NOT_FLAG))
                    {
                        if (content->flags & CONTENT_FAST_PATTERN)
                        {
                            if (content->flags & (CONTENT_BUF_URI | CONTENT_BUF_POST |
                                                  CONTENT_BUF_HEADER | CONTENT_BUF_METHOD))
                            {
                                fpContentFlags |= FASTPATTERN_URI;
                            }
                            else
                            {
                                fpContentFlags |= FASTPATTERN_NORMAL;
                            }
                        }

                        if (content->patternByteFormLength > longestContent)
                        {
                            longestContent = content->patternByteFormLength;
                            longestContentIndex = i;
                        }
                    }
                }
                break;
            case OPTION_TYPE_PCRE:
                {
                    PCREInfo *pcre = option->option_u.pcre;

                    if (pcre->compiled_expr == NULL)
                    {
                        if (PCRESetup(rule, pcre))
                        {
                            rule->initialized = 0;
                            return -1;
                        }
                    }
                }
                break;
            case OPTION_TYPE_FLOWBIT:
                {
                    FlowBitsInfo *flowbits = option->option_u.flowBit;
                    flowbits->id = _ded.flowbitRegister(flowbits->flowBitsName, flowbits->operation);
                    if (flowbits->operation & FLOWBIT_NOALERT)
                        rule->noAlert = 1;
                }
                break;
            case OPTION_TYPE_ASN1:
                /*  Call asn1_init_mem(512); if linking statically to asn source */
                break;
            case OPTION_TYPE_HDR_CHECK:
                {
                    HdrOptCheck *optData = option->option_u.hdrData;
                    result = ValidateHeaderCheck(rule, optData);
                    if (result)
                    {
                        /* Don't initialize this rule */
                        rule->initialized = 0;
                        return result;
                    }
                }
                break;
            case OPTION_TYPE_BYTE_EXTRACT:
                {
                    ByteExtract *extractData = option->option_u.byteExtract;
                    result = ByteExtractInitialize(rule, extractData);
                    if (result)
                    {
                        /* Don't initialize this rule */
                        rule->initialized = 0;
                        return result;
                    }
                }
                break;
            case OPTION_TYPE_LOOP:
                {
                    LoopInfo *loopInfo = option->option_u.loop;
                    result = LoopInfoInitialize(rule, loopInfo);
                    if (result)
                    {
                        /* Don't initialize this rule */
                        rule->initialized = 0;
                        return result;
                    }
                    loopInfo->initialized = 1;
                }
                break;
            case OPTION_TYPE_PREPROCESSOR:
                {
                    PreprocessorOption *preprocOpt = option->option_u.preprocOpt;

                    if (_ded.preprocRuleOptInit((void *)preprocOpt) == -1)
                    {
                        /* Don't initialize this rule */
                        rule->initialized = 0;
                        return -1;
                    }
                }

                break;

            case OPTION_TYPE_BYTE_TEST:
            case OPTION_TYPE_BYTE_JUMP:
            default:
                /* nada */
                break;
        }
    }

    /* If no options were marked as the fast pattern,
     * use the longest one we found.
     */
    if ((fpContentFlags == 0) && (longestContentIndex != -1))
    {
        option = rule->options[longestContentIndex];
        /* Just to be safe, make sure this is a content option */
        if (option->optionType == OPTION_TYPE_CONTENT)
        {
            ContentInfo *content = option->option_u.content;

            if (content->flags & (CONTENT_BUF_URI | CONTENT_BUF_POST | CONTENT_BUF_HEADER | CONTENT_BUF_METHOD))
                fpContentFlags |= FASTPATTERN_URI;
            else
                fpContentFlags |= FASTPATTERN_NORMAL;

            content->flags |= CONTENT_FAST_PATTERN;
        }
    }

    /* Index less one since we've iterated through them already */
    rule->numOptions = i;

    /* Might not be a stub for it, but it has been initialized.  If there is
     * not a stub for it, it will never make it's way into the rule chain and
     * will thus not be evaluated.  Important to call it initialized in case
     * the rule was initially disabled, meaning the stub was not present and
     * the otn lookup failed, then enabled on a reload.  The "initialized" is
     * only relevant to if the rule was correctly parsed, not if we were able
     * to find the relevant stub rule for it.  Being initialized and registered
     * are effectively separate processes. */
    rule->initialized = 1;

    if (registerRule)
    {
        /* Allocate an OTN and link it in with snort */
        if (_ded.ruleRegister(rule->info.sigID,
                          rule->info.genID,
                          (void *)rule,
                          &CheckRule,
                          &HasOption,
                          fpContentFlags,
                          &GetFPContent,
                          &FreeOneRule) == -1)
        {
            return -1;
        }
    }

    return 0;
}

static void FreeOneRule(void *data)
{
    int i;
    Rule *rule = (Rule *)data;

    if (rule == NULL)
        return;

    /* More than one rule may use the same rule option so make sure anything
     * free'd is set to NULL to avoid potential double free */
    for (i = 0; rule->options[i] != NULL; i++)
    {
        RuleOption *option = rule->options[i];

        switch (option->optionType)
        {
            case OPTION_TYPE_CONTENT:
                {
                    ContentInfo *content = option->option_u.content;

                    if (content->patternByteForm != NULL)
                    {
                        free(content->patternByteForm);
                        content->patternByteForm = NULL;
                    }

                    if (content->boyer_ptr != NULL)
                    {
                        hbm_free((HBM_STRUCT *)content->boyer_ptr);
                        content->boyer_ptr = NULL;
                    }
                }

                break;

            case OPTION_TYPE_PCRE:
                {
                    PCREInfo *pcre = option->option_u.pcre;

                    if (pcre->compiled_expr != NULL)
                    {
                        free(pcre->compiled_expr);
                        pcre->compiled_expr = NULL;
                    }

                    if (pcre->compiled_extra != NULL)
                    {
                        free(pcre->compiled_extra);
                        pcre->compiled_extra = NULL;
                    }
                }

                break;

            case OPTION_TYPE_BYTE_EXTRACT:
                if (rule->ruleData != NULL)
                {
                    sfghash_delete(rule->ruleData);
                    rule->ruleData = NULL;
                }

                break;

            case OPTION_TYPE_LOOP:
                {
                    LoopInfo *loopInfo = option->option_u.loop;
                    FreeOneRule((void *)loopInfo->subRule);
                }

                break;

            case OPTION_TYPE_HDR_CHECK:
            case OPTION_TYPE_ASN1:
            case OPTION_TYPE_FLOWBIT:
            case OPTION_TYPE_PREPROCESSOR:
            case OPTION_TYPE_BYTE_TEST:
            case OPTION_TYPE_BYTE_JUMP:
            default:
                break;
        }
    }
}

#define TCP_STRING "tcp"
#define UDP_STRING "udp"
#define ICMP_STRING "icmp"
#define IP_STRING "ip"
char *GetProtoString(int protocol)
{
    switch (protocol)
    {
    case IPPROTO_TCP:
        return TCP_STRING;
    case IPPROTO_UDP:
        return UDP_STRING;
    case IPPROTO_ICMP:
        return ICMP_STRING;
    default:
        break;
    }
    return IP_STRING;
}

static int DumpRule(FILE *fp, Rule *rule)
{
    RuleReference *ref;
    RuleMetaData *meta;
    int i;

    fprintf(fp, "alert %s %s %s %s %s %s ",
        GetProtoString(rule->ip.protocol),
        rule->ip.src_addr, rule->ip.src_port,
        rule->ip.direction == 0 ? "->" : "<>",
        rule->ip.dst_addr, rule->ip.dst_port);
    fprintf(fp, "(msg:\"%s\"; ", rule->info.message);
    fprintf(fp, "sid:%d; ", rule->info.sigID);
    fprintf(fp, "gid:%d; ", rule->info.genID);
    fprintf(fp, "rev:%d; ", rule->info.revision);
    if (rule->info.classification != NULL)
        fprintf(fp, "classtype:%s; ", rule->info.classification);
    if (rule->info.priority != 0)
        fprintf(fp, "priority:%d; ", rule->info.priority);

    for (i = 0; rule->options[i] != NULL; i++)
    {
        if( rule->options[i]->optionType == OPTION_TYPE_FLOWBIT )
        {
            FlowBitsInfo *flowbit = rule->options[i]->option_u.flowBit;
            int print_name = 1;

            fprintf(fp, "flowbits:");
            switch (flowbit->operation)
            {
                case FLOWBIT_SET:
                    fprintf(fp, "set,");
                    break;
                case FLOWBIT_UNSET:
                    fprintf(fp, "unset,");
                    break;
                case FLOWBIT_ISSET:
                    fprintf(fp, "isset,");
                    break;
                case FLOWBIT_ISNOTSET:
                    fprintf(fp, "isnotset,");
                    break;
                case FLOWBIT_RESET:
                    fprintf(fp, "reset; ");
                    print_name = 0;
                    break;
                case FLOWBIT_NOALERT:
                    fprintf(fp, "noalert; ");
                    print_name = 0;
                    break;
                default:
                    /* XXX: Can't call FatalError here! */
                    break;
            }
            if (print_name)
                fprintf(fp, "%s; ", flowbit->flowBitsName);
        }
    }

    if (rule->info.references)
    {
        for (i=0,ref = rule->info.references[i];
             ref != NULL;
             i++,ref = rule->info.references[i])
        {
            fprintf(fp, "reference:%s,%s; ", ref->systemName, ref->refIdentifier);
        }
    }

    fprintf(fp, "metadata: engine shared, soid %d|%d",
            rule->info.genID, rule->info.sigID);

    if(rule->info.meta)
    {
        for (i=0, meta= rule->info.meta[i];
             meta != NULL;
             i++, meta = rule->info.meta[i])
        {
            fprintf(fp, ", %s", meta->data);
        }
    }

    fprintf(fp, ";)\n");

    return 0;
}

ENGINE_LINKAGE int RegisterRules(Rule **rules)
{
    int i;

    for (i=0; rules[i] != NULL; i++)
    {
        if (rules[i]->initialized == 0)
            RegisterOneRule(rules[i], REGISTER_RULE);
    }

    return 0;
}

ENGINE_LINKAGE int DumpRules(char *rulesFileName, Rule **rules)
{
    FILE *ruleFP;
    char ruleFile[PATH_MAX+1];
    int i;
#ifndef WIN32
#define DIR_SEP "/"
#else
#define DIR_SEP "\\"
#define snprintf _snprintf
#endif

    /* XXX: Need to do some checking here on lengths */
    ruleFile[0] = '\0';
    if ((strlen(_ded.dataDumpDirectory) + strlen(DIR_SEP) + strlen(rulesFileName) + strlen(".rules")) > PATH_MAX)
        return -1;

    snprintf(ruleFile, PATH_MAX, "%s%s%s.rules", 
                _ded.dataDumpDirectory, DIR_SEP, rulesFileName);
    ruleFile[PATH_MAX] = '\0';
    ruleFP = fopen(ruleFile, "w");
    if (ruleFP)
    {
        fprintf(ruleFP, "# Autogenerated skeleton rules file.  Do NOT edit by hand\n");
        for (i=0; rules[i] != NULL; i++)
        {
            DumpRule(ruleFP, rules[i]);
        }
        fclose(ruleFP);
    }
    else
    {
        _ded.errMsg("Unable to open the directory %s for writing \n", _ded.dataDumpDirectory);
        return -1;
    }

    return 0;
}
