/* $Id$ */
#ifndef __INLINE_H__
#define __INLINE_H__

#ifdef GIDS

#ifndef IPFW
#include <libipq.h>
#include <linux/netfilter.h>
#else
#include <sys/types.h>
#include <sys/time.h>
#include <sys/unistd.h>
#include <errno.h>
#endif /* IPFW */

#include "snort.h"

typedef struct _inline_vals
{
    int drop;
    int reject;
    int replace;
    int proto;
} IV;

#ifndef IPFW
struct ipq_handle *ipqh;
#endif
IV iv;

int InitInline(void);
void InitInlinePostConfig(void);
#ifndef IPFW
void IpqLoop(void);
#else
void IpfwLoop(void);
#endif /* IPFW */
int InlineReject(Packet *); /* call to reject current packet */
int InlineAccept(void);
int InlineReplace(void);

#endif

int InlineModeSetPrivsAllowed(void);
int InlineDrop(Packet *p);  /* call to drop current packet */
int InlineWasPacketDropped(void);

#endif /* __INLINE_H__ */
