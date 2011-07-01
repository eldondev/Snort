/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* $Id$ */

#ifndef __PROTOTYPES_H__
#define __PROTOTYPES_H__

#if defined(NEED_DECL_PRINTF)
int printf (const char *_fmt, ... );
#endif

#if defined(NEED_DECL_FPRINTF)
int fprintf (FILE *stream, const char *__fmt, ... );
#endif

#if defined(NEED_DECL_VSNPRINTF)
int vsnprintf (char *str, size_t sz, const char *__fmt, va_list ap);
#endif

#if defined(NEED_DECL_SNPRINTF)
int snprintf (char *, size_t , const char *, ...);
#endif

#if defined(NEED_DECL_SYSLOG)
void syslog (int __pri, const char *__fmt, ...);
#endif

#if defined(NEED_DECL_PUTS)
int puts(const char *s);
#endif

#if defined(NEED_DECL_FPUTS)
int fputs(const char *s, FILE *stream);
#endif

#if defined(NEED_DECL_FPUTC)
int fputc(int c, FILE *stream);
#endif

#if defined(NEED_DECL_FOPEN)
FILE *fopen(const char *path, const char *mode);
#endif

#if defined(NEED_DECL_FCLOSE)
int *fclose(FILE *stream);
#endif

#if defined(NEED_DECL_FWRITE)
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
#endif

#if defined(NEED_DECL_FFLUSH)
int fflush(FILE *stream);
#endif

#if defined(NEED_DECL_GETOPT)
int getopt(int argc, char * const argv[], const char *optstring);
#endif


#if defined(NEED_DECL_BZERO)
void bzero(void *s, int n);
#endif

#if defined(NEED_DECL_BCOPY)
void bcopy(const void *src, void *dst, int n);
#endif

#if defined(NEED_DECL_MEMSET)
void memset(void *s, int c,size_t n);
#endif

#if defined(NEED_DECL_STRTOL)
long int strtol(const char *nptr, char **endptr, int base);
#endif

#if defined(NEED_DECL_STRTOUL)
unsigned long int strtoul(const char *nptr, char **endptr, int base);
#endif

#if defined(NEED_DECL_STRCASECMP)
int strcasecmp(const char *s1, const char *s2);
#endif

#if defined(NEED_DECL_STRNCASECMP)
int strncasecmp(const char *s1, const char *s2, size_t n);
#endif


#if defined(NEED_DECL_STRERROR)
char *strerror(int errnum);
#endif

#if defined(NEED_DECL_PERROR)
void perror(const char *s);
#endif

#if defined(NEED_DECL_SOCKET)
int socket(int domain, int type, int protocol);
#endif

#if defined(NEED_DECL_SENDTO)
int sendto(int s, const void *msg, int len, unsigned int flags,
	       	const struct sockaddr *to, int tolen);
#endif

#endif  /* __PROTOTYPES_H__ */
