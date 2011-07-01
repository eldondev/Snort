## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include -I${srcdir}/../libs

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

lib_LTLIBRARIES = libsf_ssl_preproc.la

libsf_ssl_preproc_la_LDFLAGS = -shared -export-dynamic -module @XCCFLAGS@
if SO_WITH_STATIC_LIB
libsf_ssl_preproc_la_LIBADD = ../libsf_dynamic_preproc.la
else
nodist_libsf_ssl_preproc_la_SOURCES = \
../include/sf_dynamic_preproc_lib.c \
../include/sfPolicyUserData.c
endif

libsf_ssl_preproc_la_SOURCES = \
spp_ssl.c \
spp_ssl.h \
${top_srcdir}/src/dynamic-preprocessors/libs/ssl.c \
${top_srcdir}/src/dynamic-preprocessors/libs/ssl.h \
${top_srcdir}/src/dynamic-preprocessors/libs/sfparser.c \
${top_srcdir}/src/dynamic-preprocessors/libs/sfcommon.h

EXTRA_DIST = \
sf_ssl.dsp

all-local:
	$(MAKE) DESTDIR=`pwd`/../build install-libLTLIBRARIES

