## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include -I${srcdir}/../libs

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

lib_LTLIBRARIES = libsf_dns_preproc.la

libsf_dns_preproc_la_LDFLAGS = -shared -export-dynamic -module @XCCFLAGS@
if SO_WITH_STATIC_LIB
libsf_dns_preproc_la_LIBADD = ../libsf_dynamic_preproc.la
else
nodist_libsf_dns_preproc_la_SOURCES = \
../include/sf_dynamic_preproc_lib.c \
../include/sfPolicyUserData.c
endif

libsf_dns_preproc_la_SOURCES = \
spp_dns.c \
spp_dns.h

EXTRA_DIST = \
sf_dns.dsp

all-local:
	$(MAKE) DESTDIR=`pwd`/../build install-libLTLIBRARIES

