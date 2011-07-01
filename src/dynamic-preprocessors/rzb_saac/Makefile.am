## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include -I${srcdir}/../libs

pkglibdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

pkglib_LTLIBRARIES = sf_rzb_saac_preproc.la

sf_rzb_saac_preproc_la_LDFLAGS = -shared -export-dynamic -module @XCCFLAGS@
if SO_WITH_STATIC_LIB
PREPROCLIB=../libsf_dynamic_preproc.la
else
nodist_sf_rzb_saac_preproc_la_SOURCES = \
../include/sf_dynamic_preproc_lib.c \
../include/sf_ip.c \
../include/sfPolicyUserData.c
endif
sf_rzb_saac_preproc_la_LIBADD = ${PREPROCLIB} @RAZORBACK_LIBS@
sf_rzb_saac_preproc_la_CFLAGS = @RAZORBACK_CFLAGS@ -Werror

sf_rzb_saac_preproc_la_SOURCES = \
rzb_debug.c \
rzb_debug.h \
rzb_http-client.c \
rzb_http-client.h \
rzb_http.h \
rzb_http-fileinfo.c \
rzb_http-fileinfo.h \
rzb_http-server.c \
rzb_http-server.h \
rzb_smtp-collector.c \
rzb_smtp-collector.h \
spp_rzb-saac.c

all-local:
	$(MAKE) DESTDIR=`pwd`/../build install-pkglibLTLIBRARIES

