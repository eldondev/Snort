## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include -I${top_srcdir}/src/dynamic-preprocessors/libs

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

lib_LTLIBRARIES = libsf_smtp_preproc.la

libsf_smtp_preproc_la_LDFLAGS = -module

BUILT_SOURCES = \
sf_dynamic_preproc_lib.c  \
sfPolicyUserData.c 

nodist_libsf_smtp_preproc_la_SOURCES = \
sf_dynamic_preproc_lib.c  \
sfPolicyUserData.c 

libsf_smtp_preproc_la_SOURCES = \
sf_preproc_info.h \
smtp_config.c \
smtp_config.h \
smtp_log.c \
smtp_log.h \
smtp_normalize.c \
smtp_normalize.h \
smtp_util.c \
smtp_util.h \
smtp_xlink2state.c \
smtp_xlink2state.h \
snort_smtp.c \
snort_smtp.h \
spp_smtp.c \
spp_smtp.h \
${top_srcdir}/src/dynamic-preprocessors/libs/ssl.c \
${top_srcdir}/src/dynamic-preprocessors/libs/ssl.h

EXTRA_DIST = \
sf_smtp.dsp

sf_dynamic_preproc_lib.c: ../include/sf_dynamic_preproc_lib.c
	cp $? $@

sfPolicyUserData.c: ../include/sfPolicyUserData.c
	cp $? $@

all-local:
	$(MAKE) DESTDIR=`pwd`/../build install-libLTLIBRARIES

clean-local:
	rm -f sf_dynamic_preproc_lib.c sfPolicyUserData.c 
