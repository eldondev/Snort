## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

lib_LTLIBRARIES = libsf_dcerpc_preproc.la

libsf_dcerpc_preproc_la_LDFLAGS = -module

BUILT_SOURCES = \
sf_dynamic_preproc_lib.c  \
sfPolicyUserData.c 

nodist_libsf_dcerpc_preproc_la_SOURCES = \
sf_dynamic_preproc_lib.c  \
sfPolicyUserData.c 

libsf_dcerpc_preproc_la_SOURCES = \
dcerpc.c \
dcerpc.h \
dcerpc_util.c \
dcerpc_util.h \
dcerpc_config.c \
sf_preproc_info.h \
smb_andx_decode.c \
smb_andx_decode.h \
smb_andx_structs.h \
smb_file_decode.c \
smb_file_decode.h \
smb_file_structs.h \
smb_structs.h \
snort_dcerpc.c \
snort_dcerpc.h \
spp_dcerpc.c \
spp_dcerpc.h \
sf_preproc_info.h

EXTRA_DIST = \
sf_dcerpc.dsp

sf_dynamic_preproc_lib.c: ../include/sf_dynamic_preproc_lib.c
	cp $? $@

sfPolicyUserData.c: ../include/sfPolicyUserData.c
	cp $? $@

all-local:
	$(MAKE) DESTDIR=`pwd`/../build install-libLTLIBRARIES

clean-local:
	rm -f sf_dynamic_preproc_lib.c sfPolicyUserData.c 
