## $Id: Makefile.am,v 1.25 2011/06/08 00:33:11 jjordan Exp $
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I${top_builddir}/src/dynamic-preprocessors/include -I${top_srcdir}/src/dynamic-preprocessors/libs

if HAVE_DYNAMIC_PLUGINS

if SO_WITH_STATIC_LIB

preproclibdir=$(pkglibdir)/dynamic_preproc

preproclib_LTLIBRARIES = libsf_dynamic_preproc.la
libsf_dynamic_preproc_la_CFLAGS = -fPIC -DPIC
libsf_dynamic_preproc_la_LDFLAGS = -static

nodist_libsf_dynamic_preproc_la_SOURCES = \
include/sf_dynamic_preproc_lib.c \
include/sf_ip.c \
include/sfrt.c \
include/sfrt_dir.c \
include/mempool.c \
include/sf_sdlist.c \
include/sfPolicyUserData.c \
include/util_unfold.c \
include/sf_base64decode.c \
include/sf_email_attach_decode.c

libsf_dynamic_preproc_la_SOURCES = \
libs/ssl.c \
libs/sfparser.c

preprocdir=$(pkgincludedir)/dynamic_preproc

nodist_preproc_HEADERS = \
libs/ssl.h \
libs/sfcommon.h \
libs/sf_preproc_info.h \
include/sf_snort_packet.h \
include/sf_protocols.h \
include/sf_snort_plugin_api.h \
include/sf_decompression.h \
include/sfPolicyUserData.h \
include/snort_debug.h \
include/snort_bounds.h \
include/cpuclock.h \
include/profiler.h \
include/bitop.h \
include/mempool.h \
include/sf_sdlist_types.h \
include/sf_ip.h \
include/sf_dynamic_common.h \
include/sf_dynamic_engine.h \
include/sf_dynamic_define.h \
include/sf_dynamic_meta.h \
include/sf_dynamic_preprocessor.h \
include/sf_dynamic_preproc_lib.h \
include/ipv6_port.h \
include/sfPolicy.h \
include/sfrt.h \
include/sfrt_dir.h \
include/sfrt_trie.h \
include/obfuscation.h \
include/stream_api.h \
include/str_search.h \
include/preprocids.h

all-local:
	$(MAKE) DESTDIR=`pwd`/build install-preproclibLTLIBRARIES

endif

endif

BUILT_SOURCES = \
	include/snort_bounds.h \
	include/snort_debug.h \
	include/preprocids.h \
	include/profiler.h \
	include/cpuclock.h \
	include/sf_dynamic_common.h \
	include/sf_dynamic_engine.h \
	include/sf_dynamic_define.h \
	include/sf_dynamic_meta.h \
	include/sf_dynamic_preprocessor.h \
	include/sf_dynamic_preproc_lib.c \
	include/sf_dynamic_preproc_lib.h \
	include/sfghash.h \
	include/sfhashfcn.h \
	include/bitop.h \
	include/sf_ip.h \
	include/sf_ip.c \
	include/sf_ipvar.h \
	include/sf_vartable.h \
	include/ipv6_port.h \
	include/sfsnort_dynamic_detection_lib.c \
	include/sfsnort_dynamic_detection_lib.h \
	include/sf_snort_packet.h \
	include/sf_protocols.h \
	include/sf_snort_plugin_api.h \
        include/sf_decompression.h \
	include/pcap_pkthdr32.h \
	include/stream_api.h \
	include/str_search.h \
	include/sf_types.h \
	include/sfrt.h \
	include/sfrt.c \
	include/sfrt_dir.h \
	include/sfrt_dir.c \
	include/sfrt_trie.h \
	include/mempool.h \
	include/mempool.c \
	include/sf_sdlist.h \
	include/sf_sdlist_types.h \
	include/sf_sdlist.c \
	include/sfPolicyUserData.c \
	include/sfPolicyUserData.h \
	include/sfPolicy.h \
	include/util_unfold.h \
	include/util_unfold.c \
	include/sf_base64decode.h \
	include/sf_base64decode.c \
	include/sf_email_attach_decode.h \
	include/sf_email_attach_decode.c \
	include/treenodes.h \
	include/signature.h \
	include/plugin_enum.h \
	include/obfuscation.h \
	include/rule_option_types.h \
	include/event.h \
	include/Unified2_common.h

sed_ipv6_headers = \
	sed -e "s/->iph->ip_src/->ip4_header->source/" \
	    -e "s/->iph->ip_dst/->ip4_header->destination/" \
	    -e "s/->iph->/->ip4_header->/" \
	    -e "s/->iph$$/->ip4_header/" \
	    -e "s/orig_iph/orig_ipv4h/" \
	    -e "s/ip_verhl/version_headerlength/" \
	    -e "s/ip_tos/type_service/" \
	    -e "s/ip_len/data_length/" \
	    -e "s/ip_id/identifier/" \
	    -e "s/ip_off/offset/" \
	    -e "s/ip_ttl/time_to_live/" \
	    -e "s/ip_proto/proto/" \
	    -e "s/ip_csum/checksum/" \
	    $$dst_header.new > $$dst_header

massage_ipv6_headers = \
	mkdir -p include; \
	mkdir -p build; \
	if test -f $$dst_header; then \
		x=`diff $$src_header $$dst_header.new >> /dev/null`; \
		if test "$$x" != "0"; then \
			echo "Updating " $$dst_header; \
			cp $$src_header $$dst_header.new; \
			$(sed_ipv6_headers); \
		fi \
	else \
		echo "Updating " $$dst_header; \
		cp $$src_header $$dst_header.new; \
		$(sed_ipv6_headers); \
	fi

sed_headers = \
	sed -e "s/Packet /SFSnortPacket /" \
	    -e "s/SnortPktHdr /SFSnortPktHdr /" \
	    -e "s/decode\.h/sf_snort_packet.h/" \
	    -e "/sfportobject\.h/d" \
	    -e "s/PortObject \*/void */g" \
	    $$dst_header.new > $$dst_header

massage_headers = \
	mkdir -p include; \
	mkdir -p build; \
	if test -f $$dst_header; then \
		x=`diff $$src_header $$dst_header.new.new >> /dev/null`; \
		if test "$$x" != "0"; then \
			echo "Updating " $$dst_header; \
			cp $$src_header $$dst_header.new; \
			$(sed_headers); \
		fi \
	else \
		echo "Updating " $$dst_header; \
		cp $$src_header $$dst_header.new; \
		$(sed_headers); \
	fi

sed_debug_header = \
	sed -e "s/DebugMessageFile = /*_dpd.debugMsgFile = /" \
	    -e "s/DebugMessageLine = /*_dpd.debugMsgLine = /" \
	    -e "s/; DebugMessageFunc$$/; _dpd.debugMsg/" \
	    -e "s/; DebugWideMessageFunc$$/; _dpd.debugWideMsg/" \
	    $$dst_header.new > $$dst_header

copy_debug_header = \
	mkdir -p include; \
	mkdir -p build; \
	if test -f $$dst_header; then \
		x=`diff $$src_header $$dst_header.new.new >> /dev/null`; \
		if test "$$x" != "0"; then \
			echo "Updating " $$dst_header; \
			cp $$src_header $$dst_header.new; \
			$(sed_debug_header); \
		fi \
	else \
		echo "Updating " $$dst_header; \
		cp $$src_header $$dst_header.new; \
		$(sed_debug_header); \
	fi

copy_error_message = \
        if test -f $$dst_header; then \
	   sed -e "s/ErrorMessage/_dpd.errMsg/" \
	       -e "s/LogMessage /_dpd.logMsg /" \
	       -e "/util.h/d" \
                        $$dst_header > $$dst_header.new; \
                mv $$dst_header.new $$dst_header; \
        fi



replace_policy_globals = \
	if test -f $$dst_header; then \
		sed -e "/SharedObjectAddStarts/d" \
		    -e "/SharedObjectAddEnds/d" \
            -e "/SharedObjectDeleteBegins/,/SharedObjectDeleteEnds/d" \
		    -e "s/getDefaultPolicy()/_dpd.getDefaultPolicy()/" \
		    -e "s/SnortStrnStr/_dpd.SnortStrnStr/" \
		        $$dst_header > $$dst_header.new; \
		mv $$dst_header.new $$dst_header; \
	fi

copy_headers = \
	mkdir -p include; \
	mkdir -p build; \
	if test -f $$dst_header; then \
		x=`diff $$src_header $$dst_header.new.new >> /dev/null`; \
		if test "$$x" != "0"; then \
			echo "Updating " $$dst_header; \
			cp $$src_header $$dst_header; \
		fi \
	else \
		echo "Updating " $$dst_header; \
		cp $$src_header $$dst_header; \
	fi

sed_treenode_header = \
	sed -f $(srcdir)/treenodes.sed $$dst_header.new > $$dst_header

copy_treenode_header = \
	mkdir -p include; \
	mkdir -p build; \
	if test -f $$dst_header; then \
		x=`diff $$src_header $$dst_header.new.new >> /dev/null`; \
		if test "$$x" != "0"; then \
			echo "Updating " $$dst_header; \
			cp $$src_header $$dst_header.new; \
			$(sed_treenode_header); \
		fi \
	else \
		echo "Updating " $$dst_header; \
		cp $$src_header $$dst_header.new; \
		$(sed_treenode_header); \
	fi

# From main src tree
include/snort_debug.h: $(srcdir)/../snort_debug.h
	@src_header=$?; dst_header=$@; $(copy_debug_header)

include/preprocids.h: $(srcdir)/../preprocids.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/profiler.h: $(srcdir)/../profiler.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/cpuclock.h: $(srcdir)/../cpuclock.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/pcap_pkthdr32.h: $(srcdir)/../pcap_pkthdr32.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/snort_bounds.h: $(srcdir)/../snort_bounds.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/ipv6_port.h: $(srcdir)/../ipv6_port.h
	@src_header=$?; dst_header=$@; $(massage_ipv6_headers)

include/sf_types.h: $(srcdir)/../sf_types.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/obfuscation.h: $(srcdir)/../obfuscation.h
	@src_header=$?; dst_header=$@; $(massage_headers)

include/rule_option_types.h: $(srcdir)/../rule_option_types.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/event.h: $(srcdir)/../event.h
	@src_header=$?; dst_header=$@; $(copy_headers)

# From dynamic-plugins
include/sf_dynamic_common.h: $(srcdir)/../dynamic-plugins/sf_dynamic_common.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_dynamic_engine.h: $(srcdir)/../dynamic-plugins/sf_dynamic_engine.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_dynamic_define.h: $(srcdir)/../dynamic-plugins/sf_dynamic_define.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_dynamic_meta.h: $(srcdir)/../dynamic-plugins/sf_dynamic_meta.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_dynamic_preprocessor.h: $(srcdir)/../dynamic-plugins/sf_dynamic_preprocessor.h
	@src_header=$?; dst_header=$@; $(massage_headers)

# From dynamic-plugins/sf_preproc_example
include/sf_dynamic_preproc_lib.c: $(srcdir)/../dynamic-plugins/sf_preproc_example/sf_dynamic_preproc_lib.c
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_dynamic_preproc_lib.h: $(srcdir)/../dynamic-plugins/sf_preproc_example/sf_dynamic_preproc_lib.h
	@src_header=$?; dst_header=$@; $(copy_headers)

# From Utils
include/sfghash.h: $(srcdir)/../sfutil/sfghash.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sfhashfcn.h: $(srcdir)/../sfutil/sfhashfcn.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/bitop.h: $(srcdir)/../sfutil/bitop.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_ip.h: $(srcdir)/../sfutil/sf_ip.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_ip.c: $(srcdir)/../sfutil/sf_ip.c
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_ipvar.h: $(srcdir)/../sfutil/sf_ipvar.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_vartable.h: $(srcdir)/../sfutil/sf_vartable.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sfrt.h: $(srcdir)/../sfutil/sfrt.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sfrt.c: $(srcdir)/../sfutil/sfrt.c
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sfrt_dir.h: $(srcdir)/../sfutil/sfrt_dir.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sfrt_dir.c: $(srcdir)/../sfutil/sfrt_dir.c
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sfrt_trie.h: $(srcdir)/../sfutil/sfrt_trie.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/mempool.h: $(srcdir)/../mempool.h
	@src_header=$?; dst_header=$@; $(copy_headers); $(copy_error_message); $(replace_policy_globals)

include/mempool.c: $(srcdir)/../mempool.c
	@src_header=$?; dst_header=$@; $(copy_headers); $(copy_error_message); $(replace_policy_globals)

include/sf_sdlist.h: $(srcdir)/../sf_sdlist.h
	@src_header=$?; dst_header=$@; $(copy_headers); $(copy_error_message); $(replace_policy_globals)

include/sf_sdlist_types.h: $(srcdir)/../sf_sdlist_types.h
	@src_header=$?; dst_header=$@; $(copy_headers); $(copy_error_message); $(replace_policy_globals)

include/sf_sdlist.c: $(srcdir)/../sf_sdlist.c
	@src_header=$?; dst_header=$@; $(copy_headers); $(copy_error_message); $(replace_policy_globals)

include/sfPolicyUserData.c: $(srcdir)/../sfutil/sfPolicyUserData.c
	@src_header=$?; dst_header=$@; $(copy_headers); $(replace_policy_globals)

include/sfPolicyUserData.h: $(srcdir)/../sfutil/sfPolicyUserData.h
	@src_header=$?; dst_header=$@; $(copy_headers); $(replace_policy_globals)

include/sfPolicy.h: $(srcdir)/../sfutil/sfPolicy.h
	@src_header=$?; dst_header=$@; $(copy_headers); $(replace_policy_globals)

include/util_unfold.h: $(srcdir)/../sfutil/util_unfold.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/util_unfold.c: $(srcdir)/../sfutil/util_unfold.c
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_base64decode.h: $(srcdir)/../sfutil/sf_base64decode.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_base64decode.c: $(srcdir)/../sfutil/sf_base64decode.c
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_email_attach_decode.h: $(srcdir)/../sfutil/sf_email_attach_decode.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_email_attach_decode.c: $(srcdir)/../sfutil/sf_email_attach_decode.c
	@src_header=$?; dst_header=$@; $(copy_headers); $(copy_error_message); $(replace_policy_globals)

include/Unified2_common.h: $(srcdir)/../sfutil/Unified2_common.h
	@src_header=$?; dst_header=$@; $(copy_headers)

# From dynamic-plugins/sf_engine/examples
include/sfsnort_dynamic_detection_lib.c: $(srcdir)/../dynamic-plugins/sf_engine/examples/sfsnort_dynamic_detection_lib.c
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sfsnort_dynamic_detection_lib.h: $(srcdir)/../dynamic-plugins/sf_engine/examples/sfsnort_dynamic_detection_lib.h
	@src_header=$?; dst_header=$@; $(copy_headers)

# From dynamic-plugins/sf_engine
include/sf_snort_packet.h: $(srcdir)/../dynamic-plugins/sf_engine/sf_snort_packet.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_protocols.h: $(srcdir)/../sf_protocols.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_snort_plugin_api.h: $(srcdir)/../dynamic-plugins/sf_engine/sf_snort_plugin_api.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_decompression.h: $(srcdir)/../dynamic-plugins/sf_engine/sf_decompression.h
	@src_header=$?; dst_header=$@; $(copy_headers)

# Stream API/String Searching, massage it to use SFSnortPacket
include/stream_api.h: $(srcdir)/../preprocessors/stream_api.h
	@src_header=$?; dst_header=$@; $(massage_headers)

include/str_search.h: $(srcdir)/../preprocessors/str_search.h
	@src_header=$?; dst_header=$@; $(massage_headers)

include/treenodes.h: $(srcdir)/../treenodes.h
	@src_header=$?; dst_header=$@; $(copy_treenode_header)

include/signature.h: $(srcdir)/../signature.h
	@src_header=$?; dst_header=$@; $(copy_treenode_header)

include/plugin_enum.h: $(srcdir)/../plugin_enum.h
	@src_header=$?; dst_header=$@; $(copy_headers)

if WANT_SF_SAAC
RZB_SAAC_DIR=rzb_saac
endif

if HAVE_DYNAMIC_PLUGINS
SUBDIRS = . libs ftptelnet pop imap smtp ssh dns ssl dcerpc2 sdf sip $(RZB_SAAC_DIR)
endif

clean-local:
	rm -rf include build

EXTRA_DIST = \
dynamic_preprocessors.dsp \
sf_dynamic_initialize/sf_dynamic_initialize.dsp \
treenodes.sed

if HAVE_DYNAMIC_PLUGINS
srcinstdir = $(exec_prefix)/src/snort_dynamicsrc

exported_files = \
include/sf_dynamic_common.h \
include/sf_dynamic_define.h \
include/sf_dynamic_engine.h \
include/sf_dynamic_meta.h \
include/sf_dynamic_preprocessor.h \
include/sf_dynamic_preproc_lib.h \
include/sf_dynamic_preproc_lib.c \
include/sf_ip.h \
include/sf_snort_packet.h \
include/sf_protocols.h \
include/sf_snort_plugin_api.h \
include/sf_decompression.h \
include/sf_types.h \
include/sfsnort_dynamic_detection_lib.h \
include/sfsnort_dynamic_detection_lib.c \
include/pcap_pkthdr32.h \
include/str_search.h \
include/stream_api.h \
include/snort_debug.h \
include/profiler.h \
include/sfghash.h \
include/sfhashfcn.h \
include/bitop.h \
include/preprocids.h \
include/sfPolicyUserData.h \
include/util_unfold.h \
include/util_unfold.c \
include/sf_base64decode.h \
include/sf_base64decode.c \
include/sf_email_attach_decode.h \
include/sf_email_attach_decode.c \
include/treenodes.h \
include/signature.h \
include/plugin_enum.h \
include/sfPolicyUserData.c \
include/obfuscation.h \
include/rule_option_types.h \
include/event.h \
include/Unified2_common.h

install-data-local:
	@for f in $(exported_files); do \
## Compute the filename only
		truefile=`echo $$f | sed -e "s/.*\///"`; \
## Make the install directory.
		$(mkinstalldirs) $(DESTDIR)$(srcinstdir); \
## Find the header file -- in our case it might be in srcdir or
## it might be in the build directory.  "p" is the variable that
## names the actual file we will install.
		if test -f $(srcdir)/$$f; then p=$(srcdir)/$$f; else p=$$f; fi; \
## Actually install the file.
		$(INSTALL_DATA) $$p $(DESTDIR)$(srcinstdir)/$$truefile; \
	done

uninstall-local:
	@for f in $(exported_files); do \
## Compute the filename only
		truefile=`echo $$f | sed -e "s/.*\///"`; \
## Make the install directory.
		$(mkinstalldirs) $(DESTDIR)$(srcinstdir); \
## Actually install the file.
		rm -f $(DESTDIR)$(srcinstdir)/$$truefile; \
	done
endif
