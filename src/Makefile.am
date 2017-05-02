include common.mk

AM_CPPFLAGS += -I$(srcdir)/../gl/ -I$(builddir)/../gl/ \
	-I$(srcdir)/ -I$(builddir)/../ -I$(srcdir)/../ $(LIBOPTS_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) -I$(srcdir)/common -I$(builddir)/common \
	$(LIBPROTOBUF_C_CFLAGS) $(LIBLZ4_CFLAGS) \
	$(LIBREADLINE_CFLAGS) $(CODE_COVERAGE_CFLAGS) \
	$(LIBTALLOC_CFLAGS) $(LIBDBUS_CFLAGS) $(LIBOATH_CFLAGS) \
	$(LIBKRB5_CFLAGS) $(LIBTASN1_CFLAGS) $(RADCLI_CFLAGS)

BUILT_SOURCES = ocserv-args.c ocserv-args.h ipc.pb-c.c ipc.pb-c.h \
	http-heads.h kkdcp_asn1_tab.c ctl.pb-c.c ctl.pb-c.h

EXTRA_DIST = version.inc.in version.inc ocserv-args.c.in ocserv-args.h.in \
	ipc.proto ctl.proto http-heads.gperf common.mk ocserv-fw occtl/occtl-args.def
	

sbin_PROGRAMS = ocserv
bin_SCRIPTS = ocserv-fw

noinst_LIBRARIES = libcmd-ocserv.a libipc.a
libcmd_ocserv_a_SOURCES = ocserv-args.def ocserv-args.c ocserv-args.h

ocserv-args.stamp: $(srcdir)/ocserv-args.def $(builddir)/version.inc
	$(AUTOGEN) $<
	touch $@
ocserv-args.h: ocserv-args.stamp
ocserv-args.c: ocserv-args.stamp

# Authentication module sources
AUTH_SOURCES=auth/pam.c auth/pam.h auth/plain.c auth/plain.h auth/radius.c auth/radius.h \
	auth/common.c auth/common.h auth/gssapi.h auth/gssapi.c auth-unix.c \
	auth-unix.h

ACCT_SOURCES=acct/radius.c acct/radius.h acct/pam.c acct/pam.h

ocserv_SOURCES = main.c main-auth.c worker-vpn.c worker-auth.c tlslib.c \
	main-worker-cmd.c ip-lease.c ip-lease.h main-proc.c \
	vpn.h tlslib.h log.c tun.c tun.h config-kkdcp.c \
	config.c worker-resume.c worker.h sec-mod-resume.c main.h \
	worker-http-handlers.c html.c html.h worker-http.c \
	main-user.c worker-misc.c route-add.c route-add.h worker-privs.c \
	sec-mod.c sec-mod-db.c sec-mod-auth.c sec-mod-auth.h sec-mod.h \
	script-list.h $(AUTH_SOURCES) $(ACCT_SOURCES) \
	icmp-ping.c icmp-ping.h worker-kkdcp.c subconfig.c \
	sec-mod-sup-config.c sec-mod-sup-config.h \
	sup-config/file.c sup-config/file.h main-sec-mod-cmd.c \
	sup-config/radius.c sup-config/radius.h \
	worker-bandwidth.c worker-bandwidth.h main-ctl.h \
	vasprintf.c vasprintf.h worker-proxyproto.c config-ports.c \
	proc-search.c proc-search.h http-heads.h ip-util.c ip-util.h \
	main-ban.c main-ban.h common-config.h valid-hostname.c \
	str.c str.h gettime.h $(CCAN_SOURCES) $(HTTP_PARSER_SOURCES) \
	sec-mod-acct.h setproctitle.c setproctitle.h sec-mod-resume.h \
	sec-mod-cookies.c defs.h

if ENABLE_COMPRESSION
ocserv_SOURCES += lzs.c lzs.h
endif

if HAVE_GSSAPI
ocserv_SOURCES += kkdcp_asn1_tab.c kkdcp.asn
endif

if LOCAL_HTTP_PARSER
HTTP_PARSER_SOURCES = http-parser/http_parser.c http-parser/http_parser.h
endif

ocserv_LDADD = ../gl/libgnu.a $(NEEDED_LIBOPTS) libcmd-ocserv.a libccan.a libcommon.a
ocserv_LDADD += $(LIBGNUTLS_LIBS) $(PAM_LIBS) $(LIBUTIL) \
	$(LIBSECCOMP) $(LIBWRAP) $(LIBCRYPT) $(NEEDED_HTTP_PARSER_LIBS) \
	$(NEEDED_LIBPROTOBUF_LIBS) $(LIBSYSTEMD) $(LIBTALLOC_LIBS) \
	$(RADCLI_LIBS) $(LIBLZ4_LIBS) $(LIBKRB5_LIBS) \
	$(LIBTASN1_LIBS) $(LIBOATH_LIBS) $(LIBNETTLE_LIBS) \
	$(LIBEV_LIBS) libipc.a $(NEEDED_LIBPROTOBUF_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)


ocserv_SOURCES += main-ctl-unix.c

libipc_a_SOURCES=ctl.pb-c.c ctl.pb-c.h ipc.pb-c.h ipc.pb-c.c

ipc.pb-c.c: ipc.proto
	protoc-c --c_out=. --proto_path=$(srcdir) $<

ipc.pb-c.h: ipc.pb-c.c

ctl.pb-c.c: ctl.proto
	protoc-c --c_out=. --proto_path=$(srcdir) $<

ctl.pb-c.h: ctl.pb-c.c

http-heads.h: $(srcdir)/http-heads.gperf
	-gperf --global-table -t $^ > $@-tmp && mv $@-tmp $@

kkdcp_asn1_tab.c: $(srcdir)/kkdcp.asn
	-asn1Parser $^ $@

clean-local:
	rm -f *.stamp

# Occtl

bin_PROGRAMS = occtl/occtl

occtl_occtl_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/occtl $(LIBNL3_CFLAGS) $(GEOIP_CFLAGS)
occtl_occtl_SOURCES = occtl/occtl.c occtl/pager.c occtl/occtl.h occtl/time.c occtl/cache.c \
	occtl/ip-cache.c occtl/nl.c occtl/ctl.h occtl/print.c occtl/json.c occtl/json.h \
	occtl/hex.c occtl/hex.h occtl/unix.c occtl/geoip.c occtl/geoip.h
occtl_occtl_LDADD = ../gl/libgnu.a libcommon.a $(LIBREADLINE_LIBS) \
	$(LIBNL3_LIBS) $(NEEDED_LIBPROTOBUF_LIBS) $(LIBTALLOC_LIBS) libccan.a \
	libipc.a $(NEEDED_LIBPROTOBUF_LIBS) $(CODE_COVERAGE_LDFLAGS) \
	$(LIBNETTLE_LIBS) $(GEOIP_LIBS)

# Ocpasswd

EXTRA_DIST += ocpasswd/ocpasswd-args.def ocpasswd/ocpasswd-args.c.in ocpasswd/ocpasswd-args.h.in

BUILT_SOURCES += ocpasswd-args.c ocpasswd-args.h

bin_PROGRAMS += ocpasswd/ocpasswd

noinst_LIBRARIES += libcmd-ocpasswd.a
libcmd_ocpasswd_a_SOURCES = ocpasswd/ocpasswd-args.def ocpasswd-args.c ocpasswd-args.h

ocpasswd_ocpasswd_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/ocpasswd
ocpasswd_ocpasswd_SOURCES = ocpasswd/ocpasswd.c
ocpasswd_ocpasswd_LDADD = ../gl/libgnu.a $(NEEDED_LIBOPTS) libcmd-ocpasswd.a
ocpasswd_ocpasswd_LDADD += $(LIBGNUTLS_LIBS) $(LIBCRYPT) $(CODE_COVERAGE_LDFLAGS) \
	$(LIBNETTLE_LIBS)

ocpasswd-args.stamp: $(srcdir)/ocpasswd/ocpasswd-args.def $(builddir)/version.inc
	$(AUTOGEN) $<
	touch $@
ocpasswd-args.h: ocpasswd-args.stamp
ocpasswd-args.c: ocpasswd-args.stamp


# libcommon
# Files common to ocserv and occtl.
libcommon_a_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/common
libcommon_a_SOURCES=common/common.c common/common.h common/system.c common/system.h \
	common/cloexec.c common/cloexec.h common/base64-helper.c common/base64-helper.h
libcommon_a_LIBS = ../gl/libgnu.a $(NEEDED_LIBPROTOBUF_LIBS)
noinst_LIBRARIES += libcommon.a


# libccan
EXTRA_DIST += ccan/licenses/BSD-MIT ccan/licenses/CC0 ccan/licenses/LGPL-2.1

noinst_LIBRARIES += libccan.a
libccan_a_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/ccan
libccan_a_SOURCES = ccan/build_assert/build_assert.h ccan/check_type/check_type.h \
	ccan/container_of/container_of.h ccan/hash/hash.c ccan/hash/hash.h \
	ccan/htable/htable.c ccan/htable/htable.h ccan/htable/htable_type.h \
	ccan/list/list.c ccan/list/list.h

if LOCAL_TALLOC
libccan_a_SOURCES += ccan/talloc/talloc.c ccan/talloc/talloc.h ccan/compiler/compiler.h \
	ccan/typesafe_cb/typesafe_cb.h
endif

# libpcl
if PCL
ocserv_LDADD += $(PCL_LIBS)
else
ocserv_LDADD += libpcl.a
AM_CPPFLAGS += -I$(srcdir)/pcl/

noinst_LIBRARIES += libpcl.a

libpcl_a_CPPFLAGS = -I$(srcdir)/pcl -I$(builddir)/../
libpcl_a_SOURCES = pcl/pcl.c pcl/pcl_version.c pcl/pcl_private.c \
	pcl/pcl_config.h pcl/pcl.h pcl/pcl_private.h

endif


if LOCAL_PROTOBUF_C
noinst_LIBRARIES += libprotobuf.a

libprotobuf_a_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/protobuf/
libprotobuf_a_SOURCES = protobuf/protobuf-c/protobuf-c.c  protobuf/protobuf-c/protobuf-c.h
endif
