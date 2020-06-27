include common.mk

AM_CPPFLAGS += -I$(srcdir)/../gl/ -I$(builddir)/../gl/ \
	-I$(srcdir)/ -I$(builddir)/../ -I$(srcdir)/../ \
	$(LIBGNUTLS_CFLAGS) -I$(srcdir)/common -I$(builddir)/common \
	$(LIBPROTOBUF_C_CFLAGS) $(LIBLZ4_CFLAGS) \
	$(LIBREADLINE_CFLAGS) $(CODE_COVERAGE_CFLAGS) \
	$(LIBTALLOC_CFLAGS) $(LIBDBUS_CFLAGS) $(LIBOATH_CFLAGS) \
	$(LIBKRB5_CFLAGS) $(LIBTASN1_CFLAGS) $(RADCLI_CFLAGS) $(SRC_CFLAGS)

if ENABLE_OIDC_AUTH
AM_CPPFLAGS += $(LIBCURL_CFLAGS) $(CJOSE_CFLAGS) $(JANSSON_CFLAGS)
endif

BUILT_SOURCES = ipc.pb-c.c ipc.pb-c.h \
	http-heads.h kkdcp_asn1_tab.c ctl.pb-c.c ctl.pb-c.h

EXTRA_DIST = version.inc.in version.inc \
	ipc.proto ctl.proto http-heads.gperf common.mk ocserv-fw


sbin_PROGRAMS = ocserv ocserv-worker
bin_SCRIPTS = ocserv-fw

ocserv_SOURCES = $(CORE_SOURCES) $(AUTH_SOURCES) $(ACCT_SOURCES) \
	main.c main-auth.c main-ban.c main-ban.h main-ctl-unix.c main-proc.c \
	main-sec-mod-cmd.c main-user.c main-worker-cmd.c proc-search.c \
	proc-search.h route-add.c route-add.h sec-mod.c sec-mod.h sec-mod-acct.h \
	sec-mod-auth.c sec-mod-auth.h sec-mod-cookies.c sec-mod-db.c \
	sec-mod-resume.c sec-mod-resume.h sec-mod-sup-config.c sec-mod-sup-config.h \
	common/sockdiag.h common/sockdiag.c namespace.c

ocserv_LDADD = $(CORE_LDADD)

ocserv_worker_CPPFLAGS = $(AM_CPPFLAGS) -DOCSERV_WORKER_PROCESS
ocserv_worker_SOURCES = $(CORE_SOURCES) \
	html.c html.h http-heads.h worker.c worker.h worker-auth.c \
	worker-bandwidth.c worker-bandwidth.h worker-http.c worker-http-handlers.c \
	worker-kkdcp.c worker-misc.c worker-privs.c worker-proxyproto.c \
	worker-resume.c worker-vpn.c

ocserv_worker_LDADD = $(CORE_LDADD)

noinst_LIBRARIES = libipc.a

# Authentication module sources
AUTH_SOURCES=auth/common.c auth/common.h auth/gssapi.c auth/gssapi.h \
	auth/pam.c auth/pam.h auth/plain.c auth/plain.h auth/radius.c \
	auth/radius.h auth-unix.c auth-unix.h

if ENABLE_OIDC_AUTH
AUTH_SOURCES += auth/openidconnect.c auth/openidconnect.h
endif

ACCT_SOURCES=acct/radius.c acct/radius.h acct/pam.c acct/pam.h

CORE_SOURCES = $(CCAN_SOURCES) $(HTTP_PARSER_SOURCES) \
	common/hmac.c common/hmac.h common/snapshot.c common/snapshot.h \
	common-config.h config.c config-kkdcp.c config-ports.c defs.h gettime.h \
	icmp-ping.c icmp-ping.h inih/ini.c inih/ini.h ip-lease.c ip-lease.h \
	ip-util.c ip-util.h isolate.h isolate.c log.c main.h main-ctl.h \
	script-list.h setproctitle.c setproctitle.h str.c str.h subconfig.c \
	sup-config/file.c sup-config/file.h sup-config/radius.c \
	sup-config/radius.h tlslib.c tlslib.h tun.c tun.h valid-hostname.c \
	vasprintf.c vasprintf.h vhost.h vpn.h namespace.h

if ENABLE_LATENCY_SUPPORT
ocserv_worker_SOURCES += worker-latency.c worker-latency.h
endif

if ENABLE_COMPRESSION
CORE_SOURCES += lzs.c lzs.h
endif

if HAVE_GSSAPI
CORE_SOURCES += kkdcp_asn1_tab.c kkdcp.asn
endif

if LOCAL_HTTP_PARSER
HTTP_PARSER_SOURCES = http-parser/http_parser.c http-parser/http_parser.h
endif

CORE_LDADD = ../gl/libgnu.a libccan.a libcommon.a
CORE_LDADD += $(LIBGNUTLS_LIBS) $(PAM_LIBS) $(LIBUTIL) \
	$(LIBSECCOMP) $(LIBWRAP) $(LIBCRYPT) $(NEEDED_HTTP_PARSER_LIBS) \
	$(NEEDED_LIBPROTOBUF_LIBS) $(LIBSYSTEMD) $(LIBTALLOC_LIBS) \
	$(RADCLI_LIBS) $(LIBLZ4_LIBS) $(LIBKRB5_LIBS) \
	$(LIBTASN1_LIBS) $(LIBOATH_LIBS) $(LIBNETTLE_LIBS) \
	$(LIBEV_LIBS) libipc.a $(NEEDED_LIBPROTOBUF_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) 
	
if ENABLE_LATENCY_SUPPORT
ocserv_worker_LDADD += $(LIBM)
endif

if ENABLE_OIDC_AUTH
CORE_LDADD += $(LIBCURL_LIBS) $(CJOSE_LIBS) $(JANSSON_LIBS)
endif

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

occtl_occtl_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/occtl $(LIBNL3_CFLAGS) $(GEOIP_CFLAGS) $(MAXMIND_CFLAGS)
occtl_occtl_SOURCES = occtl/occtl.c occtl/pager.c occtl/occtl.h occtl/time.c occtl/cache.c \
	occtl/ip-cache.c occtl/nl.c occtl/ctl.h occtl/print.c occtl/json.c occtl/json.h \
	occtl/hex.c occtl/hex.h occtl/unix.c occtl/geoip.h \
	occtl/session-cache.c

if HAVE_MAXMIND
occtl_occtl_SOURCES += occtl/maxmind.c
else
occtl_occtl_SOURCES += occtl/geoip.c
endif

occtl_occtl_LDADD = ../gl/libgnu.a libcommon.a $(LIBREADLINE_LIBS) \
	$(LIBNL3_LIBS) $(NEEDED_LIBPROTOBUF_LIBS) $(LIBTALLOC_LIBS) libccan.a \
	libipc.a $(NEEDED_LIBPROTOBUF_LIBS) $(CODE_COVERAGE_LDFLAGS) \
	$(LIBNETTLE_LIBS) $(MAXMIND_LIBS) $(GEOIP_LIBS)

# Ocpasswd

bin_PROGRAMS += ocpasswd/ocpasswd

ocpasswd_ocpasswd_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/ocpasswd
ocpasswd_ocpasswd_SOURCES = ocpasswd/ocpasswd.c
ocpasswd_ocpasswd_LDADD = ../gl/libgnu.a
ocpasswd_ocpasswd_LDADD += $(LIBGNUTLS_LIBS) $(LIBCRYPT) $(CODE_COVERAGE_LDFLAGS) \
	$(LIBNETTLE_LIBS)


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
CORE_LDADD += $(PCL_LIBS)
else
CORE_LDADD += libpcl.a
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

AM_CPPFLAGS += -I$(srcdir)/protobuf/
endif
