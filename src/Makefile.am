SUBDIRS = ccan common

AM_CPPFLAGS = -I$(srcdir)/../gl/ -I$(builddir)/../gl/ \
	-I$(srcdir)/ -I$(builddir)/../ -I$(srcdir)/../ $(LIBOPTS_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) -I$(srcdir)/common -I$(builddir)/common \
	$(LIBPROTOBUF_C_CFLAGS) $(LIBLZ4_CFLAGS) \
	$(LIBREADLINE_CFLAGS) \
	$(LIBTALLOC_CFLAGS) $(LIBDBUS_CFLAGS) $(LIBOATH_CFLAGS) \
	$(LIBKRB5_CFLAGS) $(LIBTASN1_CFLAGS) $(RADCLI_CFLAGS)

BUILT_SOURCES = ocserv-args.c ocserv-args.h ipc.pb-c.c ipc.pb-c.h \
	http-heads.h kkdcp_asn1_tab.c ctl.pb-c.c ctl.pb-c.h

if LOCAL_TALLOC
AM_CPPFLAGS += -I$(top_srcdir)/src/ccan/talloc
endif

#AM_CPPFLAGS += -DDEBUG_LEAKS

include common.mk

EXTRA_DIST = version.inc.in version.inc \
	ipc.proto ctl.proto http-heads.gperf common.mk ocserv-fw

if LOCAL_HTTP_PARSER
AM_CPPFLAGS += -I$(srcdir)/http-parser/
HTTP_PARSER_SOURCES = http-parser/http_parser.c http-parser/http_parser.h
NEEDED_HTTP_PARSER_LIBS = 
else
NEEDED_HTTP_PARSER_LIBS = $(HTTP_PARSER_LIBS)
endif

sbin_PROGRAMS = ocserv
bin_SCRIPTS = ocserv-fw

noinst_LIBRARIES = libcmd-ocserv.a libipc.a
libcmd_ocserv_a_SOURCES = ocserv-args.def ocserv-args.c ocserv-args.h

ocserv-args.c: $(srcdir)/ocserv-args.def $(builddir)/version.inc
	$(AUTOGEN) $<
ocserv-args.h: ocserv-args.c

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
	main-ban.c main-ban.h common-config.h base64-helper.c base64-helper.h \
	str.c str.h gettime.h $(CCAN_SOURCES) $(HTTP_PARSER_SOURCES) \
	sec-mod-acct.h setproctitle.c setproctitle.h sec-mod-resume.h \
	sec-mod-cookies.c

if ENABLE_COMPRESSION
ocserv_SOURCES += lzs.c lzs.h
endif

if HAVE_GSSAPI
ocserv_SOURCES += kkdcp_asn1_tab.c kkdcp.asn 
endif

ocserv_LDADD = ../gl/libgnu.a $(NEEDED_LIBOPTS) libcmd-ocserv.a ccan/libccan.a common/libcommon.a
ocserv_LDADD += $(LIBGNUTLS_LIBS) $(PAM_LIBS) $(LIBUTIL) \
	$(LIBSECCOMP) $(LIBWRAP) $(LIBCRYPT) $(NEEDED_HTTP_PARSER_LIBS) \
	$(LIBPROTOBUF_C_LIBS) $(LIBSYSTEMD) $(LIBTALLOC_LIBS) \
	$(RADCLI_LIBS) $(LIBLZ4_LIBS) $(LIBKRB5_LIBS) \
	$(LIBTASN1_LIBS) $(LIBOATH_LIBS) $(LIBNETTLE_LIBS) \
	$(LIBEV_LIBS) libipc.a


if PCL
ocserv_LDADD += $(PCL_LIBS)
else
ocserv_LDADD += pcl/libpcl.a
SUBDIRS += pcl
AM_CPPFLAGS += -I$(srcdir)/pcl/
endif

if LOCAL_PROTOBUF_C
SUBDIRS += protobuf
AM_CPPFLAGS += -I$(srcdir)/protobuf/
ocserv_LDADD += protobuf/libprotobuf.a
endif

SUBDIRS += occtl ocpasswd

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

ccan/libccan.a:
	cd ccan && $(MAKE) $(AM_MAKEFLAGS) libccan.a

common/libcommon.a:
	cd common && $(MAKE) $(AM_MAKEFLAGS) libcommon.a

.PHONY: ccan/libccan.a common/libcommon.a
