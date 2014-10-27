SUBDIRS =

AM_CPPFLAGS = -I$(srcdir)/../gl/ -I$(builddir)/../gl/ \
	-I$(srcdir)/ -I$(builddir)/../ $(LIBOPTS_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) \
	$(LIBPROTOBUF_C_CFLAGS) \
	$(LIBNL3_CFLAGS) $(LIBREADLINE_CFLAGS) \
	$(LIBTALLOC_CFLAGS) $(LIBDBUS_CFLAGS)

BUILT_SOURCES = ocpasswd-args.c ocpasswd-args.h \
	ocserv-args.c ocserv-args.h ipc.pb-c.c ipc.pb-c.h \
	ctl.pb-c.c ctl.pb-c.h

#AM_CPPFLAGS += -DDEBUG_LEAKS

if LOCAL_HTTP_PARSER
AM_CPPFLAGS += -I$(srcdir)/http-parser/
HTTP_PARSER_SOURCES = http-parser/http_parser.c http-parser/http_parser.h
NEEDED_HTTP_PARSER_LIBS = 
else
NEEDED_HTTP_PARSER_LIBS = $(HTTP_PARSER_LIBS)
endif

if NEED_LIBOPTS
NEEDED_LIBOPTS = ../libopts/libopts.a
else
NEEDED_LIBOPTS = $(LIBOPTS_LDADD)
endif

EXTRA_DIST = ccan/licenses/BSD-MIT version.inc.in \
	ccan/licenses/CC0 ccan/licenses/LGPL-2.1 version.inc \
	occtl-args.def ipc.proto ctl.proto

bin_PROGRAMS = ocpasswd occtl

sbin_PROGRAMS = ocserv

CCAN_SOURCES = ccan/build_assert/build_assert.h ccan/check_type/check_type.h \
	ccan/container_of/container_of.h ccan/hash/hash.c ccan/hash/hash.h \
	ccan/htable/htable.c ccan/htable/htable.h ccan/htable/htable_type.h \
	ccan/list/list.c ccan/list/list.h

if LOCAL_TALLOC
CCAN_SOURCES += ccan/talloc/talloc.c ccan/talloc/talloc.h ccan/compiler/compiler.h \
	ccan/typesafe_cb/typesafe_cb.h
endif


noinst_LIBRARIES = libcmd-ocserv.a
libcmd_ocserv_a_SOURCES = ocserv-args.def ocserv-args.c ocserv-args.h

ocserv-args.c: $(srcdir)/ocserv-args.def $(srcdir)/version.inc
	$(AUTOGEN) $<
ocserv-args.h: ocserv-args.c

PROTOBUF_SOURCES =
if LOCAL_PROTOBUF_C
PROTOBUF_SOURCES += protobuf/protobuf-c/protobuf-c.h protobuf/protobuf-c/protobuf-c.c
endif

# Files common to ocserv and occtl.
COMMON_SOURCES=common.c common.h system.c system.h setproctitle.c setproctitle.h

# Authentication module sources
AUTH_SOURCES=auth/pam.c auth/pam.h auth/plain.c auth/plain.h

ocserv_SOURCES = main.c main-auth.c worker-vpn.c worker-auth.c tlslib.c \
	cookies.c main-misc.c ip-lease.c ip-lease.h \
	vpn.h cookies.h tlslib.h log.c tun.c tun.h \
	config.c worker-resume.c worker.h main-resume.c main.h \
	worker-extras.c html.c html.h \
	main-user.c worker-misc.c route-add.c route-add.h worker-privs.c \
	sec-mod.c sec-mod-db.c sec-mod-auth.c sec-mod-auth.h sec-mod.h sec-mod-ban.c \
	script-list.h $(COMMON_SOURCES) $(AUTH_SOURCES) \
	icmp-ping.c icmp-ping.h \
	main-sup-config.c main-sup-config.h \
	sup-config/file.c sup-config/file.h \
	worker-bandwidth.c worker-bandwidth.h ctl.h main-ctl.h \
	vasprintf.c vasprintf.h \
	proc-search.c proc-search.h \
	str.c str.h gettime.h $(CCAN_SOURCES) $(HTTP_PARSER_SOURCES) \
	$(PROTOBUF_SOURCES)


ocserv_SOURCES += ipc.pb-c.h ipc.pb-c.c ctl.pb-c.c ctl.pb-c.h

ocserv_LDADD = ../gl/libgnu.a $(NEEDED_LIBOPTS) libcmd-ocserv.a
ocserv_LDADD += $(LIBGNUTLS_LIBS) $(PAM_LIBS) $(LIBUTIL) \
	$(LIBSECCOMP) $(LIBWRAP) $(LIBCRYPT) $(NEEDED_HTTP_PARSER_LIBS) \
	$(LIBPROTOBUF_C_LIBS) $(LIBSYSTEMD_DAEMON) $(LIBTALLOC_LIBS)


if PCL
ocserv_LDADD += $(PCL_LIBS)
else
ocserv_LDADD += pcl/libpcl.a
SUBDIRS += pcl
AM_CPPFLAGS += -I$(srcdir)/pcl/
endif

noinst_LIBRARIES += libcmd-ocpasswd.a
libcmd_ocpasswd_a_SOURCES = ocpasswd-args.def ocpasswd-args.c ocpasswd-args.h


ocpasswd_SOURCES = ocpasswd.c
ocpasswd_LDADD = ../gl/libgnu.a $(NEEDED_LIBOPTS) libcmd-ocpasswd.a
ocpasswd_LDADD += $(LIBGNUTLS_LIBS) $(LIBCRYPT)

ocpasswd-args.c: $(srcdir)/ocpasswd-args.def $(srcdir)/version.inc
	$(AUTOGEN) $<
ocpasswd-args.h: ocpasswd-args.c

occtl_SOURCES = occtl.c occtl-pager.c occtl.h occtl-time.c occtl-cache.c \
	occtl-nl.c ctl.h ctl.pb-c.c ctl.pb-c.h $(CCAN_SOURCES) $(COMMON_SOURCES) \
	$(PROTOBUF_SOURCES)
occtl_LDADD = ../gl/libgnu.a $(LIBREADLINE_LIBS) \
	$(LIBNL3_LIBS) $(LIBPROTOBUF_C_LIBS) $(LIBTALLOC_LIBS)

if HAVE_DBUS
ocserv_SOURCES += main-ctl-dbus.c
occtl_SOURCES += occtl-dbus.c
ocserv_LDADD += $(LIBDBUS_LIBS)
occtl_LDADD += $(LIBDBUS_LIBS)
else
ocserv_SOURCES += main-ctl-unix.c
occtl_SOURCES += occtl-unix.c
endif

ipc.pb-c.c: ipc.proto
	protoc-c --c_out=. --proto_path=$(srcdir) $<

ipc.pb-c.h: ipc.pb-c.c

ctl.pb-c.c: ctl.proto
	protoc-c --c_out=. --proto_path=$(srcdir) $<

ctl.pb-c.h: ctl.pb-c.c
