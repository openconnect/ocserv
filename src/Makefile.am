SUBDIRS =

AM_CPPFLAGS = -I$(srcdir)/../gl/ -I$(builddir)/../gl/ \
	-I$(srcdir)/ -I$(builddir)/../ $(LIBOPTS_CFLAGS)

BUILT_SOURCES = ocpasswd-args.c ocpasswd-args.h \
	ocserv-args.c ocserv-args.h

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
	ccan/licenses/CC0 ccan/licenses/LGPL-2.1 version.inc

bin_PROGRAMS = ocpasswd
sbin_PROGRAMS = ocserv


CCAN_SOURCES = ccan/build_assert/build_assert.h ccan/check_type/check_type.h \
	ccan/container_of/container_of.h ccan/hash/hash.c ccan/hash/hash.h \
	ccan/htable/htable.c ccan/htable/htable.h ccan/htable/htable_type.h \
	ccan/list/list.c ccan/list/list.h

noinst_LIBRARIES = libcmd-ocserv.a
libcmd_ocserv_a_SOURCES = ocserv-args.def ocserv-args.c ocserv-args.h

ocserv-args.c: $(srcdir)/ocserv-args.def
	$(AUTOGEN) $<
ocserv-args.h: ocserv-args.c

ocserv_SOURCES = main.c main-auth.c worker-vpn.c worker-auth.c tlslib.c \
	ipc.h cookies.c worker-tun.c main-misc.c \
	group-config.c ip-lease.c ip-lease.h \
	vpn.h cookies.h tlslib.h log.c tun.c tun.h \
	config.c pam.c pam.h worker-resume.c worker.h main-resume.c main.h \
	worker-extras.c main-auth.h html.c html.h \
	main-user.c worker-misc.c setproctitle.h route-add.c route-add.h \
	setproctitle.c worker-privs.c plain.c plain.h common.h common.c \
	sec-mod.c sec-mod.h script-list.h system.c system.h icmp-ping.c icmp-ping.h \
	worker-bandwidth.c worker-bandwidth.h \
	str.c str.h gettime.h $(CCAN_SOURCES) $(HTTP_PARSER_SOURCES)


ocserv_LDADD = ../gl/libgnu.a $(NEEDED_LIBOPTS) libcmd-ocserv.a
ocserv_LDADD += $(LIBGNUTLS_LIBS) $(PAM_LIBS) $(LIBUTIL) \
	$(LIBSECCOMP) $(LIBWRAP) $(LIBCRYPT) $(NEEDED_HTTP_PARSER_LIBS)

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

ocpasswd-args.c: $(srcdir)/ocpasswd-args.def
	$(AUTOGEN) $<
ocpasswd-args.h: ocpasswd-args.c
