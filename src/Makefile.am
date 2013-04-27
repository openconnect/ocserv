AM_CPPFLAGS = -I$(srcdir)/../gl/ -I$(builddir)/../gl/ \
	-I$(srcdir)/ -I$(builddir)/../ -I$(srcdir)/../libopts

EXTRA_DIST = ccan/licenses/BSD-MIT version.def.in \
	ccan/licenses/CC0 ccan/licenses/LGPL-2.1

bin_PROGRAMS = ocserv ocpasswd

CCAN_SOURCES = ccan/build_assert/build_assert.h ccan/check_type/check_type.h \
	ccan/container_of/container_of.h ccan/hash/hash.c ccan/hash/hash.h \
	ccan/htable/htable.c ccan/htable/htable.h ccan/htable/htable_type.h \
	ccan/list/list.c ccan/list/list.h


ocserv_SOURCES = main.c main-auth.c worker-vpn.c worker-auth.c tlslib.c \
	http-parser/http_parser.c ipc.h cookies.c worker-tun.c main-misc.c \
	vpn.h cookies.h tlslib.h http-parser/http_parser.h log.c tun.c tun.h \
	config.c pam.c pam.h worker-resume.c worker.h main-resume.c main.h \
	main-user.c cookies-gdbm.c cookies-hash.c worker-misc.c setproctitle.h \
	setproctitle.c worker-privs.c plain.c plain.h common.h common.c \
	sec-mod.c sec-mod.h script-list.h die.c die.h icmp-ping.c icmp-ping.h \
	$(CCAN_SOURCES)

ocserv_SOURCES += ocserv-args.def ocserv-args.c ocserv-args.h

ocserv_LDADD = ../gl/libgnu.a ../libopts/libopts.a
ocserv_LDADD += $(LIBGNUTLS_LIBS) $(GDBM_LIBS) $(PAM_LIBS) $(LIBUTIL) \
	$(LIBSECCOMP) $(LIBWRAP) $(LIBCRYPT)

ocserv-args.c ocserv-args.h: $(srcdir)/ocserv-args.def
	@AUTOGEN@ $<

ocpasswd_SOURCES = ocpasswd.c ocpasswd-args.def ocpasswd-args.c ocpasswd-args.h

ocpasswd_LDADD = ../gl/libgnu.a ../libopts/libopts.a
ocpasswd_LDADD += $(LIBGNUTLS_LIBS) $(LIBCRYPT)

ocpasswd-args.c ocpasswd-args.h: $(srcdir)/ocpasswd-args.def
	@AUTOGEN@ $<
