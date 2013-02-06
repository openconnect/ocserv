AM_CPPFLAGS = -I$(srcdir)/../gl/ -I$(builddir)/../gl/ \
	-I$(srcdir)/ -I$(builddir)/../ -I$(srcdir)/../libopts

EXTRA_DIST = ocserv.1 sample.config ccan/licenses/BSD-MIT \
	ccan/licenses/CC0 ccan/licenses/LGPL-2.1


bin_PROGRAMS = ocserv

CCAN_SOURCES = ccan/build_assert/build_assert.h ccan/check_type/check_type.h \
	ccan/container_of/container_of.h ccan/hash/hash.c ccan/hash/hash.h \
	ccan/htable/htable.c ccan/htable/htable.h ccan/htable/htable_type.h \
	ccan/list/list.c ccan/list/list.h


ocserv_SOURCES = main.c main-auth.c worker-vpn.c worker-auth.c tlslib.c \
	cookies.c http-parser/http_parser.c ipc.h \
	vpn.h cookies.h tlslib.h http-parser/http_parser.h log.c tun.c tun.h \
	config.c pam.c pam.h worker-resume.c worker.h main-resume.c main.h \
	main-script.c $(CCAN_SOURCES)

ocserv_SOURCES += ocserv-args.def ocserv-args.c ocserv-args.h

ocserv_LDADD = ../gl/libgnu.a ../libopts/libopts.a
ocserv_LDADD += $(LIBGNUTLS_LIBS) $(GDBM_LIBS) $(PAM_LIBS)

ocserv-args.c ocserv-args.h: $(srcdir)/ocserv-args.def
	-autogen ocserv-args.def

ocserv.1: ocserv-args.def
	-sed 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	autogen -DMAN_SECTION=1 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp
