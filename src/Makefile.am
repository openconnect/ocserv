AM_CPPFLAGS = -I$(srcdir)/../gl/ -I$(builddir)/../gl/ \
	-I$(srcdir)/ -I$(builddir)/../ -I$(srcdir)/../libopts

EXTRA_DIST = ocserv.1 sample.config

bin_PROGRAMS = ocserv

ocserv_SOURCES = main.c main-auth.c worker-vpn.c worker-auth.c tlslib.c \
	cookies.c http-parser/http_parser.c \
	vpn.h cookies.h tlslib.h http-parser/http_parser.h log.c tun.c tun.h \
	config.c worker-auth.h pam.c pam.h worker-resume.c worker.h hash.h \
	hashtable.h main-resume.c

ocserv_SOURCES += ocserv-args.def ocserv-args.c ocserv-args.h

ocserv_LDADD = ../gl/libgnu.a ../libopts/libopts.a
ocserv_LDADD += $(LIBGNUTLS_LIBS) $(GDBM_LIBS) $(PAM_LIBS)

ocserv-args.c ocserv-args.h: $(srcdir)/ocserv-args.def
	-autogen ocserv-args.def

ocserv.1: ocserv-args.def
	-sed 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	autogen -DMAN_SECTION=1 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp
