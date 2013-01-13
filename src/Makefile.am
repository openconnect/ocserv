AM_CPPFLAGS = -I$(srcdir)../gl/ -I$(builddir)../gl/ \
	-I$(srcdir)/ -I$(builddir)/../

bin_PROGRAMS = ocserv

ocserv_SOURCES = main.c vpn.c auth.c tlslib.c cookies.c http-parser/http_parser.c \
	vpn.h auth.h cookies.h tlslib.h http-parser/http_parser.h log.c

ocserv_LDADD = ../gl/libgnu.a 
ocserv_LDADD += $(LIBGNUTLS_LIBS) $(GDBM_LIBS)
