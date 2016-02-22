AM_CPPFLAGS = -I$(srcdir)/../../gl/ -I$(builddir)/../../gl/ \
	-I$(srcdir)/ -I$(srcdir)/../ -I$(builddir)/../../ \
	-I$(builddir) $(LIBTALLOC_CFLAGS) $(LIBOPTS_CFLAGS) 

include ../common.mk

EXTRA_DIST = args.def

BUILT_SOURCES = args.c args.h

bin_PROGRAMS = ocpasswd

noinst_LIBRARIES = libcmd-ocpasswd.a
libcmd_ocpasswd_a_SOURCES = args.def args.c args.h

ocpasswd_SOURCES = ocpasswd.c
ocpasswd_LDADD = ../../gl/libgnu.a $(NEEDED_LIBOPTS2) libcmd-ocpasswd.a
ocpasswd_LDADD += $(LIBGNUTLS_LIBS) $(LIBCRYPT)

args.c: $(srcdir)/args.def $(builddir)/../version.inc
	$(AUTOGEN) $<
args.h: args.c

