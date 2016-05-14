include ../common.mk

AM_CPPFLAGS += -I$(srcdir)/../../gl/ -I$(builddir)/../../gl/ \
	-I$(srcdir)/ -I$(srcdir)/../ -I$(builddir)/../../ \
	-I$(builddir) $(LIBTALLOC_CFLAGS) $(LIBOPTS_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS)


EXTRA_DIST = args.def

BUILT_SOURCES = args.c args.h

bin_PROGRAMS = ocpasswd

noinst_LIBRARIES = libcmd-ocpasswd.a
libcmd_ocpasswd_a_SOURCES = args.def args.c args.h

ocpasswd_SOURCES = ocpasswd.c
ocpasswd_LDADD = ../../gl/libgnu.a $(NEEDED_LIBOPTS) libcmd-ocpasswd.a
ocpasswd_LDADD += $(LIBGNUTLS_LIBS) $(LIBCRYPT) $(CODE_COVERAGE_LDFLAGS) \
	$(LIBNETTLE_LIBS)

args.c: $(srcdir)/args.def $(builddir)/../version.inc
	$(AUTOGEN) $<
args.h: args.c

