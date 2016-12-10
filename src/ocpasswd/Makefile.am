include ../common.mk

AM_CPPFLAGS += -I$(srcdir)/../../gl/ -I$(builddir)/../../gl/ \
	-I$(srcdir)/ -I$(srcdir)/../ -I$(builddir)/../../ \
	-I$(builddir) $(LIBTALLOC_CFLAGS) $(LIBOPTS_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) $(LIBGNUTLS_CFLAGS)


EXTRA_DIST = args.def args.c.in args.h.in

BUILT_SOURCES = args.c args.h

bin_PROGRAMS = ocpasswd

noinst_LIBRARIES = libcmd-ocpasswd.a
libcmd_ocpasswd_a_SOURCES = args.def args.c args.h

ocpasswd_SOURCES = ocpasswd.c
ocpasswd_LDADD = ../../gl/libgnu.a $(NEEDED_LIBOPTS) libcmd-ocpasswd.a
ocpasswd_LDADD += $(LIBGNUTLS_LIBS) $(LIBCRYPT) $(CODE_COVERAGE_LDFLAGS) \
	$(LIBNETTLE_LIBS)

args.stamp: $(srcdir)/args.def $(builddir)/../version.inc
	$(AUTOGEN) $<
	touch $@
args.h: args.stamp
args.c: args.stamp

clean-local:
	rm -f args.stamp
