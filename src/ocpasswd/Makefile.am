include ../common.mk

AM_CPPFLAGS += -I$(srcdir)/../../gl/ -I$(builddir)/../../gl/ \
	-I$(srcdir)/ -I$(srcdir)/../ -I$(builddir)/../../ \
	-I$(builddir) $(LIBTALLOC_CFLAGS) $(LIBOPTS_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) $(LIBGNUTLS_CFLAGS)


EXTRA_DIST = ocpasswd-args.def ocpasswd-args.c.in ocpasswd-args.h.in

BUILT_SOURCES = ocpasswd-args.c ocpasswd-args.h

bin_PROGRAMS = ocpasswd

noinst_LIBRARIES = libcmd-ocpasswd.a
libcmd_ocpasswd_a_SOURCES = ocpasswd-args.def ocpasswd-args.c ocpasswd-args.h

ocpasswd_SOURCES = ocpasswd.c
ocpasswd_LDADD = ../../gl/libgnu.a $(NEEDED_LIBOPTS) libcmd-ocpasswd.a
ocpasswd_LDADD += $(LIBGNUTLS_LIBS) $(LIBCRYPT) $(CODE_COVERAGE_LDFLAGS) \
	$(LIBNETTLE_LIBS)

ocpasswd-args.stamp: $(srcdir)/ocpasswd-args.def $(builddir)/../version.inc
	$(AUTOGEN) $<
	touch $@
ocpasswd-args.h: ocpasswd-args.stamp
ocpasswd-args.c: ocpasswd-args.stamp

clean-local:
	rm -f ocpasswd-args.stamp
