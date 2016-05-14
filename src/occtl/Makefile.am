include ../common.mk

AM_CPPFLAGS += -I$(srcdir)/../../gl/ -I$(builddir)/../../gl/ \
	-I$(srcdir)/ -I$(srcdir)/../ -I$(builddir)/../../ -I$(builddir)/../ \
	$(LIBNL3_CFLAGS) $(LIBPROTOBUF_C_CFLAGS) $(LIBTALLOC_CFLAGS) \
	-I$(srcdir)/../common/ -I$(builddir)/../common/ $(CODE_COVERAGE_CFLAGS)

EXTRA_DIST = args.def

bin_PROGRAMS = occtl

occtl_SOURCES = occtl.c pager.c occtl.h time.c cache.c ip-cache.c \
	nl.c ctl.h print.c json.c json.h hex.c hex.h
occtl_LDADD = ../../gl/libgnu.a ../common/libcommon.a $(LIBREADLINE_LIBS) \
	$(LIBNL3_LIBS) $(NEEDED_LIBPROTOBUF_LIBS) $(LIBTALLOC_LIBS) ../ccan/libccan.a \
	../libipc.a $(NEEDED_LIBPROTOBUF_LIBS) $(CODE_COVERAGE_LDFLAGS) \
	$(LIBNETTLE_LIBS)

occtl_SOURCES += unix.c

../libipc.a:
	cd .. && $(MAKE) $(AM_MAKEFLAGS) libipc.a

../ccan/libccan.a:
	cd ../ccan && $(MAKE) $(AM_MAKEFLAGS) libccan.a

../common/libcommon.a:
	cd ../common && $(MAKE) $(AM_MAKEFLAGS) libcommon.a

$(top_srcdir)/src/protobuf/libprotobuf.a:
	cd ../protobuf && $(MAKE) $(AM_MAKEFLAGS) libprotobuf.a

.PHONY: ../libipc.a ../ccan/libccan.a ../common/libcommon.a
