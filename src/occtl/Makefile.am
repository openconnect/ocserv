AM_CPPFLAGS = -I$(srcdir)/../../gl/ -I$(builddir)/../../gl/ \
	-I$(srcdir)/ -I$(srcdir)/../ -I$(builddir)/../../ -I$(builddir)/../ \
	$(LIBNL3_CFLAGS) $(LIBPROTOBUF_C_CFLAGS) $(LIBTALLOC_CFLAGS)

EXTRA_DIST = args.def

bin_PROGRAMS = occtl

COMMON_SOURCES=../common.c ../common.h ../system.c ../system.h

occtl_SOURCES = occtl.c pager.c occtl.h time.c cache.c ip-cache.c \
	nl.c ctl.h ../ctl.pb-c.c ../ctl.pb-c.h $(CCAN_SOURCES) $(COMMON_SOURCES) \
	print.c json.c json.h $(PROTOBUF_SOURCES)
occtl_LDADD = ../../gl/libgnu.a $(LIBREADLINE_LIBS) \
	$(LIBNL3_LIBS) $(LIBPROTOBUF_C_LIBS) $(LIBTALLOC_LIBS)

occtl_SOURCES += unix.c
