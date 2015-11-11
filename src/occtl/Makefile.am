AM_CPPFLAGS = -I$(srcdir)/../../gl/ -I$(builddir)/../../gl/ \
	-I$(srcdir)/ -I$(srcdir)/../ -I$(builddir)/../../ -I$(builddir)/../ \
	$(LIBNL3_CFLAGS) $(LIBPROTOBUF_C_CFLAGS) $(LIBTALLOC_CFLAGS) \
	-I$(srcdir)/../common/

if LOCAL_TALLOC
AM_CPPFLAGS += -I$(srcdir)/../ccan/talloc
endif

EXTRA_DIST = args.def

bin_PROGRAMS = occtl

occtl_SOURCES = occtl.c pager.c occtl.h time.c cache.c ip-cache.c \
	nl.c ctl.h print.c json.c json.h
occtl_LDADD = ../../gl/libgnu.a ../common/libcommon.a $(LIBREADLINE_LIBS) \
	$(LIBNL3_LIBS) $(LIBPROTOBUF_C_LIBS) $(LIBTALLOC_LIBS) ../ccan/libccan.a

if LOCAL_PROTOBUF_C
occtl_LDADD += ../protobuf/libprotobuf.a
endif

occtl_SOURCES += unix.c
