AM_CPPFLAGS = -I$(srcdir)/../../gl/ -I$(builddir)/../../gl/ \
	-I$(srcdir)/ -I$(srcdir)/../ -I$(builddir)/../../ -I$(builddir)/../ \
	$(LIBNL3_CFLAGS) $(LIBPROTOBUF_C_CFLAGS) $(LIBTALLOC_CFLAGS) \
	-I$(srcdir)/../common/ -I$(builddir)/../common/

if LOCAL_TALLOC
AM_CPPFLAGS += -I$(srcdir)/../ccan/talloc
endif

if LOCAL_HTTP_PARSER
AM_CPPFLAGS += -I$(srcdir)/../http-parser/
endif

EXTRA_DIST = args.def

bin_PROGRAMS = occtl

occtl_SOURCES = occtl.c pager.c occtl.h time.c cache.c ip-cache.c \
	nl.c ctl.h print.c json.c json.h hex.c hex.h
occtl_LDADD = ../../gl/libgnu.a ../common/libcommon.a $(LIBREADLINE_LIBS) \
	$(LIBNL3_LIBS) $(LIBPROTOBUF_C_LIBS) $(LIBTALLOC_LIBS) ../ccan/libccan.a \
	../libipc.a

if LOCAL_PROTOBUF_C
AM_CPPFLAGS += -I$(srcdir)/../protobuf/
occtl_LDADD += ../protobuf/libprotobuf.a
endif

occtl_SOURCES += unix.c

../libipc.a:
	cd .. && $(MAKE) $(AM_MAKEFLAGS) libipc.a

../ccan/libccan.a:
	cd ../ccan && $(MAKE) $(AM_MAKEFLAGS) libccan.a

../common/libcommon.a:
	cd ../common && $(MAKE) $(AM_MAKEFLAGS) libcommon.a

.PHONY: ../libipc.a ../ccan/libccan.a ../common/libcommon.a
