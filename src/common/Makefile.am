AM_CPPFLAGS = -I$(srcdir)/../../gl/ -I$(builddir)/../../gl/ \
	-I$(srcdir)/ -I$(srcdir)/../ -I$(builddir)/../../ -I$(srcdir)/../../ \
	$(LIBPROTOBUF_C_CFLAGS)	$(LIBTALLOC_CFLAGS)

if LOCAL_TALLOC
AM_CPPFLAGS += -I$(srcdir)/../ccan/talloc
endif

EXTRA_DIST = ctl.proto
BUILT_SOURCES = ctl.pb-c.c ctl.pb-c.h

# Files common to ocserv and occtl.
libcommon_a_SOURCES=common.c common.h system.c system.h ctl.pb-c.c ctl.pb-c.h \
	cloexec.c cloexec.h
libcommon_a_LIBS = ../../gl/libgnu.a
noinst_LIBRARIES = libcommon.a

if LOCAL_PROTOBUF_C
libcommon_a_LIBS += ../protobuf/libprotobuf.a
endif

ctl.pb-c.c: ctl.proto
	protoc-c --c_out=. --proto_path=$(srcdir) $<

ctl.pb-c.h: ctl.pb-c.c
