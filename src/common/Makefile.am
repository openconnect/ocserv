AM_CPPFLAGS = -I$(srcdir)/../../gl/ -I$(builddir)/../../gl/ \
	-I$(srcdir)/ -I$(srcdir)/../ -I$(builddir)/../../ -I$(srcdir)/../../ \
	-I$(builddir)/../ $(LIBPROTOBUF_C_CFLAGS)	$(LIBTALLOC_CFLAGS)

if LOCAL_TALLOC
AM_CPPFLAGS += -I$(srcdir)/../ccan/talloc
endif

if LOCAL_HTTP_PARSER
AM_CPPFLAGS += -I$(srcdir)/../http-parser/
endif

# Files common to ocserv and occtl.
libcommon_a_SOURCES=common.c common.h system.c system.h \
	cloexec.c cloexec.h
libcommon_a_LIBS = ../../gl/libgnu.a
noinst_LIBRARIES = libcommon.a

if LOCAL_PROTOBUF_C
AM_CPPFLAGS += -I$(srcdir)/../protobuf/
libcommon_a_LIBS += ../protobuf/libprotobuf.a
endif

