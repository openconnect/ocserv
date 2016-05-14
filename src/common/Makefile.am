include ../common.mk

AM_CPPFLAGS += -I$(srcdir)/../../gl/ -I$(builddir)/../../gl/ \
	-I$(srcdir)/ -I$(srcdir)/../ -I$(builddir)/../../ -I$(srcdir)/../../ \
	-I$(builddir)/../ $(LIBPROTOBUF_C_CFLAGS) $(LIBTALLOC_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS)

# Files common to ocserv and occtl.
libcommon_a_SOURCES=common.c common.h system.c system.h \
	cloexec.c cloexec.h base64-helper.c base64-helper.h
libcommon_a_LIBS = ../../gl/libgnu.a $(NEEDED_LIBPROTOBUF_LIBS)
noinst_LIBRARIES = libcommon.a


