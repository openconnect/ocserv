AM_CPPFLAGS =  -I$(srcdir)/ -I$(builddir)/../ -I$(srcdir)/../

EXTRA_DIST = licenses/BSD-MIT licenses/CC0 licenses/LGPL-2.1

noinst_LIBRARIES = libccan.a
libccan_a_SOURCES = build_assert/build_assert.h check_type/check_type.h \
	container_of/container_of.h hash/hash.c hash/hash.h \
	htable/htable.c htable/htable.h htable/htable_type.h \
	list/list.c list/list.h

if LOCAL_TALLOC
libccan_a_SOURCES += talloc/talloc.c talloc/talloc.h compiler/compiler.h \
	typesafe_cb/typesafe_cb.h
endif
