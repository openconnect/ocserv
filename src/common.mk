AM_CPPFLAGS = 

if NEED_LIBOPTS
NEEDED_LIBOPTS = $(top_builddir)/libopts/libopts.a
else
NEEDED_LIBOPTS = $(LIBOPTS_LDADD)
endif

if LOCAL_TALLOC
AM_CPPFLAGS += -I$(top_srcdir)/src/ccan/talloc
endif

if LOCAL_HTTP_PARSER
AM_CPPFLAGS += -I$(top_srcdir)/src/http-parser/
NEEDED_HTTP_PARSER_LIBS = 
else
NEEDED_HTTP_PARSER_LIBS = $(HTTP_PARSER_LIBS)
endif

if LOCAL_PROTOBUF_C
AM_CPPFLAGS += -I$(top_builddir)/src/protobuf/
NEEDED_LIBPROTOBUF_LIBS = $(top_builddir)/src/protobuf/libprotobuf.a
else
NEEDED_LIBPROTOBUF_LIBS = $(LIBPROTOBUF_C_LIBS)
endif
