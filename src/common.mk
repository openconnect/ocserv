AM_CPPFLAGS = 

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
NEEDED_LIBPROTOBUF_LIBS = libprotobuf.a
else
NEEDED_LIBPROTOBUF_LIBS = $(LIBPROTOBUF_C_LIBS)
endif
