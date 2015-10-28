
if NEED_LIBOPTS
NEEDED_LIBOPTS = ../libopts/libopts.a
else
NEEDED_LIBOPTS = $(LIBOPTS_LDADD)
endif

