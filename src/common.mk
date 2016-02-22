
if NEED_LIBOPTS
NEEDED_LIBOPTS = ../libopts/libopts.a
NEEDED_LIBOPTS2 = ../../libopts/libopts.a
else
NEEDED_LIBOPTS = $(LIBOPTS_LDADD)
NEEDED_LIBOPTS2 = $(LIBOPTS_LDADD)
endif

