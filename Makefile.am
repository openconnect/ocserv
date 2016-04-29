AUTOMAKE_OPTIONS = foreign
EXTRA_DIST = LICENSE README.md

SUBDIRS = gl
if NEED_LIBOPTS
SUBDIRS += libopts
endif
SUBDIRS += src doc tests

ACLOCAL_AMFLAGS = -I m4 -I gl/m4 -I libopts/m4

@CODE_COVERAGE_RULES@

local-code-coverage-output: code-coverage-capture
	cat ocserv-$(VERSION)-coverage/index.html|grep headerCovTableEntryLo|head -1|sed 's/^.*>\([0-9]\+\.[0-9]\+\s*%\)<.*$$/ coverage lines: \1/'

gl:
	gnulib-tool --add-import --lgpl=2

clang:
	make clean
	scan-build ./configure
	rm -rf scan.tmp
	scan-build -o scan.tmp make

ctags:
	find . -type f -name "*.[ch]*" | xargs @CTAGS@

cscope:
	@CSCOPE@ -b -R

cref: ctags cscope

ChangeLog:
	git log --pretty --numstat --summary -- | git2cl > ChangeLog
.PHONY: ChangeLog

dist-hook: ChangeLog
	mv ChangeLog $(distdir)
	$(AUTOGEN) --version
	@echo "*****************************************************************"
	@echo "Checking whether included libopts matches the system's. If the"
	@echo "check fails upgrade the included libopts."
	@echo "*****************************************************************"
	test "$(SKIP_LIBOPTS_CHECK)" = "1" || test "`autoopts-config libsrc|cut -d '-' -f 2|sed 's/.tar.gz//'`" = "`cat $(srcdir)/libopts/autoopts/options.h |grep OPTIONS_VERSION_STRING|cut -d '"' -f 2|sed 's/:/./g'`"
	for dir in $(distdir)/src/ $(distdir)/src/occtl/;do \
		( cd $$dir && for i in *args.def;do \
			$(AUTOGEN) $$i; \
		done && \
		for i in *args.c *args.h;do \
			mv $$i $$i.bak; \
		done ) \
	done
