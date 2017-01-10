AUTOMAKE_OPTIONS = foreign
EXTRA_DIST = LICENSE README.md CONTRIBUTING.md

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

files-update:
	cp -f $(builddir)/src/ocserv-args.c $(srcdir)/src/ocserv-args.c.in
	cp -f $(builddir)/src/ocserv-args.h $(srcdir)/src/ocserv-args.h.in
	cp -f $(builddir)/src/ocpasswd-args.c $(srcdir)/src/ocpasswd/ocpasswd-args.c.in
	cp -f $(builddir)/src/ocpasswd-args.h $(srcdir)/src/ocpasswd/ocpasswd-args.h.in

files-compare:
	@echo "*****************************************************************"
	@echo "If the following step fails, the autogen .in files are out-of-date;"
	@echo "run files-update to update them."
	@echo "*****************************************************************"
	cmp $(srcdir)/src/ocserv-args.c.in $(builddir)/src/ocserv-args.c
	cmp $(srcdir)/src/ocserv-args.h.in $(builddir)/src/ocserv-args.h
	cmp $(srcdir)/src/ocpasswd/ocpasswd-args.c.in $(builddir)/src/ocpasswd-args.c
	cmp $(srcdir)/src/ocpasswd/ocpasswd-args.h.in $(builddir)/src/ocpasswd-args.h

dist-hook: files-compare ChangeLog
	mv ChangeLog $(distdir)
	$(AUTOGEN) --version
	@echo "*****************************************************************"
	@echo "Checking whether included libopts matches the system's. If the"
	@echo "check fails upgrade the included libopts."
	@echo "*****************************************************************"
	test "$(SKIP_LIBOPTS_CHECK)" = "1" || test "`autoopts-config libsrc|cut -d '-' -f 2|sed 's/.tar.gz//'`" = "`cat $(srcdir)/libopts/autoopts/options.h |grep OPTIONS_VERSION_STRING|cut -d '"' -f 2|sed 's/:/./g'`"
	for dir in $(distdir)/src/ $(distdir)/src/ocpasswd/;do \
		( cd $$dir && for i in *args.def;do \
			$(AUTOGEN) $$i; \
		done && \
		for i in *args.c *args.h;do \
			mv $$i $$i.in; \
		done ) \
	done

.PHONY: files-update files-compare
