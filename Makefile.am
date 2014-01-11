EXTRA_DIST = LICENSE

SUBDIRS = gl
if NEED_LIBOPTS
SUBDIRS += libopts
endif
SUBDIRS += src doc tests

ACLOCAL_AMFLAGS = -I gl/m4 -I libopts/m4

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
	touch ChangeLog
	$(AUTOGEN) --version
	cd $(distdir)/src/ && for i in ocserv-args.def ocpasswd-args.def;do \
		$(AUTOGEN) $$i; \
	done
	cd $(distdir)/src/ && for i in *-args.c *-args.h;do \
		mv $$i $$i.bak; \
	done
