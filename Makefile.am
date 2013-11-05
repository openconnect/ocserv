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
	cd $(distdir)/src/ && for i in *.def;do \
		autogen $$i; \
		touch $$i; \
	done
