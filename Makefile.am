EXTRA_DIST = LICENSE

SUBDIRS = gl libopts src doc tests

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

dist-hook: 
	cd $(distdir)/src/ && for i in *.def;do \
		autogen $$i; \
	done
