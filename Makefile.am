EXTRA_DIST = m4/lib-link.m4 LICENSE

SUBDIRS = gl libopts src doc

ACLOCAL_AMFLAGS = -I gl/m4 -I libopts/m4 -I m4

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
