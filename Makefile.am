EXTRA_DIST = m4/lib-link.m4

SUBDIRS = gl libopts src doc

ACLOCAL_AMFLAGS = -I gl/m4 -I libopts/m4 -I m4

ctags:
	find . -type f -name "*.[ch]*" | xargs @CTAGS@

cscope:
	@CSCOPE@ -b -R

cref: ctags cscope
