AC_PREREQ(2.61)
AC_INIT([ocserv], [0.0.1], [nmav@gnutls.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11.3 no-dist-gzip dist-xz -Wall -Werror -Wno-override])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
gl_EARLY

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.0.0])

LIBS="$oldlibs -lgdbm"
AC_MSG_CHECKING([for gdbm library])
AC_LINK_IFELSE([AC_LANG_PROGRAM([
		   #include <gdbm.h>],[
		   GDBM_FILE dbf;
		   dbf = gdbm_open("",0,0,0,0);])],
		  [AC_MSG_RESULT(yes)
		   AC_SUBST([GDBM_LIBS], [-lgdbm])
		   AC_SUBST([GDBM_CFLAGS], [])
		   AC_DEFINE([HAVE_GDBM], 1, [Enable the GDBM library])],
		  [AC_MSG_RESULT(no)
   	           AC_MSG_ERROR([[
*** 
*** gdbm was not found. It is required for building this program.
*** ]])])
LIBS="$oldlibs"

gl_INIT

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	gl/Makefile
])
AC_OUTPUT
