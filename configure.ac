AC_PREREQ(2.61)
AC_INIT([ocserv], [0.0.1], [nmav@gnutls.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11.3 no-dist-gzip dist-xz dist-lzip -Wall -Werror -Wno-override])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
gl_EARLY

AM_PROG_AR
AM_PROG_CC_C_O
if [ test "$GCC" = "yes" ];then
	CFLAGS="$CFLAGS -Wall"
fi

AC_CHECK_SIZEOF([unsigned long])
AC_C_BIGENDIAN

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.0.28])
AC_CHECK_LIB(gnutls, gnutls_pkcs11_reinit, [
AC_DEFINE([HAVE_PKCS11], [], [PKCS11 detected in gnutls])
])

gdbm_enabled=no
LIBS="$oldlibs -lgdbm"
AC_MSG_CHECKING([for gdbm library])
AC_LINK_IFELSE([AC_LANG_PROGRAM([
		   #include <gdbm.h>],[
		   GDBM_FILE dbf;
		   dbf = gdbm_open("",0,0,0,0);])],
		  [AC_MSG_RESULT(yes)
		   AC_SUBST([GDBM_LIBS], [-lgdbm])
		   AC_SUBST([GDBM_CFLAGS], [])
		   gdbm_enabled=yes
		   AC_DEFINE([HAVE_GDBM], 1, [Enable the GDBM library])],
		  [AC_MSG_RESULT(no)
   	           AC_MSG_WARN([[
*** 
*** gdbm was not found. The server will not be able to maintain state across restarts.
*** ]])])
LIBS="$oldlibs"

pam_enabled=no
LIBS="$oldlibs -lpam"
AC_MSG_CHECKING([for pam library])
AC_LINK_IFELSE([AC_LANG_PROGRAM([
		   #include <security/pam_appl.h>],[
		   pam_start(0, 0, 0, 0);])],
		  [AC_MSG_RESULT(yes)
		   AC_SUBST([PAM_LIBS], [-lpam])
		   AC_SUBST([PAM_CFLAGS], [])
		   pam_enabled=yes
		   AC_DEFINE([HAVE_PAM], 1, [Enable the PAM library])],
		  [AC_MSG_RESULT(no)
   	           AC_MSG_WARN([[
*** 
*** libpam was not found. PAM support will be disabled.
*** ]])])
LIBS="$oldlibs"

gl_INIT

AC_LIB_HAVE_LINKFLAGS(util,, [#include <utmpx.h>], [pututxline(0);])
AC_LIB_HAVE_LINKFLAGS(wrap,, [#include <tcpd.h>], [hosts_access(0);])

if [ test -z "$LIBWRAP" ];then
	libwrap_enabled="no"
else
	libwrap_enabled="yes"
fi

AC_ARG_ENABLE(seccomp,
  AS_HELP_STRING([--disable-seccomp], [unconditionally disable seccomp]),
    seccomp_enabled=$enableval, seccomp_enabled=yes)

if [ test "$seccomp_enabled" = "yes" ];then
AC_LIB_HAVE_LINKFLAGS(seccomp,, [#include <linux/seccomp.h>
#include <seccomp.h>], [seccomp_init(0);])
if [ test -z "$LIBSECCOMP" ];then
	seccomp_enabled="no"
else
	seccomp_enabled="yes"
fi
fi

enable_local_libopts=yes
NEED_LIBOPTS_DIR=true
LIBOPTS_CHECK([libopts])

AC_CONFIG_FILES([
	Makefile
	src/version.def
	src/Makefile
	doc/Makefile
	gl/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

  version:          ${VERSION}
  Host type:        ${host}
  Install prefix:   ${prefix}
  Compiler:         ${CC}
  CFlags:           ${CFLAGS}
  GDBM backend:     ${gdbm_enabled}
  PAM backend:      ${pam_enabled}
  TCP wrappers:     ${libwrap_enabled}
  seccomp:          ${seccomp_enabled}
])

