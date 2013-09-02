AC_PREREQ(2.61)
AC_INIT([ocserv], [0.1.6], [nmav@gnutls.org])
PKG_PROG_PKG_CONFIG
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11.3 no-dist-gzip dist-xz dist-lzip -Wall -Wno-override])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
gl_EARLY

AM_PROG_AR
AM_PROG_CC_C_O
if [ test "$GCC" = "yes" ];then
	CFLAGS="$CFLAGS -Wall"
fi
AC_PATH_PROG(CTAGS, ctags, /bin/true)
AC_PATH_PROG(CSCOPE, cscope, /bin/true)
AC_PATH_PROG(AUTOGEN, autogen, /bin/true)

if test x"$AUTOGEN" = "x/bin/true"; then
	AC_MSG_WARN([[
***
*** autogen not found.  We will not build manpages.
*** ]])
fi

AC_CHECK_SIZEOF([unsigned long])
AC_C_BIGENDIAN

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.1.10])
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

AC_LIB_HAVE_LINKFLAGS(crypt,, [#include <unistd.h>], [crypt(0,0);])
AC_LIB_HAVE_LINKFLAGS(util,, [#include <utmpx.h>], [pututxline(0);])
AC_LIB_HAVE_LINKFLAGS(wrap,, [#include <tcpd.h>], [hosts_access(0);])
AC_CHECK_MEMBER([struct sockaddr.sa_len],
[AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1, [Do we have sockaddr.sa_len?])], [],
[
#include <sys/types.h>
#include <sys/socket.h>
])

AC_CHECK_FUNCS([setproctitle clock_gettime])

if [ test -z "$LIBWRAP" ];then
	libwrap_enabled="no"
else
	libwrap_enabled="yes"
fi

AC_ARG_ENABLE(seccomp,
  AS_HELP_STRING([--enable-seccomp], [enable seccomp support]),
    seccomp_enabled=$enableval, seccomp_enabled=no)

if [ test "$seccomp_enabled" = "yes" ];then
AC_LIB_HAVE_LINKFLAGS(seccomp,, [#include <seccomp.h>], [seccomp_init(0);])
if [ test -z "$LIBSECCOMP" ];then
	seccomp_enabled="no"
else
	seccomp_enabled="yes"
fi
fi

AC_ARG_ENABLE(anyconnect-compat,
  AS_HELP_STRING([--disable-anyconnect-compat], [disable Anyconnect client compatibility (experimental)]),
    anyconnect_enabled=$enableval, anyconnect_enabled=yes)
if [ test "$anyconnect_enabled" = "yes" ];then
	AC_DEFINE([ANYCONNECT_CLIENT_COMPAT], [], [Enable Anyconnect compatibility])
fi

dnl needed in the included PCL
AC_C_VOLATILE
AC_C_CONST
AC_CHECK_FUNCS(memset malloc free)
AC_CHECK_FUNCS(makecontext getcontext swapcontext)
AC_CHECK_FUNCS(sigaction)
AC_CHECK_FUNCS(longjmp setjmp)
AC_CHECK_FUNCS(sigaltstack)

pcl_enabled=no
LIBS="$oldlibs -lpcl"
AC_MSG_CHECKING([for pcl library])
AC_LINK_IFELSE([AC_LANG_PROGRAM([
		   #include <pcl.h>],[
		   co_create(0, 0, 0, 0);])],
		  [AC_MSG_RESULT(yes)
		   AC_SUBST([PCL_LIBS], [-lpcl])
		   AC_SUBST([PCL_CFLAGS], [])
		   pcl_enabled=yes],
		  [AC_MSG_RESULT(no)
   	           AC_MSG_WARN([[
*** 
*** libpcl (portable co-routines) was not found.
*** An included version of the library will be used.
*** ]])])
LIBS="$oldlibs"

AM_CONDITIONAL(PCL, test "$pcl_enabled" = yes)

enable_local_libopts=yes
NEED_LIBOPTS_DIR=true
LIBOPTS_CHECK([libopts])

AC_CONFIG_FILES([
	Makefile
	src/version.inc
	src/Makefile
	src/pcl/Makefile
	doc/Makefile
	gl/Makefile
	tests/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([
Summary of build options:
  version:              ${VERSION}
  Host type:            ${host}
  Install prefix:       ${prefix}
  Compiler:             ${CC}
  CFlags:               ${CFLAGS}

  GDBM storage backend: ${gdbm_enabled}
  PAM auth backend:     ${pam_enabled}
  TCP wrappers:         ${libwrap_enabled}
  PCL library:          ${pcl_enabled}

Experimental options:
  seccomp:              ${seccomp_enabled}
  Anyconnect compat:    ${anyconnect_enabled}
])

