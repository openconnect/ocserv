AC_PREREQ(2.61)
AC_INIT([ocserv], [0.2.1], [nmav@gnutls.org])
PKG_PROG_PKG_CONFIG
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([gl/m4])

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
AC_CHECK_PROG([AUTOGEN], [autogen], [autogen], [/bin/true])

if test x"$AUTOGEN" = "x/bin/true"; then
	AC_MSG_WARN([[
***
*** autogen not found. Will not link against libopts.
*** ]])
enable_local_libopts=yes
fi

AC_CHECK_SIZEOF([unsigned long])
AC_C_BIGENDIAN

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.1.10])
AC_CHECK_LIB(gnutls, gnutls_pkcs11_reinit, [
AC_DEFINE([HAVE_PKCS11], [], [PKCS11 detected in gnutls])
])

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

dnl Test for http_parser library
with_local_http_parser=yes
LIBS="$oldlibs -lhttp_parser"
AC_MSG_CHECKING([for http_parser library])
AC_LINK_IFELSE([AC_LANG_PROGRAM([
		   #include <http_parser.h>],[
		   http_parser_init(0, 0);])],
		  [AC_MSG_RESULT(yes)
		   AC_SUBST([HTTP_PARSER_LIBS], [-lhttp_parser])
		   AC_SUBST([HTTP_PARSER_CFLAGS], [])
		   with_local_http_parser=no],
		  [AC_MSG_RESULT(no)
  	           AC_MSG_WARN([[
*** 
*** libhttp-parser not found.
*** An included version of the library will be used.
*** ]])])
LIBS="$oldlibs"
AM_CONDITIONAL(LOCAL_HTTP_PARSER, test "x$with_local_http_parser" != xno)


dnl needed in the included PCL
AC_C_VOLATILE
AC_C_CONST
AC_CHECK_FUNCS(memset malloc free)
AC_CHECK_FUNCS(makecontext getcontext swapcontext)
AC_CHECK_FUNCS(sigaction)
AC_CHECK_FUNCS(longjmp setjmp)
AC_CHECK_FUNCS(sigaltstack)


dnl Test for PCL library
with_local_pcl=yes
LIBS="$oldlibs -lpcl"
AC_MSG_CHECKING([for pcl library])
AC_LINK_IFELSE([AC_LANG_PROGRAM([
		   #include <pcl.h>],[
		   co_create(0, 0, 0, 0);])],
		  [AC_MSG_RESULT(yes)
		   AC_SUBST([PCL_LIBS], [-lpcl])
		   AC_SUBST([PCL_CFLAGS], [])
		   with_local_pcl=no],
		  [AC_MSG_RESULT(no)
  	           AC_MSG_WARN([[
*** 
*** libpcl (portable co-routines) was not found.
*** An included version of the library will be used.
*** ]])])
LIBS="$oldlibs"
AM_CONDITIONAL(PCL, test "$with_local_pcl" = no)


LIBOPTS_CHECK([libopts])
if test "$NEED_LIBOPTS_DIR" == "true";then
	dnl create libopts-generated files
	for i in ${srcdir}/src/*-args.c.bak ${srcdir}/src/*-args.h.bak; do
		nam=`echo $i|sed 's/.bak//g'`
		if [ test -f $i ];then
			cp -f $i $nam
		fi
	done
	AC_SUBST([AUTOGEN], [/bin/true])
	enable_local_libopts=yes
else
	enable_local_libopts=no
fi
AM_CONDITIONAL(NEED_LIBOPTS, test "$enable_local_libopts" = "yes")

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
  
  PAM auth backend:     ${pam_enabled}
  TCP wrappers:         ${libwrap_enabled}
  local PCL library:    ${with_local_pcl}
  local libopts:        ${enable_local_libopts}
  local http-parser:    ${with_local_http_parser}

Experimental options:
  seccomp:              ${seccomp_enabled}
  Anyconnect compat:    ${anyconnect_enabled}
])

