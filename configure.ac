AC_PREREQ(2.61)
AC_INIT([ocserv], [0.9.1], [nmav@gnutls.org])
PKG_PROG_PKG_CONFIG
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([gl/m4])

AM_INIT_AUTOMAKE([1.11.3 subdir-objects no-dist-gzip dist-xz -Wall -Wno-override])
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

AC_CHECK_TYPES([sighandler_t, sig_t, __sighandler_t],,,
[#include <sys/types.h>
#include <signal.h> ])

AC_CHECK_TYPES([struct ucred],,,
[#include <sys/socket.h>
#include <sys/un.h>])

AC_CHECK_MEMBERS([struct iphdr.ihl], [],
             [],
             [[#include <netinet/ip.h>]])

AC_CHECK_SIZEOF([unsigned long])
AC_C_BIGENDIAN

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.1.10])
AC_CHECK_LIB(gnutls, gnutls_pkcs11_reinit, [
AC_DEFINE([HAVE_PKCS11], [], [PKCS11 detected in gnutls])
])

dbus_enabled=no
AC_ARG_WITH(dbus,
  AS_HELP_STRING([--with-dbus], [use dbus instead of unix sockets (dbus support is incomplete)]),
  test_for_dbus=$withval,
  test_for_dbus=no)

if test "$test_for_dbus" = yes;then
PKG_CHECK_MODULES([LIBDBUS], [dbus-1 >= 1.1.1],
dbus_enabled=yes
AC_DEFINE([HAVE_DBUS], [], [dbus detected]),
[dbus_enabled=no])
fi

AM_CONDITIONAL(HAVE_DBUS, test "x$dbus_enabled" != xno)

if test "x$dbus_enabled" != xno;then
dbus_conf_dir=$($PKG_CONFIG dbus-1 --variable=sysconfdir)
AC_SUBST(DBUS_CONFIG_DIR, [$dbus_conf_dir/etc/dbus-1/system.d/])
fi

AC_ARG_WITH(protobuf,
  AS_HELP_STRING([--without-protobuf], [use the included protobuf library]),
  test_for_protobuf=$withval,
  test_for_protobuf=yes)

with_local_protobuf_c=yes
if test "$test_for_protobuf" = yes;then
PKG_CHECK_MODULES([LIBPROTOBUF_C], [libprotobuf-c],
with_local_protobuf_c=no
,
[AC_LIB_HAVE_LINKFLAGS(protobuf-c,, [#include <protobuf-c/protobuf-c.h>], [protobuf_c_message_pack(0,0);])
 if test x$ac_cv_libprotobuf_c = xyes; then
  AC_SUBST([LIBPROTOBUF_C_LIBS], [$LIBPROTOBUF_C])
  with_local_protobuf_c=no
 else
  AC_MSG_WARN([[***
*** libprotobuf-c was not found.
***]])
 fi
]
)
fi

if test "$with_local_protobuf_c" != no;then
  FLAGS='-Iprotobuf'
  AC_SUBST([LIBPROTOBUF_C_CFLAGS], [$FLAGS])
fi

AM_CONDITIONAL(LOCAL_PROTOBUF_C, test "x$with_local_protobuf_c" != xno)


AC_ARG_WITH(local-talloc,
  AS_HELP_STRING([--with-local-talloc], [use the included talloc library]),
  no_test_for_talloc=$withval,
  no_test_for_talloc=no)

with_local_talloc=yes
if test "$no_test_for_talloc" != yes;then
PKG_CHECK_MODULES([LIBTALLOC], [talloc],
with_local_talloc=no,
[AC_LIB_HAVE_LINKFLAGS(talloc,, [#include <talloc.h>], [talloc_size(0,0);])
 if test x$ac_cv_libtalloc = xyes; then
  AC_SUBST([LIBTALLOC_LIBS], [$LIBTALLOC])
  with_local_talloc=no
 else
  AC_MSG_WARN([[***
*** libtalloc was not found.
***]])
 fi
]
)
fi

if test "$with_local_talloc" != no;then
FLAGS='-Iccan/talloc/ -Iccan/typedef_cb/ -Iccan/compiler/'
AC_SUBST([LIBTALLOC_CFLAGS], [$FLAGS])
else
AC_DEFINE(HAVE_LIBTALLOC, 1, [have libtalloc])
fi

AM_CONDITIONAL(LOCAL_TALLOC, test "x$with_local_talloc" != xno)


AC_ARG_WITH(libnl,
  AS_HELP_STRING([--without-libnl], [do not try to use the libnl library]),
  test_for_libnl=$withval,
  test_for_libnl=yes)

if test "$test_for_libnl" = yes;then
  PKG_CHECK_MODULES(LIBNL3, libnl-route-3.0 >= 3.1, [have_libnl3=yes], [have_libnl3=no])
  if test "${have_libnl3}" = "yes"; then
    AC_DEFINE(HAVE_LIBNL, 1, [have libnl])
  fi
fi

have_readline=no
AC_LIB_HAVE_LINKFLAGS(readline,, [
#include <stdio.h>
#include <readline/readline.h>], [rl_replace_line(0,0);])
  if test x$ac_cv_libreadline = xyes; then
    AC_SUBST(LIBREADLINE_LIBS, [$LIBREADLINE])
    AC_DEFINE(HAVE_ORIG_READLINE, 1, [have original readline])
    have_readline=yes
  else
    PKG_CHECK_MODULES(LIBREADLINE, libedit, [have_libedit=yes], [have_libedit=no])
    if test "${have_libedit}" = "no"; then
      AC_MSG_WARN([[***
*** libreadline or editline was not found. occtl will not be built.
***]])
    else
      have_readline=editline
    fi
  fi

have_glibc=no
AC_LIB_HAVE_LINKFLAGS(c,, [
#include <stdio.h>
#include <gnu/libc-version.h>
#include <stdio.h>], [ puts (gnu_get_libc_version ()); return 0; ])
if test x$ac_cv_libc = xyes; then
  AC_DEFINE(TRY_SHA2_CRYPT, 1, [have original glibc])
  have_glibc=yes
else
  have_glibc=no
fi

AC_ARG_WITH(pam,
  AS_HELP_STRING([--without-pam], [do not include PAM support]),
  test_for_pam=$withval,
  test_for_pam=yes)

pam_enabled=no

if test "$test_for_pam" = yes;then
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
fi

AC_ARG_WITH(radius,
  AS_HELP_STRING([--without-radius], [do not include Radius support]),
  test_for_radius=$withval,
  test_for_radius=yes)

radius_enabled=no

if test "$test_for_radius" = yes;then
LIBS="$oldlibs -lfreeradius-client"
AC_MSG_CHECKING([for freeradius client library])
AC_LINK_IFELSE([AC_LANG_PROGRAM([
		   #include <freeradius-client.h>],[
#ifndef PW_MAX_MSG_SIZE
#error 1
#endif
		   rc_read_config(0);])],
		  [AC_MSG_RESULT(yes)
		   AC_SUBST([FREERADIUS_CLIENT_LIBS], [-lfreeradius-client])
		   AC_SUBST([FREERADIUS_CLIENT_CFLAGS], [])
		   radius_enabled=yes
		   AC_DEFINE([HAVE_RADIUS], 1, [Enable the Radius library])],
		  [AC_MSG_RESULT(no)
   	           AC_MSG_WARN([[
*** 
*** freeradius-client 1.1.7 or later was not found. Radius support will be disabled.
*** ]])])
LIBS="$oldlibs"
fi

gl_INIT

AC_LIB_HAVE_LINKFLAGS(crypt,, [#define _XOPEN_SOURCE
#include <unistd.h>], [crypt(0,0);])

AC_ARG_WITH(utmp,
  AS_HELP_STRING([--without-utmp], [do not use libutil for utmp support]),
  test_for_utmp=$withval,
  test_for_utmp=yes)

if test "$test_for_utmp" = yes;then
AC_LIB_HAVE_LINKFLAGS(util,, [#include <utmpx.h>], [pututxline(0);])
fi


# Test for libwrap
AC_ARG_WITH(libwrap,
  AS_HELP_STRING([--without-libwrap], [do not use libwrap]),
  test_for_libwrap=$withval,
  test_for_libwrap=yes)

dnl Test for PCL library
with_local_pcl=yes

if test "$test_for_libwrap" = yes;then
AC_LIB_HAVE_LINKFLAGS(wrap,, [#include <tcpd.h>], [hosts_access(allow_severity);])
fi

# test for other types

AC_CHECK_MEMBER([struct sockaddr.sa_len],
[AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1, [Do we have sockaddr.sa_len?])], [],
[
#include <sys/types.h>
#include <sys/socket.h>
])

AC_CHECK_HEADERS([net/if_tun.h linux/if_tun.h netinet/in_systm.h], [], [], [])

AC_CHECK_FUNCS([setproctitle vasprintf clock_gettime isatty pselect getpeereid sigaltstack])
AC_CHECK_FUNCS([strlcpy posix_memalign malloc_trim])

if [ test -z "$LIBWRAP" ];then
	libwrap_enabled="no"
else
	libwrap_enabled="yes"
fi

AC_ARG_ENABLE(seccomp,
  AS_HELP_STRING([--disable-seccomp], [disable seccomp support]),
    seccomp_enabled=$enableval, seccomp_enabled=yes)

if [ test "$seccomp_enabled" = "yes" ];then
AC_LIB_HAVE_LINKFLAGS(seccomp,, [#include <seccomp.h>
#if !defined(__i386__) && !defined(__arm__) && !defined(__x86_64__)
# error 1
#endif
], [seccomp_init(0);])
 if [ test -z "$LIBSECCOMP" ];then
	seccomp_enabled="no"
 else
	seccomp_enabled="yes"
 fi
fi

AC_ARG_ENABLE(linux-namespaces,
  AS_HELP_STRING([--enable-linux-namespaces], [enable support for namespaces (containers) in Linux]),
    linux_ns_enabled=$enableval, linux_ns_enabled=no)

if [ test "$linux_ns_enabled" = "yes" ];then
AC_MSG_CHECKING([for Linux namespaces])
dnl We use Linux namespaces only in the platforms clone() works as expected
AC_LINK_IFELSE([AC_LANG_PROGRAM([
		   #include <sched.h>
		   #include <linux/sched.h>],[
		   #if defined(__i386__) || defined(__arm__) || defined(__x86_64__) || defined(__mips__)
		   unshare(CLONE_NEWPID|CLONE_NEWIPC);
		   #else
		   # error 1
		   #endif])],
		  [AC_MSG_RESULT(yes)
	  	   AC_DEFINE([ENABLE_LINUX_NS], 1, [Enable Linux namespaces support])
		   linux_ns_enabled=yes],
		  [AC_MSG_RESULT(no)
		   linux_ns_enabled=no
])
fi

AC_ARG_ENABLE(systemd,
  AS_HELP_STRING([--disable-systemd], [disable systemd support]),
    systemd_enabled=$enableval, systemd_enabled=yes)

if [ test "$systemd_enabled" = "yes" ];then
AC_LIB_HAVE_LINKFLAGS(systemd,, [#include <systemd/sd-daemon.h>], [sd_listen_fds(0);])
 if [ test -z "$LIBSYSTEMD" ];then
	systemd_enabled="no"
 else
	systemd_enabled="yes"
 fi
fi

AC_ARG_ENABLE(anyconnect-compat,
  AS_HELP_STRING([--disable-anyconnect-compat], [disable Anyconnect client compatibility (experimental)]),
    anyconnect_enabled=$enableval, anyconnect_enabled=yes)
if [ test "$anyconnect_enabled" = "yes" ];then
	AC_DEFINE([ANYCONNECT_CLIENT_COMPAT], [], [Enable Anyconnect compatibility])
fi

AC_ARG_WITH(pager,
  AS_HELP_STRING([--with-pager=PAGER], [set a specific pager for occtl]),
    occtl_pager=$withval)
if [ test -z "$occtl_pager" ];then
	AC_DEFINE_UNQUOTED([OCCTL_PAGER], ["less"], [The default pager for occtl])
else
	AC_DEFINE_UNQUOTED([OCCTL_PAGER], ["$occtl_pager"], [The default pager for occtl])
fi

AC_ARG_WITH(http-parser,
  AS_HELP_STRING([--without-http-parser], [use the included http parser]),
  test_for_http_parser=$withval,
  test_for_http_parser=yes)

dnl Test for http_parser library
with_local_http_parser=yes

if test "$test_for_http_parser" = yes;then
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
fi
AM_CONDITIONAL(LOCAL_HTTP_PARSER, test "x$with_local_http_parser" != xno)

dnl LZ4
AC_ARG_WITH(lz4,
  AS_HELP_STRING([--without-lz4], [disable support for LZ4 compression]),
  test_for_lz4=$withval,
  test_for_lz4=yes)

enable_lz4=no
if test "$test_for_lz4" = yes;then
PKG_CHECK_MODULES([LIBLZ4], [liblz4], [
enable_lz4=yes
AC_DEFINE([HAVE_LZ4], [], [LZ4 was found])
],
[
	AC_MSG_WARN([[
***
*** lz4 not found. Will disable compression support.
*** ]])
])
fi

dnl needed in the included PCL
AC_C_VOLATILE
AC_C_CONST
AC_CHECK_FUNCS(memset malloc free)
AC_CHECK_FUNCS(makecontext getcontext swapcontext)
AC_CHECK_FUNCS(sigaction)
AC_CHECK_FUNCS(longjmp setjmp)
AC_CHECK_FUNCS(sigaltstack)

AC_ARG_WITH(pcl-lib,
  AS_HELP_STRING([--without-pcl-lib], [use the included PCL library]),
  test_for_pcl_lib=$withval,
  test_for_pcl_lib=yes)

dnl Test for PCL library
with_local_pcl=yes

if test "$test_for_pcl_lib" = yes;then
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
fi
AM_CONDITIONAL(PCL, test "$with_local_pcl" = no)


LIBOPTS_CHECK([libopts])
if test "$NEED_LIBOPTS_DIR" = "true";then
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
	tests/docker-ocserv/Makefile
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
  Radius auth backend:  ${radius_enabled}
  Anyconnect compat:    ${anyconnect_enabled}
  TCP wrappers:         ${libwrap_enabled}
  systemd:              ${systemd_enabled}
  (socket activation)
  seccomp:              ${seccomp_enabled}
  LZ4 compression:      ${enable_lz4}
  readline:             ${have_readline}
  libnl3:               ${have_libnl3}
  glibc (sha2crypt):    ${have_glibc}
  local talloc:         ${with_local_talloc}
  local protobuf-c:     ${with_local_protobuf_c}
  local PCL library:    ${with_local_pcl}
  local libopts:        ${enable_local_libopts}
  local http-parser:    ${with_local_http_parser}
])

AC_MSG_NOTICE([

Experimental (not recommended) options:
  Linux namespaces:     ${linux_ns_enabled}
  dbus:                 ${dbus_enabled}
])

