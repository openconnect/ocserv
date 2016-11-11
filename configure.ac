AC_PREREQ(2.61)
AC_INIT([ocserv], [0.11.5], [nmav@gnutls.org])
PKG_PROG_PKG_CONFIG
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11.1 subdir-objects no-dist-gzip dist-xz -Wall -Wno-override])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
gl_EARLY

AM_PROG_AR
AM_PROG_CC_C_O
AC_PROG_SED
if [ test "$GCC" = "yes" ];then
	CFLAGS="$CFLAGS -Wall -Wno-strict-aliasing"
fi
AC_PATH_PROG(CTAGS, ctags, [:])
AC_PATH_PROG(CSCOPE, cscope, [:])
AC_CHECK_PROG([AUTOGEN], [autogen], [autogen], [:])

AX_CODE_COVERAGE

if test x"$AUTOGEN" = "x:"; then
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

PKG_CHECK_MODULES([LIBNETTLE], [nettle >= 2.7])
PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.1.10])
AC_CHECK_LIB(gnutls, gnutls_pkcs11_reinit, [
AC_DEFINE([HAVE_PKCS11], [], [PKCS11 detected in gnutls])
])

if ! $PKG_CONFIG --atleast-version=3.0 nettle; then
	AC_DEFINE([NETTLE_OLD_BASE64_API], [1],
		  [nettle uses the pre-3.x base64 API])
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

AM_CONDITIONAL(LOCAL_PROTOBUF_C, test "x$with_local_protobuf_c" != xno)

AC_LIB_HAVE_LINKFLAGS(ev,, [#include <ev.h>], [ev_run(0,0);])
if test x$ac_cv_libev = xyes; then
	AC_SUBST([LIBEV_LIBS], [$LIBEV])
else
	AC_MSG_ERROR([[***
*** libev4 was not found.
***]])
fi

AC_ARG_WITH(root-tests,
  AS_HELP_STRING([--without-root-tests], [disable any tests requiring root/docker]),
  root_tests=$withval,
  root_tests=yes)

AM_CONDITIONAL(ENABLE_ROOT_TESTS, test "x$root_tests" = xyes)

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

if test "$with_local_talloc" = no;then
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

have_liboath=no
AC_ARG_WITH(liboath,
  AS_HELP_STRING([--without-liboath], [do not include OTP support]),
  test_for_liboath=$withval,
  test_for_liboath=yes)

if test x$test_for_liboath = xyes;then
  PKG_CHECK_MODULES([LIBOATH], [liboath], [
AC_DEFINE([HAVE_LIBOATH], 1, [Enable the liboath library])
have_liboath=yes],
[have_liboath=no])
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

PKG_CHECK_MODULES([CWRAP], [uid_wrapper, socket_wrapper], have_cwrap=yes, have_cwrap=no)
PKG_CHECK_MODULES([CWRAP_PAM], [pam_wrapper], have_cwrap_pam=yes, have_cwrap_pam=no)

if test "$have_cwrap" != no;then
	AC_DEFINE([HAVE_CWRAP], 1, [Enable testing with cwrap])
fi
AM_CONDITIONAL(HAVE_CWRAP, test "x$have_cwrap" != xno)
AM_CONDITIONAL(HAVE_CWRAP_PAM, test "x$have_cwrap_pam" != xno && test "$have_liboath" = yes && test "$pam_enabled" = yes)

AC_ARG_WITH(radius,
  AS_HELP_STRING([--without-radius], [do not include Radius support]),
  test_for_radius=$withval,
  test_for_radius=yes)

radius_enabled=no

if test "$test_for_radius" = yes;then
	PKG_CHECK_MODULES([RADCLI], [radcli >= 1.2.5], radius_enabled=radcli, radius_enabled=no)

	if test "$radius_enabled" = no;then
		LIBS="$oldlibs -lfreeradius-client"
		AC_MSG_CHECKING([for freeradius client library])
		AC_LINK_IFELSE([AC_LANG_PROGRAM([
		   #include <freeradius-client.h>],[
#ifndef PW_MAX_MSG_SIZE
#error 1
#endif
		   rc_read_config(0);])],
		  [AC_MSG_RESULT(yes)
		   AC_SUBST([RADCLI_LIBS], [-lfreeradius-client])
		   AC_SUBST([RADCLI_CFLAGS], [])
		   radius_enabled=freeradius-client
		   AC_DEFINE([LEGACY_RADIUS], 1, [Enable the legacy library support])],
		  [AC_MSG_RESULT(no)
   	           AC_MSG_WARN([[
*** 
*** radcli 1.2.1 or later was not found. Radius support will be disabled.
*** See http://radcli.github.io/radcli/
*** ]])])
		LIBS="$oldlibs"
	fi

	if test "$radius_enabled" != no;then
		AC_DEFINE([HAVE_RADIUS], 1, [Enable the Radius library])
	fi
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

AC_CHECK_FUNCS([setproctitle vasprintf clock_gettime isatty pselect ppoll getpeereid sigaltstack])
AC_CHECK_FUNCS([strlcpy posix_memalign malloc_trim strsep])

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
], [seccomp_init(0);])
 if [ test -z "$LIBSECCOMP" ];then
	seccomp_enabled="no"
 else
	seccomp_enabled="yes"
 fi
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

pager_set=0
AC_ARG_WITH(pager,
  AS_HELP_STRING([--with-pager=PAGER], [set a specific pager for occtl; use "" for no pager]),
    occtl_pager=$withval
    pager_set=1
)

if [ test $pager_set = 0 ];then
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

dnl compression
AC_ARG_ENABLE(compression,
  AS_HELP_STRING([--disable-compression], [Disable compression support]),
  enable_compression=$enableval,
  enable_compression=yes)

if test "$enable_compression" = yes;then
AC_DEFINE([ENABLE_COMPRESSION], [], [compression enabled])
fi

AM_CONDITIONAL(ENABLE_COMPRESSION, test "$enable_compression" = yes)

dnl LZ4
AC_ARG_WITH(lz4,
  AS_HELP_STRING([--without-lz4], [disable support for LZ4 compression]),
  test_for_lz4=$withval,
  test_for_lz4=yes)

enable_lz4=no

if test "$test_for_lz4" = yes && test "$enable_compression" = yes;then
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

dnl GSSAPI
AC_ARG_WITH(gssapi,
  AS_HELP_STRING([--without-gssapi], [disable support for GSSAPI authentication]),
  test_for_gssapi=$withval,
  test_for_gssapi=yes)

enable_gssapi=no
if test "$test_for_gssapi" = yes;then
PKG_CHECK_MODULES([LIBKRB5], [krb5-gssapi], [
enable_gssapi=yes
AC_DEFINE([HAVE_GSSAPI], [], [GSSAPI was found])
PKG_CHECK_MODULES(LIBTASN1, [libtasn1 >= 3.4])
],
[
	AC_MSG_WARN([[
***
*** gssapi not found. Will disable gssapi (and Kerberos) support.
*** ]])
])

fi

AM_CONDITIONAL(HAVE_GSSAPI, test "$enable_gssapi" = yes)

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

if test -f /usr/lib64/pam_wrapper/pam_matrix.so;then
	AC_SUBST([PAMWRAPDIR], [/usr/lib64/pam_wrapper])
elif test -f /usr/lib/pam_wrapper/pam_matrix.so;then
	AC_SUBST([PAMWRAPDIR], [/usr/lib/pam_wrapper])
else
	AC_SUBST([PAMWRAPDIR], [/usr/lib/pam_wrapper])
fi

if test -f /usr/lib64/security/pam_oath.so;then
	AC_SUBST([PAMDIR], [/usr/lib64/security])
elif test -f /usr/lib/security/pam_oath.so;then
	AC_SUBST([PAMDIR], [/usr/lib/security])
else
	AC_SUBST([PAMDIR], [/usr/lib/security])
fi

uid=$(id -u)
gid=$(id -g)
AC_SUBST([ROOTUID], [$uid])
AC_SUBST([ROOTGID], [$gid])

LIBOPTS_CHECK([libopts])
if test "$NEED_LIBOPTS_DIR" = "true";then
	dnl create libopts-generated files
	for i in ${srcdir}/src/*args.c.bak ${srcdir}/src/*args.h.bak ${srcdir}/src/occtl/*args.c.bak ${srcdir}/src/occtl/*args.h.bak; do
		nam=`echo $i|sed 's/.bak//g'`
		if test -f "$i";then
			cp -f $i $nam
		fi
	done
	AC_SUBST([AUTOGEN], [:])
	enable_local_libopts=yes
else
	enable_local_libopts=no
fi
AM_CONDITIONAL(NEED_LIBOPTS, test "$enable_local_libopts" = "yes")

AC_CONFIG_FILES([
	Makefile
	src/version.inc
	src/Makefile
	src/occtl/Makefile
	src/ocpasswd/Makefile
	src/ccan/Makefile
	src/common/Makefile
	src/pcl/Makefile
	src/protobuf/Makefile
	doc/Makefile
	gl/Makefile
	tests/docker-ocserv/Makefile
	tests/docker-kerberos/Makefile
	tests/data/pam/ocserv
	tests/data/pam-single/ocserv
	tests/data/pam/nss-passwd
	tests/data/pam/nss-group
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
  CWrap testing:        ${have_cwrap}
  CWrap PAM testing:    ${have_cwrap_pam}
  
  PAM auth backend:     ${pam_enabled}
  Radius auth backend:  ${radius_enabled}
  GSSAPI auth backend:  ${enable_gssapi}
  Anyconnect compat:    ${anyconnect_enabled}
  TCP wrappers:         ${libwrap_enabled}
  systemd:              ${systemd_enabled}
  (socket activation)
  seccomp:              ${seccomp_enabled}
  Compression:          ${enable_compression}
  LZ4 compression:      ${enable_lz4}
  readline:             ${have_readline}
  libnl3:               ${have_libnl3}
  liboath:              ${have_liboath}
  glibc (sha2crypt):    ${have_glibc}
  local talloc:         ${with_local_talloc}
  local protobuf-c:     ${with_local_protobuf_c}
  local PCL library:    ${with_local_pcl}
  local libopts:        ${enable_local_libopts}
  local http-parser:    ${with_local_http_parser}
])

