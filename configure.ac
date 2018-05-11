AC_PREREQ(2.61)
AC_INIT([ocserv], [0.12.1], [openconnect-devel@lists.infradead.org])
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
	CFLAGS="$CFLAGS -Wall -Wno-strict-aliasing -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers -Wno-implicit-fallthrough -Wno-stringop-truncation"
fi
AC_PATH_PROG(CTAGS, ctags, [:])
AC_PATH_PROG(CSCOPE, cscope, [:])
AC_CHECK_PROG([RONN], [ronn], [ronn], [:])

if test x"$RONN" = "x:"; then
	AC_MSG_WARN([[
***
*** ronn (ruby-ronn) was not found. Will not be able to generate manpages
*** ]])
skip_manpages=yes
fi

AM_CONDITIONAL(SKIP_MANPAGES, test "$skip_manpages" = yes)

AM_MAINTAINER_MODE([enable])
AX_CODE_COVERAGE

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
PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.3.0])

warn_leak=no
if $PKG_CONFIG --max-version=3.5.4 gnutls;then
  if $PKG_CONFIG --atleast-version=3.3.99 gnutls || $PKG_CONFIG --max-version=3.3.24 gnutls; then
    warn_leak=yes
    AC_DEFINE([GNUTLS_BROKEN_CERTIFICATE_SET_KEY], [1],
		  [gnutls has a broken gnutls_certificate_set_key()])
  fi
fi

if ! $PKG_CONFIG --atleast-version=3.0 nettle; then
	AC_DEFINE([NETTLE_OLD_BASE64_API], [1],
		  [nettle uses the pre-3.x base64 API])
fi

AM_CONDITIONAL(GNUTLS_WITH_NEW_CERTS, $PKG_CONFIG --atleast-version=3.6.0 gnutls)

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

AC_ARG_WITH(docker-tests,
  AS_HELP_STRING([--without-docker-tests], [disable any tests requiring docker]),
  docker_tests=$withval,
  docker_tests=yes)

AM_CONDITIONAL(ENABLE_DOCKER_TESTS, test "x$docker_tests" = xyes)

AC_ARG_WITH(nuttcp-tests,
  AS_HELP_STRING([--without-nuttcp-tests], [disable any tests requiring nuttcp]),
  nuttcp_tests=$withval,
  nuttcp_tests=yes)
AM_CONDITIONAL(ENABLE_NUTTCP_TESTS, test "x$nuttcp_tests" = xyes)

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

AC_ARG_WITH(geoip,
  AS_HELP_STRING([--without-geoip], [do not try to use the geoip library]),
  test_for_geoip=$withval,
  test_for_geoip=yes)

have_geoip=no
if test "$test_for_geoip" = yes;then
  PKG_CHECK_MODULES(GEOIP, geoip >= 1.6.0, [have_geoip=yes], [have_geoip=no])
  if test "$have_geoip" = yes;then
    AC_DEFINE(HAVE_GEOIP, 1, [have libgeoip])
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

AM_CONDITIONAL(HAVE_LIBOATH, test "x$have_liboath" != xno)

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
oldlibs=$LIBS
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
PKG_CHECK_MODULES([CWRAP_NSS], [nss_wrapper], have_cwrap_nss=yes, have_cwrap_nss=no)

if test "$have_cwrap" != no;then
	AC_DEFINE([HAVE_CWRAP], 1, [Enable testing with cwrap])
fi
AM_CONDITIONAL(HAVE_CWRAP, test "x$have_cwrap" != xno)
AM_CONDITIONAL(HAVE_CWRAP_PAM, test "x$have_cwrap_pam" != xno && test "$have_liboath" = yes && test "$pam_enabled" = yes)
AM_CONDITIONAL(HAVE_CWRAP_ALL, test "x$have_cwrap_nss" != xno && test "x$have_cwrap_pam")

AC_ARG_WITH(radius,
  AS_HELP_STRING([--without-radius], [do not include Radius support]),
  test_for_radius=$withval,
  test_for_radius=yes)

radius_enabled=no

if test "$test_for_radius" = yes;then
	PKG_CHECK_MODULES([RADCLI], [radcli >= 1.2.5], radius_enabled=radcli, radius_enabled=no)

	if test "$radius_enabled" = no;then
		oldlibs=$LIBS
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

AC_CHECK_HEADERS([net/if_tun.h linux/if_tun.h netinet/in_systm.h crypt.h], [], [], [])

AC_CHECK_FUNCS([setproctitle vasprintf clock_gettime isatty pselect ppoll getpeereid sigaltstack])
AC_CHECK_FUNCS([strlcpy posix_memalign malloc_trim strsep])

if [ test -z "$LIBWRAP" ];then
	libwrap_enabled="no"
else
	libwrap_enabled="yes"
fi

isolation="none"

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
	isolation="seccomp"
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
oldlibs=$LIBS
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
oldlibs=$LIBS
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

AC_ARG_WITH(werror,
  AS_HELP_STRING([--with-werror], [fail on gcc warnings]),
  [src_cflags="-Werror"], [])
AC_SUBST([SRC_CFLAGS], [${src_cflags}])

dnl config options for inih
AC_DEFINE([INI_STOP_ON_FIRST_ERROR], [1], [inih configuration])
AC_DEFINE([INI_INLINE_COMMENT_PREFIXES], ["#"], [inih configuration])
AC_DEFINE([INI_ALLOW_MULTILINE], [1], [inih configuration])

if test "$have_cwrap_pam" = yes; then
	m4_ifdef([PKG_CHECK_VAR], [PKG_CHECK_VAR([CWRAP_PAM_MODULES], [pam_wrapper], [modules])])

	if test -f $CWRAP_PAM_MODULES/pam_matrix.so;then
		AC_SUBST([PAMWRAPDIR], [$CWRAP_PAM_MODULES])
	elif test -f /usr/lib64/pam_wrapper/pam_matrix.so;then
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
	elif test -f /lib/security/pam_oath.so;then
		AC_SUBST([PAMDIR], [/lib/security])
	else
		AC_SUBST([PAMDIR], [/usr/lib/security])
	fi
fi

uid=$(id -u)
gid=$(id -g)
AC_SUBST([ROOTUID], [$uid])
AC_SUBST([ROOTGID], [$gid])

AC_CONFIG_FILES([
	Makefile
	src/version.inc
	src/Makefile
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
  CWrap NSS testing:    ${have_cwrap_nss}
  
  PAM auth backend:     ${pam_enabled}
  Radius auth backend:  ${radius_enabled}
  GSSAPI auth backend:  ${enable_gssapi}
  Anyconnect compat:    ${anyconnect_enabled}
  TCP wrappers:         ${libwrap_enabled}
  systemd:              ${systemd_enabled}
  (socket activation)
  worker isolation:     ${isolation}
  Compression:          ${enable_compression}
  LZ4 compression:      ${enable_lz4}
  readline:             ${have_readline}
  libnl3:               ${have_libnl3}
  liboath:              ${have_liboath}
  libgeoip:             ${have_geoip}
  glibc (sha2crypt):    ${have_glibc}
  local talloc:         ${with_local_talloc}
  local protobuf-c:     ${with_local_protobuf_c}
  local PCL library:    ${with_local_pcl}
  local http-parser:    ${with_local_http_parser}
])

if test "${warn_leak}" = "yes";then
    AC_MSG_WARN([[***
*** a broken version of gnutls was found; will work around but server will leak memory;
*** please update to the latest version of a supported gnutls branch (e.g. as 3.3.x, 3.5.x, or 3.6.x)
*** for better server performance.
***]])
fi

if test "x${isolation}" = xnone;then
	AC_MSG_WARN([[
***
*** No supported worker isolation system was found. Worker processes
*** will not be isolated. Only seccomp is supported (see src/worker-privs.c)
*** ]])
fi


