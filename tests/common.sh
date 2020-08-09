#!/bin/bash
#
# Copyright (C) 2011-2013 Free Software Foundation, Inc.
# Copyright 2013 Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
#
# The launch_server() function was contributed by Cedric Arbogast.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

builddir=${builddir:-.}

OPENCONNECT=${OPENCONNECT:-$(which openconnect)}

if test -z "${OPENCONNECT}" || ! test -x ${OPENCONNECT};then
	echo "You need openconnect to run this test"
	exit 1
fi

if test "${DISABLE_ASAN_BROKEN_TESTS}" = 1;then
	echo "Disabling worker isolation to enable asan"
	ISOLATE_WORKERS=false
fi

if test -z "$NO_NEED_ROOT";then
	if test "$(id -u)" != "0";then
		echo "You need to run this script as root"
		exit 77
	fi
else
	if test "${DISABLE_ASAN_BROKEN_TESTS}" = 1;then
		echo "Skipping test requiring ldpreload"
		exit 77
	fi
	SOCKDIR="${srcdir}/tmp/sockwrap.$$.tmp"
	mkdir -p $SOCKDIR
	export SOCKET_WRAPPER_DIR=$SOCKDIR
	export SOCKET_WRAPPER_DEFAULT_IFACE=2
	export NSS_WRAPPER_HOSTS="${srcdir}/data/vhost.hosts"
	ADDRESS=127.0.0.$SOCKET_WRAPPER_DEFAULT_IFACE
	RAW_OPENCONNECT="${OPENCONNECT}"
	OPENCONNECT="eval LD_PRELOAD=libsocket_wrapper.so ${OPENCONNECT}"
fi

update_config() {
	file=$1
	username=$(whoami)
	group=$(groups|cut -f 1 -d ' ')

	if test -z "${ISOLATE_WORKERS}";then
		if test "${COVERAGE}" = "1";then
			ISOLATE_WORKERS=false
		else
			ISOLATE_WORKERS=true
		fi
	fi

	cp "${srcdir}/data/${file}" "$file.$$.tmp"
	sed -i -e 's|@USERNAME@|'${username}'|g' "$file.$$.tmp" \
	       -e 's|@GROUP@|'${group}'|g' "$file.$$.tmp" \
	       -e 's|@SRCDIR@|'${srcdir}'|g' "$file.$$.tmp" \
	       -e 's|@ISOLATE_WORKERS@|'${ISOLATE_WORKERS}'|g' "$file.$$.tmp" \
	       -e 's|@OTP_FILE@|'${OTP_FILE}'|g' "$file.$$.tmp" \
	       -e 's|@CRLNAME@|'${CRLNAME}'|g' "$file.$$.tmp" \
	       -e 's|@PORT@|'${PORT}'|g' "$file.$$.tmp" \
	       -e 's|@ADDRESS@|'${ADDRESS}'|g' "$file.$$.tmp" \
	       -e 's|@VPNNET@|'${VPNNET}'|g' "$file.$$.tmp" \
	       -e 's|@VPNNET6@|'${VPNNET6}'|g' "$file.$$.tmp" \
	       -e 's|@ROUTE1@|'${ROUTE1}'|g' "$file.$$.tmp" \
	       -e 's|@ROUTE2@|'${ROUTE2}'|g' "$file.$$.tmp" \
	       -e 's|@MATCH_CIPHERS@|'${MATCH_CIPHERS}'|g' "$file.$$.tmp" \
	       -e 's|@OCCTL_SOCKET@|'${OCCTL_SOCKET}'|g' "$file.$$.tmp" \
	       -e 's|@LISTEN_NS@|'${LISTEN_NS}'|g' "$file.$$.tmp"
	CONFIG="$file.$$.tmp"
}

fail() {
   PID=$1
   shift;
   echo "Failure: $1" >&2
   kill $PID
   exit 1
}

launch_server() {
	if test -n "${VERBOSE}" && test "${VERBOSE}" -ge 1;then
	    $SERV $* -d 3 &
	else
	    $SERV $* >/dev/null 2>&1 &
	fi
	LOCALPID="$!";
	trap "[ ! -z \"${LOCALPID}\" ] && kill ${LOCALPID};" 15
	wait "${LOCALPID}"
	LOCALRET="$?"
	if [ "${LOCALRET}" != "0" ] && [ "${LOCALRET}" != "143" ] ; then
		 # Houston, we'v got a problem...
		 exit 1
	fi
}

launch_sr_server() {
	if test -n "${VERBOSE}" && test "${VERBOSE}" -ge 1;then
		LD_PRELOAD=libsocket_wrapper.so:libuid_wrapper.so UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $SERV $* -d 3 &
	else
		LD_PRELOAD=libsocket_wrapper.so:libuid_wrapper.so UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $SERV $* >/dev/null 2>&1 &
	fi
	LOCALPID="$!";
	trap "[ ! -z \"${LOCALPID}\" ] && kill ${LOCALPID};" 15
	wait "${LOCALPID}"
	LOCALRET="$?"
	if [ "${LOCALRET}" != "0" ] && [ "${LOCALRET}" != "143" ] ; then
		 # Houston, we'v got a problem...
		 exit 1
	fi
}

launch_pam_server() {
	test -z "${TEST_PAMDIR}" && exit 2
	export PAM_WRAPPER_DEBUGLEVEL=3
	export PAM_WRAPPER_SERVICE_DIR="${builddir}/pam.$$.tmp/"
	mkdir -p "${PAM_WRAPPER_SERVICE_DIR}"
	test -f "${srcdir}/${TEST_PAMDIR}/users.oath.templ" && cp "${srcdir}/${TEST_PAMDIR}/users.oath.templ" "${PAM_WRAPPER_SERVICE_DIR}/users.oath"
	test -f "${srcdir}/${TEST_PAMDIR}/passdb.templ" && cp "${srcdir}/${TEST_PAMDIR}/passdb.templ" "${PAM_WRAPPER_SERVICE_DIR}/passdb"
	if test -f "${builddir}/${TEST_PAMDIR}/ocserv";then
		cp "${builddir}/${TEST_PAMDIR}/ocserv" "${PAM_WRAPPER_SERVICE_DIR}/"
	else
		cp "${builddir}/data/pam/ocserv" "${PAM_WRAPPER_SERVICE_DIR}/"
	fi
	sed -i -e 's|%PAM_WRAPPER_SERVICE_DIR%|'${PAM_WRAPPER_SERVICE_DIR}'|g' "${PAM_WRAPPER_SERVICE_DIR}/ocserv"

	cp "${builddir}/data/pam/nss-passwd" "${PAM_WRAPPER_SERVICE_DIR}/"
	cp "${builddir}/data/pam/nss-group" "${PAM_WRAPPER_SERVICE_DIR}/"
	export NSS_WRAPPER_PASSWD=${PAM_WRAPPER_SERVICE_DIR}/nss-passwd
	export NSS_WRAPPER_GROUP=${PAM_WRAPPER_SERVICE_DIR}/nss-group
	if test "$SOCKET_WRAPPER" != 0;then
		SR="libsocket_wrapper.so:"
	fi
	if test -n "${VERBOSE}" && test "${VERBOSE}" -ge 1;then
		LD_PRELOAD=libnss_wrapper.so:${SR}libpam_wrapper.so:libuid_wrapper.so PAM_WRAPPER=1 UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $PRELOAD_CMD $SERV $* &
	else
		LD_PRELOAD=libnss_wrapper.so:${SR}libpam_wrapper.so:libuid_wrapper.so PAM_WRAPPER=1 UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $PRELOAD_CMD $SERV $* >/dev/null 2>&1 &
	fi
	LOCALPID="$!";
	unset NSS_WRAPPER_PASSWD
	unset NSS_WRAPPER_GROUP
	trap "[ ! -z \"${LOCALPID}\" ] && kill ${LOCALPID};" 15
	wait "${LOCALPID}"
	LOCALRET="$?"
	if [ "${LOCALRET}" != "0" ] && [ "${LOCALRET}" != "143" ] ; then
		 # Houston, we'v got a problem...
		 exit 1
	fi
}

launch_sr_pam_server() {
	SOCKET_WRAPPER=1 launch_pam_server $*
}

launch_simple_sr_server() {
	if test -n "${VERBOSE}" && test "${VERBOSE}" -ge 1;then
		LD_PRELOAD=libsocket_wrapper.so:libuid_wrapper.so UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $SERV $* -d 3 &
	else
		LD_PRELOAD=libsocket_wrapper.so:libuid_wrapper.so UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $SERV $* >/dev/null 2>&1 &
	fi
}

launch_simple_server() {
	if test -n "${VERBOSE}" && test "${VERBOSE}" -ge 1;then
		$PRELOAD_CMD $SERV $* &
	else
		$PRELOAD_CMD $SERV $* >/dev/null 2>&1 &
	fi
}

launch_debug_server() {
	valgrind --leak-check=full $SERV $* >out.txt 2>&1 &
	LOCALPID="$!";
	trap "[ ! -z \"${LOCALPID}\" ] && kill ${LOCALPID};" 15
	wait "${LOCALPID}"
	LOCALRET="$?"
	if [ "${LOCALRET}" != "0" ] && [ "${LOCALRET}" != "143" ] ; then
		 # Houston, we'v got a problem...
		 exit 1
	fi
}

wait_server() {
	trap "kill $1" 1 15 2
	sleep 5
}

cleanup() {
	ret=0
	kill $PID
	if test $? != 0;then
		ret=1
	fi
	wait
	test -n "${PAM_WRAPPER_SERVICE_DIR}" && rm -rf ${PAM_WRAPPER_SERVICE_DIR}
	test -n "${SOCKDIR}" && rm -rf ${SOCKDIR}
	rm -f ${CONFIG}
	return $ret
}

# Check for a utility to list ports.  Both ss and netstat will list
# ports for normal users, and have similar semantics, so put the
# command in the caller's PFCMD, or exit, indicating an unsupported
# test.  Prefer ss from iproute2 over the older netstat.
have_port_finder() {
	for file in $(which ss 2> /dev/null) /*bin/ss /usr/*bin/ss /usr/local/*bin/ss;do
		if test -x "$file";then
			PFCMD="$file";return 0
		fi
	done

	if test -z "$PFCMD";then
	for file in $(which netstat 2> /dev/null) /bin/netstat /usr/bin/netstat /usr/local/bin/netstat;do
		if test -x "$file";then
			PFCMD="$file";return 0
		fi
	done
	fi

	if test -z "$PFCMD";then
		echo "neither ss nor netstat found"
		exit 1
	fi
}

check_if_port_in_use() {
	local PORT="$1"
	local PFCMD; have_port_finder
	$PFCMD -an|grep "[\:\.]$PORT" >/dev/null 2>&1
}

# Find a port number not currently in use.
GETPORT='
    rc=0
    unset myrandom
    while test $rc = 0; do
        if test -n "$RANDOM"; then myrandom=$(($RANDOM + $RANDOM)); fi
        if test -z "$myrandom"; then myrandom=$(date +%N | sed s/^0*//); fi
        if test -z "$myrandom"; then myrandom=0; fi
        PORT="$(((($$<<15)|$myrandom) % 63001 + 2000))"
        check_if_port_in_use $PORT;rc=$?
    done
'

trap "fail \"Failed to launch the server, aborting test... \"" 10 
