#!/bin/sh
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

#this test can only be run as root

OPENCONNECT=${OPENCONNECT:-/usr/sbin/openconnect}

if ! test -x ${OPENCONNECT};then
	echo "You need openconnect to run this test"
	exit 77
fi

if test -z "$NO_NEED_ROOT";then
	if test "$(id -u)" != "0";then
		exit 77
	fi
else
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
	cp "${srcdir}/data/${file}" "$file.$$.tmp"
	sed -i -e 's|@USERNAME@|'${username}'|g' "$file.$$.tmp" \
	       -e 's|@GROUP@|'${group}'|g' "$file.$$.tmp" \
	       -e 's|@SRCDIR@|'${srcdir}'|g' "$file.$$.tmp" \
	       -e 's|@OTP_FILE@|'${OTP_FILE}'|g' "$file.$$.tmp" \
	       -e 's|@CRLNAME@|'${CRLNAME}'|g' "$file.$$.tmp" \
	       -e 's|@PORT@|'${PORT}'|g' "$file.$$.tmp" \
	       -e 's|@ADDRESS@|'${ADDRESS}'|g' "$file.$$.tmp" \
	       -e 's|@VPNNET@|'${VPNNET}'|g' "$file.$$.tmp" \
	       -e 's|@VPNNET6@|'${VPNNET6}'|g' "$file.$$.tmp" \
	       -e 's|@ROUTE1@|'${ROUTE1}'|g' "$file.$$.tmp" \
	       -e 's|@ROUTE2@|'${ROUTE2}'|g' "$file.$$.tmp" \
	       -e 's|@OCCTL_SOCKET@|'${OCCTL_SOCKET}'|g' "$file.$$.tmp"
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

launch_sr_pam_server() {
	mkdir -p "data/$PAMDIR/"
	test -f "${srcdir}/data/$PAMDIR/users.oath.templ" && cp "${srcdir}/data/$PAMDIR/users.oath.templ" "data/$PAMDIR/users.oath"
	test -f "${srcdir}/data/$PAMDIR/passdb.templ" && cp "${srcdir}/data/$PAMDIR/passdb.templ" "data/$PAMDIR/passdb"
	export PAM_WRAPPER_SERVICE_DIR=pam.$$.tmp
	export NSS_WRAPPER_PASSWD=${srcdir}/data/pam/nss-passwd
	export NSS_WRAPPER_GROUP=${srcdir}/data/pam/nss-group
	if test -n "${VERBOSE}" && test "${VERBOSE}" -ge 1;then
		LD_PRELOAD=libnss_wrapper.so:libpam_wrapper.so:libsocket_wrapper.so:libuid_wrapper.so PAM_WRAPPER_SERVICE_DIR="data/$PAMDIR" PAM_WRAPPER=1  UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $SERV $* &
	else
		LD_PRELOAD=libnss_wrapper.so:libpam_wrapper.so:libsocket_wrapper.so:libuid_wrapper.so PAM_WRAPPER_SERVICE_DIR="data/$PAMDIR" PAM_WRAPPER=1  UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $SERV $* >/dev/null 2>&1 &
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
	test -n "$SOCKDIR" && rm -rf $SOCKDIR
	rm -f ${CONFIG}
	return $ret
}

trap "fail \"Failed to launch the server, aborting test... \"" 10 
