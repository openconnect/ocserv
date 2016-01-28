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

OPENCONNECT=/usr/sbin/openconnect

if test -z "$NO_NEED_ROOT";then
	id|grep root >/dev/null 2>&1
	if [ $? != 0 ];then
		exit 77
	fi
else
	SOCKDIR=${srcdir}/sockwrap.$$.tmp
	mkdir -p $SOCKDIR
	export SOCKET_WRAPPER_DIR=$SOCKDIR
	export SOCKET_WRAPPER_DEFAULT_IFACE=2
	ADDRESS=127.0.0.$SOCKET_WRAPPER_DEFAULT_IFACE
	OPENCONNECT="eval LD_PRELOAD=libsocket_wrapper.so /usr/sbin/openconnect"
fi

if ! test -x /usr/sbin/openconnect;then
	echo "You need openconnect to run this test"
	exit 77
fi

update_config() {
	file=$1
	cp ${srcdir}/${file} "$file.tmp"
	sed -i 's|@SRCDIR@|'${srcdir}'|g' "$file.tmp"
	CONFIG="$file.tmp"
}

fail() {
   PID=$1
   shift;
   echo "Failure: $1" >&2
   kill $PID
   exit 1
}

launch_server() {
       $SERV $* >/dev/null 2>&1 &
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
       LD_PRELOAD=libsocket_wrapper.so:libuid_wrapper.so UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $SERV $* &#>/dev/null 2>&1 &
       LOCALPID="$!";
       trap "[ ! -z \"${LOCALPID}\" ] && kill ${LOCALPID};" 15
       wait "${LOCALPID}"
       LOCALRET="$?"
       if [ "${LOCALRET}" != "0" ] && [ "${LOCALRET}" != "143" ] ; then
               # Houston, we'v got a problem...
               exit 1
       fi
}

launch_simple_sr_server() {
       LD_PRELOAD=libsocket_wrapper.so:libuid_wrapper.so UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $SERV $* >/dev/null 2>&1 &
}

launch_simple_server() {
       $PRELOAD_CMD $SERV $* >/dev/null 2>&1 &
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
