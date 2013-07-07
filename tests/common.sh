#!/bin/sh
#
# Copyright (C) 2011-2012 Free Software Foundation, Inc.
#
# This file is part of GnuTLS.
#
# The launch_server() function was contributed by Cedric Arbogast.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
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
id|grep root >/dev/null 2>&1
if [ $? != 0 ];then
	exit 77
fi

if ! test -x /usr/sbin/openconnect;then
	echo "You need openconnect to run this test"
	exit 77
fi

fail() {
   PID=$1
   shift;
   echo "Failure: $1" >&2
   kill $PID
   exit 1
}

launch_server() {
       PARENT=$1;
       shift;
       $SERV $* >/dev/null 2>&1 &
       LOCALPID="$!";
       trap "[ ! -z \"${LOCALPID}\" ] && kill ${LOCALPID};" 15
       wait "${LOCALPID}"
       LOCALRET="$?"
       if [ "${LOCALRET}" != "0" ] && [ "${LOCALRET}" != "143" ] ; then
               # Houston, we'v got a problem...
               echo "Failed to launch the server !"
               test -z "${PARENT}" || kill -10 ${PARENT}
               exit 1
       fi
}

wait_server() {
	trap "kill $1" 1 15 2
	sleep 2
}

trap "fail \"Failed to launch the server, aborting test... \"" 10 
