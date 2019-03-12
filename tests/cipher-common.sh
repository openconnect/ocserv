#!/bin/bash
#
# Copyright (C) 2018 Nikos Mavrogiannopoulos
#
# This file is part of ocserv.
#
# ocserv is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# ocserv is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# This tests operation/traffic under compression (lzs or lz4).

OCCTL="${OCCTL:-../src/occtl/occtl}"
SERV="${SERV:-../src/ocserv}"
srcdir=${srcdir:-.}
PORT=4574
PIDFILE=ocserv-pid.$$.tmp
CLIPID=oc-pid.$$.tmp
PATH=${PATH}:/usr/sbin
IP=$(which ip)
OUTFILE=traffic.$$.tmp

. `dirname $0`/common.sh

if test -z "${IP}";then
	echo "no IP tool is present"
	exit 77
fi

if test "$(id -u)" != "0";then
	echo "This test must be run as root"
	exit 77
fi

echo "Testing ocserv connection with ${CIPHER_NAME} under legacy DTLS... "

function finish {
  set +e
  echo " * Cleaning up..."
  test -n "${PID}" && kill ${PID} >/dev/null 2>&1
  test -n "${PIDFILE}" && rm -f ${PIDFILE} >/dev/null 2>&1
  test -n "${CLIPID}" && kill $(cat ${CLIPID}) >/dev/null 2>&1
  test -n "${CLIPID}" && rm -f ${CLIPID} >/dev/null 2>&1
  test -n "${CONFIG}" && rm -f ${CONFIG} >/dev/null 2>&1
  rm -f ${OUTFILE} 2>&1
}
trap finish EXIT

# server address
ADDRESS=10.201.2.1
CLI_ADDRESS=10.201.1.1
VPNNET=192.168.2.0/24
VPNADDR=192.168.2.1
VPNNET6=fd91:6d87:7341:dc6a::/112
VPNADDR6=fd91:6d87:7341:dc6a::1
OCCTL_SOCKET=./occtl-comp-$$.socket
USERNAME=test

. `dirname $0`/ns.sh

# Run servers
update_config test-ciphers.config
if test "$VERBOSE" = 1;then
DEBUG="-d 3"
fi

${CMDNS2} ${SERV} -p ${PIDFILE} -f -c ${CONFIG} ${DEBUG} & PID=$!

sleep 4

if test -n "${CIPHER12_NAME}";then
	CSTR="--dtls12-ciphers ${CIPHER12_NAME} --dtls-ciphers UNKNOWN"
else
	CSTR="--dtls-ciphers ${CIPHER_NAME}"
fi

# Run clients
echo " * Getting cookie from ${ADDRESS}:${PORT}..."
( echo "test" | ${CMDNS1} ${OPENCONNECT} ${ADDRESS}:${PORT} -u ${USERNAME} --servercert=d66b507ae074d03b02eafca40d35f87dd81049d3 ${CSTR} --cookieonly )
if test $? != 0;then
	echo "Could not get cookie from server"
	exit 1
fi

echo " * Connecting to ${ADDRESS}:${PORT}..."
( echo "test" | ${CMDNS1} ${OPENCONNECT} ${ADDRESS}:${PORT} -u ${USERNAME} --servercert=d66b507ae074d03b02eafca40d35f87dd81049d3 ${CSTR} -s ${srcdir}/scripts/vpnc-script --pid-file=${CLIPID} --passwd-on-stdin -b )
if test $? != 0;then
	echo "Could not connect to server"
	exit 1
fi

set -e
echo " * ping remote address"

${CMDNS2} nuttcp -1

${CMDNS1} ping -c 3 ${VPNADDR}

sleep 2

echo " * Transmitting with nuttcp"

${CMDNS1} nuttcp -T 6 -t ${VPNADDR}

# IPv6

${CMDNS2} nuttcp -1

${CMDNS1} ping -6 -c 3 ${VPNADDR6}

echo " * Receiving with nuttcp"

${CMDNS1} nuttcp -T 6 -r ${VPNADDR}

set +e

${OCCTL} -s ${OCCTL_SOCKET} show users|grep ${USERNAME}
if test $? != 0;then
	echo "occtl didn't find connected user!"
	exit 1
fi

${OCCTL} -s ${OCCTL_SOCKET} show user ${USERNAME} >${OUTFILE}
if test $? != 0;then
	${OCCTL} -s ${OCCTL_SOCKET} show user ${USERNAME}
	echo "occtl didn't find connected user!"
	exit 1
fi

grep "Username: ${USERNAME}" ${OUTFILE} >/dev/null
if test $? != 0;then
	${OCCTL} -s ${OCCTL_SOCKET} show user ${USERNAME}
	echo "occtl show user didn't find connected user!"
	exit 1
fi

if test -z "${GNUTLS_NAME}";then
	grep "DTLS cipher:" ${OUTFILE} >/dev/null
	if test $? = 0;then
		${OCCTL} -s ${OCCTL_SOCKET} show user ${USERNAME}
		echo "occtl show user did show a cipher!"
		exit 1
	fi
else
	grep "DTLS cipher: ${GNUTLS_NAME}" ${OUTFILE} >/dev/null
	if test $? != 0;then
		${OCCTL} -s ${OCCTL_SOCKET} show user ${USERNAME}
		echo "occtl show user didn't show cipher!"
		exit 1
	fi
fi

grep -E '[[:space:]]+TLS ciphersuite:' ${OUTFILE} >/dev/null
if test $? != 0;then
	${OCCTL} -s ${OCCTL_SOCKET} show user ${USERNAME}
	echo "occtl show user did not show a TLS cipher!"
	exit 1
fi

grep ${CLI_ADDRESS} ${OUTFILE} >/dev/null
if test $? != 0;then
	${OCCTL} -s ${OCCTL_SOCKET} show user ${USERNAME}
	echo "occtl show user didn't find client address!"
	exit 1
fi

exit 0
