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

# Input:
#  ADDRESS=10.200.2.1
#  ADDRESS2=10.200.2.2
#  CLI_ADDRESS=10.200.1.1
#  CLI_ADDRESS2=10.200.1.2
#  VPNNET=192.168.1.0/24
#  VPNADDR=192.168.1.1
#
# Provides:
#  ${NSCMD1} - to run on NS1
#  ${NSCMD2} - to run on NS2
#  ${NSCMD3} - to run on NS3
#
# Cleanup is automatic via a trap
#  Requires: finish() to be defined
 

PATH=${PATH}:/usr/sbin
IP=$(which ip)

if test "$(id -u)" != "0";then
	echo "This test must be run as root"
	exit 77
fi

ip netns list >/dev/null 2>&1
if test $? != 0;then
	echo "This test requires ip netns command"
	exit 77
fi

if test "$(uname -s)" != Linux;then
	echo "This test must be run on Linux"
	exit 77
fi

function nsfinish {
  set +e
  test -n "${ETHNAME1}" && ${IP} link delete ${ETHNAME1} >/dev/null 2>&1
  test -n "${ETHNAME2}" && ${IP} link delete ${ETHNAME2} >/dev/null 2>&1
  test -n "${ETHNAME3}" && ${IP} link delete ${ETHNAME3} >/dev/null 2>&1
  test -n "${ETHNAME4}" && ${IP} link delete ${ETHNAME4} >/dev/null 2>&1
  test -n "${NSNAME1}" && ${IP} netns delete ${NSNAME1} >/dev/null 2>&1
  test -n "${NSNAME2}" && ${IP} netns delete ${NSNAME2} >/dev/null 2>&1
  test -n "${NSNAME3}" && ${IP} netns delete ${NSNAME3} >/dev/null 2>&1

  finish
}
trap nsfinish EXIT

# ETHNAME1 and ETHNAME2 are a veth pair
# ETHNAME3 and ETHNAME4 are a veth pair
# NSNAME1 and NSNAME3 are client namespaces containing ETHNAME1 and ETHNAME3
# NSNAME2 is the server namespace containing ETHNAME2 and ETHNAME4

echo " * Setting up namespaces..."
set -e
NSNAME1="ocserv-c-tmp-$$"
NSNAME3="ocserv-c-2-tmp-$$"
NSNAME2="ocserv-s-tmp-$$"
ETHNAME1="oceth-c$$"
ETHNAME2="oceth-s$$"
ETHNAME3="oceth-c-2$$"
ETHNAME4="oceth-s-2$$"

${IP} netns add ${NSNAME1}
${IP} netns add ${NSNAME2}
${IP} netns add ${NSNAME3}

${IP} link add ${ETHNAME1} type veth peer name ${ETHNAME2}
${IP} link set ${ETHNAME1} netns ${NSNAME1}
${IP} link set ${ETHNAME2} netns ${NSNAME2}

${IP} link add ${ETHNAME3} type veth peer name ${ETHNAME4}
${IP} link set ${ETHNAME3} netns ${NSNAME3}
${IP} link set ${ETHNAME4} netns ${NSNAME2}

${IP} -n ${NSNAME1} link set ${ETHNAME1} up
${IP} -n ${NSNAME2} link set ${ETHNAME2} up
${IP} -n ${NSNAME3} link set ${ETHNAME3} up
${IP} -n ${NSNAME2} link set ${ETHNAME4} up
${IP} -n ${NSNAME2} link set lo up

${IP} -n ${NSNAME1} addr add ${CLI_ADDRESS} dev ${ETHNAME1}
${IP} -n ${NSNAME2} addr add ${ADDRESS} dev ${ETHNAME2}
test -n "${CLI_ADDRESS2}" && ${IP} -n ${NSNAME3} addr add ${CLI_ADDRESS2} dev ${ETHNAME3}
test -n "${ADDRESS2}" && ${IP} -n ${NSNAME2} addr add ${ADDRESS2} dev ${ETHNAME4}

${IP} -n ${NSNAME1} route add default via ${CLI_ADDRESS} dev ${ETHNAME1}
${IP} -n ${NSNAME2} route
${IP} -n ${NSNAME2} route add default via ${ADDRESS} dev ${ETHNAME2}

test -n "${CLI_ADDRESS2}" && ${IP} -n ${NSNAME3} route add default via ${CLI_ADDRESS2} dev ${ETHNAME3}
test -n "${ADDRESS2}" && ${IP} -n ${NSNAME2} route add ${CLI_ADDRESS2}/32 via ${ADDRESS2} dev ${ETHNAME4}

${IP} -n ${NSNAME2} addr
${IP} -n ${NSNAME2} route
${IP} -n ${NSNAME1} route
test -n "${CLI_ADDRESS2}" && ${IP} -n ${NSNAME3} route

${IP} netns exec ${NSNAME1} ping -c 1 ${ADDRESS} >/dev/null 
${IP} netns exec ${NSNAME2} ping -c 1 ${ADDRESS} >/dev/null 
${IP} netns exec ${NSNAME2} ping -c 1 ${CLI_ADDRESS} >/dev/null
test -n "${ADDRESS2}" && ${IP} netns exec ${NSNAME2} ping -c 1 ${ADDRESS2} >/dev/null 
test -n "${CLI_ADDRESS2}" && ${IP} netns exec ${NSNAME2} ping -c 1 ${CLI_ADDRESS2} >/dev/null 
set +e

CMDNS1="${IP} netns exec ${NSNAME1}"
CMDNS2="${IP} netns exec ${NSNAME2}"
CMDNS3="${IP} netns exec ${NSNAME3}"
