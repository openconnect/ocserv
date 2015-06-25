/*
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "../src/common-config.h"

int main()
{
#ifndef HAVE_GSSAPI
	exit(77);
#else
	char p[256];
	char *port, *server, *path, *realm;
	int socktype;

	strcpy(p, "/KdcProxy KERBEROS.REALM udp@127.0.0.1:88");

	parse_kkdcp_string(p, &socktype, &port, &server, &path, &realm);
	if (socktype != SOCK_DGRAM || strcmp(port, "88") != 0 || strcmp(path, "/KdcProxy") != 0 ||
	    strcmp(realm, "KERBEROS.REALM") != 0 || strcmp(server, "127.0.0.1") != 0) {
	    	fprintf(stderr, "error in %d: '%s' '%s' %u@'%s':'%s'\n", __LINE__, path, realm, socktype, server, port);
	    	exit(2);
	}

	strcpy(p, "/KdcProxy KERBEROS.REALM tcp@[::1]:88");

	parse_kkdcp_string(p, &socktype, &port, &server, &path, &realm);
	if (socktype != SOCK_STREAM || strcmp(port, "88") != 0 || strcmp(path, "/KdcProxy") != 0 ||
	    strcmp(realm, "KERBEROS.REALM") != 0 || strcmp(server, "::1") != 0) {
	    	fprintf(stderr, "error in %d: '%s' '%s' %u@'%s':'%s'\n", __LINE__, path, realm, socktype, server, port);
	    	exit(2);
	}

	strcpy(p, "/KdcProxy-xxx	 KERBEROS.REALM		udp@[fc74:cc44:8f86:0252:47d4:54bf:112b:970c]:8899");

	parse_kkdcp_string(p, &socktype, &port, &server, &path, &realm);
	if (socktype != SOCK_DGRAM || strcmp(port, "8899") != 0 || strcmp(path, "/KdcProxy-xxx") != 0 ||
	    strcmp(realm, "KERBEROS.REALM") != 0 || strcmp(server, "fc74:cc44:8f86:0252:47d4:54bf:112b:970c") != 0) {
	    	fprintf(stderr, "error in %d: '%s' '%s' %u@'%s':'%s'\n", __LINE__, path, realm, socktype, server, port);
	    	exit(2);
	}

	return 0;
#endif
}
