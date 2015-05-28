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

#ifdef HAVE_GSSAPI

#include <c-strcase.h>
#include <c-ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

static char *find_space(char *str)
{
	while(*str != 0 && c_isspace(*str) == 0) {
		str++;
	}
	if (c_isspace(*str))
		return str;
	return NULL;
}

void parse_kkdcp_string(char *str, int *socktype, char **_port, char **_server, char **_path, char **_realm)
{
	char *path, *server, *port, *realm, *p;

	path = str;
	realm = find_space(path);
	if (realm == NULL) {
		fprintf(stderr, "Cannot parse kkdcp string: %s\n", path);
		exit(1);
	}

	*realm = 0;
	realm++;
	while (c_isspace(*realm))
		realm++;

	server = find_space(realm);
	if (server == NULL) {
		fprintf(stderr, "Cannot parse kkdcp string: %s\n", realm);
		exit(1);
	}

	/* null terminate the realm */
	*server = 0;
	server++;

	while (c_isspace(*server))
		server++;

	if (strncmp(server, "udp@", 4) == 0) {
		*socktype = SOCK_DGRAM;
	} else if (strncmp(server, "tcp@", 4) == 0) {
		*socktype = SOCK_STREAM;
	} else {
		fprintf(stderr, "cannot handle protocol %s\n", server);
			exit(1);
	}
	server += 4;

	p = strchr(server, ']');
	if (p == NULL) { /* IPv4 address or server.name:port */
		port = strchr(server, ':');
	} else { /* [::IPV6address]:PORT */
		port = strchr(p, ':');
		if (port) {
			*p = 0;
			p = strchr(server, '[');
			if (p)
				server = p+1;
		}
	}

	if (port == NULL) {
		fprintf(stderr, "No server port specified in: %s\n", server);
		exit(1);
	}
	*port = 0;
	port++;

	*_port = port;
	*_realm = realm;
	*_path = path;
	*_server = server;

	return;
}

#endif
