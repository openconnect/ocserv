/*
 * Copyright (C) 2014 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef RADIUS_H
#define RADIUS_H

#include <sec-mod-auth.h>
#include <base64.h>

struct radius_ctx_st {
	char username[MAX_USERNAME_SIZE*2];
	char groupname[MAX_GROUPNAME_SIZE];
	char sid[BASE64_LENGTH(SID_SIZE) + 1];

	char remote_ip[MAX_IP_STR];

	/* variables for configuration */
	char ipv4[MAX_IP_STR];
	char ipv4_mask[MAX_IP_STR];
	char ipv4_dns1[MAX_IP_STR];
	char ipv4_dns2[MAX_IP_STR];

	char ipv6[MAX_IP_STR];
	char ipv6_net[MAX_IP_STR];
	uint16_t ipv6_prefix;
	char ipv6_dns1[MAX_IP_STR];
	char ipv6_dns2[MAX_IP_STR];

	char **routes;
	unsigned routes_size;

	const char *config;	/* radius config file */
	const char *pass_msg;
	unsigned retries;
};

extern const struct auth_mod_st radius_auth_funcs;

#endif
