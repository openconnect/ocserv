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
#include <common-config.h>
#include <c-strcase.h>
#include <c-ctype.h>
#include <talloc.h>

#include <vpn.h>

static int append_port(void *pool, FwPortSt ***fw_ports, size_t *n_fw_ports, int port, fw_proto_t proto, unsigned negate)
{
	FwPortSt *current;

	*fw_ports = talloc_realloc(pool, *fw_ports, FwPortSt*, (*n_fw_ports)+1);
	if (*fw_ports == NULL)
		return -1;

	current = talloc(pool, FwPortSt);
	if (current == NULL) {
		talloc_free(*fw_ports);
		*fw_ports = NULL;
		return -1;
	}
	fw_port_st__init(current);

	current->port = port;
	current->proto = proto;
	current->negate = negate;

	(*fw_ports)[*n_fw_ports] = current;
	(*n_fw_ports)++;

	return 0;
}

/* Parse strings of the format tcp(443), udp(111), and fill in
 * allowed_tcp_ports and allowed_udp_ports.
 */
int cfg_parse_ports(void *pool, FwPortSt ***fw_ports, size_t *n_fw_ports, const char *str)
{
	const char *p, *p2;
	unsigned finish = 0;
	int port, ret;
	fw_proto_t proto;
	int negate = 0, bracket_start = 0;

	if (str == NULL)
		return 0;

	p = str;

	while (c_isspace(*p))
		p++;

	if (*p == '!') {
		negate = 1;
		p++;
		while (c_isspace(*p) || (*p == '(')) {
			if (*p == '(')
				bracket_start = 1;
			p++;
		}

		if (bracket_start == 0) {
			syslog(LOG_ERR, "no bracket following negation at %d '%s'", (int)(ptrdiff_t)(p-str), str);
			return -1;
		}
	}

	do {

		while (c_isspace(*p))
			p++;

		if (strncasecmp(p, "tcp", 3) == 0) {
			proto = PROTO_TCP;
			p += 3;
		} else if (strncasecmp(p, "udp", 3) == 0) {
			proto = PROTO_UDP;
			p += 3;
		} else if (strncasecmp(p, "sctp", 4) == 0) {
			proto = PROTO_SCTP;
			p += 4;
		} else if (strncasecmp(p, "icmpv6", 6) == 0) {
			proto = PROTO_ICMPv6;
			p += 6;
		} else if (strncasecmp(p, "icmp", 4) == 0) {
			proto = PROTO_ICMP;
			p += 4;
		} else if (strncasecmp(p, "esp", 3) == 0) {
			proto = PROTO_ESP;
			p += 3;
		} else {
			syslog(LOG_ERR, "unknown protocol on restrict-user-to-ports at %d '%s'", (int)(ptrdiff_t)(p-str), str);
			return -1;
		}

		while (c_isspace(*p))
			p++;

		if (*p != '(') {
			syslog(LOG_ERR, "expected parenthesis on restrict-user-to-ports at %d '%s'", (int)(ptrdiff_t)(p-str), str);
			return -1;
		}

		p++;
		port = atoi(p);

		ret = append_port(pool, fw_ports, n_fw_ports, port, proto, negate);
		if (ret < 0) {
			syslog(LOG_ERR, "memory error");
			return -1;
		}

		p2 = strchr(p, ')');
		if (p2 == NULL) {
			syslog(LOG_ERR, "expected closing parenthesis on restrict-user-to-ports at %d '%s'", (int)(ptrdiff_t)(p-str), str);
			return -1;
		}

		p2++;
		while (c_isspace(*p2))
			p2++;

		if (*p2 == 0 || (negate != 0 && *p2 == ')')) {
			finish = 1;
		} else if (*p2 != ',') {
			syslog(LOG_ERR, "expected comma or end of line on restrict-user-to-ports at %d '%s'", (int)(ptrdiff_t)(p2-str), str);
			return -1;
		}
		p=p2;
		p++;
	} while(finish == 0);

	return 0;
}
