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
#include "../src/config-ports.c"
#include "../src/ipc.pb-c.h"

#define reset(x,y) { \
	talloc_free(x); \
	x = NULL; \
	y = 0; }

void fw_port_st__init(FwPortSt *message)
{
	return;
}

void check_vals(FwPortSt **fw_ports, size_t n_fw_ports) {
	if (n_fw_ports != 7) {
		fprintf(stderr, "error in %d (detected %d)\n", __LINE__, (int)n_fw_ports);
		exit(1);
	}

	if (fw_ports[0]->proto != PROTO_ICMP || fw_ports[1]->proto != PROTO_TCP || fw_ports[2]->proto != PROTO_UDP ||
		fw_ports[3]->proto != PROTO_SCTP || fw_ports[4]->proto != PROTO_TCP ||
		fw_ports[5]->proto != PROTO_UDP || fw_ports[6]->proto != PROTO_ICMPv6) {

		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (fw_ports[1]->port != 88 || fw_ports[2]->port != 90 ||
		fw_ports[3]->port != 70 || fw_ports[4]->port != 443 ||
		fw_ports[5]->port != 80) {

		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}
}

int main()
{
	char p[256];
	int ret;
	FwPortSt **fw_ports = NULL;
	size_t n_fw_ports = 0;
	void *pool = talloc_new(NULL);

	strcpy(p, "icmp(), tcp(88), udp(90), sctp(70), tcp(443), udp(80), icmpv6()");

	ret = cfg_parse_ports(pool, &fw_ports, &n_fw_ports, p);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	check_vals(fw_ports, n_fw_ports);

	/* check spacing tolerance */
	reset(fw_ports, n_fw_ports);
	strcpy(p, "icmp (  ), tcp	 (  88 ), udp  (  90  ), sctp  (  70   )   ,   tcp   (  443   )    ,  	 udp(80)  	, icmpv6 ( )   	");

	ret = cfg_parse_ports(pool, &fw_ports, &n_fw_ports, p);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	check_vals(fw_ports, n_fw_ports);

	/* test error 1 */
	reset(fw_ports, n_fw_ports);
	strcpy(p, "tcp(88), tcp(90),");
	ret = cfg_parse_ports(pool, &fw_ports, &n_fw_ports, p);
	if (ret >= 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	/* test error 2 */
	reset(fw_ports, n_fw_ports);
	strcpy(p, "tcp(88), tcp");
	ret = cfg_parse_ports(pool, &fw_ports, &n_fw_ports, p);
	if (ret >= 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	reset(fw_ports, n_fw_ports);
	strcpy(p, "!(icmp(), tcp(88), udp(90), sctp(70), tcp(443), udp(80), icmpv6())");

	ret = cfg_parse_ports(pool, &fw_ports, &n_fw_ports, p);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	check_vals(fw_ports, n_fw_ports);
	if (fw_ports[0]->negate == 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}
	talloc_free(pool);

	return 0;
}
