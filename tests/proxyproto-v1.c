/*
 * Copyright (C) 2017 Nikos Mavrogiannopoulos
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
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <gnutls/gnutls.h>

/* Unit test for proxy protocol v1.
 */
//static unsigned verbose = 0;
#define UNDER_TEST

#define force_read_timeout(fd, buf, count, time) read(fd, buf, count)
#include "../src/worker-proxyproto.c"

static unsigned try(const char *src, unsigned src_port, const char *dst, unsigned dst_port)
{
	char str[256];
	struct worker_st ws;
	unsigned ipv6 = 0;
	int ret;

	memset(&ws, 0, sizeof(ws));

	if (strchr(src, ':') != NULL) {
		/* ipv6 */
		snprintf(str, sizeof(str), "TCP6 %s %s %u %u\r\n", src, dst, src_port, dst_port);
		ipv6 = 1;
	} else {
		snprintf(str, sizeof(str), "TCP4 %s %s %u %u\r\n", src, dst, src_port, dst_port);
	}
	
	ret = parse_proxy_proto_header_v1(&ws, str);
	if (ret < 0) {
		fprintf(stderr, "error parsing: '%s': %d\n", str, ret);
		return 0;
	}

	/* check if output values are right */
	if (ipv6) {
		struct sockaddr_in6 *sa_src = (void*)&ws.remote_addr;
		struct sockaddr_in6 *sa_dst = (void*)&ws.our_addr;
	
		if (ws.remote_addr_len != sizeof(struct sockaddr_in6) ||
			ws.our_addr_len != sizeof(struct sockaddr_in6)) {
			fprintf(stderr, "error in %d for %s\n", __LINE__, str);
			return 0;
		}

		if (strcmp(inet_ntop(AF_INET6, (void*)&sa_src->sin6_addr, str, sizeof(str)), src) != 0) {
			fprintf(stderr, "error in %d for %s\n", __LINE__, str);
			return 0;
		}

		if (strcmp(inet_ntop(AF_INET6, (void*)&sa_dst->sin6_addr, str, sizeof(str)), dst) != 0) {
			fprintf(stderr, "error in %d for %s\n", __LINE__, str);
			return 0;
		}

		if (ntohs(sa_src->sin6_port) != src_port) {
			fprintf(stderr, "error in %d for %s\n", __LINE__, str);
			return 0;
		}

		if (ntohs(sa_dst->sin6_port) != dst_port) {
			fprintf(stderr, "error in %d for %s\n", __LINE__, str);
			return 0;
		}
	} else {
		struct sockaddr_in *sa_src = (void*)&ws.remote_addr;
		struct sockaddr_in *sa_dst = (void*)&ws.our_addr;

		if (ws.remote_addr_len != sizeof(struct sockaddr_in) ||
			ws.our_addr_len != sizeof(struct sockaddr_in)) {
			fprintf(stderr, "error in %d for %s\n", __LINE__, str);
			return 0;
		}

		if (strcmp(inet_ntop(AF_INET, (void*)&sa_src->sin_addr, str, sizeof(str)), src) != 0) {
			fprintf(stderr, "error in %d for %s\n", __LINE__, str);
			return 0;
		}

		if (strcmp(inet_ntop(AF_INET, (void*)&sa_dst->sin_addr, str, sizeof(str)), dst) != 0) {
			fprintf(stderr, "error in %d for %s\n", __LINE__, str);
			return 0;
		}

		if (ntohs(sa_src->sin_port) != src_port) {
			fprintf(stderr, "error in %d for %s\n", __LINE__, str);
			return 0;
		}

		if (ntohs(sa_dst->sin_port) != dst_port) {
			fprintf(stderr, "error in %d for %s\n", __LINE__, str);
			return 0;
		}
	}

	return 1;
}

int main(int argc, char **argv)
{
	assert(try("127.0.0.1", 99, "127.0.0.1", 100) == 1);
	assert(try("192.168.5.1", 1099, "172.52.3.1", 3100) == 1);
	assert(try("fcd0:4d89:c36:ca3f::", 1099, "fdce:e8e5:8c8e:4294::", 3100) == 1);
	assert(try("xxx.0.0.1", 99, "127.0.0.1", 100) == 0);
	assert(try("127.0.0.1", 99, "xxx.0.0.1", 100) == 0);
	assert(try("901.0.0.1", 99, "127.0.0.1", 100) == 0);

	return 0;
}
