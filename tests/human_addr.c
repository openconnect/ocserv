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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../src/ip-util.h"
#include "../src/ip-util.c"

static unsigned ip_to_sockaddr(const char *ip, unsigned port, struct sockaddr_storage *ss)
{
	int ret;
	struct sockaddr_in6 *s6 = (void*)ss;
	struct sockaddr_in *s4 = (void*)ss;

	memset(ss, 0, sizeof(*ss));
	if (strchr(ip, '.') == 0) {
		s6->sin6_family = AF_INET6;

		ret = inet_pton(AF_INET6, ip, &s6->sin6_addr);
		if (ret == 0) {
			fprintf(stderr, "error in inet_pton6(%s)\n", ip);
			exit(1);
		}
		s6->sin6_port = htons(port);

		return sizeof(struct sockaddr_in6);
	} else {
		s4->sin_family = AF_INET;

		ret = inet_pton(AF_INET, ip, &s4->sin_addr);
		if (ret == 0) {
			fprintf(stderr, "error in inet_pton(%s)\n", ip);
			exit(1);
		}
		s4->sin_port = htons(port);

		return sizeof(struct sockaddr_in);
	}
}

static void check(const char *ip)
{
	struct sockaddr_storage ss;
	socklen_t len;
	char *p;
	char buf[128];

	len = ip_to_sockaddr(ip, 443, &ss);
	p = human_addr2((struct sockaddr*)&ss, len, buf, sizeof(buf), 0);
	if (p == NULL) {
		fprintf(stderr, "human_addr2 couldn't convert: %s\n", ip);
		exit(1);
	}

	if (strcmp(ip, buf) != 0) {
		fprintf(stderr, "human_addr2 returned different value (have: %s, expected: %s)\n", buf, ip);
		exit(1);

	}
	return;
}

static void check_port(const char *ip, unsigned port)
{
	struct sockaddr_storage ss;
	socklen_t len;
	char *p;
	char buf[128];
	char buf2[128];

	len = ip_to_sockaddr(ip, port, &ss);
	p = human_addr2((struct sockaddr*)&ss, len, buf, sizeof(buf), 1);
	if (p == NULL) {
		fprintf(stderr, "human_addr2 couldn't convert: %s\n", ip);
		exit(1);
	}

	if (strchr(ip, ':') != 0) {
		snprintf(buf2, sizeof(buf2), "[%s]:%u", ip, port);
	} else {
		snprintf(buf2, sizeof(buf2), "%s:%u", ip, port);
	}

	if (strcmp(buf2, buf) != 0) {
		fprintf(stderr, "human_addr2 returned different value (have: %s, expected: %s)\n", buf, buf2);
		exit(1);

	}
	return;
}

int main()
{
	check("172.18.52.43");
	check("192.168.1.1");
	check("10.100.100.2");
	check("fd4f:edc6:b75:5dfd:3cd9:b8ae:97ec:52da");
	check("fc6f:8eca:d6a2:2559:90e3:1b33:8e6:ae59");
	check("fd44:1f40:e28a:1928:773c:9a1e:76dc:9a1");

	check_port("172.18.52.43", 128);
	check_port("192.168.1.1", 256);
	check_port("10.100.100.2", 443);
	check_port("fd4f:edc6:b75:5dfd:3cd9:b8ae:97ec:52da", 512);
	check_port("fc6f:8eca:d6a2:2559:90e3:1b33:8e6:ae59", 443);
	check_port("fd44:1f40:e28a:1928:773c:9a1e:76dc:9a1", 1024);

	return 0;
}
