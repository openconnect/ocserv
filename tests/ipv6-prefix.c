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

#include "../src/common.h"

int main()
{
	char *p;
	char str[MAX_IP_STR];

	p = ipv6_prefix_to_mask(str, 128);
	if (p == NULL || strcmp(p, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") != 0) {
		fprintf(stderr, "error in %d: %s\n", __LINE__, p);
		exit(1);
	}

	p = ipv6_prefix_to_mask(str, 127);
	if (p == NULL || strcmp(p, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe") != 0) {
		fprintf(stderr, "error in %d: %s\n", __LINE__, p);
		exit(1);
	}

	p = ipv6_prefix_to_mask(str, 97);
	if (p == NULL || strcmp(p, "ffff:ffff:ffff:ffff:ffff:ffff:8000:0") != 0) {
		fprintf(stderr, "error in %d: %s\n", __LINE__, p);
		exit(1);
	}

	p = ipv6_prefix_to_mask(str, 96);
	if (p == NULL || strcmp(p, "ffff:ffff:ffff:ffff:ffff:ffff::") != 0) {
		fprintf(stderr, "error in %d: %s\n", __LINE__, p);
		exit(1);
	}

	p = ipv6_prefix_to_mask(str, 95);
	if (p == NULL || strcmp(p, "ffff:ffff:ffff:ffff:ffff:fffe::") != 0) {
		fprintf(stderr, "error in %d: %s\n", __LINE__, p);
		exit(1);
	}

	p = ipv6_prefix_to_mask(str, 67);
	if (p == NULL || strcmp(p, "ffff:ffff:ffff:ffff:e000::") != 0) {
		fprintf(stderr, "error in %d: %s\n", __LINE__, p);
		exit(1);
	}

	p = ipv6_prefix_to_mask(str, 64);
	if (p == NULL || strcmp(p, "ffff:ffff:ffff:ffff::") != 0) {
		fprintf(stderr, "error in %d: %s\n", __LINE__, p);
		exit(1);
	}

	p = ipv6_prefix_to_mask(str, 59);
	if (p == NULL || strcmp(p, "ffff:ffff:ffff:ffe0::") != 0) {
		fprintf(stderr, "error in %d: %s\n", __LINE__, p);
		exit(1);
	}

	p = ipv6_prefix_to_mask(str, 48);
	if (p == NULL || strcmp(p, "ffff:ffff:ffff::") != 0) {
		fprintf(stderr, "error in %d: %s\n", __LINE__, p);
		exit(1);
	}

	p = ipv6_prefix_to_mask(str, 32);
	if (p == NULL || strcmp(p, "ffff:ffff::") != 0) {
		fprintf(stderr, "error in %d: %s\n", __LINE__, p);
		exit(1);
	}

	p = ipv6_prefix_to_mask(str, 12);
	if (p == NULL || strcmp(p, "fff0::") != 0) {
		fprintf(stderr, "error in %d: %s\n", __LINE__, p);
		exit(1);
	}

	return 0;
}
