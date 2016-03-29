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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>

#include "../src/str.h"
#include "../src/str.c"

#define STR1 "  hi there people. How are you?"
int main()
{
	char str[64];

	strcpy(str, STR1"     ");

	trim_trailing_whitespace(str);

	if (strncmp(str, STR1, sizeof(STR1)-1) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	strcpy(str, STR1" ");

	trim_trailing_whitespace(str);

	if (strncmp(str, STR1, sizeof(STR1)-1) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	strcpy(str, STR1);

	trim_trailing_whitespace(str);

	if (strncmp(str, STR1, sizeof(STR1)-1) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	strcpy(str, "  "STR1);

	trim_trailing_whitespace(str);

	if (strncmp(str, "  "STR1, sizeof("  "STR1)-1) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	strcpy(str, "  ");

	trim_trailing_whitespace(str);

	if (strncmp(str, "", sizeof("")-1) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	str[0] = 0;

	trim_trailing_whitespace(str);

	if (str[0] != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	return 0;
}
