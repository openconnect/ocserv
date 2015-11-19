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

static char *myfunc(void *pool, const char *str)
{
	return talloc_strdup(pool, str);
}

#define STR1 "hi there people. How are you?"
int main()
{
	str_st str;
	str_rep_tab tab[16];

	str_init(&str, NULL);

	if (str_append_printf(&str, "hi there %s", "people.") != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (str_append_str(&str, " How are you?") != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (str.length != sizeof(STR1)-1 ||
	    strncmp((char*)str.data, STR1, sizeof(STR1)-1) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	/* check replaces */
	STR_TAB_SET(0, "%R", "route1");
	STR_TAB_SET(1, "%{R}", "route2");
	STR_TAB_SET(2, "%{R2}", "route3");
	STR_TAB_SET(3, "%{D}", "dev1");
	STR_TAB_SET(4, "%D", "dev2");
	STR_TAB_SET(5, "%U", "u1");
	STR_TAB_SET_FUNC(6, "%{FUNC}", myfunc, "function-output");
	STR_TAB_TERM(7);

	/* check proper operation */
#define STR2 "This is one route1, and one route2, while a route3 was replaced by dev1 and dev2 and dev1. That's all u1."
	str_reset(&str);
	if (str_append_str(&str, "This is one %R, and one %{R}, while a %{R2} was replaced by %{D} and %D and %{D}. That's all %U.") != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (str_replace_str(&str, tab) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (str.length != sizeof(STR2)-1) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (strncmp((char*)str.data, STR2, sizeof(STR2)-1) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	/* check failure on unknown pattern */
	str_reset(&str);
	str_append_str(&str, "This is one %A.");
	if (str_replace_str(&str, tab) == 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

#define STR3 "%U: Testing %{FUNC}."
#define STR3_OUT "u1: Testing function-output."
	str_reset(&str);
	str_append_str(&str, STR3);

	if (str_replace_str(&str, tab) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (str.length != sizeof(STR3_OUT)-1) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (strncmp((char*)str.data, STR3_OUT, sizeof(STR3_OUT)-1) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	str_clear(&str);

	return 0;
}
