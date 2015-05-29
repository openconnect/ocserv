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
#include "../src/common-json.h"

static char *strings[] = 
{
	"hello there",
	"hi bro\n",
	"small ascii\x10\x01\x03\x04\x18\x20\x21\x1f end",
	"try to escape \"quotes",
	"try to escape \\escapes",
	"\tbig pile  \b\b of stuff\r\n"
};

static char *encoded_strings[] = 
{
	"hello there",
	"hi bro\\u000a",
	"small ascii\\u0010\\u0001\\u0003\\u0004\\u0018 !\\u001f end",
	"try to escape \\\"quotes",
	"try to escape \\\\escapes",
	"\\u0009big pile  \\u0008\\u0008 of stuff\\u000d\\u000a"
};

int main()
{
	char tmp[512];
	char *p;
	unsigned i;

	for (i=0;i<sizeof(strings)/sizeof(strings[0]);i++) {
		tmp[0] = 0;
		p = json_escape_val(tmp, sizeof(tmp), strings[i]);
		if (strcmp(p, encoded_strings[i]) != 0) {
			fprintf(stderr, "string %d, fails encoding:\n\tinput: '%s'\n\toutput: '%s'\n", i, strings[i], p);
			exit(1);
		}
	}
	return 0;
}
