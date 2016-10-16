/*
 * Copyright (C) 2016 Nikos Mavrogiannopoulos
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
#include "../src/html.h"
#include "../src/html.c"

static char *strings[] = 
{
	"Laguna%20Beach",
	"%20",
	"Laguna%25%2B%40Beach"
};

static char *decoded_strings[] = 
{
	"Laguna Beach",
	" ",
	"Laguna%+@Beach"
};

int main()
{
	char *dec, *url;
	unsigned i;
	unsigned len;

	for (i=0;i<sizeof(strings)/sizeof(strings[0]);i++) {
		dec = unescape_url(NULL, strings[i], strlen(strings[i]), &len);
		if (strcmp(dec, decoded_strings[i]) != 0) {
			fprintf(stderr, "string %d, fails decoding:\n\tinput: '%s'\n\toutput: '%s'\n", i, decoded_strings[i], dec);
			exit(1);
		}
		talloc_free(dec);

		url = escape_url(NULL, decoded_strings[i], strlen(decoded_strings[i]), &len);
		if (strcmp(url, strings[i]) != 0) {
			fprintf(stderr, "string %d, fails encoding:\n\tinput: '%s'\n\toutput: '%s'\n", i, decoded_strings[i], url);
			exit(1);
		}
		talloc_free(url);
	}
	return 0;
}
