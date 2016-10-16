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
	"hello there",
	"hi bro\n",
	"small ascii\x10\x01\x03\x04\x18\x20\x21\x1f end",
	"try to escape \"quotes",
	"try to escape \\escapes",
	"\tbig pile  \b\b of stuff\r\n",
	"<hi there>",
	"\"hi there\""
};

static char *encoded_strings[] = 
{
	"hello there",
	"hi bro&#x000a;",
	"small ascii&#x0010;&#x0001;&#x0003;&#x0004;&#x0018; !&#x001f; end",
	"try to escape &quot;quotes",
	"try to escape \\escapes",
	"&#x0009;big pile  &#x0008;&#x0008; of stuff&#x000d;&#x000a;",
	"&lt;hi&nbsp;there&gt;",
	"&quot;hi there&quot;"
};

int main()
{
	char *dec;
	unsigned i;
	unsigned len;

	for (i=0;i<sizeof(encoded_strings)/sizeof(encoded_strings[0]);i++) {
		dec = unescape_html(NULL, encoded_strings[i], strlen(encoded_strings[i]), &len);
		if (dec == NULL) {
			fprintf(stderr, "failed to unescape %s\n", encoded_strings[i]);
			exit(1);
		}
		if (strcmp(dec, strings[i]) != 0) {
			fprintf(stderr, "string %d, fails decoding:\n\tinput: '%s'\n\toutput: '%s'\n", i, strings[i], dec);
			exit(1);
		}
		talloc_free(dec);
	}
	return 0;
}
