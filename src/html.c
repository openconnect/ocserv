/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
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
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <common.h>
#include <c-strcase.h>
#include <c-ctype.h>
#include <wchar.h>

#include "html.h"

char *unescape_html(void *pool, const char *html, unsigned len, unsigned *out_len)
{
	char *msg;
	int pos;
	unsigned i;

	msg = talloc_size(pool, len + 1);
	if (msg == NULL)
		return NULL;

	for (i = pos = 0; i < len;) {
		if (len-pos < 1) {
			goto fail;
		}

		if (html[i] == '&') {
			if (!c_strncasecmp(&html[i], "&lt;", 4)) {
				msg[pos++] = '<';
				i += 4;
			} else if (!c_strncasecmp(&html[i], "&gt;", 4)) {
				msg[pos++] = '>';
				i += 4;
			} else if (!c_strncasecmp(&html[i], "&nbsp;", 6)) {
				msg[pos++] = ' ';
				i += 6;
			} else if (!c_strncasecmp(&html[i], "&quot;", 6)) {
				msg[pos++] = '"';
				i += 6;
			} else if (!c_strncasecmp(&html[i], "&amp;", 5)) {
				msg[pos++] = '&';
				i += 5;
			} else if (!c_strncasecmp(&html[i], "&apos;", 6)) {
				msg[pos++] = '\'';
				i += 6;
			} else if (!strncmp(&html[i], "&#", 2)) {
				const char *p = &html[i];
				char *endptr = NULL;
				long val;

				if (p[2]=='x') {
					p += 3;
					val = strtol(p, &endptr, 16);
				} else {
					p += 2;
					val = strtol(p, &endptr, 10);
				}
				if (endptr == NULL || *endptr != ';' || val > WCHAR_MAX) {
					/* skip */
					msg[pos++] = html[i++];
				} else {
					char tmpmb[MB_CUR_MAX];
					wchar_t ch = val;
					mbstate_t ps;
					memset(&ps, 0, sizeof(ps));

					i += (ptrdiff_t)(1+endptr-(&html[i]));
					val = wcrtomb(tmpmb, ch, &ps);

					if (val == -1)
						goto fail;
					if (len-pos > val)
						memcpy(&msg[pos], tmpmb, val);
					else
						goto fail;
					pos += val;
				}
			} else
				msg[pos++] = html[i++];
		} else
			msg[pos++] = html[i++];
	}

	msg[pos] = 0;
	if (out_len)
		*out_len = pos;

	return msg;
 fail:
 	talloc_free(msg);
 	return NULL;
}

char *unescape_url(void *pool, const char *url, unsigned len, unsigned *out_len)
{
	char *msg;
	int pos;
	unsigned i;

	msg = talloc_size(pool, len + 1);
	if (msg == NULL)
		return NULL;

	for (i = pos = 0; i < len;) {
		if (url[i] == '%') {
			char b[3];
			unsigned int u;

			b[0] = url[i + 1];
			b[1] = url[i + 2];
			b[2] = 0;

			if (sscanf(b, "%02x", &u) <= 0) {
				talloc_free(msg);
				syslog(LOG_ERR, "%s: error parsing URL: %s", __func__, url);
				return NULL;
			}

			msg[pos++] = u;
			i += 3;
		} else if (url[i] == '+') {
			msg[pos++] = ' ';
			i++;
		} else
			msg[pos++] = url[i++];
	}

	msg[pos] = 0;
	if (out_len)
		*out_len = pos;

	return msg;
}

char *escape_url(void *pool, const char *url, unsigned len, unsigned *out_len)
{
	char *msg;
	int pos;
	unsigned i;

	msg = talloc_size(pool, 3*len + 1);
	if (msg == NULL)
		return NULL;

	for (i = pos = 0; i < len;) {
		if (c_isalnum(url[i]) || url[i]=='-' || url[i]=='_' || url[i]=='.' || url[i]=='~') {
			msg[pos++] = url[i++];
		} else if (url[i] == ' ') {
			msg[pos++] = '+';
			i++;
		} else {
			snprintf(&msg[pos], 4, "%%%02X", (unsigned)url[i++]);
			pos+=3;
		}
	}
	msg[pos] = 0;
	if (out_len)
		*out_len = pos;

	return msg;
}

