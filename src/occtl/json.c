/*
 * Copyright (C) 2015 Red Hat
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>

/* Escapes @val and stores it in tmp. A fixed string is returned
 * in case tmp is too small.
 */
char *json_escape_val(char *tmp, unsigned tmp_size, const char *val)
{
	unsigned val_len = strlen(val);
	unsigned i, j;

	for (i=j=0;i<val_len;i++) {
		if (j + 7 >= tmp_size)
			return "(invalid)";
		if (val[i] == '"' || val[i] == '\\') {
		    snprintf(&tmp[j], 3, "\\%c", val[i]);
		    j+=2;
		} else if (val[i] <= 0x1F) {
		    snprintf(&tmp[j], 7, "\\u00%02x", (unsigned)val[i]);
		    j+=6;
		} else tmp[j++] = val[i];
	}
	tmp[j] = 0;

	return tmp;
}
