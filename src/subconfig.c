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
#include <unistd.h>
#include <sys/types.h>
#include <c-strcase.h>
#include <c-ctype.h>

#include <common.h>
#include <vpn.h>
#include "cfg.h"

/* Returns the number of suboptions processed.
 */
unsigned expand_brackets_string(struct cfg_st *config, const char *str, subcfg_val_st out[MAX_SUBOPTIONS])
{
	char *p, *p2, *p3;
	unsigned len, len2;
	unsigned pos = 0, finish = 0;

	p = strchr(str, '[');
	if (p == NULL) {
		return 0;
	}
	p++;
	while (c_isspace(*p))
		p++;

	do {
		p2 = strchr(p, '=');
		if (p2 == NULL) {
			if (p2 == NULL) {
				fprintf(stderr, "error parsing %s\n", str);
				exit(1);
			}
		}
		len = p2 - p;

		p2++;
		while (c_isspace(*p2))
			p2++;

		p3 = strchr(p2, ',');
		if (p3 == NULL) {
			p3 = strchr(p2, ']');
			if (p3 == NULL) {
				fprintf(stderr, "error parsing %s\n", str);
				exit(1);
			}
			finish = 1;
		}
		len2 = p3 - p2;

		while (c_isspace(p[len-1]))
			len--;
		while (c_isspace(p2[len2-1]))
			len2--;

		out[pos].name = talloc_strndup(config, p, len);
		out[pos].value = talloc_strndup(config, p2, len2);
		pos++;
		
	} while(finish == 0 && pos < MAX_SUBOPTIONS);

	return pos;
}

#ifdef HAVE_GSSAPI
void *gssapi_get_brackets_string(struct cfg_st *config, const char *str)
{
	subcfg_val_st vals[MAX_SUBOPTIONS];
	unsigned vals_size, i;
	gssapi_cfg_st *additional;

	additional = talloc_zero(config, gssapi_cfg_st);
	if (additional == NULL) {
		return NULL;
	}

	vals_size = expand_brackets_string(config, str, vals);
	for (i=0;i<vals_size;i++) {
		if (c_strcasecmp(vals[i].name, "keytab") == 0) {
			additional->keytab = talloc_strdup(config, vals[i].value);
			vals[i].value = NULL;
		} else if (c_strcasecmp(vals[i].name, "require-local-user-map") == 0) {
			additional->no_local_map = 1-CHECK_TRUE(vals[i].value);
		} else {
			fprintf(stderr, "unknown option '%s'\n", vals[i].name);
			exit(1);
		}
	}
	free_expanded_brackets_string(vals, vals_size);
	return additional;
}
#endif
