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

#include <sec-mod-sup-config.h>
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

void *get_brackets_string1(struct cfg_st *config, const char *str)
{
	char *p, *p2;
	unsigned len;

	p = strchr(str, '[');
	if (p == NULL) {
		return NULL;
	}
	p++;
	while (c_isspace(*p))
		p++;

	p2 = strchr(p, ',');
	if (p2 == NULL) {
		p2 = strchr(p, ']');
		if (p2 == NULL) {
			fprintf(stderr, "error parsing %s\n", str);
			exit(1);
		}
	}

	len = p2 - p;

	return talloc_strndup(config, p, len);
}

#ifdef HAVE_RADIUS
static void *get_brackets_string2(struct cfg_st *config, const char *str)
{
	char *p, *p2;
	unsigned len;

	p = strchr(str, '[');
	if (p == NULL) {
		return NULL;
	}
	p++;

	p = strchr(p, ',');
	if (p == NULL) {
		return NULL;
	}
	p++;

	while (c_isspace(*p))
		p++;

	p2 = strchr(p, ',');
	if (p2 == NULL) {
		p2 = strchr(p, ']');
		if (p2 == NULL) {
			fprintf(stderr, "error parsing %s\n", str);
			exit(1);
		}
	}

	len = p2 - p;

	return talloc_strndup(config, p, len);
}

void *radius_get_brackets_string(struct cfg_st *config, const char *str)
{
	char *p;
	subcfg_val_st vals[MAX_SUBOPTIONS];
	unsigned vals_size, i;
	radius_cfg_st *additional;

	additional = talloc_zero(config, radius_cfg_st);
	if (additional == NULL) {
		return NULL;
	}

	if (str && str[0] == '[' && str[1] == '/') { /* legacy format */
		fprintf(stderr, "Parsing radius auth method subconfig using legacy format\n");

		additional->config = get_brackets_string1(config, str);
		if (additional->config == NULL) {
			fprintf(stderr, "No radius configuration specified: %s\n", str);
			exit(1);
		}

		p = get_brackets_string2(config, str);
		if (p != NULL) {
			if (strcasecmp(p, "groupconfig") != 0) {
				fprintf(stderr, "No known configuration option: %s\n", p);
				exit(1);
			}
			config->sup_config_type = SUP_CONFIG_RADIUS;
		}
	} else {
		/* new format */
		vals_size = expand_brackets_string(config, str, vals);
		for (i=0;i<vals_size;i++) {
			if (c_strcasecmp(vals[i].name, "config") == 0) {
				additional->config = talloc_strdup(config, vals[i].value);
				vals[i].value = NULL;
			} else if (c_strcasecmp(vals[i].name, "groupconfig") == 0) {
				if (CHECK_TRUE(vals[i].value))
					config->sup_config_type = SUP_CONFIG_RADIUS;
			} else {
				fprintf(stderr, "unknown option '%s'\n", vals[i].name);
				exit(1);
			}
		}
		free_expanded_brackets_string(vals, vals_size);
	}

	return additional;
}
#endif

#ifdef HAVE_PAM
void *pam_get_brackets_string(struct cfg_st *config, const char *str)
{
	subcfg_val_st vals[MAX_SUBOPTIONS];
	unsigned vals_size, i;
	pam_cfg_st *additional;

	additional = talloc_zero(config, pam_cfg_st);
	if (additional == NULL) {
		return NULL;
	}

	/* new format */
	vals_size = expand_brackets_string(config, str, vals);
	for (i=0;i<vals_size;i++) {
		if (c_strcasecmp(vals[i].name, "gid-min") == 0) {
			additional->gid_min = atoi(vals[i].value);
			if (additional->gid_min < 0) {
				fprintf(stderr, "error in gid-min value: %d\n", additional->gid_min);
				exit(1);
			}
		} else {
			fprintf(stderr, "unknown option '%s'\n", vals[i].name);
			exit(1);
		}
	}

	free_expanded_brackets_string(vals, vals_size);
	return additional;
}
#endif
