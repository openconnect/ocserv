/*
 * Copyright (C) 2014, 2015 Red Hat
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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <c-ctype.h>
#include <occtl.h>
#include <common.h>
#include <common-json.h>
#include <c-strcase.h>

#define MAX_STR_SIZE 512

#define escape_val json_escape_val

int print_list_entries(FILE* out, cmd_params_st *params, const char* name, char **val, unsigned vsize, unsigned have_more)
{
	const char * tmp;
	unsigned int i = 0;

	if (HAVE_JSON(params)) {
		fprintf(out, "    \"%s\":\t[", name);
		for (i=0;i<vsize;i++) {
			tmp = val[i];
			if (tmp != NULL) {
				if (i==0)
					fprintf(out, "%s", tmp);
				else
					fprintf(out, ", %s", tmp);
			}
		}
		fprintf(out, "]%s\n", have_more?",":"");
	} else {
		for (i=0;i<vsize;i++) {
			tmp = val[i];
			if (tmp != NULL) {
				if (i==0)
					fprintf(out, "\t%s: %s\n", name, tmp);
				else
					fprintf(out, "\t\t%s\n", tmp);
			}
		}
	}

	return i;
}

void print_start_block(FILE *out, cmd_params_st *params)
{
	if (HAVE_JSON(params))
		fprintf(out, "  {\n");
}

void print_end_block(FILE *out, cmd_params_st *params, unsigned have_more)
{
	if (HAVE_JSON(params))
		fprintf(out, "  }%s\n", have_more?",":"");
}

void print_array_block(FILE *out, cmd_params_st *params)
{
	if (HAVE_JSON(params))
		fprintf(out, "[\n");
}

void print_end_array_block(FILE *out, cmd_params_st *params)
{
	if (HAVE_JSON(params))
		fprintf(out, "]\n");
}

void print_separator(FILE *out, cmd_params_st *params)
{
	if (NO_JSON(params))
		fprintf(out, "\n");
}

void print_single_value(FILE *out, cmd_params_st *params, const char *name, const char *value, unsigned have_more)
{
	char tmp[MAX_STR_SIZE];
	if (value[0] == 0)
		return;

	if (HAVE_JSON(params))
		fprintf(out, "    \"%s\":  \"%s\"%s\n", name, escape_val(tmp, sizeof(tmp), value), have_more?",":"");
	else
		fprintf(out, "\t%s: %s\n", name, value);
}

void print_single_value_int(FILE *out, cmd_params_st *params, const char *name, long i, unsigned have_more)
{
	if (HAVE_JSON(params))
		fprintf(out, "    \"%s\":  \%lu%s\n", name, i, have_more?",":"");
	else
		fprintf(out, "\t%s: %lu\n", name, i);
}

void print_single_value_ex(FILE *out, cmd_params_st *params, const char *name, const char *value, const char *ex, unsigned have_more)
{
	char tmp[MAX_STR_SIZE];
	if (value[0] == 0)
		return;

	if (HAVE_JSON(params)) {
		fprintf(out, "    \"%s\":  \"%s\",\n", name, escape_val(tmp, sizeof(tmp), value));
		fprintf(out, "    \"_%s\":  \"%s\"%s\n", name, escape_val(tmp, sizeof(tmp), ex), have_more?",":"");
	} else
		fprintf(out, "\t%s: %s (%s)\n", name, value, ex);
}

void print_pair_value(FILE *out, cmd_params_st *params, const char *name1, const char *value1, const char *name2, const char *value2, unsigned have_more)
{
	char tmp[MAX_STR_SIZE];
	if (HAVE_JSON(params)) {
		if (value1 && value1[0] != 0)
			fprintf(out, "    \"%s\":  \"%s\"%s\n", name1, escape_val(tmp, sizeof(tmp), value1), have_more?",":"");
		if (value2 && value2[0] != 0)
			fprintf(out, "    \"%s\":  \"%s\"%s\n", name2, escape_val(tmp, sizeof(tmp), value2), have_more?",":"");
	} else {
		if (value1 && value1[0] != 0)
			fprintf(out, "\t%s: %s", name1, value1);

		if (value2 && value2[0] != 0) {
			const char *sep;
			if (name1)
				sep = "   ";
			else
				sep = "\t";
			fprintf(out, "%s%s: %s", sep, name2, value2);
		}
		if ((value1 && value1[0] != 0) || (value2 && value2[0] != 0))
			fprintf(out, "\n");
	}
}
