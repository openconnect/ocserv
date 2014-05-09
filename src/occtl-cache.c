/*
 * Copyright (C) 2014 Red Hat
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
#include <occtl.h>
#include <c-strcase.h>
#include <minmax.h>

typedef struct uid_entries_st {
	char* user;
	unsigned user_size;
	char id[8];
	unsigned id_size;
} uid_entries_st;

static uid_entries_st *entries = NULL;
static unsigned entries_size = 0;
static unsigned max_entries_size = 0;

void entries_clear(void)
{
unsigned i;

	for (i=0;i<entries_size;i++) {
		talloc_free(entries[i].user);
		entries[i].user = 0;
	}
	entries_size = 0;
}

void entries_add(void *pool, const char* user, unsigned user_size, unsigned id)
{
	if (entries_size+1 > max_entries_size) {
		max_entries_size += 128;
		entries = talloc_realloc_size(pool, entries, sizeof(uid_entries_st)*max_entries_size);
	}
	
	entries[entries_size].user = talloc_strdup(pool, user);
	entries[entries_size].user_size = user_size;
	entries[entries_size].id_size = 
		snprintf(entries[entries_size].id, sizeof(entries[entries_size].id), "%u", id);
	
	entries_size++;
	
	return;
}

char* search_for_user(unsigned idx, const char* match, int match_size)
{
unsigned i;

	if (idx >= entries_size)
		return NULL;

	for (i=idx;i<entries_size;i++) {
		if (match_size <= entries[i].user_size) {
			if (c_strncasecmp(match, entries[i].user, match_size) == 0)
				return strdup(entries[i].user);
		}
	}
	
	return NULL;
}

char* search_for_id(unsigned idx, const char* match, int match_size)
{
unsigned i;

	if (idx >= entries_size)
		return NULL;

	for (i=idx;i<entries_size;i++) {
		if (match_size <= entries[i].id_size) {
			if (c_strncasecmp(match, entries[i].id, match_size) == 0) {
				return strdup(entries[i].id);
			}
		}
	}
	
	return NULL;
}
