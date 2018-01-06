/*
 * Copyright (C) 2018 Nikos Mavrogiannopoulos
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
#include <occtl/occtl.h>
#include <c-strcase.h>
#include <minmax.h>
#include <common.h>

typedef struct session_entries_st {
	char session[SAFE_ID_SIZE];
} session_entries_st;

static session_entries_st *session_entries = NULL;
static unsigned session_entries_size = 0;
static unsigned max_session_entries_size = 0;

void session_entries_clear(void)
{
	session_entries_size = 0;
}

void session_entries_add(void *pool, const char* session)
{
	if (session_entries_size+1 > max_session_entries_size) {
		max_session_entries_size += 128;
		session_entries = talloc_realloc_size(pool, session_entries, sizeof(session_entries_st)*max_session_entries_size);
	}

	strlcpy(session_entries[session_entries_size].session, session, sizeof(session_entries[session_entries_size].session));
	session_entries_size++;

	return;
}

char* search_for_session(unsigned idx, const char* match, int match_size)
{
unsigned i;

	if (idx >= session_entries_size)
		return NULL;

	for (i=idx;i<session_entries_size;i++) {
		if (c_strncasecmp(match, session_entries[i].session, MIN(match_size, SAFE_ID_SIZE)) == 0)
			return strdup(session_entries[i].session);
	}

	return NULL;
}
