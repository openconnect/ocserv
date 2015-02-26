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
#include <common.h>

typedef struct ip_entries_st {
	char ip[MAX_IP_STR];
	unsigned ip_size;
} ip_entries_st;

static ip_entries_st *ip_entries = NULL;
static unsigned ip_entries_size = 0;
static unsigned max_ip_entries_size = 0;

void ip_entries_clear(void)
{
unsigned i;

	for (i=0;i<ip_entries_size;i++) {
		ip_entries[i].ip_size = 0;
	}
	ip_entries_size = 0;
}

void ip_entries_add(void *pool, const char* ip, unsigned ip_size)
{
	if (ip_entries_size+1 > max_ip_entries_size) {
		max_ip_entries_size += 128;
		ip_entries = talloc_realloc_size(pool, ip_entries, sizeof(ip_entries_st)*max_ip_entries_size);
	}
	
	strlcpy(ip_entries[ip_entries_size].ip, ip, sizeof(ip_entries[ip_entries_size].ip));
	ip_entries[ip_entries_size].ip_size = ip_size;
	ip_entries_size++;
	
	return;
}

char* search_for_ip(unsigned idx, const char* match, int match_size)
{
unsigned i;

	if (idx >= ip_entries_size)
		return NULL;

	for (i=idx;i<ip_entries_size;i++) {
		if (match_size <= ip_entries[i].ip_size) {
			if (c_strncasecmp(match, ip_entries[i].ip, match_size) == 0)
				return strdup(ip_entries[i].ip);
		}
	}
	
	return NULL;
}
