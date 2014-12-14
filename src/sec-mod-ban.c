/*
 * Copyright (C) 2014 Red Hat
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <system.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <common.h>
#include <syslog.h>
#include <vpn.h>
#include <tlslib.h>
#include <sec-mod.h>
#include <ccan/hash/hash.h>
#include <ccan/htable/htable.h>

typedef struct ban_entry_st {
	char ip[MAX_IP_STR];
	time_t expires; /* the time after the client is allowed to login */
} ban_entry_st;

static size_t rehash(const void *_e, void *unused)
{
	ban_entry_st *e = (void*)_e;
	return hash_any(e->ip, strlen(e->ip), 0);

}

void *sec_mod_ban_db_init(sec_mod_st *sec)
{
	struct htable *db = talloc(sec, struct htable);
	if (db == NULL)
		return NULL;

	htable_init(db, rehash, NULL);
	sec->ban_db = db;

	return db;
}

void sec_mod_ban_db_deinit(sec_mod_st *sec)
{
struct htable *db = sec->ban_db;

	if (db != NULL) {
		htable_clear(db);
		talloc_free(db);
	}
}

unsigned sec_mod_ban_db_elems(sec_mod_st *sec)
{
struct htable *db = sec->ban_db;

	if (db)
		return db->elems;
	else
		return 0;
}

void add_ip_to_ban_list(sec_mod_st *sec, const char *ip, time_t reenable_time)
{
	struct htable *db = sec->ban_db;
	struct ban_entry_st *e;

	if (db == NULL)
		return;

	e = talloc_zero(db, ban_entry_st);
	if (e == NULL) {
		return;
	}

	strlcpy(e->ip, ip, sizeof(e->ip));
	e->expires = reenable_time;

	if (htable_add(db, rehash(e, NULL), e) == 0) {
		seclog(sec, LOG_INFO,
		       "could not add ban entry to hash table");
		goto fail;
	}

	seclog(sec, LOG_INFO,"added IP '%s' to ban list, will be removed at: %u", ip, (unsigned)reenable_time);
	return;
 fail:
	talloc_free(e);
	return;
}

/* The first argument is the entry from the hash, and
 * the second is the entry from check_if_banned().
 */
static bool ban_entry_cmp(const void *_c1, void *_c2)
{
	const struct ban_entry_st *c1 = _c1;
	struct ban_entry_st *c2 = _c2;

	if (strcmp(c1->ip, c2->ip) == 0 && c2->expires < c1->expires)
		return 1;
	return 0;
}

unsigned check_if_banned(sec_mod_st *sec, const char *ip)
{
	struct htable *db = sec->ban_db;
	ban_entry_st t;

	if (db == NULL || ip == NULL || ip[0] == 0)
		return 0;

	/* pass the current time somehow */
	t.expires = time(0);
	strlcpy(t.ip, ip, sizeof(t.ip));

	if (htable_get(db, rehash(&t, NULL), ban_entry_cmp, &t) != 0)
		return 1;
	return 0;
}

void cleanup_banned_entries(sec_mod_st *sec)
{
	struct htable *db = sec->ban_db;
	ban_entry_st *t;
	struct htable_iter iter;
	time_t now = time(0);

	if (db == NULL)
		return;

	t = htable_first(db, &iter);
	while (t != NULL) {
		if (now >= t->expires) {
			htable_delval(db, &iter);
			talloc_free(t);
		}
		t = htable_next(db, &iter);

	}
}
