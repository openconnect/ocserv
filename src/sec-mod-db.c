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

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

static size_t rehash(const void *_e, void *unused)
{
	const client_entry_st *e = _e;

	return hash_any(e->sid, sizeof(e->sid), 0);
}

void *sec_mod_client_db_init(void *pool)
{
	struct htable *db = talloc(pool, struct htable);
	if (db == NULL)
		return NULL;

	htable_init(db, rehash, NULL);

	return db;
}

void sec_mod_client_db_deinit(void *_db)
{
struct htable *db = _db;

	htable_clear(db);
	talloc_free(db);
}

/* The number of elements */
unsigned sec_mod_client_db_elems(void *_db)
{
struct htable *db = _db;

	if (db)
		return db->elems;
	else
		return 0;
}

client_entry_st *new_client_entry(void *_db, const char *ip)
{
	struct htable *db = _db;
	client_entry_st *e;
	int ret;

	e = talloc_zero(db, client_entry_st);
	if (e == NULL) {
		return NULL;
	}

	snprintf(e->ip, sizeof(e->ip), "%s", ip);
	ret = gnutls_rnd(GNUTLS_RND_RANDOM, e->sid, sizeof(e->sid));
	if (ret < 0) {
		seclog(LOG_ERR, "error generating SID");
		goto fail;
	}
	e->time = time(0);

	if (htable_add(db, rehash(e, NULL), e) == 0) {
		seclog(LOG_ERR,
		       "could not add client entry to hash table");
		goto fail;
	}

	return e;

 fail:
	talloc_free(e);
	return NULL;
}

static bool client_entry_cmp(const void *_c1, void *_c2)
{
	const struct client_entry_st *c1 = _c1;
	struct client_entry_st *c2 = _c2;

	if (memcmp(c1->sid, c2->sid, SID_SIZE) == 0)
		return 1;
	return 0;
}

client_entry_st *find_client_entry(void *_db, uint8_t sid[SID_SIZE])
{
	struct htable *db = _db;
	client_entry_st t;

	memcpy(t.sid, sid, SID_SIZE);

	return htable_get(db, rehash(&t, NULL), client_entry_cmp, &t);
}

static void clean_entry(client_entry_st * e)
{
	sec_auth_user_deinit(e);
	talloc_free(e);
}

/* Allow few seconds prior to cleaning up entries, to avoid any race
 * conditions when session control is enabled.
 */
#define SLACK_TIME 10

void cleanup_client_entries(void *_db)
{
	struct htable *db = _db;
	client_entry_st *t;
	struct htable_iter iter;
	time_t now = time(0);

	t = htable_first(db, &iter);
	while (t != NULL) {
		if (t->have_session == 0 && now - t->time > MAX_AUTH_SECS + SLACK_TIME) {
			htable_delval(db, &iter);
			clean_entry(t);
		}
		t = htable_next(db, &iter);

	}
}

void del_client_entry(void *_db, client_entry_st * e)
{
	struct htable *db = _db;

	htable_del(db, rehash(e, NULL), e);
	clean_entry(e);
}
