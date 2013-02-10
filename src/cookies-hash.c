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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

#include <main.h>
#include <cookies.h>
#include <ccan/htable/htable.h>
#include <ccan/hash/hash.h>

#define MAX_COOKIES(n) ((n>0&&n>2048)?(2*n):4096)

/* receives allocated data and stores them.
 */
int store_cookie_hash(main_server_st *s, struct stored_cookie_st* sc)
{
size_t key;

	if (s->cookie_db->entries >= MAX_COOKIES(s->config->max_clients)) {
		syslog(LOG_INFO, "Maximum number of cookies was reached (%u)", MAX_COOKIES(s->config->max_clients));
		return -1;
	}

	key = hash_stable_8(sc->cookie, COOKIE_SIZE, 0);

	htable_add(&s->cookie_db->ht, key, sc);
	s->cookie_db->entries++;

	return 0;
}

int retrieve_cookie_hash(main_server_st *s, const void* cookie, unsigned cookie_size, 
			struct stored_cookie_st* rsc)
{
size_t key;
struct htable_iter iter;
struct stored_cookie_st * sc;

	key = hash_stable_8(cookie, cookie_size, 0);

	sc = htable_firstval(&s->cookie_db->ht, &iter, key);
	while(sc != NULL) {
		if (cookie_size == COOKIE_SIZE &&
	          memcmp (cookie, sc->cookie, COOKIE_SIZE) == 0) {

			if (sc->expiration < time(0))
				return -1;
			
			memcpy(rsc, sc, sizeof(*sc));
	          	return 0;
		}

          	sc = htable_nextval(&s->cookie_db->ht, &iter, key);
        }

	return -1;
}

void expire_cookies_hash(main_server_st* s)
{
struct stored_cookie_st *sc;
struct htable_iter iter;
time_t now = time(0);

	sc = htable_first(&s->cookie_db->ht, &iter);
	while(sc != NULL) {
		if (sc->expiration <= now) {
	          	htable_delval(&s->cookie_db->ht, &iter);
	          	free(sc);
			s->cookie_db->entries--;
		}
          	sc = htable_next(&s->cookie_db->ht, &iter);
        }
}

void erase_cookies_hash(main_server_st* s)
{
struct stored_cookie_st *sc;
struct htable_iter iter;
time_t now = time(0);

	sc = htable_first(&s->cookie_db->ht, &iter);
	while(sc != NULL) {
		if (sc->expiration <= now) {
	          	htable_delval(&s->cookie_db->ht, &iter);
	          	memset(sc->cookie, 0, sizeof(sc->cookie));
	          	free(sc);
			s->cookie_db->entries--;
		}
          	sc = htable_next(&s->cookie_db->ht, &iter);
        }
}

static size_t rehash(const void *_e, void *unused)
{
const struct stored_cookie_st *e = _e;

	return hash_stable_8(e->cookie, COOKIE_SIZE, 0);
}

int cookie_db_init_hash(main_server_st * s)
{
hash_db_st * db;

	db = malloc(sizeof(*db));
	if (db == NULL)
		return -1;

	htable_init(&db->ht, rehash, NULL);
	db->entries = 0;

	s->cookie_db = db;
	
	return 0;
}

void cookie_db_deinit_hash(main_server_st* s)
{
struct stored_cookie_st* cache;
struct htable_iter iter;

	cache = htable_first(&s->cookie_db->ht, &iter);
	while(cache != NULL) {
          	free(cache);
          	cache = htable_next(&s->cookie_db->ht, &iter);
        }
        htable_clear(&s->cookie_db->ht);
	s->cookie_db->entries = 0;

        return;
}

struct cookie_storage_st hash_cookie_funcs = {
	.store = store_cookie_hash,
	.retrieve = retrieve_cookie_hash,
	.expire = expire_cookies_hash,
	.erase = erase_cookies_hash,
	.init = cookie_db_init_hash,
	.deinit = cookie_db_deinit_hash,
};
