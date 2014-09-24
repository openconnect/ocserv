/*
 * Copyright (C) 2013, 2014 Nikos Mavrogiannopoulos
 * Copyright (C) 2014 Red Hat
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

#include <ccan/htable/htable.h>
#include <ccan/hash/hash.h>
#include <ip-lease.h>
#include <main.h>
#include <cookies.h>

int decrypt_cookie(ProtobufCAllocator *pa, gnutls_datum_t *key,
			uint8_t* cookie, unsigned cookie_size, 
			Cookie **msg)
{
gnutls_datum_t iv = { (void*)cookie, COOKIE_IV_SIZE };
int ret;
uint8_t tag[COOKIE_MAC_SIZE];
gnutls_cipher_hd_t h;
uint8_t *p;
unsigned p_size;

	if (cookie_size <= COOKIE_IV_SIZE+COOKIE_MAC_SIZE)
		return -1;

	ret = gnutls_cipher_init(&h, GNUTLS_CIPHER_AES_128_GCM, key, &iv);
	if (ret < 0)
		return -1;

	cookie += COOKIE_IV_SIZE;
	cookie_size -= (COOKIE_IV_SIZE + COOKIE_MAC_SIZE);

	ret = gnutls_cipher_decrypt2(h, cookie, cookie_size, cookie, cookie_size);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	p = cookie;
	p_size = cookie_size;

	ret = gnutls_cipher_tag(h, tag, sizeof(tag));
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}
	cookie += cookie_size;
	if (memcmp(tag, cookie, COOKIE_MAC_SIZE) != 0) {
		ret = -1;
		goto cleanup;
	}

	/* unpack */
	*msg = cookie__unpack(pa, p_size, p);
	if (*msg == NULL) {
		ret = -1;
		goto cleanup;
	}

	ret = 0;

cleanup:
	gnutls_cipher_deinit(h);

	return ret;
}

int encrypt_cookie(void *pool, gnutls_datum_t *key, const Cookie *msg,
        uint8_t** ecookie, unsigned *ecookie_size)
{
uint8_t _iv[COOKIE_IV_SIZE];
gnutls_cipher_hd_t h = NULL;
gnutls_datum_t iv = { _iv, sizeof(_iv) };
int ret;
unsigned packed_size, e_size;
uint8_t *packed = NULL, *e;

	/* pack the cookie */
	packed_size = cookie__get_packed_size(msg);
	if (packed_size == 0)
		return -1;

	packed = talloc_size(pool, packed_size);
	if (packed == NULL)
		return -1;

	ret = cookie__pack(msg, packed);
	if (ret == 0) {
		ret = -1;
		goto cleanup;
	}

	ret = gnutls_rnd(GNUTLS_RND_NONCE, _iv, sizeof(_iv));
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	ret = gnutls_cipher_init(&h, GNUTLS_CIPHER_AES_128_GCM, key, &iv);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	e_size = packed_size+COOKIE_IV_SIZE+COOKIE_MAC_SIZE;
	e = talloc_size(pool, e_size);
	if (e == NULL) {
		ret = -1;
		goto cleanup;
	}

	*ecookie = e;
	*ecookie_size = e_size;

	memcpy(e, _iv, COOKIE_IV_SIZE);
	e += COOKIE_IV_SIZE;
	e_size -= COOKIE_IV_SIZE;

	ret = gnutls_cipher_encrypt2(h, packed, packed_size, e, e_size);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	e += packed_size;

	ret = gnutls_cipher_tag(h, e, COOKIE_MAC_SIZE);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	ret = 0;

cleanup:
	talloc_free(packed);
	if (h != NULL)
		gnutls_cipher_deinit(h);
	return ret;

}

void cookie_db_deinit(struct cookie_entry_db_st* db)
{
struct cookie_entry_st * e;
struct htable_iter iter;

	e = htable_first(db->db, &iter);
	while(e != NULL) {
		if (e->proc)
			e->proc->cookie_ptr = NULL;

		e->proc = NULL;
		talloc_free(e);

		e = htable_next(db->db, &iter);
	}
	htable_clear(db->db);
	talloc_free(db->db);

	return;
}

void expire_cookies(struct cookie_entry_db_st* db)
{
struct cookie_entry_st * e;
struct htable_iter iter;
time_t now = time(0);

	e = htable_first(db->db, &iter);
	while(e != NULL) {
		if (e->expiration == -1 || now < e->expiration)
			goto cont;

		if (e->proc) {
			syslog(LOG_ERR, "found proc that references expired cookie!");
			e->proc->cookie_ptr = NULL;
		}

		htable_delval(db->db, &iter);
		db->total--;

		talloc_free(e);
 cont:
		e = htable_next(db->db, &iter);
	}

	return;
}

static size_t rehash(const void* _e, void* unused)
{
const struct cookie_entry_st * e = _e;

	return hash_any(e->cookie_hash, sizeof(e->cookie_hash), 0);
}

void cookie_db_init(void *pool, struct cookie_entry_db_st* db)
{
	db->db = talloc(pool, struct htable);
	htable_init(db->db, rehash, NULL);
	db->total = 0;
}

static bool cookie_entry_cmp(const void* _c1, void* _c2)
{
const struct cookie_entry_st* c1 = _c1;
struct cookie_entry_st* c2 = _c2;

	if (memcmp(c1->cookie_hash, c2->cookie_hash, sizeof(c1->cookie_hash)) == 0)
		return 1;

	return 0;
}

struct cookie_entry_st *find_cookie_entry(struct cookie_entry_db_st* db, void *cookie, unsigned cookie_size)
{
	struct cookie_entry_st *e;
	struct cookie_entry_st t;
	int ret;

	ret = gnutls_hash_fast(COOKIE_HASH, cookie, cookie_size, t.cookie_hash);
	if (ret < 0) {
		return NULL;
	}

	e = htable_get(db->db, hash_any(t.cookie_hash, sizeof(t.cookie_hash), 0), cookie_entry_cmp, &t);
	if (e == NULL)
		return NULL;

	if (e->expiration != -1 && e->expiration < time(0))
		return NULL;

	return e;
}

struct cookie_entry_st *new_cookie_entry(struct cookie_entry_db_st* db, proc_st *proc, void *cookie, unsigned cookie_size)
{
	struct cookie_entry_st *t;
	int ret;

	t = talloc(db->db, struct cookie_entry_st);
	if (t == NULL)
		return NULL;

	t->expiration = -1;

	ret = gnutls_hash_fast(COOKIE_HASH, cookie, cookie_size, t->cookie_hash);
	if (ret < 0) {
		goto fail;
	}

	t->proc = proc;

	if (htable_add(db->db, rehash(t, NULL), t) == 0) {
		goto fail;
	}

	db->total++;

	return t;

 fail:
 	talloc_free(t);
 	return NULL;
}
