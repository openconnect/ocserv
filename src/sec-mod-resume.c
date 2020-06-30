/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
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
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <ccan/hash/hash.h>

#include <main.h>
#include <sec-mod-resume.h>
#include <common.h>
#include <ip-util.h>
#include <tlslib.h>

int handle_resume_delete_req(sec_mod_st *sec,
			     const SessionResumeFetchMsg *req)
{
	tls_cache_st *cache;
	struct htable_iter iter;
	size_t key;

	key = hash_any(req->session_id.data, req->session_id.len, 0);

	cache = htable_firstval(sec->tls_db.ht, &iter, key);
	while (cache != NULL) {
		if (req->session_id.len == cache->session_id_size &&
		    memcmp(req->session_id.data, cache->session_id,
			   req->session_id.len) == 0) {

			cache->session_data_size = 0;
			cache->session_id_size = 0;

			htable_delval(sec->tls_db.ht, &iter);
			talloc_free(cache);
			sec->tls_db.entries--;
			return 0;
		}

		cache = htable_nextval(sec->tls_db.ht, &iter, key);
	}

	return 0;
}

int handle_resume_fetch_req(sec_mod_st *sec,
			    const SessionResumeFetchMsg *req,
			    SessionResumeReplyMsg *rep)
{
	tls_cache_st *cache;
	struct htable_iter iter;
	size_t key;

	rep->reply = SESSION_RESUME_REPLY_MSG__RESUME__REP__FAILED;

	key = hash_any(req->session_id.data, req->session_id.len, 0);

	cache = htable_firstval(sec->tls_db.ht, &iter, key);
	while (cache != NULL) {
		if (req->session_id.len == cache->session_id_size &&
		    memcmp(req->session_id.data, cache->session_id,
			   req->session_id.len) == 0) {

			if (req->vhost && cache->vhostname && c_strcasecmp(req->vhost, cache->vhostname) != 0)
				return 0;
			else if (req->vhost != cache->vhostname)
				return 0;

			if (req->cli_addr.len == cache->remote_addr_len &&
			    ip_cmp((struct sockaddr_storage *)req->cli_addr.data, &cache->remote_addr) == 0) {

				rep->reply =
				    SESSION_RESUME_REPLY_MSG__RESUME__REP__OK;

				rep->has_session_data = 1;

				rep->session_data.data =
				    (void *)cache->session_data;
				rep->session_data.len =
				    cache->session_data_size;

				seclog_hex(sec, LOG_DEBUG, "TLS session DB resuming",
					  req->session_id.data,
					  req->session_id.len, 0);

				return 0;
			}
		}

		cache = htable_nextval(sec->tls_db.ht, &iter, key);
	}

	return 0;

}

int handle_resume_store_req(sec_mod_st *sec,
			    const SessionResumeStoreReqMsg *req)
{
	tls_cache_st *cache;
	size_t key;
	unsigned int max;

	if (req->session_id.len > GNUTLS_MAX_SESSION_ID)
		return -1;
	if (req->session_data.len > MAX_SESSION_DATA_SIZE)
		return -1;

	max = MAX(2 * GETCONFIG(sec)->max_clients, DEFAULT_MAX_CACHED_TLS_SESSIONS);
	if (sec->tls_db.entries >= max) {
		seclog(sec, LOG_INFO,
		      "maximum number of stored TLS sessions reached (%u)",
		      max);
		return -1;
	}

	if (req->cli_addr.len == 0) {
		seclog(sec, LOG_INFO,
		      "invalid address length");
		return -1;
	}

	key = hash_any(req->session_id.data, req->session_id.len, 0);

	cache = talloc(sec->tls_db.ht, tls_cache_st);
	if (cache == NULL)
		return -1;

	cache->session_id_size = req->session_id.len;
	cache->session_data_size = req->session_data.len;
	cache->remote_addr_len = req->cli_addr.len;
	if (req->vhost)
		cache->vhostname = talloc_strdup(cache, req->vhost);
	else
		cache->vhostname = NULL;

	memcpy(cache->session_id, req->session_id.data, req->session_id.len);
	memcpy(cache->session_data, req->session_data.data,
	       req->session_data.len);
	memcpy(&cache->remote_addr, req->cli_addr.data, req->cli_addr.len);

	if (htable_add(sec->tls_db.ht, key, cache) == 0) {
		seclog(sec, LOG_INFO,
		      "could not add TLS session to hash table");
		talloc_free(cache);
	} else {
		sec->tls_db.entries++;

		seclog_hex(sec, LOG_DEBUG, "TLS session DB storing",
					req->session_id.data,
					req->session_id.len, 0);
	}

	return 0;
}

void expire_tls_sessions(sec_mod_st *sec)
{
	tls_cache_st *cache;
	struct htable_iter iter;
	time_t now, exp;

	now = time(0);

	cache = htable_first(sec->tls_db.ht, &iter);
	while (cache != NULL) {
		gnutls_datum_t d;

		d.data = (void *)cache->session_data;
		d.size = cache->session_data_size;

		exp = gnutls_db_check_entry_time(&d);

		if (now - exp > TLS_SESSION_EXPIRATION_TIME(GETCONFIG(sec))) {
			cache->session_id_size = 0;

			htable_delval(sec->tls_db.ht, &iter);

			safe_memset(cache->session_data, 0, cache->session_data_size);
			talloc_free(cache);
			sec->tls_db.entries--;
		}
		cache = htable_next(sec->tls_db.ht, &iter);
	}

	return;
}
