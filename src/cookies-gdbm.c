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
#include <gdbm.h>
#include <sys/stat.h>

#include <main.h>
#include <cookies.h>

#ifdef HAVE_GDBM

static
int cookie_gdbm_store(main_server_st *s, struct stored_cookie_st* sc)
{
GDBM_FILE dbf;
datum key;
datum data;
int ret;

	dbf = gdbm_open((char*)s->config->cookie_db_name, 0, GDBM_WRCREAT, S_IRUSR|S_IWUSR, NULL);
	if (dbf == NULL) {
		syslog(LOG_ERR, "Cannot open cookie database: %s", s->config->cookie_db_name);
		return -1;
	}

	key.dptr = (void*)sc->cookie;
	key.dsize = sizeof(sc->cookie);
	data.dptr = (void*)sc;
	data.dsize = sizeof(*sc);

	ret = gdbm_store( dbf, key, data, GDBM_INSERT);
	if (ret != 0) {
		ret = -1;
		goto finish;
	}

	ret = 0;

finish:
	free(sc);
	gdbm_close(dbf);
	return ret;
}

static
int cookie_gdbm_retrieve(main_server_st *s, const void* cookie, unsigned cookie_size, 
			struct stored_cookie_st* sc)
{
GDBM_FILE dbf;
datum key;
datum data;
int ret;

	dbf = gdbm_open((char*)s->config->cookie_db_name, 0, GDBM_READER, 0, NULL);
	if (dbf == NULL) {
		syslog(LOG_ERR, "Cannot open cookie database: %s", s->config->cookie_db_name);
		return -1;
	}

	key.dptr = (void*)cookie;
	key.dsize = cookie_size;

	data = gdbm_fetch( dbf, key);
	if (data.dsize != sizeof(*sc)) {
		ret = -1;
		goto finish;
	}
	memcpy(sc, data.dptr, data.dsize);

	if (sc->expiration >= time(0))
		ret = 0;
	else
		ret = -1;

finish:
	gdbm_close(dbf);
	return ret;
}

static
void cookie_gdbm_expire(main_server_st* s)
{
GDBM_FILE dbf;
datum key;
datum data;
int deleted = 0;
struct stored_cookie_st sc;
time_t now = time(0);

	dbf = gdbm_open((char*)s->config->cookie_db_name, 0, GDBM_WRITER, 0, NULL);
	if (dbf == NULL)
		return;

	key = gdbm_firstkey(dbf);
	if (key.dptr == NULL)
		goto finish;

	while(key.dptr != NULL) {
		data = gdbm_fetch( dbf, key);
		if (data.dsize != sizeof(sc)) {
			gdbm_delete(dbf, key);
			deleted++;
		} else {
			memcpy(&sc, data.dptr, data.dsize);
			if (sc.expiration <= now) {
				gdbm_delete(dbf, key);
				deleted++;
			}
		}

		key = gdbm_nextkey(dbf, key);
	}
	
	if (deleted > 0)
		gdbm_reorganize(dbf);

finish:
	gdbm_close(dbf);
}

static
int cookie_gdbm_init(main_server_st* s)
{
	return 0;
}

static
void cookie_gdbm_erase(main_server_st* s)
{
	return;
}

static
void cookie_gdbm_deinit(main_server_st* s)
{
        return;
}

struct cookie_storage_st gdbm_cookie_funcs = {
	.store = cookie_gdbm_store,
	.retrieve = cookie_gdbm_retrieve,
	.expire = cookie_gdbm_expire,
	.init = cookie_gdbm_init,
	.deinit = cookie_gdbm_deinit,
	.erase = cookie_gdbm_erase,
};

#endif
