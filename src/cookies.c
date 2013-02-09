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

cookie_store_fn store_cookie;
cookie_retrieve_fn retrieve_cookie;
cookie_db_deinit_fn cookie_db_deinit;
cookie_expire_fn expire_cookies;
cookie_expire_fn erase_cookies;

int cookie_db_init(main_server_st* s)
{
struct cookie_storage_st* funcs;

#ifdef HAVE_GDBM
	if (s->config->cookie_db_name != NULL)
		funcs = &gdbm_cookie_funcs;
	else
#endif
		funcs = &hash_cookie_funcs;

	cookie_db_deinit = funcs->deinit;
	expire_cookies = funcs->expire;
	erase_cookies = funcs->erase;
	store_cookie = funcs->store;
	retrieve_cookie = funcs->retrieve;

	return funcs->init(s);
}
